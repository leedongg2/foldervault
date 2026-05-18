# -*- coding: utf-8 -*-
"""
FolderVault — 실사용 가능한 폴더 보안(암호화) 프로그램
=====================================================

핵심 보안 설계
--------------
* 비밀번호 → 키 유도 : Argon2id (메모리 하드, 현대 표준 KDF)
* 키 분리           : HKDF-SHA256 (헤더/인덱스/파일별 서브키 분리)
* 데이터 암호화     : AES-256-GCM (기밀성 + 무결성 + 인증)
* 변조 방지         : AAD 바인딩(상대경로 + 청크 인덱스 + 청크 수)으로
                      청크 재정렬 / 잘림 / 교체 공격 차단
* 큰 파일 지원      : 1 MiB 청크 스트리밍 암호화

이 프로그램은 폴더를 "숨기는" 것이 아니라 파일 내용 자체를 암호화합니다.
따라서 한 번 잠그면 재부팅, 앱 삭제, OS 재설치와 무관하게
올바른 비밀번호 없이는 데이터를 복원할 수 없습니다.

주의
----
* 비밀번호를 잊으면 어떤 방법으로도 복구할 수 없습니다(설계상 의도).
* .foldervault 파일 자체가 데이터입니다. 이 파일이 삭제되면 데이터도 사라집니다.
  반드시 별도 백업을 보관하세요.
* SSD에서는 웨어 레벨링 때문에 "안전 삭제(덮어쓰기)"가 원본 흔적을
  100% 제거한다고 보장할 수 없습니다(하드웨어 한계, 모든 소프트웨어 공통).
* 비밀번호/키의 메모리 잔존: 통제 가능한 평문 버퍼는 사용 후 0으로
  덮지만, 파이썬의 immutable str(GUI 입력값)과 Tk 내부 사본, 라이브러리가
  반환하는 키 바이트는 순수 파이썬에서 신뢰성 있게 지울 수 없습니다.
  실행 중 메모리 스캔/코어 덤프 위협에는 OS 수준 보호(전체 디스크 암호화,
  신뢰된 단독 사용 환경)가 필요합니다. — 소프트웨어만으로는 한계가 있어
  과장하지 않고 정직히 밝힙니다.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import queue
import stat
import struct
import sys
import threading
import time
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path

# ---- 외부 암호 라이브러리 -------------------------------------------------
try:
    from argon2.low_level import Type as Argon2Type
    from argon2.low_level import hash_secret_raw
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey)
    from cryptography.hazmat.primitives.asymmetric.mldsa import (
        MLDSA65PrivateKey)
    from cryptography.hazmat.primitives.ciphers.aead import (
        AESGCM, ChaCha20Poly1305)
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except Exception as exc:  # pragma: no cover
    raise SystemExit(
        "필수 라이브러리가 없습니다. 다음을 실행하세요:\n"
        '    pip install "cryptography>=48.0.0" argon2-cffi\n\n'
        "Required libraries are missing. Run:\n"
        '    pip install "cryptography>=48.0.0" argon2-cffi\n\n'
        f"(원인 / cause: {exc})"
    )

# ---- GUI ------------------------------------------------------------------
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

APP_NAME = "FolderVault"
APP_TITLE = "FolderVault — 폴더 보안"
VAULT_EXT = ".foldervault"
MAGIC_PREFIX = b"FLDRVLT"        # 7 bytes (포맷 식별)
MAGIC = b"FLDRVLT\x02"           # 8 bytes (포맷 v2 — 읽기 호환 유지)
MAGIC3 = b"FLDRVLT\x03"          # 8 bytes (포맷 v3 — Ed25519 단독, 읽기호환)
MAGIC4 = b"FLDRVLT\x04"          # 8 bytes (포맷 v4 — 하이브리드 서명, 신규)
CHUNK = 1024 * 1024              # 1 MiB 평문 청크
KEY_LEN = 32                     # AES-256 / ChaCha20 키 길이
SIG_LEN = 64                     # Ed25519 서명 길이
MLDSA_MAX = 1 << 16              # ML-DSA 서명 길이 상한(견고성, ML-DSA-65=3309)
MAX_HEADER = 16 * 1024 * 1024    # 헤더 ct 절대 상한(16 MiB)
MAX_INDEX = 256 * 1024 * 1024    # 인덱스 ct 절대 상한(256 MiB) — DoS 방지

# 앱 내장 페퍼 — KDF 에 추가로 섞이는 비밀.
# 정직한 한계: 오픈소스/배포본이라 '소스까지 탈취'되면 비밀이 아니다.
# 단 '.foldervault 파일만' 유출된 경우엔 추가 방어선이 된다.
# (무작위로 생성한 32바이트 상수)
PEPPER = bytes.fromhex(
    "7ee7a36953b33cd7459e64fcbdea9c0a"
    "469b4adf7f475d0c2c7c851c4e769669")

# Argon2id 프리셋 (메모리 KiB 단위) — 2026 기준 상향, 미래 GPU 대비
KDF_PRESETS = {
    "standard": {"time_cost": 4, "memory_cost": 262144,  "parallelism": 4},  # 256 MiB
    "high":     {"time_cost": 5, "memory_cost": 524288,  "parallelism": 4},  # 512 MiB
    "paranoid": {"time_cost": 6, "memory_cost": 1048576, "parallelism": 4},  # 1 GiB
}

CONFIG_DIR = Path(os.environ.get("APPDATA", str(Path.home()))) / APP_NAME
CONFIG_PATH = CONFIG_DIR / "config.json"
REGISTRY_PATH = CONFIG_DIR / "registry.json"


# ===========================================================================
#  i18n — UI 문자열만 번역(로직 비변경). 기본 ko. 모르는 키/언어는 ko 폴백.
# ===========================================================================
LANG = "ko"


def set_lang(code: str) -> None:
    global LANG
    LANG = "en" if code == "en" else "ko"


def T(key: str, **kw) -> str:
    """번역 문자열. kw 가 있으면 .format 적용. ko 값은 원문과 동일."""
    pair = _TR.get(key)
    s = (pair.get(LANG) or pair["ko"]) if pair else key
    return s.format(**kw) if kw else s


def T_other(key: str) -> str:
    """현재 언어의 '반대' 언어 문자열(언어 전환 안내 배너용)."""
    pair = _TR.get(key)
    if not pair:
        return key
    other = "ko" if LANG == "en" else "en"
    return pair.get(other) or pair["ko"]


def T_lang(key: str, lang: str, **kw) -> str:
    """특정 언어로 강제(언어 변경 직후 안내 등). 전역 LANG 불변."""
    pair = _TR.get(key)
    s = (pair.get(lang) or pair["ko"]) if pair else key
    return s.format(**kw) if kw else s


_TR: dict[str, dict[str, str]] = {
    # ---- 공통 버튼/상태 ----
    "btn.ok": {"ko": "확인", "en": "OK"},
    "btn.cancel": {"ko": "취소", "en": "Cancel"},
    "btn.save": {"ko": "저장", "en": "Save"},
    "status.ready": {"ko": "준비됨", "en": "Ready"},
    "status.error": {"ko": "오류 발생", "en": "Error occurred"},
    # ---- 비밀번호 강도 ----
    "pw.none": {"ko": "없음", "en": "none"},
    "pw.s0": {"ko": "매우 약함", "en": "Very weak"},
    "pw.s1": {"ko": "약함", "en": "Weak"},
    "pw.s2": {"ko": "보통", "en": "Fair"},
    "pw.s3": {"ko": "양호", "en": "Good"},
    "pw.s4": {"ko": "강함", "en": "Strong"},
    "pw.s5": {"ko": "매우 강함", "en": "Very strong"},
    # ---- PasswordDialog ----
    "pwd.label": {"ko": "비밀번호:", "en": "Password:"},
    "pwd.show": {"ko": "표시", "en": "Show"},
    "pwd.confirm": {"ko": "비밀번호 확인:", "en": "Confirm password:"},
    "pwd.strength_dash": {"ko": "강도: -", "en": "Strength: -"},
    "pwd.strength": {"ko": "강도: {label}", "en": "Strength: {label}"},
    "pwd.enter": {"ko": "비밀번호를 입력하세요.",
                  "en": "Please enter a password."},
    "pwd.mismatch": {"ko": "비밀번호 확인이 일치하지 않습니다.",
                     "en": "The password confirmation does not match."},
    "pwd.min8": {"ko": "보안을 위해 8자 이상으로 설정하세요.",
                 "en": "For security, use at least 8 characters."},
    "pwd.weak_confirm": {
        "ko": "비밀번호가 약합니다. 그래도 사용하시겠습니까?",
        "en": "This password is weak. Use it anyway?"},
    # ---- ProgressDialog ----
    "prog.preparing": {"ko": "준비 중...", "en": "Preparing..."},
    "prog.cancelling": {"ko": "취소 중... 잠시만 기다리세요.",
                        "en": "Cancelling... please wait."},
    # ---- 진행 메시지 ----
    "prog.encrypting": {"ko": "암호화 중: {rp}", "en": "Encrypting: {rp}"},
    "prog.verifying": {"ko": "검증 중: {rp}", "en": "Verifying: {rp}"},
    "prog.restoring": {"ko": "복원 중: {rp}", "en": "Restoring: {rp}"},
    "prog.reencrypting": {"ko": "재암호화 중: {rp}",
                          "en": "Re-encrypting: {rp}"},
    "prog.delete_original": {"ko": "원본 폴더 안전 삭제 중...",
                             "en": "Securely deleting the original..."},
    "prog.delete_vault": {"ko": "보안 파일 삭제 중...",
                          "en": "Deleting the vault file..."},
    "prog.reencrypt_nodisk": {
        "ko": "재암호화 중 (평문은 디스크에 쓰지 않음)...",
        "en": "Re-encrypting (no plaintext written to disk)..."},
    # ---- 코어 예외 ----
    "err.cancelled_op": {"ko": "사용자가 취소했습니다.",
                         "en": "Cancelled by user."},
    "err.links": {
        "ko": "폴더 안에 심볼릭 링크/정션이 있어 안전하게 암호화할 수 "
              "없습니다.\n이 항목들의 내용이 누락된 채 원본이 삭제되는 "
              "사고를 막기 위해 작업을 중단합니다.\n\n해당 링크/정션을 "
              "제거하거나 실제 폴더/파일로 교체한 뒤 다시 시도하세요:\n\n",
        "en": "This folder contains symbolic links/junctions, so it "
              "cannot be encrypted safely.\nTo prevent the original from "
              "being deleted while their contents are silently missing, "
              "the operation has been stopped.\n\nRemove these links/"
              "junctions or replace them with real folders/files, then "
              "try again:\n\n"},
    "list.more": {"ko": "\n  …외 {n}개", "en": "\n  …and {n} more"},
    "err.open_file": {"ko": "파일을 열 수 없습니다: {rp}\n{ex}",
                      "en": "Cannot open file: {rp}\n{ex}"},
    "err.vault_open": {"ko": "볼트 파일을 열 수 없습니다.",
                       "en": "Cannot open the vault file."},
    "err.vault_corrupt_fmt": {
        "ko": "볼트 파일이 손상되었거나 형식이 올바르지 않습니다.",
        "en": "The vault file is corrupted or has an invalid format."},
    "err.vault_old_test": {
        "ko": "이 볼트는 이전(테스트) 버전 형식이라 현재 버전과 "
              "호환되지 않습니다.",
        "en": "This vault uses an older (test) format that is not "
              "compatible with the current version."},
    "err.not_vault": {"ko": "올바른 볼트 파일이 아닙니다.",
                      "en": "This is not a valid vault file."},
    "err.header_corrupt": {"ko": "볼트 헤더가 손상되었습니다.",
                           "en": "The vault header is corrupted."},
    "err.idx_pos": {
        "ko": "볼트 파일이 손상되었습니다(인덱스 위치 오류).",
        "en": "The vault file is corrupted (bad index position)."},
    "err.idx_size_bad": {
        "ko": "볼트 파일이 손상되었습니다(인덱스 크기 비정상).",
        "en": "The vault file is corrupted (abnormal index size)."},
    "err.idx_size_mismatch": {
        "ko": "볼트 파일이 손상되었습니다(인덱스 크기 불일치).",
        "en": "The vault file is corrupted (index size mismatch)."},
    "err.pw_or_corrupt": {
        "ko": "비밀번호가 틀렸거나 볼트가 손상/변조되었습니다.",
        "en": "Wrong password, or the vault is corrupted/tampered."},
    "err.verifier": {"ko": "검증자 불일치 — 볼트 손상.",
                     "en": "Verifier mismatch — vault corrupted."},
    "err.index_corrupt": {"ko": "인덱스가 손상되었습니다.",
                          "en": "The index is corrupted."},
    "err.pmode": {
        "ko": "볼트 파일이 손상되었습니다(페퍼 모드 오류).",
        "en": "The vault file is corrupted (bad pepper mode)."},
    "err.pw_or_tampered": {
        "ko": "비밀번호가 틀렸거나 볼트가 변조/손상되었습니다.",
        "en": "Wrong password, or the vault was tampered/corrupted."},
    "err.pqc_len": {
        "ko": "볼트 파일이 손상되었습니다(PQC 서명 길이 오류).",
        "en": "The vault file is corrupted (bad PQC signature length)."},
    "err.sig_pos": {
        "ko": "볼트 파일이 손상되었습니다(서명 위치 오류).",
        "en": "The vault file is corrupted (bad signature position)."},
    "err.vault_corrupt": {"ko": "볼트 파일이 손상되었습니다.",
                          "en": "The vault file is corrupted."},
    "err.chunk_size": {"ko": "볼트 손상(청크 크기 오류).",
                       "en": "Vault corrupted (bad chunk size)."},
    "err.integrity": {
        "ko": "무결성 검증 실패(변조/손상 의심).",
        "en": "Integrity check failed (tampering/corruption suspected)."},
    "err.keychain_required": {
        "ko": "이 볼트는 OS 키체인 페퍼가 필요합니다 (생성한 Windows "
              "계정·PC 전용).\n설정 → '페퍼 복원'으로 백업본을 가져오거나, "
              "원래 환경에서 여세요.",
        "en": "This vault requires the OS keychain pepper (only the "
              "Windows account/PC that created it).\nUse Settings -> "
              "'Restore pepper' to import a backup, or open it on the "
              "original machine."},
    "err.size_verify": {
        "ko": "크기 검증 실패(데이터 불일치): {rp}",
        "en": "Size verification failed (data mismatch): {rp}"},
    "err.struct_verify": {
        "ko": "구조 검증 실패(데이터 영역 크기 불일치).",
        "en": "Structure verification failed (data region size "
              "mismatch)."},
    "err.restore_size": {
        "ko": "복원 크기 불일치(데이터 손상): {rp}",
        "en": "Restored size mismatch (data corruption): {rp}"},
    "err.src_size": {
        "ko": "원본 크기 불일치(데이터 손상): {rp}",
        "en": "Source size mismatch (data corruption): {rp}"},
    "err.struct_src": {
        "ko": "구조 검증 실패(원본 데이터 영역 불일치).",
        "en": "Structure verification failed (source data region "
              "mismatch)."},
    "name.restore_folder": {"ko": "복원폴더", "en": "RestoredFolder"},
    # ---- 메인 창 ----
    "app.title": {"ko": "FolderVault — 폴더 보안",
                  "en": "FolderVault — Folder Security"},
    "app.header": {"ko": "🔒 FolderVault", "en": "FolderVault"},
    "app.subtitle": {"ko": "  폴더를 강력하게 암호화하여 보관합니다",
                     "en": "  Strong encryption for your folders"},
    "btn.settings": {"ko": "설정 / Settings", "en": "설정 / Settings"},
    "hint.lang": {
        "ko": "언어를 바꾸려면 오른쪽 위 '설정 / Settings' 버튼을 "
              "누르세요.",
        "en": "To change the language, click the 'Settings' button "
              "at the top right."},
    "col.name": {"ko": "이름", "en": "Name"},
    "col.status": {"ko": "상태", "en": "Status"},
    "col.size": {"ko": "크기", "en": "Size"},
    "col.path": {"ko": "볼트 경로", "en": "Vault path"},
    "btn.lock": {"ko": "➕ 폴더 잠그기", "en": "Lock Folder"},
    "btn.open": {"ko": "🔓 보안 폴더 열기", "en": "Open Vault"},
    "btn.relock": {"ko": "🔁 다시 잠그기", "en": "Re-lock"},
    "btn.changepw": {"ko": "🔑 비밀번호 변경", "en": "Change Password"},
    "btn.remove": {"ko": "✖ 목록에서 제거", "en": "Remove from List"},
    "btn.refresh": {"ko": "🔄 새로고침", "en": "Refresh"},
    "st.file_missing": {"ko": "⚠ 파일없음", "en": "Missing file"},
    "st.unlocked": {"ko": "🔓 풀림 — 보안 안됨",
                    "en": "Unlocked — not secure"},
    "st.secured": {"ko": "🔒 보안됨", "en": "Secured"},
    "err.unexpected": {
        "ko": "예기치 못한 오류가 발생했습니다.\n\n{last}\n\n"
              "자세한 내용:\n{path}",
        "en": "An unexpected error occurred.\n\n{last}\n\n"
              "Details:\n{path}"},
    # ---- 페퍼/키체인 ----
    "msg.keychain_win_only": {
        "ko": "OS 키체인 모드는 Windows 에서만 지원됩니다. "
              "앱 모드로 진행합니다.",
        "en": "OS keychain mode is supported on Windows only. "
              "Continuing in app mode."},
    "msg.keychain_prep_fail": {
        "ko": "키체인 페퍼를 준비하지 못했습니다.\n{e}\n"
              "앱 모드로 진행합니다.",
        "en": "Could not prepare the keychain pepper.\n{e}\n"
              "Continuing in app mode."},
    "msg.keychain_created": {
        "ko": "⚠ OS 키체인 페퍼가 새로 생성되었습니다.\n\n"
              "이 모드로 만든 볼트는 '이 Windows 계정·이 PC'에서만 "
              "열립니다. OS 재설치·계정 삭제·다른 PC 에서는 올바른 "
              "비밀번호로도 복구 불가합니다.\n\n"
              "지금 '설정 → 페퍼 백업'으로 반드시 백업하세요.",
        "en": "Warning: a new OS keychain pepper was created.\n\n"
              "Vaults made in this mode open only on THIS Windows "
              "account and PC. After an OS reinstall, account deletion, "
              "or on another PC, they cannot be recovered even with the "
              "correct password.\n\nBack it up now via "
              "'Settings -> Back up pepper'."},
    # ---- 폴더 검사/덮어쓰기 ----
    "msg.folder_inaccessible": {
        "ko": "폴더에 접근할 수 없습니다:\n{folder}\n\n{e}",
        "en": "Cannot access the folder:\n{folder}\n\n{e}"},
    "msg.empty_folder": {"ko": "빈 폴더입니다.",
                         "en": "The folder is empty."},
    "msg.overwrite": {
        "ko": "이미 존재하는 파일입니다. 덮어쓰시겠습니까?\n\n{path}\n\n"
              "(다른 볼트라면 그 데이터가 영구히 사라집니다.)",
        "en": "This file already exists. Overwrite it?\n\n{path}\n\n"
              "(If it is a different vault, its data is lost forever.)"},
    # ---- 원본 처리 정책 ----
    "msg.original_policy": {
        "ko": "원본 폴더를 어떻게 처리할까요?\n\n대상: {folder}\n\n"
              "[예]    암호화 후 원본을 영구 삭제\n"
              "         → 진짜 보안 (평문 사본이 남지 않음)\n\n"
              "[아니오] 원본을 그대로 두고 암호본만 생성\n"
              "         → 처음 동작을 시험할 때 권장\n"
              "         (평문 원본이 남으므로 보안 효과는 없음)\n\n"
              "[취소]   작업 중단",
        "en": "What should happen to the original folder?\n\n"
              "Target: {folder}\n\n"
              "[Yes]    Encrypt, then permanently delete the original\n"
              "         -> real security (no plaintext copy remains)\n\n"
              "[No]     Keep the original, only create the encrypted "
              "copy\n         -> recommended for a first test run\n"
              "         (no security: plaintext original remains)\n\n"
              "[Cancel] Stop"},
    "msg.original_final": {
        "ko": "⚠ 마지막 확인 — 되돌릴 수 없습니다\n\n"
              "다음 폴더가 영구 삭제됩니다:\n{folder}\n\n"
              "• 비밀번호를 잊으면 복구 불가\n"
              "• .foldervault 파일이 없으면 복구 불가\n\n"
              "암호화는 삭제 '전에' 검증되며, 검증에 실패하면\n"
              "원본은 삭제되지 않습니다.\n\n정말 진행하시겠습니까?",
        "en": "Warning: final confirmation — this cannot be undone\n\n"
              "The following folder will be permanently deleted:\n"
              "{folder}\n\n"
              "- Unrecoverable if you forget the password\n"
              "- Unrecoverable without the .foldervault file\n\n"
              "Encryption is verified BEFORE deletion; if verification "
              "fails, the original is not deleted.\n\nProceed?"},
    # ---- 잠그기 흐름 ----
    "title.lock_folder": {"ko": "암호화할 폴더 선택",
                          "en": "Select a folder to encrypt"},
    "title.save_vault": {
        "ko": "보안 파일(.foldervault) 저장 위치",
        "en": "Where to save the vault (.foldervault)"},
    "ft.all_files": {"ko": "모든 파일", "en": "All files"},
    "msg.vault_inside": {
        "ko": "보안 파일(.foldervault)을 암호화 대상 폴더 '안에' 저장할 "
              "수 없습니다.\n\n암호화 후 그 폴더가 삭제될 때 보안 파일까지 "
              "함께 사라져 데이터를 영구히 잃습니다.\n\n폴더 바깥(상위 "
              "폴더나 다른 드라이브)을 선택하세요.",
        "en": "The vault (.foldervault) cannot be saved INSIDE the "
              "folder being encrypted.\n\nWhen that folder is deleted "
              "after encryption, the vault would be deleted with it and "
              "the data lost forever.\n\nChoose a location outside the "
              "folder (a parent folder or another drive)."},
    "title.set_new_pw": {"ko": "새 비밀번호 설정",
                         "en": "Set a new password"},
    "info.new_pw": {
        "ko": "이 폴더를 열 때 사용할 비밀번호입니다.\n"
              "⚠ 비밀번호를 잊으면 복구가 불가능합니다. 안전하게 "
              "보관하세요.",
        "en": "This is the password used to open this folder.\n"
              "Warning: if you forget it, recovery is impossible. "
              "Keep it safe."},
    "task.encrypt": {"ko": "폴더 암호화", "en": "Encrypting folder"},
    "task.decrypt": {"ko": "폴더 복호화", "en": "Decrypting folder"},
    "task.changepw": {"ko": "비밀번호 변경", "en": "Changing password"},
    "status.encrypting": {"ko": "암호화 중...", "en": "Encrypting..."},
    "status.done_keep": {"ko": "완료(원본 유지): '{name}'",
                         "en": "Done (original kept): '{name}'"},
    "msg.done_keep": {
        "ko": "암호화가 완료되었습니다. (원본 유지)\n\n"
              "• 보안 파일: {vault}\n• 원본 폴더는 그대로 있습니다.\n\n"
              "동작을 확인했다면, 실제 보안을 위해 원본을 직접 삭제하거나"
              " '다시 잠그기'를 사용하세요.\n"
              "(원본이 남아 있는 동안에는 보안 효과가 없습니다.)",
        "en": "Encryption complete. (Original kept)\n\n"
              "- Vault file: {vault}\n- The original folder is "
              "untouched.\n\nOnce you have verified it works, delete "
              "the original yourself or use 'Re-lock' for real "
              "security.\n(There is no security while the original "
              "remains.)"},
    "status.partial_del": {
        "ko": "주의: 원본 일부 삭제 실패 — 평문 잔존",
        "en": "Warning: some originals not deleted — plaintext remains"},
    "msg.partial_del": {
        "ko": "암호화는 완료됐고 보안 파일은 정상입니다.\n"
              "그러나 원본 일부를 삭제하지 못했습니다(다른 프로그램이 "
              "사용 중이거나 권한 문제).\n아래 항목은 평문으로 남아 있어 "
              "보안되지 않습니다 — 수동으로 삭제하세요:\n\n{shown}{more}"
              "\n\n• 보안 파일: {vault}\n  (반드시 백업하세요.)",
        "en": "Encryption completed and the vault file is fine.\n"
              "However, some originals could not be deleted (in use by "
              "another program, or a permission issue).\nThe items "
              "below remain as plaintext and are NOT secured — delete "
              "them manually:\n\n{shown}{more}\n\n- Vault file: {vault}"
              "\n  (Be sure to back it up.)"},
    "status.done_remain": {"ko": "완료: '{name}' (폴더 잔존)",
                           "en": "Done: '{name}' (folder remains)"},
    "msg.done_remain": {
        "ko": "폴더가 안전하게 암호화되고 원본 파일들은 삭제되었습니다."
              "\n\n다만 잠금 이후 새로 생긴 파일이 있어 폴더가 남아 "
              "있습니다(그 파일들은 안전을 위해 건드리지 않았습니다):\n"
              "{folder}\n확인 후 직접 정리하세요.\n\n"
              "• 보안 파일: {vault}\n  (반드시 백업하세요.)",
        "en": "The folder was encrypted securely and the original "
              "files were deleted.\n\nHowever, files created after the "
              "lock scan remain, so the folder still exists (those "
              "files were left untouched for safety):\n{folder}\n"
              "Review and clean up yourself.\n\n- Vault file: {vault}"
              "\n  (Be sure to back it up.)"},
    "status.done_lock": {
        "ko": "완료: '{name}' 잠금 ({entries}개 항목)",
        "en": "Done: '{name}' locked ({entries} items)"},
    "msg.done_lock": {
        "ko": "폴더가 안전하게 암호화되었습니다.\n\n"
              "• 보안 파일: {vault}\n• 원본 폴더는 삭제되었습니다.\n\n"
              "이 .foldervault 파일을 반드시 백업하세요.",
        "en": "The folder was encrypted securely.\n\n"
              "- Vault file: {vault}\n- The original folder was "
              "deleted.\n\nBe sure to back up this .foldervault file."},
    # ---- 열기 흐름 ----
    "title.choose_vault": {"ko": "보안 파일 선택",
                           "en": "Select a vault file"},
    "title.enter_pw": {"ko": "비밀번호 입력", "en": "Enter password"},
    "info.vault": {"ko": "볼트: {name}", "en": "Vault: {name}"},
    "status.checking_pw": {"ko": "비밀번호 확인 중...",
                           "en": "Verifying password..."},
    "status.open_fail": {"ko": "열기 실패", "en": "Open failed"},
    "title.restore_where": {
        "ko": "'{name}' 폴더를 복원할 위치 선택",
        "en": "Choose where to restore the '{name}' folder"},
    "msg.same_name": {
        "ko": "이미 같은 이름의 폴더가 있습니다:\n{final}",
        "en": "A folder with the same name already exists:\n{final}"},
    "msg.keep_vault": {
        "ko": "복원 후 보안 파일(.foldervault)을 유지할까요?\n\n"
              "[예] 보안 파일 유지 (권장 — 백업으로 보관)\n"
              "[아니오] 복원 후 보안 파일 삭제\n[취소] 작업 중단",
        "en": "Keep the vault (.foldervault) after restoring?\n\n"
              "[Yes] Keep the vault (recommended — keep as a backup)\n"
              "[No] Delete the vault after restoring\n[Cancel] Stop"},
    "status.decrypting": {"ko": "복호화 중...", "en": "Decrypting..."},
    "status.restore_done_del": {
        "ko": "복원 완료(보안 파일 삭제): {out}",
        "en": "Restore complete (vault deleted): {out}"},
    "msg.restore_done_del": {
        "ko": "폴더가 복원되었고 보안 파일은 삭제되었습니다:\n\n{out}",
        "en": "The folder was restored and the vault was deleted:"
              "\n\n{out}"},
    "status.restore_done_delfail": {
        "ko": "복원 완료 — 보안 파일 삭제 실패",
        "en": "Restore complete — vault deletion failed"},
    "msg.restore_done_delfail": {
        "ko": "폴더는 복원되었습니다:\n{out}\n\n그러나 보안 파일을 "
              "삭제하지 못했습니다(다른 프로그램이 사용 중이거나 권한 "
              "문제). 파일이 그대로 남아 목록에 유지됩니다:\n{vault}\n"
              "필요하면 직접 삭제하세요.",
        "en": "The folder was restored:\n{out}\n\nHowever, the vault "
              "file could not be deleted (in use by another program, "
              "or a permission issue). It remains and stays in the "
              "list:\n{vault}\nDelete it yourself if needed."},
    "status.restore_done": {"ko": "복원 완료: {out}",
                            "en": "Restore complete: {out}"},
    "msg.restore_done": {
        "ko": "폴더가 복원되었습니다:\n\n{out}\n\n이 폴더가 디스크에 "
              "남아 있는 동안에는 목록 상태가\n'🔓 풀림 — 보안 안됨'으로 "
              "표시됩니다.\n다시 안전하게 하려면 '다시 잠그기'를 "
              "사용하세요.",
        "en": "The folder was restored:\n\n{out}\n\nWhile this folder "
              "remains on disk, its list status shows\n'Unlocked — not "
              "secure'.\nUse 'Re-lock' to secure it again."},
    # ---- 다시 잠그기 ----
    "title.relock_folder": {
        "ko": "다시 잠글 (이미 복원된) 폴더 선택",
        "en": "Select the (already restored) folder to re-lock"},
    "title.save_vault2": {"ko": "보안 파일 저장 위치",
                          "en": "Where to save the vault file"},
    "msg.vault_inside2": {
        "ko": "보안 파일을 암호화 대상 폴더 '안에' 저장할 수 없습니다.\n"
              "그 폴더 삭제 시 보안 파일까지 사라져 데이터를 잃습니다.\n"
              "폴더 바깥을 선택하세요.",
        "en": "The vault cannot be saved INSIDE the folder being "
              "encrypted.\nDeleting that folder would delete the vault "
              "too and lose the data.\nChoose a location outside the "
              "folder."},
    "title.set_pw": {"ko": "비밀번호 설정", "en": "Set password"},
    "info.relock": {"ko": "이 폴더를 다시 암호화합니다.",
                    "en": "This will re-encrypt this folder."},
    # ---- 비밀번호 변경 ----
    "title.cur_pw": {"ko": "현재 비밀번호", "en": "Current password"},
    "title.new_pw": {"ko": "새 비밀번호", "en": "New password"},
    "status.pw_changed": {"ko": "비밀번호가 변경되었습니다.",
                          "en": "Password changed."},
    "msg.pw_changed": {"ko": "비밀번호가 변경되었습니다.",
                       "en": "The password has been changed."},
    # ---- 목록에서 제거 ----
    "msg.select_item": {"ko": "목록에서 항목을 선택하세요.",
                        "en": "Please select an item from the list."},
    "msg.remove_confirm": {
        "ko": "목록에서만 제거합니다. (실제 .foldervault 파일은 삭제되지 "
              "않습니다.)\n계속할까요?",
        "en": "This only removes it from the list. (The actual "
              ".foldervault file is not deleted.)\nContinue?"},
    "status.removed": {"ko": "목록에서 제거됨", "en": "Removed from list"},
    # ---- 백그라운드 작업 ----
    "cancel.status": {"ko": "취소되었습니다.", "en": "Cancelled."},
    "cancel.msg": {"ko": "작업이 취소되었습니다.",
                   "en": "The operation was cancelled."},
    "err.generic": {"ko": "오류가 발생했습니다:\n\n{e}",
                    "en": "An error occurred:\n\n{e}"},
    # ---- 설정 ----
    "title.settings": {"ko": "설정", "en": "Settings"},
    "set.lang_title": {"ko": "언어 / Language", "en": "언어 / Language"},
    "set.lang_ko": {"ko": "한국어", "en": "한국어"},
    "set.lang_en": {"ko": "English", "en": "English"},
    "msg.lang_restart": {
        "ko": "언어 설정이 저장되었습니다. 프로그램을 다시 시작하면 "
              "적용됩니다.",
        "en": "Language saved. Restart the program to apply it."},
    "set.kdf_title": {"ko": "암호화 강도 (Argon2id)",
                      "en": "Encryption strength (Argon2id)"},
    "set.kdf_std": {
        "ko": "표준 — 256MB 메모리 (권장, 대부분 환경에 적합)",
        "en": "Standard — 256 MB memory (recommended, fits most "
              "systems)"},
    "set.kdf_high": {"ko": "강력 — 512MB 메모리 (느리지만 더 강력)",
                     "en": "High — 512 MB memory (slower but stronger)"},
    "set.kdf_para": {
        "ko": "편집증 — 1GB 메모리 (최강, 저사양 PC엔 무거움)",
        "en": "Paranoid — 1 GB memory (strongest; heavy on low-end "
              "PCs)"},
    "set.del_title": {"ko": "원본 삭제 방식",
                      "en": "Original deletion method"},
    "set.del_secure": {
        "ko": "안전 삭제(무작위 덮어쓰기 후 삭제)",
        "en": "Secure delete (random overwrite, then delete)"},
    "set.del_note": {
        "ko": "※ SSD는 하드웨어 특성상 덮어쓰기로 흔적을 100% 지울 수 "
              "없습니다. 데이터 보호는 '암호화' 자체로 보장됩니다.",
        "en": "Note: on SSDs, overwriting cannot fully erase traces "
              "(hardware limitation). Data protection comes from the "
              "encryption itself."},
    "set.pep_title": {"ko": "페퍼 모드 (KDF 추가 비밀)",
                      "en": "Pepper mode (extra KDF secret)"},
    "set.pep_app": {
        "ko": "앱 내장 — 이식 가능 (어느 PC에서나 비번만으로 열림)",
        "en": "App-embedded — portable (opens on any PC with just the "
              "password)"},
    "set.pep_kc": {
        "ko": "OS 키체인 — 이 PC·계정 전용 (페퍼가 진짜 비밀이 됨)",
        "en": "OS keychain — this PC/account only (the pepper becomes "
              "a real secret)"},
    "set.pep_warn": {
        "ko": "⚠ 키체인 모드로 만든 볼트는 '이 Windows 계정·이 PC'"
              "에서만 열립니다. OS 재설치·다른 PC 에서는 올바른 "
              "비밀번호로도 복구 불가 — 반드시 아래로 백업하세요.",
        "en": "Warning: vaults made in keychain mode open only on THIS "
              "Windows account/PC. After an OS reinstall or on another "
              "PC, recovery is impossible even with the correct "
              "password — back it up below."},
    "set.kc_win_only": {"ko": "(키체인 모드는 Windows 에서만 동작)",
                        "en": "(Keychain mode works on Windows only)"},
    "msg.no_pep_backup": {
        "ko": "백업할 키체인 페퍼가 없습니다.\n키체인 모드로 폴더를 한 "
              "번 잠그면 생성됩니다.",
        "en": "There is no keychain pepper to back up.\nIt is created "
              "once you lock a folder in keychain mode."},
    "title.pep_backup": {
        "ko": "페퍼 백업 저장(이 파일=비밀, 안전히 보관)",
        "en": "Save pepper backup (this file is the secret — store "
              "safely)"},
    "ft.pepper": {"ko": "FolderVault pepper", "en": "FolderVault pepper"},
    "msg.pep_backed": {
        "ko": "페퍼를 백업했습니다.\n\n이 파일은 그 자체가 비밀입니다 — "
              "볼트와 '다른 곳'(오프라인 등)에 안전히 보관하세요. 분실 "
              "시 키체인 볼트는 복구 불가합니다.",
        "en": "Pepper backed up.\n\nThis file IS the secret — store it "
              "safely somewhere separate from the vault (offline, "
              "etc.). If lost, keychain vaults cannot be recovered."},
    "err.backup_fail": {"ko": "백업 실패:\n{e}",
                        "en": "Backup failed:\n{e}"},
    "msg.win_only": {"ko": "Windows 에서만 가능합니다.",
                     "en": "Available on Windows only."},
    "title.pep_restore": {"ko": "페퍼 백업 파일 선택",
                          "en": "Select a pepper backup file"},
    "err.pep_badfmt": {"ko": "형식이 올바르지 않습니다(32바이트 아님).",
                       "en": "Invalid format (not 32 bytes)."},
    "msg.pep_restored": {
        "ko": "페퍼를 복원했습니다. 이제 이 PC·계정에서 해당 키체인 "
              "볼트를 열 수 있습니다.",
        "en": "Pepper restored. You can now open the corresponding "
              "keychain vaults on this PC/account."},
    "err.restore_fail": {"ko": "복원 실패:\n{e}",
                         "en": "Restore failed:\n{e}"},
    "btn.pep_backup": {"ko": "페퍼 백업(내보내기)",
                       "en": "Back up pepper (export)"},
    "btn.pep_restore": {"ko": "페퍼 복원(가져오기)",
                        "en": "Restore pepper (import)"},
    "status.settings_saved": {"ko": "설정이 저장되었습니다.",
                              "en": "Settings saved."},
    # ---- 시작 크래시 ----
    "msg.start_error": {
        "ko": "프로그램 시작 중 오류가 발생했습니다.\n\n{line}\n\n"
              "자세한 내용:\n{log}",
        "en": "An error occurred while starting the program.\n\n"
              "{line}\n\nDetails:\n{log}"},
    "log.fail": {"ko": "(로그 기록 실패)",
                 "en": "(failed to write log)"},
    "err.dpapi": {"ko": "{fn} 실패(err={code})",
                  "en": "{fn} failed (err={code})"},
}


# ===========================================================================
#  유틸리티
# ===========================================================================
def _lp(path: str) -> str:
    """Windows 260자 경로 제한 우회용 확장 경로 접두사."""
    if os.name != "nt":
        return path
    p = os.path.abspath(path)
    if p.startswith("\\\\?\\"):
        return p
    if p.startswith("\\\\"):                       # UNC
        return "\\\\?\\UNC\\" + p[2:]
    return "\\\\?\\" + p


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S")


def human_size(n: int) -> str:
    f = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if f < 1024 or unit == "TB":
            return f"{f:.0f} {unit}" if unit == "B" else f"{f:.1f} {unit}"
        f /= 1024
    return f"{f:.1f} TB"


def load_json(path: Path, default):
    try:
        return json.loads(path.read_text("utf-8"))
    except Exception:
        return default


def save_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), "utf-8")
    os.replace(tmp, path)


# ===========================================================================
#  암호 코어
# ===========================================================================
def derive_master_key(password: str, salt: bytes, kdf: dict) -> bytes:
    """Argon2id 로 비밀번호에서 마스터 키(32B) 유도.

    참고: Argon2 는 immutable bytes 를 요구하고, 파이썬의 str/bytes 와
    Tk Entry 내부 사본은 순수 파이썬에서 신뢰성 있게 메모리에서 지울 수
    없다(설계상 한계). 작동하지 않는 '와이프'를 흉내내지 않고, 한계를
    정직히 밝힌다(모듈 docstring 참고). argon2-cffi 는 내부 C 비밀번호
    버퍼를 자체적으로 0으로 지운다.
    """
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=int(kdf["time_cost"]),
        memory_cost=int(kdf["memory_cost"]),
        parallelism=int(kdf["parallelism"]),
        hash_len=KEY_LEN,
        type=Argon2Type.ID,
    )


def subkey(master: bytes, info: bytes) -> bytes:
    """HKDF-SHA256 으로 용도별 서브키 분리."""
    return HKDF(algorithm=hashes.SHA256(), length=KEY_LEN,
                salt=None, info=info).derive(master)


HKDF_HEADER = b"FolderVault/header/v1"
HKDF_INDEX = b"FolderVault/index/v1"
HKDF_FILE = b"FolderVault/file/v1:"   # + relpath(utf-8)


def gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce, ct


def gcm_decrypt(key: bytes, nonce: bytes, ct: bytes, aad: bytes) -> bytes:
    return AESGCM(key).decrypt(nonce, ct, aad)


# ---- v3: 루트 키(Argon2 + 페퍼) -------------------------------------------
HKDF_ROOT_V3 = b"FolderVault/root/v3"
HKDF_HDR_A = b"FolderVault/hdr/aes/v3"
HKDF_HDR_C = b"FolderVault/hdr/cha/v3"
HKDF_IDX_A = b"FolderVault/idx/aes/v3"
HKDF_IDX_C = b"FolderVault/idx/cha/v3"
HKDF_FILE_A = b"FolderVault/file/aes/v3:"   # + relpath
HKDF_FILE_C = b"FolderVault/file/cha/v3:"   # + relpath
HKDF_SIGN = b"FolderVault/sign/ed25519/v3"
HKDF_MLDSA = b"FolderVault/sign/mldsa65/v4"   # PQC 서명 시드(루트에서 유도)


def derive_root_v3(password: str, salt: bytes, kdf: dict,
                   user_pepper: bytes | None = None) -> bytes:
    """Argon2id 결과에 페퍼를 HKDF salt 로 섞어 루트 키(32B) 유도.

    - user_pepper 없음(앱 모드): 앱 내장 PEPPER 만. '볼트 파일만' 탈취
      시 추가 방어선이나, 소스/배포본까지 탈취되면 비밀이 아니다.
    - user_pepper 있음(키체인 모드): PEPPER + OS 키체인(DPAPI) 의 사용자
      전용 비밀을 결합 → 페퍼가 '진짜 비밀'이 됨(해당 PC·계정 한정).
    """
    argon = derive_master_key(password, salt, kdf)
    if user_pepper:
        salt_material = hashlib.sha256(PEPPER + user_pepper).digest()
    else:
        salt_material = PEPPER
    return HKDF(algorithm=hashes.SHA256(), length=KEY_LEN,
                salt=salt_material, info=HKDF_ROOT_V3).derive(argon)


# ---- v3: 캐스케이드 AEAD (AES-256-GCM → ChaCha20-Poly1305) -----------------
def casc_encrypt(k_aes: bytes, k_cha: bytes, pt: bytes,
                 aad: bytes) -> tuple[bytes, bytes, bytes]:
    """이중 인증 암호화. 두 키·두 논스 독립. 반환: (nA, nC, ct)."""
    n_aes = os.urandom(12)
    inner = AESGCM(k_aes).encrypt(n_aes, pt, aad)
    n_cha = os.urandom(12)
    ct = ChaCha20Poly1305(k_cha).encrypt(n_cha, inner, aad)
    return n_aes, n_cha, ct


def casc_decrypt(k_aes: bytes, k_cha: bytes, n_aes: bytes,
                 n_cha: bytes, ct: bytes, aad: bytes) -> bytes:
    """ChaCha20-Poly1305 해제 → AES-256-GCM 해제. 둘 다 인증 검증."""
    inner = ChaCha20Poly1305(k_cha).decrypt(n_cha, ct, aad)
    return AESGCM(k_aes).decrypt(n_aes, inner, aad)


# ---- v3: 루트 키에서 결정적으로 유도한 Ed25519 서명 키 --------------------
def sign_key_v3(root: bytes):
    seed = subkey(root, HKDF_SIGN)            # 32B
    return Ed25519PrivateKey.from_private_bytes(seed)


def mldsa_key_v4(root: bytes):
    """ML-DSA-65(FIPS 204) 서명 키를 루트에서 결정적으로 유도.

    from_seed_bytes(32B) → 저장 불필요, 비밀번호 보유자만 서명/검증.
    """
    seed = subkey(root, HKDF_MLDSA)           # 32B
    return MLDSA65PrivateKey.from_seed_bytes(seed)


def hybrid_sign(root: bytes, digest: bytes) -> tuple[bytes, bytes]:
    """digest(=SHA-512(파일)) 에 Ed25519 + ML-DSA-65 동시 서명."""
    ed = sign_key_v3(root).sign(digest)
    ml = mldsa_key_v4(root).sign(digest)
    return ed, ml


def hybrid_verify(root: bytes, digest: bytes, ed_sig: bytes,
                  ml_sig: bytes) -> None:
    """두 서명 모두 검증. 하나라도 실패하면 InvalidSignature."""
    sign_key_v3(root).public_key().verify(ed_sig, digest)
    mldsa_key_v4(root).public_key().verify(ml_sig, digest)


# ---- v3: Padmé 패딩 (개별 파일 크기를 버킷으로 은닉, 낭비 < ~12%) ---------
def padme(n: int) -> int:
    """PURBs 논문 Padmé: n 을 정보 누출이 적은 버킷 크기로 올림."""
    if n < 2:
        return n
    e = n.bit_length() - 1            # floor(log2 n)
    s = e.bit_length()
    last = e - s
    if last <= 0:
        return n
    mask = (1 << last) - 1
    return (n + mask) & ~mask


def _sha512_region(f, start: int, end: int) -> bytes:
    """파일의 [start, end) 구간 SHA-512 (상수 메모리 스트리밍)."""
    h = hashlib.sha512()
    f.seek(start)
    rem = end - start
    while rem > 0:
        b = f.read(min(CHUNK, rem))
        if not b:
            break
        h.update(b)
        rem -= len(b)
    return h.digest()


def _file_keys(version: int, root: bytes, rp: str) -> tuple:
    """파일별 키. v3/v4 → (kA, kC) 캐스케이드, v2 → (k,) 단일.

    v3·v4 의 데이터/청크 포맷은 동일(차이는 서명 트레일러뿐).
    """
    if version >= 3:
        return (subkey(root, HKDF_FILE_A + _b(rp)),
                subkey(root, HKDF_FILE_C + _b(rp)))
    return (subkey(root, HKDF_FILE + _b(rp)),)


def _read_decrypt_chunk(f, version: int, keys: tuple,
                        aad: bytes) -> bytes:
    """청크 1개를 읽고 복호화(버전별 포맷). f 를 전진시킴."""
    if version >= 3:
        n_aes = _readn(f, 12)
        n_cha = _readn(f, 12)
        clen = _u32(_readn(f, 4))
        if clen <= 0 or clen > CHUNK + 128:
            raise WrongPasswordOrCorrupt("볼트 손상(청크 크기 오류).")
        ct = _readn(f, clen)
        try:
            return casc_decrypt(keys[0], keys[1], n_aes, n_cha, ct, aad)
        except Exception:
            raise WrongPasswordOrCorrupt("무결성 검증 실패(변조/손상 의심).")
    cn = _readn(f, 12)
    clen = _u32(_readn(f, 4))
    if clen <= 0 or clen > CHUNK + 64:
        raise WrongPasswordOrCorrupt("볼트 손상(청크 크기 오류).")
    cct = _readn(f, clen)
    try:
        return gcm_decrypt(keys[0], cn, cct, aad)
    except Exception:
        raise WrongPasswordOrCorrupt("무결성 검증 실패(변조/손상 의심).")


class WrongPasswordOrCorrupt(Exception):
    """비밀번호 오류 또는 볼트 손상/변조."""


def _b(s: str) -> bytes:
    """파일명을 깨지지 않게(왕복 가능) 바이트로. 윈도우 비정상 파일명 대응."""
    return s.encode("utf-8", "surrogatepass")


def _readn(f, n: int) -> bytes:
    """정확히 n 바이트를 읽거나 손상으로 간주(친절한 예외)."""
    b = f.read(n)
    if len(b) != n:
        raise WrongPasswordOrCorrupt(
            T("err.vault_corrupt_fmt"))
    return b


def _u32(b: bytes) -> int:
    try:
        return struct.unpack(">I", b)[0]
    except struct.error:
        raise WrongPasswordOrCorrupt(T("err.vault_corrupt"))


def _u64(b: bytes) -> int:
    try:
        return struct.unpack(">Q", b)[0]
    except struct.error:
        raise WrongPasswordOrCorrupt(T("err.vault_corrupt"))


def _verifier_ok(header) -> bool:
    """검증자 상수시간 비교(방어적). 실제 인증은 AEAD/Ed25519 가 이미
    상수시간으로 처리하므로 익스플로잇 가능한 타이밍 오라클은 없었다."""
    v = header.get("verifier") if isinstance(header, dict) else None
    if not isinstance(v, str):
        return False
    return hmac.compare_digest(v.encode("utf-8"), b"FOLDERVAULT-OK")


def _resolve(p: str) -> str:
    r = os.path.realpath(os.path.abspath(p))
    return r.lower() if os.name == "nt" else r


def path_is_within(child: str, parent: str) -> bool:
    """child 가 parent 폴더 내부(또는 동일)인지. 볼트 자기삭제 방지용."""
    try:
        c, p = _resolve(child), _resolve(parent)
        if c == p:
            return True
        return os.path.commonpath([c, p]) == p
    except (ValueError, OSError):
        return False


class UnsupportedLinkError(Exception):
    """심볼릭 링크/정션이 포함되어 안전하게 처리할 수 없음."""


class KeychainPepperRequired(WrongPasswordOrCorrupt):
    """이 볼트는 OS 키체인 페퍼가 필요한데 사용할 수 없음(분실/다른 PC)."""


# ===========================================================================
#  OS 키체인 페퍼 (Windows DPAPI) — 옵트인. 페퍼를 '진짜 비밀'로.
# ===========================================================================
#  ⚠ 데이터 안전: 키체인 모드 볼트는 '생성한 Windows 계정·PC'에서만 열린다.
#  키체인 비밀을 잃으면(OS 재설치/계정 삭제/다른 PC) 올바른 비밀번호로도
#  복구 불가. 그래서 기본은 '앱 모드(이식 가능)'이고, 키체인은 옵트인 +
#  반드시 백업(내보내기) + 분실 시 명확한 안내로만 제공한다.
DPAPI_ENTROPY = b"FolderVault/DPAPI/userpepper/v1"
USERPEPPER_PATH = CONFIG_DIR / "userpepper.bin"
_CRYPTPROTECT_UI_FORBIDDEN = 0x1


def dpapi_available() -> bool:
    return os.name == "nt"


def _dpapi(func_name: str, data: bytes) -> bytes:
    """CryptProtectData / CryptUnprotectData 호출(현재 사용자 범위)."""
    import ctypes
    from ctypes import wintypes

    class BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_char))]

    def mk(b: bytes):
        buf = ctypes.create_string_buffer(bytes(b), max(1, len(b)))
        return BLOB(len(b), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf

    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    in_blob, _b1 = mk(data)
    ent_blob, _b2 = mk(DPAPI_ENTROPY)
    out = BLOB()
    fn = getattr(crypt32, func_name)
    ok = fn(ctypes.byref(in_blob), None, ctypes.byref(ent_blob),
            None, None, _CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out))
    if not ok:
        raise OSError(T("err.dpapi", fn=func_name,
                        code=ctypes.GetLastError()))
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(out.pbData)


def dpapi_protect(data: bytes) -> bytes:
    return _dpapi("CryptProtectData", data)


def dpapi_unprotect(blob: bytes) -> bytes:
    return _dpapi("CryptUnprotectData", blob)


def load_user_pepper() -> bytes | None:
    """DPAPI 로 보호된 사용자 페퍼(32B)를 읽어온다. 없거나 다른
    계정/PC라 복호 불가하면 None."""
    try:
        blob = USERPEPPER_PATH.read_bytes()
    except OSError:
        return None
    try:
        up = dpapi_unprotect(blob)
    except Exception:
        # 어떤 DPAPI/ctypes 실패든 None → 호출부가 명확한
        # KeychainPepperRequired 로 안내(조용한 크래시 금지).
        return None
    return up if len(up) == 32 else None


def ensure_user_pepper() -> tuple[bytes, bool]:
    """사용자 페퍼를 로드, 없으면 새로 생성·저장. 반환:(pepper, 새로생성?)."""
    up = load_user_pepper()
    if up is not None:
        return up, False
    up = os.urandom(32)
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    tmp = USERPEPPER_PATH.with_suffix(".tmp")
    tmp.write_bytes(dpapi_protect(up))
    os.replace(tmp, USERPEPPER_PATH)
    return up, True


def store_user_pepper(up: bytes) -> None:
    """가져온 페퍼(32B)를 DPAPI 로 보호해 저장(복원용)."""
    if len(up) != 32:
        raise ValueError("페퍼는 32바이트여야 합니다.")
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    tmp = USERPEPPER_PATH.with_suffix(".tmp")
    tmp.write_bytes(dpapi_protect(up))
    os.replace(tmp, USERPEPPER_PATH)


_REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def _is_reparse_point(path: str) -> bool:
    """심볼릭 링크 또는 (Windows) 정션/마운트 포인트인지."""
    try:
        st = os.lstat(_lp(path))
    except OSError:
        return False
    if stat.S_ISLNK(st.st_mode):
        return True
    return bool(getattr(st, "st_file_attributes", 0) & _REPARSE)


def scan_reparse_points(folder: str, limit: int = 20) -> list[str]:
    """폴더 트리 안의 모든 심볼릭 링크/정션 상대경로 목록(최대 limit)."""
    base = Path(os.path.abspath(folder))
    found: list[str] = []
    for root, dirs, files in os.walk(folder):
        for name in list(dirs) + files:
            p = os.path.join(root, name)
            if _is_reparse_point(p):
                try:
                    found.append(Path(p).relative_to(base).as_posix())
                except ValueError:
                    found.append(name)
                if len(found) >= limit:
                    return found
    return found


# ===========================================================================
#  볼트 컨테이너  (단일 .foldervault 파일)
# ===========================================================================
#
#  포맷 v3 (신규 생성):  키 = HKDF(Argon2id(pw,salt), salt=PEPPER)
#    [프리픽스] MAGIC3(8) salt(16) t,m,p(>I*3)
#               nAh(12) nCh(12) hlen(>I) hct      # 캐스케이드(header), aad=MAGIC3
#    [데이터]   파일마다, Padmé 패딩까지 포함한 청크들:
#               nA(12) nC(12) clen(>I) ct          # casc, aad= rp|fid|ci
#    [푸터]     nAi(12) nCi(12) ilen(>Q) ict        # casc(index),
#                                                  #   aad=MAGIC3+nAh+nCh
#               index_off(>Q)                       # nAi 절대 오프셋
#               sig(64)                             # Ed25519(SHA-512(파일[0:-64]))
#
#  포맷 v2 (읽기 호환 유지): 단일 AES-GCM, 패딩/서명 없음. 신규 생성은 안 함.
#
#  불변식: 인덱스의 s(실제크기)/ps(패딩크기)/n/fid 는 실제 기록값. 생성 직후
#  서명+캐스케이드 전체검증을 통과해야만 배치/원본삭제가 허용된다.
#
PREFIX_FIXED = 8 + 16 + 12          # v2 프리픽스 고정부 (MAGIC+salt+t,m,p)


class Vault:
    def __init__(self, path: str):
        self.path = path

    # ---- 생성(잠그기) — 항상 v3 ------------------------------------------
    @staticmethod
    def create_from_folder(folder: str, vault_path: str, password: str,
                           kdf: dict, progress=None, cancel=None,
                           pmode: int = 0,
                           user_pepper: bytes | None = None) -> dict:
        """folder 전체를 v3(캐스케이드+페퍼+Padmé+Ed25519)로 암호화.

        pmode 0=앱 페퍼(이식 가능), 1=OS 키체인 페퍼(해당 PC·계정 한정).
        tmp 에 쓰고 서명·전체검증 통과 후에만 원자적 배치한다.
        """
        folder = os.path.abspath(folder)
        # 심볼릭 링크/정션은 내용이 조용히 누락될 수 있으므로,
        # 어떤 것도 쓰거나 지우기 전에 즉시 중단(원본 보존).
        links = scan_reparse_points(folder)
        if links:
            shown = "\n".join("  - " + x for x in links[:10])
            more = (T("list.more", n=len(links) - 10)
                    if len(links) > 10 else "")
            raise UnsupportedLinkError(
                T("err.links") + shown + more)
        pmode = 1 if (pmode == 1 and user_pepper) else 0
        salt = os.urandom(16)
        root = derive_root_v3(password, salt, kdf,
                              user_pepper if pmode == 1 else None)
        k_aes_h = subkey(root, HKDF_HDR_A)
        k_cha_h = subkey(root, HKDF_HDR_C)
        k_aes_i = subkey(root, HKDF_IDX_A)
        k_cha_i = subkey(root, HKDF_IDX_C)

        # 1) 스캔: 경로/종류만 확정(크기는 진행률 추정용 best-effort)
        entries: list[dict] = []
        est_total = 0
        base = Path(folder)
        for root_d, dirs, files in os.walk(folder):
            dirs.sort()
            files.sort()
            rp_dir = Path(root_d).relative_to(base).as_posix()
            if rp_dir != ".":
                entries.append({"p": rp_dir, "t": "d"})
            for name in files:
                fp = os.path.join(root_d, name)
                try:
                    est_total += os.path.getsize(_lp(fp))
                except OSError:
                    pass
                rp = Path(fp).relative_to(base).as_posix()
                entries.append({"p": rp, "t": "f"})
        est_total = max(1, est_total)

        header = {
            "app": APP_NAME, "version": 4,
            "vault_id": uuid.uuid4().hex,
            "name": base.name,
            "created": now_iso(),
            "verifier": "FOLDERVAULT-OK",
        }
        nAh, nCh, hct = casc_encrypt(
            k_aes_h, k_cha_h, json.dumps(header).encode("utf-8"), MAGIC4)

        tmp_path = vault_path + ".tmp"
        done_bytes = 0
        real_total = 0
        try:
            with open(_lp(tmp_path), "w+b") as out:
                out.write(MAGIC4)
                out.write(salt)
                out.write(struct.pack(">I", int(kdf["time_cost"])))
                out.write(struct.pack(">I", int(kdf["memory_cost"])))
                out.write(struct.pack(">I", int(kdf["parallelism"])))
                out.write(bytes([pmode]))            # 0=앱 / 1=키체인
                out.write(nAh)
                out.write(nCh)
                out.write(struct.pack(">I", len(hct)))
                out.write(hct)

                # 2) 데이터: 실제바이트 + Padmé 패딩을 청크 캐스케이드 암호화
                for e in entries:
                    if cancel and cancel():
                        raise InterruptedError(T("err.cancelled_op"))
                    if e["t"] != "f":
                        continue
                    rp = e["p"]
                    fid = uuid.uuid4().hex
                    k_aes_f = subkey(root, HKDF_FILE_A + _b(rp))
                    k_cha_f = subkey(root, HKDF_FILE_C + _b(rp))
                    src = os.path.join(folder, rp.replace("/", os.sep))
                    try:
                        fh = open(_lp(src), "rb")
                    except OSError as ex:
                        raise IOError(T("err.open_file", rp=rp, ex=ex))
                    n = 0
                    fsize = 0
                    with fh:
                        while True:
                            data = fh.read(CHUNK)
                            if not data:
                                break
                            aad = (_b(rp) + b"|" + fid.encode("ascii")
                                   + b"|" + str(n).encode("ascii"))
                            cnA, cnC, cct = casc_encrypt(
                                k_aes_f, k_cha_f, data, aad)
                            out.write(cnA)
                            out.write(cnC)
                            out.write(struct.pack(">I", len(cct)))
                            out.write(cct)
                            n += 1
                            fsize += len(data)
                            done_bytes += len(data)
                            if progress:
                                progress(done_bytes, est_total,
                                         T("prog.encrypting", rp=rp))
                    # Padmé: 실제 크기를 버킷으로 올려 개별 파일 크기 은닉
                    ps = padme(fsize)
                    pad_rem = ps - fsize
                    while pad_rem > 0:
                        block = os.urandom(min(CHUNK, pad_rem))
                        aad = (_b(rp) + b"|" + fid.encode("ascii")
                               + b"|" + str(n).encode("ascii"))
                        cnA, cnC, cct = casc_encrypt(
                            k_aes_f, k_cha_f, block, aad)
                        out.write(cnA)
                        out.write(cnC)
                        out.write(struct.pack(">I", len(cct)))
                        out.write(cct)
                        n += 1
                        pad_rem -= len(block)
                    e["n"] = n
                    e["s"] = fsize
                    e["ps"] = ps
                    e["fid"] = fid
                    real_total += fsize

                # 3) 인덱스(실제 값)를 푸터로 기록
                data_end = out.tell()
                index = {"entries": entries, "total_size": real_total,
                         "folder_name": base.name}
                nAi, nCi, ict = casc_encrypt(
                    k_aes_i, k_cha_i,
                    json.dumps(index).encode("utf-8"),
                    MAGIC4 + nAh + nCh)
                out.write(nAi)
                out.write(nCi)
                out.write(struct.pack(">Q", len(ict)))
                out.write(ict)
                out.write(struct.pack(">Q", data_end))    # index_off

                # 4) 파일 전체(서명 제외)에 하이브리드 서명 부착:
                #    Ed25519(64B) + ML-DSA-65 + ml_len(>I). 둘 다 검증.
                out.flush()
                sig_pos = out.tell()
                digest = _sha512_region(out, 0, sig_pos)
                ed_sig, ml_sig = hybrid_sign(root, digest)
                out.seek(sig_pos)
                out.write(ed_sig)
                out.write(ml_sig)
                out.write(struct.pack(">I", len(ml_sig)))
                out.flush()
                os.fsync(out.fileno())
        except BaseException:
            try:
                os.remove(_lp(tmp_path))
            except OSError:
                pass
            raise

        # 5) 서명+캐스케이드 전체 검증 통과 후에만 배치
        try:
            Vault(tmp_path)._verify_full(
                password, progress=progress, cancel=cancel,
                user_pepper=user_pepper if pmode == 1 else None)
        except BaseException:
            try:
                os.remove(_lp(tmp_path))
            except OSError:
                pass
            raise

        os.replace(_lp(tmp_path), _lp(vault_path))
        return {"vault_id": header["vault_id"], "name": header["name"],
                "entries": len(entries), "total_size": real_total,
                "file_paths": [e["p"] for e in entries if e["t"] == "f"],
                "dir_paths": [e["p"] for e in entries if e["t"] == "d"]}

    # ---- 열기(내부): 버전 판별 후 복호화 -------------------------------
    def _open(self, password: str, user_pepper: bytes | None = None):
        try:
            filesize = os.path.getsize(_lp(self.path))
        except OSError:
            raise WrongPasswordOrCorrupt(T("err.vault_open"))
        if filesize < 8:
            raise WrongPasswordOrCorrupt(
                T("err.vault_corrupt_fmt"))
        with open(_lp(self.path), "rb") as f:
            magic = f.read(8)
        if magic == MAGIC4:
            return self._open_v4(password, filesize, user_pepper)
        if magic == MAGIC3:
            return self._open_v3(password, filesize, user_pepper)
        if magic == MAGIC:
            return self._open_v2(password, filesize)
        if magic[:7] == MAGIC_PREFIX:
            raise WrongPasswordOrCorrupt(
                T("err.vault_old_test"))
        raise WrongPasswordOrCorrupt(T("err.not_vault"))

    # ---- v2 (읽기 호환 전용) -------------------------------------------
    def _open_v2(self, password: str, filesize: int):
        if filesize < PREFIX_FIXED + 16 + 8:
            raise WrongPasswordOrCorrupt(
                T("err.vault_corrupt_fmt"))
        with open(_lp(self.path), "rb") as f:
            f.seek(8)
            salt = _readn(f, 16)
            t_cost = _u32(_readn(f, 4))
            m_cost = _u32(_readn(f, 4))
            par = _u32(_readn(f, 4))
            hn = _readn(f, 12)
            hlen = _u32(_readn(f, 4))
            if hlen <= 0 or hlen > MAX_HEADER:
                raise WrongPasswordOrCorrupt(T("err.header_corrupt"))
            hct = _readn(f, hlen)
            data_start = f.tell()
            kdf = {"time_cost": t_cost, "memory_cost": m_cost,
                   "parallelism": par}
            f.seek(filesize - 8)
            index_off = _u64(_readn(f, 8))
            if not (data_start <= index_off <= filesize - 8):
                raise WrongPasswordOrCorrupt(
                    T("err.idx_pos"))
            f.seek(index_off)
            in_ = _readn(f, 12)
            ilen = _u64(_readn(f, 8))
            if ilen <= 0 or ilen > MAX_INDEX:
                raise WrongPasswordOrCorrupt(
                    T("err.idx_size_bad"))
            if index_off + 12 + 8 + ilen != filesize - 8:
                raise WrongPasswordOrCorrupt(
                    T("err.idx_size_mismatch"))
            ict = _readn(f, ilen)
        master = derive_master_key(password, salt, kdf)
        try:
            header = json.loads(gcm_decrypt(
                subkey(master, HKDF_HEADER), hn, hct, MAGIC))
            index = json.loads(gcm_decrypt(
                subkey(master, HKDF_INDEX), in_, ict, MAGIC + hn))
        except Exception:
            raise WrongPasswordOrCorrupt(
                T("err.pw_or_corrupt"))
        if not _verifier_ok(header):
            raise WrongPasswordOrCorrupt(T("err.verifier"))
        if not isinstance(index, dict) or "entries" not in index:
            raise WrongPasswordOrCorrupt(T("err.index_corrupt"))
        return master, kdf, header, index, data_start, index_off, 2

    # ---- v3 (캐스케이드 + 페퍼 + 전체 서명) ----------------------------
    def _open_v3(self, password: str, filesize: int,
                 user_pepper: bytes | None = None):
        min_size = (8 + 16 + 12 + 1 + 12 + 12 + 4
                    + 12 + 12 + 8 + 8 + SIG_LEN)
        if filesize < min_size:
            raise WrongPasswordOrCorrupt(
                T("err.vault_corrupt_fmt"))
        signed_end = filesize - SIG_LEN
        with open(_lp(self.path), "rb") as f:
            f.seek(8)
            salt = _readn(f, 16)
            t_cost = _u32(_readn(f, 4))
            m_cost = _u32(_readn(f, 4))
            par = _u32(_readn(f, 4))
            pmode = _readn(f, 1)[0]
            if pmode not in (0, 1):
                raise WrongPasswordOrCorrupt(
                    T("err.pmode"))
            nAh = _readn(f, 12)
            nCh = _readn(f, 12)
            hlen = _u32(_readn(f, 4))
            if hlen <= 0 or hlen > MAX_HEADER:
                raise WrongPasswordOrCorrupt(T("err.header_corrupt"))
            hct = _readn(f, hlen)
            data_start = f.tell()
            kdf = {"time_cost": t_cost, "memory_cost": m_cost,
                   "parallelism": par}
            f.seek(signed_end - 8)
            index_off = _u64(_readn(f, 8))
            if not (data_start <= index_off <= signed_end - 8):
                raise WrongPasswordOrCorrupt(
                    T("err.idx_pos"))
            f.seek(index_off)
            nAi = _readn(f, 12)
            nCi = _readn(f, 12)
            ilen = _u64(_readn(f, 8))
            if ilen <= 0 or ilen > MAX_INDEX:
                raise WrongPasswordOrCorrupt(
                    T("err.idx_size_bad"))
            if index_off + 12 + 12 + 8 + ilen != signed_end - 8:
                raise WrongPasswordOrCorrupt(
                    T("err.idx_size_mismatch"))
            ict = _readn(f, ilen)
            f.seek(signed_end)
            sig = _readn(f, SIG_LEN)
            digest = _sha512_region(f, 0, signed_end)

        if pmode == 1 and not user_pepper:
            raise KeychainPepperRequired(
                T("err.keychain_required"))
        root = derive_root_v3(password, salt, kdf,
                              user_pepper if pmode == 1 else None)
        # 1) 전체 파일 Ed25519 서명 검증(비번 오류·변조를 한 번에 차단)
        try:
            sign_key_v3(root).public_key().verify(sig, digest)
        except InvalidSignature:
            raise WrongPasswordOrCorrupt(
                T("err.pw_or_tampered"))
        # 2) 헤더/인덱스 캐스케이드 복호화
        try:
            header = json.loads(casc_decrypt(
                subkey(root, HKDF_HDR_A), subkey(root, HKDF_HDR_C),
                nAh, nCh, hct, MAGIC3))
            index = json.loads(casc_decrypt(
                subkey(root, HKDF_IDX_A), subkey(root, HKDF_IDX_C),
                nAi, nCi, ict, MAGIC3 + nAh + nCh))
        except Exception:
            raise WrongPasswordOrCorrupt(
                T("err.pw_or_corrupt"))
        if not _verifier_ok(header):
            raise WrongPasswordOrCorrupt(T("err.verifier"))
        if not isinstance(index, dict) or "entries" not in index:
            raise WrongPasswordOrCorrupt(T("err.index_corrupt"))
        return root, kdf, header, index, data_start, index_off, 3

    # ---- v4 (캐스케이드 + 페퍼 + 하이브리드 Ed25519+ML-DSA 서명) -------
    def _open_v4(self, password: str, filesize: int,
                 user_pepper: bytes | None = None):
        min_size = (8 + 16 + 12 + 1 + 12 + 12 + 4
                    + 12 + 12 + 8 + 8 + SIG_LEN + 4 + 1)
        if filesize < min_size:
            raise WrongPasswordOrCorrupt(
                T("err.vault_corrupt_fmt"))
        with open(_lp(self.path), "rb") as f:
            f.seek(filesize - 4)
            ml_len = _u32(_readn(f, 4))
            if ml_len <= 0 or ml_len > MLDSA_MAX:
                raise WrongPasswordOrCorrupt(
                    T("err.pqc_len"))
            sig_start = filesize - 4 - ml_len - SIG_LEN
            if sig_start < (8 + 16 + 12 + 1 + 12 + 12 + 4):
                raise WrongPasswordOrCorrupt(
                    T("err.sig_pos"))
            f.seek(8)
            salt = _readn(f, 16)
            t_cost = _u32(_readn(f, 4))
            m_cost = _u32(_readn(f, 4))
            par = _u32(_readn(f, 4))
            pmode = _readn(f, 1)[0]
            if pmode not in (0, 1):
                raise WrongPasswordOrCorrupt(
                    T("err.pmode"))
            nAh = _readn(f, 12)
            nCh = _readn(f, 12)
            hlen = _u32(_readn(f, 4))
            if hlen <= 0 or hlen > MAX_HEADER:
                raise WrongPasswordOrCorrupt(T("err.header_corrupt"))
            hct = _readn(f, hlen)
            data_start = f.tell()
            kdf = {"time_cost": t_cost, "memory_cost": m_cost,
                   "parallelism": par}
            f.seek(sig_start - 8)
            index_off = _u64(_readn(f, 8))
            if not (data_start <= index_off <= sig_start - 8):
                raise WrongPasswordOrCorrupt(
                    T("err.idx_pos"))
            f.seek(index_off)
            nAi = _readn(f, 12)
            nCi = _readn(f, 12)
            ilen = _u64(_readn(f, 8))
            if ilen <= 0 or ilen > MAX_INDEX:
                raise WrongPasswordOrCorrupt(
                    T("err.idx_size_bad"))
            if index_off + 12 + 12 + 8 + ilen != sig_start - 8:
                raise WrongPasswordOrCorrupt(
                    T("err.idx_size_mismatch"))
            ict = _readn(f, ilen)
            f.seek(sig_start)
            ed_sig = _readn(f, SIG_LEN)
            ml_sig = _readn(f, ml_len)
            digest = _sha512_region(f, 0, sig_start)

        if pmode == 1 and not user_pepper:
            raise KeychainPepperRequired(
                T("err.keychain_required"))
        root = derive_root_v3(password, salt, kdf,
                              user_pepper if pmode == 1 else None)
        # 1) 하이브리드 서명 검증: Ed25519 + ML-DSA-65 (둘 다 통과해야 함)
        try:
            hybrid_verify(root, digest, ed_sig, ml_sig)
        except InvalidSignature:
            raise WrongPasswordOrCorrupt(
                T("err.pw_or_tampered"))
        # 2) 헤더/인덱스 캐스케이드 복호화
        try:
            header = json.loads(casc_decrypt(
                subkey(root, HKDF_HDR_A), subkey(root, HKDF_HDR_C),
                nAh, nCh, hct, MAGIC4))
            index = json.loads(casc_decrypt(
                subkey(root, HKDF_IDX_A), subkey(root, HKDF_IDX_C),
                nAi, nCi, ict, MAGIC4 + nAh + nCh))
        except Exception:
            raise WrongPasswordOrCorrupt(
                T("err.pw_or_corrupt"))
        if not _verifier_ok(header):
            raise WrongPasswordOrCorrupt(T("err.verifier"))
        if not isinstance(index, dict) or "entries" not in index:
            raise WrongPasswordOrCorrupt(T("err.index_corrupt"))
        return root, kdf, header, index, data_start, index_off, 4

    def read_header(self, password: str,
                    user_pepper: bytes | None = None) -> dict:
        _, _, header, index, _, _, _ = self._open(password, user_pepper)
        header = dict(header)
        header["_entries"] = len(index["entries"])
        header["_total_size"] = index.get("total_size", 0)
        header["_folder_name"] = index.get("folder_name", header.get("name"))
        return header

    # ---- 전체 검증: 서명(_open) + 모든 청크 복호화 + 구조 정합성 -------
    def _verify_full(self, password: str, progress=None, cancel=None,
                     user_pepper: bytes | None = None) -> None:
        root, kdf, header, index, data_start, index_off, ver = \
            self._open(password, user_pepper)
        entries = index["entries"]
        total = max(1, index.get("total_size", 0))
        done = 0
        with open(_lp(self.path), "rb") as f:
            f.seek(data_start)
            for e in entries:
                if cancel and cancel():
                    raise InterruptedError(T("err.cancelled_op"))
                if e.get("t") != "f":
                    continue
                rp = e["p"]
                fid = e.get("fid", "")
                n = int(e.get("n", 0))
                s = int(e.get("s", 0))
                ps = int(e.get("ps", s))             # v2 → ps == s
                keys = _file_keys(ver, root, rp)
                acc = 0
                for ci in range(n):
                    aad = (_b(rp) + b"|" + fid.encode("ascii")
                           + b"|" + str(ci).encode("ascii"))
                    pt = _read_decrypt_chunk(f, ver, keys, aad)
                    acc += len(pt)
                    done += len(pt)
                    if progress:
                        progress(done, total, T("prog.verifying", rp=rp))
                if acc != ps:
                    raise WrongPasswordOrCorrupt(
                        T("err.size_verify", rp=rp))
            if f.tell() != index_off:
                raise WrongPasswordOrCorrupt(
                    T("err.struct_verify"))

    # ---- 추출(열기/복원) -------------------------------------------------
    def extract_to(self, password: str, dest_parent: str,
                    progress=None, cancel=None,
                    user_pepper: bytes | None = None) -> str:
        """dest_parent 아래에 원본 폴더명으로 복원. 복원된 경로 반환."""
        root, kdf, header, index, data_start, index_off, ver = \
            self._open(password, user_pepper)
        folder_name = (index.get("folder_name") or header.get("name")
                       or T("name.restore_folder"))
        final_dir = os.path.join(dest_parent, folder_name)
        if os.path.exists(_lp(final_dir)):
            raise FileExistsError(final_dir)

        tmp_dir = os.path.join(dest_parent,
                               f".{folder_name}.{uuid.uuid4().hex[:8]}.tmp")
        total = max(1, index.get("total_size", 0))
        done = 0

        try:
            os.makedirs(_lp(tmp_dir), exist_ok=True)
            entries = index["entries"]
            with open(_lp(self.path), "rb") as f:
                f.seek(data_start)
                for e in entries:
                    if cancel and cancel():
                        raise InterruptedError(T("err.cancelled_op"))
                    rel = e["p"].replace("/", os.sep)
                    out_path = os.path.join(tmp_dir, rel)
                    if e.get("t") == "d":
                        os.makedirs(_lp(out_path), exist_ok=True)
                        continue
                    os.makedirs(_lp(os.path.dirname(out_path)),
                                exist_ok=True)
                    rp = e["p"]
                    fid = e.get("fid", "")
                    n = int(e.get("n", 0))
                    size = int(e.get("s", 0))
                    keys = _file_keys(ver, root, rp)
                    written = 0
                    with open(_lp(out_path), "wb") as w:
                        for ci in range(n):
                            aad = (_b(rp) + b"|" + fid.encode("ascii")
                                   + b"|" + str(ci).encode("ascii"))
                            pt = _read_decrypt_chunk(f, ver, keys, aad)
                            # 실제 크기까지만 기록(Padmé 패딩은 폐기)
                            if written < size:
                                take = pt[:size - written]
                                w.write(take)
                                written += len(take)
                            done += len(pt)
                            if progress:
                                progress(done, total,
                                         T("prog.restoring", rp=rp))
                    if written != size:
                        raise WrongPasswordOrCorrupt(
                            T("err.restore_size", rp=rp))
                if f.tell() != index_off:
                    raise WrongPasswordOrCorrupt(
                        "구조 검증 실패(데이터 영역 크기 불일치).")
            os.replace(_lp(tmp_dir), _lp(final_dir))
            return final_dir
        except BaseException:
            _rmtree_quiet(tmp_dir)
            raise

    # ---- 비밀번호 변경 (메모리 내 재암호화) ----------------------------
    @staticmethod
    def _reencrypt(src_path: str, dst_path: str, old_pw: str,
                    new_pw: str, kdf: dict, progress=None, cancel=None,
                    src_user_pepper: bytes | None = None,
                    pmode: int = 0,
                    user_pepper: bytes | None = None) -> None:
        """src 볼트(v2/v3/v4)를 new_pw 로 재암호화해 dst(v4) 에 기록.

        청크를 '복호화 → 즉시 재암호화'하므로 평문이 디스크에 절대
        기록되지 않는다(메모리 내 소량만 잠시 존재). 새 볼트를 하이브리드
        서명·전체 검증한 뒤에만 dst 로 원자적 배치한다.
        src_user_pepper: 원본 열기용 키체인 페퍼. pmode/user_pepper: 새 볼트.
        """
        v = Vault(src_path)
        root_old, _kdf_old, header, index, data_start, index_off, ver = \
            v._open(old_pw, src_user_pepper)
        entries = index["entries"]
        total = max(1, index.get("total_size", 0))
        done = 0

        pmode = 1 if (pmode == 1 and user_pepper) else 0
        salt_new = os.urandom(16)
        root_new = derive_root_v3(new_pw, salt_new, kdf,
                                  user_pepper if pmode == 1 else None)
        header_new = {
            "app": APP_NAME, "version": 4,
            "vault_id": header.get("vault_id", uuid.uuid4().hex),
            "name": header.get("name", index.get("folder_name", "?")),
            "created": header.get("created", now_iso()),
            "verifier": "FOLDERVAULT-OK",
        }
        nAh, nCh, hct = casc_encrypt(
            subkey(root_new, HKDF_HDR_A), subkey(root_new, HKDF_HDR_C),
            json.dumps(header_new).encode("utf-8"), MAGIC4)

        tmp_path = dst_path + ".tmp"
        try:
            with open(_lp(src_path), "rb") as fin, \
                    open(_lp(tmp_path), "w+b") as out:
                out.write(MAGIC4)
                out.write(salt_new)
                out.write(struct.pack(">I", int(kdf["time_cost"])))
                out.write(struct.pack(">I", int(kdf["memory_cost"])))
                out.write(struct.pack(">I", int(kdf["parallelism"])))
                out.write(bytes([pmode]))
                out.write(nAh)
                out.write(nCh)
                out.write(struct.pack(">I", len(hct)))
                out.write(hct)

                fin.seek(data_start)
                for e in entries:
                    if cancel and cancel():
                        raise InterruptedError(T("err.cancelled_op"))
                    if e.get("t") != "f":
                        continue
                    rp = e["p"]
                    fid_old = e.get("fid", "")
                    n = int(e.get("n", 0))
                    s = int(e.get("s", 0))
                    keys_old = _file_keys(ver, root_old, rp)
                    kA = subkey(root_new, HKDF_FILE_A + _b(rp))
                    kC = subkey(root_new, HKDF_FILE_C + _b(rp))
                    fid_new = uuid.uuid4().hex
                    out_n = 0
                    buf = bytearray()
                    real_rem = s

                    def emit(block):
                        nonlocal out_n
                        a = (_b(rp) + b"|" + fid_new.encode("ascii")
                             + b"|" + str(out_n).encode("ascii"))
                        bnA, bnC, bct = casc_encrypt(
                            kA, kC, bytes(block), a)
                        out.write(bnA)
                        out.write(bnC)
                        out.write(struct.pack(">I", len(bct)))
                        out.write(bct)
                        out_n += 1

                    for ci in range(n):
                        a_old = (_b(rp) + b"|" + fid_old.encode("ascii")
                                 + b"|" + str(ci).encode("ascii"))
                        pt = _read_decrypt_chunk(fin, ver, keys_old, a_old)
                        if real_rem > 0:
                            take = pt[:real_rem]
                            buf += take
                            real_rem -= len(take)
                            while len(buf) >= CHUNK:
                                emit(buf[:CHUNK])
                                del buf[:CHUNK]
                            done += len(take)
                            if progress:
                                progress(done, total,
                                         T("prog.reencrypting", rp=rp))
                    if real_rem != 0:
                        raise WrongPasswordOrCorrupt(
                            T("err.src_size", rp=rp))
                    if buf:
                        emit(buf)
                        buf = bytearray()
                    ps = padme(s)
                    pad_rem = ps - s
                    while pad_rem > 0:
                        blk = os.urandom(min(CHUNK, pad_rem))
                        emit(blk)
                        pad_rem -= len(blk)
                    e["n"] = out_n
                    e["s"] = s
                    e["ps"] = ps
                    e["fid"] = fid_new
                if fin.tell() != index_off:
                    raise WrongPasswordOrCorrupt(
                        T("err.struct_src"))

                data_end = out.tell()
                index["total_size"] = sum(
                    int(x.get("s", 0)) for x in entries
                    if x.get("t") == "f")
                nAi, nCi, ict = casc_encrypt(
                    subkey(root_new, HKDF_IDX_A),
                    subkey(root_new, HKDF_IDX_C),
                    json.dumps(index).encode("utf-8"),
                    MAGIC4 + nAh + nCh)
                out.write(nAi)
                out.write(nCi)
                out.write(struct.pack(">Q", len(ict)))
                out.write(ict)
                out.write(struct.pack(">Q", data_end))
                out.flush()
                sig_pos = out.tell()
                digest = _sha512_region(out, 0, sig_pos)
                ed_sig, ml_sig = hybrid_sign(root_new, digest)
                out.seek(sig_pos)
                out.write(ed_sig)
                out.write(ml_sig)
                out.write(struct.pack(">I", len(ml_sig)))
                out.flush()
                os.fsync(out.fileno())
        except BaseException:
            try:
                os.remove(_lp(tmp_path))
            except OSError:
                pass
            raise

        # 새 볼트를 새 비밀번호로 서명+전체 검증한 뒤에만 배치
        try:
            Vault(tmp_path)._verify_full(
                new_pw, progress=progress, cancel=cancel,
                user_pepper=user_pepper if pmode == 1 else None)
        except BaseException:
            try:
                os.remove(_lp(tmp_path))
            except OSError:
                pass
            raise
        os.replace(_lp(tmp_path), _lp(dst_path))

    def change_password(self, old_pw: str, new_pw: str, kdf: dict,
                         progress=None, secure: bool = True,
                         src_user_pepper: bytes | None = None,
                         pmode: int = 0,
                         user_pepper: bytes | None = None) -> None:
        """비밀번호 변경 — 평문을 디스크에 전혀 쓰지 않는 메모리 내
        재암호화. src_user_pepper 로 기존 볼트를 열고, pmode/user_pepper
        로 새 볼트를 만든다.

        새 볼트가 전체 검증을 통과한 경우에만 기존 볼트를 원자적으로
        교체하므로, 변경 중 어떤 실패가 나도 기존 볼트는 손상되지 않는다.
        (secure 인자는 더 이상 필요 없으나 호환성 위해 유지 — 무시됨.)
        """
        new_tmp = self.path + ".new"
        moved = False
        try:
            if progress:
                progress(0, 1, T("prog.reencrypt_nodisk"))
            Vault._reencrypt(self.path, new_tmp, old_pw, new_pw, kdf,
                             progress=progress,
                             src_user_pepper=src_user_pepper,
                             pmode=pmode, user_pepper=user_pepper)
            os.replace(_lp(new_tmp), _lp(self.path))
            moved = True
        finally:
            if not moved:
                try:
                    os.remove(_lp(new_tmp))
                except OSError:
                    pass


# ===========================================================================
#  안전 삭제
# ===========================================================================
def _make_writable(path: str) -> None:
    try:
        os.chmod(_lp(path), stat.S_IWRITE | stat.S_IREAD)
    except OSError:
        pass


def secure_delete_file(path: str, passes: int = 1) -> bool:
    """무작위 덮어쓰기 후 삭제. 성공(파일이 사라짐) 시 True.

    덮어쓰기에 성공했으면 os.remove 가 실패해도 평문은 이미 파괴된
    상태지만, '파일이 남아 있다'는 사실 자체를 사용자에게 알리기
    위해 최종 존재 여부로 성공을 판단한다.
    """
    if not os.path.exists(_lp(path)):
        return True
    try:
        _make_writable(path)
        size = os.path.getsize(_lp(path))
        with open(_lp(path), "r+b", buffering=0) as f:
            for _ in range(max(1, passes)):
                f.seek(0)
                left = size
                while left > 0:
                    n = min(CHUNK, left)
                    f.write(os.urandom(n))
                    left -= n
                f.flush()
                os.fsync(f.fileno())
            f.seek(0)
            f.truncate(0)
            f.flush()
            os.fsync(f.fileno())
    except OSError:
        pass
    try:
        os.remove(_lp(path))
    except OSError:
        pass
    return not os.path.exists(_lp(path))


def _plain_delete_file(path: str) -> bool:
    if not os.path.exists(_lp(path)):
        return True
    _make_writable(path)
    try:
        os.remove(_lp(path))
    except OSError:
        pass
    return not os.path.exists(_lp(path))


def secure_delete_listed(folder: str, file_paths, dir_paths,
                         secure: bool = True) -> list:
    """암호화·검증된 항목만 정확히 삭제(라이브 트리 전체 삭제 금지).

    스캔 이후 새로 생긴 파일 등 '볼트에 없는 것'은 절대 건드리지
    않는다. 반환값: 삭제에 실패해 평문이 남은 파일 경로 목록.
    """
    folder = os.path.abspath(folder)
    failed: list = []
    for rp in file_paths:
        fp = os.path.join(folder, rp.replace("/", os.sep))
        ok = (secure_delete_file(fp) if secure
              else _plain_delete_file(fp))
        if not ok:
            failed.append(fp)
    # 깊은 디렉터리부터 비어 있을 때만 제거(모르는 파일은 보존)
    for rp in sorted(dir_paths, key=lambda p: p.count("/"),
                     reverse=True):
        dp = os.path.join(folder, rp.replace("/", os.sep))
        try:
            os.rmdir(_lp(dp))
        except OSError:
            pass
    try:
        os.rmdir(_lp(folder))
    except OSError:
        pass
    return failed


def secure_delete_tree(folder: str, secure: bool = True) -> None:
    """폴더 전체 삭제(우리가 만든 임시 폴더 정리 전용, 베스트 에포트)."""
    if not os.path.exists(_lp(folder)):
        return
    for root, dirs, files in os.walk(folder, topdown=False):
        for name in files:
            fp = os.path.join(root, name)
            if secure:
                secure_delete_file(fp)
            else:
                _make_writable(fp)
                try:
                    os.remove(_lp(fp))
                except OSError:
                    pass
        for name in dirs:
            try:
                os.rmdir(_lp(os.path.join(root, name)))
            except OSError:
                pass
    try:
        os.rmdir(_lp(folder))
    except OSError:
        pass


def _rmtree_quiet(folder: str) -> None:
    secure_delete_tree(folder, secure=False)


# ===========================================================================
#  비밀번호 강도
# ===========================================================================
def password_strength(pw: str) -> tuple[int, str]:
    if not pw:
        return 0, T("pw.none")
    score = 0
    if len(pw) >= 8:
        score += 1
    if len(pw) >= 12:
        score += 1
    if len(pw) >= 16:
        score += 1
    classes = sum(bool(any(c in grp for c in pw)) for grp in (
        "abcdefghijklmnopqrstuvwxyz",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "0123456789",
        "!@#$%^&*()-_=+[]{};:,.<>/?\\|`~'\" ",
    ))
    score += max(0, classes - 1)
    score = min(score, 5)
    return score, [T("pw.s0"), T("pw.s1"), T("pw.s2"),
                   T("pw.s3"), T("pw.s4"), T("pw.s5")][score]


# ===========================================================================
#  GUI
# ===========================================================================
class PasswordDialog(tk.Toplevel):
    """비밀번호 입력(+옵션: 확인 입력, 강도 표시)."""

    def __init__(self, parent, title: str, confirm: bool = False,
                 info: str = ""):
        super().__init__(parent)
        self.title(title)
        self.resizable(False, False)
        self.result: str | None = None
        self.confirm = confirm
        self.transient(parent)
        self.grab_set()

        pad = {"padx": 14, "pady": 6}
        if info:
            tk.Label(self, text=info, justify="left", fg="#444",
                     wraplength=420).pack(anchor="w", **pad)

        frm = tk.Frame(self)
        frm.pack(fill="x", **pad)
        tk.Label(frm, text=T("pwd.label"), width=10, anchor="w").grid(
            row=0, column=0, sticky="w", pady=4)
        self.e1 = tk.Entry(frm, show="•", width=34)
        self.e1.grid(row=0, column=1, pady=4)
        self.e1.focus_set()

        self.var_show = tk.IntVar(value=0)
        tk.Checkbutton(frm, text=T("pwd.show"), variable=self.var_show,
                       command=self._toggle).grid(row=0, column=2, padx=6)

        if confirm:
            tk.Label(frm, text=T("pwd.confirm"), width=10,
                     anchor="w").grid(
                row=1, column=0, sticky="w", pady=4)
            self.e2 = tk.Entry(frm, show="•", width=34)
            self.e2.grid(row=1, column=1, pady=4)
            self.bar = ttk.Progressbar(self, maximum=5, length=300)
            self.bar.pack(**pad)
            self.lbl_strength = tk.Label(
                self, text=T("pwd.strength_dash"), anchor="w")
            self.lbl_strength.pack(anchor="w", padx=14)
            self.e1.bind("<KeyRelease>", self._upd_strength)

        btns = tk.Frame(self)
        btns.pack(fill="x", **pad)
        tk.Button(btns, text=T("btn.ok"), width=10,
                  command=self._ok).pack(side="right", padx=4)
        tk.Button(btns, text=T("btn.cancel"), width=10,
                  command=self._cancel).pack(side="right", padx=4)
        self.bind("<Return>", lambda e: self._ok())
        self.bind("<Escape>", lambda e: self._cancel())
        self.protocol("WM_DELETE_WINDOW", self._cancel)
        self.update_idletasks()
        self._center(parent)

    def _center(self, parent):
        self.geometry(
            f"+{parent.winfo_rootx() + 60}+{parent.winfo_rooty() + 80}")

    def _toggle(self):
        ch = "" if self.var_show.get() else "•"
        self.e1.config(show=ch)
        if self.confirm:
            self.e2.config(show=ch)

    def _upd_strength(self, _e=None):
        s, label = password_strength(self.e1.get())
        self.bar["value"] = s
        self.lbl_strength.config(text=T("pwd.strength", label=label))

    def _ok(self):
        pw = self.e1.get()
        if not pw:
            messagebox.showwarning(APP_NAME, T("pwd.enter"), parent=self)
            return
        if self.confirm:
            if pw != self.e2.get():
                messagebox.showwarning(APP_NAME, T("pwd.mismatch"),
                                       parent=self)
                return
            if len(pw) < 8:
                messagebox.showwarning(
                    APP_NAME, T("pwd.min8"), parent=self)
                return
            s, _ = password_strength(pw)
            if s < 2 and not messagebox.askyesno(
                    APP_NAME, T("pwd.weak_confirm"),
                    parent=self):
                return
        self.result = pw
        self.destroy()

    def _cancel(self):
        self.result = None
        self.destroy()

    @staticmethod
    def ask(parent, title, confirm=False, info=""):
        d = PasswordDialog(parent, title, confirm, info)
        parent.wait_window(d)
        return d.result


class ProgressDialog(tk.Toplevel):
    def __init__(self, parent, title: str):
        super().__init__(parent)
        self.title(title)
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        self.cancelled = False
        tk.Label(self, text=title, font=("", 10, "bold")).pack(
            padx=20, pady=(16, 4), anchor="w")
        self.msg = tk.Label(self, text=T("prog.preparing"),
                            anchor="w", width=52)
        self.msg.pack(padx=20, pady=4, anchor="w")
        self.bar = ttk.Progressbar(self, maximum=1000, length=380)
        self.bar.pack(padx=20, pady=8)
        self.pct = tk.Label(self, text="0%")
        self.pct.pack()
        tk.Button(self, text=T("btn.cancel"), width=10,
                  command=self._cancel).pack(pady=(8, 16))
        self.protocol("WM_DELETE_WINDOW", self._cancel)
        self.update_idletasks()
        self.geometry(
            f"+{parent.winfo_rootx() + 80}+{parent.winfo_rooty() + 120}")

    def _cancel(self):
        self.cancelled = True
        self.msg.config(text=T("prog.cancelling"))

    def set_progress(self, done: int, total: int, text: str):
        total = max(1, total)
        frac = min(1.0, done / total)
        self.bar["value"] = int(frac * 1000)
        self.pct.config(text=f"{frac * 100:.1f}%")
        if text:
            self.msg.config(text=text[:70])


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("760x520")
        self.minsize(680, 460)
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        cfg = load_json(CONFIG_PATH, {})
        if not isinstance(cfg, dict):
            cfg = {}
        preset = cfg.get("kdf_preset", "standard")
        pmode = cfg.get("pepper_mode", "app")
        lang = cfg.get("lang", "ko")
        set_lang(lang)
        self.title(T("app.title"))
        self.config_data = {
            "kdf_preset": preset if preset in KDF_PRESETS else "standard",
            "secure_delete": bool(cfg.get("secure_delete", True)),
            "pepper_mode": pmode if pmode in ("app", "keychain") else "app",
            "lang": "en" if lang == "en" else "ko",
        }
        self.registry = self._sanitize_registry(
            load_json(REGISTRY_PATH, {"vaults": []}))
        self._build_ui()
        self._refresh_list()

    # ---- 레지스트리 정규화(손상/구버전 방어) ----------------------------
    @staticmethod
    def _sanitize_registry(raw) -> dict:
        vaults = raw.get("vaults") if isinstance(raw, dict) else None
        if not isinstance(vaults, list):
            vaults = []
        out: list[dict] = []
        for v in vaults:
            if not isinstance(v, dict):
                continue
            vp = v.get("vault_path")
            if not isinstance(vp, str) or not vp:
                continue
            ext = v.get("extracted_to")
            ts = v.get("total_size")
            entry = {
                "vault_path": vp,
                "name": (v.get("name") if isinstance(v.get("name"), str)
                         else os.path.basename(vp.rstrip("\\/")) or "?"),
                "total_size": ts if isinstance(ts, (int, float)) else 0,
                "added": v.get("added") if isinstance(
                    v.get("added"), str) else "",
                "extracted_to": ext if isinstance(ext, str) and ext
                else None,
            }
            # 중복 경로 → 마지막 항목으로 대체(Treeview iid 충돌 방지)
            out = [x for x in out if x["vault_path"] != vp]
            out.append(entry)
        return {"vaults": out}

    # ---- UI 구성 ---------------------------------------------------------
    def _build_ui(self):
        top = tk.Frame(self, padx=14, pady=12)
        top.pack(fill="x")
        tk.Label(top, text=T("app.header"), font=("", 16, "bold")).pack(
            side="left")
        tk.Label(top, text=T("app.subtitle"),
                 fg="#666").pack(side="left")
        tk.Button(top, text=T("btn.settings"),
                  command=self._open_settings).pack(side="right")

        tk.Label(self, text=T_other("hint.lang"), fg="#888",
                 anchor="w", padx=14).pack(fill="x")

        body = tk.Frame(self, padx=14)
        body.pack(fill="both", expand=True)

        cols = ("name", "status", "size", "path")
        self.tree = ttk.Treeview(body, columns=cols, show="headings",
                                 height=12)
        for c, t, w in (("name", T("col.name"), 150),
                        ("status", T("col.status"), 90),
                        ("size", T("col.size"), 90),
                        ("path", T("col.path"), 380)):
            self.tree.heading(c, text=t)
            self.tree.column(c, width=w, anchor="w")
        self.tree.pack(side="left", fill="both", expand=True, pady=8)
        sb = ttk.Scrollbar(body, command=self.tree.yview)
        sb.pack(side="left", fill="y", pady=8)
        self.tree.config(yscrollcommand=sb.set)

        side = tk.Frame(self, padx=14, pady=4)
        side.pack(fill="x")
        mk = lambda txt, cmd, **kw: tk.Button(
            side, text=txt, width=18, command=cmd, **kw)
        mk(T("btn.lock"), self.lock_folder).pack(side="left", padx=3)
        mk(T("btn.open"), self.unlock_vault).pack(side="left", padx=3)
        mk(T("btn.relock"), self.relock).pack(side="left", padx=3)
        mk(T("btn.changepw"), self.change_pw).pack(side="left", padx=3)
        mk(T("btn.remove"), self.remove_from_list).pack(
            side="left", padx=3)
        tk.Button(side, text=T("btn.refresh"), width=12,
                  command=self._refresh_list).pack(side="right", padx=3)

        self.status = tk.Label(self, text=T("status.ready"),
                                anchor="w", fg="#333",
                                relief="sunken", padx=8)
        self.status.pack(fill="x", side="bottom")

    def _set_status(self, text: str):
        self.status.config(text=text)
        self.update_idletasks()

    def report_callback_exception(self, exc, val, tb):
        """Tk 콜백 예외 처리. pythonw 는 콘솔이 없어 기본 동작 시
        오류가 조용히 사라지므로, 로그를 남기고 팝업으로 알린다."""
        detail = "".join(traceback.format_exception(exc, val, tb))
        try:
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            with open(CONFIG_DIR / "crash.log", "a",
                      encoding="utf-8") as fp:
                fp.write(f"\n===== {now_iso()} (callback) =====\n"
                         f"{detail}\n")
        except Exception:
            pass
        try:
            self._set_status(T("status.error"))
        except Exception:
            pass
        try:
            last = traceback.format_exception_only(exc, val)[-1].strip()
            messagebox.showerror(
                APP_NAME,
                T("err.unexpected", last=last,
                  path=CONFIG_DIR / 'crash.log'))
        except Exception:
            pass

    def _kdf(self) -> dict:
        return KDF_PRESETS.get(
            self.config_data.get("kdf_preset", "standard"),
            KDF_PRESETS["standard"])

    def _pepper_for_create(self):
        """새 볼트용. 반환:(pmode, user_pepper). 키체인 모드면 사용자
        페퍼를 보장(없으면 생성)하고, 새로 생성됐다면 백업을 권한다."""
        if self.config_data.get("pepper_mode") != "keychain":
            return 0, None
        if not dpapi_available():
            messagebox.showwarning(
                APP_NAME, T("msg.keychain_win_only"))
            return 0, None
        try:
            up, created = ensure_user_pepper()
        except Exception as e:
            messagebox.showerror(
                APP_NAME, T("msg.keychain_prep_fail", e=e))
            return 0, None
        if created:
            messagebox.showwarning(
                APP_NAME, T("msg.keychain_created"))
        return 1, up

    def _pepper_for_open(self):
        """기존 볼트 열기용. 가능한 사용자 페퍼를 로드(없으면 None).
        볼트 자체의 pmode 가 실제 필요 여부를 결정한다."""
        if not dpapi_available():
            return None
        try:
            return load_user_pepper()
        except Exception:
            return None

    def _check_folder(self, folder: str) -> bool:
        """접근 가능하고 비어있지 않으면 True, 아니면 경고 후 False."""
        try:
            empty = not os.listdir(_lp(folder))
        except OSError as e:
            messagebox.showerror(
                APP_NAME, T("msg.folder_inaccessible", folder=folder, e=e))
            return False
        if empty:
            messagebox.showwarning(APP_NAME, T("msg.empty_folder"))
            return False
        return True

    def _confirm_overwrite(self, vault_path: str) -> bool:
        """대상 볼트 파일이 이미 있으면 덮어쓰기 확인. 진행 가능하면 True."""
        if os.path.exists(_lp(vault_path)):
            return messagebox.askyesno(
                APP_NAME, T("msg.overwrite", path=vault_path))
        return True

    # ---- 레지스트리 ------------------------------------------------------
    def _refresh_list(self):
        try:
            self.tree.delete(*self.tree.get_children())
        except tk.TclError:
            return
        seen = set()
        for v in self.registry.get("vaults", []):
            if not isinstance(v, dict):
                continue
            vp = v.get("vault_path")
            if not isinstance(vp, str) or not vp or vp in seen:
                continue
            seen.add(vp)
            vault_exists = os.path.exists(_lp(vp))
            ext = v.get("extracted_to")
            ext_exists = bool(ext) and os.path.exists(_lp(ext))
            if not vault_exists:
                status = T("st.file_missing")
            elif ext_exists:
                status = T("st.unlocked")
            else:
                status = T("st.secured")
            try:
                self.tree.insert("", "end", iid=vp, values=(
                    v.get("name", "?"), status,
                    human_size(v.get("total_size", 0) or 0), vp))
            except tk.TclError:
                continue

    def _register_vault(self, vault_path, name, total_size,
                        extracted_to=None):
        vs = [x for x in self.registry["vaults"]
              if x["vault_path"] != vault_path]
        vs.append({"vault_path": vault_path, "name": name,
                   "total_size": total_size, "added": now_iso(),
                   "extracted_to": extracted_to})
        self.registry["vaults"] = vs
        save_json(REGISTRY_PATH, self.registry)
        self._refresh_list()

    def _selected_vault(self) -> str | None:
        sel = self.tree.selection()
        return sel[0] if sel else None

    # ---- 백그라운드 작업 실행 -------------------------------------------
    def _run_bg(self, title, work, on_success):
        """work(progress_cb, cancel_cb) 를 스레드로 실행."""
        dlg = ProgressDialog(self, title)
        q: queue.Queue = queue.Queue()

        def progress_cb(done, total, text):
            q.put(("progress", done, total, text))

        def cancel_cb():
            return dlg.cancelled

        def runner():
            try:
                result = work(progress_cb, cancel_cb)
                q.put(("done", result))
            except InterruptedError as e:
                q.put(("cancelled", str(e)))
            except Exception as e:
                q.put(("error", e, traceback.format_exc()))

        threading.Thread(target=runner, daemon=True).start()

        def poll():
            try:
                while True:
                    item = q.get_nowait()
                    kind = item[0]
                    if kind == "progress":
                        dlg.set_progress(item[1], item[2], item[3])
                    elif kind == "done":
                        dlg.destroy()
                        on_success(item[1])
                        return
                    elif kind == "cancelled":
                        dlg.destroy()
                        self._set_status(T("cancel.status"))
                        messagebox.showinfo(APP_NAME, T("cancel.msg"))
                        return
                    elif kind == "error":
                        dlg.destroy()
                        self._set_status(T("status.error"))
                        messagebox.showerror(
                            APP_NAME, T("err.generic", e=item[1]))
                        return
            except queue.Empty:
                pass
            self.after(80, poll)

        self.after(80, poll)

    # ---- 원본 폴더 처리 방식 확인(파괴적 작업 동의) --------------------
    def _ask_original_policy(self, folder: str):
        """반환: None=취소, True=원본 삭제, False=원본 유지."""
        choice = messagebox.askyesnocancel(
            APP_NAME, T("msg.original_policy", folder=folder))
        if choice is None:
            return None
        if not choice:
            return False
        confirm = messagebox.askyesno(
            APP_NAME, T("msg.original_final", folder=folder),
            icon="warning", default="no")
        return True if confirm else None

    # ---- 기능: 폴더 잠그기 ----------------------------------------------
    def lock_folder(self):
        folder = filedialog.askdirectory(title=T("title.lock_folder"))
        if not folder:
            return
        folder = os.path.abspath(folder)
        if not self._check_folder(folder):
            return
        default_vault = folder.rstrip("\\/") + VAULT_EXT
        vault_path = filedialog.asksaveasfilename(
            title=T("title.save_vault"),
            initialfile=os.path.basename(default_vault),
            initialdir=os.path.dirname(default_vault),
            defaultextension=VAULT_EXT,
            filetypes=[("FolderVault", "*" + VAULT_EXT)])
        if not vault_path:
            return
        if not self._confirm_overwrite(vault_path):
            return
        if path_is_within(vault_path, folder) or \
                path_is_within(vault_path + ".tmp", folder):
            messagebox.showerror(
                APP_NAME, T("msg.vault_inside"))
            return

        pw = PasswordDialog.ask(
            self, T("title.set_new_pw"), confirm=True,
            info=T("info.new_pw"))
        if not pw:
            return

        policy = self._ask_original_policy(folder)
        if policy is None:
            return
        delete_original = policy
        secure = self.config_data.get("secure_delete", True)
        kdf = self._kdf()
        pmode, upep = self._pepper_for_create()
        self._set_status(T("status.encrypting"))

        def work(progress_cb, cancel_cb):
            info = Vault.create_from_folder(
                folder, vault_path, pw, kdf,
                progress=progress_cb, cancel=cancel_cb,
                pmode=pmode, user_pepper=upep)
            info["delete_failed"] = []
            info["folder_remains"] = False
            if delete_original:
                progress_cb(0, 1, T("prog.delete_original"))
                info["delete_failed"] = secure_delete_listed(
                    folder, info["file_paths"], info["dir_paths"],
                    secure=secure)
                info["folder_remains"] = os.path.exists(_lp(folder))
            return info

        def done(info):
            self._lock_done(info, vault_path, folder, delete_original)

        self._run_bg(T("task.encrypt"), work, done)

    def _lock_done(self, info, vault_path, folder, delete_original):
        """잠그기/다시잠그기 공통 결과 처리 — 삭제 결과를 정직하게 반영."""
        failed = info.get("delete_failed", [])
        remains = info.get("folder_remains", False)
        if not delete_original:
            self._register_vault(vault_path, info["name"],
                                 info["total_size"], extracted_to=folder)
            self._set_status(T("status.done_keep", name=info['name']))
            messagebox.showinfo(
                APP_NAME, T("msg.done_keep", vault=vault_path))
            return
        if failed:
            # 평문이 일부 남음 → 보안 미완성. 정직하게 경고 + 상태 반영.
            self._register_vault(vault_path, info["name"],
                                 info["total_size"], extracted_to=folder)
            shown = "\n".join("  - " + p for p in failed[:10])
            more = (T("list.more", n=len(failed) - 10)
                    if len(failed) > 10 else "")
            self._set_status(T("status.partial_del"))
            messagebox.showwarning(
                APP_NAME, T("msg.partial_del", shown=shown, more=more,
                            vault=vault_path))
            return
        # 우리 데이터의 평문은 모두 제거됨 → 보안 완료.
        self._register_vault(vault_path, info["name"],
                             info["total_size"], extracted_to=None)
        if remains:
            self._set_status(T("status.done_remain", name=info['name']))
            messagebox.showinfo(
                APP_NAME, T("msg.done_remain", folder=folder,
                            vault=vault_path))
        else:
            self._set_status(T("status.done_lock", name=info['name'],
                                entries=info['entries']))
            messagebox.showinfo(
                APP_NAME, T("msg.done_lock", vault=vault_path))

    # ---- 기능: 보안 폴더 열기 -------------------------------------------
    def unlock_vault(self):
        vault_path = self._selected_vault()
        if not vault_path or not os.path.exists(_lp(vault_path)):
            vault_path = filedialog.askopenfilename(
                title=T("title.choose_vault"),
                filetypes=[("FolderVault", "*" + VAULT_EXT),
                           (T("ft.all_files"), "*.*")])
        if not vault_path:
            return
        pw = PasswordDialog.ask(
            self, T("title.enter_pw"),
            info=T("info.vault", name=os.path.basename(vault_path)))
        if not pw:
            return
        upep = self._pepper_for_open()
        try:
            self._set_status(T("status.checking_pw"))
            header = Vault(vault_path).read_header(pw, user_pepper=upep)
        except WrongPasswordOrCorrupt as e:
            self._set_status(T("status.open_fail"))
            messagebox.showerror(APP_NAME, str(e))
            return

        dest_parent = filedialog.askdirectory(
            title=T("title.restore_where", name=header['_folder_name']))
        if not dest_parent:
            return
        final = os.path.join(dest_parent, header["_folder_name"])
        if os.path.exists(_lp(final)):
            messagebox.showerror(
                APP_NAME, T("msg.same_name", final=final))
            return

        keep = messagebox.askyesnocancel(
            APP_NAME, T("msg.keep_vault"))
        if keep is None:
            return

        secure = self.config_data.get("secure_delete", True)
        self._set_status(T("status.decrypting"))

        def work(progress_cb, cancel_cb):
            out = Vault(vault_path).extract_to(
                pw, dest_parent, progress=progress_cb, cancel=cancel_cb,
                user_pepper=upep)
            vault_deleted = True
            if not keep:
                progress_cb(0, 1, T("prog.delete_vault"))
                vault_deleted = (secure_delete_file(vault_path) if secure
                                 else _plain_delete_file(vault_path))
            return {"out": out, "vault_deleted": vault_deleted}

        def reg_extracted(out):
            self._register_vault(
                vault_path,
                header.get("name") or header.get("_folder_name", "?"),
                header.get("_total_size", 0), extracted_to=out)

        def done(res):
            out = res["out"]
            if not keep and res["vault_deleted"]:
                self.registry["vaults"] = [
                    x for x in self.registry["vaults"]
                    if isinstance(x, dict)
                    and x.get("vault_path") != vault_path]
                save_json(REGISTRY_PATH, self.registry)
                self._refresh_list()
                self._set_status(T("status.restore_done_del", out=out))
                messagebox.showinfo(
                    APP_NAME, T("msg.restore_done_del", out=out))
            elif not keep and not res["vault_deleted"]:
                # 삭제 실패 → 볼트가 그대로 존재. 목록 유지 + 정직히 경고.
                reg_extracted(out)
                self._set_status(T("status.restore_done_delfail"))
                messagebox.showwarning(
                    APP_NAME, T("msg.restore_done_delfail", out=out,
                                vault=vault_path))
            else:
                reg_extracted(out)
                self._set_status(T("status.restore_done", out=out))
                messagebox.showinfo(
                    APP_NAME, T("msg.restore_done", out=out))

        self._run_bg(T("task.decrypt"), work, done)

    # ---- 기능: 다시 잠그기 ----------------------------------------------
    def relock(self):
        folder = filedialog.askdirectory(
            title=T("title.relock_folder"))
        if not folder:
            return
        folder = os.path.abspath(folder)
        if not self._check_folder(folder):
            return
        default_vault = folder.rstrip("\\/") + VAULT_EXT
        vault_path = filedialog.asksaveasfilename(
            title=T("title.save_vault2"),
            initialfile=os.path.basename(default_vault),
            initialdir=os.path.dirname(default_vault),
            defaultextension=VAULT_EXT,
            filetypes=[("FolderVault", "*" + VAULT_EXT)])
        if not vault_path:
            return
        if not self._confirm_overwrite(vault_path):
            return
        if path_is_within(vault_path, folder) or \
                path_is_within(vault_path + ".tmp", folder):
            messagebox.showerror(
                APP_NAME, T("msg.vault_inside2"))
            return
        pw = PasswordDialog.ask(self, T("title.set_pw"), confirm=True,
                                info=T("info.relock"))
        if not pw:
            return
        policy = self._ask_original_policy(folder)
        if policy is None:
            return
        delete_original = policy
        secure = self.config_data.get("secure_delete", True)
        kdf = self._kdf()
        pmode, upep = self._pepper_for_create()

        def work(progress_cb, cancel_cb):
            info = Vault.create_from_folder(
                folder, vault_path, pw, kdf,
                progress=progress_cb, cancel=cancel_cb,
                pmode=pmode, user_pepper=upep)
            info["delete_failed"] = []
            info["folder_remains"] = False
            if delete_original:
                progress_cb(0, 1, T("prog.delete_original"))
                info["delete_failed"] = secure_delete_listed(
                    folder, info["file_paths"], info["dir_paths"],
                    secure=secure)
                info["folder_remains"] = os.path.exists(_lp(folder))
            return info

        def done(info):
            self._lock_done(info, vault_path, folder, delete_original)

        self._run_bg(T("task.encrypt"), work, done)

    # ---- 기능: 비밀번호 변경 --------------------------------------------
    def change_pw(self):
        vault_path = self._selected_vault()
        if not vault_path or not os.path.exists(_lp(vault_path)):
            vault_path = filedialog.askopenfilename(
                title=T("title.choose_vault"),
                filetypes=[("FolderVault", "*" + VAULT_EXT)])
        if not vault_path:
            return
        old = PasswordDialog.ask(self, T("title.cur_pw"))
        if not old:
            return
        src_upep = self._pepper_for_open()
        try:
            Vault(vault_path).read_header(old, user_pepper=src_upep)
        except WrongPasswordOrCorrupt as e:
            messagebox.showerror(APP_NAME, str(e))
            return
        new = PasswordDialog.ask(self, T("title.new_pw"), confirm=True)
        if not new:
            return
        kdf = self._kdf()
        secure = self.config_data.get("secure_delete", True)
        new_pmode, new_upep = self._pepper_for_create()

        def work(progress_cb, cancel_cb):
            Vault(vault_path).change_password(
                old, new, kdf, progress=progress_cb, secure=secure,
                src_user_pepper=src_upep,
                pmode=new_pmode, user_pepper=new_upep)
            return True

        def done(_):
            self._set_status(T("status.pw_changed"))
            messagebox.showinfo(APP_NAME, T("msg.pw_changed"))

        self._run_bg(T("task.changepw"), work, done)

    # ---- 기능: 목록에서 제거 --------------------------------------------
    def remove_from_list(self):
        vp = self._selected_vault()
        if not vp:
            messagebox.showinfo(APP_NAME, T("msg.select_item"))
            return
        if not messagebox.askyesno(
                APP_NAME, T("msg.remove_confirm")):
            return
        self.registry["vaults"] = [
            x for x in self.registry["vaults"] if x["vault_path"] != vp]
        save_json(REGISTRY_PATH, self.registry)
        self._refresh_list()
        self._set_status(T("status.removed"))

    # ---- 설정 ------------------------------------------------------------
    def _open_settings(self):
        d = tk.Toplevel(self)
        d.title(T("title.settings"))
        d.resizable(False, False)
        d.transient(self)
        d.grab_set()

        lang_var = tk.StringVar(value=self.config_data.get("lang", "ko"))
        tk.Label(d, text=T("set.lang_title"), font=("", 10, "bold")).pack(
            anchor="w", padx=16, pady=(14, 4))
        tk.Radiobutton(d, text=T("set.lang_ko"), variable=lang_var,
                       value="ko").pack(anchor="w", padx=24)
        tk.Radiobutton(d, text=T("set.lang_en"), variable=lang_var,
                       value="en").pack(anchor="w", padx=24)

        tk.Label(d, text=T("set.kdf_title"), font=("", 10, "bold")).pack(
            anchor="w", padx=16, pady=(14, 4))
        preset = tk.StringVar(value=self.config_data.get("kdf_preset",
                                                         "standard"))
        tk.Radiobutton(
            d, text=T("set.kdf_std"),
            variable=preset, value="standard").pack(anchor="w", padx=24)
        tk.Radiobutton(
            d, text=T("set.kdf_high"),
            variable=preset, value="high").pack(anchor="w", padx=24)
        tk.Radiobutton(
            d, text=T("set.kdf_para"),
            variable=preset, value="paranoid").pack(anchor="w", padx=24)

        sd = tk.IntVar(value=1 if self.config_data.get(
            "secure_delete", True) else 0)
        tk.Label(d, text=T("set.del_title"), font=("", 10, "bold")).pack(
            anchor="w", padx=16, pady=(14, 4))
        tk.Checkbutton(
            d, text=T("set.del_secure"),
            variable=sd).pack(anchor="w", padx=24)
        tk.Label(
            d, fg="#888", justify="left", wraplength=380,
            text=T("set.del_note")).pack(
            anchor="w", padx=24, pady=4)

        tk.Label(d, text=T("set.pep_title"),
                 font=("", 10, "bold")).pack(
            anchor="w", padx=16, pady=(14, 4))
        pep = tk.StringVar(value=self.config_data.get("pepper_mode", "app"))
        tk.Radiobutton(
            d, text=T("set.pep_app"),
            variable=pep, value="app").pack(anchor="w", padx=24)
        tk.Radiobutton(
            d, text=T("set.pep_kc"),
            variable=pep, value="keychain").pack(anchor="w", padx=24)
        tk.Label(
            d, fg="#a00", justify="left", wraplength=380,
            text=T("set.pep_warn")).pack(
            anchor="w", padx=24, pady=4)
        if not dpapi_available():
            tk.Label(d, fg="#888",
                     text=T("set.kc_win_only")).pack(
                anchor="w", padx=24)

        def backup_pepper():
            up = load_user_pepper() if dpapi_available() else None
            if up is None:
                messagebox.showinfo(
                    APP_NAME, T("msg.no_pep_backup"), parent=d)
                return
            p = filedialog.asksaveasfilename(
                title=T("title.pep_backup"),
                defaultextension=".pepper",
                filetypes=[(T("ft.pepper"), "*.pepper")])
            if not p:
                return
            try:
                with open(_lp(p), "w", encoding="ascii") as fp:
                    fp.write(up.hex())
                messagebox.showwarning(
                    APP_NAME, T("msg.pep_backed"), parent=d)
            except OSError as e:
                messagebox.showerror(
                    APP_NAME, T("err.backup_fail", e=e), parent=d)

        def restore_pepper():
            if not dpapi_available():
                messagebox.showwarning(
                    APP_NAME, T("msg.win_only"), parent=d)
                return
            p = filedialog.askopenfilename(
                title=T("title.pep_restore"),
                filetypes=[(T("ft.pepper"), "*.pepper"),
                           (T("ft.all_files"), "*.*")])
            if not p:
                return
            try:
                up = bytes.fromhex(
                    open(_lp(p), "r", encoding="ascii").read().strip())
                if len(up) != 32:
                    raise ValueError(T("err.pep_badfmt"))
                store_user_pepper(up)
                messagebox.showinfo(
                    APP_NAME, T("msg.pep_restored"), parent=d)
            except Exception as e:
                messagebox.showerror(
                    APP_NAME, T("err.restore_fail", e=e), parent=d)

        bf = tk.Frame(d)
        bf.pack(anchor="w", padx=24, pady=(2, 4))
        tk.Button(bf, text=T("btn.pep_backup"),
                  command=backup_pepper).pack(side="left", padx=(0, 6))
        tk.Button(bf, text=T("btn.pep_restore"),
                  command=restore_pepper).pack(side="left")

        def save():
            lang_changed = (lang_var.get() != self.config_data.get("lang"))
            self.config_data["kdf_preset"] = preset.get()
            self.config_data["secure_delete"] = bool(sd.get())
            self.config_data["pepper_mode"] = pep.get()
            self.config_data["lang"] = lang_var.get()
            save_json(CONFIG_PATH, self.config_data)
            d.destroy()
            self._set_status(T("status.settings_saved"))
            if lang_changed:
                messagebox.showinfo(
                    APP_NAME,
                    T_lang("msg.lang_restart", lang_var.get()))

        tk.Button(d, text=T("btn.save"), width=12,
                  command=save).pack(pady=16)
        d.geometry(f"+{self.winfo_rootx()+90}+{self.winfo_rooty()+90}")


def main():
    try:
        app = App()
        app.mainloop()
    except BaseException:
        # pythonw.exe 는 콘솔이 없어 오류가 안 보이므로,
        # 크래시 로그를 남기고 가능하면 팝업으로 알린다.
        tb = traceback.format_exc()
        try:
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            log = CONFIG_DIR / "crash.log"
            with open(log, "a", encoding="utf-8") as fp:
                fp.write(f"\n===== {now_iso()} =====\n{tb}\n")
        except Exception:
            log = T("log.fail")
        try:
            import tkinter as _tk
            from tkinter import messagebox as _mb
            _r = _tk.Tk()
            _r.withdraw()
            _mb.showerror(
                APP_NAME,
                T("msg.start_error",
                  line=tb.strip().splitlines()[-1], log=log))
            _r.destroy()
        except Exception:
            pass
        raise


if __name__ == "__main__":
    main()
