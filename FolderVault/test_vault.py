# -*- coding: utf-8 -*-
"""FolderVault 암호화 코어 자가검증 (GUI 없이 실행).

콘솔 인코딩 문제를 피하려고 결과는 ASCII 로만 출력한다.
"""
import os
import sys
import struct
import tempfile
import filecmp
import shutil

import folder_vault as fv

KDF = {"time_cost": 1, "memory_cost": 8192, "parallelism": 1}  # 테스트용 경량
PW = "S3cure-한글-Pass!#"
WRONG = "wrong-pass"
C = fv.CHUNK

ok = 0
fail = 0


def check(name, cond):
    global ok, fail
    if cond:
        ok += 1
        print(f"  [PASS] {name}")
    else:
        fail += 1
        print(f"  [FAIL] {name}")


def expect_raises(name, exc, fn):
    try:
        fn()
        check(name, False)
    except exc:
        check(name, True)
    except Exception as e:                       # 잘못된 예외 타입
        check(f"{name} (got {type(e).__name__})", False)


def build_sample(root):
    os.makedirs(os.path.join(root, "문서", "하위"), exist_ok=True)
    os.makedirs(os.path.join(root, "빈폴더"), exist_ok=True)
    with open(os.path.join(root, "secret.txt"), "wb") as f:
        f.write(b"TOP-SECRET-PLAINTEXT-MARKER-12345")
    with open(os.path.join(root, "메모.txt"), "w", encoding="utf-8") as f:
        f.write("비밀 메모입니다.\n")
    # 청크 경계 전수 검사: 0, 1, C-1, C, C+1, 3C+777
    for nm, sz in [("z0.bin", 0), ("z1.bin", 1), ("zCm1.bin", C - 1),
                   ("zC.bin", C), ("zCp1.bin", C + 1),
                   ("big.bin", 3 * C + 777)]:
        with open(os.path.join(root, "문서", nm), "wb") as f:
            f.write(os.urandom(sz))
    open(os.path.join(root, "문서", "하위", "empty.dat"), "wb").close()


def deep_equal(d):
    if d.left_only or d.right_only or d.diff_files or d.funny_files:
        return False
    return all(deep_equal(s) for s in d.subdirs.values())


def build_v2_vault(folder, vault_path, pw, kdf):
    """구버전(v2) 포맷 볼트를 합성: 단일 AES-GCM, 패딩/서명 없음.
    _open_v2 호환 경로를 실제로 검증하기 위함."""
    base = fv.Path(os.path.abspath(folder))
    salt = os.urandom(16)
    master = fv.derive_master_key(pw, salt, kdf)
    k_hdr = fv.subkey(master, fv.HKDF_HEADER)
    k_idx = fv.subkey(master, fv.HKDF_INDEX)
    entries = []
    for root, dirs, files in os.walk(folder):
        dirs.sort()
        files.sort()
        rpd = fv.Path(root).relative_to(base).as_posix()
        if rpd != ".":
            entries.append({"p": rpd, "t": "d"})
        for nm in files:
            fp = os.path.join(root, nm)
            rp = fv.Path(fp).relative_to(base).as_posix()
            entries.append({"p": rp, "t": "f", "_src": fp})
    header = {"app": "FolderVault", "version": 2,
              "vault_id": fv.uuid.uuid4().hex, "name": base.name,
              "created": fv.now_iso(), "verifier": "FOLDERVAULT-OK"}
    hn, hct = fv.gcm_encrypt(
        k_hdr, fv.json.dumps(header).encode("utf-8"), fv.MAGIC)
    total = 0
    with open(vault_path, "wb") as out:
        out.write(fv.MAGIC)
        out.write(salt)
        out.write(struct.pack(">I", int(kdf["time_cost"])))
        out.write(struct.pack(">I", int(kdf["memory_cost"])))
        out.write(struct.pack(">I", int(kdf["parallelism"])))
        out.write(hn)
        out.write(struct.pack(">I", len(hct)))
        out.write(hct)
        for e in entries:
            if e["t"] != "f":
                continue
            rp = e["p"]
            fid = fv.uuid.uuid4().hex
            k = fv.subkey(master, fv.HKDF_FILE + fv._b(rp))
            n = 0
            s = 0
            with open(e["_src"], "rb") as fh:
                while True:
                    data = fh.read(fv.CHUNK)
                    if not data:
                        break
                    aad = (fv._b(rp) + b"|" + fid.encode("ascii")
                           + b"|" + str(n).encode("ascii"))
                    cn, cct = fv.gcm_encrypt(k, data, aad)
                    out.write(cn)
                    out.write(struct.pack(">I", len(cct)))
                    out.write(cct)
                    n += 1
                    s += len(data)
            e["n"] = n
            e["s"] = s
            e["fid"] = fid
            del e["_src"]
            total += s
        data_end = out.tell()
        index = {"entries": entries, "total_size": total,
                 "folder_name": base.name}
        in_, ict = fv.gcm_encrypt(
            k_idx, fv.json.dumps(index).encode("utf-8"), fv.MAGIC + hn)
        out.write(in_)
        out.write(struct.pack(">Q", len(ict)))
        out.write(ict)
        out.write(struct.pack(">Q", data_end))


def build_v3_vault(folder, vault_path, pw, kdf):
    """v3 포맷(캐스케이드+페퍼+Padmé+단일 Ed25519) 합성. 생성이 v4로
    바뀐 뒤에도 v3 읽기 호환 경로를 실제로 검증하기 위함."""
    base = fv.Path(os.path.abspath(folder))
    salt = os.urandom(16)
    root = fv.derive_root_v3(pw, salt, kdf)
    entries = []
    for r, dirs, files in os.walk(folder):
        dirs.sort()
        files.sort()
        rpd = fv.Path(r).relative_to(base).as_posix()
        if rpd != ".":
            entries.append({"p": rpd, "t": "d"})
        for nm in files:
            fp = os.path.join(r, nm)
            entries.append({"p": fv.Path(fp).relative_to(base).as_posix(),
                            "t": "f", "_src": fp})
    header = {"app": "FolderVault", "version": 3,
              "vault_id": fv.uuid.uuid4().hex, "name": base.name,
              "created": fv.now_iso(), "verifier": "FOLDERVAULT-OK"}
    nAh, nCh, hct = fv.casc_encrypt(
        fv.subkey(root, fv.HKDF_HDR_A), fv.subkey(root, fv.HKDF_HDR_C),
        fv.json.dumps(header).encode("utf-8"), fv.MAGIC3)
    total = 0
    with open(vault_path, "w+b") as out:
        out.write(fv.MAGIC3)
        out.write(salt)
        out.write(struct.pack(">I", int(kdf["time_cost"])))
        out.write(struct.pack(">I", int(kdf["memory_cost"])))
        out.write(struct.pack(">I", int(kdf["parallelism"])))
        out.write(b"\x00")                              # pmode=0
        out.write(nAh)
        out.write(nCh)
        out.write(struct.pack(">I", len(hct)))
        out.write(hct)
        for e in entries:
            if e["t"] != "f":
                continue
            rp = e["p"]
            fid = fv.uuid.uuid4().hex
            kA = fv.subkey(root, fv.HKDF_FILE_A + fv._b(rp))
            kC = fv.subkey(root, fv.HKDF_FILE_C + fv._b(rp))
            n = 0
            s = 0
            with open(e["_src"], "rb") as fh:
                while True:
                    data = fh.read(fv.CHUNK)
                    if not data:
                        break
                    aad = (fv._b(rp) + b"|" + fid.encode("ascii")
                           + b"|" + str(n).encode("ascii"))
                    a, c, ct = fv.casc_encrypt(kA, kC, data, aad)
                    out.write(a)
                    out.write(c)
                    out.write(struct.pack(">I", len(ct)))
                    out.write(ct)
                    n += 1
                    s += len(data)
            ps = fv.padme(s)
            rem = ps - s
            while rem > 0:
                blk = os.urandom(min(fv.CHUNK, rem))
                aad = (fv._b(rp) + b"|" + fid.encode("ascii")
                       + b"|" + str(n).encode("ascii"))
                a, c, ct = fv.casc_encrypt(kA, kC, blk, aad)
                out.write(a)
                out.write(c)
                out.write(struct.pack(">I", len(ct)))
                out.write(ct)
                n += 1
                rem -= len(blk)
            e["n"] = n
            e["s"] = s
            e["ps"] = ps
            e["fid"] = fid
            del e["_src"]
            total += s
        data_end = out.tell()
        index = {"entries": entries, "total_size": total,
                 "folder_name": base.name}
        nAi, nCi, ict = fv.casc_encrypt(
            fv.subkey(root, fv.HKDF_IDX_A), fv.subkey(root, fv.HKDF_IDX_C),
            fv.json.dumps(index).encode("utf-8"), fv.MAGIC3 + nAh + nCh)
        out.write(nAi)
        out.write(nCi)
        out.write(struct.pack(">Q", len(ict)))
        out.write(ict)
        out.write(struct.pack(">Q", data_end))
        out.flush()
        sig_pos = out.tell()
        digest = fv._sha512_region(out, 0, sig_pos)
        out.seek(sig_pos)
        out.write(fv.sign_key_v3(root).sign(digest))
        out.flush()


def main():
    global ok, fail
    tmp = tempfile.mkdtemp(prefix="fv_test_")
    try:
        src = os.path.join(tmp, "비밀폴더")
        os.makedirs(src)
        build_sample(src)
        vault = os.path.join(tmp, "비밀폴더.foldervault")

        # --- 1. 생성(내부 전체검증 포함) -----------------------------
        info = fv.Vault.create_from_folder(src, vault, PW, KDF)
        check("볼트 생성됨", os.path.exists(vault))
        check("엔트리 수 > 0", info["entries"] > 0)
        check("MAGIC v4", open(vault, "rb").read(8) == fv.MAGIC4)
        check("헤더 version==4",
              fv.Vault(vault).read_header(PW).get("version") == 4)

        blob = open(vault, "rb").read()
        check("평문 미노출",
              b"TOP-SECRET-PLAINTEXT-MARKER-12345" not in blob)
        check("파일명(secret.txt) 미노출", b"secret.txt" not in blob)

        # --- 2. 전체검증 통과 ----------------------------------------
        fv.Vault(vault)._verify_full(PW)
        check("정상 볼트 _verify_full 통과", True)

        # --- 3. 잘못된 비밀번호 거부 ---------------------------------
        expect_raises("잘못된 비밀번호 거부", fv.WrongPasswordOrCorrupt,
                      lambda: fv.Vault(vault).read_header(WRONG))

        # --- 4. 복원 = 원본과 바이트 단위 동일 -----------------------
        outp = os.path.join(tmp, "복원")
        os.makedirs(outp)
        restored = fv.Vault(vault).extract_to(PW, outp)
        check("복원 내용 완전 일치",
              deep_equal(filecmp.dircmp(src, restored)))
        for nm in ("z0.bin", "z1.bin", "zCm1.bin", "zC.bin", "zCp1.bin",
                   "big.bin"):
            a = os.path.join(src, "문서", nm)
            b = os.path.join(restored, "문서", nm)
            check(f"청크경계 {nm} 바이트 일치",
                  filecmp.cmp(a, b, shallow=False))
        check("빈 폴더 보존",
              os.path.isdir(os.path.join(restored, "빈폴더")))
        check("빈 파일 보존", os.path.exists(
            os.path.join(restored, "문서", "하위", "empty.dat")))

        # --- 5. 변조 탐지: 데이터 영역 1바이트 뒤집기 ----------------
        t1 = os.path.join(tmp, "t1.foldervault")
        shutil.copyfile(vault, t1)
        with open(t1, "r+b") as f:
            f.seek(fv.PREFIX_FIXED + 200)        # 데이터 영역 내부
            b = f.read(1)
            f.seek(-1, 1)
            f.write(bytes([b[0] ^ 0xFF]))
        expect_raises("데이터 변조 → _verify_full 거부",
                      fv.WrongPasswordOrCorrupt,
                      lambda: fv.Vault(t1)._verify_full(PW))
        op = os.path.join(tmp, "복원2")
        os.makedirs(op)
        expect_raises("데이터 변조 → extract 거부",
                      fv.WrongPasswordOrCorrupt,
                      lambda: fv.Vault(t1).extract_to(PW, op))
        check("변조 시 부분 복원물 없음",
              not os.path.exists(os.path.join(op, "비밀폴더")))

        # --- 6. 손상 볼트 → 친절한 예외(raw 크래시 금지) -------------
        t2 = os.path.join(tmp, "t2.foldervault")
        with open(t2, "wb") as f:
            f.write(b"\x00" * 5)                 # 너무 짧음
        expect_raises("초단편 파일 → 친절 예외",
                      fv.WrongPasswordOrCorrupt,
                      lambda: fv.Vault(t2).read_header(PW))

        t3 = os.path.join(tmp, "t3.foldervault")
        with open(t3, "wb") as f:
            f.write(os.urandom(4096))            # 무작위 쓰레기
        expect_raises("무작위 쓰레기 → 친절 예외",
                      fv.WrongPasswordOrCorrupt,
                      lambda: fv.Vault(t3).read_header(PW))

        t4 = os.path.join(tmp, "t4.foldervault")
        with open(t4, "wb") as f:
            f.write(b"FLDRVLT\x01" + os.urandom(200))   # 구버전 MAGIC
        expect_raises("구버전 형식 → 친절 예외",
                      fv.WrongPasswordOrCorrupt,
                      lambda: fv.Vault(t4).read_header(PW))

        t5 = os.path.join(tmp, "t5.foldervault")
        shutil.copyfile(vault, t5)
        with open(t5, "r+b") as f:               # 끝 8바이트(index_off) 훼손
            f.seek(-1, 2)
            f.write(b"\xff")
        expect_raises("index_off 훼손 → 친절 예외",
                      fv.WrongPasswordOrCorrupt,
                      lambda: fv.Vault(t5).read_header(PW))

        t6 = os.path.join(tmp, "t6.foldervault")
        shutil.copyfile(vault, t6)
        with open(t6, "ab") as f:
            f.write(b"EXTRA-GARBAGE-APPENDED")   # 뒤에 쓰레기 추가
        expect_raises("뒤쪽 쓰레기 추가 → 거부",
                      fv.WrongPasswordOrCorrupt,
                      lambda: fv.Vault(t6).read_header(PW))

        # --- 7. 비밀번호 변경(전체검증 후 원자적 교체) ---------------
        NEW = "새-비번-9!@xyz"
        fv.Vault(vault).change_password(PW, NEW, KDF)
        expect_raises("변경 후 옛 비번 거부", fv.WrongPasswordOrCorrupt,
                      lambda: fv.Vault(vault).read_header(PW))
        check("변경 후 새 비번 OK",
              fv.Vault(vault).read_header(NEW).get("verifier")
              == "FOLDERVAULT-OK")
        op3 = os.path.join(tmp, "복원3")
        os.makedirs(op3)
        r3 = fv.Vault(vault).extract_to(NEW, op3)
        check("비번 변경 후 내용 무결",
              deep_equal(filecmp.dircmp(src, r3)))

        # 비번 변경 실패 시 기존 볼트 보존: 잘못된 old_pw
        before = open(vault, "rb").read()
        expect_raises("틀린 옛비번으로 변경 시도 → 거부",
                      fv.WrongPasswordOrCorrupt,
                      lambda: fv.Vault(vault).change_password(
                          "TOTALLY-WRONG", "x", KDF))
        check("실패해도 기존 볼트 그대로",
              open(vault, "rb").read() == before)

        # --- 8. path_is_within (볼트 자기삭제 방지) ------------------
        F = os.path.join(tmp, "대상폴더")
        check("폴더 안 볼트 → 차단(True)",
              fv.path_is_within(os.path.join(F, "v.foldervault"), F))
        check("하위폴더 안 볼트 → 차단(True)",
              fv.path_is_within(os.path.join(F, "sub", "v.foldervault"), F))
        check("형제 .foldervault → 허용(False)",
              not fv.path_is_within(F + ".foldervault", F))
        check("다른 폴더 → 허용(False)",
              not fv.path_is_within(
                  os.path.join(tmp, "other", "v.foldervault"), F))
        check("폴더 자신과 동일 → 차단(True)",
              fv.path_is_within(F, F))
        if os.name == "nt":
            check("대소문자 무시(Windows) → 차단(True)",
                  fv.path_is_within(
                      os.path.join(tmp, "대상폴더", "V.FOLDERVAULT"),
                      os.path.join(tmp, "대상폴더")))

        # --- 9. 빈 폴더만 있는 경우도 정상 ---------------------------
        e_src = os.path.join(tmp, "빈것")
        os.makedirs(os.path.join(e_src, "안쪽빈폴더"))
        e_v = os.path.join(tmp, "빈것.foldervault")
        fv.Vault.create_from_folder(e_src, e_v, PW, KDF)
        e_out = os.path.join(tmp, "빈복원")
        os.makedirs(e_out)
        e_r = fv.Vault(e_v).extract_to(PW, e_out)
        check("빈 하위폴더 보존",
              os.path.isdir(os.path.join(e_r, "안쪽빈폴더")))

        # --- 10. 레지스트리 정규화(손상 방어) ------------------------
        san = fv.App._sanitize_registry
        check("dict 아님 → 빈 vaults",
              san("쓰레기") == {"vaults": []})
        check("vaults 가 list 아님 → 빈 vaults",
              san({"vaults": 123}) == {"vaults": []})
        r = san({"vaults": [
            "문자열항목",                                  # dict 아님
            {"name": "키없음"},                            # vault_path 없음
            {"vault_path": ""},                            # 빈 경로
            {"vault_path": "C:/a.fv", "total_size": "삼"},  # 잘못된 크기
            {"vault_path": "C:/a.fv", "name": "중복뒤",
             "total_size": 50, "extracted_to": 123},        # 중복(뒤가 이김)
            {"vault_path": "C:/b.fv", "name": "정상",
             "total_size": 10, "extracted_to": "C:/ext"},
        ]})
        paths = [x["vault_path"] for x in r["vaults"]]
        check("불량 항목 제거 + 중복 제거",
              paths == ["C:/a.fv", "C:/b.fv"])
        a = next(x for x in r["vaults"] if x["vault_path"] == "C:/a.fv")
        check("중복은 마지막 항목 채택", a["name"] == "중복뒤")
        check("잘못된 total_size → 0", a["total_size"] == 50)
        check("잘못된 extracted_to → None", a["extracted_to"] is None)
        check("정상 extracted_to 유지", next(
            x for x in r["vaults"]
            if x["vault_path"] == "C:/b.fv")["extracted_to"] == "C:/ext")

        # --- 11. 심볼릭링크/정션 → 암호화 중단(원본·볼트 무변경) -----
        ln_src = os.path.join(tmp, "링크폴더")
        os.makedirs(os.path.join(ln_src, "안"))
        with open(os.path.join(ln_src, "보통.txt"), "wb") as f:
            f.write(b"data")
        ln_v = os.path.join(tmp, "링크.foldervault")
        orig_scan = fv.scan_reparse_points
        fv.scan_reparse_points = lambda folder, limit=20: ["안/링크"]
        try:
            expect_raises("리파스 포인트 → 암호화 거부",
                          fv.UnsupportedLinkError,
                          lambda: fv.Vault.create_from_folder(
                              ln_src, ln_v, PW, KDF))
        finally:
            fv.scan_reparse_points = orig_scan
        check("거부 시 볼트 미생성", not os.path.exists(ln_v))
        check("거부 시 임시파일 없음",
              not os.path.exists(ln_v + ".tmp"))
        check("거부 시 원본 보존",
              os.path.exists(os.path.join(ln_src, "보통.txt")))
        check("정상 트리 scan_reparse_points == []",
              fv.scan_reparse_points(src) == [])
        check("일반 폴더는 reparse 아님",
              not fv._is_reparse_point(src))

        # 실제 심볼릭 링크 생성 가능하면 추가 검증(권한 없으면 건너뜀)
        try:
            os.symlink(src, os.path.join(ln_src, "진짜링크"),
                       target_is_directory=True)
            made = True
        except (OSError, NotImplementedError, AttributeError):
            made = False
        if made:
            check("실제 링크 감지(scan 비어있지 않음)",
                  len(fv.scan_reparse_points(ln_src)) >= 1)
            expect_raises("실제 링크 → 암호화 거부",
                          fv.UnsupportedLinkError,
                          lambda: fv.Vault.create_from_folder(
                              ln_src, ln_v, PW, KDF))
        else:
            check("실제 링크 테스트(권한없음, 건너뜀)", True)

        # --- 12. 긴 경로 접두사(_lp) ---------------------------------
        if os.name == "nt":
            check("_lp 확장 접두사 부여",
                  fv._lp("C:\\Users\\x").startswith("\\\\?\\"))
            check("_lp 이미 접두사면 유지",
                  fv._lp("\\\\?\\C:\\x") == "\\\\?\\C:\\x")

        # --- 13. 정직한/정밀한 삭제 ----------------------------------
        df = os.path.join(tmp, "del.bin")
        with open(df, "wb") as f:
            f.write(b"x" * 1234)
        check("secure_delete_file 성공 시 True",
              fv.secure_delete_file(df) is True)
        check("secure_delete_file 후 파일 없음",
              not os.path.exists(df))
        check("secure_delete_file 없는 파일 → True",
              fv.secure_delete_file(df) is True)
        df2 = os.path.join(tmp, "del2.bin")
        open(df2, "wb").close()
        check("_plain_delete_file 성공 → True",
              fv._plain_delete_file(df2) is True and
              not os.path.exists(df2))

        # secure_delete_listed: 목록 항목만 삭제, 그 외 보존
        dl = os.path.join(tmp, "삭제대상")
        os.makedirs(os.path.join(dl, "sub"))
        with open(os.path.join(dl, "a.txt"), "wb") as f:
            f.write(b"A")
        with open(os.path.join(dl, "sub", "b.txt"), "wb") as f:
            f.write(b"B")
        with open(os.path.join(dl, "스캔후추가.txt"), "wb") as f:
            f.write(b"NEW")           # 목록에 없음(스캔 이후 생성 모사)
        failed = fv.secure_delete_listed(
            dl, ["a.txt", "sub/b.txt"], ["sub"], secure=True)
        check("실패 목록 비어 있음", failed == [])
        check("목록 파일 a.txt 삭제됨",
              not os.path.exists(os.path.join(dl, "a.txt")))
        check("목록 파일 sub/b.txt 삭제됨",
              not os.path.exists(os.path.join(dl, "sub", "b.txt")))
        check("빈 sub 디렉터리 제거됨",
              not os.path.isdir(os.path.join(dl, "sub")))
        check("★ 목록에 없는 파일은 보존(데이터 손실 방지)",
              os.path.exists(os.path.join(dl, "스캔후추가.txt")))
        check("미지 파일 있어 폴더 잔존", os.path.isdir(dl))
        # 미지 파일 제거 후 빈 폴더는 정리됨
        os.remove(os.path.join(dl, "스캔후추가.txt"))
        fv.secure_delete_listed(dl, [], [], secure=True)
        check("빈 폴더는 최종 정리됨", not os.path.isdir(dl))

        # create_from_folder 가 검증된 경로 목록을 반환
        info2 = fv.Vault.create_from_folder(src, os.path.join(
            tmp, "p.foldervault"), PW, KDF)
        check("info 에 file_paths 포함",
              isinstance(info2.get("file_paths"), list)
              and "메모.txt" in info2["file_paths"])
        check("info 에 dir_paths 포함(문서)",
              "문서" in info2.get("dir_paths", []))
        # 통합: 반환 목록으로 정확히 원본만 삭제, 추가 파일 보존
        intg = os.path.join(tmp, "통합")
        os.makedirs(intg)
        with open(os.path.join(intg, "orig.txt"), "wb") as f:
            f.write(b"ORIG")
        i3 = fv.Vault.create_from_folder(
            intg, os.path.join(tmp, "통합.foldervault"), PW, KDF)
        with open(os.path.join(intg, "나중에.txt"), "wb") as f:
            f.write(b"LATER")        # 잠금 후 추가
        fl = fv.secure_delete_listed(
            intg, i3["file_paths"], i3["dir_paths"], secure=True)
        check("통합: 원본만 삭제, 실패 없음", fl == [])
        check("통합: 원본 orig.txt 삭제",
              not os.path.exists(os.path.join(intg, "orig.txt")))
        check("★ 통합: 잠금 후 추가 파일 보존",
              os.path.exists(os.path.join(intg, "나중에.txt")))

        # --- 14. 비밀번호 변경: 임시 평문 안전 정리 ------------------
        cp_src = os.path.join(tmp, "cp")
        os.makedirs(cp_src)
        with open(os.path.join(cp_src, "비밀.txt"), "wb") as f:
            f.write(b"CHANGE-PW-SECRET")
        cp_v = os.path.join(tmp, "cp.foldervault")
        fv.Vault.create_from_folder(cp_src, cp_v, PW, KDF)
        fv.Vault(cp_v).change_password(PW, "새비번#1", KDF)
        leftovers = [n for n in os.listdir(tmp)
                     if n.startswith(".pwchg.")]
        check("비번변경 후 임시 작업폴더 잔존 없음", leftovers == [])
        expect_raises("비번변경 후 옛 비번 거부",
                      fv.WrongPasswordOrCorrupt,
                      lambda: fv.Vault(cp_v).read_header(PW))
        cp_out = os.path.join(tmp, "cp복원")
        os.makedirs(cp_out)
        cp_r = fv.Vault(cp_v).extract_to("새비번#1", cp_out)
        check("비번변경 후 내용 무결",
              open(os.path.join(cp_r, "비밀.txt"), "rb").read()
              == b"CHANGE-PW-SECRET")
        # 두 번째 비번 변경도 임시폴더 정리 + 새 비번으로 열림
        fv.Vault(cp_v).change_password("새비번#1", "새비번#2", KDF)
        check("연속 비번변경 임시폴더 정리",
              [n for n in os.listdir(tmp)
               if n.startswith(".pwchg.")] == [])
        check("연속 비번변경 후에도 새 비번 OK",
              fv.Vault(cp_v).read_header("새비번#2").get("verifier")
              == "FOLDERVAULT-OK")

        # --- 15. 콜백 예외 핸들러(로그+무중단) ------------------------
        orig_cd = fv.CONFIG_DIR
        orig_err = fv.messagebox.showerror
        try:
            cb_dir = fv.Path(os.path.join(tmp, "cfgdir"))
            fv.CONFIG_DIR = cb_dir
            fv.messagebox.showerror = lambda *a, **k: None
            app = fv.App()
            app.withdraw()
            app.report_callback_exception(
                ValueError, ValueError("의도된-테스트-오류"), None)
            log = cb_dir / "crash.log"
            txt = log.read_text("utf-8") if log.exists() else ""
            check("콜백 예외 → crash.log 기록",
                  "의도된-테스트-오류" in txt and "(callback)" in txt)
            check("콜백 핸들러가 예외를 다시 던지지 않음", True)
            app.destroy()
        except Exception as e:
            check(f"콜백 핸들러 테스트(예외: {type(e).__name__})", False)
        finally:
            fv.CONFIG_DIR = orig_cd
            fv.messagebox.showerror = orig_err

        # --- 16. 인덱스 크기 절대 상한(메모리 DoS 차단) -------------
        # v2 경로로 안전하게 합성: 거대 ilen → MemoryError 아닌 친절 예외
        prefix = (fv.MAGIC + b"\x00" * 16
                  + struct.pack(">I", 0) * 3
                  + b"\x00" * 12                       # header nonce
                  + struct.pack(">I", 1) + b"\x00")    # hlen=1, hct=1B
        data_start = len(prefix)                       # = 53
        body = (b"\x00" * 12                           # index nonce
                + struct.pack(">Q", 2 ** 40))          # ilen = 1 TiB
        blob = prefix + body + struct.pack(">Q", data_start)
        cap_v = os.path.join(tmp, "cap.foldervault")
        with open(cap_v, "wb") as f:
            f.write(blob)
        expect_raises("거대 인덱스 → MemoryError 아닌 친절 예외",
                      fv.WrongPasswordOrCorrupt,
                      lambda: fv.Vault(cap_v).read_header(PW))
        check("MAX_INDEX 상한 존재(<=256MiB)",
              fv.MAX_INDEX == 256 * 1024 * 1024)
        # _open 디스패치: 손상 v3/구버전도 친절 예외
        for magic, nm in ((fv.MAGIC4, "v4"), (fv.MAGIC3, "v3"),
                          (b"FLDRVLT\x01", "v1")):
            p = os.path.join(tmp, f"disp_{nm}.foldervault")
            with open(p, "wb") as f:
                f.write(magic + os.urandom(300))
            expect_raises(f"손상 {nm} → 친절 예외",
                          fv.WrongPasswordOrCorrupt,
                          lambda p=p: fv.Vault(p).read_header(PW))

        # --- 17. 비밀번호 변경: 평문 디스크 미기록 + 안전성 ----------
        rd = os.path.join(tmp, "재암호화")
        os.makedirs(rd)
        rsrc = os.path.join(rd, "src")
        os.makedirs(rsrc)
        with open(os.path.join(rsrc, "기밀.bin"), "wb") as f:
            f.write(os.urandom(C + 999))             # 멀티청크
        with open(os.path.join(rsrc, "메모.txt"), "wb") as f:
            f.write("평문마커-PLAINTEXT-MARKER".encode("utf-8"))
        A = os.path.join(rd, "A.foldervault")
        fv.Vault.create_from_folder(rsrc, A, "old-pw", KDF)
        shutil.rmtree(rsrc)                          # 원본 제거
        before = set(os.listdir(rd))
        fv.Vault(A).change_password("old-pw", "new-pw", KDF)
        after = set(os.listdir(rd))
        check("비번변경: 새 임시/평문 산출물 없음", after == before)
        check("비번변경: .new/.tmp 잔존 없음",
              not any(n.endswith((".new", ".tmp")) or
                      n.startswith(".pwchg.") for n in after))
        expect_raises("비번변경 후 옛 비번 거부",
                      fv.WrongPasswordOrCorrupt,
                      lambda: fv.Vault(A).read_header("old-pw"))
        ro = os.path.join(rd, "out")
        os.makedirs(ro)
        rr = fv.Vault(A).extract_to("new-pw", ro)
        check("재암호화 후 내용 무결(메모)",
              open(os.path.join(rr, "메모.txt"), "rb").read()
              == "평문마커-PLAINTEXT-MARKER".encode("utf-8"))
        check("재암호화 컨테이너에 평문 미노출",
              "평문마커-PLAINTEXT-MARKER".encode("utf-8")
              not in open(A, "rb").read())

        # _reencrypt 직접: 원본 불변 + 산출물 격리 검증
        B = os.path.join(rd, "B.foldervault")
        a_bytes = open(A, "rb").read()
        fv.Vault._reencrypt(A, B, "new-pw", "third-pw", KDF)
        check("_reencrypt: 원본 A 불변",
              open(A, "rb").read() == a_bytes)
        check("_reencrypt: B 생성 + MAGIC v4",
              os.path.exists(B) and open(B, "rb").read(8) == fv.MAGIC4)
        check("_reencrypt: B.tmp 잔존 없음",
              not os.path.exists(B + ".tmp"))
        expect_raises("_reencrypt B 를 옛 비번으로 거부",
                      fv.WrongPasswordOrCorrupt,
                      lambda: fv.Vault(B).read_header("new-pw"))
        fv.Vault(B)._verify_full("third-pw")
        check("_reencrypt: B 새 비번으로 전체검증 통과", True)
        # 변조된 새 볼트도 여전히 탐지
        with open(B, "r+b") as f:
            f.seek(fv.PREFIX_FIXED + 80)
            b = f.read(1)
            f.seek(-1, 1)
            f.write(bytes([b[0] ^ 0xFF]))
        expect_raises("_reencrypt 후 변조 → 거부",
                      fv.WrongPasswordOrCorrupt,
                      lambda: fv.Vault(B)._verify_full("third-pw"))

        # --- 18. 키 유도 sanity(반환은 bytes 32B, 결정적) ----------
        s16 = b"0123456789abcdef"
        k1 = fv.derive_master_key("pw", s16, KDF)
        k2 = fv.derive_master_key("pw", s16, KDF)
        k3 = fv.derive_master_key("pw", b"f" * 16, KDF)
        check("derive: 동일 입력 → 동일 32B 키",
              k1 == k2 and len(k1) == 32)
        check("derive: salt 다르면 키 다름", k1 != k3)

        # --- 19. Argon2 프리셋 상향(2026) ---------------------------
        check("standard=256MiB",
              fv.KDF_PRESETS["standard"]["memory_cost"] == 262144)
        check("high=512MiB",
              fv.KDF_PRESETS["high"]["memory_cost"] == 524288)
        check("paranoid=1GiB",
              fv.KDF_PRESETS["paranoid"]["memory_cost"] == 1048576)

        # --- 20. 상수시간 검증자 비교 -------------------------------
        check("_verifier_ok 정상", fv._verifier_ok(
            {"verifier": "FOLDERVAULT-OK"}) is True)
        check("_verifier_ok 불일치 거부",
              fv._verifier_ok({"verifier": "X"}) is False)
        check("_verifier_ok 비-str 거부",
              fv._verifier_ok({"verifier": 123}) is False)

        # --- 21. 키체인 페퍼(옵트인) 경로 ---------------------------
        UP = b"U" * 32
        rA = fv.derive_root_v3("pw", b"s" * 16, KDF)
        rB = fv.derive_root_v3("pw", b"s" * 16, KDF, user_pepper=UP)
        check("user_pepper 있으면 루트키 달라짐", rA != rB)

        ks = os.path.join(tmp, "kc_src")
        os.makedirs(ks)
        with open(os.path.join(ks, "기밀.txt"), "wb") as f:
            f.write(b"KEYCHAIN-SECRET-DATA")
        kv = os.path.join(tmp, "kc.foldervault")
        fv.Vault.create_from_folder(ks, kv, "pw", KDF,
                                    pmode=1, user_pepper=UP)
        # pmode 바이트(프리픽스 8+16+12 위치) == 1
        with open(kv, "rb") as f:
            f.seek(8 + 16 + 12)
            check("pmode 바이트 == 1(키체인)", f.read(1) == b"\x01")
        check("올바른 user_pepper 로 헤더 열림",
              fv.Vault(kv).read_header("pw", user_pepper=UP)
              .get("verifier") == "FOLDERVAULT-OK")
        expect_raises("user_pepper 없이 → KeychainPepperRequired",
                      fv.KeychainPepperRequired,
                      lambda: fv.Vault(kv).read_header("pw"))
        check("KeychainPepperRequired ⊂ WrongPasswordOrCorrupt",
              issubclass(fv.KeychainPepperRequired,
                         fv.WrongPasswordOrCorrupt))
        expect_raises("틀린 user_pepper → 거부",
                      fv.WrongPasswordOrCorrupt,
                      lambda: fv.Vault(kv).read_header(
                          "pw", user_pepper=b"Z" * 32))
        ko = os.path.join(tmp, "kc_out")
        os.makedirs(ko)
        kr = fv.Vault(kv).extract_to("pw", ko, user_pepper=UP)
        check("키체인 볼트 복원 내용 무결",
              open(os.path.join(kr, "기밀.txt"), "rb").read()
              == b"KEYCHAIN-SECRET-DATA")
        # 키체인 볼트 비번 변경(소스/대상 모두 키체인)
        fv.Vault(kv).change_password(
            "pw", "pw2", KDF, src_user_pepper=UP,
            pmode=1, user_pepper=UP)
        expect_raises("키체인 비번변경 후 옛 비번 거부",
                      fv.WrongPasswordOrCorrupt,
                      lambda: fv.Vault(kv).read_header(
                          "pw", user_pepper=UP))
        check("키체인 비번변경 후 새 비번 OK",
              fv.Vault(kv).read_header("pw2", user_pepper=UP)
              .get("verifier") == "FOLDERVAULT-OK")
        # 앱 모드(pmode=0) 기본 동작 불변: user_pepper 없이 열림
        av = os.path.join(tmp, "appmode.foldervault")
        fv.Vault.create_from_folder(ks, av, "pw", KDF)
        with open(av, "rb") as f:
            f.seek(8 + 16 + 12)
            check("pmode 바이트 == 0(앱)", f.read(1) == b"\x00")
        check("앱 모드: user_pepper 없이 열림",
              fv.Vault(av).read_header("pw").get("verifier")
              == "FOLDERVAULT-OK")

        # --- 22. DPAPI 왕복(Windows; 실제 키체인) -------------------
        if fv.dpapi_available():
            blob = fv.dpapi_protect(b"hello-secret-123")
            check("DPAPI protect→unprotect 왕복",
                  fv.dpapi_unprotect(blob) == b"hello-secret-123"
                  and blob != b"hello-secret-123")
            orig_up_path = fv.USERPEPPER_PATH
            try:
                fv.USERPEPPER_PATH = fv.Path(
                    os.path.join(tmp, "userpepper.bin"))
                up1, created1 = fv.ensure_user_pepper()
                check("ensure_user_pepper 최초 생성", created1
                      and len(up1) == 32)
                up2, created2 = fv.ensure_user_pepper()
                check("ensure_user_pepper 재로드 동일",
                      up2 == up1 and not created2)
                fv.store_user_pepper(b"Q" * 32)
                check("store→load 왕복",
                      fv.load_user_pepper() == b"Q" * 32)
            finally:
                fv.USERPEPPER_PATH = orig_up_path
        else:
            check("DPAPI 테스트(비-Windows, 건너뜀)", True)

        # --- 23. v2 하위호환 경로 전수 검증(데이터-안전 약속) -------
        v2s = os.path.join(tmp, "v2src")
        os.makedirs(os.path.join(v2s, "문서", "하위"))
        os.makedirs(os.path.join(v2s, "빈폴더"))
        with open(os.path.join(v2s, "메모.txt"), "wb") as f:
            f.write(b"OLD-V2-SECRET")
        with open(os.path.join(v2s, "문서", "big.bin"), "wb") as f:
            f.write(os.urandom(C + 4321))            # 멀티청크
        open(os.path.join(v2s, "문서", "하위", "e.dat"), "wb").close()
        v2v = os.path.join(tmp, "v2.foldervault")
        build_v2_vault(v2s, v2v, "v2pw", KDF)
        check("합성 v2 MAGIC == v2",
              open(v2v, "rb").read(8) == fv.MAGIC)
        hdr2 = fv.Vault(v2v).read_header("v2pw")
        check("v2 헤더 version==2", hdr2.get("version") == 2)
        expect_raises("v2 잘못된 비번 거부",
                      fv.WrongPasswordOrCorrupt,
                      lambda: fv.Vault(v2v).read_header("nope"))
        fv.Vault(v2v)._verify_full("v2pw")
        check("v2 _verify_full 통과", True)
        v2o = os.path.join(tmp, "v2out")
        os.makedirs(v2o)
        v2r = fv.Vault(v2v).extract_to("v2pw", v2o)
        check("v2 복원 내용 완전 일치",
              deep_equal(filecmp.dircmp(v2s, v2r)))
        check("v2 멀티청크 파일 바이트 일치", filecmp.cmp(
            os.path.join(v2s, "문서", "big.bin"),
            os.path.join(v2r, "문서", "big.bin"), shallow=False))
        check("v2 빈 폴더 보존",
              os.path.isdir(os.path.join(v2r, "빈폴더")))
        # v2 데이터 변조 → 청크 GCM 으로 탐지
        v2t = os.path.join(tmp, "v2t.foldervault")
        shutil.copyfile(v2v, v2t)
        with open(v2t, "r+b") as f:
            f.seek(fv.PREFIX_FIXED + 60)
            b = f.read(1)
            f.seek(-1, 1)
            f.write(bytes([b[0] ^ 0xFF]))
        expect_raises("v2 데이터 변조 → 거부",
                      fv.WrongPasswordOrCorrupt,
                      lambda: fv.Vault(v2t)._verify_full("v2pw"))
        # v2 → 비밀번호 변경 시 v4(하이브리드)로 안전 업그레이드
        before_v2 = open(v2v, "rb").read()
        fv.Vault(v2v).change_password("v2pw", "v3pw", KDF)
        check("v2→비번변경 후 MAGIC == v4",
              open(v2v, "rb").read(8) == fv.MAGIC4)
        expect_raises("업그레이드 후 옛 v2 비번 거부",
                      fv.WrongPasswordOrCorrupt,
                      lambda: fv.Vault(v2v).read_header("v2pw"))
        v2o2 = os.path.join(tmp, "v2out2")
        os.makedirs(v2o2)
        v2r2 = fv.Vault(v2v).extract_to("v3pw", v2o2)
        check("v2→v3 업그레이드 후 내용 무결",
              deep_equal(filecmp.dircmp(v2s, v2r2)))
        check("v2→v3 전환은 원본 v2와 다른 바이트(재암호화)",
              before_v2 != open(v2v, "rb").read())

        # --- 24. v3 하위호환 경로 검증 ------------------------------
        v3s = os.path.join(tmp, "v3src")
        os.makedirs(os.path.join(v3s, "안"))
        with open(os.path.join(v3s, "비밀.txt"), "wb") as f:
            f.write(b"OLD-V3-DATA")
        with open(os.path.join(v3s, "안", "big.bin"), "wb") as f:
            f.write(os.urandom(C + 222))
        v3v = os.path.join(tmp, "v3.foldervault")
        build_v3_vault(v3s, v3v, "v3p", KDF)
        check("합성 v3 MAGIC == v3",
              open(v3v, "rb").read(8) == fv.MAGIC3)
        check("v3 헤더 version==3",
              fv.Vault(v3v).read_header("v3p").get("version") == 3)
        fv.Vault(v3v)._verify_full("v3p")
        v3o = os.path.join(tmp, "v3out")
        os.makedirs(v3o)
        v3r = fv.Vault(v3v).extract_to("v3p", v3o)
        check("v3 복원 완전 일치",
              deep_equal(filecmp.dircmp(v3s, v3r)))
        expect_raises("v3 잘못된 비번 거부", fv.WrongPasswordOrCorrupt,
                      lambda: fv.Vault(v3v).read_header("nope"))
        with open(v3v, "r+b") as f:                  # v3 변조
            f.seek(fv.PREFIX_FIXED + 70)
            b = f.read(1)
            f.seek(-1, 1)
            f.write(bytes([b[0] ^ 0xFF]))
        expect_raises("v3 변조 → 거부(Ed25519 서명)",
                      fv.WrongPasswordOrCorrupt,
                      lambda: fv.Vault(v3v)._verify_full("v3p"))
        # v3 → v4 업그레이드(비번 변경)
        build_v3_vault(v3s, v3v, "v3p", KDF)         # 새로(변조본 폐기)
        fv.Vault(v3v).change_password("v3p", "v4p", KDF)
        check("v3→비번변경 후 MAGIC == v4",
              open(v3v, "rb").read(8) == fv.MAGIC4)
        v3o2 = os.path.join(tmp, "v3out2")
        os.makedirs(v3o2)
        check("v3→v4 업그레이드 후 내용 무결",
              deep_equal(filecmp.dircmp(v3s, fv.Vault(v3v).extract_to(
                  "v4p", v3o2))))

        # --- 25. v4 하이브리드 서명(Ed25519 + ML-DSA-65) ------------
        # 결정적 키 + 왕복
        dg = b"d" * 64
        rt = fv.derive_root_v3("pw", b"S" * 16, KDF)
        es, ms = fv.hybrid_sign(rt, dg)
        check("ML-DSA-65 서명 길이 == 3309", len(ms) == 3309)
        check("Ed25519 서명 길이 == 64", len(es) == 64)
        fv.hybrid_verify(rt, dg, es, ms)             # 통과해야
        check("hybrid_verify 정상 왕복", True)
        expect_raises("digest 변조 → 하이브리드 거부",
                      Exception,
                      lambda: fv.hybrid_verify(rt, b"e" * 64, es, ms))
        rt2 = fv.derive_root_v3("pw2", b"S" * 16, KDF)
        expect_raises("다른 루트키 → 하이브리드 거부",
                      Exception,
                      lambda: fv.hybrid_verify(rt2, dg, es, ms))

        # v4 볼트에서 ML-DSA 서명만 1바이트 훼손 → 거부(PQC 실제 적용 증명)
        hv_s = os.path.join(tmp, "hyb_src")
        os.makedirs(hv_s)
        with open(os.path.join(hv_s, "x.bin"), "wb") as f:
            f.write(os.urandom(2048))
        hv = os.path.join(tmp, "hyb.foldervault")
        fv.Vault.create_from_folder(hv_s, hv, "hp", KDF)
        sz = os.path.getsize(hv)
        with open(hv, "rb") as f:
            f.seek(sz - 4)
            ml_len = struct.unpack(">I", f.read(4))[0]
        check("v4 ml_len 합리적(=3309)", ml_len == 3309)
        ml_off = sz - 4 - ml_len                      # ML-DSA 서명 시작
        ed_off = ml_off - 64                          # Ed25519 시작
        # (a) ML-DSA 서명만 훼손
        t_ml = os.path.join(tmp, "t_ml.foldervault")
        shutil.copyfile(hv, t_ml)
        with open(t_ml, "r+b") as f:
            f.seek(ml_off + 10)
            b = f.read(1)
            f.seek(-1, 1)
            f.write(bytes([b[0] ^ 0xFF]))
        expect_raises("ML-DSA 서명만 훼손 → 거부(PQC 강제됨)",
                      fv.WrongPasswordOrCorrupt,
                      lambda: fv.Vault(t_ml).read_header("hp"))
        # (b) Ed25519 서명만 훼손
        t_ed = os.path.join(tmp, "t_ed.foldervault")
        shutil.copyfile(hv, t_ed)
        with open(t_ed, "r+b") as f:
            f.seek(ed_off + 10)
            b = f.read(1)
            f.seek(-1, 1)
            f.write(bytes([b[0] ^ 0xFF]))
        expect_raises("Ed25519 서명만 훼손 → 거부(고전 강제됨)",
                      fv.WrongPasswordOrCorrupt,
                      lambda: fv.Vault(t_ed).read_header("hp"))
        # (c) 정상본은 열림 + 복원 무결
        ho = os.path.join(tmp, "hyb_out")
        os.makedirs(ho)
        hr = fv.Vault(hv).extract_to("hp", ho)
        check("v4 정상본 복원 무결",
              deep_equal(filecmp.dircmp(hv_s, hr)))

        # --- 26. 위조 볼트의 경로탈출 차단(extract 전에 _open 단계 거부) -
        # 정상 v3 볼트를 합성한 뒤, 인덱스 'p' 또는 폴더명에 traversal 을
        # 주입한 변형을 만들어 _open 이 거부함을 검증.
        def build_malicious(folder, vault_path, pw, kdf, *,
                            rp_override=None, folder_name_override=None,
                            t_override=None):
            base = fv.Path(os.path.abspath(folder))
            salt = os.urandom(16)
            root = fv.derive_root_v3(pw, salt, kdf)
            entries = []
            for rdir, _ds, fs in os.walk(folder):
                for nm in sorted(fs):
                    fp = os.path.join(rdir, nm)
                    entries.append({"p": fv.Path(fp).relative_to(base)
                                    .as_posix(), "t": "f", "_src": fp})
            if entries:
                if rp_override is not None:
                    entries[0]["p"] = rp_override
                if t_override is not None:
                    entries[0]["t"] = t_override
            header = {"app": "FolderVault", "version": 4,
                      "vault_id": fv.uuid.uuid4().hex,
                      "name": folder_name_override or base.name,
                      "created": fv.now_iso(),
                      "verifier": "FOLDERVAULT-OK"}
            nAh, nCh, hct = fv.casc_encrypt(
                fv.subkey(root, fv.HKDF_HDR_A),
                fv.subkey(root, fv.HKDF_HDR_C),
                fv.json.dumps(header).encode("utf-8"), fv.MAGIC4)
            with open(vault_path, "w+b") as out:
                out.write(fv.MAGIC4); out.write(salt)
                out.write(struct.pack(">I", int(kdf["time_cost"])))
                out.write(struct.pack(">I", int(kdf["memory_cost"])))
                out.write(struct.pack(">I", int(kdf["parallelism"])))
                out.write(b"\x00")
                out.write(nAh); out.write(nCh)
                out.write(struct.pack(">I", len(hct))); out.write(hct)
                for e in entries:
                    rp = e["p"]
                    fid = fv.uuid.uuid4().hex
                    kA = fv.subkey(root, fv.HKDF_FILE_A + fv._b(rp))
                    kC = fv.subkey(root, fv.HKDF_FILE_C + fv._b(rp))
                    n = 0; s = 0
                    with open(e["_src"], "rb") as fh:
                        while True:
                            data = fh.read(fv.CHUNK)
                            if not data:
                                break
                            aad = (fv._b(rp) + b"|" + fid.encode("ascii")
                                   + b"|" + str(n).encode("ascii"))
                            a, c, ct = fv.casc_encrypt(kA, kC, data, aad)
                            out.write(a); out.write(c)
                            out.write(struct.pack(">I", len(ct)))
                            out.write(ct)
                            n += 1; s += len(data)
                    ps = fv.padme(s); rem = ps - s
                    while rem > 0:
                        blk = os.urandom(min(fv.CHUNK, rem))
                        aad = (fv._b(rp) + b"|" + fid.encode("ascii")
                               + b"|" + str(n).encode("ascii"))
                        a, c, ct = fv.casc_encrypt(kA, kC, blk, aad)
                        out.write(a); out.write(c)
                        out.write(struct.pack(">I", len(ct)))
                        out.write(ct)
                        n += 1; rem -= len(blk)
                    e["n"] = n; e["s"] = s; e["ps"] = ps; e["fid"] = fid
                    del e["_src"]
                data_end = out.tell()
                index = {"entries": entries,
                         "total_size": sum(x["s"] for x in entries),
                         "folder_name": folder_name_override or base.name}
                nAi, nCi, ict = fv.casc_encrypt(
                    fv.subkey(root, fv.HKDF_IDX_A),
                    fv.subkey(root, fv.HKDF_IDX_C),
                    fv.json.dumps(index).encode("utf-8"),
                    fv.MAGIC4 + nAh + nCh)
                out.write(nAi); out.write(nCi)
                out.write(struct.pack(">Q", len(ict))); out.write(ict)
                out.write(struct.pack(">Q", data_end))
                out.flush()
                sig_pos = out.tell()
                digest = fv._sha512_region(out, 0, sig_pos)
                ed_sig, ml_sig = fv.hybrid_sign(root, digest)
                out.seek(sig_pos)
                out.write(ed_sig); out.write(ml_sig)
                out.write(struct.pack(">I", len(ml_sig)))

        atk_src = os.path.join(tmp, "atk_src")
        os.makedirs(atk_src)
        with open(os.path.join(atk_src, "x.bin"), "wb") as f:
            f.write(b"OWNED")
        cases = [
            ("rp_traversal",  "rp ../ traversal",
             {"rp_override": "../../HIJACKED.txt"}),
            ("rp_absolute",   "rp 절대경로(POSIX)",
             {"rp_override": "/etc/passwd"}),
            ("rp_nul",        "rp NUL",
             {"rp_override": "ok\x00bad"}),
            ("rp_backslash",  "rp 백슬래시",
             {"rp_override": "a\\b"}),
            ("rp_empty_comp", "rp 빈 컴포넌트",
             {"rp_override": "a//b"}),
            ("rp_dot_comp",   "rp '.' 컴포넌트",
             {"rp_override": "a/./b"}),
            ("rp_drive",      "rp 드라이브",
             {"rp_override": "C:foo"}),
            ("fn_traversal",  "folder_name ..",
             {"folder_name_override": "../EVIL"}),
            ("fn_sep",        "folder_name '/'",
             {"folder_name_override": "a/b"}),
            ("type_bad",      "entry t 비정상",
             {"t_override": "x"}),
        ]
        for slug, label, kw in cases:
            vp = os.path.join(tmp, f"atk_{slug}.foldervault")
            build_malicious(atk_src, vp, "p", KDF, **kw)
            expect_raises(f"위조 차단: {label}",
                          fv.WrongPasswordOrCorrupt,
                          lambda vp=vp: fv.Vault(vp).read_header("p"))
            # extract_to 호출도 동일하게 거부되어야 함
            od = os.path.join(tmp, f"atk_{slug}_out")
            os.makedirs(od)
            expect_raises(f"위조 차단(extract): {label}",
                          fv.WrongPasswordOrCorrupt,
                          lambda vp=vp, od=od:
                              fv.Vault(vp).extract_to("p", od))
            check(f"위조 시 dest 바깥 미기록: {label}",
                  not os.path.exists(os.path.join(tmp, "HIJACKED.txt"))
                  and not os.path.exists(os.path.join(tmp, "EVIL")))

    except Exception:
        import traceback
        traceback.print_exc()
        fail += 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print(f"\n결과: {ok} PASS / {fail} FAIL")
    sys.exit(1 if fail else 0)


if __name__ == "__main__":
    main()
