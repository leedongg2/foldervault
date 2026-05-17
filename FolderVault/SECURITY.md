# Security Policy

## Reporting a vulnerability

If you find a security issue, please report it. I would genuinely rather know
than not.

- Open an issue: `https://github.com/<YOUR-GITHUB-USERNAME>/FolderVault/issues`
- If you think it is sensitive, put `[security]` in the title and keep the
  proof-of-concept minimal; we can take details private from there.
- Please include: what you attacked, what you expected, what actually
  happened, and steps to reproduce.

I am a student doing this in my spare time, so I cannot promise a response
time, but I will read every report.

## What I claim

- **Confidentiality** of `.foldervault` contents against an attacker who has
  only the file, given a strong password.
- **Integrity / authenticity**: tampering, reordering, truncation, or
  substitution is detected — per-chunk AEAD + AAD binding + a whole-vault
  hybrid Ed25519 + ML-DSA-65 signature, both of which must verify.
- **Post-quantum integrity** via ML-DSA-65 (FIPS 204), hybridised with
  Ed25519.

## What I do NOT claim (honest limits)

These are real limitations I cannot fix in software. I would rather state them
than pretend.

- **In-memory secrets.** Python cannot reliably zero an immutable `str` (the
  password from the GUI), Tk's internal copies, or key bytes returned by
  libraries. An attacker who can read process memory or a core dump while the
  app runs is out of scope; that needs OS-level protection (full-disk
  encryption, a trusted single-user machine, memory protection across
  sleep/hibernate). `argon2-cffi` zeroes its own internal C password buffer;
  that is all that can honestly be claimed.
- **Keychain mode is not portable.** A vault created with the opt-in
  OS-keychain pepper (Windows DPAPI) opens only on that Windows account and
  machine. OS reinstall, account deletion, or another PC means it cannot be
  opened even with the correct password. That is why the default is the
  portable app mode, and keychain mode is opt-in and requires a pepper backup.
- **The app-embedded pepper is not secret against source disclosure.**
  FolderVault is open source, so the embedded pepper is visible. It is
  intentionally only a defense for the case where *only the `.foldervault`
  file* leaks (not the source). The real secret-grade pepper is the opt-in
  DPAPI keychain mode. The pepper is deliberately not configurable or
  removable, because changing it would make every existing vault permanently
  undecryptable — data loss is treated as the worst possible outcome.
- **Timing.** The core authentication (AES-GCM / ChaCha20-Poly1305 / Ed25519)
  is already constant-time in the underlying library; there was no exploitable
  timing oracle. The `hmac.compare_digest` on the verifier is defensive, not a
  fix for a known vulnerability — stated honestly so it is not oversold.
- **Lost password or lost/corrupted file = unrecoverable.** By design. There
  is no backdoor and no recovery key. Keep backups of the `.foldervault` file.
- **SSD secure-erase.** Wear-levelling means no software can guarantee the
  original plaintext is unrecoverable by hardware forensics. The real
  protection is the encryption, not the deletion.

## Scope

In scope: the vault format, key derivation, the encryption and signature code
in `folder_vault.py`, and the data-loss safety logic.

Out of scope: attacks requiring read access to the running process's memory, a
compromised OS, or a hardware attacker; weak user-chosen passwords; loss of
the vault file or the password.
