# FolderVault — Design Notes

These are the design decisions and the reasoning behind them. The goal is that
a reviewer can understand not just what the code does, but why it does it that
way — and where I chose honesty over features that look impressive but do not
actually help.

## Priorities, in order

1. **Do not lose data.** The tool deletes originals, so one mistake is
   permanent loss. Every destructive step (placing the vault, deleting
   originals, replacing a vault on password change) happens only after a full
   decrypt and structural verification of the new vault. If verification
   fails, the original is never touched.
2. Real confidentiality and integrity.
3. Honesty about limits over features that look good but do not help.

## Key derivation

```
password --Argon2id(salt, t, m, p)--> argon (32 B)
root = HKDF-SHA256(argon, salt = pepper_material, info = "FolderVault/root/v3")
```

- Argon2id, because it is the current memory-hard password-hashing standard
  and resists GPU/ASIC brute force. Presets: standard 256 MiB (t=4, p=4),
  high 512 MiB (t=5, p=4), paranoid 1 GiB (t=6, p=4).
- HKDF-SHA256 then splits `root` into independent subkeys: header, index, and
  per-file keys (each per-file key bound to that file's relative path).

### Pepper

`pepper_material` is either the app-embedded `PEPPER` constant (default,
portable) or `SHA-256(PEPPER || user_pepper)`, where `user_pepper` is a
32-byte secret stored via Windows DPAPI (opt-in keychain mode).

- App mode is the default because it is portable: the vault opens on any
  machine with the right password.
- The embedded pepper is **not** claimed to be secret against source
  disclosure — this is open source. It only adds a defense line if *only* the
  `.foldervault` file leaks.
- Keychain mode makes the pepper a real per-account/per-machine secret, at the
  cost of portability. It is opt-in and requires a backup, because losing the
  DPAPI secret means losing the data.
- The pepper is deliberately **not** user-removable or rotatable: changing it
  would make every existing vault permanently undecryptable. Per priority 1,
  that is unacceptable as a silent or casual operation. This is a conscious
  trade-off, not an oversight.

## Encryption: cascade AEAD

Each 1 MiB plaintext chunk is encrypted as:

```
inner = AES-256-GCM(k_aes, nonce_a, pt, aad)
ct    = ChaCha20-Poly1305(k_cha, nonce_c, inner, aad)
```

- Two independent keys, two independent nonces, two independent AEADs. A break
  or implementation flaw in one construction still leaves the other.
- `aad` binds the relative path, the chunk index, and the total chunk count,
  so reordering, truncating, or swapping chunks between files is detected.
- 1 MiB streaming so multi-GB files do not blow up memory.

## Integrity and post-quantum scope

The whole vault (everything except the trailing signature) is hashed with
SHA-512 and signed with **both** Ed25519 and ML-DSA-65 (FIPS 204). Both
signatures are derived deterministically from `root` (no separate key
storage), and both must verify or the vault is rejected.

The honest reasoning about PQC scope:

- **Confidentiality is already post-quantum.** It is pure symmetric crypto
  from a password (Argon2id then AES-256 + ChaCha20). There is no public-key
  key exchange, so "harvest now, decrypt later" does not apply, Shor does not
  apply, and only Grover does — which merely halves an already-infeasible
  256-bit brute force.
- **Therefore ML-KEM was deliberately not added.** There is no key exchange
  for it to protect; adding it would be theater.
- **Signatures are where a quantum adversary actually matters,** so that is
  the only place PQC was applied: ML-DSA-65, hybridised with Ed25519
  (classical + PQC, the standard transition practice).

## Padding

Per-file sizes are rounded up with Padmé (PURBs paper), which bounds the size
leak while keeping overhead under ~12%. Filenames and the directory structure
are encrypted in the index, so the container reveals neither names nor exact
sizes.

## Container format

`v4` (current, written by all new vaults):

```
[prefix]  MAGIC4(8)  salt(16)  t,m,p (>I x3)
          pmode(1)                                # 0 = app/portable, 1 = DPAPI keychain
          cascade(header)   aad = MAGIC4
[data]    per file, Padmé-padded chunks:
          nonce_a(12) nonce_c(12) clen(>I) ct     # cascade, aad = relpath | fid | chunk_index
[footer]  cascade(index)    aad = MAGIC4 + header nonces
          index_offset(>Q)
          Ed25519 sig(64)  ||  ML-DSA-65 sig(len)
```

- `v2` (single AES-GCM, no padding/signature) and `v3` (Ed25519-only) remain
  **readable**. New vaults are always v4. The backward-compat read paths are
  exercised by the test suite with synthetic v2/v3 vaults — because silently
  dropping the ability to open an old vault would itself be data loss.

## Data-loss safety model

This is the reason most of the test suite exists:

- **Verify-before-delete:** write to a temp file, fully decrypt every chunk
  and check structural consistency; only then place the vault and delete
  originals.
- **TOCTOU:** each file is streamed to its real end and the real chunk
  count/size/file-id is recorded in the authenticated index, so "recorded ==
  actually encrypted" even if files change between scan and encryption.
- **Self-deletion prevention:** refuse to store the vault inside the folder
  being encrypted.
- **No-loss password change:** chunk-by-chunk decrypt-then-reencrypt (no
  plaintext ever hits disk), new vault fully verified, then atomic replace.
  Any failure leaves the old vault intact.
- **Symlink/junction:** abort before writing or deleting if the tree contains
  reparse points, so their contents are not silently lost.
- **Exact deletion:** delete only the encrypted-and-verified entries, never a
  blanket folder wipe; files created after the lock scan are never deleted.
- **Honest reporting:** if some files were locked and deletion failed, it says
  so and marks the state "unlocked — not secure" rather than reporting
  success.
- **DoS bombs:** hard caps on header/index/chunk sizes so a malicious vault
  cannot exhaust memory.
- **No silent failure:** even under `pythonw` (no console), unexpected errors
  are shown and logged to `crash.log`.

## Tests

`python test_vault.py` runs **143 assertions across 25 categories**:
creation/verify, wrong-password rejection, byte-exact restore, tamper
detection (data byte flip, Ed25519-only and ML-DSA-only corruption),
corrupt-vault graceful handling, password change (atomic, no temp plaintext,
no plaintext to disk), self-deletion guard, empty folders, registry-corruption
tolerance, symlink/junction abort, long-path prefix, precise/honest deletion,
callback error handling, index DoS cap, key-derivation sanity, constant-time
verifier compare, keychain/DPAPI round-trip, and v2/v3/v4 compatibility.
Current status: **143 PASS / 0 FAIL**.

## UI language

The UI ships in Korean and English (Settings -> language; restart to
apply). It is a pure string-lookup layer over one central table, keyed
by short stable IDs, with a Korean fallback for any unmapped key. It
touches no crypto, I/O, or control flow, and Korean output is
byte-identical to before — so the 143-test suite is unaffected.

## Known limits

See [../SECURITY.md](../SECURITY.md). Short version: in-memory secrets cannot
be wiped in pure Python; keychain mode is not portable; the embedded pepper is
not secret against source disclosure (by design); a lost password or lost file
is unrecoverable (by design).
