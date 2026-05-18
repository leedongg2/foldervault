# FolderVault

> "Dad asked me to make a folder password protector. I got carried away."

A folder encryption tool I built as a 14-year-old Korean middle schooler. It
does not "hide" folders — it actually encrypts the file contents, so without
the correct password nobody (me included) can get the data back.

I am publishing it so people can review it and break it. That is the point —
see [Please tear it apart](#please-tear-it-apart).

Korean: [README.ko.md](README.ko.md)

## What it does

- Cascade AEAD: AES-256-GCM then ChaCha20-Poly1305, independent keys and nonces
- Argon2id key derivation, up to 1 GiB memory (standard 256 MiB / high 512 MiB / paranoid 1 GiB)
- Hybrid signatures: Ed25519 + ML-DSA-65 (NIST FIPS 204, post-quantum) — both must verify
- HKDF-SHA256 subkey separation (header / index / per-file keys)
- Padmé padding (PURBs paper) to blur individual file sizes (< ~12% overhead)
- Single-file container; filenames and folder structure are encrypted too
- Honest about its limits (see [SECURITY.md](SECURITY.md))

## Why post-quantum, and why only half of it

The confidentiality here is already quantum-safe. It is pure symmetric crypto
driven by a password (Argon2id then AES-256 + ChaCha20). There is no public-key
key exchange to "harvest now, decrypt later," so Shor's algorithm does not
apply and only Grover does — which merely halves an already-infeasible 256-bit
brute force.

So I deliberately did not add ML-KEM. There is no key exchange for it to
protect; bolting it on would be security theater. Where a quantum computer
*would* matter is the integrity signature, so that is the only place I applied
PQC: ML-DSA-65, hybridised with classical Ed25519, and a vault opens only if
both signatures verify. That is the honest, correct scope — not "we sprinkled
post-quantum on everything."

## Quickstart

```
pip install -r requirements.txt
python folder_vault.py      # GUI (Korean or English — Settings -> language)
python test_vault.py        # 143 self-test assertions across 25 categories
```

On Windows you can just double-click `start.bat`; it sets up a virtual
environment on first run.

## How this was built

This project was built with AI assistance, and I want to be upfront about
exactly how — pretending otherwise would be dishonest, and it also misses the
part I think is actually interesting.

- **Architecture, threat model, and design decisions are mine.** Why PQC and
  where it actually matters, why a cascade AEAD, why Padmé padding, what to
  test, which edge cases matter, the data-loss safety model — those were my
  calls.
- **The cryptographic primitive wiring was generated with Claude Opus 4.7
  from my specifications.** Everything uses vetted libraries (`cryptography`,
  `argon2-cffi`). No hand-rolled crypto, on purpose.
- **Integration, testing, and debugging were done by me:** 143 pass/fail
  assertions across 25 categories, including tamper detection, backward
  compatibility, and data-loss safety.

I am 14 and still learning the cryptography deeply — see the roadmap. External
review is the entire reason this is public. The system-level decisions being
mine while the implementation benefits from AI assistance is, I think, a
reasonable and honest way to build software, and I would rather say that
plainly than hide it. This is a real engineering project, not a vibe-coded
toy.

## Threat model

| Threat | Protected? | How / caveat |
|---|---|---|
| Attacker steals only the `.foldervault` file | Yes | Content encrypted under Argon2id + cascade AEAD; useless without the password |
| Offline password brute force | Mostly | Argon2id, 256 MiB–1 GiB, memory-hard. Real strength still depends on your password |
| Tampering / reordering / truncation | Yes | Per-chunk AEAD + AAD binding (path, chunk index, count) + whole-vault hybrid signature |
| Future quantum attacker (integrity) | Yes | ML-DSA-65 (FIPS 204) hybridised with Ed25519 |
| Future quantum attacker (confidentiality) | Yes | Symmetric / password-based; no key exchange to harvest |
| Attacker reads RAM while the app runs | No | Python cannot reliably wipe immutable `str` / library key bytes. Needs OS-level protection |
| `.foldervault` lost or corrupted | No | The file *is* the data. Keep backups. Lost password = unrecoverable, by design |
| SSD forensic recovery of the original | Partial | Wear-levelling means no software can guarantee secure erase. Encryption, not deletion, is the real protection |

## Roadmap

- [x] English UI (Settings -> language; Korean stays the default)
- [ ] External security audit / independent review
- [ ] CLI mode (no GUI)
- [ ] Reproducible, CryptoHack-style proofs for the container format

## Please tear it apart

This is not production-ready and I am not claiming it is. If you find a
weakness, a wrong assumption, or a place where I am fooling myself, please open
an issue — see [SECURITY.md](SECURITY.md). That is how I learn, and it is the
whole reason this is public.

## License

MIT — see [LICENSE](LICENSE).
