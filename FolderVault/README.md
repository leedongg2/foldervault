# FolderVault

> "Dad asked me to make a folder password protector. I kind of got carried away."

I'm 14, in middle school in Korea, and I built this mostly over a few late
nights. It doesn't *hide* folders. It actually encrypts what's inside them, so
without the password nobody gets the data back. Not you, not me, not the
program.

I put it online because I want people to break it. I mean that — jump to
[Please tear it apart](#please-tear-it-apart).

Korean readme: [README.ko.md](README.ko.md)

## What's in it

- AES-256-GCM and ChaCha20-Poly1305, cascaded: encrypt with one, then the
  other, separate keys and separate nonces. A break in one still leaves the
  other.
- Argon2id turns your password into the key. Up to 1 GiB of memory on the
  paranoid setting (256 MiB standard / 512 MiB high / 1 GiB paranoid).
- Every chunk is tied to its file path and position, so you can't reorder,
  cut, or splice the vault without it failing to open.
- The whole vault is signed twice: Ed25519 and ML-DSA-65 (the NIST FIPS 204
  post-quantum one). Both have to verify or it won't open.
- Padmé padding (from the PURBs paper) so the file doesn't leak exact sizes.
- One `.foldervault` file. Filenames and the folder tree are encrypted too.

No hand-rolled crypto anywhere. It all sits on `cryptography` and
`argon2-cffi`.

## Why post-quantum, and why I only did half

Because the confidentiality here is already quantum-safe, so I didn't fake
the other half.

It's all symmetric, driven by your password (Argon2id, then AES-256 plus
ChaCha20). There's no public-key key exchange anywhere, so "record it now,
decrypt it once quantum computers exist" doesn't apply, and Shor's algorithm
has nothing to attack. Grover's just halves a 256-bit key, and halving 256
bits still isn't happening.

So I didn't bolt on ML-KEM. There's no key exchange for it to protect; it
would just be a word in the README. The one place a quantum computer actually
bites is the signature, so that's the one place I put post-quantum crypto:
ML-DSA-65, right next to classical Ed25519, both required. That's the honest
scope. I'd rather get one thing right than sprinkle "post-quantum" on
everything.

## Quickstart

```
pip install -r requirements.txt
python folder_vault.py      # GUI, Korean or English (switch in Settings)
python test_vault.py        # 143 checks across 25 categories
```

On Windows just double-click `start.bat`. It builds a venv the first time,
then it's instant.

## How I built this

I used AI to build parts of this, and I'd rather say so straight than pretend
I didn't. The honest version is more interesting anyway.

The decisions are mine. The threat model, why a cascade instead of one
cipher, where post-quantum actually matters and where it'd just be noise, the
rules for never deleting your originals until the encrypted copy is fully
verified, what to test. I worked those out and I can defend any of them.

The implementation, wiring those primitives together, I generated with Claude
Opus 4.7 from my own specs, on top of vetted libraries. Then the integration,
the debugging, and the 143 pass/fail tests were me, including the mean ones:
flipping a byte to check tampering is caught, opening older vault formats, and
making sure a failed encryption can never delete your originals.

I'm 14 and there's a lot of crypto I'm still actually learning (that's what
the roadmap is). Getting people to review this is the whole reason it's
public. The thinking is mine, the implementation had AI help, and saying
which is which honestly is the point. This isn't a vibe-coded toy.

## Threat model

| Threat | Protected? | How / caveat |
|---|---|---|
| Someone steals just the `.foldervault` file | Yes | Encrypted under Argon2id + cascade AEAD; useless without the password |
| Offline password guessing | Mostly | Argon2id, 256 MiB–1 GiB, memory-hard. Still only as good as your password |
| Tampering / reordering / truncation | Yes | Per-chunk AEAD bound to path+index+count, plus a whole-vault hybrid signature |
| Quantum attacker, integrity | Yes | ML-DSA-65 (FIPS 204) alongside Ed25519 |
| Quantum attacker, confidentiality | Yes | Symmetric and password-based; nothing to harvest now and crack later |
| Someone reading RAM while it's running | No | Python can't reliably wipe key bytes from memory. That needs OS-level protection |
| You lose the `.foldervault` file or the password | No | The file *is* the data, and there's no recovery. Keep backups |
| SSD forensic recovery of the old plaintext | Partial | Wear-levelling beats overwrite-erase on any software. The encryption is the real protection, not the deletion |

## Roadmap

- [x] English UI (Korean is still the default)
- [ ] Someone who does crypto for a living actually reviewing this
- [ ] A CLI so you don't need the GUI
- [ ] Reproducible test vectors for the format

## Please tear it apart

This is not production-ready and I'm not going to pretend it is. If you find a
hole, a wrong assumption, or somewhere I'm fooling myself, open an issue (see
[SECURITY.md](SECURITY.md) first). Breaking it is the single most useful thing
you can do for me, and it's the entire reason this repo exists. Read
[SECURITY.md](SECURITY.md) before you trust it with anything that matters,
because I'm honest in there about what it can't do.

## License

MIT. See [LICENSE](LICENSE).
