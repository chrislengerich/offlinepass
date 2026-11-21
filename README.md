# offlinepass (alpha)

A low-dependency password manager in the spirit of [Proton Pass](https://proton.me/pass):
one OpenPGP-encrypted vault file in a git repo, with three clients.

- **Linux (terminal UI)** — this repo's `offlinepass.py`: search, display,
  and manage Proton Pass login entries; render any entry as a QR code.
  See [the Linux client](#linux-client-tui) below.
- **Android (native app)** — the same vault on the phone: unlock with a
  hardware key, full CRUD, live TOTP, git sync, autofill, and QR/qrft
  exports. **[`android/README.md`](android/README.md)**
- **Chrome extension** — receives an encrypted single-entry paste from
  the phone's QR and auto-fills it into the browser tab, gated by a
  security-key PIN + touch. **[`extension/README.md`](extension/README.md)**
- **Release tooling** — the build/sign/verify/publish pipeline, the
  baseline-profile generator, and the protocol vector generators.
  **[`scripts/README.md`](scripts/README.md)**

Unlike Proton Pass, however, it works perfectly well fully offline and
doesn't leak your sites via remote fetches of favicons. Unlike KeePassXC,
it supports security key E2E encryption natively, is modern, simple and
self-contained, and has QRFT export to support fully offline password
management. It also encrypts unused memory at rest, can be configured to
back up to any Git remote or USB cold storage.

## Prerequisites: a security key holding an OpenPGP key set

The whole system assumes a **YubiKey (or any OpenPGP-compatible token)
that holds a GPG key set** — the three card slots (SIGN, ENCRYPT, AUTH).
The vault's decrypt happens in-process against the card (the DEC slot),
the git commits sign with it (the SIG slot or the device screenlock
key), and the sync authenticates with it (the AUT slot).

To initialize a key set on the card — either from **Linux** (`gpg
--card-edit`, the authoritative flow) or from **Android** (OpenKeyChain
over NFC/USB) — see the step-by-step in
**[`android/README.md`](android/README.md#initialize-the-security-key-openpgp-key-set)**.

## Security & authentication

### Encryption suites (the vault at rest, synced)

| Layer | What | Details |
|---|---|---|
| Vault file (`state/10.gpg`) | OpenPGP SEIPD | AES-256 session key, MDC-integrity-checked, encrypted to the recipients' public keys |
| Recipient key types | RSA-3072 / RSA-4096 / **ECDH P-256** | RSA (the screenlock-derived key, the card's DEC slot) and EC (the card's EC DEC slot) — the encrypt side accepts any BC-supported OpenPGP public key |
| Device-local sealed cache | AES-256-GCM | each item's secrets sealed directly under the screenlock-gated AndroidKeyStore key (no KEK, no wrapping layer); never synced |

### Authentication types

| What | Where | Mechanism |
|---|---|---|
| Hardware security key | the vault decrypt, the commit signing, the SSH sync | OpenPGP card: the PIN + the touch per operation (PSO:DEC / internally consistent) |
| Device screenlock | the entry gate, the at-rest seal, screenlock commit signing | the AndroidKeyStore keys gated by biometric/PIN (the 60 s validity window) |
| SSH keys over GitHub | the git sync transport | `rsa-sha2-256`/`rsa-sha2-512`, `ecdsa-sha2-nistp256`, `ssh-ed25519` |
| HTTPS + PAT | the git sync transport (deprecated) | the fine-grained PAT, stored encrypted |

## Key-type support roadmap

The card slots (the OpenPGP applet) and what the app does with each —
the encrypt side is BC-native (it emits PKESKs for any supported
algorithm); the card-side decrypt/sign needs per-algorithm support:

| Key type (slot) | Sign | Encrypt/decrypt | Status |
|---|---|---|---|
| RSA-3072/4096 (DEC, SIG) | ✓ | ✓ | supported (the PSO:DEC RSA path) |
| ECDSA NIST P-256/P-384/P-521 (SIG/AUT) | ✓ | n/a | supported (the commit signing — the curve-agnostic r/s MPIs; the SSH auth via YubiKit) |
| ECDH NIST P-256 (DEC) | — | ✓ | the card PSO:DEC with the ephemeral point; the card performs the RFC 6637 KDF + the AES-key-unwrap |
| ECDH NIST P-384/P-521 (DEC) | — | ✓ | the same flow; the point length follows the card's reported key |
| ECDH Curve25519 (DEC) | — | ✓ | the same flow (the v6-era packets; the card applet 5.7+ / the OpenPGP 3.4 cards) |
| Ed25519 (SIG/AUT) | ✓ | n/a | supported — the alg-22 sig body (the card PureEdDSAs the raw SHA-256 digest per the card spec's digest-only PSO:CDS; the BC round-trip test pins it) |
| RSA-2048 (any slot) | supported | supported | the same paths as RSA-4096 (the shorter moduli) |
| ML-KEM / ML-DSA (PQ) | — | — | **not supported** — BC 1.87 has the low-level packet shapes but no high-level OpenPGP PQ paths; unblocks with BC 1.88+ (and the PQ hardware is further out) — see TODO.md |
| secp256k1 | not planned | not planned | the niche OpenPGP use |

The unit-test strategy: BC's own `BcPublicKeyDataDecryptorFactory`
implements the exact RFC 6637 math the card performs — the tests use it
as the fake card, so the app's decrypt pipeline is proven against the
card's contract without hardware in the loop.

**OpenPGP v6**: the v6 PKESK dispatch is pinned by test; the v6-ECDH
session-data recovery is still blocked on BC 1.87 (see TODO.md) — the
AEAD SEIPD-v2 support follows the same BC upgrade.

## Repository layout

```
offlinepass/
├── offlinepass.py          # Linux: curses TUI (search, detail, QR, writes, TOTP)
├── passlib.py              # Linux: item model, GPG storage, git sync, generators
├── test_data.json          # Linux: 5 sample entries for testing
├── test_passlib.py         # Linux: unit tests (37)
├── android/                # Android: Gradle project — README has the build/
│   └── README.md           #   test/release instructions + the key-init guide
├── extension/              # Chrome MV3 extension: scan/pair/decrypt/autofill
│   ├── README.md           #   install, security model, the contract test
│   └── test/               #   the paste-crypto contract test (node)
├── scripts/                # release pipeline + generators — README covers each
│   └── README.md
└── docs/                   # design, work plan, testing plan, extension protocol
```

## The shared vault format

The store file is a **Proton Pass JSON export envelope** (`vaults.<id>.items[]`),
extended with sync bookkeeping all clients understand:

| Field | Meaning |
|---|---|
| `rev` | monotonic envelope revision, bumped per save |
| `deviceId` | stable per-clone/per-device id |
| `deletedItemUuids` | tombstones — deletes survive merges/syncs |
| `devices` | paired paste targets (Chrome extension security keys); union-merged by keyId, newer copy wins |
| `removedDeviceIds` | unpaired-device tombstones |
| *(unknown fields)* | preserved verbatim through round-trips |

The file is **always ciphertext at rest**: GPG-encrypted on the desktop,
card-encrypted on the phone (in-process YubiKit + BouncyCastle framing),
to the configured recipients. Git history holds ciphertext commits only —
that enables rollback/audit without exposing content, and sync is
ordinary pull/push with an application-level union-merge (by `itemUuid` +
tombstones) when two devices diverge.

### QR exports

"Display QR code" (TUI) and "Export as QRFT" (Android) encode one item —
the object inside `vaults.<id>.items[]`. The Android app's
`ProtonPassParser` reads `data.content.itemUsername` (falling back to
`itemEmail`) and `data.content.password`:

```json
{"itemId":"...","shareId":"local","data":{"type":"login","metadata":{"name":"GitHub","itemUuid":"..."},"content":{"itemEmail":"","itemUsername":"ko","password":"secret","urls":["https://github.com"],"totpUri":"","passkeys":[]}},"state":1,...}
```

Keep the payload small — the minimal item (~100 chars) produces a 21x21 QR
that scans in under a second.

## Linux client (TUI)

### Install

Prerequisites: Python 3.12+, `qrencode`, `gpg` (production only), `git`
(optional, for auto-commit).

```bash
# 1. Clone the repo
git clone <repo-url> ~/offlinepass
cd ~/offlinepass

# 2. Install system dependencies
sudo apt install qrencode gpg

# 3. (Optional) Set up encrypted storage with git sync
mkdir -p ~/product/state && cd ~/product/state && git init
cd ~/offlinepass

# 4. Run in test mode (unencrypted, no GPG needed)
python3 offlinepass.py
```

### Production configuration

```bash
offlinepass_USE_GPG=1 \
offlinepass_GPG_RECIPIENTS="key-id-1,key-id-2" \
offlinepass_FILE="~/product/state/10.gpg" \
offlinepass_GIT_DIR="~/product/state" \
python3 offlinepass.py
```

(Or export the variables in your shell profile; the single-recipient form
`offlinepass_GPG_RECIPIENT` also works.)

| Variable | Default | Description |
|----------|---------|-------------|
| `offlinepass_FILE` | `~/offlinepass/test_data.json` | Path to store file |
| `offlinepass_USE_GPG` | `0` | Set to `1` for GPG encryption |
| `offlinepass_GPG_RECIPIENTS` | — | Comma-separated GPG key IDs/emails |
| `offlinepass_GIT_DIR` | directory of `offlinepass_FILE` | Git repo root for auto-commit |

### Usage

- **Main menu** — Search, Add entry (username or SimpleLogin-style email
  alias; generated 24-char password, editable), git repo location, Quit.
- **Entry detail** — Display QR code, Show credentials (live TOTP with
  countdown when enrolled), Update password, Enroll TOTP (base32 secret or
  `otpauth://` URI), Back.
- **Add entry** collects URL, username/alias, password, and notes; display
  names derive from explicit name → URL domain → username → email.
- **Search** matches all words across name, username, email, URL, and note.

| Key | Action |
|-----|--------|
| `j` / `↓`, `k` / `↑` | move down / up |
| `Enter` | select / confirm |
| `q` / `Esc` | back / cancel |
| any key | dismiss message / exit credentials view |

On exit the TUI pushes any pending commit to the remote (best-effort,
`GIT_TERMINAL_PROMPT=0`).

## Testing

```bash
# Linux unit tests (no terminal needed)
python3 test_passlib.py

# Interactive TUI test
python3 offlinepass.py
# → Search "git" → Enter → select GitHub → Show credentials
# → or Display QR code → scan with the phone

# Android unit tests + the paste-crypto contract test
cd android && ./gradlew :app:testDebugUnitTest
node extension/test/wrap_contract_test.mjs

# Extension self-test (fixed cross-impl vectors; needs a browser)
# → chrome://extensions → offlinepass → the "Run self-test" link
```

Linux tests cover item parsing, search matching, password generation, TOTP
(verified against RFC 6238 test vectors), display-name derivation, and
file round-trips. The Android side (229 unit tests + the extension
contract test) is detailed in
[`android/README.md`](android/README.md#test-layout) and
[`docs/testing-plan.md`](docs/testing-plan.md).
