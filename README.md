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
that holds a GPG key set** — the three card slots (SIGN, ENCRYPT, AUTH),
modern ECC flavors recommended (cv25519 for the decryption slot,
ed25519/NIST-P256 for signing and auth). The vault's decrypt happens
in-process against the card (the DEC slot), the git commits sign with it
(the SIG slot or the device screenlock key), and the sync authenticates
with it (the AUT slot).

To initialize a key set on the card — either from **Linux** (`gpg
--card-edit`, the authoritative flow) or from **Android** (OpenKeyChain
over NFC/USB) — see the step-by-step in
**[`android/README.md`](android/README.md#initialize-the-security-key-openpgp-key-set)**.

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
