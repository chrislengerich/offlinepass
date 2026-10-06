# linuxpass

A low-dependency password manager in the spirit of [Proton Pass](https://proton.me/pass):
one OpenPGP-encrypted vault file in a git repo, with two clients that
share it —

- **Linux (terminal UI)** — search, display, and manage Proton Pass login
  entries; render any entry as a QR code in the terminal.
- **Android (native app)** — the same vault on the phone: unlock with a
  hardware key, full CRUD, live TOTP, git sync, autofill, and QR/qrft
  exports for the [QR Autofill](../qrautofill) app.

```
$T $                    Linux: qrencode in the terminal
██████  ████  ██  ██        ↓ scan
██  ██ ▄▄▄▄▄ █ █▀▄█▄█ ▄▄▄▄▄ ██  ██    Android: QRFT export in-app
██  ██ █   █ █  ▀▄ █   █ ██  ██        ↓
...                                    autofill in any app
Scan with the phone → autofill
```

## Repository layout

```
linuxpass/
├── linuxpass.py        # Linux: curses TUI (search, detail, QR, writes, TOTP)
├── passlib.py          # Linux: item model, GPG storage, git sync, generators
├── test_data.json      # Linux: 5 sample entries for testing
├── test_passlib.py     # Linux: unit tests (36)
├── android/            # Android: Gradle project (UI, crypto, git, autofill)
│   └── README.md       #   status, spikes, on-device storage map
└── docs/               # design, work plan, testing plan
```

## The shared vault format

The store file is a **Proton Pass JSON export envelope** (`vaults.<id>.items[]`),
extended with sync bookkeeping both clients understand:

| Field | Meaning |
|---|---|
| `rev` | monotonic envelope revision, bumped per save |
| `deviceId` | stable per-clone/per-device id |
| `deletedItemUuids` | tombstones — deletes survive merges/syncs |
| *(unknown fields)* | preserved verbatim through round-trips |

The file is **always ciphertext at rest**: GPG-encrypted on the desktop,
OpenKeyChain-encrypted on the phone, to the configured recipients
(YubiKey-held OpenPGP keys and/or a device-held software key). Git history
holds ciphertext commits only — that enables rollback/audit without
exposing content, and sync is ordinary pull/push with an application-level
union-merge (by `itemUuid` + tombstones) when two devices diverge.

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
git clone <repo-url> ~/linuxpass
cd ~/linuxpass

# 2. Install system dependencies
sudo apt install qrencode gpg

# 3. (Optional) Set up encrypted storage with git sync
mkdir -p ~/product/state && cd ~/product/state && git init
cd ~/linuxpass

# 4. Run in test mode (unencrypted, no GPG needed)
python3 linuxpass.py
```

### Production configuration

```bash
LINUXPASS_USE_GPG=1 \
LINUXPASS_GPG_RECIPIENTS="key-id-1,key-id-2" \
LINUXPASS_FILE="~/product/state/10.gpg" \
LINUXPASS_GIT_DIR="~/product/state" \
python3 linuxpass.py
```

(Or export the variables in your shell profile; the single-recipient form
`LINUXPASS_GPG_RECIPIENT` also works.)

| Variable | Default | Description |
|----------|---------|-------------|
| `LINUXPASS_FILE` | `~/linuxpass/test_data.json` | Path to store file |
| `LINUXPASS_USE_GPG` | `0` | Set to `1` for GPG encryption |
| `LINUXPASS_GPG_RECIPIENTS` | — | Comma-separated GPG key IDs/emails |
| `LINUXPASS_GIT_DIR` | directory of `LINUXPASS_FILE` | Git repo root for auto-commit |

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

## Android client

Status, spike results, and the per-file on-device storage map live in
[`android/README.md`](android/README.md); design and plans in
[`docs/android-app-design.md`](docs/android-app-design.md),
[`docs/work-plan.md`](docs/work-plan.md),
[`docs/testing-plan.md`](docs/testing-plan.md).

Build:

```bash
cd android && ./gradlew :app:assembleDebug
```

### What it does

- **Unlock** — clone/fetch the repo (PAT over HTTPS), decrypt
  `state/10.gpg` via OpenKeyChain (YubiKey touch + PIN); optional
  biometric/PIN gate before the key.
- **CRUD + TOTP** — search, add/edit (URL, username/email, editable
  password, notes), update password, enroll TOTP with live countdown,
  tombstoned delete; entries carry a last-modified timestamp (shown in the
  list and detail views, with an optional secondary sort "most recently
  modified first", default on); every save re-encrypts, commits (signed
  via OpenKeyChain), and pushes.
- **QRFT transfer (phone ↔ phone)** — Settings → "Export as QRFT (pick
  entries)" encodes a JSON array of the selected entries into the looping
  QR sender; "Import from QRFT (scan)" opens the in-app camera scanner
  (vendored jsQR + pako) to reassemble it on another device. Imports
  dedupe by `itemUuid` — the local version wins on conflict.
- **Sync** — explicit "Sync now" with divergence detection: behind →
  fast-forward, diverged → union-merge and re-encrypt; local-only mode runs
  the same repo without a remote.
- **Setup tab** — remote config, recipients (OpenKeyChain picker), commit
  signer, USB save/restore, autofill enablement, screen-lock gate,
  lock-vault action.

### Security posture

| Artifact | State |
|---|---|
| Vault file (`10.gpg`) | OpenPGP ciphertext to the configured recipients. **Never plaintext on disk.** |
| Git history | Ciphertext commits only |
| PAT | AES-256-GCM blob wrapped by AndroidKeyStore (TEE-held) |
| Decrypted entries | **RAM only**, while the session is unlocked |
| QR exports | Plaintext by explicit user choice (screen = trust boundary); generated in memory and injected into the WebView — never persisted to disk |

**Zeroing.** Decrypted material is deliberately erased, not left behind:

- Every decrypt/encrypt call runs through a cache-dir temp file that is
  **zero-filled and deleted on exit of the call** (`SecureWipe`) — unlock,
  save, merge re-encrypt, and USB restore alike.
- The OpenPGP pipe pump zeroes its 64 KB transfer buffer (it carries
  plaintext chunks during decrypt).
- On **exit** (`Activity.onDestroy` when finishing) and via **Setup →
  "Lock vault (zero decrypted data)"**, `VaultSession.zero()` drops the
  unlocked item list and envelope, wipes all plaintext temp files, steps
  the state machine back to Locked, and hints GC.

Zeroing is best-effort in two documented ways: Java strings are immutable,
so heap copies are released for GC rather than overwritten; and flash
wear-leveling limits in-place overwrites. The primary defenses remain
ciphertext-at-rest and app-private storage — zeroing shrinks the window,
it is not a guarantee.

**What a stolen device yields:** vault ciphertext + a wrapped token. No
plaintext, no keys, no decryptable state.

## Releases

Release artifacts (debug + profileable APKs) attach to GitHub releases —
`docs/release.md` and `scripts/release.sh` cover build → sign → verify →
publish. `scripts/release.sh verify <version>` re-checks signatures and
checksums at any time.

## Testing

```bash
# Linux unit tests (no terminal needed)
python3 test_passlib.py

# Interactive TUI test
python3 linuxpass.py
# → Search "git" → Enter → select GitHub → Show credentials
# → or Display QR code → scan with the phone

# Android unit tests
cd android && ./gradlew :app:testDebugUnitTest
```

Linux tests cover item parsing, search matching, password generation, TOTP
(verified against RFC 6238 test vectors), display-name derivation, and file
round-trips. The Android test matrix is defined in `docs/testing-plan.md`.
