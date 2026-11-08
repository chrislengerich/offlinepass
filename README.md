# offlinepass (alpha)

A low-dependency password manager in the spirit of [Proton Pass](https://proton.me/pass):
one OpenPGP-encrypted vault file in a git repo, with two clients.

- **Linux (terminal UI)** — search, display, and manage Proton Pass login
  entries; render any entry as a QR code in the terminal.
- **Android (native app)** — the same vault on the phone: unlock with a
  hardware key, full CRUD, live TOTP, git sync, autofill, and QR/qrft
  exports for the [QR Autofill](../qrautofill) app.
- **Chrome extension (Chromebook)** — receives an encrypted single-entry
  paste from the phone's QR and auto-fills it into the browser tab,
  gated by a security-key PIN + touch.

Unlike Proton Pass, however, it works perfectly well fully offline and doesn't leak your sites via remote fetches of favicons. Unlike KeePassXC, it supports security key E2E encryption natively, is modern, simple and self-contained, and has QRFT export to support fully offline password management.

## Repository layout

```
offlinepass/
├── offlinepass.py        # Linux: curses TUI (search, detail, QR, writes, TOTP)
├── passlib.py          # Linux: item model, GPG storage, git sync, generators
├── test_data.json      # Linux: 5 sample entries for testing
├── test_passlib.py     # Linux: unit tests (37)
├── android/            # Android: Gradle project (UI, crypto, git, autofill)
│   └── README.md       #   status, spikes, on-device storage map
├── extension/          # Chrome MV3 extension: scan/pair/decrypt/autofill
│   └── selftest.html   #   crypto-chain self-test (fixed cross-impl vectors)
├── scripts/            # release + vector generation
└── docs/               # design, work plan, testing plan, extension protocol
```

## The shared vault format

The store file is a **Proton Pass JSON export envelope** (`vaults.<id>.items[]`),
extended with sync bookkeeping both clients understand:

| Field | Meaning |
|---|---|
| `rev` | monotonic envelope revision, bumped per save |
| `deviceId` | stable per-clone/per-device id |
| `deletedItemUuids` | tombstones — deletes survive merges/syncs |
| `devices` | paired paste targets (Chrome extension security keys); union-merged by keyId, newer copy wins |
| `removedDeviceIds` | unpaired-device tombstones |
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
  via OpenKeyChain — or, when **screenlock signing** is enrolled in Setup,
  via an AndroidKeystore key gated by the device screen lock, with its
  public key published to `keys/keystore-signer.pub` for independent
  verification), and pushes.
- **QRFT transfer (phone ↔ phone)** — Settings → "Export as QRFT (pick
  entries)" encodes a JSON array of the selected entries into the looping
  QR sender; "Import from QRFT (scan)" opens the in-app camera scanner
  (vendored jsQR + pako) to reassemble it on another device. Imports
  dedupe by `itemUuid` — the local version wins on conflict.
- **Encrypted pastes to the browser** — an entry's "Export as QRFT"
  carries an *"Encrypt to paired paste keys (N)"* checkbox (default on):
  the paste is encrypted once under a random CEK and wrapped to every
  paired Chrome-extension key (any one of them opens it, after a
  security-key PIN + touch); unchecked keeps the plain QR anyone can
  read. The multi-entry picker wraps to a selectable subset.
- **Paste devices (Chrome extension)** — Setup → *"Pair paste device
  (scan)"* reads the extension's single pairing QR into the vault's
  `devices` records (git-synced, newer copy wins); *"Show QR"* re-renders
  a record to restore a pairing on a new Chromebook; *"Remove"* unpairs.
  Protocol and threat model: [`docs/extension-protocol.md`](docs/extension-protocol.md).
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

## Chrome extension (paste receive + autofill)

**What it does** — click the offlinepass icon in Chrome: with a key paired,
the scan window opens instantly for the tab you clicked from; scan the
phone's looping paste QR with the Chromebook's camera; decryption starts
automatically once the transfer completes (insert key → FIDO2 PIN +
touch — no extra click); an entry whose URLs match the tab
(subdomain-aware) **auto-fills** and the window closes; no match → entry
cards with Fill / Reveal / Copy / TOTP-copy. Nothing runs on any site by
default: `activeTab` + no content scripts — the platform grants access
only to the tab you clicked on, and every decryption requires the key.

### Install (ChromeOS / desktop Chrome)

1. `chrome://extensions` → enable **Developer mode** → **Load unpacked**
   → select the `extension/` directory of the repo.
2. Click the offlinepass icon → the pair page opens → follow the two
   touches (set a **FIDO2 PIN** if Chrome asks — the same PIN your
   passkeys use, separate from the OpenPGP/PIV PINs).
3. On the phone: offlinepass → Setup → **"Pair paste device (scan)"** →
   scan the extension's pairing QR → the record lands in the vault and
   syncs to all clients via git.
4. Send a paste: open the entry → **Export as QRFT** → leave
   *"Encrypt to paired paste keys (N)"* checked → scan the looping QR
   with the extension (insert + PIN + touch) → auto-filled.

**Requirements:** a security key with the WebAuthn `prf` extension
(YubiKey 5, fw ≥ 5.3) and Chrome on ChromeOS/desktop. Pairing is per key,
not per Chromebook — the same key works on any machine via the extension,
and the pairing record can be re-shown from the phone (Setup → Paste
devices → "Show QR") to restore a lost browser profile without re-pairing.

### Security model

A paste decrypts only with the paired key present + PIN + touch (touch
every paste; the PIN re-asks per operation in practice — CTAP2.1
auth-token expiry). The extension stores public records plus an
AES-wrapped seed only — the seed never exists in plaintext without the
touch — makes **no network requests**, and decrypts in memory. The
security key accumulates no state: non-resident credential, no passkey
slots used, existing GPG/PIV keys and passkeys untouched. Lost key → it
alone decrypts nothing; unpair on the phone and re-pair. Lost
Chromebook/profile → restore from the phone's "Show QR". Full wire
format, key chain, and threat model:
[`docs/extension-protocol.md`](docs/extension-protocol.md).

### Troubleshooting

- **Pairing fails with a PRF error** — the key lacks `hmac-secret`
  (YubiKey fw < 5.3): update the firmware, or pair the ChromeOS platform
  authenticator instead (PIN-based UV; pairing becomes per-machine).
- **"No paired key for \<keyId\>"** — that key isn't paired in this
  browser: pair it, or restore its pairing QR from the phone.
- **Transfer stalls mid-chunks** — hold the phone steady; the progress
  line names the missing chunk; if nothing moves for 5s, check the
  sender's speed selector on the phone.
- **Decrypt asks for the PIN every time** — expected: the key's PIN/UV
  token expires between operations; the touch is always required.

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
python3 offlinepass.py
# → Search "git" → Enter → select GitHub → Show credentials
# → or Display QR code → scan with the phone

# Android unit tests
cd android && ./gradlew :app:testDebugUnitTest

# Extension self-test (fixed cross-impl vectors; needs a browser)
# → chrome://extensions → offlinepass → "Run self-test" link on the pair page link on the pair page

# Regenerate the cross-implementation vectors (protocol change only)
python3 scripts/gen_device_wrap_vectors.py
```

Linux tests cover item parsing, search matching, password generation, TOTP
(verified against RFC 6238 test vectors), display-name derivation, and file
round-trips. The Android test matrix is defined in `docs/testing-plan.md`
and includes the device-wrap vectors shared with the extension's
self-test page — both sides assert the same numbers, so the JCE and
WebCrypto implementations cannot drift apart.
