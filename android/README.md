# linuxpass Android

Native Android client for the linuxpass vault (design:
`../docs/android-app-design.md`, work plan: `../docs/work-plan.md`).

## Status — Phase 0 (spikes)

| Spike | What | Status |
|---|---|---|
| S1 | OpenKeyChain round-trip vs the real vault | **integration proven + end-to-end UI pass** (software-key; real-applet run pending) |
| S2 | Sign-action probe | **done** — OpenKeyChain signs PGP-only → git auth via PAT; Keystore SSH identity committed for later |
| S3 | JGit transport | **PASS** — clone/fetch/commit/push over HTTPS+PAT; now the production transport in-app |
| S4 | Autofill | **PASS** — service enabled, datasets offered, form filled |
| S5 | Vendored qrft generator interop | **PASS** — payload prefilled, sender auto-starts in WebView |
| S6 | NFC / touch UX timing | pending (needs the real YubiKey applet flow) |
| S4 | Autofill shell | not started |
| S5 | Vendored qrft generator interop | not started |
| S6 | NFC / touch UX timing | pending (needs the real YubiKey applet flow) |

## On-device storage & encryption

Everything lives in **app-private storage** (readable only by the app's
UID — and by `adb` only for debug builds via `run-as`).

```
filesDir/
├── vault/
│   ├── repo/                  # REMOTE mode: git clone of the vault repo
│   │   ├── state/10.gpg       #   the vault file — OpenPGP ciphertext
│   │   └── .git/              #   full history of ciphertext commits only
│   └── local/
│       └── 10.gpg             # LOCAL-ONLY mode: same format, no git
└── vault_config.xml-style prefs:
    ├── remoteUrl, recipientEmails, recipientKeyIds   # NOT secrets
    └── deviceId               # per-install UUID (envelope bookkeeping)

shared_prefs/linuxpass_secret_keys.xml
└── pat → AES-256-GCM blob wrapped by an AndroidKeyStore key
        (the wrapping key is TEE-held + non-exportable)
```

**Encryption states, per artifact:**

| Artifact | State |
|---|---|
| Vault file (`10.gpg`) | OpenPGP ciphertext (RFC 4880), encrypted to the configured recipients: YubiKey-held keys (desktop `gpg`, touch+PIN; phone OpenKeyChain, touch+PIN) and/or a device-held software key (noodlefish pattern). **Never plaintext on disk.** |
| Git history | Ciphertext commits only — the history enables rollback/audit without exposing content. |
| PAT | AES-256-GCM blob; the wrapping key lives in the hardware Keystore. A stolen device + pulled files can't unwrap it. |
| Decrypted entries | **RAM only**, while the session is unlocked. |
| QR exports | Plaintext by explicit user choice (screen = trust boundary); generated transiently, never persisted. |

**What a stolen device yields:** vault ciphertext + a wrapped token. No
plaintext, no keys, no decryptable state.

## Building

Requires Android SDK (compileSdk 36) + JDK 17 — same toolchain as
offlinecam. First build downloads Gradle 8.13 + dependencies.

```bash
cd android
./gradlew :app:assembleDebug        # debug APK
./gradlew :app:testDebugUnitTest    # L1 JVM suite
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

## Running spike S1 (hardware-in-the-loop)

Prereqs: OpenKeychain installed, your YubiKey paired in it (applet keys
imported/detected), the app approved inside OpenKeychain on first use.

1. Open the app → **Open Spike S1**.
2. **Pick vault file** → choose your `10.gpg` (from the vault repo working
   tree, or via Files). Key touch + PIN → expect
   `OK: <N> bytes, signature=…`.
3. Enter the OpenKeychain identity email that matches the GPG key you
   encrypt with on desktop → **Re-encrypt**.
4. **Share** the re-encrypted file to the desktop, then decrypt it there:
   ```bash
   gpg --decrypt re-encrypted.gpg > /tmp/roundtrip.json
   ```
   Compare against a plaintext decrypt of the original (`gpg --decrypt
   10.gpg`). Record the result in `docs/testing-plan.md` (T-D-01..03,
   T-X-01).

Repeat step 2 with the key on USB (not NFC) for T-D-02.

## Notes

- `crypto/OpenPgpClient.kt` is lifted from offlinecam (Apache-2.0 protocol
  surface; docs reworded for the vault context).
- The qrft generator pages get vendored under
  `app/src/main/assets/qrft/` when spike S5 starts.
