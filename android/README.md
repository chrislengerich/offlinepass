# linuxpass Android

Native Android client for the linuxpass vault (design:
`../docs/android-app-design.md`, work plan: `../docs/work-plan.md`).

## Status — Phase 0 (spikes)

| Spike | What | Status |
|---|---|---|
| S1 | OpenKeyChain round-trip vs the real vault | **wired, needs on-device run** (`spike/S1DecryptActivity`) |
| S2 | OpenKeyChain SSH-sign | not started |
| S3 | JGit + SSH transport | not started |
| S4 | Autofill shell | not started |
| S5 | Vendored qrft generator interop | not started |
| S6 | NFC / touch UX timing | not started |

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
