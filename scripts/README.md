# offlinepass scripts

The release pipeline and the generators. Run everything from the repo
root unless noted.

## The release pipeline (`release.sh`)

Build → stage → sign → verify → publish. The only human steps are the
YubiKey touches and running the GPG step in a terminal with a working
pinentry.

```bash
# 1. Build + stage dist/vX.Y.Z/ (all three variants; runs the
#    baseline-profile verification below)
scripts/release.sh build 0.10.5

# 2. Sign the release APK with the YubiKey (PKCS11; expect the touch).
#    NOTE: android/sign.sh runs from android/ and reads android/opensc.cfg
#    (the PKCS11 driver config: OpenSC + the slot).
cd android && ./sign.sh && cd ..

# 3. GPG-detach-sign every staged artifact — run in YOUR terminal
#    (pinentry needs a TTY; a non-interactive shell fails with
#    "Inappropriate ioctl for device")
scripts/release.sh sign 0.10.5

# 4. Verify (gpg + checksums) at any time
scripts/release.sh verify 0.10.5

# 5. Publish: the commit-check, the tag, the push, the GH release.
#    Requires a clean tree + gh authed with repo write; resumable
#    (completed steps skipped; OFFLINEPASS_RETAG=1 moves a stale tag).
scripts/release.sh publish 0.10.5
```

Artifacts attach to the GitHub release only — `dist/` is gitignored.
Env knobs: `OFFLINEPASS_VERSION`, `OFFLINEPASS_GPG_KEY` (a non-default
signing key), `OFFLINEPASS_RENOTES=1` (regenerate the stage's release
notes).

## The APK signing (`../android/sign.sh`)

Signs the release APK with the OpenPGP SIG certificate via OpenSC/PKCS11
(the same security key offlinecam signs with). Expects the touch; writes
`android/app-release-signed.apk` (the device-install artifact). The
`.idsig` sidecar (the v4 signature) travels with it.

## The baseline profile (`verify-profile.sh`, `gen-baseline-profile.py`)

The release APK embeds a baseline profile: the JGit/JSch/BouncyCastle
method rules ART pre-compiles at install — the first Setup/sync never
pays the JIT cliff.

- **`verify-profile.sh`** — the packaging guard (runs automatically
  inside `release.sh build`): dumps the assembled release's compiled
  profile and asserts the method-rule counts (≥ 5000 jgit, ≥ 1500 jsch,
  ≥ 800 bc; `Git.open`/`Git.commit` present). Guards the silent-death
  modes: a mangled rule (the L-type's trailing `;` is descriptor
  content!), and the R8 rename drop (fixed by `-keepnames` on the
  scoped packages — allowshrinking still strips unused code).

- **`gen-baseline-profile.py`** — regenerates the METHOD-level rules by
  static analysis (javap over the pinned jars — no device, no
  macrobenchmark). Run after any dependency bump; the rules land in
  `android/app/src/main/baseline-prof.txt` between the GENERATED
  markers.

## The protocol vector generator (`gen_device_wrap_vectors.py`)

Generates the fixed cross-implementation vectors for the device-wrap
protocol (the paste path): the seed wrap, the ECDH/HKDF paste KEK, the
two-target wrapped paste, and the expected plaintext. The SAME numbers
are pinned by the Android `DeviceWrapTest` and driven through the
extension's real `wrap.js` by `extension/test/wrap_contract_test.mjs` —
the two implementations cannot drift without a red test. Run after any
protocol change and re-embed.

## The YubiKey helper (`yubikey_ec_auth_key.sh`)

A desktop one-shot: swaps the card's AUTH slot to an ECDSA P-256 key
(the admin PIN required; the old AUTH key is destroyed). Background:
the EC-AUT path and the RSA-4096-over-USB dead end are documented in the
script's header.

## The commit-signature verifier (`verify-commit-sig.py`)

Verifies a git commit's OpenPGP signature offline (the audit trail's
spot-check): the signed content + the gpgsig header against the
enrolled public keys.

## Reference

- `../docs/release.md` — the release doc
- `../android/README.md` — the app's build/test/storage map + the
  security-key initialization guide (Linux gpg + Android OpenKeyChain)
- `../docs/testing-plan.md` — the test layers and the hardware-in-the-loop plan
