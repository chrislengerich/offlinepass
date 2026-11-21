# Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Make your changes.
4. Commit your changes (`git commit -am 'Add new feature'`).
5. Push to the branch (`git push origin feature-branch`).
6. Create a new Pull Request.

## Repo assumptions

This repository is deliberately kept small. All contributions must respect
these assumptions:

- **Minimal code and dependencies.** Prefer the smallest change that fixes
  the problem. The Android app's dependencies are pinned and reviewed
  (the crypto libraries especially); the Chrome extension is zero-dependency
  with its vendored libraries (`extension/vendor/`); the Linux client is
  stdlib Python. Do not introduce frameworks, transpilers, or new build
  tooling.
- **The security invariants are load-bearing.** The vault file is OpenPGP
  ciphertext at rest; the git history carries signed ciphertext commits
  only; the sealed cache is screenlock-gated; the decrypted material lives
  in RAM only and is zeroed on lock/exit; the card operations (the decrypt,
  the sign, the auth) require the PIN/touch. A change must not weaken any
  of these guarantees — when in doubt, the tests pin them
  (`IdleLockStagedStateSweepTest`, `SealedVaultTest`,
  `VaultSaveTransactionTest`), and a change that alters the crypto surface
  must extend them.
- **Minimal features.** Bugfixes are always welcome. Feature requests are
  considered only when they fit the assumptions above; when in doubt, open
  an issue describing the problem before writing code.
- **Verified commits.** The commits are signed with the hardware security
  key (the same OpenPGP key set the vault itself uses) — the signed history
  is the project's audit trail.
- **Offline-first.** No network requests beyond the user-configured git
  sync transport; the extension makes none at all.

## Tests

CI runs the test matrix on every push and pull request (the badge in the
README). Please run it locally before submitting, and add tests for
bugfixes:

```sh
# The Linux client (stdlib Python, no terminal needed)
python3 linux/test_passlib.py

# The Android unit suite (Robolectric; JDK 17 + the Android SDK)
cd android && ./gradlew testDebugUnitTest

# The extension's paste-crypto contract test (Node ≥ 19, no deps)
node extension/test/wrap_contract_test.mjs

# The release build's baseline-profile guard (after a release build)
scripts/verify-profile.sh
```

The crypto algorithms' behavior is pinned by test — the signer matrix,
the Ed25519/ECDSA/RSA signature shapes, the ECDH decrypt edges (see
`docs/testing-plan.md` for the full plan and the hardware-in-the-loop
layers, which run manually on real devices).
