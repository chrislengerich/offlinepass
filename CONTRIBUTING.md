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
- **Encrypted at rest, encrypted to hardware keys.** 
- **Offline-first.** Minimal network requests, offline mode prioritized.
- **Minimal features.** Bugfixes are always welcome. Feature requests are
  considered only when they fit the assumptions above; when in doubt, open
  an issue describing the problem before writing code.
- **Verified commits.** 

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
