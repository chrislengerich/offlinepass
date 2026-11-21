# Work notes: JGit baseline profile + the setup-snapshot revert (post-0.10.4)

Date: 2026-11-20 · branch `paste-fix-0.10.5`

## What changed

### 1. The setup-snapshot mechanic removed (the post-v0.10.4 parts only)

`ac4bce9` added a Setup "async snapshot" (`setupSnapshot` / `readRepoSnapshot()`
/ `RepoSnapshot` / `invalidateSetupSnapshot()`) as a workaround for the Setup
first-load slowness. The UI side (the interstitial) never landed — the state
was dead code, but it added a lifetime to track (the invalidate-on-save hook in
the save path). Removed from `VaultSession.kt`:

- `var setupSnapshot: RepoSnapshot?`
- `fun invalidateSetupSnapshot()`
- `data class RepoSnapshot`
- `fun readRepoSnapshot(...)`
- the `invalidateSetupSnapshot()` call in the save path

**Kept** (pre-v0.10.4, unrelated): the save-path *transaction* snapshot (the
rollback machinery), `headCommitShort()` / `recentCommits()` /
`syncDivergenceText()` (the Setup's synchronous git reads), and the
`SetupTiming` log lines in `SetupTab.kt` — the logs stay until the on-device
Setup timing is re-measured on a profiled build, then they go.

The speed problem is solved properly instead by the baseline profile (below).

### 2. The JGit baseline profile

`android/app/src/main/baseline-prof.txt` (manual, wildcard rules):

```
Lorg/eclipse/jgit/**;
Lcom/jcraft/jsch/**;
Lorg/bouncycastle/openpgp/**;
Lorg/bouncycastle/crypto/**;
```

- ART pre-compiles these at install on **non-debuggable** builds only
  (debuggable processes ignore profiles — don't benchmark on `debug`).
- The `profileable` tag is unrelated to profiles: plain `release` gets the
  same treatment. `profileable` only allows profilers to attach.
- Wildcard **class** rules must be bare (no `HSPL` prefix) — AGP's
  `expandArtProfileWildcards` rejects flags on class rules.
- BC is scoped to the `openpgp`/`crypto` packages (the envelope + the
  commit-signing paths); a blanket BC rule would bloat the odex.
- AGP rewrites the rules through the R8 mapping automatically — verified
  (below). `androidx.profileinstaller:profileinstaller:1.3.1` added as
  belt-and-suspenders (ART reads the APK profile natively at install; the
  library adds ProfileVerifier for assertions).

## Verification (all done)

1. **Unit suite**: `./gradlew testDebugUnitTest` — 206 tests, 0 failures.
2. **Profile packaging**: `assembleRelease` → `assets/dexopt/baseline.prof`
   (4,390 B) in the APK. Wildcards expanded to 33k rules; profgen
   `dumpProfile` against the APK + mapping confirms the binary profile maps
   onto the OBFUSCATED dex correctly: 712 JGit + 306 JSch + 147 BC classes
   (5,986 method rules, 2,833 class rules total).
3. **On-device** (Pixel, Android 17): `assembleProfileable` signed with a
   throwaway key, installed as the separate `com.offlinepass.app.profileable`
   package (the real `com.offlinepass.app` install untouched). After
   `bg-dexopt-job`: **`[status=speed] [reason=bg-dexopt]`** — the profiled
   JGit/JSch/BC surface is AOT-compiled instead of first-touch JIT.
   `dumpsys package dexopt` Package Usage Score: 0.9999 (the profile is
   registered and prioritized). Test install uninstalled after.

## Follow-ups (not done here)

1. **Measure Setup first-load on the profileable install** — the
   `offlinepass·p` build is LEFT INSTALLED for testing (separate package,
   own fresh data; the real install is untouched). Create a scratch vault
   on it, run the first Setup load, and read the `SetupTiming` logcat lines
   (`adb logcat -s SetupTiming`). Compare the pre-profile APK (the
   app-release-signed.apk at the repo root, built before the profile) if a
   baseline number is wanted. When confirmed fast: strip the four
   `android.util.Log.i("SetupTiming", ...)` lines from `SetupTab.kt`
   (446, 478, 580, 582) and the `SideEffect`.
   NOTE: the test install is signed with a THROWAWAY key
   (/tmp/opencode/verify.jks) — a future properly-signed profileable build
   needs an uninstall first (signature mismatch blocks the update; the
   scratch data goes with it, by design).
2. **YubiKey commit-signing UI restore** (separate task): `72c49b9` removed
   the Setup's "Sync via YubiKey SSH (OpenKeyChain)" button + enrollment
   dialog — the backend (`onEnrollYubikeySsh`, `onPickAuthSubkey`,
   `MainActivity.enrollYubikeySsh()`, `VaultSession.setYubikeySsh()`) is all
   still wired. Without the enrollment UI, `yubikeyAuthSubkeyId()` is null
   and the Commit signer section's "Use the YubiKey (touch to sign)" button
   never renders. Restore the dialog into the Deployment section + a
   not-enrolled hint in the Commit signer section + fix the stale
   "Setup → Choose key" pointers (`MainActivity.kt`, `VaultSession.kt`).
