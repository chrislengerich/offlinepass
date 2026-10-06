# Cutting a linuxpass release

The pipeline: **build → stage → sign → verify → publish**, all via
`scripts/release.sh`. Artifacts attach to a GitHub release (they are never
committed into git — `dist/` is gitignored).

## Artifacts

| File | What |
|---|---|
| `linuxpass-vX.Y.Z-debug.apk` | Debuggable build, signed with the debug key — for development installs. |
| `linuxpass-vX.Y.Z-profileable.apk` | Minified release build + `<profileable android:shell="true"/>` — profilers (simpleperf, perfetto) can attach. APK itself is **unsigned** (Android-keystore signing deferred — app-store mechanics); ships with a GPG detached signature. |
| `*.asc` | Detached armored GPG signatures over each APK (`gpg --detach-sign --armor`), made with the security key. Verify: `gpg --verify <file>.asc <file>`. |
| `SHA256SUMS.txt` | sha256 of both APKs; verify downloads with `shasum -a 256 -c`. |

The profileable build installs alongside the debug build (application id
`com.linuxpass.app.profileable`).

## Steps

### 1. Build + stage

```bash
scripts/release.sh build 0.9.0
# → dist/v0.9.0/: unsigned profileable APK, debug APK, release notes, checksums
```

### 2. Sign (manual — the release holder does this)

Each APK is detached-signed with the security key (`gpg --detach-sign
--armor` → `.asc` sidecar). The key's secret half lives on the hardware
token, so expect the touch prompt. To pick a non-default key, export
`LINUXPASS_GPG_KEY=<keyid/email>`:

```bash
scripts/release.sh sign 0.9.0
# → linuxpass-v0.9.0-debug.apk.asc, linuxpass-v0.9.0-profileable.apk.asc
```

Existing `.asc` files are kept (don't get overwritten), so re-running
`sign` is safe. Note the profileable APK is **not** APK-signed — Android
keystore signing is deferred until app-store mechanics; it's not
installable on a device until then (the debug APK is, and is what gets
installed for development).

### 3. Verify

```bash
scripts/release.sh verify 0.9.0
# apksigner verify on both APKs + sha256 check
```

### 4. Publish

Commit the release work first (the script refuses to run on a dirty tree):

```bash
git add -A && git commit -m "Release v0.9.0"
scripts/release.sh publish 0.9.0
```

`publish` creates the annotated tag (`LINUXPASS_SIGN_TAG=1` for a GPG-signed
tag), pushes the branch + tag (SSH — the security key is the SSH identity;
expect the touch prompt), and creates the GitHub release with both APKs +
signatures + checksums + release notes via `gh`. Requires `gh auth login`
with write access to the origin repo.

`publish` is **resumable** — a failed run (e.g. push denied before the key
touch) can simply be re-run: an existing tag is reused as-is for the
release, completed steps are skipped. To move an existing tag to HEAD
instead, `LINUXPASS_RETAG=1`; to sign the tag with GPG,
`LINUXPASS_SIGN_TAG=1`.

## Bumping the version

`android/app/build.gradle.kts` (`versionName`/`versionCode`) — or pass the
version explicitly to every script step; the scripts never touch Gradle.

## Install from a release

```bash
gh release download v0.9.0 -R <owner>/<repo> -p '*-profileable.apk'
adb install -r linuxpass-v0.9.0-profileable.apk
```

The debug APK installs with `-r` the same way.
