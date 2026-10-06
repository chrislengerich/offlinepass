# Cutting a linuxpass release

The pipeline: **build → stage → sign → verify → publish**, all via
`scripts/release.sh`. Artifacts attach to a GitHub release (they are never
committed into git — `dist/` is gitignored).

## Artifacts

| File | What |
|---|---|
| `linuxpass-vX.Y.Z-debug.apk` | Debuggable build, signed with the debug key — for development installs. |
| `linuxpass-vX.Y.Z-profileable.apk` | Minified release build + `<profileable android:shell="true"/>` — profilers (simpleperf, perfetto) can attach. Signed with the release key. |
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

Needs a release keystore. Create one if missing:

```bash
keytool -genkeypair -v -keystore ~/linuxpass-release.keystore \
  -alias linuxpass -keyalg RSA -keysize 4096 -validity 10000
```

Sign the profileable APK (passwords are prompted for if not exported):

```bash
export LINUXPASS_KEYSTORE=~/linuxpass-release.keystore
export LINUXPASS_KEY_ALIAS=linuxpass
scripts/release.sh sign 0.9.0
# → dist/v0.9.0/linuxpass-v0.9.0-profileable.apk (signed), checksums refreshed
```

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
tag), pushes the branch + tag, and creates the GitHub release with both APKs
+ checksums + release notes via `gh`. Requires `gh auth login` with write
access to the origin repo.

## Bumping the version

`android/app/build.gradle.kts` (`versionName`/`versionCode`) — or pass the
version explicitly to every script step; the scripts never touch Gradle.

## Install from a release

```bash
gh release download v0.9.0 -R <owner>/<repo> -p '*-profileable.apk'
adb install -r linuxpass-v0.9.0-profileable.apk
```

The debug APK installs with `-r` the same way.
