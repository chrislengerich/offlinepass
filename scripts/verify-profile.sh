#!/usr/bin/env bash
# Verify the assembled release APK's baseline profile: the METHOD-level
# rules (scripts/gen-baseline-profile.py) must be present and mapped onto
# the dex. Guards the silent-death failure modes that actually happened:
# (1) the L-type return's ';' stripped from the rules → every non-void
# method's rule dropped; (2) R8 method renames → renamed methods' rules
# dropped (fixed with -keepnames); (3) a rule file lost from packaging.
# Run AFTER assembleRelease:  scripts/verify-profile.sh [apk]
# Exits nonzero on any assertion failure.
set -euo pipefail
cd "$(dirname "$0")/.."

APK="${1:-android/app/build/outputs/apk/release/app-release-unsigned.apk}"

# The profgen discovery: the ANDROID_HOME/the SDK roots first (the CI's
# layout), then the local default.
PROFGEN=""
for root in "${ANDROID_HOME:-}" "${ANDROID_SDK_ROOT:-}" "$HOME/android-sdk"; do
  [ -n "$root" ] || continue
  PROFGEN=$(ls "$root"/cmdline-tools/*/bin/profgen 2>/dev/null | sort -V | tail -1)
  [ -n "$PROFGEN" ] && break
done
[ -n "$PROFGEN" ] || { echo "profgen not found (cmdline-tools in ANDROID_HOME)"; exit 1; }
[ -f "$APK" ] || { echo "APK not built: $APK"; exit 1; }

# The APK carries the profile at all (capture, don't pipe: pipefail +
# grep -q's early exit SIGPIPEs unzip and fakes a failure).
UNZIP_OUT=$(unzip -l "$APK")
[[ "$UNZIP_OUT" == *"assets/dexopt/baseline.prof"* ]] || {
  echo "FAIL: assets/dexopt/baseline.prof missing from $APK"; exit 1; }

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
"$PROFGEN" dumpProfile -p \
  android/app/build/intermediates/binary_art_profile/release/compileReleaseArtProfile/baseline.prof \
  -a "$APK" -o "$TMP/dump.txt"

count() { grep -c "^$1" "$TMP/dump.txt" || true; }

JGIT=$(count 'HSPLorg/eclipse/jgit')
JSCH=$(count 'HSPLcom/jcraft')
BC=$(count 'HSPLorg/bouncycastle')
OPEN=$(grep -c 'Git;->open(Ljava/io/File;)Lorg/eclipse/jgit/api/Git;' "$TMP/dump.txt" || true)
COMMIT=$(grep -c 'Git;->commit()Lorg/eclipse/jgit/api/CommitCommand;' "$TMP/dump.txt" || true)

echo "profile entries: total=$(wc -l < "$TMP/dump.txt") jgit=$JGIT jsch=$JSCH bc=$BC"

fail() { echo "FAIL: $*"; exit 1; }
[ "$JGIT" -ge 5000 ] || fail "jgit method rules fell to $JGIT (want ≥ 5000) — the generated rules or the -keepnames regressed"
[ "$JSCH" -ge 1500 ] || fail "jsch method rules fell to $JSCH (want ≥ 1500)"
[ "$BC" -ge 800 ] || fail "bouncycastle method rules fell to $BC (want ≥ 800)"
[ "$OPEN" -eq 1 ] || fail "Git.open(File) missing — the first-sync path is unprofiled"
[ "$COMMIT" -eq 1 ] || fail "Git.commit() missing — the save path is unprofiled"

echo "OK: the baseline profile is packaged, mapped, and complete."
