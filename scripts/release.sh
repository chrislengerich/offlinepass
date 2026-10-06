#!/usr/bin/env bash
#
# linuxpass release pipeline: build → stage → (you gpg-sign) → verify → publish.
#
# Usage:
#   scripts/release.sh build [version]    # assemble + stage dist/v<version>/
#   scripts/release.sh sign  [version]    # gpg --detach-sign --armor each APK
#   scripts/release.sh verify [version]   # gpg --verify + checksums
#   scripts/release.sh publish [version]  # commit-check, tag, push, GH release
#
# Signing: each APK gets a detached ASCII-armored GPG signature (.asc
# sidecar) from the security key. Set LINUXPASS_GPG_KEY=<keyid/email> to
# pick a non-default key (the key's secret half lives on the hardware
# token — expect the touch prompt). APK-side Android-keystore signing is
# DEFERRED (app-store mechanics): the profileable APK ships as built
# (unsigned APK) plus its GPG signature — not installable until APK-signed;
# device installs use the debug APK (debug-signed by AGP).
#
# The `publish` step requires: a CLEAN git tree (commit the release first),
# the tag NOT existing, and the `gh` CLI logged in with write access to the
# origin repo. Artifacts attach to the GitHub release; they are NOT
# committed into git (dist/ is gitignored).
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ANDROID_DIR="$REPO_ROOT/android"
DIST_ROOT="$REPO_ROOT/dist"
VERSION="${2:-${LINUXPASS_VERSION:-0.9.0}}"
TAG="v$VERSION"
STAGE="$DIST_ROOT/$TAG"

# -- helpers ----------------------------------------------------------------

die() { echo "release: $*" >&2; exit 1; }

build_tools_dir() {
  # Newest build-tools from ANDROID_HOME, ANDROID_SDK_ROOT, or local.properties.
  local sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
  if [ -z "$sdk" ] && [ -f "$ANDROID_DIR/local.properties" ]; then
    sdk=$(grep '^sdk.dir' "$ANDROID_DIR/local.properties" | cut -d= -f2- | sed 's/\\:/:/g')
  fi
  [ -n "$sdk" ] || die "SDK dir unknown — set ANDROID_HOME"
  ls -d "$sdk"/build-tools/*/ 2>/dev/null | sort -V | tail -1
}

checksums() {
  ( cd "$STAGE" && shasum -a 256 ./*.apk > SHA256SUMS.txt )
}

require_stage() {
  [ -d "$STAGE" ] || die "$STAGE missing — run: scripts/release.sh build $VERSION"
}

gpg_key_args() {
  [ -n "${LINUXPASS_GPG_KEY:-}" ] && echo "--local-user" "$LINUXPASS_GPG_KEY"
}

# -- build -------------------------------------------------------------------

cmd_build() {
  ( cd "$ANDROID_DIR" && ./gradlew :app:assembleDebug :app:assembleProfileable --console=plain )
  mkdir -p "$STAGE"
  cp "$ANDROID_DIR/app/build/outputs/apk/debug/app-debug.apk" \
     "$STAGE/linuxpass-$VERSION-debug.apk"
  cp "$ANDROID_DIR/app/build/outputs/apk/profileable/app-profileable-unsigned.apk" \
     "$STAGE/linuxpass-$VERSION-profileable.apk"
  # Existing signatures survive a rebuild only if the bytes are identical;
  # any stale sidecar for CHANGED artifacts is stale by definition.
  rm -f "$STAGE"/*.asc
  if [ ! -f "$STAGE/RELEASE_NOTES.md" ]; then
    cat > "$STAGE/RELEASE_NOTES.md" <<'NOTES'
## linuxpass v0.9.0

First packaged release of both clients.

### Android (com.linuxpass.app)
- Hardware-key unlock (OpenKeyChain/YubiKey) with optional biometric gate
- Full CRUD: add/edit with editable generated password + notes, TOTP enroll
  with live countdown, tombstoned delete
- Last-modified timestamps, list entry count, secondary sort (most recent
  first, default on)
- QRFT phone↔phone transfer: multi-entry export (pick entries / select all)
  and in-app camera import with dedupe (local version wins on conflict)
- Signed git commits via OpenKeyChain (pre-flight sign-key check with the
  interaction loop surfaced to the UI)
- USB save/restore, union-merge sync, local-only mode, autofill service
- Security: ciphertext at rest, zero-on-exit + lock action, plaintext temp
  files zero-filled and deleted on every decrypt/encrypt

### Artifacts
- `linuxpass-vX.Y.Z-debug.apk` — debuggable, signed with the debug key
  (installable via adb)
- `linuxpass-vX.Y.Z-profileable.apk` — minified release + <profileable>
  (profilers can attach). Android-keystore signing is deferred: the APK
  itself is unsigned (not installable until APK-signed); its integrity is
  attested by the GPG detached signature.
- `*.asc` — detached armored GPG signatures over each APK (security key);
  verify: `gpg --verify <file>.asc <file>`
- `SHA256SUMS.txt` — sha256 of both APKs
NOTES
  fi
  checksums
  echo
  echo "Staged: $STAGE"
  echo "Next:   scripts/release.sh sign $VERSION   (gpg --detach-sign --armor both APKs)"
}

# -- sign --------------------------------------------------------------------

cmd_sign() {
  require_stage
  for apk in "$STAGE"/linuxpass-"$VERSION"-*.apk; do
    [ -f "$apk" ] || continue
    if [ -f "$apk.asc" ]; then
      echo "already signed: $(basename "$apk") — keeping the existing .asc"
      continue
    fi
    # The security key's secret half is on the hardware token — gpg will
    # prompt/touch as configured.
    gpg --detach-sign --armor $(gpg_key_args) "$apk"
    echo "signed: $(basename "$apk")"
  done
  checksums
  cmd_verify
}

# -- verify ------------------------------------------------------------------

cmd_verify() {
  require_stage
  local found=0
  for apk in "$STAGE"/linuxpass-"$VERSION"-*.apk; do
    [ -f "$apk" ] || continue
    found=1
    echo "== $(basename "$apk")"
    [ -f "$apk.asc" ] || die "missing signature: $apk.asc — run: scripts/release.sh sign $VERSION"
    gpg --verify "$apk.asc" "$apk" || die "GPG signature INVALID: $apk"
  done
  [ "$found" = 1 ] || die "no APKs staged in $STAGE"
  checksums
  ( cd "$STAGE" && shasum -a 256 --check SHA256SUMS.txt )
  echo "verify OK"
}

# -- publish -----------------------------------------------------------------

cmd_publish() {
  require_stage
  for apk in "$STAGE"/linuxpass-"$VERSION"-*.apk; do
    [ -f "$apk" ] || continue
    [ -f "$apk.asc" ] || die "$(basename "$apk") not signed — run: scripts/release.sh sign $VERSION"
  done
  ( cd "$REPO_ROOT"
    [ -z "$(git status --porcelain)" ] || die "git tree is dirty — commit the release first"
    # Resumable: a previous run may have tagged before failing at push/release.
    head_sha=$(git rev-parse HEAD)
    if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null 2>&1; then
      tagged_sha=$(git rev-parse -q --verify "refs/tags/$TAG^{commit}")
      [ "$tagged_sha" = "$head_sha" ] || die "$TAG exists at $tagged_sha but HEAD is $head_sha"
      echo "$TAG already tagged at HEAD — resuming"
    else
      # Annotated tag; export LINUXPASS_SIGN_TAG=1 for a GPG-signed tag.
      if [ "${LINUXPASS_SIGN_TAG:-0}" = "1" ]; then
        git tag -s "$TAG" -m "linuxpass $TAG"
      else
        git tag -a "$TAG" -m "linuxpass $TAG"
      fi
    fi
    # Idempotent push: harmless if both (or either) already arrived.
    git push origin HEAD "$TAG" || die "push failed — fix git auth and re-run publish (it resumes)"
    if command -v gh >/dev/null 2>&1; then
      if gh release view "$TAG" >/dev/null 2>&1; then
        echo "release $TAG exists — (re-)uploading artifacts"
        gh release upload "$TAG" --clobber \
          "$STAGE"/linuxpass-"$VERSION"-debug.apk \
          "$STAGE"/linuxpass-"$VERSION"-debug.apk.asc \
          "$STAGE"/linuxpass-"$VERSION"-profileable.apk \
          "$STAGE"/linuxpass-"$VERSION"-profileable.apk.asc \
          "$STAGE"/SHA256SUMS.txt
      else
        gh release create "$TAG" \
          "$STAGE"/linuxpass-"$VERSION"-debug.apk \
          "$STAGE"/linuxpass-"$VERSION"-debug.apk.asc \
          "$STAGE"/linuxpass-"$VERSION"-profileable.apk \
          "$STAGE"/linuxpass-"$VERSION"-profileable.apk.asc \
          "$STAGE"/SHA256SUMS.txt \
          --notes-file "$STAGE/RELEASE_NOTES.md" \
          --title "linuxpass $TAG"
      fi
      echo "GitHub release in place."
    else
      echo "gh not found — upload $STAGE/* manually:"
      echo "  https://github.com/$(git remote get-url origin | sed -E 's#.*github.com[:/]##;s#\.git$##')/releases/new?tag=$TAG"
    fi
  )
  echo "v$VERSION published."
}

case "${1:-}" in
  build)  cmd_build ;;
  sign)   cmd_sign ;;
  verify) cmd_verify ;;
  publish) cmd_publish ;;
  *) die "usage: scripts/release.sh {build|sign|verify|publish} [version]" ;;
esac
