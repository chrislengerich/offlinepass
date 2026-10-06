#!/usr/bin/env bash
#
# linuxpass release pipeline: build → stage → (you sign) → verify → publish.
#
# Usage:
#   scripts/release.sh build [version]    # assemble + stage dist/v<version>/
#   scripts/release.sh sign  [version]    # sign the staged profileable APK
#   scripts/release.sh verify [version]   # apksigner verify + checksums
#   scripts/release.sh publish [version]  # commit-check, tag, push, GH release
#
# Signing env (for `sign`):
#   LINUXPASS_KEYSTORE      path to the release keystore (required)
#   LINUXPASS_KEY_ALIAS     key alias in the keystore (default: linuxpass)
#   LINUXPASS_KS_PASS       keystore password (optional; apksigner prompts)
#   LINUXPASS_KEY_PASS      key password   (optional; defaults to keystore pass)
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

apksigner_bin() { build_tools_dir; }  # dir contains the apksigner wrapper

stage_paths() {
  echo "$STAGE/linuxpass-$VERSION-debug.apk"
  echo "$STAGE/linuxpass-$VERSION-profileable.apk"
}

checksums() {
  ( cd "$STAGE" && shasum -a 256 ./*.apk > SHA256SUMS.txt )
}

require_stage() {
  [ -d "$STAGE" ] || die "$STAGE missing — run: scripts/release.sh build $VERSION"
}

# -- build -------------------------------------------------------------------

cmd_build() {
  ( cd "$ANDROID_DIR" && ./gradlew :app:assembleDebug :app:assembleProfileable --console=plain )
  mkdir -p "$STAGE"
  cp "$ANDROID_DIR/app/build/outputs/apk/debug/app-debug.apk" \
     "$STAGE/linuxpass-$VERSION-debug.apk"
  cp "$ANDROID_DIR/app/build/outputs/apk/profileable/app-profileable-unsigned.apk" \
     "$STAGE/linuxpass-$VERSION-profileable-unsigned.apk"
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
- `linuxpass-vX.Y.Z-profileable.apk` — minified release + <profileable>
  (profilers can attach); signed release key
- `SHA256SUMS.txt` — sha256 of both APKs; verify after download
NOTES
  fi
  checksums || true
  echo
  echo "Staged: $STAGE"
  echo "Next:   scripts/release.sh sign $VERSION   (signs the profileable APK)"
}

# -- sign --------------------------------------------------------------------

cmd_sign() {
  require_stage
  local unsigned="$STAGE/linuxpass-$VERSION-profileable-unsigned.apk"
  local signed="$STAGE/linuxpass-$VERSION-profileable.apk"
  [ -f "$unsigned" ] || die "no unsigned APK at $unsigned (already signed?)"
  [ -n "${LINUXPASS_KEYSTORE:-}" ] || die "set LINUXPASS_KEYSTORE=<release keystore path>"
  local alias_args=() ks_args=()
  alias_args+=(--ks-key-alias "${LINUXPASS_KEY_ALIAS:-linuxpass}")
  [ -n "${LINUXPASS_KS_PASS:-}" ] && ks_args+=(--ks-pass "pass:$LINUXPASS_KS_PASS")
  if [ -n "${LINUXPASS_KEY_PASS:-}" ]; then
    ks_args+=(--key-pass "pass:$LINUXPASS_KEY_PASS")
  elif [ -z "${LINUXPASS_KS_PASS:-}" ]; then
    : # apksigner prompts for both on the terminal
  fi
  cp "$unsigned" "$signed"
  "$(apksigner_bin)/apksigner" sign \
    --ks "$LINUXPASS_KEYSTORE" "${alias_args[@]}" ${ks_args[@]+"${ks_args[@]}"} \
    "$signed"
  rm "$unsigned"
  checksums
  cmd_verify
}

# -- verify ------------------------------------------------------------------

cmd_verify() {
  require_stage
  local bt; bt="$(apksigner_bin)"
  local found=0
  for apk in "$STAGE"/linuxpass-"$VERSION"-*.apk; do
    case "$apk" in *-unsigned.apk) continue ;; esac   # signed artifacts only
    found=1
    echo "== $(basename "$apk")"
    "$bt/apksigner" verify "$apk" || die "signature invalid: $apk"
    "$bt/apksigner" verify --print-certs "$apk" | sed -n '1,3p'
  done
  [ "$found" = 1 ] || echo "(no signed APKs yet — nothing to verify)"
  checksums
  ( cd "$STAGE" && shasum -a 256 --check SHA256SUMS.txt )
  echo "verify OK"
}

# -- publish -----------------------------------------------------------------

cmd_publish() {
  require_stage
  [ -f "$STAGE/linuxpass-$VERSION-profileable.apk" ] || \
    die "profileable APK not signed yet — run: scripts/release.sh sign $VERSION"
  ( cd "$REPO_ROOT"
    [ -z "$(git status --porcelain)" ] || die "git tree is dirty — commit the release first"
    git rev-parse -q --verify "refs/tags/$TAG" >/dev/null 2>&1 && die "$TAG already exists"
    # Annotated tag; export LINUXPASS_SIGN_TAG=1 for a GPG-signed tag.
    if [ "${LINUXPASS_SIGN_TAG:-0}" = "1" ]; then
      git tag -s "$TAG" -m "linuxpass $TAG"
    else
      git tag -a "$TAG" -m "linuxpass $TAG"
    fi
    git push origin HEAD "$TAG"
    if command -v gh >/dev/null 2>&1; then
      gh release create "$TAG" \
        "$STAGE"/linuxpass-"$VERSION"-debug.apk \
        "$STAGE"/linuxpass-"$VERSION"-profileable.apk \
        "$STAGE"/SHA256SUMS.txt \
        --notes-file "$STAGE/RELEASE_NOTES.md" \
        --title "linuxpass $TAG"
      echo "GitHub release created."
    else
      echo "gh not found — upload $STAGE/*.apk manually:"
      echo "  https://github.com/$(git -C . remote get-url origin | sed -E 's#.*github.com[:/]##;s#\.git$##')/releases/new?tag=$TAG"
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
