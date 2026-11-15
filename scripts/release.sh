#!/usr/bin/env bash
#
# offlinepass release pipeline: build → stage → (you gpg-sign) → verify → publish.
#
# Usage:
#   scripts/release.sh build [version]    # assemble + stage dist/v<version>/
#   scripts/release.sh sign  [version]    # gpg --detach-sign --armor each APK
#   scripts/release.sh verify [version]   # gpg --verify + checksums
#   scripts/release.sh publish [version]  # commit-check, tag, push, GH release
#
# Signing: each APK gets a detached ASCII-armored GPG signature (.asc
# sidecar) from the security key. Set OFFLINEPASS_GPG_KEY=<keyid/email> to
# pick a non-default key (the key's secret half lives on the hardware
# token — expect the touch prompt). APK-side Android signing is DONE
# LOCALLY by android/sign.sh (hardware-key PKCS11 via apksigner — same key
# as offlinecam); this pipeline ships the UNSIGNED APK + its GPG
# signature; device installs use android/app-release-signed.apk (or the
# debug APK).
#
# The `publish` step requires: a CLEAN git tree (commit the release first),
# and the `gh` CLI logged in with write access to the origin repo (push is
# SSH — the security key is the SSH identity, expect the touch prompt).
# It is RESUMABLE: a tag left behind by a failed run is reused as-is
# (OFFLINEPASS_RETAG=1 moves it to HEAD instead), completed steps are
# skipped. Artifacts attach to the GitHub release; they are NOT committed
# into git (dist/ is gitignored).
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ANDROID_DIR="$REPO_ROOT/android"
DIST_ROOT="$REPO_ROOT/dist"
VERSION="${2:-${OFFLINEPASS_VERSION:-0.10.0}}"
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
  [ -n "${OFFLINEPASS_GPG_KEY:-}" ] && echo "--local-user" "$OFFLINEPASS_GPG_KEY"
}

# -- build -------------------------------------------------------------------

cmd_build() {
  ( cd "$ANDROID_DIR" && ./gradlew :app:assembleDebug :app:assembleProfileable :app:assembleRelease --console=plain )
  # Keep the R8 mapping next to the build — a minified-build crash shows
  # obfuscated class names in the log viewer; this de-obfuscates them
  # (untracked: device-local only, not part of the release artifacts).
  [ -f "$ANDROID_DIR/app/build/outputs/mapping/release/mapping.txt" ] && \
    cp "$ANDROID_DIR/app/build/outputs/mapping/release/mapping.txt" \
       "$ANDROID_DIR/app-release-mapping.txt"
  mkdir -p "$STAGE"
  cp "$ANDROID_DIR/app/build/outputs/apk/debug/app-debug.apk" \
     "$STAGE/offlinepass-$VERSION-debug.apk"
  cp "$ANDROID_DIR/app/build/outputs/apk/profileable/app-profileable-unsigned.apk" \
     "$STAGE/offlinepass-$VERSION-profileable.apk"
  # Existing signatures survive a rebuild only if the bytes are identical;
  # any stale sidecar for CHANGED artifacts is stale by definition.
  rm -f "$STAGE"/*.asc
  # The hardware-key-signed release APK (android/sign.sh — the device-
  # install artifact) joins the stage when it exists.
  if [ -f "$ANDROID_DIR/app-release-signed.apk" ]; then
    cp "$ANDROID_DIR/app-release-signed.apk" \
       "$STAGE/offlinepass-$VERSION-release.apk"
    rm -f "$STAGE/offlinepass-$VERSION-release.apk.asc"
  fi
  if [ ! -f "$STAGE/RELEASE_NOTES.md" ] || [ "${OFFLINEPASS_RENOTES:-0}" = 1 ]; then
    cat > "$STAGE/RELEASE_NOTES.md" <<NOTES
## offlinepass v$VERSION

### Android (com.offlinepass.app)
- **Encrypt individual items while in use (experimental toggle)** — the
  locked app stays fully searchable (names/usernames/URLs from a
  device-local sealed manifest; never synced), and tapping an entry
  reveals it after one screen-lock prompt; editing saves ride the
  existing screenlock commit signer
- **Screen-lock toggle now governs the whole app**: entry gate at app
  open / after the idle timeout, plus **idle auto-lock** with a
  configurable minutes field (default 5) — everything zeroed back to
  encrypted-at-rest
- Sync-auth options: screenlock SSH key (default, deploy-key least
  privilege), YubiKey OpenPGP SSH, HTTPS+PAT (deprecated)
- Screenlock commit signing (keystore-gated, public key published to
  keys/ for verification)
- QRFT phone↔phone transfer (multi-entry export + camera import with
  dedupe), encrypted pastes to the paired Chrome extension
- Signing: android/sign.sh — hardware-key PKCS11 via apksigner (same
  security key as offlinecam); the release APK is the device-install
  artifact

### Artifacts
- \`offlinepass-vX.Y.Z-release.apk\` — minified release build, signed with
  the hardware security key (adb-installable)
- \`offlinepass-vX.Y.Z-debug.apk\` — debuggable, signed with the debug key
- \`offlinepass-vX.Y.Z-profileable.apk\` — minified + <profileable>,
  unsigned (integrity attested by its GPG signature)
- \`*.asc\` — detached armored GPG signatures over each APK; verify:
  \`gpg --verify <file>.asc <file>\`
- \`SHA256SUMS.txt\` — sha256 of every artifact
NOTES
  fi
  checksums
  echo
  echo "Staged: $STAGE"
  echo "Next:   scripts/release.sh sign $VERSION   (gpg --detach-sign --armor every artifact)"
}

# -- sign --------------------------------------------------------------------

cmd_sign() {
  require_stage
  for apk in "$STAGE"/offlinepass-"$VERSION"-*.apk; do
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
  for apk in "$STAGE"/offlinepass-"$VERSION"-*.apk; do
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
  for apk in "$STAGE"/offlinepass-"$VERSION"-*.apk; do
    [ -f "$apk" ] || continue
    [ -f "$apk.asc" ] || die "$(basename "$apk") not signed — run: scripts/release.sh sign $VERSION"
  done
  ( cd "$REPO_ROOT"
    [ -z "$(git status --porcelain)" ] || die "git tree is dirty — commit the release first"
    # Resumable: a previous run may have tagged before failing at push/release.
    # An EXISTING tag is reused as-is (publish attaches the release to it);
    # OFFLINEPASS_RETAG=1 moves it to HEAD instead.
    head_sha=$(git rev-parse HEAD)
    if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null 2>&1; then
      tagged_sha=$(git rev-parse -q --verify "refs/tags/$TAG^{commit}")
      if [ "${OFFLINEPASS_RETAG:-0}" = "1" ]; then
        if [ "${OFFLINEPASS_SIGN_TAG:-0}" = "1" ]; then
          git tag -f -s "$TAG" -m "offlinepass $TAG" "$head_sha"
        else
          git tag -f -a "$TAG" -m "offlinepass $TAG" "$head_sha"
        fi
        echo "$TAG moved to HEAD ($head_sha)"
      elif [ "$tagged_sha" != "$head_sha" ]; then
        echo "note: reusing $TAG at ${tagged_sha:0:7} (HEAD is ${head_sha:0:7}; OFFLINEPASS_RETAG=1 moves it)"
      else
        echo "$TAG already tagged at HEAD"
      fi
    else
      # Annotated tag; export OFFLINEPASS_SIGN_TAG=1 for a GPG-signed tag.
      if [ "${OFFLINEPASS_SIGN_TAG:-0}" = "1" ]; then
        git tag -s "$TAG" -m "offlinepass $TAG"
      else
        git tag -a "$TAG" -m "offlinepass $TAG"
      fi
    fi
    # Idempotent push: harmless if both (or either) already arrived. The
    # SSH identity is the security key — expect the touch prompt.
    git push origin HEAD "$TAG" || die "push failed — fix git auth and re-run publish (it resumes)"
    if command -v gh >/dev/null 2>&1; then
      if gh release view "$TAG" >/dev/null 2>&1; then
        echo "release $TAG exists — (re-)uploading artifacts"
        gh release upload "$TAG" --clobber \
          "$STAGE"/offlinepass-"$VERSION"-*.apk \
          "$STAGE"/offlinepass-"$VERSION"-*.apk.asc \
          "$STAGE"/SHA256SUMS.txt "$STAGE"/RELEASE_NOTES.md
      else
        gh release create "$TAG" \
          "$STAGE"/offlinepass-"$VERSION"-*.apk \
          "$STAGE"/offlinepass-"$VERSION"-*.apk.asc \
          "$STAGE"/SHA256SUMS.txt "$STAGE"/RELEASE_NOTES.md \
          --notes-file "$STAGE/RELEASE_NOTES.md" \
          --title "offlinepass $TAG"
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
