#!/usr/bin/env bash
#
# Sign the release APK with the hardware security key (YubiKey OpenPGP
# applet via OpenSC/PKCS11 — the same "SIG certificate" offlinecam uses).
# Run from android/: ./sign.sh  (expect the key's touch prompt).
#
set -euo pipefail
cd "$(dirname "$0")"

OPENSC_DRIVER=openpgp /home/ko/android-sdk/build-tools/34.0.0/apksigner \
  -J-add-exports=jdk.crypto.cryptoki/sun.security.pkcs11=ALL-UNNAMED \
  sign --ks NONE --ks-type PKCS11 \
  --ks-key-alias "SIG certificate" \
  --provider-class sun.security.pkcs11.SunPKCS11 \
  --provider-arg opensc.cfg \
  --out app-release-signed.apk \
  app/build/outputs/apk/release/app-release-unsigned.apk

/home/ko/android-sdk/build-tools/34.0.0/apksigner verify --print-certs \
  app-release-signed.apk
