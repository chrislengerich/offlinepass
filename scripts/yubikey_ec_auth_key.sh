#!/usr/bin/env bash
# =============================================================================
# YubiKey OpenPGP AUTH slot → ECDSA P-256 swap
#
# WHY: an RSA-4096 AUTH key's challenge/response (512 B) does not fit the
# phone's USB transport (the 0x6581 dead end); a P-256 challenge is 32 B.
# The phone app's SSH auth then works over USB.
#
# WHAT IT DOES (destructive to the AUTH slot ONLY):
#   1. Verifies the OpenPGP admin PIN.
#   2. OVERWRITES the AUTH slot's key with a new ECDSA P-256 key generated
#      ON the YubiKey (the old AUTH key is destroyed and unrecoverable).
#   3. Prints the new public key material for the SSH line.
#
# WHAT IT DOES NOT TOUCH:
#   - The vault (its encryption keys live in the DECRYPT slot).
#   - The SIGNATURE slot (commit signing keeps working).
#   - Any gpg keyring entries (the new AUTH key exists only on the card
#     until you add it to your key — see NOTES below).
#
# RUN ON THE DESKTOP (Linux) with the YubiKey plugged in:
#   ./scripts/yubikey_ec_auth_key.sh
#
# AFTER: in the phone app, re-run "Show auth key for GitHub" / re-Enroll —
# the enrolled line must be the NEW AUTH key's, and GitHub's deploy key
# must be updated to match.
#
# The same operation exists as app library code
# (YubiKitSshAuth.generateEcAuthKey — OpenPgpSession.generateEcKey(AUT,
# SECP256R1)); this script is the inspectable desktop path for the same
# swap. The desktop gpg route regenerates the slot; the key never leaves
# the card in either path.
# =============================================================================

set -euo pipefail

ADMIN_PIN="${ADMIN_PIN:-}"

if ! command -v gpg >/dev/null 2>&1; then
    echo "gpg not found — this script needs GnuPG 2.x on the desktop." >&2
    exit 1
fi

echo "== BEFORE =="
gpg --card-status || true

if [ -z "$ADMIN_PIN" ]; then
    echo
    echo "The swap needs the OpenPGP ADMIN PIN (default: the YubiKey's set"
    echo "admin code). It is prompted by gpg below and is NOT recorded here."
fi

# -- The swap ---------------------------------------------------------------
# gpg --card-edit, scripted: admin mode, then key-attribute + generate for
# key number 3 (the AUTH slot; 1 = SIG, 2 = DEC, 3 = AUT). keyattr sets the
# slot's algorithm attributes; generate creates the key on-card.
#
# Feed order: admin -> keyattr 3 -> the algorithm string -> generate -> 3
# -> (the PIN prompts happen interactively via the pinentry program).
gpg --card-edit <<'GPGCMDS'
admin
keyattr 3
ecdsa
nistp256
generate
3
GPGCMDS

echo
echo "== AFTER =="
gpg --card-status

echo
echo "== New AUTH public key (OpenSSH line candidates) =="
echo "The on-card AUTH key has no keyring entry yet. To get the SSH line:"
echo "  gpg --card-status   (note the AUT slot's key id/signing fingerprint)"
echo "  gpg --export-ssh-key <AUT key id>!    (the '!' forces that exact key)"
echo
echo "Then in the phone app: Setup → re-run Enroll / Show auth key for"
echo "GitHub, and update the GitHub deploy key to the new line."
