# linuxpass device-wrap protocol (Chrome extension ⇄ Android)

Plan 2 rev 2 reference. Scope: Android app + `extension/` only — the Linux
TUI is untouched (it preserves the new envelope fields verbatim; locked in
by `test_passlib.py::test_paste_devices_preserved_for_extension`).

## 1. Roles

- **Phone (Android app)** — the offline password manager. Holds the vault,
  pairs paste targets, encrypts single-entry QRFT pastes to ALL selected
  paired keys, renders the looping QRFT frames (existing generator page).
- **Chromebook (extension)** — scans the phone's QR with its camera,
  decrypts the paste **only after a FIDO2 PIN + security-key touch**,
  auto-fills the active tab. Persists public data + wrapped seed only.

## 2. Trust root

A FIDO2 security key (YubiKey 5, fw ≥ 5.3) used as a WebAuthn authenticator
with the **PRF (`hmac-secret`) extension**:

- Pairing credential: `userVerification: "required"`,
  `residentKey: "discouraged"` (non-discoverable — no resident-key slot
  consumed; PRF works with non-discoverable credentials).
- **UV = FIDO2 PIN (knowledge) + touch (possession)**. The FIDO2 PIN is the
  same one passkeys on the key use — one FIDO2 PIN per YubiKey, separate
  from the OpenPGP and PIV PINs. If unset, Chrome prompts to create one
  during pairing (retry lockout is per-power-cycle). Works on Chromebooks
  without fingerprint readers.
- The ChromeOS platform authenticator (PIN-based UV, per-machine pairing)
  is the documented fallback.

**State on the key: none.** Non-resident credentials wrap the credential key
material and PRF secret INSIDE the credential ID (which the extension
stores), keyed by the YubiKey's internal wrapping key — the resident-slot
pool and any existing passkeys are never written, and FIDO2 operations
cannot reach the OpenPGP or PIV applets. The only destructive FIDO2
operation (a full FIDO2 reset, which would also wipe existing passkeys) is
never invoked.

The ECDH seed is a random WebCrypto keypair whose pkcs8 is AES-256-GCM-wrapped
under a PRF-derived KEK. The seed never exists in plaintext without a PIN +
touch. (Why not a PRF-*derived* scalar: WebCrypto cannot multiply curve
points, so a scalar → public-key conversion would require hand-rolled EC
math. The wrapped form has the same properties.)

## 3. Key chain

```
salt      = SHA-256("linuxpass-device-v1" || rawCredentialId)
seed KEK  = HKDF-SHA256(ikm = PRF(salt), salt, info = "linuxpass-seed-kek-v1")
seed      = ECDH P-256 keypair, stored as AES-GCM(pkcs8, seed KEK, aad = "linuxpass-seed-wrap-v1")
keyId     = hex( SHA-256(rawCredentialId)[0..8] )        (stable identity)
cek       = random 32 bytes per paste
payload   = AES-256-GCM(cek, iv_p, aad = "linuxpass-paste-wrap-v1", protonJson)
per target: shared = ECDH(ephemeral priv, device pub) (X coordinate, 32B)
            kek_t  = HKDF-SHA256(shared, salt = keyId bytes, info = "linuxpass-paste-wrap-v1")
            ct_t   = AES-256-GCM(kek_t, iv_t, aad_t, cek)
```

Target AAD string: `"linuxpass-paste-wrap-v1:" + keyId + ":" + base64(epk)`.
HKDF is RFC 5869 (JCE has none; the Android side uses HmacSHA256
extract+expand). Public points are 65-byte uncompressed (`0x04 || X || Y`),
standard base64.

## 4. Wire formats

### 4.1 Pairing record (extension → phone)

Emitted by the pair page as a tiny QRFT transfer (metadata frame + one
chunk), so the phone's existing **Import from QRFT** scan reads it with no
new UI:

```json
{"type": "linuxpass-device", "device": {
  "id": "<keyId>", "name": "<user label>", "credId": "<b64>",
  "pub": "<b64 raw point>", "keyId": "<hex8>", "added": <unix sec>,
  "salt": "<b64>", "wrapped": {"iv": "<b64>", "ct": "<b64>"}}}
```

The phone stores it in the envelope's top-level `devices` array (union by
`keyId` in merges; same-`keyId` conflicts → **newer envelope's copy wins**;
`removedDeviceIds` tombstones unpairing). Scanning a record whose `keyId`
already exists **updates it in place** — that is how re-wrapped seeds
propagate. The Linux TUI preserves the field without understanding it.

The record doubles as the **pairing-state backup** (see §6): it contains
everything the extension needs, wrapped seed included (itself encrypted
under the PRF, inside the GPG vault — two independent layers).

### 4.2 Wrapped paste (phone → extension) — rev 2: wrap-once, target-many

The QRFT payload (the string the generator page transmits — it is gzipped
and chunked by the QRFT layer like any other payload):

```json
{"v": 1, "type": "linuxpass-wrap",
 "payload": {"iv": "<b64>", "ct": "<b64>"},
 "targets": [{"keyId": "<hex8>", "epk": "<b64 raw ephemeral point>",
              "iv": "<b64>", "ct": "<b64>"}]}
```

- `payload.ct` decrypts (after a touch) to the usual Proton Pass JSON
  (item, array, or envelope) — the same payload shapes the plain QRFT path
  carries. Plain payloads (no `type: "linuxpass-wrap"`) remain accepted.
- **Any one of the targets' keys opens the paste**: each target wraps the
  same CEK. The default export wraps to **all paired keys** (redundancy
  matching the vault's multi-key model). Budget ≈170 chars per extra
  target (~a couple of QR frames).
- The extension picks the target matching its local `keyId`.

### 4.3 QRFT framing (unchanged, upstream airgap-qr-offline)

- metadata frame: `{"name": ..., "chunks": N, "size": M}`
- data frames: `"<index>,<base64(chunk)>"`, 250-byte chunks of the gzip
- **Chunk encoding quirk (must match upstream `encode_data`)**: chunk bytes
  are turned into a Latin-1 string, **UTF-8-encoded**, then base64'd.
  Decoding inverts: base64 → UTF-8 decode → char codes. Skipping the
  inversion corrupts every byte ≥ 0x80 — i.e. every gzip stream. (The
  vendored Android `scanner.html` was missing this step and has been fixed
  on this branch.)
- **Resource caps (both receivers, ported from `~/3p/airgap-qr-offline`)**:
  `valid_meta` rejects metadata frames with junk (`chunks` outside
  1..1,000,000, non-integer or oversized `size` (>3 GiB), names > 5000
  chars), and `safe_inflate` streams the gzip in 64 KiB slices, aborting the
  moment output exceeds `declared size + 1 MiB` (or 3 GiB when no size is
  declared). A hostile QR therefore cannot exhaust memory (decompression
  bomb) or steer the transfer with a spoofed metadata frame; the first valid
  metadata frame wins and later ones are ignored.

## 5. User flows

**Pair (once per key):** extension toolbar → *Pair a security key* → touch
(create credential; FIDO2 PIN if prompted) → touch again (derive + wrap
seed) → phone scans the pairing QR via *Import from QRFT* → record syncs
through git to all clients.

**Send (phone):** Setup → *Export as QRFT* → pick entries → target
checklist (all paired keys pre-selected) → looping QR of the wrapped paste.

**Receive (Chromebook):** toolbar → *Scan a paste* (the target tab is
captured when the popup opens) → camera scans the phone's screen →
*Decrypt (touch key)* — the prompt names the expected key → entry summary
with reveal/copy/TOTP → *Fill in tab* → content script fills username +
password (no auto-submit). Passwords are dropped from memory after
fill/copy; TOTP is copy-only.

**Restore pairing (Chromebook/profile loss, or second Chromebook):** phone
Setup → Paste devices → *Show QR* → extension scan window → *Restore
pairing* → same key, same keyId, no duplicate record.

**Unpair / replace:** phone Setup → Paste devices → Remove (tombstoned;
merges honor it). Extension popup → Forget prunes the local record. A
replaced key = pair the new one, remove the old one. Pastes wrapped for a
removed key become undecryptable — regenerate. A lost key alone decrypts
nothing (the wrapped seed is on the Chromebook).

## 6. The vault is the pairing-state backup

The full record — pub, salt, wrapped seed — lives in the envelope, inside
the GPG-encrypted vault. Two independent encryption layers protect the
wrapped seed (AES under the PRF, inside the OpenPGP vault). Consequences:
any client holding the vault + the physical key can recover an extension
install or onboard a new Chromebook without re-pairing, and record updates
sync via the normal git merge rules (newer wins).

## 7. Threat model (honest boundaries)

- A wrapped paste decrypts only with (a) possession of the paired security
  key, (b) the FIDO2 PIN + a deliberate touch, and (c) the extension
  deriving the seed in memory. Compromise of the Chromebook (no touch), the
  key alone (no wrapped seed), or the vault alone (no key) each yield
  nothing on their own.
- Decryption happens in extension memory; the secure element **gates** it.
  State this explicitly — the AES keys are not inside the chip.
- `chrome.storage.local` holds public records + the wrapped seed only; the
  plaintext seed never persists anywhere.
- The security key accumulates no state (§2).
- The extension makes no network requests (MV3 CSP pins this).
- Plain QRFT export remains available and is flagged as such in the
  Android UI (existing behavior, used for the QR Autofill companion).
- Camera scanning is local-only; frames never leave the device.
- A crafted pairing QR could inject a bogus local record, but such a record
  decrypts nothing (its wrapped seed won't match the real key's PRF — AES-GCM
  fails) — worst case is clutter, cleaned by the explicit confirm + Forget.

## 8. Cross-implementation vectors

`scripts/gen_device_wrap_vectors.py` generates fixed inputs/outputs for the
whole chain (including a 2-target paste); both implementations assert them:

- Android: `android/app/src/test/.../DeviceWrapTest.kt` (JCE chain + RFC 5869
  HKDF test case)
- Extension: `extension/selftest.html` (run from the popup; needs a browser —
  asserts the same WebCrypto chain + the QRFT frame round-trip)

Regenerate only with a protocol change, and update BOTH sides.
