# linuxpass device-wrap protocol (Chrome extension ⇄ Android)

Plan 2 reference. Scope: Android app + `extension/` only — the Linux TUI is
untouched (it preserves the new envelope fields verbatim; locked in by
`test_passlib.py::test_paste_devices_preserved_for_extension`).

## 1. Roles

- **Phone (Android app)** — the offline password manager. Holds the vault,
  pairs paste targets, encrypts single-entry QRFT pastes to a target's
  public key, renders the looping QRFT frames (existing generator page).
- **Chromebook (extension)** — scans the phone's QR with its camera,
  decrypts the paste **only after a security-key touch**, auto-fills the
  active tab. Persists public data only.

## 2. Trust root

A FIDO2 security key (YubiKey 5, fw ≥ 5.3) used as a WebAuthn authenticator
with the **PRF (`hmac-secret`) extension**:

- Pairing credential: `userVerification: "required"`,
  `residentKey: "discouraged"` (no resident-key slot consumed),
  `extensions: { prf: {} }`.
- Every use requires a **touch** (UV is touch-based on security keys — works
  on Chromebooks without fingerprint readers; the ChromeOS platform
  authenticator with PIN-based UV is the documented fallback).

The ECDH seed is a random WebCrypto keypair whose pkcs8 is AES-256-GCM-wrapped
under a PRF-derived KEK. The seed never exists in plaintext without a touch.
(Why not a PRF-*derived* scalar: WebCrypto cannot multiply curve points, so a
scalar → public-key conversion would require hand-rolled EC math. The wrapped
form has the same properties — nothing usable persists without the key.)

## 3. Key chain

```
salt      = SHA-256("linuxpass-device-v1" || rawCredentialId)
seed KEK  = HKDF-SHA256(ikm = PRF(salt), salt, info = "linuxpass-seed-kek-v1")
seed      = ECDH P-256 keypair, stored as AES-GCM(pkcs8, seed KEK, aad = "linuxpass-seed-wrap-v1")
keyId     = hex( SHA-256(rawPublicKeyPoint)[0..8] )
shared    = ECDH(sender ephemeral priv, device pub)         (X coordinate, 32B)
paste KEK = HKDF-SHA256(ikm = shared, salt = keyId bytes, info = "linuxpass-paste-wrap-v1")
ct        = AES-256-GCM(paste KEK, iv, aad, payload)
```

AAD string: `"linuxpass-paste-wrap-v1:" + keyId + ":" + base64(epk)`.
HKDF is RFC 5869 (JCE has none; the Android side uses HmacSHA256 extract+expand).
Public points are 65-byte uncompressed (`0x04 || X || Y`), standard base64.

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
`id` in merges; `removedDeviceIds` tombstones unpairing). The Linux TUI
preserves the field without understanding it. `id == keyId`, so re-pairing
the same key is idempotent under merge.

### 4.2 Wrapped paste (phone → extension)

The QRFT payload (the string the generator page transmits — it is gzipped
and chunked by the QRFT layer like any other payload):

```json
{"v": 1, "type": "linuxpass-wrap",
 "wrap": {"keyId": "<hex8>", "epk": "<b64 raw ephemeral point>"},
 "iv": "<b64>", "ct": "<b64>"}
```

`ct` decrypts (after a touch) to the usual Proton Pass JSON (item, array, or
envelope) — the same payload shapes the plain QRFT path carries. Plain
payloads (no `type: "linuxpass-wrap"`) remain accepted by the extension.

### 4.3 QRFT framing (unchanged, upstream airgap-qr-offline)

- metadata frame: `{"name": ..., "chunks": N, "size": M}`
- data frames: `"<index>,<base64(chunk)>"`, 250-byte chunks of the gzip
- **Chunk encoding quirk (must match upstream `encode_data`)**: chunk bytes
  are turned into a Latin-1 string, **UTF-8-encoded**, then base64'd.
  Decoding inverts: base64 → UTF-8 decode → char codes. Skipping the
  inversion corrupts every byte ≥ 0x80 — i.e. every gzip stream. (The
  vendored Android `scanner.html` was missing this step and has been fixed
  on this branch.)

## 5. User flows

**Pair (once per key):** extension toolbar → *Pair a security key* → touch
(create credential) → touch again (derive + wrap seed) → phone scans the
pairing QR via *Import from QRFT* → record syncs through git to all clients.

**Send (phone):** Setup → *Export as QRFT* → pick entries → pick device →
looping QR of the wrapped paste.

**Receive (Chromebook):** toolbar → *Scan a paste* (the target tab is
captured when the popup opens) → camera scans the phone's screen →
*Decrypt (touch key)* → entry summary with reveal/copy/TOTP → *Fill in tab*
→ content script fills username + password (no auto-submit). Passwords are
dropped from memory after fill/copy; TOTP is copy-only.

**Unpair:** phone Setup → *Paste devices* → Remove (tombstoned; merges honor
it). Pastes wrapped for a removed key become undecryptable — regenerate.

## 6. Threat model (honest boundaries)

- A wrapped paste decrypts only with (a) the paired security key in hand,
  (b) a deliberate touch, (c) the extension deriving the seed in memory.
- Decryption happens in extension memory; the secure element **gates** it
  (the AES keys themselves are not inside the chip).
- `chrome.storage.local` holds public records + the wrapped seed only.
- The extension makes no network requests (MV3 CSP pins this).
- Plain QRFT export remains available and is labeled as readable by anyone
  scanning the QR.
- Losing the key loses access to pastes wrapped for it (re-pair to rotate).

## 7. Cross-implementation vectors

`scripts/gen_device_wrap_vectors.py` generates fixed inputs/outputs for the
whole chain; both implementations assert them:

- Android: `android/app/src/test/.../DeviceWrapTest.kt` (JCE chain + RFC 5869
  HKDF test case)
- Extension: `extension/selftest.html` (run from the popup; needs a browser —
  asserts the same WebCrypto chain + the QRFT frame round-trip)

Regenerate only with a protocol change, and update BOTH sides.
