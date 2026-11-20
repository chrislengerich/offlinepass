# offlinepass TODO

- [~] The OpenPGP v6/AEAD: the v6 PKESK **dispatch** pinned by test
  (EcdhDecryptTest). The v6-ECDH **decrypt** = still failing after the
  BC 1.87 bump (parseECDHEncSessionKey's "encoded length out of range"
  — the v6 session-data semantics differ from the v3's; needs either
  the correct v6 ECDH session-data construction or the BC's guidance).
  The AEAD SEIPD-v2 public-key generation = not exposed by BC 1.87's
  PGPEncryptedDataGenerator (the SK-based builder only).
- [ ] **Post-quantum crypto support** — the ML-KEM/ML-DSA composite
  algorithms (the OpenPGP draft): the BC's PQ releases + the v6 packet
  adoption; the card-side = the YubiKey 5.7+ PQ roadmap. Its own
  project: the key generation, the PKESK/SKESK shapes, the migration.
- [ ] **The feature-complete Chrome extension** (the standalone client,
  the card-resident keys):
  - the card-over-WebUSB (the OpenPGP applet: the PIN, the PSO:DEC for
    RSA/ECDH, the INTERNAL AUTHENTICATE for Ed25519) — the private
    keys never leave the key
  - openpgp.js for the envelope; the card-in-the-middle session-key
    recovery
  - the at-rest + the memory: the WebAuthn-PRF-derived WebCrypto
    AES-256-GCM (the secure element derivation, gated by the key press
    — the phone's trust model reused; the one-time PRF registration)
  - the sync: isomorphic-git over HTTPS with a token (the MV3's
    no-TCP; the SSH stays the phone's identity)
  - the full CRUD + the search + the TOTP + the remote attach
  - the QRFT both directions (the export to the phone, the camera
    import)
  - the phases: ① the card-over-WebUSB prototype ② the openpgp.js
    integration + the decrypt ③ the git + the CRUD + the config ④ the
    QRFT + the TOTP polish
