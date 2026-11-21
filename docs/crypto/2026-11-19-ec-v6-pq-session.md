# Crypto session notes — EC decrypt, v6, PQ probe (2026-11-19)

Branches: `ec-decrypt-keys`, `openpgp-v6-aead-tests`, `pq-prototype`.

## What landed

### EC decrypt (EcdhDecryptTest, the pipeline)
- The card's ECDH PSO:DEC contract: the input = the bare ephemeral
  point (the MPI value, no RSA padding); the card performs the RFC 6637
  KDF + the AES-key-unwrap and returns the plain session data (the
  algo-byte + key + checksum — the shape the factory's <128-byte path
  already handled).
- `YubiKitCardDecrypt`: the DEC slot's EC branch — the command length =
  the card's reported encoded point (`PublicKeyValues.Ec.encodedPoint`,
  YubiKit core 3.3.0; there is no PublicKeyValues in the openpgp jar).
- `generateEcDecKey` — the DEC slot's EC swap (the admin-PIN-gated
  library call, the mirror of the AUTH swap).
- Curve sweep proven by test: **P-256, P-384, P-521, Curve25519** — the
  flow is curve-agnostic (the point length follows the card's reported
  key; the session-key algorithm byte rides the envelope).
- The fake card = BC's `BcPublicKeyDataDecryptorFactory` — the exact
  RFC 6637 math the card performs. `recoverSessionData` takes the
  STRIPPED value (the packet parser removed the MPI prefix). The RSA
  fake emulation hits a BC converter/Pkcs1Encoding quirk ("block
  incorrect" while the JCA decrypts the same block fine) — the RSA
  path stayed production-proven instead.

### Ed25519 (the AUT slot's auth)
- ssh-ed25519 signs the RAW handshake data (PureEdDSA) — the OpenPGP
  hashed-sign path (OpenKeyChain's detached-sign) CANNOT serve it; the
  identity's ed25519 branch goes YubiKit-direct
  (`session.authenticate(payload)` = the AUT slot's PSO:INTERNAL
  AUTHENTICATE) → the 64-byte r||s → string("ssh-ed25519") +
  string(sig).
- `YubiKitSshAuth.authenticateAut` — the which-key read + the
  expected-fingerprint gate by name (`ed25519SshLineFingerprint` — the
  card's raw point digests identically to the enrolled line), the
  auth-capable PIN verify (the extended flavor).
- Ed25519 CANNOT encrypt — the DEC/encrypt's EdDSA counterpart =
  Curve25519 (supported). YubiKit 3.3.0 cannot GENERATE Ed25519 — gpg
  generates on the card (the applet 5.7+); the app imports the line.

### OpenPGP v6 (the pin, not the full support)
- The v6 PKESK **dispatch** works: the hand-assembled packet via BC's
  `createV6PKESKPacket` + the app's v6 octet-count `mpiValue` branch.
- The v6-ECDH **decrypt** = blocked: BC's `parseECDHEncSessionKey`
  errors ("encoded length out of range") in 1.79 AND 1.87, regardless
  of the session-data shape (the stripped, the MPI-encoded). The salt/
  fingerprint semantics of the v6 PKESK need the BC's guidance or a
  gpg-generated corpus to reverse. Fails cleanly; documented in TODO.
- The AEAD SEIPD-v2: BC 1.87 has the AEAD classes (the AEADAlgorithm
  tags EAX/OCB/GCM, the AEADEncDataPacket) but NO public-key AEAD
  generation (the SK-based builder only). Deferred to the BC upgrade.
- The packet-parse learnings (the test's parser): the old-format
  two-octet length = the first octet's low 5 bits + the second + 192;
  the v3 PKESK's body = the version(1) + the keyid(8) + the
  ALGORITHM(1) + the MPI field.

### PQ probe (the negative finding)
- BC 1.87 has the LOW-level ML-KEM packet shapes
  (`MLKEMCompositePublicBCPGKey`, the PQC JCA provider) but the
  HIGH-LEVEL OpenPGP layer (PGPPublicKey, the encryptor/decryptor
  factories) has NO ML-KEM paths. The encrypt/decrypt is not
  implementable on BC 1.87 — the prototype unblocks when BC ships the
  high-level PQ OpenPGP (the 1.88+ watch).
- BC was bumped 1.79 → 1.87 for this probe (the PQ tags on the
  classpath: MLKEM768_X25519, MLDSA65_Ed25519).

## The extension's crypto implications (the next context)
- The card-over-WebUSB prototype = the SAME card contract (the RSA
  PKCS#1 + the ECDH PSO:DEC, the PIN, the touch) minus YubiKit —
  pcsc-js/WebUSB-CCID + the OpenPGP applet APDUs.
- openpgp.js for the envelope; the card-in-the-middle session-key
  recovery (the message.parse → the PKESK → the card → the session
  key → the decrypt).
- The at-rest = the WebAuthn-PRF-derived WebCrypto key (the same trust
  model as the phone's vault root; the one-time PRF registration).
