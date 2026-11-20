# The card-over-WebUSB prototype (the phase 1)

- `card/ccid.js` — the CCID transport (the XfrBlock pass-through) over
  navigator.usb; the YubiKey's CCID interface (the class 0x0B).
- `card/openpgp.js` — the OpenPGP applet: the SELECT, the GET DATA (the
  version, the fingerprints), the PW1 verify (the P2=0x82 decrypt
  flavor), the PSO:DEC (the RSA = the zero-padded extended APDU; the
  ECDH = the bare point).
- `probe.html`/`probe.js` — the prototype page: the connect, the
  applet reads, the PIN, the PSO:DEC (the real envelope = the phase 2,
  with the openpgp.js integration).

The next phases: ② the openpgp.js integration (the envelope parse →
the PKESK dispatch → the card → the session key → the SEIPD open) ③
the isomorphic-git sync (the HTTPS+token) + the full CRUD ④ the QRFT
both directions + the TOTP. The at-rest = the WebAuthn-PRF-derived
WebCrypto key (the secure element derivation, the key press as the
gate — the phone's trust model).
