# offlinepass Chrome extension (paste receive + autofill)

Chrome MV3 companion: scan the phone's looping paste QR, decrypt with a
paired security key (PIN + touch), auto-fill the entry into the tab.

## What it does

Click the offlinepass icon in Chrome: with a key paired, the scan window
opens instantly for the tab you clicked from; scan the phone's looping
paste QR with the Chromebook's camera; decryption starts automatically
once the transfer completes (insert key → FIDO2 PIN + touch — no extra
click); an entry whose URLs match the tab (subdomain-aware) **auto-fills**
and the window closes; with no match the extension still attempts the fill
(the first entry) but stays open with a warning banner plus the entry cards
(Fill / Reveal / Copy / TOTP-copy) so the guessed fill can be verified,
copied, or redone by hand. Nothing runs on any site by default: `activeTab` + no content
scripts — the platform grants access only to the tab you clicked on, and
every decryption requires the key.

## Install (ChromeOS / desktop Chrome)

1. `chrome://extensions` → enable **Developer mode** → **Load unpacked**
   → select this `extension/` directory.
2. Click the offlinepass icon → the pair page opens → follow the two
   touches (set a **FIDO2 PIN** if Chrome asks — the same PIN your
   passkeys use, separate from the OpenPGP/PIV PINs).
3. On the phone: offlinepass → Setup → **"Pair paste device (scan)"** →
   scan the extension's pairing QR → the record lands in the vault and
   syncs to all clients via git.
4. Send a paste: open the entry → **Export as QRFT** → leave
   *"Encrypt to paired paste keys (N)"* checked → scan the looping QR
   with the extension (insert + PIN + touch) → auto-filled.

**Requirements:** a security key with the WebAuthn `prf` extension
(YubiKey 5, fw ≥ 5.3) and Chrome on ChromeOS/desktop. Pairing is per key,
not per Chromebook — the same key works on any machine via the extension,
and the pairing record can be re-shown from the phone (Setup → Paste
devices → "Show QR") to restore a lost browser profile without
re-pairing. The OpenPGP key set on the same key (the vault's decrypt/
sign slots) is independent — see
[`../android/README.md`](../android/README.md#initialize-the-security-key-openpgp-key-set).

## Files

| File | Role |
|---|---|
| `bg.js` | the service worker: the popup wiring, the scan/decrypt pipeline |
| `fill.js` | the content script injected into the active tab: the fill/reveal |
| `lib/wrap.js` | the paste-crypto chain (WebCrypto): the PRF seed KEK, the ECDH paste KEK, AES-GCM layers, TOTP |
| `lib/qrft.js` / `lib/store.js` | the QR reassembly + the pairing store |
| `pair.html/js`, `scan.html/js` | the pair wizard + the scan window |
| `selftest.html/js` | the in-browser self-test over the fixed cross-impl vectors |

## Tests

```bash
# The paste-crypto CONTRACT test (node ≥ 19, no deps): wrap.js must
# decrypt the DEVICE-generated vectors — the same numbers the Android
# DeviceWrapTest pins. Run from the repo root:
node extension/test/wrap_contract_test.mjs

# The in-browser self-test: chrome://extensions → offlinepass →
# the "Run self-test" link on the pair page.

# Regenerate the cross-implementation vectors (protocol change only):
python3 scripts/gen_device_wrap_vectors.py
```

Both implementations (the extension's WebCrypto and the Android JCE side)
assert the same vector numbers — they cannot drift apart without a red
test.

## Security model

A paste decrypts only with the paired key present + PIN + touch (touch
every paste; the PIN re-asks per operation in practice — CTAP2.1
auth-token expiry). The extension stores public records plus an
AES-wrapped seed only — the seed never exists in plaintext without the
touch — makes **no network requests**, and decrypts in memory. The
security key accumulates no state: non-resident credential, no passkey
slots used, existing GPG/PIV keys and passkeys untouched. Lost key → it
alone decrypts nothing; unpair on the phone and re-pair. Lost
Chromebook/profile → restore from the phone's "Show QR". Full wire
format, key chain, and threat model:
[`../docs/extension-protocol.md`](../docs/extension-protocol.md).

## Troubleshooting

- **Pairing fails with a PRF error** — the key lacks `hmac-secret`
  (YubiKey fw < 5.3): update the firmware, or pair the ChromeOS platform
  authenticator instead (PIN-based UV; pairing becomes per-machine).
- **"No paired key for \<keyId\>"** — that key isn't paired in this
  browser: pair it, or restore its pairing QR from the phone.
- **Transfer stalls mid-chunks** — hold the phone steady; the progress
  line names the missing chunk; if nothing moves for 5s, check the
  sender's speed selector on the phone.
- **Decrypt asks for the PIN every time** — expected: the key's PIN/UV
  token expires between operations; the touch is always required.

## License

GNU General Public License v3.0 — see [../LICENSE](../LICENSE). Contributions: [../CONTRIBUTING.md](../CONTRIBUTING.md).
