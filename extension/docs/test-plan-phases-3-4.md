# Test plan — phases ③ (git sync) and ④ (QRFT both ways)

## Scope under test

- ③ **Git sync (isomorphic-git, HTTPS + token)**: the clone, the fetch,
  the push, the merge-by-divergence, the credentials, the service-worker
  constraints, the offline behavior.
- ④ **QRFT both directions**: the export-to-phone (the QR render via
  qrcode's browser build — CommonJS, needs a shim) and the camera import
  (jsQR's decode of the phone-rendered QRFT stream).

## Test environment & fixtures

- **No runtime fetches**: every library vendored (`lib/isogit.umd.min.js`,
  `lib/jsQR.js`, `lib/qrcode.cjs`, `lib/openpgp.mjs`). The tests run on
  Node's built-in runner (`node --test`) against the same files.
- **Git server fixtures**: a local bare repo served over HTTP. Two tiers:
  1. **Dumb-HTTP** (a static file server over a bare repo) — for
     isomorphic-git's fetch/clone of a prepared state (read paths only).
  2. **Smart-HTTP** (`git http-backend` behind a tiny Node/CGI wrapper)
     — for the push/fetch round-trips. The wrapper = part of the test
     fixtures; `git` is present on the dev machines.
- **Auth fixtures**: the HTTP Basic with a test token (the isomorphic-git
  `onAuth` hook returns it) — the same interface the production settings
  use.
- **Crypto fixtures**: a **test key ring** — a software RSA/ECDH keypair
  per test run; the vault envelope fixtures encrypted to them. The
  card is NOT in these tests (the card's decrypt = the phase 2 probe's
  hardware path; the unit tests use the same sessionKey handoff shape).
- **QRFT fixtures**: the known payload → PNG/QR matrix pairs. The QR
  *render* test decodes with jsQR (the round-trip: the render → the
  decode → the identical payload); the multi-frame QRFT stream =
  the fixture from the phone's qrft.js (the SAME codec — the
  extension reuses `lib/qrft.js`).

## Unit tests

### ③ Git sync
1. **The clone**: a fresh local dir → clone the smart-HTTP fixture →
   the HEAD matches the fixture's HEAD; the `state/10.gpg` present.
2. **The fetch**: the pre-cloned dir + the new fixture commit → fetch →
   the remote-tracking ref advances; no working-tree changes.
3. **The push (the fast-forward)**: the local commit ahead → push →
   the remote HEAD advances; the tracking ref updated (the
   push-by-URL trap: the test asserts via a fresh `git ls-remote`).
4. **The push (the divergence)**: both sides advance → the push is
   rejected → the app's merge path (the union-merge of the decrypted
   envelopes) → the push succeeds; the merged rev > both.
5. **The credentials**: the wrong token → the auth error surfaces with
   the actionable message (no silent retry loops).
6. **The offline**: the network error → the local commit stays; the
   status says "will sync later" (the save-local-first contract).
7. **The service-worker constraints**: the sync initiated from the SW
   (the alarm-triggered) completes despite no DOM; the fetch keeps
   alive within the SW's 5-min budget for the sized repos (the
   measured: the vault repo = tiny; the large = out of scope).

### ④ QRFT
1. **The render→decode round-trip**: the payload → the QR matrix →
   jsQR → the payload bit-identical (single-frame and multi-frame).
2. **The chunked stream**: a 2KB payload → the frames → the sequential
   decode → the reassembly; the out-of-order frame rejection.
3. **The camera path (semi-integration)**: a rendered QR displayed on
   a canvas → the getUserMedia frame → jsQR → the decode (the headless
   can't camera: the canvas-fixture test covers the decode; the real
   camera = the human plan).
4. **The encrypted paste**: the QRFT wrap to the paired keys — the
   decode side opens with the same key set (the wrap.js reuse).

## Integration tests

1. **The sync-then-decrypt**: the clone → the decrypt (the sessionKey
   handoff shape) → the entries parse.
2. **The edit→save→sync**: the entry edit → the save (the re-encrypt)
   → the sync push → a second clone sees it.
3. **The extension↔phone parity**: the same fixture envelope decrypted
   by (a) the extension's pipeline and (b) the phone's known-good
   output — the identical plaintext.

## Risks / known traps

- **isomorphic-git's smart-HTTP only** — the dumb-HTTP tier = the read
  fixture; the push tests = the smart-HTTP wrapper required.
- **MV3 service worker lifetimes** — the long syncs may be killed; the
  design: the sync = resumable (the local commit first, the push
  retried).
- **The QR scale/contrast** — the jsQR needs the quiet zone + the
  contrast; the render tests pin the module size (the phone's qrft.js
  parameters reused).
- **The CJS shim**: qrcode's browser build = CommonJS — the import
  wrapper test (the default export's presence) before the render use.
