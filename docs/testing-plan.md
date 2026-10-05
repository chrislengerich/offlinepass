# linuxpass Android — Testing Plan

Status: active
Date: 2026-10-04
Companion docs: `docs/android-app-design.md` (design), `docs/work-plan.md` (execution).

## 1. Principles

- **Tests mirror the risk.** The two riskiest seams are (a) OpenKeyChain
  ↔ JGit SSH transport and (b) cross-platform vault format compatibility;
  both get dedicated suites.
- **Hardware-in-the-loop tests are explicit.** Any test needing a YubiKey
  or OpenKeyChain is tagged and never runs in the plain JVM unit suite.
- **No plaintext fixtures.** Encrypted fixtures are ciphertext committed
  as test resources; plaintext appears only transiently in memory during
  a test.
- **Desktop parity is a contract.** Any file the app writes must decrypt
  with desktop `gpg`, and vice versa — tested both directions.

## 2. Test layers

| Layer | Where | Runs on | Needs |
|---|---|---|---|
| L1 — JVM unit | `android/app/src/test` | JVM (Robolectric where needed) | nothing |
| L2 — instrumented crypto | `android/app/src/androidTest` | device/emulator + OpenKeyChain | OpenKeyChain, YubiKey (NFC/USB) |
| L3 — git/integration | `android/app/src/androidTest` | device + real GitHub | scratch private repo, YubiKey |
| L4 — cross-platform | shell-driven, repo-rooted | desktop + device | `gpg`, `git`, QR Autofill app, qrft.org pages |
| L5 — manual UX scripts | this file, §5 | real devices | everything |

Tags: `@OpenKeyChain`, `@Hardware` (YubiKey required), `@Network`
(real GitHub), `@Slow`. L1 runs everywhere, always; L2–L4 run explicitly
on hardware.

## 3. Suites & test IDs

### L1 — JVM unit tests (`T-U-*`)

| ID | Suite | Covers |
|---|---|---|
| T-U-01 | EnvelopeCodecTest | Proton Pass JSON round-trip; unknown-field preservation; `rev` bump on save; `deviceId` stability |
| T-U-02 | EnvelopeCodecTest | tolerant parse: extra/missing fields, both envelope shapes (list / vaults-dict) like `passlib.py` |
| T-U-03 | MergeTest | union by `itemUuid`; idempotence; ordering stable |
| T-U-04 | MergeTest | tombstones: delete survives sync; resurrect conflict rules |
| T-U-05 | MergeTest | divergence detection via `rev`/`deviceId`; conflict classification (clean / conflict) |
| T-U-06 | EntryPayloadTest | single-entry Proton-JSON payload build/parse (QR export source of truth) |
| T-U-07 | TotpTest | RFC 6238 test vectors; `otpauth://` parsing (digits/period/issuer); countdown math |
| T-U-08 | PasswordGenTest | alphabet/length; alias stub charset asserted |
| T-U-09 | OpenPgpClientMappingTest | result/status mapping + user-interaction path with mocked binder (offlinecam pattern) |
| T-U-10 | RestoreDecisionTest | whole-file restore decision logic: same state / newer theirs / divergent → conflict classification |
| T-U-11 | LocalOnlyModeTest | working copy without remote: sync disabled, CRUD + local commits still function |

### L2 — instrumented crypto (`T-D-*`, `@OpenKeyChain @Hardware`)

| ID | Suite | Covers |
|---|---|---|
| T-D-01 | OpenKeyChainRoundTripTest | decrypt the committed ciphertext fixture via applet (NFC) — manual key touch |
| T-D-02 | OpenKeyChainRoundTripTest | same over USB/OTG |
| T-D-03 | OpenKeyChainRoundTripTest | encrypt to all enrolled recipients; output written to app storage for desktop cross-check |
| T-D-04 | OpenKeyChainSignTest | sign arbitrary bytes (SSH-challenge-sized) via the YubiKey-held key |
| T-D-05 | NfcDispatchTest | foreground dispatch reliability; cancel/timeout → clean abort |
| T-D-06 | UnlockFlowTest | biometric gate → decrypt; biometric-fail → retry path |
| T-D-07 | CiphertextAtRestTest | after an unlock cycle: no plaintext on disk (working tree + caches greped in test) |
| T-D-08 | QrftGeneratorTest | vendored `generator.html` renders a single-entry payload in the WebView; frames visible on screen |

### L3 — git/integration (`T-G-*`, `@Network @Hardware`)

| ID | Suite | Covers |
|---|---|---|
| T-G-01 | SshSignAuthTest | SSH client authenticates to `git@github.com` with the Android-Keystore-backed identity (S2/S3) |
| T-G-02 | JgitSyncTest | fetch of the scratch vault repo |
| T-G-03 | JgitSyncTest | commit + push by key touch; commit identity/metadata correct |
| T-G-04 | JgitSyncTest | non-fast-forward push → detected → re-pull/merge path exercised |
| T-G-05 | JgitSyncTest | offline edit → later sync converges (queue-then-push) |
| T-G-06 | DesktopSyncTest | TUI (`passlib.py`) push observed by app and vice versa in the same scratch repo |

### L4 — cross-platform (`T-X-*`, shell-driven)

| ID | Covers | How |
|---|---|---|
| T-X-01 | Desktop `gpg` decrypts an Android-written vault | pull file from device, `gpg --decrypt` with applet key |
| T-X-02 | Android decrypts a TUI-written vault | commit from desktop, sync in app |
| T-X-03 | Envelope field preservation both directions | `rev`/`deviceId`/unknown fields survive desktop save then app save and vice versa |
| T-X-04 | qrft interop: app-rendered payload → qrft.org scanner page | manual, scripted (desktop browser) |
| T-X-05 | QR Autofill app scans app-rendered single-frame QR | manual, on phone |
| T-X-06 | USB snapshot imported by desktop TUI | restored file dropped into `LINUXPASS_FILE`/`LINUXPASS_GIT_DIR`; TUI reads it |

### L5 — manual UX scripts (`T-M-*`)

| ID | Script |
|---|---|
| T-M-01 | Fresh setup end-to-end (install → OpenKeyChain pairing → remote config → enrollment → first sync) |
| T-M-02 | Daily offline use: unlock → search → CRUD → TOTP, no network |
| T-M-03 | Two-device convergence drill (desktop + phone, deliberate conflict) |
| T-M-04 | Autofill matrix: Chrome, Firefox, Samsung Internet + two native app login forms; inline unlock path |
| T-M-05 | Offline phone drill: USB restore → local-only use → USB save → online side imports + reconciles |
| T-M-06 | Maintenance runbooks: add hardware key C; key rotation; all-keys-lost doc walk-through |
| T-M-07 | NFC/USB alternation across a week of real use (prompt friction log) |

## 4. Fixtures & environments

- **Ciphertext fixtures** (committed under `android/app/src/test/resources`
  and `android/app/src/main/assets`): an envelope with 5 entries (from
  `test_data.json`), one with TOTP enrolled; encrypted to a **test**
  recipient set. Hardware round-trips additionally use the real vault via
  a manual gate.
- **Scratch repo:** private GitHub repo `linuxpass-vault-test`, resettable
  by force-pushing a seed commit; both the app (test build) and the TUI
  point at it during testing.
- **Devices:** daily phone (NFC YubiKey A), offline test phone (USB-C
  YubiKey B), desktop (`ed25519-sk` + applet via `gpg`).
- **USB sticks:** two (save/restore drill needs a carrier).

## 5. Manual scripts (L5) — summary

Full checklists are executed per release and signed off with dated
initials in this file's git history. The scripts above (T-M-01..07) are
walked start-to-finish; any failure opens a work-plan task, never a
silent pass.

## 5b. Run log

**2026-10-04 — Spike S3 PASS (production transport):**
- JGit clone → fetch → commit → push over HTTPS with a fine-grained PAT, on-device: **two full cycles** (`7669ad9`, `4542aa0`), both visible from the desktop via the API.
- Push-retry fix exercised (clean tree with an unpushed head pushes instead of reporting up-to-date — a gap in the offlinecam pattern, fixed here).
- Keystore SSH identity (SshKeyManager + jsch) remains committed but deferred; T-G-01 (SSH auth) moves to the backlog test list.

**2026-10-04 — Spike S2 decision:**
- OpenKeyChain sign → PGP-only (see probe above) → **phone git auth moved to Android Keystore SSH keys** (per-device deploy keys; ed25519 API 33+ / RSA-3072 fallback; CCID upgrade deferred to backlog). Design §8 + decision log updated.

**2026-10-04 — Spike S2 probe (same device):**
- Sign actions: `SIGN` (inline, 313 B) and `DETACHED_SIGN` both **code 1 OK**.
- `DETACHED_SIGN` extra `detached_signature` = **ByteArray(244), armor `-----BEGIN PGP S…`** → PGP packet, **not** SSH-wire format → OpenKeyChain signing cannot produce SSH-auth signatures (hash framing + packet format differ). SSH-auth-via-OpenKeyChain is closed.
- `GET_SIGN_KEY_ID` picker works (UI-driven selection flaky via adb taps; lookup-based bypass used).

**2026-10-04 — Spike S1 (Pixel 10a, adb-driven; OpenKeyChain `noodlefish@nan.404`, software key on-device):**
- OpenKeyChain binding + first-use approval flow: PASS (`RemoteRegisterActivity` via PendingIntent; user tap).
- `GET_KEY_IDS` by email: PASS → `0xCCCB519D89D05EEA`.
- `GET_KEY` armored export: PASS (566 B).
- Desktop→phone: stub vault written by desktop `gpg` (noodlefish pub, 1102 B) decrypted on phone: **PASS** (T-X-02 for a software key; 3071 B plaintext).
- Round-trip on phone: decrypt → re-encrypt (1098 B) → re-decrypt → **MATCH** (T-D-03 essence).
- **Pending:** T-D-01/02 with the *real applet keys* + real `10.gpg` (OpenKeychain currently holds only noodlefish + Jiji S as software keys; applet keys need pairing). T-X-01 deferred to that run (desktop holds the real secrets; noodlefish self-encryption can't be desktop-decrypted by design).
- Platform notes: short screen-timeout stalls the flow → `svc power stayon usb`; scoped-storage EACCES on raw `/sdcard` paths → inputs read from the app's external dir; `S1DecryptActivity` stays non-exported, extras forwarded via `MainActivity`.

**2026-10-04 — End-to-end pass (Pixel 10a, adb-driven; stub vault via `noodlefish@nan.404`, GitHub storage-test repo):**
- Setup → Load from GitHub: clone → decrypt → **5 entries listed** (search screen, TUI-parity).
- Entry detail: reveal, **live TOTP ticking** (AWS Console entry), actions all present.
- **Update password: PASS** — rev 1, push `0805291`, remote-verified.
- **Add entry: PASS** — `test.example.com`/`testuser`, rev 2, push `fa86961`, remote-verified + listed.
- **Delete: PASS** — tombstone, rev 3, push `27ef021`, entry gone from list.
- **QRFT export: PASS** — paste prefilled with the real entry payload, sender auto-started ("chunk 1/2" looping; screenshot).
- **Autofill: PASS** — service enabled via system picker; fake-login form offered ranked datasets (AWS/GitHub/GitLab); selecting AWS Console filled username + password (screenshot).
- **USB save: PASS** — SAF snapshot `linuxpass-vault-rev3.gpg` (1174 B), desktop-pulled.
- Pending: real-applet-keys variant of the above (YubiKey pairing in OpenKeyChain + the real 192 KB vault), USB restore+merge drill, S6 NFC timing.
- Fixes landed en route: search rows clickable; push-retry on clean tree; `getRootViewNode()` API name; PAT field on first-run setup AND on the locked screen when unstored.

**2026-10-04 — USB restore + storage verification pass (same device):**
- **USB restore + merge: PASS** — picked the saved rev-3 snapshot from Downloads; decrypt → union-merge with current → rev 4 (1175 B) → push `2a87a9a`, remote-verified.
- **PAT at rest: PROVEN encrypted** — `run-as` dump of the SecretStore prefs shows only an IV-prefixed AES/GCM base64 blob; plaintext PAT appears **0** times in app storage.
- Setup tab now shows: sync status line (above Sync now) + "PAT: stored (encrypted in Android Keystore)".
- Known gap handled: renaming SecretStore prefs orphaned the previously stored PAT (one-time; re-entered via the new locked-screen field).

## 6. Traceability — phase exit criteria

| Milestone (work plan) | Green tests |
|---|---|
| M1 — vault opens on phone | T-U-01..05, T-U-09, T-D-01..07, T-X-01..03 |
| M2 — fully usable offline | T-U-07/08, T-M-02 |
| M3 — two devices converge | T-G-01..06, T-M-03 |
| M4 — entry travels by QR; offline copy survives save/restore | T-U-06, T-D-08, T-X-04..06, T-M-05 |
| M5 — daily driver | T-M-04, T-M-06/07, L1–L4 all green |

## 7. Backlog tests (written when the feature lands)

- **Passkey-derived unlock spike:** does `Fido2ApiClient`/Credential
  Manager return PRF extension outputs with a YubiKey 5 (NFC)? One
  instrumented probe; result recorded here before any design work.
- Whole-vault QR export, delta exchange, in-app qrft scanner (deferred
  features) — suites defined when/if un-deferred.

## 8. Conventions

- Test classes live beside their layer: JVM in `src/test`, device in
  `src/androidTest`; tags via JUnit `@Tag` (`OpenKeyChain`, `Hardware`,
  `Network`, `Slow`).
- Gradle helpers: `gradlew test` (L1 only), `gradlew
  connectedAndroidTest -Ptags=hardware` (explicit hardware runs) — plain
  CI (if ever added) runs L1 exclusively.
- Every bug fix adds the test that would have caught it.
