# The sync-era pass: tabled items (from the 2026-11-18 session)

The source of truth for landing: `docs/sync-era-workplan.md` (to be copied
from this plan on the next build-mode session).

## 1. The cert-signing touch prompt in the screenlock enrollment

**Reported:** the cert-signing touch during the screenlock enrollment lacks
the touch-prompt dialog the other card ops show.

**State:** `enrollScreenlockSigning` wraps the card sign in
`withTouchPrompt` (VaultSession ~549) — the report suggests either the
prompt is not rendered on that screen, or the signing happens through a
path that bypasses the wrapper. Investigate the actual enrollment flow on
device (the logcat breadcrumbs: `yubikit: PIN verified — PSO:CDS`) vs the
dialog state.

**Fix:** the enrollment's card sign = the same `withTouchPrompt` router
dialog as the SSH auth / the commit signing / the decrypt. If the dialog
is shown but the WINDOW is wrong (the BiometricPrompt overlap?), match
the decrypt's sequencing: the PIN prompt → the touch dialog → the sign.

## 2. The sync must not touch OpenKeyChain

**Reported:** the sync still reaches OpenKeyChain somehow — the sync's
pull→push should be YubiKit-only.

**Likely source:** `syncNow` calls `updateRepoKeyMaterial(openPgpClientFactory(appContext))`
— the OKK client = used for the recipient-key fetch when the armored
files are missing. Also `sharedOpenPgpClient` warm-ups (the OKK bind =
the IPC lines in the log at the load).

**Fix:** the sync's key-material step = local-only (the files exist in the
pulled repo; the fetch = the Setup-time operation, never mid-sync). Audit
every OKK touch in the sync flow: `updateRepoKeyMaterial`, `ensureSignKeyReady`,
`OpenKeyChainSigner` (the legacy commit mode), the OKK warmup. The sync =
the YubiKit path only: the SSH fetch (the card handshake), the commit
sign (the SIG slot), the push, the pull decrypt (the card).

## 3. The last-5-commits display under Sync

**Feature:** after the sync (and in the Sync tab), show up to the last 5
commit lines — like the git log: the short sha, the subject, the author,
the relative time.

**Implementation:** JGit `git.log().setMaxCount(5)` on the local main →
the UI rows under the sync status. Read-only, no auth needed (the metadata
is public).

## 4. The Setup screen's slowness

**Reported:** opening Setup is quite slow now.

**Hypotheses (to profile):**
- The Setup/SetupChoice composition does per-recomposition work:
  `recipientIds = VaultSession.recipientKeyIds()` (the prefs read), the
  `runCatching { File(...storage-pat.txt).readText() }` prefill read,
  `yubikeySshLine()`/`yubikeyAuthSubkeyId()` (the prefs reads), the
  `commitSigningMode()`, the device name — all cheap individually, but
  the screen = recreated on every nav (the ROM kills the app
  aggressively; the singletons survive, the composition = fresh).
- The screen switch itself = the recomposition of the whole router
  (the when(state) — the heavy branches = recomposed).
- The OKK bind attempt at the first save/sync = the multi-second hang —
  is anything on the Setup path triggering the OKK bind (the
  `warmOpenKeyChain()` at the activity start?).

**Plan:** the breadcrumb timestamps on the nav (the loadPhase-style
file channel), find the slow step, then: the precomputed session snapshot
(the StateFlow) instead of the per-composition prefs reads; the OKK warmup
= removed from the activity start.

## The order
1 = the quick verify + fix; 2 = the audit + the removal (the sync = the
YubiKit only); 3 = the small feature; 4 = the profile then the fix.
All four = one branch, the commits per item.

---

# The autofill era: landed + parked (from the 2026-11-19 session)

## Landed (the feature/aut-key → main merge, released as v0.10.3)

- **The autofill service**: the layered fill response (the sealed
  manifest datasets + the app fallback), the dataset-ID matching, the
  reveal (the store → the framework's re-invoked onFillRequest), the
  generate chip, the save flow, the crash guards (the service never
  throws into the framework).
- **The save flow (the user's shape)**: the platform's save dialog =
  the ONE question (onSaveRequest fires only AFTER its confirm) → the
  armed intent → the screenlock → the upsert → the toast. For the
  username-less generated logins (the platform's save event = the
  user-typed-delta only — an all-autofilled submission fires NOTHING):
  the SILENT tray trigger (the LOW importance, no banner) → its tap =
  the bottom card (yes/no) → the screenlock → the upsert.
- **The upsert = the SITE + USERNAME key** (the user's ask): the same
  origin AND the same (possibly empty) username = the update (the full
  item from loadedEnvelope — the state's items = the stubs post-promote,
  asStub strips the password/note/totp — the update base MUST be the
  full item); anything else = the append.
- **The save-pipeline hardening**: the seal-of-stubs clobber root (the
  loadedEnvelope NEVER carries stubs; the tail seals env.items), the
  modifyTime apply-diff + the explicit-edit tie, saveSealed's
  now-stamp + the uuid, the tombstones carried across the promote, the
  sync merge = the per-item modifyTime.
- **The EC (ECC) AUT path**: the EC P-256 auth-key generation on the
  card (in-app), the dual-slot enrollment (the AUT-first/SIG-fallthrough
  slot discovery, the recorded yubikeySshSlot), the EC SIG/EC auth +
  the commit sigs, the repo-QRFT export/import + the PK route.
- **The RSA-4096 AUT over USB = the named dead end**: the 0x6581
  (no extended APDUs over USB, no INS-0x88 chaining) — the EC path =
  the answer; don't revisit.
- The keystore-window hardening: the reveal's unseal retry (the
  gate→unseal window lag on this ROM), the auth activity's opaque theme
  (the translucent broke the framework's post-auth fill).
- The test harness: the `autofilltest` module (the login/signup forms,
  the captured-values toast/log).

## Parked

- **DEC/EC (the card-backed decryption key)**: the ECDH PSO:DEC path +
  the card-backed BC factory + the re-encrypt-on-swap. The scoping:
  the seal envelope's recipients = the card's DEC pubkey (the
  KDF=the ECDH tunnel); the unseal = PSO:DEC on the card (the PIN/touch
  = the existing prompts); the re-encrypt-on-swap = the recipient
  rotation at the card swap (the QRFT/sync pairing needs the new DEC
  pubkey enrollment first). Blocks: the YubiKit DEC support surface
  (the same extended-APDU question as the RSA AUT — probe EC DEC first).
- **The legacy OKK signer deletion** (the workplan item 2) — the sync =
  the YubiKit only.
- **The pin-prompt hardening** — the OpenPGP PIN surfaces = the
  per-activity dialogs now (the MainActivity + the autofill's auth
  activity); consolidate.
- **The Setup slowness** (the workplan item 4) — the breadcrumbs, then
  the precomputed session snapshot.
- **The TUI side (offlinepass.py)** — the user's to schedule: the
  sealed-manifest/autofill-era format changes are Android-only so far;
  the TUI reads the same repo.
