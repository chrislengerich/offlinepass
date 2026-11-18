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
