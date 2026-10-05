# linuxpass Android — Design

Status: finalized — ready for spike phase
Date: 2026-10-04
Scope: native Android client for the linuxpass vault
Code layout: `linuxpass/android/` — own Gradle project in this repo,
alongside the desktop TUI.
Related docs: `docs/work-plan.md` (execution), `docs/testing-plan.md` (QA),
`user_flows.md` (target end-state UX, repo root — mapped in work-plan).

## 1. Summary

A native Android app joins the existing desktop TUI as a second client for
the same encrypted vault repo. The design rests on four constants:

- **One vault file** (`10.gpg`), standard OpenPGP — decryptable by desktop
  `gpg` unchanged, encrypted to hardware security keys only.
- **Every unlock requires a hardware key.** The app decrypts through
  OpenKeyChain against the OpenPGP applet on 2–3 YubiKeys (NFC/USB),
  touch+PIN per operation. The keys are the backup.
- **GitHub (private repo) is the default master**, synced over SSH with
  the applet's authentication subkey — no tokens anywhere. Offline edits
  queue as local commits and push on reconnect.
- **Single-entry QR exports and USB save/restore** cover the offline-copy
  story; bulk vault transfer is deferred (see §10–§11, decision log).

Native is required, not optional: the browser sandbox can neither reach
the OpenPGP applet for unlock/signing nor speak SSH — and Android autofill
requires an `AutofillService`.

## 2. Background (existing system)

`linuxpass` today is a Python curses TUI (`linuxpass.py`) + vault library
(`passlib.py`): a Proton Pass JSON envelope encrypted with
`gpg --encrypt --recipient` into a single file, git auto-commit on writes,
and terminal QR display of single entries — scanned by the existing QR
Autofill companion app to autofill credentials on the phone. The Android
app described here reuses the vault format, the QR pairing, and adds
native CRUD + autofill + sync.

## 3. Goals / non-goals

**Goals**
- Vault decrypt/encrypt via OpenKeyChain + YubiKey (touch/PIN per op)
- SSH pull/push from GitHub with the applet auth subkey; repo = master
- CRUD, search, live TOTP, password/alias generation
- Android Autofill Service filling any app's login forms
- Single-entry QR export: plaintext Proton-JSON — single-frame for QR
  Autofill, qrft-generator mode for low-dependency machines
- USB whole-file save/restore for offline copies (save = snapshot to
  stick; restore = import, merge if diverged)
- Offline operation: local working copy, queued commits, sync on reconnect

**Non-goals (deferred to backlog — see §16)**
- Whole-vault QR export / repo-bundle transfer (qrft bandwidth: ~100s of
  B/s makes multi-KB payloads impractical)
- Delta-exchange engine (watermarks, phone-to-phone op-batches)
- In-app qrft scanner (sender-side generator only)
- Web-based client — the browser sandbox can neither reach the OpenPGP
  applet for unlock/signing nor speak SSH, and native autofill requires
  a native app
- Passkey-derived key unlock (backlog behind a platform spike)
- Passkey/Credential-Manager provider (classic Autofill Service only)
- Background sync (all sync explicit)
- Root/hardened-device guarantees (standard app sandbox)
- Key generation or key export — keys live on the hardware keys only

## 4. Vault & repo format

- Single `10.gpg`, OpenPGP message, **PKESK-only, applet-key recipients
  only** (2–3 YubiKeys). No SKESK/passphrase packets, no recovery
  passphrase. Any one key opens the message.
- Envelope: Proton Pass JSON, extended with `rev` (monotonic, bumps on
  every save) and `deviceId` (stable per install).
- Repo layout (private, master):
  ```
  state/10.gpg               # vault
  keys/*.public.asc          # applet public keys (for encrypt-side)
  ```
- Desktop `passlib.py` changes required: multi-recipient env var
  (`LINUXPASS_GPG_RECIPIENTS`), preserve/generate `rev`/`deviceId`
  through saves, wire the existing (unused) `git_pull()` at startup, push
  after commit over SSH.

## 5. Crypto & key model

| Path | Factors | Channel |
|---|---|---|
| Desktop TUI | OpenPGP applet + touch/PIN | `gpg` + pcscd |
| Android app | OpenPGP applet + touch/PIN | OpenKeyChain (NFC or USB/OTG) |

- All private material stays on the hardware keys. Nothing key-shaped is
  ever on any device or server.
- OpenKeyChain performs decrypt/encrypt (OpenPGP API) and SSH-auth
  signing (sign API) as intent-based services.
- Optional BiometricPrompt gate is UX convenience, not a security
  boundary — the key touch/PIN is the invariant.
- Plaintext entries exist only in app memory while in use; on-device
  vault copy is ciphertext (the repo working tree).

## 6. Code layout & reuse (from `~/3p`)

- **Copy-sources policy:** `~/3p/offlinecam` and `~/3p/airgap-qr-offline`
  are *copy sources only* — nothing from them is assumed present on any
  device; lifted/vendored files are committed into `linuxpass/android`
  themselves. Commits land incrementally per task.
- **Toolchain from `offlinecam`** (proven, reused wholesale): AGP 8.11.1,
  Kotlin 1.9.22 (+kapt), compileSdk 36 / minSdk 26 / targetSdk 34, Java
  17, viewBinding, test stack = JUnit + Robolectric + Mockito(-kotlin) +
  Espresso; JGit `7.7.1.202607240634-r` + `slf4j-nop` already proven
  there (HTTPS-only — the SSH transport is new work, see §8).
- **OpenKeyChain binding lifted from `offlinecam`** (working +
  unit-tested): vendored OpenPGP API (`IOpenPgpService2` AIDL) plus a
  self-contained minimal client (`OpenPgpClient`) speaking API v11 over
  binder pipes — key lookup by email, multi-recipient binary encrypt,
  decrypt-verify with signature-status mapping, armored public-key
  export, sign-key picking. No external openpgp-api library needed;
  Apache-2.0 attribution preserved.
- **qrft generator vendored from `airgap-qr-offline`** (`offline/`):
  `generator.html` + `vendor/{jsQR,pako,qrcode}` — inlined into the app
  as WebView assets (sender-side only; no native codec).

## 7. Architecture

| Component | Choice | Notes |
|---|---|---|
| UI | Kotlin + Compose | search, detail, CRUD, TOTP, QR, sync, settings |
| Crypto | OpenKeyChain (OpenPGP API) | lifted `OpenPgpClient` + AIDL; decrypt/encrypt vault; sign SSH challenges; NFC + USB(OTG) |
| Git | JGit (7.7.1) | from offlinecam (HTTPS-proven); SSH transport = Apache SSHD artifact + custom OpenKeyChain-backed auth |
| Autofill | `android.service.autofill.AutofillService` | Bitwarden/KeePassDX pattern |
| QR single-frame | ZXing core | Proton-item QR for QR Autofill |
| QR export (qrft) | vendored `generator.html` in WebView | payload file → looping QR frames; receiver scans with any qrft.org-compatible scanner |
| USB exchange | Storage Access Framework pickers | whole-file save/restore of the vault (see §11) |
| Local store | app-private dir = working copy of repo files | decrypted plaintext in memory only during use |
| Biometric | BiometricPrompt (optional gate) | hardware key touch/PIN remains mandatory per crypto op |

## 8. GitHub sync over SSH

- Remote: `git@github.com:<user>/<vault>.git` (private).
- Auth: a **per-device SSH key generated non-exportably inside Android
  Keystore** (ed25519 where the device supports it, RSA-3072 fallback),
  enrolled on GitHub as a per-repo **deploy key** (read/write). The SSH
  auth signature is computed by the phone's TEE via
  `java.security.Signature`; the private key never leaves the device.
  OpenKeyChain is not part of transport auth. (Spike probe: OpenKeyChain
  sign actions produce PGP-armored detached signatures — unusable for
  SSH wire auth; see testing-plan run log.)
- Enrollment: the Keystore public key (OpenSSH wire format) registered as
  the vault repo's deploy key; per-device keys are revocable individually.
- Sync is explicit: pull → decrypt both states → if diverged, union-merge
  by `itemUuid` + tombstones (conflict UI: keep mine / take theirs /
  merge) → encrypt (touch) → commit → push (sign, touch). Non-fast-forward
  → re-pull, re-merge, retry.
- Commit identity: user-configured name/email; messages follow the TUI's
  `Update <file>` convention (plus rev).
- **Documented fallback** (only if the spike fails): HTTPS remote with a
  fine-grained PAT held in Android Keystore. Everything else in this
  design is independent of that choice.

## 9. Autofill

- `AutofillService` with dataset building for username / password / TOTP;
  field heuristics per the Bitwarden/KeePassDX pattern.
- Inline unlock: when the vault is locked, the autofill dialog offers
  unlock → key tap → fill; no app switch needed.
- Compat matrix across OEM browsers/apps is a phase-5 test concern.

## 10. Single-entry QR exports (vendored qrft generator)

The only QR export in scope is **per-entry**, and it is plaintext by user
decision (same posture as the TUI today; the screen is the trust
boundary). Two renderings of the same Proton-JSON payload:

1. **Single-frame QR** (ZXing) — the existing QR Autofill pairing,
   unchanged; also readable by any generic QR decoder.
2. **qrft-generator mode** — the payload is packaged as a small file and
   streamed through the vendored `generator.html` (WebView) as looping QR
   frames; a low-dependency machine running any qrft.org-compatible
   *scanner* page decodes it back into the file. **Generator-side only:**
   the app never scans qrft streams, so no camera code is involved.
   A single entry (~100–150 bytes of JSON) is a one-to-few-frame loop —
   seconds on screen.

Bulk vault transfer via QR is **deferred**: qrft's real throughput
(~100s of B/s) makes multi-KB payloads minutes-long and fragile. USB
save/restore (§11) covers offline copies instead.

## 11. Offline operation: queued commits, USB save/restore

- The app's working copy is the repo itself (JGit works offline); no
  network → offline banner, edits queue as local commits, push on
  reconnect.
- **USB save/restore** (whole file, no delta machinery):
  - *Save:* SAF `CreateDocument` → writes the current encrypted working
    file as `linuxpass-vault-rev<N>.gpg`. Ciphertext only; nothing
    plaintext touches disk.
  - *Restore:* SAF `OpenDocument` → decrypt-check via OpenKeyChain
    (touch) → compare `rev`/`deviceId` against local state → if both
    sides diverge, the same conflict UI built for online sync resolves it
    (keep mine / take theirs / union-merge by `itemUuid`) → winner
    written to the working copy and committed locally; pushed whenever
    the network returns.
- **Local-only mode:** an offline phone restored from USB needs no GitHub
  remote at all — the app runs with a working copy and sync disabled
  until a remote is configured. Offline-copy lifecycle: restore → use →
  save → (online side imports and reconciles).
- **Master reconciliation:** GitHub is the default master for online
  devices; a USB round-trip that lands two divergent snapshots resolves
  through the merge UI on the next unlock-capable device that sees both,
  then republishes to the chosen master. Git history is the online safety
  net for tampering.

The delta-exchange engine (per-peer watermarks, encrypted op-batches,
phone-to-phone transfer) is **deferred to backlog**; the merge code it
would need is built anyway for the online path.

## 12. User flows

### Setup (one-time)
1. Install app + OpenKeyChain; register API access.
2. Pair YubiKey (NFC or USB); applet keys detected.
3. Configure repo remote (SSH URL) + identity (sign key).
4. Enroll the signing key's public half on GitHub (deploy key R/W or
   account key).
5. First pull (touch) → first decrypt (touch) → working copy ready.
   *(USB-only alternative: skip 3–4, restore a snapshot from a stick →
   local-only mode.)*

### Regular use
6. **Unlock & browse** — open → (biometric) → tap → decrypt → search →
   detail → live TOTP with countdown.
7. **CRUD** — add entry (generated password / alias stub), update
   password, enroll TOTP (base32 or `otpauth://`), delete (tombstone) →
   save → encrypt → commit → push.
8. **Autofill** — any app's login form → system dialog → pick entry →
   inline unlock → fill.

### Exports & offline copies
9. **Single-entry QR** — Proton-JSON: single-frame (QR Autofill / generic
   decoder) or qrft-generator stream (qrft.org-compatible machine).
10. **USB save** — snapshot the working file to a stick.
11. **USB restore** — import a snapshot; conflict UI if diverged;
    local-only mode if no remote is configured.

### Sync
12. **Online sync** — explicit action; pull/merge/push per §8.
13. **Reconciliation** — divergent snapshots (from USB or parallel
    devices) resolved by the merge UI, `rev` bumped, republished to the
    chosen master.

### Maintenance
14. **Add hardware key C** — commit its public key → any unlock-capable
    device re-encrypts adding PKESK.C.
15. **Key rotation (compromise)** — re-encrypt to remaining keys; remove
    old pub from repo + GitHub.
16. **All keys lost** — vault unrecoverable (accepted; keys are the
    backup).

### Error flows
- OpenKeyChain cancel/timeout → operation aborted, state unchanged
- Non-FF push → auto re-pull → re-merge → retry
- NFC dispatch quirk → retry; USB-C fallback documented
- No network → offline banner; edits queue locally
- QR decode stall → sender loops frames until complete

## 13. Security properties

- **Unlock invariant:** the vault opens only with a hardware key
  (touch/PIN), on desktop and Android alike.
- No tokens, no PATs, no passphrases, no key material in app storage,
  repo, or transit. On-device copy: ciphertext. USB snapshots: ciphertext.
- Plaintext exists in memory only during active use; single-entry QR
  export is plaintext by explicit user posture (screen = trust boundary).
- OpenKeyChain unattended operations (API allowlist) are a UX-vs-prompts
  setting; default is prompted for every op.
- Repo compromise ⇒ tamper/rollback risk only; git history exposes it,
  desktop `--ff-only` refuses rewrites.

## 14. Risks & mitigations

| Risk | Mitigation |
|---|---|
| OpenKeyChain SSH-sign + JGit integration depth | spikes #2/#3 first; fallback = HTTPS + PAT in Android Keystore (token reluctantly returns) |
| OpenKeyChain prompt friction in daily use | user-configurable unattended ops; UX test early |
| NFC dispatch quirks across OEMs | USB-C fallback; spike #6 |
| Autofill compat across OEM browsers | standard service pattern; phase-5 test matrix |
| Plaintext QR exposure | user-chosen posture; screen-trust documented |

## 15. Build phases

See `docs/work-plan.md` for the task-level breakdown and exit criteria;
summary:

- **Phase 0 — spikes:** OpenKeyChain round-trip (lifted client vs real
  applet + real vault); OpenKeyChain SSH-sign; JGit+SSH integration;
  autofill shell; vendored qrft generator interop; NFC/UX timing.
- **Phase 1 — core:** envelope model; OpenKeyChain layer (lifted); JGit
  working copy; unlock UX; desktop `passlib.py` changes.
- **Phase 2 — UI:** search/browse, detail, CRUD, TOTP, generators.
- **Phase 3 — sync:** SSH transport; merge + conflict UI; enrollment UX.
- **Phase 4 — exports:** single-entry QR (both renderings); USB
  save/restore; local-only mode.
- **Phase 5 — autofill + hardening:** service hardening, error UX,
  release build, full test sweep.

## 16. Decision log

1. Native app over web client — autofill requires it; browser sandbox
   cannot access the OpenPGP applet or SSH.
2. Vault unlock requires a hardware key, always; no recovery passphrase;
   the 2–3 keys are the backup.
3. Recipients: applet keys only; no software private keys anywhere.
4. GitHub sync: OpenKeyChain-signed SSH; PAT only as a documented
   fallback.
5. Single-file vault format kept; envelope extended with `rev`/`deviceId`.
6. Single-entry QR export: plaintext Proton-JSON (TUI parity); two
   renderings (single-frame, qrft-generator).
7. Offline copies via USB whole-file save/restore + local-only mode.
8. qrft vendored as WebView assets (`airgap-qr-offline`), generator-side
   only; GPL-3 accepted for a personal tool; wire compatibility inherent
   since it *is* the qrft code.
9. Deferred to backlog (qrft bandwidth ~100s B/s): repo-bundle transfer,
   delta-exchange engine (watermarks), in-app qrft scanner. The
   union-merge code is built anyway for the online conflict path.
10. Monorepo: app at `linuxpass/android`; toolchain + OpenKeyChain
    binding lifted from `offlinecam` (copy-source policy; nothing assumed
    installed anywhere).
11. Process: incremental commits per task/spike.
12. Passkey-derived key unlock: backlog behind a ~1-day platform spike
    (does Android's FIDO2/Credential Manager surface YubiKey PRF outputs
    to apps?). If yes: extra derived-key recipient + optional unlock
    path; SSH signing still needs OpenKeyChain; device-bound passkeys
    rejected (would break the hardware-key invariant).
13. Phone git auth = **Android Keystore SSH key** as a per-device deploy
    key (S2 probe showed OpenKeyChain's detached signatures are
    PGP-armored — unusable for SSH wire auth). Non-exportable, TEE-held,
    revocable per device; no tokens.
14. Backlog upgrade: in-app CCID `PSO:SIGN` against the YubiKey's [A]
    subkey so the hardware key signs SSH too (raw USB/CCID + card
    protocol; weeks-scale).
15. Commit signing today = the vault identity's key (picker-chosen
    recipients; unsigned fallback). A DEDICATED signing key — picked via
    OpenKeyChain's `GET_SIGN_KEY_ID` picker (already in OpenPgpClient) —
    is a separate config field for later; needed when the recipient keys
    cannot sign (e.g. [CE] applet primaries).

## 17. References

- OpenKeyChain OpenPGP API docs; ConnectBot OpenKeyChain SSH-auth precedent
- qrft.org — airgap-qr-offline (GPL-3.0): github.com/chrislengerich/airgap-qr-offline
  (local clone: `~/3p/airgap-qr-offline`)
- offlinecam (local: `~/3p/offlinecam`) — Gradle baseline, JGit usage,
  `OpenPgpClient`/vendored OpenPGP AIDL integration
- txqr (fountain-code prior art): github.com/divan/txqr
- OpenPGP RFC 4880/9580; RFC 6238 (TOTP)
- Android Autofill Service docs; Storage Access Framework docs;
  WebViewAssetLoader docs; FIDO2 API / Credential Manager (backlog spike)
