# linuxpass Android — Work Plan

Status: active
Date: 2026-10-04
Companion docs: `docs/android-app-design.md` (design), `docs/testing-plan.md` (QA).

## 0. How this plan works

- Phases are ordered by risk: everything that could invalidate the design
  is in Phase 0; nothing expensive starts until the spikes pass.
- Every phase ends with a **milestone** — a demoable state with explicit
  exit criteria, verified by the mapped tests in `docs/testing-plan.md`.
- Tests are tagged `T-*` and referenced per phase; definitions live in
  the testing plan.
- Desktop (`passlib.py`) changes are small and land early, because
  Android-side milestones depend on reading desktop-written vault files.
- **Commits land incrementally per task/spike.**

## Repo layout (target)

```
linuxpass/
├── linuxpass.py / passlib.py / test_passlib.py   # existing TUI
├── docs/                                          # design, work plan, testing plan
└── android/                                       # Gradle project (from offlinecam baseline)
    ├── build.gradle.kts / settings.gradle.kts / gradle/
    └── app/
        ├── src/main/         # UI, crypto, git, qrft vendored assets, AIDL
        ├── src/test/         # JVM unit tests (Robolectric/Mockito)
        └── src/androidTest/  # instrumented + hardware-in-the-loop tests
```

## Phase 0 — Spikes (de-risk first)

All six spikes run in throwaway code inside `android/` (a stub module or
`debug` sourcesets); each ends in a keep/kill decision.

| # | Spike | Tasks | Exit criteria | Tests |
|---|---|---|---|---|
| S1 | OpenKeyChain crypto round-trip | Lift `OpenPgpClient` + vendored AIDL + manifest visibility from offlinecam into the stub; decrypt the real `10.gpg` via applet (NFC **and** USB); encrypt multi-recipient | Stub decrypts the real vault; stub-written file decrypts with desktop `gpg` | T-D-01..03 |
| S2 | Keystore SSH identity | Generate a non-exportable ed25519 (API 33+) / RSA-3072 (fallback) key in Android Keystore; export the OpenSSH-format public half; user enrolls it as the scratch repo's deploy key | Public key in OpenSSH wire format produced on-device | T-D-09 |
| S3 | JGit + SSH transport | JGit transport wired to the Keystore-backed signer (SSHD custom auth or JSch Identity); fetch + push a scratch repo | Commit pushed to scratch repo by key-backed signature; non-FF rejection observed | T-G-02..04 |
| S4 | Autofill shell | `AutofillService` + dataset building; fill a login form; inline-unlock path | A real login form fills with a stub dataset | T-M-04 |
| S5 | Vendored qrft generator interop | Vendor `generator.html` + vendor libs as WebView assets; feed the single-entry payload file in; render loop on screen | qrft.org's *scanner* page (desktop) decodes the app-rendered payload back to the original bytes | T-D-08, T-X-04 |
| S6 | NFC / touch UX | Foreground dispatch patterns, prompt latency, cancel/timeout handling | UX pattern for tap prompts written down (used by Phases 1–3 UI) | T-D-05 |

**Kill switches:** S2/S3 fail → fall back to HTTPS remote + fine-grained
PAT in Android Keystore (design §8 unchanged otherwise). S5 fails → the
single-frame ZXing rendering remains regardless (qrft mode is a
convenience, not a dependency).

## Phase 1 — Core vault

| Task | Detail | Depends on |
|---|---|---|
| Gradle scaffold | `android/` project from offlinecam baseline (AGP 8.11.1 / Kotlin 1.9.22 / compileSdk 36 / minSdk 26 / Java 17); AIDL on | — |
| Envelope model | `ProtonItem` port; envelope build/parse preserving unknown fields; `rev`/`deviceId`; tombstones | — |
| OpenKeyChain layer | Lifted `OpenPgpClient` productionized: decrypt/encrypt with progress + cancel; operation queue (no concurrent binder calls) | S1 |
| Working copy | JGit clone/pull into app-private dir; file IO; ciphertext at rest | S3 (SSH) or HTTPS fallback |
| Unlock UX | decrypt-on-demand flow; optional biometric gate; tap-prompt screens; cancel/timeout states | S6 |
| Desktop changes | `passlib.py`: multi-recipient env var; envelope field preservation; `git_pull()` wiring; push after commit | S1 (interop verified via `gpg` CLI) |

**Milestone M1 — "the vault opens on the phone."** App shows real entries
from the real repo; an edit on desktop appears on the phone and vice versa
(one manual sync each way). Exit tests: T-U-01..05, T-U-09, T-D-01..07,
T-X-01..03.

## Phase 2 — UI (CRUD + TOTP)

| Task | Detail |
|---|---|
| Search/browse | list view, all-word match over name/username/email/URL/note (TUI parity) |
| Detail view | fields, TOTP state, entry actions |
| CRUD | add (URL + username / alias stub, generated password), update password, enroll TOTP, delete = tombstone |
| Live TOTP | code + countdown refresh |
| Settings | remote URL, commit identity, biometric toggle, unattended-ops toggle |

**Milestone M2 — "fully usable offline."** All CRUD works against the
local copy with zero network. Exit tests: T-U-07/08, T-M-02.

## Phase 3 — Sync

| Task | Detail | Depends on |
|---|---|---|
| SSH transport productionized | JGit wired to the Keystore-backed SSH identity (SSHD custom auth or JSch Identity); artifact pinned | S2, S3 |
| Sync action | explicit pull → merge → push; offline banner; queued edits | M2 |
| Merge + conflict UI | union by `itemUuid` + tombstones; keep-mine/theirs/merge screens; `rev`/`deviceId` bookkeeping | M2 |
| Enrollment UX | signing key public half → GitHub deploy key flow (QR/copy + instructions) | S2 |
| Desktop sync check | TUI pull-before-load / push-after-commit over SSH vs the same repo | Phase 1 desktop task |

**Milestone M3 — "two devices converge."** Desktop↔phone edits converge
in both directions; a deliberately diverged pair resolves via the
conflict UI. Exit tests: T-G-02..06, T-M-03.

## Phase 4 — Single-entry exports + USB save/restore

| Task | Detail | Depends on |
|---|---|---|
| Single-entry packaging | entry → Proton-JSON payload file | M2 |
| Single-frame QR | ZXing rendering (QR Autofill parity + generic decoders) | packaging |
| qrft-generator export | vendored `generator.html` in WebView; payload in, looping frames out (sender-side only) | packaging |
| USB save | SAF `CreateDocument` → `linuxpass-vault-rev<N>.gpg` snapshot | M2 |
| USB restore | SAF open → decrypt-check → `rev`/`deviceId` compare → conflict UI if diverged → working copy + local commit | M2, merge code |
| Local-only mode | run without a configured remote; sync disabled; surfaced in UI | restore |

**Milestone M4 — "an entry travels by QR; an offline copy survives
save/restore."** Exit tests: T-U-06, T-D-08, T-X-04..06, T-M-05.

## Phase 5 — Autofill + hardening

| Task | Detail |
|---|---|
| Autofill hardening | dataset trimming, heuristics tuning, locked-vault behavior |
| Error UX | every error flow in design §12 has a screen + recovery path |
| Release build | minify + local keystore signing (offlinecam pattern); proguard rules for JGit/SSHD/AIDL |
| Full sweep | complete testing-plan matrix executed; manual scripts signed off |

**Milestone M5 — "daily driver."** Exit tests: T-M-04, T-M-06/07, full
L1–L4 matrix green.

## Backlog (deferred)

- **Repo-bundle QR export** — offline repo bootstrap via qrft (bandwidth
  impractical: 30–100 KB at ~100s B/s)
- **Delta-exchange engine** — per-peer watermarks, encrypted op-batches,
  phone-to-phone qrft sync
- **In-app qrft scanner** — unnecessary while exports are single-entry
- **Passkey-derived key unlock** — behind a ~1-day spike: does Android's
  FIDO2 API / Credential Manager surface YubiKey PRF (`hmac-secret`)
  outputs to apps? If yes: extra derived-key recipient + optional unlock
  path (SSH still OpenKeyChain-signed; device-bound passkeys rejected)
- **CCID SSH signing upgrade** — in-app `PSO:SIGN` against the YubiKey
  [A] subkey so the hardware key signs SSH too (replaces the Keystore
  git identity; Keystore route ships first)
- Encrypted single-entry QR mode, web client, background sync,
  credential-manager provider, TUI import command for snapshots

## Target user flows (`user_flows.md`) → plan mapping

The repo-root `user_flows.md` is the target end-state UX. Mapping to
phases/milestones:

| Flow (user_flows.md) | Plan mapping | Status |
|---|---|---|
| Initial setup → **New vault** (storage: GitHub / USB) | Phase 1: empty-envelope creation + storage choice (remote config or local-only mode) | **addition** — small task, lands with Phase 1/2 |
| Load existing → GitHub info + auth key + encrypt key | M1 (Phase 1): remote config; auth key = per-device Keystore deploy key (S2/S3); encrypt keys = OpenKeyChain applet pairing | planned |
| Load existing → USB | Phase 4 USB restore (whole-file save/restore) | planned |
| Load existing → **QRTF import** | Deferred (qrft bandwidth; bulk QR) | backlog — revisit on request |
| Setup tab (persistent): sync / GitHub info + identities / enroll key / autofill setup / export | Phase 2 settings + Phase 3 sync/enrollment + Phase 4 exports + Phase 5 autofill setup | planned |
| Password search (main page) + entry options | Phase 2 (TUI-parity search + detail actions) | planned |
| Autofill interaction (context match → dropdown → fill) | Phase 5 Autofill Service | planned |

Terminology: "auth security key" = the per-device Keystore SSH deploy
key (git transport); "encrypt security key" = the YubiKey OpenPGP applet
keys (vault recipients, via OpenKeyChain). Two different roles — the
setup UI should keep them visually distinct.

## Risk-driven ordering (why this order)

1. **S2/S3 (Keystore SSH identity + JGit transport)** is the only place
   the design can still fail — it gates Phase 3, so it spikes early.
2. **S1** confirms the crypto path but is already mostly de-risked by
   offlinecam's tested client.
3. **S5** is generator-only with a trivial fallback (single-frame ZXing),
   so it never blocks.
4. Desktop changes are tiny and unblock cross-platform tests, so they
   land in Phase 1, not later.
