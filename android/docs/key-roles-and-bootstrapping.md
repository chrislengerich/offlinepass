# Key roles & bootstrapping — work plan

Status: **plan** (branch `feature/screenlock-role-split`; items 1–4 and the
role/migration tests are implemented — see the "done" marks below).

## 1. Context

Three key materials exist on a device, with different capabilities:

| Key | Lives in | Can do |
|---|---|---|
| **Security key** (the card) | The YubiKey's OpenPGP applet (SIG subkey; DEC via OKK) | SSH auth (YubiKit, direct), OpenPGP decrypt (via OKK), commit signing (YubiKit) |
| **Screenlock key** | Android Keystore (EC P-256, per-op credential auth) | SSH auth, commit signing (JGit `Signer`), local unlock/seal gate. **Cannot** be an OpenPGP encryption recipient (EC, sign-only) |
| **OpenKeyChain keys** | OKK's keyring (software keys + routing to the card) | OpenPGP encrypt/decrypt (the vault envelope), commit signing (detached) |

The envelope (the vault file, `state/10.gpg`) is **OpenPGP-only**: its
recipients are OKP public keys. Cross-device and desktop-verifiable by
design. The screenlock never joins the envelope; its local role is the
unlock/seal gate plus (when enrolled) signing/auth.

## 2. Role model

| Role | Bootstrap pull (load existing) | After load |
|---|---|---|
| SSH auth | **Security key only** — no PAT, no screenlock UI | screenlock *if this device is enrolled*, else the security key |
| Commit signing | n/a | screenlock *if this device is enrolled*, else the security key, else OKK |
| Encryption / local protection | n/a | the screenlock = the unlock/seal gate (existing); the envelope recipients stay OpenPGP regardless |

Principles:
- Bootstrap pulls authenticate with the **security key only** (the card's
  PIN + touch are the gate).
- The screenlock is **never** the bootstrap key. It is enrolled *later*,
  post-load, as a first-class local signer (and optionally for SSH auth).
- Every pull decrypts (via OKK → the card's DEC path). No optimization:
  simple over clever.

## 3. PAT policy

The PAT UI is **removed** from the load-existing and unlock screens (the
backend PAT helper stays for non-SSH remotes that were already configured).
No PAT is requested at load or unlock. A token would only ever be needed
for **key administration** (adding keys via the GitHub API) — currently not
used: key pairing happens out-of-band (QRFT / manual GitHub).

## 4. Screenlock enrollment (composite, post-load)

1. `KeystoreSigner.ensureKey()` — the per-op-credential EC key (existing).
2. **Pair to GitHub out-of-band via QRFT** (existing flow, unchanged).
3. On "paired": **update the repo's key material** (see §6) — the
   screenlock's line + cert land in `keys/` locally (no network needed: the
   app generated the material), the card's SSH line resolves via the
   enrollment flow (§7), the card's cert materializes via OKK's GET_KEY.
4. `syncNow()` (YubiKey-authed) publishes the material into the repo.
5. Roles set: `commitSigningMode = SCREENLOCK` (+ optionally
   `sshSyncMode = SCREENLOCK` on request).

In the future, **multiple screenlocks for multiple devices**: the registry
is append-only and device-tagged (§6); a second device appends.

## 5. Un-enroll migration

`migrateOffScreenlock()`:
- `sshSyncMode == SCREENLOCK` → `SSH_SYNC_YUBIKEY` (if the YubiKey is
  enrolled; otherwise it stays with an explanation)
- `commitSigningMode == SCREENLOCK` → `SIGNING_YUBIKEY`, else
  `SIGNING_OPENKEYCHAIN` (no YubiKey enrolled)
- **This device's** registry entry is removed and **this device's** keystore
  key is deleted — other devices' entries/keys are untouched
- The envelope's OpenPGP recipients are unaffected (the screenlock key was
  never one)

## 6. The repo as the offline keyring

`keys/` carries (committed with the vault, per-revision accountability):

```
keys/<recipient-keyid>.public.asc   # the envelope recipients (existing)
keys/keystore-signer.pub            # legacy single-file name (existing)
keys/screenlock-signers.pub         # NEW: multi-line, append-only, per-device:
                                    #   ssh-<alg> <b64> # offlinepass screenlock device=<deviceId> name=<Name>
keys/signer-<subkeyid>.asc          # NEW: the card's full GPG cert (primary+subkeys)
keys/authorized-keys                # NEW (optional): the transport registry —
                                    #   the SSH lines that may pull/push, per device
```

The device identity: the stable `deviceId` (the envelope already carries
one) + a user-editable device name (default `Build.MODEL`), stamped into
every registry entry and shown in Setup.

A fresh device: **Load from GitHub** (YubiKey auth) → the repo's `keys/` →
init OKK (§8) → decrypt. No desktop, no gpg exports.

## 7. Enrolling the card's SSH key: source resolution + proof

The card (imported keys) exposes only its **fingerprints** — no public
material to read from the card directly. The SSH line therefore resolves
from multiple sources, and the enrollment **verifies the card
cryptographically** (a stronger guarantee than the OKK picker ever gave:
the wrong-subkey class of bug is structurally impossible):

1. **The repo's registry** (offline, trusted) — the primary path once any
   device has enrolled
2. **`github.com/<user>.keys`** (public, account-level keys only) — the
   username derives from the remote field; **one touch**: the card signs a
   nonce, the signature is verified against each fetched line — the line
   that verifies is *provably* the card's; the subkey id comes from the
   card's SIG fingerprint (unauthenticated GET DATA)
3. **OKK `GET_KEY` derive** (offline) — derives the line from the cert OKK
   holds; no picker

Notes:
- **Deploy keys are NOT visible in `<user>.keys`** (repo-scoped, no public
  listing; API-visible only with a token). Sources 1 and 3 still cover them.
- Recommendation: register auth keys as **account keys** where possible.
- No match from any source → a clear error naming the fix
  (`gpg --export-ssh-key <subkey>!` → GitHub).

## 8. Bootstrapping OpenKeyChain from the repo

A fresh device's OKK is empty; decrypt routing needs the public certs.
`github.com/<user>.gpg` exists as a fallback for repos that predate this
feature, but the **repo itself is the primary source** (offline-capable):

- After a load, if `keys/` carries certs OKK doesn't hold (detected via a
  cheap lookup), offer **"Initialize OpenKeyChain from this repo"**: the
  app stages the `.asc` and opens OKK's import screen (the file hand-off —
  the OpenPGP remote API deliberately cannot mutate OKK's keyring). One
  confirmation inside OKK.

## 9. The decrypt story

- Every pull decrypts via OKK → the card's DEC path (PIN/touch per the
  card's policy). Kept simple by design.
- The plaintext exists **transiently in memory only** (never at rest on
  disk; `SecureWipe` for temp files; `zero()` on lock/exit; the seal for
  the locked display). Inherent to a manager that displays entries.
- The network never sees private material. GitHub's key endpoints serve
  **public** material only: `<user>.keys` (SSH), `<user>.gpg` (GPG).

## 10. Deferred (documented dead ends / future work)

- **YubiKit decrypt** (a custom OpenPGP message path: PKESK parsing +
  session-key unwrap in-app): the risky kind of plumbing (a spec deviation
  = an unreadable vault). OKK's decrypt is measured-good; deferred.
- **The AUT slot** (INTERNAL AUTHENTICATE) for SSH: raw RSA, no on-card
  padding → a 512-byte command → fails `0x6581` on this transport. The SIG
  slot + the bare DigestInfo is the measured-green configuration.
- **The FIDO2/PRF KEK layer** (hmac-secret): a derived symmetric KEK; the
  master secret stays on the key (non-exportable), the derived output is
  transient in app memory, normal FIDO2 auths never touch it, and a
  non-resident credential costs **zero** resident slots (fw 5.7: 100
  resident max, irrelevant if keyless). Every derivation costs a touch. It
  can only ever be an ADDITIONAL lock (recovery stays via the OpenPGP
  envelope). YubiKit's `fido` module can do it directly (no browser/local
  website needed). Parked as its own future project.
- Multiple screenlocks: the registry is ready; the UI/multi-device
  enrollment flow comes when needed.

## 11. Test plan (unit-first)

Unit (Robolectric/JVM):
1. **Registry format & multi-device**: append-only device-tagged entries;
   a second device appends; parsing yields both; the lookup filters by
   deviceId; the device name round-trips
2. **Migration is surgical**: two devices enrolled → the local un-enroll
   removes only the local entry + the local keystore key; the modes move per
   the matrix (partly implemented: `ScreenlockRoleMigrationTest`)
3. **Resolution**: "screenlock enrolled" = the registry contains *this
   device's* entry; the empty registry → YubiKey → OKK (implemented)
4. **GitHub-.keys match** (pure JVM, fetch mocked): the card's signature
   verifies the matching line, rejects the others; the fingerprint→key-id
   derivation; zero matches → the named error; the username derives from
   the remote
5. **Card-cert materialization**: `keys/signer-<subkeyid>.asc` lands with
   the full cert; re-save is append-safe
6. **OKK-init detection**: the repo has material + OKK lacks it → the
   hand-off intent carries the staged `.asc` (`application/pgp-keys`)
7. **PAT decoupling**: the load/unlock paths never touch `savePat`

On-device acceptance run (not unit-testable):
- The real card: the enrollment touch + the live `.keys` match; the OKK
  import hand-off; the end-to-end bootstrap; the second-device case; the
  surgical un-enroll against real material

## 12. Branch/merge state

- `feature/screenlock-role-split` (this plan) — cut from
  `feature/yubikit-commit-signing`, which carries the **entire** YubiKit era
  (SSH auth, commit signing). `main` is **stale** (it ends at the chip-era
  commits) — merging THIS branch into main brings everything; required
  before the v0.10.2 release.
