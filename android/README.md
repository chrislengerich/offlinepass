# offlinepass Android

Native Android client for the offlinepass vault: the entries live in an
OpenPGP-encrypted envelope, committed to a git repo whose history is
**signed ciphertext only**, synced over SSH with a **hardware security
key** (YubiKey) holding the keys.

Design: `../docs/android-app-design.md` · work plan: `../docs/work-plan.md`
· testing: `../docs/testing-plan.md` · release: `../scripts/release.sh`.

## Prerequisites (build machine)

| Tool | Used for | Notes |
|---|---|---|
| JDK 17 | everything | `compileOptions` target |
| Android SDK (platform 36) | build | `android/local.properties` → `sdk.dir` |
| adb + a device | install / instrumented runs | USB debugging on the phone |
| Node ≥ 19 | the paste-crypto contract test | needs the global WebCrypto |
| python3 (+ `cryptography`) | the wrap-vector generator | `pip install cryptography` |
| YubiKey (OpenPGP applet) | APK signing + release GPG sigs | OpenSC installed (`opensc-pkcs11.so`) |
| `gh` CLI | the GitHub release publish | authed with repo write |

Day-to-day builds need only the first three.

## Initialize the security key (OpenPGP key set)

The app needs a YubiKey whose OpenPGP applet holds a key set: the three
card slots — **SIGN** (the commit signatures), **DEC** (the vault
decrypt), **AUT** (the SSH sync auth). Use **modern ECC flavors**
(cv25519 for DEC, ed25519 or NIST-P256 for SIGN/AUT — all proven by the
app's curve sweep; RSA-2048/3072/4096 also works but is slower over USB).
Two ways to set it up:

### From Linux (gpg, the authoritative flow)

```bash
# 0. Install the tooling
sudo apt install gnupg pcscd opensc          # (Debian/Ubuntu names)

# 1. See the card (proves the reader/pcscd work)
gpg --card-status                             # expect: "Application ID ... Signature key ... none"

# 2. Set the card's key attributes to the modern ECC flavors ONCE
#    (do this BEFORE generating: the attributes define the algorithms
#    the on-card generation will use)
gpg --card-edit
  gpg/card> admin
  gpg/card> key-attr                          # pick: 1) default (ECC)
      # → "Signature key"     → ECC → cv25519/ed25519 per the prompt
      # → "Encryption key"    → ECC → cv25519
      # → "Authentication key"→ ECC → cv25519/ed25519
  gpg/card> quit

# 3. Generate the key set ON the card — the keys never exist off it.
#    Set/confirm the PINs when asked (the OpenPGP PIN for daily use,
#    the ADMIN PIN for management; the defaults are 123456 / 12345678 —
#    CHANGE THEM).
gpg --card-edit
  gpg/card> admin
  gpg/card> generate
      # backup copy off-card? → usually NO (the card is the only copy;
      # a lost card = re-key the vault)
  gpg/card> quit

# 4. Verify + make the key usable on the desktop
gpg --card-status                             # the slots now show key ids + fingerprints
gpg --list-keys                               # the card stub appears in the keyring
gpg --export > my-keys.pub                    # the public half for other machines

# 5. The SSH auth line (for the GitHub sync auth)
gpg --export-ssh-key $(gpg --card-status | awk '/Signature key/ {print $3}')
```

Notes:
- The card holds the ONLY private-key copy in this flow — back up the
  public key and record the PINs somewhere safe (a lost card means
  re-keying every vault recipient; the git history stays decryptable
  from any OTHER enrolled key/card).
- A second key set lives fine on a SECOND YubiKey for backup — repeat
  the flow, keep both cards' public keys as recipients.

### From Android (OpenKeyChain, NFC/USB)

OpenKeyChain can manage the card from the phone — useful when the
setup happens on a machine without gpg:

1. Install **OpenKeyChain** (F-Droid or Play).
2. OpenKeyChain → the **"YubiKey: use YubiKey"** navigation entry.
3. Tap the card (NFC) or plug it (USB-OTG) — the applet is detected.
4. **Set the OpenPGP PIN and the Admin PIN** (OpenKeyChain's YubiKey
   screen → the PIN management; change the factory defaults).
5. Generate the key set **on the card** (OpenKeyChain's YubiKey setup
   creates the keys directly on the token — they never exist off it).
6. The public half: OpenKeyChain → the key → **share/export the public
   key** (a file or a QR) — the desktop imports it
   (`gpg --import my-keys.pub`) and the vault's recipients take it.

Notes:
- The app's own daily flow (unlock/save/sync/sign) does NOT go through
  OpenKeyChain — it talks to the card directly (YubiKit over NFC/USB).
  OpenKeyChain is needed only for the cold paths (the first-save key
  lookup, the optional key import) and for this initialization.
- OpenKeyChain will ask for approval the first time another app uses
  the card through it (the API permission prompt).

## Build, test, install

```bash
cd android

# Debug build → install (functional testing; JIT-only, profiles ignored)
./gradlew :app:assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk

# The unit suite (Robolectric, no device needed)
./gradlew testDebugUnitTest

# The paste-crypto CONTRACT test (extension ↔ device, no device needed)
node ../extension/test/wrap_contract_test.mjs
```

The `profileable` build type (`offlinepass·p` on the launcher) is a
minified non-debuggable variant that allows profilers to attach — the
right surface for performance measurement (debug builds are JIT-only by
platform policy and never tell the truth about speed).

## Using the app (first run)

1. **Create / load the vault** — the start screen offers *New vault*
   (needs the YubiKey attached: the card's key is the first recipient),
   *Import* (a plaintext Proton Pass export), or *Load existing* (GitHub
   via the security key, a USB backup zip, or QRFT).
2. **The Get-started checklist** — attach the GitHub remote, enroll the
   security key for sync auth (one touch against your GitHub keys), and
   enroll the screenlock (commit signing + the at-rest seal).
3. **Daily flow** — unlock (the screenlock gate), browse/search;
   the secrets unseal behind a screen-lock prompt per use. **Sync** asks
   for the YubiKey touch (PIN + touch, cached 60s). Every commit is
   signed: the screenlock key by default, the YubiKey's SIG slot when
   chosen in Setup → Commit signer (the card is the default signer when
   the screenlock isn't configured).
4. **Idle lock** — after the configured idle seconds the decrypted
   session is zeroed (the staged pairings survive via the stash);
   re-unlock restores from the sealed cache.

## Release pipeline (signed artifacts)

The whole flow is scripted; the only human steps are the YubiKey touches
and running the GPG step in a terminal with a working pinentry.

```bash
# 1. Build + stage dist/vX.Y.Z/ (runs the baseline-profile verification)
scripts/release.sh build 0.10.5

# 2. Sign the release APK with the YubiKey (PKCS11; expect the touch)
cd android && ./sign.sh && cd ..

# 3. GPG-detach-sign every staged artifact (touch; run in YOUR terminal —
#    pinentry needs a TTY)
scripts/release.sh sign 0.10.5

# 4. Verify signatures + checksums, then tag/push/GitHub-release
scripts/release.sh verify 0.10.5
scripts/release.sh publish 0.10.5
```

`publish` requires a clean tree and `gh` authed with repo write; it is
resumable (completed steps are skipped; `OFFLINEPASS_RETAG=1` moves a
stale tag). Artifacts live only on the GitHub release — `dist/` is
gitignored.

The staged release APK embeds the **baseline profile** (JGit/JSch/
BouncyCastle method rules — ART pre-compiles them at install or on the
first background-dexopt pass; debug builds ignore profiles). The
packaging is verified inside `release.sh build` via
`scripts/verify-profile.sh`; regenerate the rules after a dependency
bump with `python3 scripts/gen-baseline-profile.py`.

## On-device storage & encryption

Everything lives in **app-private storage** (readable only by the app's
UID — and by `adb` only for debug builds via `run-as`).

**File structure (device):**

```
/data/data/com.offlinepass.app/                    (app-private, internal)
├── files/
│   ├── vault/
│   │   └── repo/                        # THE repo — same location in both modes
│   │       ├── .git/                    #   signed commits (the screenlock key or
│   │       │                            #   the card's SIG slot); local-only
│   │       │                            #   mode: no remotes
│   │       ├── keys/                    # who can open/sign the vault (the ledger)
│   │       │   ├── encrypt/             #   <KEYID>.pub.asc — the envelope
│   │       │   │   └── recipients.txt   #   recipients; the emails, the key ids
│   │       │   ├── sign/                #   <KEYID>.pub.asc — the commit-signing
│   │       │   │                        #   certs (the card-attested screenlock key)
│   │       │   ├── auth/                # authorized_keys (the SSH sync lines)
│   │       │   └── meta/devices.json    #   the device name → the public key (+ the cert)
│   │       └── state/
│   │           └── 10.gpg               # THE VAULT — OpenPGP ciphertext
│   ├── sealed/
│   │   └── sealed.json                  # THE SEALED CACHE — the per-item secrets
│   │                                    #   encrypted to the screenlock key
│   └── cache/                           # the transient decrypt buffers (wiped)
├── shared_prefs/
│   ├── vault_config.xml                 # the remote URL (absent in local-only),
│   │                                    #   the recipient emails/ids, the deviceId
│   └── offlinepass_secret_keys.xml      # the PAT: the AES-256-GCM blob wrapped by
│                                        #   AndroidKeyStore (TEE-held)
└── (sdcard) Android/data/com.offlinepass.app/files/
    ├── storage-pat.txt                  # the optional PAT prefill (remove after setup)
    └── id-offlinepass.pub               # the device's Keystore SSH public key
```

Local-only mode is the **same git repo** without a `remote`; configuring
a remote later connects it — the history merges via the sync flow;
nothing is wiped.

**The backing stores and what guards each secret:**

| Store | Contents | Guard |
|---|---|---|
| Vault file (`state/10.gpg`) | The full `Envelope` JSON: the items (all fields), the tombstones, the device registry, the unknown fields. | OpenPGP ciphertext — the AES-256 SEIPD v1 + the MDC, encrypted to the **recipients** (the card's DEC key first). The decrypt = the card (the PIN + the touch), in-process via YubiKit + BouncyCastle; no OpenKeyChain in the path. |
| Sealed cache (`sealed/sealed.json`) | Per item: the **plaintext** identity fields (the name, the username, the email, the URLs, the modifyTime — the search/list backing) + the **sealed** `iv`/`ct` of the secrets (the password, the note, the TOTP URI), bound by the per-item AAD; plus the envelope's public meta (the rev, the tombstones, the devices). | AES-256-GCM under the AndroidKeyStore key `offlinepass-seal-aes` — **screenlock-gated** (the 60s validity window). The cache binds to the current vault file's sha256 — a stale cache falls back to the card unlock, which re-seals. |
| Git history | Signed ciphertext commits only. | The rollback/audit without exposing content. |
| SharedPreferences | The config: the remote, the recipient emails/ids, the signing mode, the screenlock toggle. | Non-secret. |
| SecretStore (the prefs) | The GitHub PAT. | An AES-256-GCM blob wrapped by the TEE-held Keystore key. |
| AndroidKeyStore | The seal AES key (`offlinepass-seal-aes`), the screenlock EC signing key. | TEE-held; the auth gating per the above. |

**The stub session model (the screenlock enrolled):**

The item secrets exist in exactly two places at rest — the **vault file**
(security-key-encrypted) and the **sealed cache** (screenlock-encrypted,
per-item). The in-memory session holds **stubs**: the name, the username,
the email, and the URLs stay plaintext (the search and the list are fully
functional), while the password/note/TOTP are absent from memory. Each
path that touches secrets unseals transiently:

- **The item detail** — a screenlock interaction per item, then a
  targeted single-item unseal from the cache.
- **The save/sync** — one screen-lock press opens the keystore window;
  the batch unseal rehydrates all items transiently, the merge runs, the
  vault re-encrypts, and the cache re-seals against the new file. The
  stubs can never reach the vault file (an invariant with a dedicated
  test).
- **The autofill** — the targeted single-item unseal, behind the
  screenlock.
- **Without the screenlock enrolled** — the legacy behavior: the
  unlocked session holds the full items in memory (no gate is possible).

The URLs/usernames/names are intentionally plaintext in the sealed cache:
the search and the locked-mode manifest work without any authentication,
and only the secrets are protected.

**Encryption states, per artifact:**

| Artifact | State |
|---|---|
| Vault file (`10.gpg`) | OpenPGP ciphertext — never plaintext on disk. The decrypt/encrypt = in-process (the YubiKit card ops + the BouncyCastle framing); OpenKeyChain only for the cold paths (the first-save key lookup/fetch, the USB restore). |
| Sealed cache | The per-item AES-256-GCM ciphertexts for the secrets; the identity fields plaintext by design. |
| Git history | Signed ciphertext commits only — the rollback/audit without exposing content. |
| PAT | AES-256-GCM blob; the wrapping key lives in the hardware Keystore. A stolen device + pulled files can't unwrap it. |
| Decrypted entries | **RAM only**, and — with the screenlock enrolled — the secrets are zeroed from memory after the seal; each access re-unseals transiently. |
| QR exports | Plaintext by explicit user choice (the screen = the trust boundary); generated transiently, never persisted. |

**What a stolen device yields:** the vault ciphertext (the card-gated),
the sealed cache (screenlock-gated), and a wrapped PAT token. No
plaintext secrets, no keys, no decryptable state — and the two remaining
guards are independent: the card decrypts the repo on any device, the
screenlock decrypts the cache only on this one.

## Test layout

| Layer | Where | Needs |
|---|---|---|
| L1 unit (229 tests) | `app/src/test` | nothing (Robolectric where needed) |
| Paste crypto contract | `extension/test/wrap_contract_test.mjs` | Node ≥ 19 |
| Profile packaging guard | `scripts/verify-profile.sh` | the built release APK |
| L2/L3 instrumented | `app/src/androidTest` (planned — see `../docs/work-plan.md` T6) | device + OpenKeyChain/YubiKey/GitHub |

Notable L1 suites: `IdleLockStagedStateSweepTest` (the zero→unlock loop
must preserve every staged state — it caught the stash-clobber and the
lost-unpair bugs), `SignerResolutionMatrixTest` (the signer default
chain), `VaultGitClientTest` (the ahead/behind divergence accounting),
`PasteDeviceStagingTest` + `DeviceWrapTest` (the paste pairings),
`JGitSignProbeTest` (the pluggable-signer embedding).
