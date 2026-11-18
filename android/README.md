# offlinepass Android

Native Android client for the offlinepass vault (design:
`../docs/android-app-design.md`, work plan: `../docs/work-plan.md`).

## Status — Phase 0 (spikes)

| Spike | What | Status |
|---|---|---|
| S1 | OpenKeyChain round-trip vs the real vault | **integration proven + end-to-end UI pass** (software-key; real-applet run pending) |
| S2 | Sign-action probe | **done** — OpenKeyChain signs PGP-only → git auth via PAT; Keystore SSH identity committed for later |
| S3 | JGit transport | **PASS** — clone/fetch/commit/push over HTTPS+PAT; now the production transport in-app |
| S4 | Autofill | **PASS** — service enabled, datasets offered, form filled |
| S5 | Vendored qrft generator interop | **PASS** — payload prefilled, sender auto-starts in WebView |
| S6 | NFC / touch UX timing | pending (needs the real YubiKey applet flow) |

## TODOs

- [ ] **Real-applet-keys pass** — import `real-keys.pub` into the phone's OpenKeyChain, pair the jiji key (USB OTG), run unlock/CRUD against the real 192 KB vault; verify desktop `gpg --list-packets` ↔ recipients-ledger parity (T-X-01/03)
- [ ] **USB restore drill on a diverged snapshot** — restore a stale rev over a newer local state; confirm the union-merge conflict path
- [ ] **Sign-key picker UX polish** — dedicated signing key (GET_SIGN_KEY_ID) is wired; document/verify rotation (design decision log #15)
- [ ] **Keystore-SSH / CCID git auth upgrade** — per-device deploy keys (built: `SshKeyManager`) or in-app CCID `PSO:SIGN`; PAT/HTTPS ships for now
- [ ] **PAT hardening** — rotation policy/expiry reminders; GrapheneOS network-toggle note
- [ ] **QRFT variants** — encrypted single-entry export (vs plaintext); whole-vault transfer (deferred: bandwidth)

## Next up (later)

- [ ] **E2E test to the Linux password manager** — qrft password transfer to a low-dependency computer: phone → QRFT export → qrft.org scanner on a bare machine → entry file → decrypt/open with the desktop flow; exercise the whole chain offline.
| S4 | Autofill shell | not started |
| S5 | Vendored qrft generator interop | not started |
| S6 | NFC / touch UX timing | pending (needs the real YubiKey applet flow) |

## TODOs

- [ ] **Real-applet-keys pass** — import `real-keys.pub` into the phone's OpenKeyChain, pair the jiji key (USB OTG), run unlock/CRUD against the real 192 KB vault; verify desktop `gpg --list-packets` ↔ recipients-ledger parity (T-X-01/03)
- [ ] **USB restore drill on a diverged snapshot** — restore a stale rev over a newer local state; confirm the union-merge conflict path
- [ ] **Sign-key picker UX polish** — dedicated signing key (GET_SIGN_KEY_ID) is wired; document/verify rotation (design decision log #15)
- [ ] **Keystore-SSH / CCID git auth upgrade** — per-device deploy keys (built: `SshKeyManager`) or in-app CCID `PSO:SIGN`; PAT/HTTPS ships for now
- [ ] **PAT hardening** — rotation policy/expiry reminders; GrapheneOS network-toggle note
- [ ] **QRFT variants** — encrypted single-entry export (vs plaintext); whole-vault transfer (deferred: bandwidth)

## Next up (later)

- [ ] **E2E test to the Linux password manager** — qrft password transfer to a low-dependency computer: phone → QRFT export → qrft.org scanner on a bare machine → entry file → decrypt/open with the desktop flow; exercise the whole chain offline.

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
│   │       │   ├── auth/                #   authorized_keys (the SSH sync lines)
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

Local-only mode is the **same git repo** without a `remote`; configuring a
remote later connects it (`git remote add origin`) — the history merges via
the sync flow; nothing is wiped.

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
functional), while the password/note/TOTP are absent from memory. Each path
that touches secrets unseals transiently:

- **The item detail** — a screenlock interaction per item, then a targeted
  single-item unseal from the cache.
- **The save/sync** — one screen-lock press opens the keystore window; the
  batch unseal rehydrates all items transiently, the merge runs, the vault
  re-encrypts, and the cache re-seals against the new file. The stubs can
  never reach the vault file (an invariant with a dedicated test).
- **The autofill** — the targeted single-item unseal, behind the screenlock.
- **Without the screenlock enrolled** — the legacy behavior: the unlocked
  session holds the full items in memory (no gate is possible).

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

**What a stolen device yields:** the vault ciphertext (the card-gated), the
sealed cache (screenlock-gated), and a wrapped PAT token. No plaintext
secrets, no keys, no decryptable state — and the two remaining guards are
independent: the card decrypts the repo on any device, the screenlock
decrypts the cache only on this one.

## Running spike S1 (hardware-in-the-loop)

Prereqs: OpenKeychain installed, your YubiKey paired in it (applet keys
imported/detected), the app approved inside OpenKeychain on first use.

1. Open the app → **Open Spike S1**.
2. **Pick vault file** → choose your `10.gpg` (from the vault repo working
   tree, or via Files). Key touch + PIN → expect
   `OK: <N> bytes, signature=…`.
3. Enter the OpenKeychain identity email that matches the GPG key you
   encrypt with on desktop → **Re-encrypt**.
4. **Share** the re-encrypted file to the desktop, then decrypt it there:
   ```bash
   gpg --decrypt re-encrypted.gpg > /tmp/roundtrip.json
   ```
   Compare against a plaintext decrypt of the original (`gpg --decrypt
   10.gpg`). Record the result in `docs/testing-plan.md` (T-D-01..03,
   T-X-01).

Repeat step 2 with the key on USB (not NFC) for T-D-02.

## Notes

- `crypto/OpenPgpClient.kt` is lifted from offlinecam (Apache-2.0 protocol
  surface; docs reworded for the vault context).
- The qrft generator pages get vendored under
  `app/src/main/assets/qrft/` when spike S5 starts.
