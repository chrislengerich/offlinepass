# Human test plan — phases ③ (git sync) and ④ (QRFT) — run on the Chromebook

Everything runs from the vendored files (the repo-local libraries); the
only network = the GitHub sync itself. The extension = Load unpacked
(`chrome://extensions` → the developer mode → the `extension/` dir).

## 0. The setup (once)

- [ ] The YubiKey plugged into the Chromebook's USB port
- [ ] The token ready: a GitHub fine-grained PAT with the read/write
      Contents on the vault repo (the Settings page has the field)
- [ ] A phone with the vault (the source of the QRFT + the backup file)

## 1. Phase ③ — the git sync

### 1a. The clone
1. Open the extension's settings → the sync: paste the repo's HTTPS URL
   (`https://github.com/<user>/<repo>.git`) + the token
2. Tap **Clone**
- **Expect**: "Cloned (rev N)" — the Setup's sync line shows the
  "in sync with origin/main" state; the entries count nonzero

### 1b. The fetch (the phone pushed meanwhile)
1. On the phone: edit/save an entry → sync (the phone pushes)
2. In the extension: tap **Fetch**
- **Expect**: "Fetched (rev M)" with M > N; the search list shows the
  phone's edit

### 1c. The push (the extension edited)
1. In the extension: edit an entry's note → **Save** (the local commit
   lands first) → **Sync**
- **Expect**: "Pushed (rev N+1)"; the Setup's line = in-sync
- **Verify**: on the phone, sync → the extension's edit appears

### 1d. The divergence (the both-sides edits)
1. The phone edits entry A + pushes; the extension (without fetching)
   edits entry B → **Sync**
- **Expect**: the merge completes ("Merged + pushed") — the A and the B
  edits both survive; the rev > both parents
- **Verify**: the phone syncs → both edits present

### 1e. The wrong token
1. Break the token in the settings → **Sync**
- **Expect**: the actionable auth error, the local state intact, no
  retry storm

## 2. Phase ④ — the QRFT

### 2a. The extension → the phone (the export)
1. In the extension: open an entry → **Export as QRFT** → the QR
   displays
2. On the phone: **Import from QRFT (scan)** → scan
- **Expect**: the phone imports the entry (the dedupe rule: the same
  uuid = the local kept)

### 2b. The phone → the extension (the import)
1. On the phone: an entry → **Export as QRFT** → the QR displays
2. In the extension: **Import from camera** → grant the camera → hold
   the phone steady (~15–30 cm, the QR fills ~60% of the frame)
- **Expect**: the frame counter ticks up → "Imported"; the entry in
  the extension's list

### 2c. The multi-frame (the big payload)
1. The phone: export an entry with a LONG note (~1–2 KB) → the QRFT
   stream = the many frames
2. The extension: the camera import
- **Expect**: the frames decode sequentially; the reassembled payload
  parses; the entry lands

### 2d. The encrypted paste (the paired keys)
1. The phone: export with **Encrypt to paired paste keys** (the
   extension's pairing = the QR scanned on the phone first)
2. The extension: the import → the decrypt with the paired WebCrypto
   key
- **Expect**: the entry opens (the decryption needs no card — the
  paired-key model); an unpaired second extension CANNOT open it

## 3. The regression sweep (after any change)
- [ ] The card decrypt (the phase 2 probe: the vault file → the card →
      the entries)
- [ ] The idle-lock/the at-rest behavior unchanged (the at-rest = the
      WebAuthn-PRF: not yet implemented — the memory-only session dies
      with the tab; the re-open = the card again)
- [ ] The autofill still works for the received pastes
- [ ] The matched auto-fill leaves the scan window OPEN with the entry
      cards (Reveal/Copy/TOTP still work); the passwords zero when the
      window is closed (reopen → Reveal shows "No password" only if the
      window was actually destroyed, not merely refocused)
- [ ] On a page with a site-header search box the username/email lands in
      the login field, NEVER the search input (type="search", a
      name/id/placeholder like "search"/"query"/"filter", or a
      form[role="search"])
- [ ] A username-only entry (no password on the page) still fills the
      username field and reports success

## 4. The failure-recovery drill
- [ ] The tab closed mid-sync → re-open: the local commit intact; the
      sync completes
- [ ] The card unplugged mid-decrypt → the clean error; the retry works
      after the replug
