User flows:

Initial setup:

New vault (storage choices):
 1. Github info.
 2. USB 

Load from existing (choices):
 1. Github info + auth security key + encrypt security key.
 2. USB.
 3. QRTF import.

Setup tab (persistent): 
 1. Sync with remote.
 2. Github info + auth and encrypt security key identity. 
 3. Enroll security key.
 4. Setup autofill.
 5. Export vault (QRFT export).
 6. Encrypt individual items while in use (experimental toggle).

Password search (main page):
 1. Type in, get a list of plaintext matches (rows, similar to linux desktop).
 2. Password options (same as linux desktop) 

Password search — sealed launch (item encryption ON, experimental):
 1. Run: the list + search work immediately, backed by the device-local
    sealed cache's manifest (names, usernames, emails, URLs at rest —
    app-private, never synced; passwords/notes/TOTP stay sealed under a
    screen-lock keystore key).
 2. Click an entry: screen-lock prompt → that entry unseals into a
    read-mostly detail. Edit → Save runs the promotion (unseal-all,
    silent while the auth window is open) + the normal save, signed via
    the existing screen-lock signer. The GPG security key is only needed
    when the seal is stale (first run / after a remote pull) or to
    refresh it — "Use security key" stays available.
 3. "Unlock all" promotes without opening an entry; Add/Setup promote
    the same way.
 4. Toggle OFF = legacy behavior (GPG unlock for everything); the cache
    is wiped.

Autofill interaction:
 1. Matches on content (webpage or Android app context).
 2. Dropdown list of entries.
 3. Select one, android-autofill API.
