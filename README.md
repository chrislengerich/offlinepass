# linuxpass

Terminal UI companion for the [QR Autofill](../qrautofill) Android app.

Search, display, and manage Proton Pass login entries. Display any entry as a
QR code in the terminal, then scan it with the Android app to autofill
username/password in any app on the phone.

```
 ┌─ linuxpass ──────────────────────────────┐
 │   Search                                  │
 │ > Add entry                               │
 │   Add email (SimpleLogin)                 │
 │   Update password                         │
 │   Quit                                    │
 └──────────────────────────────────────────┘
        ↓ search "git"
 ┌─ Results (2) ────────────────────────────┐
 │   GitHub                      ko          │
 │ > GitLab                      ko@work.com │
 └──────────────────────────────────────────┘
        ↓ select, display QR
 ██████    ████  ██  ██    ██████
 ██  ██ ▄▄▄▄▄ █ █▀▄█▄█ ▄▄▄▄▄ ██  ██
 ██  ██ █   █ █  ▀▄ █ █   █ ██  ██
 ...
     Scan with QR Autofill app
```

## Quick start

```bash
# Test mode — unencrypted JSON, no GPG required
python3 linuxpass.py

# Production — GPG-encrypted file with git sync
LINUXPASS_USE_GPG=1 \
LINUXPASS_GPG_RECIPIENT="your-key-id" \
LINUXPASS_FILE="~/product/state/10.gpg" \
LINUXPASS_GIT_DIR="~/product/state" \
python3 linuxpass.py
```

## How it works

1. The store file is a Proton Pass JSON export (full vault envelope format).
   In test mode it's plaintext JSON; in production it's GPG-encrypted.
2. On startup the file is decrypted and parsed into `ProtonItem` objects,
   sorted alphabetically by name.
3. Search filters entries by name, username, email, URL, or note (all words
   must match).
4. Selecting an entry shows its details and an action menu.
5. "Display QR code" renders the entry as a single Proton Pass JSON item
   (the `items[]` object with `data.content`) in the terminal via `qrencode`.
   This is the exact format the Android app's `ProtonPassParser` expects.
6. Write operations (add entry, add email, update password) modify the
   in-memory list, re-encrypt the file, and commit to git.

## Features

### Step 1 — read-only

- **Search** — fuzzy keyword search across all fields
- **Select** — navigate filtered results with vim-style keys
- **Display QR code** — terminal QR rendering of the Proton Pass item JSON
- **Show password** — display in plain text
- **Copy password** — copy to clipboard via `xclip` or `wl-copy`

### Step 2 — write

- **Add entry** — enter website name, URL, username or email; password is
  auto-generated (24 chars, mixed case + digits + symbols)
- **Add email** — generate a SimpleLogin-style alias (stub — not actually
  registered with SimpleLogin) and create an entry with auto-generated password
- **Update password** — search for an entry, confirm, and replace its password
  with a newly generated one

## QR code format

The QR encodes one item from a Proton Pass JSON export — the object you'd find
inside `vaults.<id>.items[]`. Minimal example:

```json
{"itemId":"...","shareId":"local","data":{"type":"login","metadata":{"name":"GitHub","itemUuid":"..."},"content":{"itemEmail":"","itemUsername":"ko","password":"secret","urls":["https://github.com"],"totpUri":"","passkeys":[]}},"state":1,...}
```

The Android app parses `data.content.itemUsername` (falling back to
`itemEmail`) and `data.content.password`.

Keep the payload small — large QR codes are harder to scan. The minimal item
(~100 chars) produces a 21×21 QR that scans in under a second.

## Keybindings

| Key | Action |
|-----|--------|
| `j` / `↓` | move down |
| `k` / `↑` | move up |
| `Enter` | select |
| `q` / `Esc` | back / cancel |
| any key | dismiss message / QR |

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `LINUXPASS_FILE` | `~/linuxpass/test_data.json` | Path to store file |
| `LINUXPASS_USE_GPG` | `0` | Set to `1` for GPG encryption |
| `LINUXPASS_GPG_RECIPIENT` | — | GPG key ID or email for encryption |
| `LINUXPASS_GIT_DIR` | directory of `LINUXPASS_FILE` | Git repo root for auto-commit |

## Dependencies

- Python 3.12+
- `qrencode` — QR code rendering (`apt install qrencode`)
- `gpg` — encrypted storage (`apt install gpg`)
- `xclip` or `wl-copy` — optional, for clipboard copy

## Project structure

```
linuxpass/
├── linuxpass.py     # curses TUI (search, select, QR, write ops)
├── passlib.py       # ProtonItem model, GPG storage, git sync, password gen
├── test_data.json   # 5 sample entries for testing
└── test_passlib.py  # unit tests
```

## Testing

```bash
# Unit tests (no terminal needed)
python3 test_passlib.py

# Interactive TUI test
python3 linuxpass.py
# → Search "git" → Enter → select GitHub → Display QR code → scan with phone
```

See `test_passlib.py` for automated coverage of the library layer: item
parsing, search matching, password generation, and file round-trips.
