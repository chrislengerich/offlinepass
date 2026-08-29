# linuxpass

Terminal UI companion for the [QR Autofill](../qrautofill) Android app.

Search, display, and manage Proton Pass login entries. Display any entry as a
QR code in the terminal, then scan it with the Android app to autofill
username/password in any app on the phone.

```
 ┌─ linuxpass ──────────────────────────────┐
 │   Search                                  │
 │   Add entry                               │
 │   Show git repo location                  │
 │   Quit                                    │
 └──────────────────────────────────────────┘
        ↓ search "git"
 ┌─ Results (2) ────────────────────────────┐
 │   GitHub                      ko          │
 │ > GitLab                      ko@work.com │
 └──────────────────────────────────────────┘
        ↓ select, Show credentials
  Name:     AWS Console
  Email:    ko.admin@company.com
  Password: AWS-r00t-key!2024
  TOTP:     890059
  Refresh:  ██████████░░░░░░░░░░ 16s
        ↓ or select Display QR code
  ██████    ████  ██  ██    ██████
  ██  ██ ▄▄▄▄▄ █ █▀▄█▄█ ▄▄▄▄▄ ██  ██
  ██  ██ █   █ █  ▀▄ █ █   █ ██  ██
  ...
      Scan with QR Autofill app
```

## Install

### Prerequisites

- Python 3.12+
- `qrencode` — terminal QR rendering
- `gpg` — encrypted storage (production only)
- `git` — auto-commit on writes (optional)

### One-time setup

```bash
# 1. Clone the repo
git clone <repo-url> ~/linuxpass
cd ~/linuxpass

# 2. Install system dependencies
sudo apt install qrencode gpg

# 3. (Optional) Set up encrypted storage with git sync
mkdir -p ~/product/state
cd ~/product/state
git init
cd ~/linuxpass

# 4. Run in test mode (unencrypted, no GPG needed)
python3 linuxpass.py
```

### Production configuration

```bash
LINUXPASS_USE_GPG=1 \
LINUXPASS_GPG_RECIPIENT="your-key-id" \
LINUXPASS_FILE="~/product/state/10.gpg" \
LINUXPASS_GIT_DIR="~/product/state" \
python3 linuxpass.py
```

Or export them in your shell profile:

```bash
export LINUXPASS_USE_GPG=1
export LINUXPASS_GPG_RECIPIENT="your-key-id"
export LINUXPASS_FILE="~/product/state/10.gpg"
export LINUXPASS_GIT_DIR="~/product/state"
```

## How it works

1. The store file is a Proton Pass JSON export (full vault envelope format).
   In test mode it's plaintext JSON; in production it's GPG-encrypted.
2. On startup the file is decrypted and parsed into `ProtonItem` objects,
   sorted alphabetically by display name.
3. Search filters entries by name, username, email, URL, or note (all words
   must match).
4. Selecting an entry opens the detail view with actions.
5. "Display QR code" renders the entry as a single Proton Pass JSON item
   in the terminal via `qrencode`. This is the exact format the Android
   app's `ProtonPassParser` expects.
6. Write operations (add entry, update password, enroll TOTP) modify the
   in-memory list, re-encrypt the file, and commit to git.

## Features

### Main menu

- **Search** — keyword search across all fields; select an entry to open
  the detail view
- **Add entry** — choose identity type (Username or Email alias), enter URL,
  password is auto-generated (24 chars, mixed case + digits + symbols)
- **Show git repo location** — display repo path, git status, and data file
- **Quit**

### Entry detail view

- **Display QR code** — terminal QR rendering of the Proton Pass item JSON
- **Show credentials** — display username/email and password; if TOTP is
  enrolled, shows a live-refreshing TOTP code with countdown bar
- **Update password** — generates a new password; `Enter` to confirm,
  `Esc` to cancel
- **Enroll TOTP** — enter a base32 secret or `otpauth://` URI to enable
  TOTP code generation for this entry
- **Back** — return to search results

### Entry display name

Entries don't require a name. The display name is derived in priority order:
1. Explicit name (if set)
2. URL domain (e.g. `https://gitlab.com` → `gitlab.com`)
3. Username
4. Email
5. `(unnamed)`

## QR code format

The QR encodes one item from a Proton Pass JSON export — the object you'd find
inside `vaults.<id>.items[]`. Minimal example:

```json
{"itemId":"...","shareId":"local","data":{"type":"login","metadata":{"name":"GitHub","itemUuid":"..."},"content":{"itemEmail":"","itemUsername":"ko","password":"secret","urls":["https://github.com"],"totpUri":"","passkeys":[]}},"state":1,...}
```

The Android app parses `data.content.itemUsername` (falling back to
`itemEmail`) and `data.content.password`.

Keep the payload small — large QR codes are harder to scan. The minimal item
(~100 chars) produces a 21x21 QR that scans in under a second.

## Keybindings

| Key | Action |
|-----|--------|
| `j` / `↓` | move down |
| `k` / `↑` | move up |
| `Enter` | select / confirm |
| `q` / `Esc` | back / cancel |
| `Esc` | cancel password update |
| any key | dismiss message / exit credentials view |

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
- `git` — auto-commit on writes (optional)

## Project structure

```
linuxpass/
├── linuxpass.py     # curses TUI (search, detail view, QR, write ops, TOTP)
├── passlib.py       # ProtonItem model, GPG storage, git sync, password/TOTP gen
├── test_data.json   # 5 sample entries for testing
└── test_passlib.py  # unit tests (32 tests)
```

## Testing

```bash
# Unit tests (no terminal needed)
python3 test_passlib.py

# Interactive TUI test
python3 linuxpass.py
# → Search "git" → Enter → select GitHub → Show credentials
# → or Display QR code → scan with phone
```

Tests cover item parsing, search matching, password generation, TOTP
generation (verified against RFC 6238 test vectors), display name derivation,
and file round-trips.
