# linuxpass

TUI companion for the [QR Autofill](../qrautofill) Android app. Search, display,
and manage Proton Pass login entries, with QR code rendering for scanning by the
Android app.

## Usage

```bash
# Test mode (unencrypted JSON, no GPG)
python3 linuxpass.py

# Production (GPG-encrypted file with git sync)
LINUXPASS_USE_GPG=1 \
LINUXPASS_GPG_RECIPIENT="your@gpg.key" \
LINUXPASS_FILE="~/product/state/10.gpg" \
LINUXPASS_GIT_DIR="~/product/state" \
python3 linuxpass.py
```

## Features

**Step 1 (read-only):**
- Search entries by website name, username, email, or URL
- Select from filtered results
- Display QR code (Proton Pass JSON item) in terminal
- Show/copy password

**Step 2 (write):**
- Add new entry with auto-generated password
- Add new email entry (SimpleLogin stub)
- Update entry password (auto-generated)
- Changes saved to GPG-encrypted file and committed to git

## Keybindings

- `j`/`↓` — move down
- `k`/`↑` — move up
- `Enter` — select
- `q`/`Esc` — back / cancel

## Dependencies

- Python 3.12+
- `qrencode` (for QR rendering)
- `gpg` (for encrypted storage)
- `xclip` or `wl-copy` (optional, for clipboard)
