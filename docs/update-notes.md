# Running update notes

The running log of user-facing changes — one entry per landed feature,
newest section first. When a release is cut, the top (unreleased) section
is folded into the release notes (`scripts/release.sh` writes
`RELEASE_NOTES.md` at build stage) and any standing README claims are
updated; the entries then move under that release's version heading here.

## Unreleased

### Android

- **Google Passwords import/export** — the second foreign format beside
  the Proton export. Setup → Import gains **"From Google CSV"**: pick a
  Google Password Manager export (the Android or Chrome CSV), the entries
  land as normal vault items through the same save path. Setup → Export
  gains **"To Google Passwords (CSV)"**: the vault writes the exact
  four-column CSV Chrome's password import accepts back.
  - The Google CSV carries ONLY name / url / username / password — the
    notes, the TOTP, the extra URLs and the passkeys are dropped in BOTH
    directions (the format has no columns for them). The export flow
    says so up front; delete the plaintext file once imported.
  - Import handles the real-shaped exports: quoted fields (passwords
    with commas/quotes/newlines), the BOM, case-insensitive headers,
    app rows without a URL.
