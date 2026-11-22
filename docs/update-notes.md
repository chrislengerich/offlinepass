# Running update notes

The running log of user-facing changes — one entry per landed feature,
newest section first. When a release is cut, the top (unreleased) section
is folded into the release notes (`scripts/release.sh` writes
`RELEASE_NOTES.md` at build stage) and any standing README claims are
updated; the entries then move under that release's version heading here.

## Unreleased

### Android

- **The autofill generate chips** — the sheet's two generate options,
  each followed by the immediate **"Save this login to the vault?"**
  card (the silent tray notification and its POST_NOTIFICATIONS
  permission are gone). The platform's own save prompt still covers
  user-typed changes: typing a NEW password on a site updates the SAME
  saved item in place (matched by site + username — the note, TOTP and
  other fields survive); a different username = a second entry.
  - **⚡ Generate a strong password** — offered on forms with no
    matching vault entry (the registration case); fills the generated
    password ONLY, and the email already typed on the site's form rides
    into the save card and the saved item.
  - **✨ Generate SimpleLogin alias + password** — offered on any form
    with a username/email field, with the vault unlocked OR sealed (the
    common case: the sealed sheet finds the linked SimpleLogin entry in
    the manifest and the device-lock gate authorizes the api-key
    reveal). One tap: the gate → a real **passmail.net** alias + the
    generated password → both filled. SimpleLogin unreachable = the
    password-only fill, never a dead end.
- **Generated password default** — 10 characters over letters and
  digits (was 24 with symbols).
- **SimpleLogin linked accounts** — Setup → Linked accounts links the
  SimpleLogin account by pasting an API key from the dashboard
  (numbered a/b/c instructions with a direct link to the API-keys
  page). The key is stored as a regular vault item ("SimpleLogin API",
  url `app.simplelogin.io`) — card-encrypted and synced like anything
  else. **Relink** replaces the key in place (the same item uuid, so an
  old key cannot resurrect through the merge); the linked state shows
  the account email and the alias domains.
- **SimpleLogin aliases on Add-entry** — the email field is always
  present; "✨ SimpleLogin alias" creates a real alias on the linked
  account and writes it into the email field, saved with the entry.
- **SimpleLogin status on the item page** — for an item whose email is
  an alias, "Check SimpleLogin status" reveals its enabled/disabled
  state and arms the enable/disable toggle. Items carry no SimpleLogin
  state and make no requests by default.
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

### Extension

- **Fill without a URL match** — "Fill in tab" no longer refuses when
  no entry URL matches the captured tab: the first entry fills anyway
  and the window stays open with a warning banner naming the origin it
  filled into (Reveal/Copy/TOTP keep working). The matched-fill path is
  unchanged.

### Repository

- **Ed25519 + EC card crypto** — commit signing works on Ed25519
  (alg 22, the card PureEdDSAs the raw SHA-256 digest) alongside
  RSA/ECDSA; the vault decrypt covers ECDH card keys; BouncyCastle
  1.79 → 1.87. The OpenPGP v6/AEAD and the post-quantum algorithms
  remain documented blockers.
- **CI** — GitHub Actions runs the Linux, extension, and Android test
  jobs on every push/PR, with the test reports uploaded on failure and
  the baseline-profile verification guarding the release build.
- **Layout & licensing** — the Linux client lives under `linux/`; the
  GPLv3 LICENSE and CONTRIBUTING.md added; the READMEs split per
  component.
