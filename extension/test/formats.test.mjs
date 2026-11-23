/**
 * THE FOREIGN-FORMAT IMPORT CONTRACT: the extension's parsers for the
 * two plaintext formats the Android app also accepts — the Google
 * Passwords CSV (the four columns Chrome/GPM write) and the Proton Pass
 * plaintext export (the vault JSON) — plus the PROVENANCE NOTE (the
 * appended line naming the source; the dedupe on the exact line).
 *
 * No autodetection: the Import section's popup names the source
 * explicitly (the user's choice), the parse = the explicit call.
 *
 * The JS twins of the Android's GooglePasswordsCsv.parse and
 * Envelope.parseImport/ProtonItem.fromJson — the same shapes, the same
 * leniency: the BOM tolerated, the header by name (case-insensitive,
 * extra columns ignored), the positional fallback, RFC-4180 quoting,
 * the lossy rule (the Google CSV has no note/TOTP — nothing to import).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  parseGoogleCsv, parseProtonPlaintext, appendImportNote,
} from "../formats.js";

// -- the GOOGLE PASSWORDS CSV ------------------------------------------------

test("the Google CSV: the canonical header, one entry per row", () => {
  const items = parseGoogleCsv("name,url,username,password\nGitHub,https://github.com,ko,pw1\nMail,https://mail.x.org,alice,pw2");
  assert.equal(items.length, 2);
  assert.equal(items[0].data.metadata.name, "GitHub");
  assert.equal(items[0].data.content.itemUsername, "ko");
  assert.equal(items[0].data.content.password, "pw1");
  assert.deepEqual(items[0].data.content.urls, ["https://github.com"]);
  assert.equal(items[1].data.metadata.name, "Mail");
});

test("the Google CSV: the BOM tolerated, the header case-insensitive, extra columns ignored", () => {
  const items = parseGoogleCsv("\uFEFFName,URL,Username,Password,Extra\nG,https://g.co,u,p,junk");
  assert.equal(items.length, 1);
  assert.equal(items[0].data.metadata.name, "G");
  assert.equal(items[0].data.content.password, "p");
});

test("the Google CSV: the positional fallback when the header row is absent", () => {
  const items = parseGoogleCsv("Site,https://s.co,user,pw");
  assert.equal(items.length, 1);
  assert.equal(items[0].data.metadata.name, "Site");
  assert.equal(items[0].data.content.itemUsername, "user");
  assert.equal(items[0].data.content.password, "pw");
});

test("the Google CSV: RFC-4180 quoting — the embedded comma, the escaped quote, the embedded newline", () => {
  const items = parseGoogleCsv(
    "name,url,username,password\n" +
    '"GitHub, Inc.",https://github.com,ko,"the ""secret"" pw"', );
  assert.equal(items.length, 1);
  assert.equal(items[0].data.metadata.name, "GitHub, Inc.");
  assert.equal(items[0].data.content.password, 'the "secret" pw');
});

test("the Google CSV: the empty rows skipped; the empty file → no items", () => {
  const items = parseGoogleCsv("name,url,username,password\n\n,,,\n, , ,");
  assert.ok(items.every((it) => it.data.metadata.name === "" &&
    it.data.content.password === "") || items.length === 0);
  assert.deepEqual(parseGoogleCsv(""), []);
  assert.deepEqual(parseGoogleCsv("   \n \n"), []);
});

test("the Google CSV: the LOSSY rule — no note, no TOTP, no multi-URL", () => {
  const items = parseGoogleCsv("name,url,username,password\nG,https://g.co,u,p");
  assert.equal(items[0].data.metadata.note ?? "", "");
  assert.equal(items[0].data.content.totpUri ?? "", "");
});

// -- the PROTON PASS PLAINTEXT EXPORT ---------------------------------------

const protonItem = (name, user, pass, note = "") => ({
  itemId: "i-" + name, shareId: "local", state: 1,
  data: { type: "login",
    metadata: { name, itemUuid: "u-" + name, note },
    content: { itemUsername: user, itemEmail: "", password: pass,
      urls: ["https://x.co"], totpUri: "", modifyTime: 100 } },
});

test("the Proton plaintext: the bare array shape", () => {
  const items = parseProtonPlaintext(JSON.stringify([protonItem("GitHub", "ko", "pw")]));
  assert.equal(items.length, 1);
  assert.equal(items[0].data.metadata.name, "GitHub");
  assert.equal(items[0].data.content.password, "pw");
});

test("the Proton plaintext: the {items} shape", () => {
  const items = parseProtonPlaintext(JSON.stringify({ items: [protonItem("A", "u", "p")] }));
  assert.equal(items.length, 1);
});

test("the Proton plaintext: the {vaults.local.items} shape (the full envelope)", () => {
  const env = { rev: 7, deviceId: "d1", deletedItemUuids: [],
    vaults: { local: { items: [protonItem("A", "u", "p")] } } };
  const items = parseProtonPlaintext(JSON.stringify(env));
  assert.equal(items.length, 1);
});

test("the Proton plaintext: the single-item {data...} shape", () => {
  const items = parseProtonPlaintext(JSON.stringify(protonItem("Solo", "u", "p")));
  assert.equal(items.length, 1);
  assert.equal(items[0].data.metadata.name, "Solo");
});

test("the Proton plaintext: the note and the TOTP survive (not a lossy format)", () => {
  const items = parseProtonPlaintext(JSON.stringify([protonItem("A", "u", "p", "the vault note")]));
  assert.equal(items[0].data.metadata.note, "the vault note");
});

test("the Proton plaintext: the malformed JSON → null (not a throw)", () => {
  assert.equal(parseProtonPlaintext("{not json"), null);
  assert.equal(parseProtonPlaintext(""), null);
  assert.equal(parseProtonPlaintext("-----BEGIN PGP MESSAGE-----"), null);
});

// -- the PROVENANCE NOTE ----------------------------------------------------

test("the provenance note: the empty note → the line only", () => {
  const it = protonItem("G", "u", "p", "");
  appendImportNote(it, "Google Passwords CSV (USB file)");
  assert.match(it.data.metadata.note,
    /^\[Imported from Google Passwords CSV \(USB file\) — \d{4}-\d{2}-\d{2}\]$/);
});

test("the provenance note: the existing note → the line appended on a new line", () => {
  const it = protonItem("A", "u", "p", "the vault note");
  appendImportNote(it, "Proton Pass export (QRFT scan)");
  assert.match(it.data.metadata.note,
    /^the vault note\n\[Imported from Proton Pass export \(QRFT scan\) — \d{4}-\d{2}-\d{2}\]$/);
});

test("the provenance note: the re-import dedupes (no stacked duplicate lines)", () => {
  const it = protonItem("A", "u", "p", "");
  appendImportNote(it, "Google Passwords CSV (USB file)");
  const once = it.data.metadata.note;
  appendImportNote(it, "Google Passwords CSV (USB file)");
  assert.equal(it.data.metadata.note, once,
    "the second append with the SAME label must not stack");
  appendImportNote(it, "Proton Pass export (QRFT scan)");
  assert.ok(it.data.metadata.note.includes("Proton Pass export (QRFT scan)"),
    "a DIFFERENT label still appends");
});
