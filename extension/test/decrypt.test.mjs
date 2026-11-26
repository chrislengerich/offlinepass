/**
 * THE CARD-IN-THE-MIDDLE DECRYPT CONTRACT: decryptWithCard() over a
 * FAKE card (node crypto, software RSA keys — see fakecard.mjs) — the
 * same pipeline the extension pages run, with the hardware's PSO:DEC
 * response shapes reproduced:
 *
 *  - the OLD applet shape = the full PKCS#1 type-2 block (00 02 PS 00
 *    M) out of the raw RSA — decryptWithCard's stripType2 strips;
 *  - the NEW applet shape = the unpadded M — parsed directly;
 *  - the multi-recipient envelope = the PKESKs tried in order, the
 *    card opens ITS recipient (the ENCRYPTION SUBKEY's, not the
 *    primary's — the measured rule);
 *  - the WRONG CARD = the mismatch: the card decrypts a foreign
 *    recipient's PKESK into garbage → the checksum rejects it → the
 *    named "opens none of the N" error (distinct from blank);
 *  - the BLANK CARD = no GPG key on the DEC slot → the named
 *    initialize-the-key-set error (the discrimination the paired-key
 *    interaction needs: blank ≠ wrong);
 *  - the EdDSA PKESK (algo 22) cannot decrypt — rejected by name.
 *
 * The session-key shapes and the SEIPD framing compatibility against
 * the REAL device vault files were hardware-measured (the phase-2
 * probe); this suite pins the pipeline logic on the reproducible
 * fixtures.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { rsaRecipient, fakeRsaCard, fakeBlankCard, envelopeTo } from "./fakecard.mjs";

const { decryptWithCard, DecryptError } = await import("../card/decrypt.js");

const PAYLOAD = JSON.stringify({ rev: 1, vaults: { local: { items: [] } } });

test("the RSA card-in-the-middle decrypt — the OLD applet shape (the full type-2 block)", async () => {
  const recipient = await rsaRecipient();
  const blob = await envelopeTo([recipient], PAYLOAD);
  const out = await decryptWithCard(blob, fakeRsaCard(recipient, "old"),
    () => {});
  assert.equal(new TextDecoder().decode(out.data), PAYLOAD);
});

test("the RSA decrypt — the NEW applet shape (the unpadded M)", async () => {
  const recipient = await rsaRecipient();
  const blob = await envelopeTo([recipient], PAYLOAD);
  const out = await decryptWithCard(blob, fakeRsaCard(recipient, "new"),
    () => {});
  assert.equal(new TextDecoder().decode(out.data), PAYLOAD);
});

test("the multi-recipient envelope: the PKESKs tried in order, the card opens ITS recipient", async () => {
  const mine = await rsaRecipient();
  const other = await rsaRecipient();
  const blob = await envelopeTo([other, mine], PAYLOAD);  // the card's is SECOND
  const out = await decryptWithCard(blob, fakeRsaCard(mine, "old"), () => {});
  assert.equal(new TextDecoder().decode(out.data), PAYLOAD);
});

test("the WRONG CARD: the foreign recipient's PKESK decrypts to garbage — the named mismatch", async () => {
  const foreign = await rsaRecipient();
  const blob = await envelopeTo([foreign], PAYLOAD);
  // The card = a DIFFERENT key: the raw RSA decrypt still runs (the
  // hardware does too) but produces garbage — the checksum rejects it.
  const other = await rsaRecipient();
  await assert.rejects(
    decryptWithCard(blob, fakeRsaCard(other, "old"), () => {}),
    (e) => e instanceof DecryptError && e.message.includes("opens none of the 1 recipient(s)"));
});

test("the BLANK CARD: no GPG key on the DEC slot — the named initialize-the-key-set error", async () => {
  const blob = await envelopeTo([await rsaRecipient()], PAYLOAD);
  await assert.rejects(
    decryptWithCard(blob, fakeBlankCard(), () => {}),
    (e) => e instanceof DecryptError && e.message.includes("no GPG key"));
});

test("the EdDSA PKESK (algo 22) is rejected by name (it cannot decrypt)", async () => {
  // The synthetic v3 PKESK with the EdDSA algorithm byte — the whole
  // point: decryptWithCard refuses BEFORE any card op.
  const recipient = await rsaRecipient();
  const blob = await envelopeTo([recipient], PAYLOAD);
  // Swap the PKESK's algorithm byte (9 → 22): the rest stays structurally
  // valid, so openpgp.readMessage accepts it and the dispatch sees 22.
  const m = Buffer.from(blob);
  let p = 0;
  outer: while (p < m.length) {
    const first = m[p]; const tag = first & 0x3f; const lt = first & 3;
    let len, hdr;
    if (lt === 0) { len = m[p + 1]; hdr = 2; }
    else if (lt === 1) { len = ((m[p + 1] & 0x1f) << 8 | m[p + 2]) + 192; hdr = 3; }
    else { len = (m[p + 1] << 24 | m[p + 2] << 16 | m[p + 3] << 8 | m[p + 4]); hdr = 5; }
    if (tag === 1) { m[p + hdr + 9] = 22; break outer; }
    p += hdr + len;
  }
  await assert.rejects(
    decryptWithCard(m, fakeRsaCard(recipient, "old"), () => {}),
    (e) => e instanceof DecryptError && e.message.includes("EdDSA cannot decrypt"));
});
