/**
 * THE CARD-IN-THE-MIDDLE DECRYPT CONTRACT: decryptWithCard() over a
 * FAKE card (node crypto, software RSA keys) — the same pipeline the
 * extension pages run, with the hardware's PSO:DEC response shapes
 * reproduced:
 *
 *  - the OLD applet shape = the full PKCS#1 type-2 block (00 02 PS 00
 *    M) out of the raw RSA — decryptWithCard's stripType2 strips;
 *  - the NEW applet shape = the unpadded M — parsed directly;
 *  - the multi-recipient envelope = the PKESKs tried in order, the
 *    card opens ITS recipient;
 *  - the WRONG CARD = the mismatch: the card decrypts a foreign
 *    recipient's PKESK into garbage → the checksum rejects it → the
 *    named "opens none of the N" error (distinct from blank);
 *  - the BLANK CARD = no GPG key on the DEC slot → the named
 *    initialize-the-key-set error (the discrimination the paired-key
 *    interaction needs: blank ≠ wrong).
 *
 * The session-key shapes and the SEIPD framing compatibility against
 * the REAL device vault files were hardware-measured (the phase-2
 * probe); this suite pins the pipeline logic on the reproducible
 * fixtures.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";

// The openpgp.mjs bundle's own window shim (the vendored UMD assumes a
// browser-ish global; the decrypt.js import path expects it too).
globalThis.window = globalThis;
globalThis.self = globalThis;

const openpgp = await import("../lib/openpgp.mjs");
const { decryptWithCard, DecryptError } = await import("../card/decrypt.js");

const PAYLOAD = JSON.stringify({ rev: 1, vaults: { local: { items: [] } } });

/** The software RSA recipient: the openpgp.js key pair + the JWK for the
 *  fake card's node-crypto private ops. */
async function rsaRecipient(rsaBits = 2048) {
  const key = await openpgp.generateKey({
    type: "rsa", rsaBits,
    userIDs: [{ name: "Test", email: "test@offlinepass.local" }],
    format: "object",
  });
  const pkt = key.privateKey.getKeys()
    .map((k) => k.keyPacket)
    .find((p) => p.constructor.name === "SecretSubkeyPacket");   // the PKESK targets the ENCRYPTION subkey
  const bi = (arr) => BigInt("0x" + Buffer.from(arr).toString("hex"));
  const pack = (v) => { let h = v.toString(16); if (h.length % 2) h = "0" + h; return Buffer.from(h, "hex").toString("base64url"); };
  const n = bi(pkt.publicParams.n), e = bi(pkt.publicParams.e);
  const d = bi(pkt.privateParams.d), p = bi(pkt.privateParams.p), q = bi(pkt.privateParams.q);
  const inv = (a, m) => { let [x, x1] = [1n, 0n], g = a % m, g1 = m; while (g1) { const q2 = g / g1; [g, g1] = [g1, g % g1]; [x, x1] = [x1, x - q2 * x1]; } return ((x % m) + m) % m; };
  const jwk = {
    kty: "RSA",
    n: pack(n), e: pack(e), d: pack(d), p: pack(p), q: pack(q),
    dp: pack(d % (p - 1n)), dq: pack(d % (q - 1n)), qi: pack(inv(q, p)),
  };
  return { key, modulusLen: rsaBits / 8, jwk };
}

/** The fake card: the interface decryptWithCard() calls — decPublicKey()
 *  + psodec(mpiField, decKey). `shape` = the PSO:DEC response flavor the
 *  hardware applet generation produces. */
function fakeRsaCard(recipient, shape) {
  const priv = crypto.createPrivateKey({ key: recipient.jwk, format: "jwk" });
  return {
    decPublicKey: async () => ({ rsa: true, modulusLen: recipient.modulusLen }),
    async psodec(mpiField, decKey) {
      // decryptWithCard passes body.slice(10): [bitlen hi, lo, mpi…].
      const mpiBits = (mpiField[0] << 8) | mpiField[1];
      const mpiLen = (mpiBits + 7) >> 3;
      if (process.env.OP_DEBUG) console.error(`psodec: mpiBits=${mpiBits} mpiLen=${mpiLen} field=${mpiField.length}`);
      const mpi = mpiField.slice(2, 2 + mpiLen);
      const padded = Buffer.concat(
        [Buffer.alloc(recipient.modulusLen - mpi.length, 0), mpi]);
      const block = crypto.privateDecrypt(
        { key: priv, padding: crypto.constants.RSA_NO_PADDING }, padded);
      if (shape === "old") return block;           // 00 02 PS 00 M
      const sep = block.indexOf(0x00, 2);           // the unpadded M
      return block.slice(sep + 1);
    },
  };
}

/** The blank card: the applet answers but the DEC slot holds no key —
 *  the REAL card/openpgp.js layer's failure shape. */
function fakeBlankCard() {
  return {
    decPublicKey: async () => {
      throw new Error("the DEC DO carries no modulus");
    },
    psodec: async () => { throw new Error("unreachable"); },
  };
}

const envelopeTo = async (recipients) => Buffer.from(
  await openpgp.encrypt({
    message: await openpgp.createMessage({ text: PAYLOAD }),
    encryptionKeys: recipients.map((r) => r.key.publicKey),
    format: "binary",
  }));

test("the RSA card-in-the-middle decrypt — the OLD applet shape (the full type-2 block)", async () => {
  const recipient = await rsaRecipient();
  const blob = await envelopeTo([recipient]);
  const out = await decryptWithCard(blob, fakeRsaCard(recipient, "old"),
    () => {});
  assert.equal(new TextDecoder().decode(out.data), PAYLOAD);
});

test("the RSA decrypt — the NEW applet shape (the unpadded M)", async () => {
  const recipient = await rsaRecipient();
  const blob = await envelopeTo([recipient]);
  const out = await decryptWithCard(blob, fakeRsaCard(recipient, "new"),
    () => {});
  assert.equal(new TextDecoder().decode(out.data), PAYLOAD);
});

test("the multi-recipient envelope: the PKESKs tried in order, the card opens ITS recipient", async () => {
  const mine = await rsaRecipient();
  const other = await rsaRecipient();
  const blob = await envelopeTo([other, mine]);  // the card's is SECOND
  const out = await decryptWithCard(blob, fakeRsaCard(mine, "old"), () => {});
  assert.equal(new TextDecoder().decode(out.data), PAYLOAD);
});

test("the WRONG CARD: the foreign recipient's PKESK decrypts to garbage — the named mismatch", async () => {
  const foreign = await rsaRecipient();
  const blob = await envelopeTo([foreign]);
  // The card = a DIFFERENT key: the raw RSA decrypt still runs (the
  // hardware does too) but produces garbage — the checksum rejects it.
  const other = await rsaRecipient();
  await assert.rejects(
    decryptWithCard(blob, fakeRsaCard(other, "old"), () => {}),
    (e) => e instanceof DecryptError && e.message.includes("opens none of the 1 recipient(s)"));
});

test("the BLANK CARD: no GPG key on the DEC slot — the named initialize-the-key-set error", async () => {
  const blob = await envelopeTo([await rsaRecipient()]);
  await assert.rejects(
    decryptWithCard(blob, fakeBlankCard(), () => {}),
    (e) => e instanceof DecryptError && e.message.includes("no GPG key"));
});
