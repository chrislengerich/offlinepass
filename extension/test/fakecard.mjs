/**
 * THE FAKE CARD + the software-key fixtures — shared by the decrypt
 * contract tests and the sync E2E: the node-crypto RSA numbers from an
 * openpgp.js-generated key pair, shaped as the card's PSO:DEC interface
 * (decPublicKey + psodec(mpiField, decKey)).
 *
 * THE SUBKEY RULE (measured): the PKESK targets the ENCRYPTION SUBKEY —
 * the primary's numbers never match it. The fixture builds the JWK from
 * the SecretSubkeyPacket.
 */
import crypto from "node:crypto";

globalThis.window = globalThis;
globalThis.self = globalThis;

export const openpgp = await import("../lib/openpgp.mjs");

const bi = (arr) => BigInt("0x" + Buffer.from(arr).toString("hex"));
const pack = (v) => {
  let h = v.toString(16);
  if (h.length % 2) h = "0" + h;
  return Buffer.from(h, "hex").toString("base64url");
};
const inv = (a, m) => {
  let [x, x1] = [1n, 0n], g = a % m, g1 = m;
  while (g1) { const q2 = g / g1; [g, g1] = [g1, g % g1]; [x, x1] = [x1, x - q2 * x1]; }
  return ((x % m) + m) % m;
};

/** The software RSA-2048 recipient: the openpgp.js key pair + the JWK
 *  (from the SUBKEY — the encryption target) for the fake card. */
export async function rsaRecipient(rsaBits = 2048) {
  const key = await openpgp.generateKey({
    type: "rsa", rsaBits,
    userIDs: [{ name: "Test", email: "test@offlinepass.local" }],
    format: "object",
  });
  const sub = key.privateKey.getKeys()
    .map((k) => k.keyPacket)
    .find((p) => p.constructor.name === "SecretSubkeyPacket");
  const n = bi(sub.publicParams.n), e = bi(sub.publicParams.e);
  const d = bi(sub.privateParams.d), p = bi(sub.privateParams.p), q = bi(sub.privateParams.q);
  const jwk = {
    kty: "RSA", n: pack(n), e: pack(e), d: pack(d), p: pack(p), q: pack(q),
    dp: pack(d % (p - 1n)), dq: pack(d % (q - 1n)), qi: pack(inv(q, p)),
  };
  return { key, modulusLen: rsaBits / 8, jwk };
}

/** The envelope encrypted to the recipients (the PKESK v3 + the SEIPD —
 *  the same recipient system the device's bcpg writes). */
export async function envelopeTo(recipients, payload) {
  return Buffer.from(await openpgp.encrypt({
    message: await openpgp.createMessage({ text: payload ?? JSON.stringify(
      { rev: 1, vaults: { local: { items: [] } } }) }),
    encryptionKeys: recipients.map((r) => r.key.publicKey),
    format: "binary",
  }));
}

/**
 * The fake card: decryptWithCard()'s interface — decPublicKey() +
 * psodec(mpiField, decKey).
 *
 * - `shape: "old"` — the response = the FULL PKCS#1 type-2 block (00 02
 *   PS 00 M): the older applets' shape; decryptWithCard's stripType2
 *   strips it.
 * - `shape: "new"` — the response = the unpadded M: the newer applets'.
 */
export function fakeRsaCard(recipient, shape) {
  const priv = crypto.createPrivateKey({ key: recipient.jwk, format: "jwk" });
  return {
    decPublicKey: async () => ({ rsa: true, modulusLen: recipient.modulusLen }),
    async psodec(mpiField, decKey) {
      // decryptWithCard passes body.slice(10): [bitlen hi, lo, mpi…].
      const mpiBits = (mpiField[0] << 8) | mpiField[1];
      const mpiLen = (mpiBits + 7) >> 3;
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
export function fakeBlankCard() {
  return {
    decPublicKey: async () => {
      throw new Error("the DEC DO carries no modulus");
    },
    psodec: async () => { throw new Error("unreachable"); },
  };
}
