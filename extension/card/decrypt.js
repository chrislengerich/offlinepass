/**
 * THE CARD-IN-THE-MIDDLE DECRYPT (the extension's pipeline):
 *   1. the manual OpenPGP packet walk → the first PKESK's encrypted
 *      session-key field (the same shapes the Android's parser walks:
 *      the old/new headers, the v3 PKESK's version+id+algorithm+MPI)
 *   2. the CARD: the RSA = the zero-pad to the modulus (the extended
 *      APDU), the ECDH = the bare point — the response = the session
 *      data (the algo-byte + key + checksum; the applets' two shapes)
 *   3. the session key → openpgp.decrypt({ message, sessionKeys }) —
 *      the openpgp.js opens the SEIPD and verifies the MDC natively.
 *
 * The multi-recipient envelopes: the PKESKs are tried in order; the
 * card opens the one matching its DEC slot.
 */
import * as openpgp from "../lib/openpgp.mjs";

const SYM_ALG_NAMES = { 0: "plaintext", 2: "3des", 7: "aes128", 8: "aes192", 9: "aes256" };

/** The packet walk: the old/new-format headers → the [tag, body, next]
 *  list. Enough for the PKESK locate + the SEIPD's span. The lengths per
 *  RFC 4880 §4.2.2 — the NEW format's length TYPE lives in the first
 *  LENGTH octet's top bits (not the tag byte's!), and the 4-octet form is
 *  UNSIGNED (a signed `<< 24` read of a ≥0x80 first octet turns negative,
 *  walked `p` backwards, and looped the parser into an OOM — the sync E2E
 *  caught it). */
function walkPackets(bytes) {
  const out = [];
  let p = 0;
  while (p < bytes.length) {
    const first = bytes[p];
    let tag, len, hdr;
    if (first & 0x80) {
      // The NEW format: bit7 = 1, the tag = the 6 low bits.
      // (The (first >>> 2) & 0x0f here before decoded every new-format
      // tag wrongly — the old format's shapes only — the fixture now
      // caught it: openpgp.js writes 0xc1 = new-format tag 1 = the
      // PKESK the old decode read as tag 0.)
      tag = first & 0x3f;
      const lb = bytes[p + 1];   // the FIRST length octet carries the type
      if (lb < 192) { len = lb; hdr = 2; }
      else if (lb <= 223) { len = (((lb & 0x1f) << 8) | bytes[p + 2]) + 192; hdr = 3; }
      else if (lb === 255) {
        len = (((bytes[p + 2] << 24) | (bytes[p + 3] << 16) |
          (bytes[p + 4] << 8) | bytes[p + 5]) >>> 0); hdr = 6;
      }
      else { throw new Error("partial/indeterminate packet length unsupported"); }
      p += hdr;
    } else {
      // The OLD format: bit6 = 1, the tag = bits 5-2, the length TYPE =
      // the low 2 bits (0/1/2 = the 1/2/4-octet length, 3 = indeterminate).
      tag = (first >>> 2) & 0x0f;
      const ltype = first & 3;
      if (ltype === 0) { len = bytes[p + 1]; hdr = 2; }
      else if (ltype === 1) { len = (bytes[p + 1] << 8) | bytes[p + 2]; hdr = 3; }
      else if (ltype === 2) {
        len = (((bytes[p + 1] << 24) | (bytes[p + 2] << 16) |
          (bytes[p + 3] << 8) | bytes[p + 4]) >>> 0); hdr = 5;
      }
      else { throw new Error("the legacy indeterminate length unsupported"); }
      p += hdr;
    }
    if (!Number.isSafeInteger(len) || len < 0) {
      throw new Error("implausible packet length " + len + " at offset " + (p - hdr));
    }
    const body = bytes.slice(p, p + len);
    out.push({ tag, body, start: p - hdr, total: hdr + len });
    p += len;
  }
  return out;
}

export class DecryptError extends Error {}

/** The PKESK's encrypted session-key field: the version(1) + the
 *  keyid(8) + the algorithm(1) + the MPI field (the 2-byte prefix +
 *  the value). Returns { keyId, algorithm, mpiField } or null. */
function parsePkesk(body) {
  if (body.length < 11) return null;
  const version = body[0];
  if (version !== 3) return null;   // the v6 = the later phase
  const keyId = [...body.slice(1, 9)].map((x) => x.toString(16).padStart(2, "0")).join("");
  const algorithm = body[9];
  const mpiLen = (body[10] << 8) | body[11];
  const mpi = body.slice(12, 12 + ((mpiLen + 7) >> 3));
  return { keyId, algorithm, mpiField: body.slice(10) };
}

/** The session data's parse: the algo-byte + the key + the checksum
 *  (RFC 4880 §5.1: the checksum = the sum of the SESSION KEY's octets
 *  ONLY — not the algorithm byte — mod 65536, big-endian). */
export function parseSessionData(m) {
  if (m.length < 4) throw new DecryptError("the session data too short");
  const algorithm = m[0];
  const key = m.slice(1, m.length - 2);
  const sum = [...key].reduce((a, b) => (a + b) & 0xffff, 0);
  const expect = (m[m.length - 2] << 8) | m[m.length - 1];
  if (sum !== expect) throw new DecryptError("the session key's checksum mismatch");
  return { algorithm, key, name: SYM_ALG_NAMES[algorithm] || `alg${algorithm}` };
}

/** The card-in-the-middle decrypt of a whole vault file. */
export async function decryptWithCard(msgBytes, card, onLog = () => {}) {
  const packets = walkPackets(msgBytes);
  const pkesks = packets.filter((pk) => pk.tag === 1);
  if (!pkesks.length) throw new DecryptError("no PKESK in the message");
  const message = await openpgp.readMessage({ binaryMessage: msgBytes });
  // The BLANK CARD first (the paired-key interaction's discrimination):
  // the applet answers but the DEC slot holds no GPG key — the
  // initialize-the-key-set error, NOT a wrong-card complaint.
  let decKey;
  try {
    decKey = await card.decPublicKey();
  } catch (e) {
    throw new DecryptError(
      "the card's DEC slot has no GPG key set (it may have other keys) — " +
        "initialize a key set on the YubiKey first: the Android README's " +
        "'Initialize the security key (OpenPGP key set)' section",
      { cause: e });
  }
  onLog(`the PKESKs: ${pkesks.length}; the DEC slot: ${decKey.rsa ? `RSA-${decKey.modulusLen * 8}` : "EC"}`);

  const lastError = [];
  for (const pk of pkesks) {
    const pkesk = parsePkesk(pk.body);
    if (!pkesk) continue;
    if (pkesk.algorithm === 22) throw new DecryptError("EdDSA cannot decrypt");
    try {
      const m = await card.psodec(pkesk.mpiField, decKey);
      // The response's shape: the older applets = the PKCS#1 type-2 block
      // (the RSA: the modulus length); the newer = the unpadded M. Strip
      // when the size says so (the same rule the Android's factory uses).
      let sessionData = m;
      if (decKey.rsa && m.length > decKey.modulusLen - 3) {
        sessionData = stripType2(m);
      }
      const { algorithm, key, name } = parseSessionData(sessionData);
      onLog(`the session key: ${name} (${key.length}B)`);
      const result = await openpgp.decrypt({
        message,
        sessionKeys: [{ data: key, algorithm: name }],
        format: "binary",
      });
      return result;
    } catch (e) {
      lastError.push(`${pkesk.keyId.slice(-8)}: ${e.message}`);
    }
  }
  throw new DecryptError(
    `the card opens none of the ${pkesks.length} recipient(s) — ${lastError.join("; ")}`);
}

/** The PKCS#1 type-2 strip: 00 02 PS 00 M. */
function stripType2(block) {
  let p = 2;
  while (p < block.length && block[p] !== 0x00) p++;
  p++;
  if (p >= block.length) throw new DecryptError("not a type-2 block");
  return block.slice(p);
}
