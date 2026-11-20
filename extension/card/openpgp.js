/**
 * The OpenPGP applet over the CCID transport — the operations the
 * extension's decrypt needs. The same card contract the Android's
 * YubiKitCardDecrypt implements (docs/crypto session notes):
 *   - the RSA PSO:DEC: the PKESK's MPI (zero-padded to the modulus) in,
 *     the PKCS#1 type-2 block (or the unpadded M on the newer applets) out
 *   - the ECDH PSO:DEC: the bare ephemeral point in, the plain session
 *     data out (the card performs the RFC 6637 KDF + the AES-key-unwrap)
 *   - the PIN verify with the "extended" flavor (P2=0x82 = the
 *     decrypt-capable; the P2=0x81 sign-only flavor fails PSO:DEC with
 *     0x6982 despite the verify's own 9000)
 *
 * The extended-length APDUs: the PSO:DEC for RSA-4096 = the 512-byte
 * command — the 3-byte extended header (0xC3-style lengths).
 */
import { Ccid } from "./ccid.js";

const OPENPGP_AID = [0xa0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00];

export class OpenPgpCard {
  static async open() { return new OpenPgpCard(await Ccid.open()); }

  constructor(ccid) { this.ccid = ccid; }

  apdu(cla, ins, p1, p2, data = [], le = 0) {
    const cmd = [cla, ins, p1, p2, data.length, ...data];
    if (le) cmd.push(le & 0xff);
    return new Uint8Array(cmd);
  }

  /** The extended-length command frame: the 3-byte data length, the
   *  Le = 3 bytes (0x00 0x00 0x00 = the max). */
  apduExt(cla, ins, p1, p2, data, leExt = true) {
    const cmd = [cla, ins, p1, p2, 0x00,
      (data.length >>> 16) & 0xff, (data.length >>> 8) & 0xff, data.length & 0xff,
      ...data];
    if (leExt) cmd.push(0x00, 0x00, 0x00);
    return new Uint8Array(cmd);
  }

  async send(apdu) {
    const resp = await this.ccid.xfrBlock(apdu);
    if (resp.length < 2) throw new Error("the empty card response");
    const sw = (resp[resp.length - 2] << 8) | resp[resp.length - 1];
    const data = resp.slice(0, resp.length - 2);
    if (sw !== 0x9000) {
      const e = new Error(`the card status 0x${sw.toString(16).padStart(4, "0")}`);
      e.sw = sw; e.data = data;
      throw e;
    }
    return data;
  }

  async select() {
    await this.send(this.apdu(0x00, 0xa4, 0x04, 0x00, OPENPGP_AID, 0));
  }

  /** The GET DATA: the tag in, the value out. The unauthenticated reads
   *  (the applet version, the fingerprints) need no PIN. */
  async getData(tagHi, tagLo, expectedLen = 0) {
    const resp = await this.send(this.apdu(0x00, 0xca, tagHi, tagLo, [], expectedLen));
    // The DO envelope: the tag + the 2-byte length + the value — strip it.
    if (resp[0] === tagHi && resp[1] === tagLo) {
      const len = (resp[2] << 8) | resp[3];
      return resp.slice(4, 4 + len);
    }
    return resp;
  }

  async version() {
    const aid = await this.getData(0x4f, 0x00);
    return `${aid[6]}.${aid[7]}.${aid[8]}`;
  }

  /** The fingerprints DO (the tag 0x005E = the composite, or the 0x00C5 =
   *  the 3x20-byte fingerprints of the SIG/DEC/AUT slots). */
  async fingerprints() {
    const raw = await this.getData(0x00, 0xc5);
    return {
      sig: raw.slice(0, 20), dec: raw.slice(20, 40), aut: raw.slice(40, 60),
    };
  }

  /** The PW1 verify, the decrypt-capable flavor (the P2=0x82; the PIN =
   *  the ASCII digits, the space-padded to 8). */
  async verifyPin(pin) {
    const bytes = Array.from(pin.toString()).map((c) => c.charCodeAt(0));
    while (bytes.length < 8) bytes.push(0x20);
    await this.send(this.apdu(0x00, 0x20, 0x00, 0x82, bytes));
  }

  /** The DEC slot's public key (the DO 0x7F49): the TLV parse → the
   *  modulus (the 0x81 tag) for the RSA's zero-padding, and the key
   *  type. The read = unauthenticated (no PIN). */
  async decPublicKey() {
    const dof = await this.getData(0x7f, 0x49, 0);
    // The TLV walk: the 0x81 = the modulus, the 0x82 = the exponent.
    let p = 0;
    let modulus = null, exponent = null, isEcdh = false;
    while (p + 2 <= dof.length) {
      const tag = dof[p]; const len = dof[p + 1]; p += 2;
      const val = dof.slice(p, p + len); p += len;
      if (tag === 0x81) modulus = val;
      if (tag === 0x82) exponent = val;
      if (tag === 0x86) { isEcdh = true; modulus = val; }
    }
    if (isEcdh) return { rsa: false, pointLen: modulus.length };
    if (!modulus) throw new Error("the DEC DO carries no modulus");
    return { rsa: true, modulusLen: modulus.length, exponent };
  }

  /** The PSO:DEC. The algorithm is read from the DEC slot's public key:
   *  the RSA = the zero-padded ciphertext in (the extended APDU for the
   *  4096-bit keys), the ECDH = the bare ephemeral point in. The
   *  response = the decrypted session data (the shape differences
   *  between the applets handled by the caller, as on Android). */
  async psodec(ciphertext, decPublicKey) {
    const isRsa = decPublicKey.rsa;
    const body = isRsa
      ? zeroPad(ciphertext, decPublicKey.modulusLen)
      : ciphertext;
    const cmd = isRsa
      ? this.apduExt(0x00, 0x2a, 0x80, 0x86, body)
      : this.apdu(0x00, 0x2a, 0x80, 0x86, body, 0);
    const resp = await this.send(cmd);
    return resp;
  }
}

function zeroPad(data, len) {
  const out = new Uint8Array(len);
  out.set(data, len - data.length);
  return out;
}
