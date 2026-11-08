/**
 * linuxpass device-wrap crypto (Plan 2, docs/extension-protocol.md).
 *
 * Everything is standard WebCrypto — no hand-rolled primitives:
 *   PRF output (security key, hmac-secret)  ──HKDF──▶  seed KEK (AES-GCM)
 *   seed KEK unwraps the ECDH P-256 seed (pkcs8, stored wrapped)
 *   seed private key + sender ephemeral pubkey (ECDH)  ──HKDF──▶  paste KEK
 *   paste KEK AES-256-GCM-decrypts the wrapped paste
 *
 * The seed never exists in plaintext without a WebAuthn user-verification
 * touch: the PRF eval happens inside the security key and requires it.
 */
window.LpWrap = (function () {
  "use strict";

  const te = new TextEncoder();
  const td = new TextDecoder();

  const SEED_INFO = te.encode("linuxpass-seed-kek-v1");
  const SEED_AAD = te.encode("linuxpass-seed-wrap-v1");
  const PASTE_INFO = te.encode("linuxpass-paste-wrap-v1");

  const subtle = crypto.subtle;

  function ab(bytes) { // BufferSource -> ArrayBuffer view for subtle calls
    return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
  }
  function u8(view) { return new Uint8Array(view); }

  async function sha256(bytes) {
    return u8(await subtle.digest("SHA-256", ab(bytes)));
  }

  async function hkdf(ikm, salt, info, len) {
    const key = await subtle.importKey("raw", ab(ikm), "HKDF", false, ["deriveBits"]);
    const bits = await subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: ab(salt), info: ab(info) }, key, (len || 32) * 8);
    return u8(bits);
  }

  /** PRF salt for a credential (must match the Android/record side). */
  function prfSalt(credIdRaw) {
    return sha256(concat(te.encode("linuxpass-device-v1"), credIdRaw));
  }

  function concat(a, b) {
    const out = new Uint8Array(a.length + b.length);
    out.set(a, 0); out.set(b, a.length);
    return out;
  }

  function hexToBytes(hex) {
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
  }
  function bytesToHex(bytes) {
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  }

  // -- WebAuthn -------------------------------------------------------------

  /** Creates the pairing credential (PRF enabled, UV required, non-resident
   *  so no YubiKey resident-key slot is consumed). Returns {credIdRaw}. */
  async function createCredential() {
    const cred = await navigator.credentials.create({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        user: {
          id: crypto.getRandomValues(new Uint8Array(16)),
          name: "linuxpass paste device",
          displayName: "linuxpass paste device",
        },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
        authenticatorSelection: {
          userVerification: "required",
          residentKey: "discouraged",
        },
        extensions: { prf: {} },
      },
    });
    return { credIdRaw: new Uint8Array(cred.rawId) };
  }

  /** Runs a PRF eval for an existing credential — REQUIRES a key touch. */
  async function prfEval(credIdB64, salt) {
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials: [{ type: "public-key", id: ab(b64ToBytesRaw(credIdB64)) }],
        userVerification: "required",
        extensions: { prf: { eval: { first: ab(salt) } } },
      },
    });
    const prf = assertion.getClientExtensionResults().prf;
    if (!prf || !prf.results || !prf.results.first) {
      throw new Error("Security key did not return a PRF result (hmac-secret unsupported?).");
    }
    return u8(prf.results.first);
  }

  function b64ToBytesRaw(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function bytesRawToB64(bytes) {
    let s = "";
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }

  // -- seed wrap / unwrap ---------------------------------------------------

  /** Step 1 of pairing: create the credential (one touch). */
  async function createPairing() {
    const { credIdRaw } = await createCredential();
    const credId = bytesRawToB64(credIdRaw);
    const salt = await prfSalt(credIdRaw);
    return { credId, salt };
  }

  /** Step 2 of pairing (another touch): eval PRF, wrap a fresh ECDH seed.
   *  Returns the full record (public data + wrapped seed only). */
  async function finishPairing(credId, saltB64, name) {
    const salt = b64ToBytesRaw(saltB64);
    const prfOut = await prfEval(credId, salt);
    const kek = await hkdf(prfOut, salt, SEED_INFO, 32);

    const seedPair = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    const pkcs8 = u8(await subtle.exportKey("pkcs8", seedPair.privateKey));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = u8(await subtle.encrypt({ name: "AES-GCM", iv, additionalData: SEED_AAD }, 
      await importAes(kek), ab(pkcs8)));

    // Public point = last 65 bytes of the SPKI DER.
    const spki = u8(await subtle.exportKey("spki", seedPair.publicKey));
    const pub = spki.slice(spki.length - 65);
    const keyId = bytesToHex((await sha256(pub)).slice(0, 8));

    return {
      id: keyId, keyId,
      name: String(name || "security key").slice(0, 60),
      credId, salt: saltB64, pub: bytesRawToB64(pub),
      added: Math.floor(Date.now() / 1000),
      wrapped: { iv: bytesRawToB64(iv), ct: bytesRawToB64(ct) },
    };
  }

  async function importAes(raw32) {
    return subtle.importKey("raw", ab(raw32), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  }

  /** Touch + unwrap the seed private key (deriveBits-only, non-extractable). */
  async function unwrapSeed(record) {
    const salt = b64ToBytesRaw(record.salt);
    const prfOut = await prfEval(record.credId, salt);
    const kek = await hkdf(prfOut, salt, SEED_INFO, 32);
    const iv = b64ToBytesRaw(record.wrapped.iv);
    const pkcs8 = u8(await subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: SEED_AAD }, await importAes(kek),
      ab(b64ToBytesRaw(record.wrapped.ct))));
    return subtle.importKey("pkcs8", ab(pkcs8), { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  }

  // -- paste wrap / unwrap --------------------------------------------------

  /** Decrypts a wrapped paste JSON ({"type":"linuxpass-wrap",...}).
   *  Requires a security-key touch. Returns the plaintext payload string. */
  async function unwrapPaste(record, wrappedJson) {
    const w = JSON.parse(wrappedJson);
    if (w.type !== "linuxpass-wrap" || w.v !== 1) throw new Error("Not a wrapped paste.");
    if (w.wrap.keyId !== record.keyId) throw new Error("Paste targets key " + w.wrap.keyId + " — paired key is " + record.keyId + ".");
    const seedPriv = await unwrapSeed(record);           // touch happens here
    const epk = await subtle.importKey("raw", ab(b64ToBytesRaw(w.wrap.epk)),
      { name: "ECDH", namedCurve: "P-256" }, false, []);
    const shared = u8(await subtle.deriveBits({ name: "ECDH", public: epk }, seedPriv, 256));
    const pasteKek = await hkdf(shared, hexToBytes(record.keyId), PASTE_INFO, 32);
    const aad = te.encode("linuxpass-paste-wrap-v1:" + w.wrap.keyId + ":" + w.wrap.epk);
    const plain = await subtle.decrypt(
      { name: "AES-GCM", iv: ab(b64ToBytesRaw(w.iv)), additionalData: aad },
      await importAes(pasteKek), ab(b64ToBytesRaw(w.ct)));
    return td.decode(plain);
  }

  // -- TOTP (RFC 6238 over the item's otpauth:// URI; copy-only) ------------

  function base32Decode(s) {
    const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    s = s.toUpperCase().replace(/=+$/, "").replace(/\s/g, "");
    let bits = 0, value = 0;
    const out = [];
    for (const c of s) {
      const idx = A.indexOf(c);
      if (idx < 0) throw new Error("Bad base32 in TOTP secret");
      value = (value << 5) | idx;
      bits += 5;
      if (bits >= 8) { out.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
    }
    return new Uint8Array(out);
  }

  async function totp(uri) {
    if (!uri || !uri.startsWith("otpauth://")) return null;
    const q = new URL(uri);
    const secret = base32Decode(q.searchParams.get("secret") || "");
    if (!secret.length) return null;
    const digits = parseInt(q.searchParams.get("digits") || "6", 10) || 6;
    const period = parseInt(q.searchParams.get("period") || "30", 10) || 30;
    const alg = (q.searchParams.get("algorithm") || "SHA1").toUpperCase();
    if (alg !== "SHA1") return null; // non-default params: copy the URI instead
    const counter = Math.floor(Date.now() / 1000 / period);
    const buf = new ArrayBuffer(8);
    new DataView(buf).setUint32(4, counter);
    const key = await subtle.importKey("raw", ab(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
    const mac = u8(await subtle.sign("HMAC", key, buf));
    const off = mac[mac.length - 1] & 0xf;
    const code = (((mac[off] & 0x7f) << 24) | (mac[off + 1] << 16) | (mac[off + 2] << 8) | mac[off + 3]) % 10 ** digits;
    return { code: String(code).padStart(digits, "0"), period, secondsLeft: period - (Math.floor(Date.now() / 1000) % period) };
  }

  return { createPairing, finishPairing, unwrapPaste, prfEval, prfSalt, hkdf, sha256, totp,
           SEED_INFO, PASTE_INFO, SEED_AAD,
           b64: bytesRawToB64, unb64: b64ToBytesRaw, bytesToHex, hexToBytes };
})();
