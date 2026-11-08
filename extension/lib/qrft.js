/**
 * linuxpass QRFT helpers — shared by the scan window (receive) and the pair
 * page (emit). The wire format is the airgap-qr-offline protocol vendored in
 * the Android app (android/app/src/main/assets/qrft/):
 *
 *   metadata frame : JSON.stringify({ name, chunks, size })
 *   data frames    : "<index>,<base64(chunk)>"   (250-byte chunks)
 *
 * The chunk encoding has a quirk we MUST match (upstream encode_data):
 * the raw bytes are turned into a Latin-1 string, then UTF-8-encoded, then
 * base64'd. Decoding inverts that: base64 -> UTF-8 decode -> char codes.
 *
 * Resource caps (constants, valid_meta, safe_inflate) are ported verbatim
 * from ~/3p/airgap-qr-offline's scanner so a hostile QR cannot exhaust
 * memory (decompression bomb) or steer the transfer with a bogus metadata
 * frame.
 */
window.LpQrft = (function () {
  "use strict";

  const CHUNK_SIZE = 250;
  // --- upstream airgap-qr-offline caps (do not diverge) ---
  const MAX_CHUNKS = 1000000;
  const MAX_SIZE = 3 * 1024 * 1024 * 1024;
  const MAX_INFLATED = 3 * 1024 * 1024 * 1024; // cap when no size is declared
  const INFLATE_SLACK = 1024 * 1024;           // slack over a declared size

  function b64ToBytes(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function bytesToB64(bytes) {
    let s = "";
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }

  /** Chunk-frame decode, matching upstream scanner decode_data: base64 →
   *  UTF-8 decode → Latin-1 char codes → original bytes. */
  function decodeChunk(frame) {
    const comma = frame.indexOf(",");
    if (comma <= 0) return null;
    const index = parseInt(frame.slice(0, comma), 10);
    if (isNaN(index) || index < 0) return null;
    const bin = atob(frame.slice(comma + 1));
    const raw = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) raw[i] = bin.charCodeAt(i);
    const str = new TextDecoder().decode(raw);
    return { index, data: Uint8Array.from(str, (c) => c.charCodeAt(0)) };
  }

  /** Chunk-frame encode, matching upstream generator encode_data. */
  function encodeChunk(index, bytes) {
    const latin = String.fromCharCode.apply(null, bytes);
    const utf8 = new TextEncoder().encode(latin);
    return index + "," + btoa(String.fromCharCode.apply(null, utf8));
  }

  /** Upstream valid_meta: reject bogus metadata frames before they steer
   *  the transfer (chunk flood, size lie, junk name). */
  function validMeta(m) {
    if (!m || typeof m !== "object" || Array.isArray(m)) return false;
    if (typeof m.name !== "string" || m.name.length > 5000) return false;
    if (!Number.isInteger(m.chunks) || m.chunks < 1 || m.chunks > MAX_CHUNKS) return false;
    if (m.size !== undefined && m.size !== null) {
      if (!Number.isInteger(m.size) || m.size < 0 || m.size > MAX_SIZE) return false;
    }
    return true;
  }

  /** Upstream safe_inflate: stream the gzip in slices and abort the moment
   *  output exceeds maxOut — a decompression bomb never materializes. */
  function safeInflate(data, maxOut) {
    const inflator = new pako.Inflate();
    const parts = [];
    let total = 0;
    inflator.onData = function (chunk) {
      parts.push(chunk);
      total += chunk.length;
      if (total > maxOut) {
        throw new Error("decompressed data exceeds " + maxOut + " bytes");
      }
    };
    const STEP = 1 << 16;
    for (let i = 0; i < data.length; i += STEP) {
      inflator.push(data.subarray(i, Math.min(i + STEP, data.length)));
      if (inflator.err) {
        throw new Error(inflator.msg || "inflate failed");
      }
      if (inflator.ended) break;
    }
    if (!inflator.ended) {
      throw new Error("truncated deflate stream");
    }
    return { parts, length: total };
  }

  /** Feed camera frames here; resolves when the transfer completes. On a
   *  protocol violation, sets `.error` (the scanner shows it and stops) —
   *  the internal state is reset so scanning can restart cleanly. */
  class Reassembler {
    constructor() {
      this.chunks = {};
      this.total = -1;
      this.name = "";
      this.got = 0;
      this.size = undefined;
      this.rawBytes = 0;
      this.error = null;
    }
    fail(message) {
      this.error = message;
      this.chunks = {};
      this.total = -1;
      this.got = 0;
      this.rawBytes = 0;
    }
    /** Which chunks have landed (for the receiver's progress display). */
    peekChunk(i) { return this.chunks[i]; }
    /** @returns null (keep scanning) or {name, bytes, text} */
    push(data) {
      if (this.error) return null;
      if (data.charAt(0) === "{") {
        try {
          const m = JSON.parse(data);
          if (this.total < 0 && validMeta(m)) {
            this.total = m.chunks;
            this.name = String(m.name || "payload");
            this.size = m.size;
          } else if (this.total < 0 && !validMeta(m)) {
            this.fail("invalid metadata frame");
          }
        } catch (e) { /* not metadata */ }
        return null;
      }
      if (this.total < 0) return null;
      const c = decodeChunk(data);
      if (!c || c.index >= this.total || this.chunks[c.index] !== undefined) return null;
      const cap = (this.size != null ? this.size : 0) + INFLATE_SLACK;
      this.rawBytes += c.data.length;
      if (this.rawBytes > Math.min(cap, MAX_INFLATED)) {
        this.fail("transfer exceeds size cap");
        return null;
      }
      this.chunks[c.index] = c.data;
      this.got++;
      if (this.got < this.total) return null;
      let size = 0;
      for (let i = 0; i < this.total; i++) size += this.chunks[i].length;
      const raw = new Uint8Array(size);
      let off = 0;
      for (let i = 0; i < this.total; i++) { raw.set(this.chunks[i], off); off += this.chunks[i].length; }
      let bytes;
      try {
        const inflated = safeInflate(raw, this.size != null ? this.size + INFLATE_SLACK : MAX_INFLATED);
        bytes = new Uint8Array(inflated.length);
        let b = 0;
        for (const part of inflated.parts) { bytes.set(part, b); b += part.length; }
      } catch (e) {
        this.fail(String(e.message || e));
        return null;
      }
      return { name: this.name, bytes, text: new TextDecoder().decode(bytes) };
    }
  }

  /** Build the looping frame list for a text payload (pair page emit). */
  function buildFrames(name, text) {
    const bytes = new TextEncoder().encode(text);
    const gz = pako.gzip(bytes, { level: 9 });
    const total = Math.ceil(gz.length / CHUNK_SIZE);
    const frames = [JSON.stringify({ name: String(name || "payload"), chunks: total, size: bytes.length })];
    for (let i = 0; i < total; i++) {
      frames.push(encodeChunk(i, gz.subarray(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE)));
    }
    return frames;
  }

  /** Loop frames into a canvas via the vendored qrcode.js; returns stop().
   *  Reuses ONE QRCode instance with clear()/makeCode() — the same pattern
   *  as the vendored generator page (re-creating instances per frame is
   *  what made rotating frames flaky to scan). */
  function loopRender(frames, holder, intervalMs) {
    let i = 0;
    let timer = null;
    const qrcode = new QRCode(holder, { width: 320, height: 320, correctLevel: QRCode.CorrectLevel.L });
    const show = () => {
      qrcode.clear();
      qrcode.makeCode(frames[i]);
      holder.title = "frame " + i + " / " + (frames.length - 1);
      i = (i + 1) % frames.length;
    };
    show();
    timer = setInterval(show, intervalMs || 400);
    return () => clearInterval(timer);
  }

  return { Reassembler, buildFrames, loopRender, validMeta, safeInflate,
           b64ToBytes, bytesToB64, CHUNK_SIZE,
           MAX_CHUNKS, MAX_SIZE, MAX_INFLATED, INFLATE_SLACK };
})();
