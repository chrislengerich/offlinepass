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
 */
window.LpQrft = (function () {
  "use strict";

  const CHUNK_SIZE = 250;

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

  /** Feed camera frames here; resolves when the transfer completes. */
  class Reassembler {
    constructor() {
      this.chunks = {};
      this.total = -1;
      this.name = "";
      this.got = 0;
    }
    /** @returns null (keep scanning) or {name, bytes, text} */
    push(data) {
      if (data.charAt(0) === "{") {
        try {
          const m = JSON.parse(data);
          if (typeof m.chunks === "number" && this.total < 0) {
            this.total = m.chunks;
            this.name = String(m.name || "payload");
            this.size = m.size;
          }
        } catch (e) { /* not metadata */ }
        return null;
      }
      if (this.total < 0) return null;
      const c = decodeChunk(data);
      if (!c || c.index >= this.total || this.chunks[c.index] !== undefined) return null;
      this.chunks[c.index] = c.data;
      this.got++;
      if (this.got < this.total) return null;
      let size = 0;
      for (let i = 0; i < this.total; i++) size += this.chunks[i].length;
      const raw = new Uint8Array(size);
      let off = 0;
      for (let i = 0; i < this.total; i++) { raw.set(this.chunks[i], off); off += this.chunks[i].length; }
      const bytes = pako.ungzip(raw);
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

  /** Loop frames into a canvas via the vendored qrcode.js; returns stop(). */
  function loopRender(frames, holder, intervalMs) {
    let i = 0;
    let timer = null;
    const show = () => {
      holder.innerHTML = "";
      holder.title = "frame " + i + " / " + (frames.length - 1);
      new QRCode(holder, { text: frames[i], width: 320, height: 320, correctLevel: QRCode.CorrectLevel.L });
      i = (i + 1) % frames.length;
    };
    show();
    timer = setInterval(show, intervalMs || 400);
    return () => clearInterval(timer);
  }

  return { Reassembler, buildFrames, loopRender, b64ToBytes, bytesToB64, CHUNK_SIZE };
})();
