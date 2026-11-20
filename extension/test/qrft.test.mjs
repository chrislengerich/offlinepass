/**
 * THE QRFT CODEC round-trip on Node — the SAME vendored qrft.js the
 * extension pages load. The window/pako shims = the load mechanics; the
 * asserts = the codec contract (the build → the reassemble → the
 * identical payload; the chunk caps; the checksums).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
globalThis.window = globalThis;
globalThis.self = globalThis;
const require = createRequire(import.meta.url);
globalThis.pako = require("../vendor/pako.min.js");
(0, eval)(fs.readFileSync(path.join(here, "../lib/qrft.js"), "utf8"));
const LpQrft = globalThis.window.LpQrft ?? globalThis.LpQrft;

test("the QRFT round-trip: the build → the reassemble → the identical payload", () => {
  const payload = JSON.stringify({
    rev: 12,
    vaults: { local: { items: [
      { data: { metadata: { name: "GitHub", itemUuid: "u-1" },
        content: { itemUsername: "ko", password: "pw" } } },
      { data: { metadata: { name: "Mail — long note", itemUuid: "u-2" },
        content: { itemUsername: "a@x.org",
          password: "p".repeat(1500),
          note: "n".repeat(900) } } },
    ] } },
  });
  const frames = LpQrft.buildFrames("vault.json", payload);
  assert.ok(frames.length > 1, "the long payload spans the multiple frames");

  const reassembler = new LpQrft.Reassembler();
  let res = null;
  for (const frame of frames) {
    res = reassembler.push(frame);
    if (res) break;
  }
  assert.ok(res, "the reassembler completed");
  assert.equal(res.name, "vault.json");
  assert.equal(res.text, payload);
});

test("the round-trip of the EMPTY-ish payload (the single frame)", () => {
  const frames = LpQrft.buildFrames("tiny", "x");
  const reassembler = new LpQrft.Reassembler();
  let res = null;
  for (const frame of frames) { res = reassembler.push(frame); if (res) break; }
  assert.equal(res.text, "x");
});

test("the chunked frames are independent: the out-of-order delivery tolerated", () => {
  const payload = "z".repeat(800);
  const frames = LpQrft.buildFrames("ooo", payload);
  const reassembler = new LpQrft.Reassembler();
  let res = null;
  // The metadata first, then the DATA frames in REVERSE (the scanner
  // order-independence: the chunks carry their indexes).
  const [meta, ...data] = frames;
  reassembler.push(meta);
  for (const frame of data.reverse()) { res = reassembler.push(frame); if (res) break; }
  assert.ok(res, "the reassembler completed out of order");
  assert.equal(res.text, payload);
});

test("the garbage frame does not poison the reassembler", () => {
  const frames = LpQrft.buildFrames("g", "the payload");
  const reassembler = new LpQrft.Reassembler();
  reassembler.push(frames[0]);
  // The garbage data frame.
  try { reassembler.push("99999,not-base64!!!"); } catch (e) { /* the cap */ }
  let res = null;
  for (const frame of frames.slice(1)) { res = reassembler.push(frame); if (res) break; }
  assert.ok(res, "the real frames still complete after the garbage");
  assert.equal(res.text, "the payload");
});
