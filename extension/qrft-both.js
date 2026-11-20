/**
 * THE QRFT BOTH DIRECTIONS (the phase 4):
 *  - the export-to-phone: the payload → the frames (LpQrft.buildFrames)
 *    → the QR canvases (qrcode-generator's UMD) → the sequential render
 *    (the phone's scanner advances on each stable frame — the same loop
 *    the pair page's loopRender runs, re-hosted here with the canvas).
 *  - the import-from-phone: the camera (getUserMedia) → the frames to
 *    jsQR → LpQrft.Reassembler → the payload.
 */
export function buildQr(payload) {
  // The typeNumber = 0 (the auto); the ECC = 'L' (the max data density —
  // the phone's scanner handles the density fine at the 15-30cm range).
  const qr = window.qrcode(0, "L");
  qr.addData(payload, "Byte");
  qr.make();
  return qr; // .getModuleCount() / .isDark(r, c) — the render draws it.
}

export function drawQrToCanvas(qr, canvas, scale = 6, quiet = 4) {
  const count = qr.getModuleCount();
  const size = (count + quiet * 2) * scale;
  canvas.width = size; canvas.height = size;
  const ctx = canvas.getContext("2d");
  ctx.fillStyle = "#fff"; ctx.fillRect(0, 0, size, size);
  ctx.fillStyle = "#000";
  for (let r = 0; r < count; r++) {
    for (let c = 0; c < count; c++) {
      if (qr.isDark(r, c)) {
        ctx.fillRect((c + quiet) * scale, (r + quiet) * scale, scale, scale);
      }
    }
  }
  return size;
}

/** The export loop: the frames rendered one at a time into the canvas,
 *  the index displayed; the phone's scanner advances (the same contract
 *  as loopRender: the frame stays until the scanner's ack — here, the
 *  manual Next + the auto-advance timer). */
export async function renderFrames(name, text, canvas, statusFn = () => {}, frameMs = 1200) {
  const frames = window.LpQrft.buildFrames(name, text);
  for (let i = 0; i < frames.length; i++) {
    const qr = buildQr(frames[i]);
    drawQrToCanvas(qr, canvas);
    statusFn(`frame ${i + 1} / ${frames.length} — hold the scanner steady`);
    await new Promise((r) => setTimeout(r, frameMs));
  }
  statusFn("done — all frames rendered");
  return frames.length;
}

/** The import loop: the camera → jsQR → the Reassembler. */
export async function cameraImport(video, statusFn = () => {}, signal) {
  const stream = await navigator.mediaDevices.getUserMedia({
    video: { facingMode: "environment", width: { ideal: 1280 } },
  });
  video.srcObject = stream;
  await video.play();
  const canvas = document.createElement("canvas");
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  const reassembler = new window.LpQrft.Reassembler();
  let lastText = null;

  const done = new Promise((resolve, reject) => {
    signal?.addEventListener("abort", () => reject(new Error("cancelled")));
    const tick = async () => {
      if (signal?.aborted) return;
      if (video.videoWidth) {
        canvas.width = video.videoWidth; canvas.height = video.videoHeight;
        ctx.drawImage(video, 0, 0);
        const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const code = window.jsQR(img.data, canvas.width, canvas.height);
        if (code && code.data && code.data !== lastText) {
          lastText = code.data;
          try {
            // The push returns the payload {name, text} when complete.
            const res = reassembler.push(code.data);
            if (res) { resolve(res); return; }
            statusFn(reassembler.total < 0
              ? "waiting for the metadata frame…"
              : `${reassembler.got} / ${reassembler.total} chunks`);
          } catch (e) { statusFn(`frame rejected: ${e.message}`); }
        }
      }
      requestAnimationFrame(() => setTimeout(tick, 150));
    };
    tick();
  });
  try {
    return await done;   // { name, text } — the reassembled payload
  } finally {
    stream.getTracks().forEach((t) => t.stop());
    video.srcObject = null;
  }
}
