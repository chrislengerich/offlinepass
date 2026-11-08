"use strict";

const msg = document.getElementById("msg");
const qr = document.getElementById("qr");
const recordBox = document.getElementById("record");
const btnPair = document.getElementById("btn_pair");
const btnShow = document.getElementById("btn_show");

let pending = null;   // {credId, salt} between the two touch steps
let lastRecord = null;
let stopLoop = null;

function showQr(record) {
  if (stopLoop) stopLoop();
  stopLoop = null;
  qr.innerHTML = "";
  const payload = JSON.stringify({ type: "offlinepass-device", device: record });
  recordBox.textContent = payload;
  // Single STATIC QR: pairing is one small payload — a static code gives
  // the phone's scanner unlimited attempts (a rotating QRFT loop stalls
  // easily on focus/timing). Fall back to the QRFT loop only if the record
  // ever outgrows one QR.
  try {
    new QRCode(qr, { text: payload, width: 400, height: 400, correctLevel: QRCode.CorrectLevel.L });
    qr.title = "pairing record (single QR)";
  } catch (e) {
    const frames = LpQrft.buildFrames("offlinepass-device", payload);
    stopLoop = LpQrft.loopRender(frames, qr, 600);
  }
}

btnPair.addEventListener("click", async () => {
  btnPair.disabled = true;
  if (!pending) {
    // Step 1: create the credential in the key (touch #1).
    msg.textContent = "Touch your security key to CREATE the pairing credential…";
    try {
      pending = await LpWrap.createPairing();
      msg.textContent = "Credential created. Touch AGAIN to derive + wrap the paste key…";
      btnPair.textContent = "Finish pairing (touch again)";
      btnPair.disabled = false;
      return;
    } catch (e) {
      msg.textContent = "Pairing failed: " + (e.message || e.name) +
        (e.name === "NotAllowedError" ? " — (PRF/hmac-secret unsupported by this key? See docs.)" : "");
      btnPair.disabled = false;
      return;
    }
  }
  // Step 2: PRF eval + seed wrap (touch #2).
  msg.textContent = "Touch your security key to derive the paste key…";
  try {
    const record = await LpWrap.finishPairing(
      pending.credId, pending.salt, document.getElementById("name").value);
    lastRecord = record;
    await LpStore.addDevice(record);
    pending = null;
    msg.textContent = "Paired. Scan the QR with the phone (Setup → Import from QRFT).";
    showQr(record);
    btnShow.disabled = false;
    btnPair.textContent = "Pair security key";
  } catch (e) {
    msg.textContent = "Pairing failed: " + (e.message || e.name);
  }
  btnPair.disabled = false;
});

btnShow.addEventListener("click", () => lastRecord && showQr(lastRecord));

// Re-show the QR for the most recent pairing if the page was reopened.
LpStore.devices().then((list) => {
  if (list.length) {
    lastRecord = list[list.length - 1];
    btnShow.disabled = false;
  }
});