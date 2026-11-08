"use strict";

const msgEl = document.getElementById("msg");
const progressEl = document.getElementById("progress");
const entriesEl = document.getElementById("entries");
const fillMsg = document.getElementById("fillmsg");
const video = document.getElementById("v");
const canvas = document.getElementById("c");
const ctx = canvas.getContext("2d", { willReadFrequently: true });

// Fill target: captured by the popup BEFORE this window opened.
const targetTabId = (() => {
  const t = new URLSearchParams(location.search).get("tab");
  return t == null ? null : parseInt(t, 10);
})();

let done = false;
let entries = [];   // {name, username, password, totpUri}
let stopTotp = null;

// ---- camera + QRFT assembly -----------------------------------------------

function stopCamera() {
  try { video.srcObject.getTracks().forEach((t) => t.stop()); } catch (e) {}
}

const reassembler = new LpQrft.Reassembler();

function scanLoop() {
  if (done) return;
  requestAnimationFrame(scanLoop);
  if (video.readyState < 2 || video.videoWidth === 0) return;
  const scale = Math.min(1, 720 / video.videoWidth);
  canvas.width = Math.round(video.videoWidth * scale);
  canvas.height = Math.round(video.videoHeight * scale);
  ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
  const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
  const code = jsQR(img.data, img.width, img.height, { inversionAttempts: "dontInvert" });
  if (code && code.data) {
    if (reassembler.error) {
      // Hostile/broken transfer: stop scanning, show why (H3).
      done = true;
      stopCamera();
      msgEl.textContent = "Bad transfer: " + reassembler.error;
      return;
    }
    const res = reassembler.push(code.data);
    if (reassembler.error) {
      done = true;
      stopCamera();
      msgEl.textContent = "Bad transfer: " + reassembler.error;
      return;
    }
    progressEl.textContent = reassembler.got + " / " + reassembler.total + " chunks";
    if (res) handlePayload(res.name, res.text);
  }
}

navigator.mediaDevices.getUserMedia({
  video: { facingMode: "user", width: { ideal: 1280 } },
  audio: false,
}).then((stream) => {
  video.srcObject = stream;
  video.play();
  scanLoop();
}).catch((e) => {
  msgEl.textContent = "Camera failed: " + (e.message || e.name);
});

// ---- payload handling ------------------------------------------------------

function handlePayload(name, text) {
  done = true;
  stopCamera();
  let obj;
  try { obj = JSON.parse(text); } catch (e) {
    msgEl.textContent = "Payload is not JSON: " + e.message; return;
  }
  if (obj && obj.type === "linuxpass-device") {
    offerRestore(obj.device).catch((e) => { msgEl.textContent = "Restore failed: " + (e.message || e.name); });
    return;
  }
  if (obj && obj.type === "linuxpass-wrap") {
    prepareDecrypt(text).catch((e) => {
      msgEl.textContent = "Decrypt failed: " + (e.message || e.name);
      entriesEl.textContent = "";
    });
    return;
  }
  const items = parseProtonItems(obj);
  if (!items.length) {
    msgEl.textContent = "Payload did not parse as Proton Pass JSON.";
    return;
  }
  msgEl.textContent = "Received \"" + name + "\" (plain QRFT paste).";
  showEntries(items);
}

function parseProtonItems(obj) {
  const out = [];
  const push = (o) => {
    const d = o && o.data;
    if (d && d.content) {
      out.push({
        name: (d.metadata && d.metadata.name) || "(unnamed)",
        username: d.content.itemUsername || d.content.itemEmail || "",
        password: d.content.password || "",
        totpUri: d.content.totpUri || "",
        urls: (d.content.urls || []).filter(Boolean),
      });
    }
  };
  if (Array.isArray(obj)) obj.forEach(push);
  else if (obj && obj.vaults) {
    for (const k of Object.keys(obj.vaults)) (obj.vaults[k].items || []).forEach(push);
  } else push(obj);
  return out;
}

async function prepareDecrypt(text) {
  const w = JSON.parse(text);
  const devices = await LpStore.devices();
  // Any one of the paste's targets that we have locally will open it.
  const match = (w.targets || [])
    .map((t) => devices.find((d) => d.keyId === t.keyId))
    .find(Boolean);
  if (!match) {
    msgEl.textContent = "No paired key for " +
      (w.targets || []).map((t) => t.keyId).join(", ") +
      " — pair it first (toolbar → Pair a security key) or restore the pairing QR.";
    return;
  }
  // Explicit button: the security-key touch is a deliberate user action,
  // and the click guarantees a user gesture for the WebAuthn ceremony.
  msgEl.textContent = "Encrypted paste for key \"" + match.name + "\" — insert + touch it.";
  const btn = document.createElement("button");
  btn.textContent = "Decrypt (touch key)";
  btn.addEventListener("click", async () => {
    btn.disabled = true;
    msgEl.textContent = "Touch your security key…";
    try {
      const plain = await LpWrap.unwrapPaste(match, text);
      msgEl.textContent = "Decrypted (key " + match.name + ").";
      showEntries(parseProtonItems(JSON.parse(plain)));
    } catch (e) {
      msgEl.textContent = "Decrypt failed: " + (e.message || e.name);
      btn.disabled = false;
    }
  });
  entriesEl.append(btn);
}

/** R2: the phone's "Show pairing QR" re-displays a pairing record (the
 *  vault carries the wrapped seed) — restore it into this browser instead
 *  of re-pairing (same key, same keyId, no duplicate records). */
async function offerRestore(device) {
  done = true;
  stopCamera();
  video.remove();
  progressEl.textContent = "";
  if (!device || !device.keyId || !device.wrapped) {
    msgEl.textContent = "Malformed pairing record."; return;
  }
  const existing = await LpStore.byKeyId(device.keyId);
  const identical = existing && existing.wrapped && existing.wrapped.ct === device.wrapped.ct;
  msgEl.textContent = "Pairing record for \"" + (device.name || "security key") +
    "\" (key " + device.keyId + ")." +
    (identical ? " Already paired here — nothing to do." : "");
  if (identical) return;
  const btn = document.createElement("button");
  btn.textContent = existing ? "Replace existing record" : "Restore pairing on this browser";
  btn.addEventListener("click", async () => {
    btn.disabled = true;
    await LpStore.addDevice(device);
    msgEl.textContent = "Restored \"" + device.name + "\" — pastes to key " + device.keyId +
      " work on this browser now (touch the key to decrypt).";
    setTimeout(() => window.close(), 1500);
  });
  entriesEl.append(btn);
}

// ---- fill UI ---------------------------------------------------------------

// H2: the fill target is the tab captured when the popup opened. Show its
// origin before any fill and warn when an entry's urls[] don't match —
// protects against a tab navigating (or being swapped) between popup open
// and the Fill click.
let targetInfo = null; // { origin, url } | null
let targetGone = false;
let targetBanner = null;

function originOf(url) {
  try { return new URL(url).origin; } catch (e) { return null; }
}

function entryMatchesTarget(item) {
  if (!targetInfo || !targetInfo.origin) return true; // unknown — no signal
  if (!item.urls || !item.urls.length) return true;   // nothing to compare
  return item.urls.some((u) => originOf(u) === targetInfo.origin);
}

function renderTargetBanner() {
  if (!targetBanner) return;
  targetBanner.textContent = targetGone
    ? "⚠ Target tab is gone — reopen the extension on the tab you want to fill."
    : targetInfo
      ? "Will fill into: " + targetInfo.origin
      : "No target tab captured (open via the toolbar popup).";
  targetBanner.style.color = targetGone ? "#ff7f7f" : "#9aa3b2";
}

function refreshTarget() {
  if (targetTabId == null) return Promise.resolve();
  return chrome.tabs.get(targetTabId).then((tab) => {
    targetGone = false;
    targetInfo = { origin: originOf(tab.url || ""), url: tab.url || "" };
    renderTargetBanner();
    document.querySelectorAll(".entry .urlwarn").forEach((el) => {
      const item = entries[Number(el.dataset.idx)];
      if (item) updateUrlWarning(el, Number(el.dataset.idx));
    });
  }).catch(() => {
    targetGone = true;
    targetInfo = null;
    renderTargetBanner();
  });
}

function updateUrlWarning(warnEl, idx) {
  const item = entries[idx];
  if (!item) return;
  if (!entryMatchesTarget(item)) {
    warnEl.textContent = "⚠ This entry lists " + item.urls.join(", ") +
      " — the target tab is " + (targetInfo ? targetInfo.origin : "unknown") + ". Check before filling.";
    warnEl.style.display = "block";
  } else {
    warnEl.style.display = "none";
  }
}

function showEntries(items) {
  entries = items;
  entriesEl.textContent = "";
  video.remove();
  progressEl.textContent = "";
  if (stopTotp) stopTotp();
  targetBanner = document.createElement("div");
  targetBanner.className = "kv";
  entriesEl.append(targetBanner);
  renderTargetBanner();
  refreshTarget();
  items.forEach((item, idx) => {
    const box = document.createElement("div");
    box.className = "entry";
    const h = document.createElement("h3"); h.textContent = item.name; box.append(h);
    const warn = document.createElement("div"); warn.className = "kv urlwarn";
    warn.dataset.idx = String(idx);
    warn.style.color = "#ffd75e"; warn.style.display = "none";
    box.append(warn);
    const u = document.createElement("div"); u.className = "kv";
    u.textContent = "username: "; const uv = document.createElement("span"); uv.className = "v";
    uv.textContent = item.username || "(none)"; u.append(uv); box.append(u);
    const p = document.createElement("div"); p.className = "kv";
    p.textContent = "password: "; const pv = document.createElement("span"); pv.className = "v";
    pv.textContent = "•".repeat(Math.min(item.password.length, 12));
    p.append(pv); box.append(p);
    const btns = document.createElement("div");
    const fill = document.createElement("button");
    fill.textContent = "Fill in tab";
    const reveal = document.createElement("button"); reveal.className = "secondary";
    reveal.textContent = "Reveal";
    const copy = document.createElement("button"); copy.className = "secondary";
    copy.textContent = "Copy password";
    btns.append(fill, reveal, copy);
    box.append(btns);
    let shown = false;
    reveal.addEventListener("click", () => {
      shown = !shown;
      pv.textContent = shown ? item.password : "•".repeat(Math.min(item.password.length, 12));
      reveal.textContent = shown ? "Hide" : "Reveal";
    });
    copy.addEventListener("click", async () => {
      await navigator.clipboard.writeText(item.password);
      item.password = ""; // single copy — drop it
      copy.textContent = "Copied"; copy.disabled = true;
    });
    fill.addEventListener("click", () => fillTab(item));
    entriesEl.append(box);
    if (item.totpUri) {
      const t = document.createElement("div"); t.className = "kv";
      t.textContent = "TOTP: "; const code = document.createElement("span"); code.className = "totp";
      t.append(code); box.append(t);
      const tick = async () => {
        const r = await LpWrap.totp(item.totpUri);
        if (r) code.textContent = r.code + " (" + r.secondsLeft + "s)";
      };
      tick(); const timer = setInterval(tick, 1000);
      stopTotp = () => clearInterval(timer);
      const tc = document.createElement("button"); tc.className = "secondary"; tc.textContent = "Copy code";
      tc.addEventListener("click", async () => {
        const r = await LpWrap.totp(item.totpUri);
        if (r) await navigator.clipboard.writeText(r.code);
      });
      box.append(tc);
    }
  });
}

async function fillTab(item) {
  fillMsg.textContent = "";
  if (targetTabId == null) { fillMsg.textContent = "No target tab (open via the toolbar popup)."; return; }
  let tab;
  try {
    tab = await chrome.tabs.get(targetTabId); // re-check at click time (H2)
  } catch (e) {
    fillMsg.textContent = "Target tab is gone — reopen the extension on the tab you want to fill.";
    return;
  }
  targetInfo = { origin: originOf(tab.url || ""), url: tab.url || "" };
  renderTargetBanner();
  try {
    await chrome.scripting.executeScript({ target: { tabId: targetTabId }, files: ["fill.js"] });
    const res = await chrome.tabs.sendMessage(targetTabId, {
      type: "linuxpass-fill", username: item.username, password: item.password,
    });
    if (res && res.ok) {
      fillMsg.textContent = "Filled" + (res.count > 1 ? " (" + res.count + " password fields)" : "") + " — closing…";
      item.password = ""; entries.forEach((e) => { e.password = ""; });
      setTimeout(() => window.close(), 900);
    } else {
      fillMsg.textContent = "No login fields found on that tab" + (res && res.error ? ": " + res.error : ".");
    }
  } catch (e) {
    fillMsg.textContent = "Fill failed: " + (e.message || e.name);
  }
}