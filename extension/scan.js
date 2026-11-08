"use strict";

const msgEl = document.getElementById("msg");
const progressEl = document.getElementById("progress");
const entriesEl = document.getElementById("entries");
const fillMsg = document.getElementById("fillmsg");
const video = document.getElementById("v");
const canvas = document.getElementById("c");
const ctx = canvas.getContext("2d", { willReadFrequently: true });

// Menu link → the popup page (pair another key / self-test / forget),
// passing the original fill target through so the popup's windows keep
// targeting the right tab.
document.getElementById("btn_menu").addEventListener("click", (e) => {
  e.preventDefault();
  const q = targetTabId != null ? "?tab=" + targetTabId : "";
  chrome.windows.create({ url: "popup.html" + q, type: "popup", width: 320, height: 460, focused: true });
  window.close(); // the camera window is replaced by the menu
});

// Fill target: captured by the popup BEFORE this window opened.
const targetTabId = (() => {
  const t = new URLSearchParams(location.search).get("tab");
  return t == null ? null : parseInt(t, 10);
})();

let done = false;
let entries = [];   // {name, username, password, totpUri, urls}
let stopTotp = null;

// ---- camera + QRFT assembly -----------------------------------------------

function stopCamera() {
  try { video.srcObject.getTracks().forEach((t) => t.stop()); } catch (e) {}
}

const reassembler = new LpQrft.Reassembler();
let lastGot = -1;
let lastProgressAt = 0;

function progressText() {
  if (reassembler.total < 0) return "waiting for the sender's metadata frame…";
  const missing = [];
  for (let i = 0; i < reassembler.total; i++) {
    if (reassembler.peekChunk(i) === undefined) missing.push(i + 1);
  }
  const base = reassembler.got + " / " + reassembler.total + " chunks";
  return missing.length ? base + " — waiting for chunk " + missing.join(", ") : base;
}

function scanLoop() {
  if (done) return;
  requestAnimationFrame(scanLoop);
  if (video.readyState < 2 || video.videoWidth === 0) return;
  const scale = Math.min(1, 720 / video.videoWidth);
  canvas.width = Math.round(video.videoWidth * scale);
  canvas.height = Math.round(video.videoHeight * scale);
  ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
  const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
  const code = jsQR(img.data, img.width, img.height, { inversionAttempts: "attemptBoth" });
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
    progressEl.textContent = progressText();
    const now = performance.now();
    if (reassembler.got !== lastGot) {
      lastGot = reassembler.got;
      lastProgressAt = now;
    } else if (reassembler.total > 0 && now - lastProgressAt > 5000) {
      progressEl.textContent = progressText() +
        " — no progress in 5s: hold the phone steady, or slow the sender (its speed selector)";
    }
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
  if (obj && obj.type === "offlinepass-device") {
    offerRestore(obj.device).catch((e) => { msgEl.textContent = "Restore failed: " + (e.message || e.name); });
    return;
  }
  if (obj && obj.type === "offlinepass-ssh-pubkey") {
    showSshPubkey(obj).catch((e) => { msgEl.textContent = "SSH key display failed: " + (e.message || e.name); });
    return;
  }
  if (obj && obj.type === "offlinepass-wrap") {
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
  deliver(items);
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
  // No button: the ceremony starts the moment the QR is complete. The
  // window is top-level (no user-gesture requirement) and the security
  // gate is the key's own PIN + touch, which always happens.
  msgEl.textContent = "Encrypted paste for key \"" + match.name + "\" — insert it, then PIN + touch…";
  try {
    const plain = await LpWrap.unwrapPaste(match, text);
    msgEl.textContent = "Decrypted (key " + match.name + ").";
    deliver(parseProtonItems(JSON.parse(plain)));
  } catch (e) {
    msgEl.textContent = "Decrypt failed: " + (e.message || e.name);
  }
}

/** Deliver decrypted entries: URL-match against the target tab → auto-fill
 *  (no UI); no match → the entry cards. */
async function deliver(items) {
  await refreshTarget();
  const best = bestMatch(items);
  if (best) {
    msgEl.textContent = "Matched " + (targetInfo ? targetInfo.origin : "tab") +
      " — filling \"" + best.name + "\"…";
    const ok = await fillTab(best);
    if (ok) return; // window closed by fillTab
    // Fill couldn't find fields — fall back to the cards.
    msgEl.textContent = "Auto-fill found no login fields on the tab — fill manually.";
  }
  showEntries(items);
}

/** URL matching: scheme-insensitive, host-only, `www.` stripped, and a
 *  subdomain counts as a match (entry "domain.com" matches tab
 *  "sub.domain.com" and vice versa). Returns 2 (exact host), 1 (subdomain
 *  relation), 0 (no match). */
function hostOf(u) {
  try {
    const s = /^[a-z][a-z0-9+.-]*:\/\//i.test(u) ? u : "https://" + u;
    return new URL(s).hostname.toLowerCase().replace(/^www\./, "");
  } catch (e) { return null; }
}

function matchScore(item, tabUrl) {
  const tab = hostOf(tabUrl || "");
  if (!tab || !item.urls || !item.urls.length) return 0;
  let best = 0;
  for (const u of item.urls) {
    const e = hostOf(u);
    if (!e) continue;
    if (e === tab) return 2;
    if (tab.endsWith("." + e) || e.endsWith("." + tab)) best = Math.max(best, 1);
  }
  return best;
}

function bestMatch(items) {
  if (!targetInfo || !targetInfo.url) return null;
  let best = null, bestScore = 0;
  for (const it of items) {
    const s = matchScore(it, targetInfo.url);
    if (s > bestScore) { best = it; bestScore = s; }
  }
  return best;
}

/** SSH-sync enrollment: the phone shows its screenlock keystore key's
 *  OpenSSH public line; the user copies it into GitHub as a repo deploy
 *  key (write access) so syncs authenticate without a PAT. */
async function showSshPubkey(obj) {
  done = true;
  stopCamera();
  video.remove();
  progressEl.textContent = "";
  const line = String(obj.sshKey || "");
  if (!line.includes(" ")) { msgEl.textContent = "Malformed SSH public key."; return; }
  msgEl.textContent = "Public key captured — copy it into GitHub:";
  const key = document.createElement("div");
  key.className = "kv";
  const kv = document.createElement("span"); kv.className = "v";
  kv.style.wordBreak = "break-all";
  kv.textContent = line;
  key.append(kv);
  entriesEl.append(key);
  const btns = document.createElement("div");
  const copy = document.createElement("button");
  copy.textContent = "Copy public key";
  copy.addEventListener("click", async () => {
    await navigator.clipboard.writeText(line);
    copy.textContent = "Copied"; copy.disabled = true;
  });
  btns.append(copy);
  entriesEl.append(btns);
  const hint = document.createElement("div"); hint.className = "kv";
  hint.innerHTML = "GitHub → the vault repo → <b>Settings → Deploy keys</b> → " +
    "Add deploy key → paste → tick <b>Allow write access</b> → Add. Then on the " +
    "phone: Setup → Connect remote → git@github.com:&lt;owner&gt;/&lt;repo&gt;.git → " +
    "every sync opens with the screen lock.";
  hint.style.color = "#9aa3b2";
  entriesEl.append(hint);
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

// ---- fill UI (shown only when nothing matched) ------------------------------

// H2: the fill target is the tab captured when the popup opened. Show its
// origin and warn when an entry's urls[] don't relate to it.
let targetInfo = null; // { origin, url } | null
let targetGone = false;
let targetBanner = null;

function originOf(url) {
  try { return new URL(url).origin; } catch (e) { return null; }
}

/** Lenient (subdomain-aware) relation used for WARNINGS: no entry URLs or
 *  no target info ⇒ no signal, no warning. */
function entryMatchesTarget(item) {
  if (!targetInfo || !targetInfo.url) return true;
  if (!item.urls || !item.urls.length) return true;
  return matchScore(item, targetInfo.url) > 0;
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
      updateUrlWarning(el, Number(el.dataset.idx));
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
    // Per-card copy: Copy/Fill may zero the shared entry object; Reveal and
    // Hide must keep working afterwards.
    const passwordValue = item.password;
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
    const btns = document.createElement("div");
    const fill = document.createElement("button");
    fill.textContent = "Fill in tab";
    const reveal = document.createElement("button"); reveal.className = "secondary";
    const copy = document.createElement("button"); copy.className = "secondary";
    if (!passwordValue) {
      // Nothing to reveal or copy — say so instead of a no-op button.
      reveal.textContent = "No password";
      reveal.disabled = true;
      copy.textContent = "No password";
      copy.disabled = true;
    } else {
      const pv = document.createElement("div"); pv.className = "kv";
      pv.textContent = "password: "; const pvSpan = document.createElement("span"); pvSpan.className = "v";
      pvSpan.textContent = "•".repeat(Math.min(passwordValue.length, 12));
      pv.append(pvSpan); box.append(pv);
      reveal.textContent = "Reveal";
      copy.textContent = "Copy password";
      let shown = false;
      reveal.addEventListener("click", () => {
        shown = !shown;
        pvSpan.textContent = shown ? passwordValue : "•".repeat(Math.min(passwordValue.length, 12));
        reveal.textContent = shown ? "Hide" : "Reveal";
      });
      copy.addEventListener("click", async () => {
        await navigator.clipboard.writeText(passwordValue);
        copy.textContent = "Copied"; copy.disabled = true;
      });
    }
    btns.append(fill, reveal, copy);
    box.append(btns);
    fill.addEventListener("click", async () => { await fillTab(item); });
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

/** Fills the captured tab; resolves true when fields were found (the
 *  window closes right then), false otherwise (cards stay usable). */
async function fillTab(item) {
  fillMsg.textContent = "";
  if (targetTabId == null) { fillMsg.textContent = "No target tab (open via the toolbar popup)."; return false; }
  let tab;
  try {
    tab = await chrome.tabs.get(targetTabId); // re-check at click time (H2)
  } catch (e) {
    fillMsg.textContent = "Target tab is gone — reopen the extension on the tab you want to fill.";
    return false;
  }
  targetInfo = { origin: originOf(tab.url || ""), url: tab.url || "" };
  try {
    await chrome.scripting.executeScript({ target: { tabId: targetTabId }, files: ["fill.js"] });
    const res = await chrome.tabs.sendMessage(targetTabId, {
      type: "offlinepass-fill", username: item.username, password: item.password,
    });
    if (res && res.ok) {
      item.password = ""; entries.forEach((e) => { e.password = ""; });
      window.close(); // filled — popup gone immediately
      return true;
    }
    fillMsg.textContent = "No login fields found on that tab" + (res && res.error ? ": " + res.error : ".");
    return false;
  } catch (e) {
    fillMsg.textContent = "Fill failed: " + (e.message || e.name);
    return false;
  }
}