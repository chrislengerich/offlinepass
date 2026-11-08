"use strict";

const msg = document.getElementById("msg");
const devBox = document.getElementById("dev");

function openWindow(page) {
  // Capture the paste target BEFORE opening the scan window (the scan
  // window itself will be the focused one from then on).
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tabId = tabs && tabs[0] ? tabs[0].id : null;
    const url = page + (tabId != null ? "?tab=" + tabId : "");
    chrome.windows.create({ url, type: "popup", width: 560, height: 720, focused: true });
    window.close();
  });
}

document.getElementById("btn_scan").addEventListener("click", () => openWindow("scan.html"));
document.getElementById("btn_pair").addEventListener("click", () => openWindow("pair.html"));
document.getElementById("btn_test").addEventListener("click", () => openWindow("selftest.html"));
document.getElementById("lnk_docs").addEventListener("click", (e) => { e.preventDefault(); window.close(); });

chrome.storage.local.get("devices").then((o) => {
  const list = o.devices || [];
  if (!list.length) return;
  devBox.className = "dev";
  devBox.textContent = list.length === 1
    ? "Paired: " + list[0].name + " (" + list[0].keyId + ")"
    : list.length + " keys paired";
}).catch((e) => { msg.textContent = String(e); });