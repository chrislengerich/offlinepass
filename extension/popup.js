"use strict";

const msg = document.getElementById("msg");
const devBox = document.getElementById("dev");
const devList = document.getElementById("devlist");

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

async function renderDevices() {
  const list = await LpStore.devices();
  devList.textContent = "";
  if (!list.length) {
    devBox.className = "dev none";
    devBox.textContent = "No security key paired yet.";
    return;
  }
  devBox.className = "dev";
  devBox.textContent = list.length + " key" + (list.length === 1 ? "" : "s") + " paired:";
  list.forEach((d) => {
    const row = document.createElement("div");
    row.className = "devrow";
    const label = document.createElement("span");
    label.textContent = d.name + " (" + d.keyId + ")";
    const forget = document.createElement("button");
    forget.textContent = "Forget";
    forget.title = "Remove this record from this browser (R5). The phone keeps its copy until you remove it there.";
    forget.addEventListener("click", async () => {
      const rest = (await LpStore.devices()).filter((x) => x.keyId !== d.keyId);
      await LpStore.save(rest);
      renderDevices();
    });
    row.append(label, forget);
    devList.append(row);
  });
}

renderDevices().catch((e) => { msg.textContent = String(e); });