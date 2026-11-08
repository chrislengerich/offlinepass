"use strict";

const msg = document.getElementById("msg");
const devBox = document.getElementById("dev");
const devList = document.getElementById("devlist");

function openWindow(page) {
  // Capture the paste target BEFORE opening the scan window — unless the
  // popup itself was opened from the scan window's menu link, which passes
  // the original target through (?tab=).
  const urlTab = new URLSearchParams(location.search).get("tab");
  const resolveTab = urlTab != null
    ? Promise.resolve({ id: parseInt(urlTab, 10) })
    : new Promise((res) => chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => res(tabs && tabs[0] ? tabs[0] : {})));
  resolveTab.then((t) => {
    const tabId = t && t.id != null ? t.id : null;
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