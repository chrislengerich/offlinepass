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

// -- THE VAULT AUTOFILL: the stubs in, the keypress-decrypt on select -----
const vaultBox = document.getElementById("vault");
const vaultList = document.getElementById("vaultlist");

/** The active tab's fill: the fill.js injected + the message — the
 *  same contract the scan window's fill uses. */
async function fillTab(password, username) {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const tabId = tabs && tabs[0] && tabs[0].id;
  if (tabId == null) throw new Error("no active tab");
  await chrome.scripting.executeScript({ target: { tabId }, files: ["fill.js"] });
  const res = await chrome.tabs.sendMessage(tabId,
    { type: "offlinepass-fill", password, username });
  if (!res || !res.ok) throw new Error(res && res.error || "the fill failed");
  return res;
}

async function renderVaultStubs() {
  const { stubs } = await chrome.storage.local.get("stubs");
  if (!stubs || !stubs.length) { vaultBox.classList.add("hidden"); return; }
  vaultBox.classList.remove("hidden");
  vaultList.textContent = "";
  for (const it of stubs) {
    const row = document.createElement("button");
    row.className = "secondary";
    row.textContent = `${it.name}${it.username ? " — " + it.username : ""}`;
    row.onclick = async () => {
      msg.textContent = "Touch the security key…";
      try {
        // THE KEYPRESS = THE DECRYPT: the card re-decrypts the synced
        // vault (the LightningFS's 10.gpg persists) and the entry's
        // secret fills the active tab. The touch = per selection —
        // the stubs' metadata never carries the secrets.
        const { OpenPgpCard } = await import("./card/openpgp.js");
        const { decryptWithCard } = await import("./card/decrypt.js");
        const card = await OpenPgpCard.open();
        await card.select();
        const bytes = await new window.LightningFS("offlinepass-fs")
          .promises.readFile("/offlinepass/state/10.gpg");
        const result = await decryptWithCard(bytes, card, (l) => { msg.textContent = l; });
        const env = JSON.parse(new TextDecoder().decode(result.data));
        const items = env.vaults.local.items || [];
        const hit = items.find((x) => x.data.metadata.itemUuid === it.uuid);
        if (!hit) throw new Error("the entry not found in the vault");
        const res = await fillTab(hit.data.content.password || "",
          hit.data.content.itemUsername || "");
        msg.textContent = `filled (${res.count} password field(s))`;
        window.close();
      } catch (e) {
        msg.textContent = "the fill failed: " + e.message;
      }
    };
    vaultList.appendChild(row);
  }
}
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