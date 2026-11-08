// Toolbar click → straight into the interaction. No popup, no default
// surface: a paired key goes straight to the scan window (fill target =
// the tab that was active at click time); an unpaired key goes straight
// to pairing. Everything else (menu, self-test, forget) is reachable from
// the scan window's menu link. The activeTab grant is issued BY this
// click for the active tab — the extension never touches a site without it.
chrome.action.onClicked.addListener(async (tab) => {
  const { devices } = await chrome.storage.local.get("devices");
  const paired = Array.isArray(devices) && devices.length > 0;
  const q = tab && tab.id != null ? "?tab=" + tab.id : "";
  chrome.windows.create({
    url: (paired ? "scan.html" : "pair.html") + q,
    type: "popup",
    width: 560,
    height: paired ? 720 : 800,
    focused: true,
  });
});