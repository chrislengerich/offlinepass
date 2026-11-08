/** chrome.storage.local helpers — the extension persists PUBLIC data only:
 *  paired device records carry the credential id, public key, and the
 *  AES-GCM-wrapped seed (never plaintext key material). */
window.LpStore = (function () {
  "use strict";
  const KEY = "devices";

  async function devices() {
    const o = await chrome.storage.local.get(KEY);
    return o[KEY] || [];
  }

  async function save(list) {
    await chrome.storage.local.set({ [KEY]: list });
  }

  async function addDevice(record) {
    const list = await devices();
    const i = list.findIndex((d) => d.keyId === record.keyId);
    if (i >= 0) list[i] = record; else list.push(record);
    await save(list);
    return list;
  }

  async function byKeyId(keyId) {
    return (await devices()).find((d) => d.keyId === keyId) || null;
  }

  return { devices, save, addDevice, byKeyId };
})();
