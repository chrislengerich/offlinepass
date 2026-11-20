/**
 * THE EXTENSION'S APP (the phases 3+4 wired): the unlock (the sync's
 * clone-or-fetch → the card decrypt; or the file fallback), the
 * entries' full CRUD (the re-encrypt to the repo's recipient keys →
 * the commit → the push), the sync pipeline, the QRFT both directions.
 * Everything vendored; the only network = the git transport.
 */
import { OpenPgpCard } from "./card/openpgp.js";
import { decryptWithCard } from "./card/decrypt.js";
import { cloneVault, syncVault } from "./git.js";
import { parseEnvelope, serialize, listSummary, findItem,
  upsertItem, tombstone } from "./vault.js";
import { renderFrames, cameraImport } from "./qrft-both.js";

const $ = (id) => document.getElementById(id);
const log = (line) => { $("log").textContent += line + "\n";
  $("log").scrollTop = $("log").scrollHeight; };
const show = (id) => {
  for (const s of ["settings", "entries", "detail", "qrftImport"])
    $(id).classList.toggle("hidden", s !== id);
};

const state = { card: null, env: null, url: "", token: "", currentUuid: null };
const REPO_DIR = "/offlinepass";
const VAULT_PATH = "state/10.gpg";

function fs() { return new window.LightningFS("offlinepass-fs"); }
function gitLib() { return window.git; }
function httpLib() { return window.GitHttp; }

async function ensureCard() {
  if (!state.card) {
    state.card = await OpenPgpCard.open();
    await state.card.select();
    log(`the card: applet ${(await state.card.version())}`);
  }
  return state.card;
}

/** The vault file's read: the synced clone's 10.gpg, decrypted. */
async function loadVaultFromFs() {
  const bytes = await fs().promises.readFile(`${REPO_DIR}/${VAULT_PATH}`);
  const result = await decryptWithCard(bytes, await ensureCard(), log);
  state.env = parseEnvelope(new TextDecoder().decode(result.data));
}

/** The recipients' public keys: the repo's keys/encrypt/*.pub.asc —
 *  the openpgp.js reads the armored keys. The card's DEC pubkey also
 *  qualifies (the read = unauthenticated). */
async function recipientKeys() {
  const out = [];
  try {
    const dir = `${REPO_DIR}/keys/encrypt`;
    const names = await fs().promises.readdir(dir);
    for (const name of names.filter((n) => n.endsWith(".pub.asc"))) {
      const armor = await fs().promises.readFile(`${dir}/${name}`, "utf8");
      out.push(await openpgp.readKey({ armoredKey: armor }));
    }
  } catch (e) { log(`the recipient keys: ${e.message} — the card's key only`); }
  if (!out.length) {
    // The fallback: the card's DEC public key (the GET DATA) → the
    // openpgp.js's key = the RSA/ECDH material from the DO — the
    // prototype's limitation: the recipients = the repo's keys; without
    // them the save can't re-encrypt (the honest error).
    throw new Error("no recipient keys in the synced repo (keys/encrypt/) — " +
      "sync once with the phone first");
  }
  return out;
}

/** The re-encrypt + the write + the commit (+ the push attempt). */
async function persist() {
  const bytes = new TextEncoder().encode(serialize(state.env));
  const keys = await recipientKeys();
  const msg = await openpgp.createMessage({ binary: bytes });
  const encrypted = await openpgp.encrypt({ message: msg,
    encryptionKeys: keys, format: "binary" });
  await fs().promises.mkdir(`${REPO_DIR}/state`, { recursive: true });
  await fs().promises.writeFile(`${REPO_DIR}/${VAULT_PATH}`, encrypted);
  const git = gitLib();
  await git.add({ fs: fs(), dir: REPO_DIR, filepath: VAULT_PATH });
  await git.commit({ fs: fs(), dir: REPO_DIR,
    message: `Update 10.gpg (rev ${state.env.rev})`,
    author: { name: "offlinepass-extension", email: "offlinepass@ext.local" } });
  try {
    await git.push({ fs: fs(), http: httpLib(), httpUrl: state.url,
      token: state.token, dir: REPO_DIR, force: false });
    log(`pushed (rev ${state.env.rev})`);
  } catch (e) { log(`the push failed — the local commit stays (${e.message})`); }
}

// -- the screens -----------------------------------------------------------

function renderList() {
  const list = listSummary(state.env);
  $("count").textContent = `(${list.length})`;
  $("list").innerHTML = "";
  for (const it of list) {
    const li = document.createElement("li");
    li.textContent = `${it.name}${it.username ? " — " + it.username : ""}`;
    li.onclick = () => openDetail(it.uuid);
    $("list").appendChild(li);
  }
  show("entries");
}

function openDetail(uuid) {
  state.currentUuid = uuid;
  const it = findItem(state.env, uuid);
  $("dName").textContent = it.data.metadata.name;
  $("eName").value = it.data.metadata.name;
  $("eUrls").value = (it.data.content.urls || []).join(", ");
  $("eUser").value = it.data.content.itemUsername || "";
  $("eEmail").value = it.data.content.itemEmail || "";
  $("ePass").value = it.data.content.password || "";
  $("eTotp").value = it.data.content.totpUri || "";
  $("eNote").value = it.data.metadata.note || "";
  $("qr").classList.add("hidden");
  show("detail");
}

function editedItem() {
  const it = findItem(state.env, state.currentUuid);
  const copy = JSON.parse(JSON.stringify(it));
  copy.data.metadata.name = $("eName").value.trim();
  copy.data.content.urls = $("eUrls").value.split(",").map((u) => u.trim()).filter(Boolean);
  copy.data.content.itemUsername = $("eUser").value;
  copy.data.content.itemEmail = $("eEmail").value;
  copy.data.content.password = $("ePass").value;
  copy.data.content.totpUri = $("eTotp").value;
  copy.data.metadata.note = $("eNote").value;
  return copy;
}

// -- the handlers ----------------------------------------------------------

$("btnClone").onclick = async () => {
  try {
    state.url = $("url").value.trim(); state.token = $("token").value.trim();
    await cloneVault({ httpUrl: state.url, token: state.token,
      card: await ensureCard(), onLog: log });
    await loadVaultFromFs();
    renderList();
  } catch (e) { log("the clone failed: " + e.message); }
};

$("btnSync").onclick = async () => {
  try {
    state.url = $("url").value.trim(); state.token = $("token").value.trim();
    const out = await syncVault({ httpUrl: state.url, token: state.token,
      card: await ensureCard(), onLog: log });
    log(`the sync done: ${JSON.stringify(out)}`);
    await loadVaultFromFs();
    renderList();
  } catch (e) { log("the sync failed: " + e.message); }
};

$("file").onchange = async () => {
  try {
    const bytes = new Uint8Array(await $("file").files[0].arrayBuffer());
    await decryptWithCard(bytes, await ensureCard(), log)
      .then((r) => { state.env = parseEnvelope(new TextDecoder().decode(r.data)); });
    // The file-open = no repo yet: the state.env lives in memory until
    // the sync configures the remote.
    renderList();
  } catch (e) { log("the open failed: " + e.message); }
};

$("btnSyncTop").onclick = () => $("btnSync").click();

$("btnAdd").onclick = () => {
  // The blank item = the upsert with the fresh uuid.
  state.currentUuid = null;
  for (const id of ["eName", "eUrls", "eUser", "eEmail", "ePass", "eTotp", "eNote"])
    $(id).value = "";
  $("dName").textContent = "(new entry)";
  show("detail");
};

$("btnSave").onclick = async () => {
  try {
    const item = state.currentUuid
      ? editedItem()
      : { itemId: "", shareId: "local", state: 1,
          data: { type: "login",
            metadata: { name: $("eName").value.trim(), itemUuid: "" },
            content: { itemUsername: $("eUser").value,
              itemEmail: $("eEmail").value, password: $("ePass").value,
              urls: $("eUrls").value.split(",").map((u) => u.trim()).filter(Boolean),
              totpUri: $("eTotp").value, passkeys: [],
              modifyTime: 0 }, extraFields: [], platformSpecific: {} } };
    upsertItem(state.env, item);
    await persist();
    state.currentUuid = item.data.metadata.itemUuid;
    $("dName").textContent = item.data.metadata.name;
    renderList();
    show("detail");
    log("saved");
  } catch (e) { log("the save failed: " + e.message); }
};

$("btnDel").onclick = async () => {
  try {
    tombstone(state.env, state.currentUuid);
    await persist();
    renderList();
  } catch (e) { log("the delete failed: " + e.message); }
};

$("btnBack").onclick = () => renderList();

// The QRFT export: the entry's JSON → the frames → the canvas render.
$("btnQr").onclick = async () => {
  try {
    const it = findItem(state.env, state.currentUuid);
    const payload = JSON.stringify({ entries: [it] });
    $("qr").classList.remove("hidden");
    await renderFrames("offlinepass-entry", payload, $("qr"),
      (s) => log(s), 1500);
  } catch (e) { log("the QRFT render failed: " + e.message); }
};

// The QRFT import: the camera → the reassembler → the upsert.
$("btnImport").onclick = async () => {
  try {
    show("qrftImport");
    const payload = await cameraImport($("video"),
      (s) => { $("qrStatus").textContent = s; });
    const parsed = JSON.parse(payload.text);
    const entries = parsed.entries || parsed.vaults?.local?.items ||
      (parsed.data ? [parsed] : []);
    for (const it of entries) {
      const uuid = it.data?.metadata?.itemUuid;
      const existing = uuid && findItem(state.env, uuid);
      if (existing) {
        // The dedupe: the local kept (the same rule).
        log(`skipped ${it.data.metadata.name} (the local kept)`);
        continue;
      }
      upsertItem(state.env, it);
      log(`imported ${it.data.metadata.name}`);
    }
    await persist();
    renderList();
  } catch (e) { log("the QRFT import failed: " + e.message); }
};
$("btnQrCancel").onclick = () => { renderList(); };

// The boot: the settings' persisted values.
chrome.storage?.local?.get(["url", "token"], (v) => {
  if (v.url) $("url").value = v.url;
  if (v.token) $("token").value = v.token;
});
$("url").onchange = () => chrome.storage?.local?.set({ url: $("url").value });
show("settings");
