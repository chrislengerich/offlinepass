/**
 * THE VAULT SYNC (the phase 3): isomorphic-git over HTTPS with a
 * token, the LightningFS (IndexedDB) working tree, and the vault-level
 * merge pipeline — the same shape as the Android's syncNow:
 *
 *   fetch → decrypt both sides (the card) → union-merge → re-encrypt →
 *   commit → push.
 *
 * Everything runs from the vendored files; the only network = the git
 * transport itself (HTTPS).
 */
import * as openpgp from "./lib/openpgp.mjs";
import { decryptWithCard } from "./card/decrypt.js";

const REPO_DIR = "/offlinepass";
const VAULT_PATH = "state/10.gpg";

/** The isomorphic-git's module: the UMD global (the lib sets
 *  window.git / the module.exports — the extension's import via the
 *  script tag in the host page; this module lazily grabs it). */
function gitLib() {
  const g = (typeof window !== "undefined" && window.git) ||
    (typeof globalThis !== "undefined" && globalThis.git);
  if (!g) throw new Error("the isomorphic-git bundle not loaded (the script tag first)");
  return g;
}

/** The isomorphic-git's HTTP client: the SEPARATE UMD bundle
 *  (lib/isogit-http.umd.js → the global GitHttp), the fetch-based. */
function httpLib() {
  const h = typeof window !== "undefined" && window.GitHttp;
  if (!h) throw new Error("the isomorphic-git HTTP bundle not loaded (the script tag first)");
  return h;
}

/** The vault's current plaintext (the decrypted by the card, on
 *  demand): reads state/10.gpg from the FS and runs the card pipeline.
 *  The [dir] = the repo dir override (the tests' absolute dir; the app
 *  omits it). */
export async function currentPlaintext(fs, card, token, httpUrl, onLog = () => {}, dir = REPO_DIR) {
  const git = gitLib();
  const bytes = await fs.promises.readFile(`${dir}/${VAULT_PATH}`);
  const result = await decryptWithCard(bytes, card, onLog);
  return new TextDecoder().decode(result.data);
}

/** The recipients' public keys: the repo's keys/encrypt/*.pub.asc — the
 *  SAME contract app.js's persist() uses for its saves. [fsP] = the
 *  normalized promises API (the caller's `fsp.promises ?? fsp`). */
async function recipientKeys(fsP, dir) {
  let names;
  try { names = await fsP.readdir(`${dir}/keys/encrypt`); }
  catch (e) {
    throw new Error("no recipient keys in the synced repo (keys/encrypt/) — " +
      "sync once with the phone first");
  }
  const out = [];
  for (const name of names.filter((n) => n.endsWith(".pub.asc"))) {
    const armor = await fsP.readFile(`${dir}/keys/encrypt/${name}`, "utf8");
    out.push(await openpgp.readKey({ armoredKey: armor }));
  }
  if (!out.length) {
    throw new Error("no recipient keys in the synced repo (keys/encrypt/) — " +
      "sync once with the phone first");
  }
  return out;
}

/** The envelope JSON's item extraction + the union-merge (the SAME
 *  rules as the Android's VaultMerge: the uuid-keyed, the newer
 *  modifyTime wins, the tombstones survive). */
export function unionMerge(current, incoming) {
  const cur = JSON.parse(current);
  const inc = JSON.parse(incoming);
  const rev = Math.max(cur.rev || 0, inc.rev || 0) + 1;
  const byUuid = new Map();
  for (const it of cur.vaults?.local?.items || []) byUuid.set(it.data.metadata.itemUuid, it);
  for (const it of inc.vaults?.local?.items || []) {
    const existing = byUuid.get(it.data.metadata.itemUuid);
    if (!existing) { byUuid.set(it.data.metadata.itemUuid, it); continue; }
    const a = existing.data.content.modifyTime ?? existing.data.modifyTime ?? 0;
    const b = it.data.content.modifyTime ?? it.data.modifyTime ?? 0;
    if (b > a) byUuid.set(it.data.metadata.itemUuid, it);
  }
  // The tombstones: the union.
  const deleted = new Set([...(cur.deletedItemUuids || []),
    ...(inc.deletedItemUuids || [])]);
  const items = [...byUuid.values()].filter((it) =>
    !deleted.has(it.data.metadata.itemUuid));
  return JSON.stringify({ rev, deviceId: cur.deviceId || inc.deviceId || "ext",
    deletedItemUuids: [...deleted], vaults: { local: { items } } }, null, 0);
}

/** THE FULL SYNC: the fetch → the merge (if diverged) → the commit →
 *  the push. The credentials = the Basic with the token. The [fs] and
 *  [repoDir] params = the test seams (the app omits them → the
 *  LightningFS's IndexedDB tree at the standard repo path; the tests
 *  inject the node fs + the absolute dir). */
export async function syncVault({ httpUrl, token, card, fs: fsOverride = null, repoDir = null, onLog = () => {} }) {
  const git = gitLib();
  const fsp = fsOverride ?? new (window.LightningFS)("offlinepass-fs");
  const fsPromises = fsp.promises ?? fsp;
  const dir = repoDir ?? REPO_DIR;
  const author = { name: "offlinepass-extension", email: "offlinepass@ext.local" };
  const out = { pushed: false, fetched: false, merged: false, rev: null };

  // The remote state first (the fetch = cheap; the tracking = isogit's).
  onLog("fetching…");
  await git.fetch({ fs: fsp, http: httpLib(), url: httpUrl, dir,
    onAuth: () => ({ username: "x", password: token }) });
  out.fetched = true;

  // The local vault's plaintext (the decrypted on demand).
  let localPlain = null, hasLocal = false;
  try {
    localPlain = await currentPlaintext(fsp, card, token, httpUrl, onLog, dir);
    hasLocal = true;
  } catch (e) { onLog(`the local decrypt: ${e.message} — proceeding remote-only`); }

  // The remote's plaintext (the fetched 10.gpg).
  let remotePlain = null;
  try {
    const oid = await git.resolveRef({ fs: fsp, dir, ref: "refs/remotes/origin/main" });
    const { blob } = await git.readBlob({ fs: fsp, dir, oid, filepath: VAULT_PATH });
    const remoteResult = await decryptWithCard(blob, card, onLog);
    remotePlain = new TextDecoder().decode(remoteResult.data);
  } catch (e) {
    onLog(`the remote read: ${e.message} — treating the remote as absent`);
  }

  // The merge: the union (the SAME rules as the Android's VaultMerge).
  let mergedPlain = null;
  if (localPlain && remotePlain) {
    const a = JSON.parse(localPlain), b = JSON.parse(remotePlain);
    if (a.rev === b.rev && JSON.stringify(a) === JSON.stringify(b)) {
      mergedPlain = localPlain;  // in sync
    } else {
      mergedPlain = unionMerge(localPlain, remotePlain);
      out.merged = true;
    }
  } else mergedPlain = remotePlain || localPlain;
  if (!mergedPlain) throw new Error("nothing to sync — neither side decryptable");
  const merged = JSON.parse(mergedPlain);
  out.rev = merged.rev;

  // The write + the commit + the push (the ALWAYS: the local truth).
  // THE RE-ENCRYPT FIRST: the merged plaintext NEVER touches the repo —
  // the write/commit/push carry the sealed envelope (the recipients =
  // the repo's keys/encrypt/*.pub.asc). No keys → abort BEFORE the
  // write: committing plaintext would defeat the whole design.
  const keys = await recipientKeys(fsPromises, dir);
  const sealed = await openpgp.encrypt({
    message: await openpgp.createMessage({
      binary: new TextEncoder().encode(mergedPlain) }),
    encryptionKeys: keys, format: "binary",
  });
  await fsPromises.mkdir(`${dir}/state`, { recursive: true });
  await fsPromises.writeFile(`${dir}/${VAULT_PATH}`, sealed);
  await git.add({ fs: fsp, dir, filepath: VAULT_PATH });
  await git.commit({ fs: fsp, dir, message: `Update 10.gpg (rev ${merged.rev})`, author });
  try {
    await git.push({ fs: fsp, http: httpLib(), url: httpUrl, dir, force: false,
    onAuth: () => ({ username: "x", password: token }) });
    out.pushed = true;
  } catch (e) {
    onLog(`the push failed (${e.message}) — the local commit stays, retried next sync`);
  }
  return out;
}

/** The one-time clone (the fresh device). The [fs]/[repoDir] params =
 *  the same test seams [syncVault] has. */
export async function cloneVault({ httpUrl, token, card, fs: fsOverride = null, repoDir = null, onLog = () => {} }) {
  const git = gitLib();
  const fsp = fsOverride ?? new (window.LightningFS)("offlinepass-fs");
  const dir = repoDir ?? REPO_DIR;
  await git.clone({ fs: fsp, http: httpLib(), url: httpUrl, dir, depth: 50,
    onAuth: () => ({ username: "x", password: token }) });
  onLog("cloned");
  return syncVault({ httpUrl, token, card, fs: fsp, repoDir: dir, onLog });
}
