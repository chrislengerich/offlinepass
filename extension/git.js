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

/** The isomorphic-git's built-in fetch-based HTTP client. */
function httpLib() {
  const h = gitLib().http;
  if (!h) throw new Error("the isomorphic-git bundle lacks the http client");
  return h;
}

/** The vault's current plaintext (the decrypted by the card, on
 *  demand): reads state/10.gpg from the FS and runs the card pipeline. */
export async function currentPlaintext(fs, card, token, httpUrl, onLog = () => {}) {
  const git = gitLib();
  const bytes = await fs.promises.readFile(`${REPO_DIR}/${VAULT_PATH}`);
  const result = await decryptWithCard(bytes, card, onLog);
  return new TextDecoder().decode(result.data);
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
 *  the push. The credentials = the Basic with the token. */
export async function syncVault({ httpUrl, token, card, onLog = () => {} }) {
  const git = gitLib();
  const fs = new (window.LightningFS)("offlinepass-fs");
  const dir = REPO_DIR;
  const author = { name: "offlinepass-extension", email: "offlinepass@ext.local" };
  const out = { pushed: false, fetched: false, merged: false, rev: null };

  // The remote state first (the fetch = cheap; the tracking = isogit's).
  onLog("fetching…");
  await git.fetch({ fs, http: httpLib(), httpUrl, token, dir });
  out.fetched = true;

  // The local vault's plaintext (the decrypted on demand).
  let localPlain = null, hasLocal = false;
  try {
    localPlain = await currentPlaintext(fs, card, token, httpUrl, onLog);
    hasLocal = true;
  } catch (e) { onLog(`the local decrypt: ${e.message} — proceeding remote-only`); }

  // The remote's plaintext (the fetched 10.gpg).
  let remotePlain = null;
  try {
    const oid = await git.resolveRef({ fs, dir, ref: "refs/remotes/origin/main" });
    const { blob } = await git.readBlob({ fs, dir, oid, filepath: VAULT_PATH });
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
  await fs.promises.mkdir(`${dir}/state`, { recursive: true });
  await fs.promises.writeFile(`${dir}/${VAULT_PATH}`,
    new TextEncoder().encode(mergedPlain));
  await git.add({ fs, dir, filepath: VAULT_PATH });
  await git.commit({ fs, dir, message: `Update 10.gpg (rev ${merged.rev})`, author });
  try {
    await git.push({ fs, http: httpLib(), httpUrl, token, dir, force: false });
    out.pushed = true;
  } catch (e) {
    onLog(`the push failed (${e.message}) — the local commit stays, retried next sync`);
  }
  return out;
}

/** The one-time clone (the fresh device). */
export async function cloneVault({ httpUrl, token, card, onLog = () => {} }) {
  const git = gitLib();
  const fs = new (window.LightningFS)("offlinepass-fs");
  const dir = REPO_DIR;
  await git.clone({ fs, http: httpLib(), httpUrl, token, dir, depth: 50 });
  onLog("cloned");
  return syncVault({ httpUrl, token, card, onLog });
}
