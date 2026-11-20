/**
 * THE VAULT LOGIC (the pure, the node-testable): the envelope's shape,
 * the item upsert/tombstone/rev — the JS twin of the Android's
 * VaultMerge rules (the uuid-keyed, the newer-modifyTime-wins).
 *
 * The envelope's shape = the Proton Pass JSON export envelope extended
 * with the sync bookkeeping: {rev, deviceId, deletedItemUuids,
 * vaults: {local: {items: [ProtonItem...]}}}.
 */

export function parseEnvelope(text) {
  const env = JSON.parse(text);
  if (!env.vaults?.local) throw new Error("no vaults.local in the envelope");
  return env;
}

export function serialize(env) { return JSON.stringify(env); }

export function items(env) {
  return env.vaults.local.items || [];
}

export function listSummary(env) {
  return items(env)
    .filter((it) => !(env.deletedItemUuids || []).includes(it.data.metadata.itemUuid))
    .map((it) => ({
      uuid: it.data.metadata.itemUuid,
      name: it.data.metadata.name,
      username: it.data.content.itemUsername,
      modifyTime: it.data.content.modifyTime ?? 0,
    }))
    .sort((a, b) => (b.modifyTime - a.modifyTime) || a.name.localeCompare(b.name));
}

export function findItem(env, uuid) {
  return items(env).find((it) => it.data.metadata.itemUuid === uuid) || null;
}

/** The upsert: the uuid-keyed, the modifyTime = NOW (the edit wins —
 *  the same stamp rule the Android's save applies). The rev bumps. */
export function upsertItem(env, item) {
  const uuid = item.data.metadata.itemUuid ||
    ("ext-" + crypto.randomUUID());
  item.data.metadata.itemUuid = uuid;
  item.data.content.modifyTime = Math.floor(Date.now() / 1000);
  if (!item.itemId) item.itemId = uuid;
  if (!item.shareId) item.shareId = "local";
  if (item.state === undefined) item.state = 1;
  const list = items(env);
  const idx = list.findIndex((it) => it.data.metadata.itemUuid === uuid);
  if (idx >= 0) list[idx] = item; else list.push(item);
  env.vaults.local.items = list;
  env.rev = (env.rev || 0) + 1;
  // The resurrection: the tombstone cleared (the entry re-added).
  env.deletedItemUuids = (env.deletedItemUuids || []).filter((u) => u !== uuid);
  return env;
}

/** The tombstone: the entry marked deleted; the list pruned; the rev
 *  bumps. The delete survives the merges (the same rule). */
export function tombstone(env, uuid) {
  env.deletedItemUuids = [...(env.deletedItemUuids || []), uuid];
  env.vaults.local.items = items(env)
    .filter((it) => it.data.metadata.itemUuid !== uuid);
  env.rev = (env.rev || 0) + 1;
  return env;
}

/** The union-merge: the JS twin of the Android's VaultMerge — the
 *  uuid-keyed, the newer modifyTime wins, the tombstones survive, the
 *  rev = max+1. */
export function unionMerge(mine, theirs) {
  const byUuid = new Map();
  for (const it of items(mine)) byUuid.set(it.data.metadata.itemUuid, it);
  for (const it of items(theirs)) {
    const existing = byUuid.get(it.data.metadata.itemUuid);
    if (!existing) { byUuid.set(it.data.metadata.itemUuid, it); continue; }
    const a = existing.data.content.modifyTime ?? 0;
    const b = it.data.content.modifyTime ?? 0;
    if (b > a) byUuid.set(it.data.metadata.itemUuid, it);
  }
  const deleted = new Set([...(mine.deletedItemUuids || []),
    ...(theirs.deletedItemUuids || [])]);
  return {
    rev: Math.max(mine.rev || 0, theirs.rev || 0) + 1,
    deviceId: mine.deviceId || theirs.deviceId,
    deletedItemUuids: [...deleted],
    vaults: { local: { items: [...byUuid.values()].filter((it) =>
      !deleted.has(it.data.metadata.itemUuid)) } },
  };
}
