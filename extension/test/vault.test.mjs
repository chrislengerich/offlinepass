/** THE VAULT LOGIC tests: the upsert/tombstone/merge/rev — the JS twin
 *  of the Android's rules, pinned. */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  parseEnvelope, serialize, items, listSummary, findItem,
  upsertItem, tombstone, unionMerge,
} from "../vault.js";

const env = () => ({ rev: 3, deviceId: "d1", deletedItemUuids: [],
  vaults: { local: { items: [
    proton("u-1", "GitHub", "ko", "pw1", 100),
    proton("u-2", "Mail", "alice", "pw2", 200),
  ] } } });

function proton(uuid, name, user, pass, mod) {
  return { itemId: uuid, shareId: "local", state: 1,
    data: { type: "login",
      metadata: { name, itemUuid: uuid },
      content: { itemUsername: user, password: pass,
        modifyTime: mod, itemEmail: "", urls: [], totpUri: "" } } };
}

test("listSummary: the names sorted by the modifyTime desc", () => {
  const list = listSummary(env());
  assert.deepEqual(list.map((x) => x.name), ["Mail", "GitHub"]);
});

test("upsert: the existing item replaced, the rev bumps, the modifyTime = now", () => {
  const e = env();
  const it = findItem(e, "u-1");
  it.data.metadata.name = "GitHub Enterprise";
  const before = Math.floor(Date.now() / 1000);
  upsertItem(e, it);
  assert.equal(e.rev, 4);
  assert.equal(findItem(e, "u-1").data.metadata.name, "GitHub Enterprise");
  assert.ok(findItem(e, "u-1").data.content.modifyTime >= before);
});

test("upsert: a NEW item appended + the resurrection clears the tombstone", () => {
  const e = env();
  const it = proton("u-9", "New", "n", "p", 0);
  upsertItem(e, it);
  tombstone(e, "u-9");
  upsertItem(e, proton("u-9", "New", "n", "p", 0));
  assert.equal(e.rev, 6);
  assert.ok(findItem(e, "u-9"));
  assert.ok(!e.deletedItemUuids.includes("u-9"));
});

test("tombstone: the entry removed, the marker survives, the rev bumps", () => {
  const e = env();
  tombstone(e, "u-1");
  assert.equal(e.rev, 4);
  assert.ok(e.deletedItemUuids.includes("u-1"));
  assert.ok(!findItem(e, "u-1"));
  assert.equal(listSummary(e).length, 1);
});

test("unionMerge: the newer modifyTime wins; the both-sides adds kept; the rev = max+1", () => {
  const mine = env();   // the u-1's mod 100
  const theirs = { rev: 5, deviceId: "d2", deletedItemUuids: [],
    vaults: { local: { items: [
      proton("u-1", "GitHub", "ko", "theirs-wins", 900),
      proton("u-3", "Bank", "me", "pw3", 50),
    ] } } };
  const merged = unionMerge(mine, theirs);
  assert.equal(merged.rev, 6);
  const byName = Object.fromEntries(listSummary(merged).map((x) => [x.name, x]));
  assert.deepEqual(Object.keys(byName).sort(), ["Bank", "GitHub", "Mail"]);
  assert.equal(findItem(merged, "u-1").data.content.password, "theirs-wins");
});

test("unionMerge: the tombstone beats the newer item (the delete survives)", () => {
  const mine = env();
  tombstone(mine, "u-2");
  const theirs = { rev: 9, deviceId: "d2", deletedItemUuids: [],
    vaults: { local: { items: [
      proton("u-2", "Mail", "alice", "pw2-newer", 9999) ] } } };
  const merged = unionMerge(mine, theirs);
  assert.ok(!findItem(merged, "u-2"), "the tombstoned entry stays deleted");
  assert.equal(merged.rev, 10);
});

test("the serialize/parse round-trip is lossless", () => {
  const e = env();
  assert.deepEqual(parseEnvelope(serialize(e)), e);
});
