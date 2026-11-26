/**
 * THE SYNC E2E (the tier-2's missing piece): syncVault's FULL
 * orchestration — the fetch → the card decrypt of BOTH sides → the
 * union-merge → the commit → the push — against the smart-HTTP
 * fixture, with the FAKE CARD (the software RSA key from fakecard.mjs)
 * standing in for the hardware. This is the transaction the extension's
 * whole repo mode (and the import's one-commit claim) rides on.
 *
 * The FS seam: git.js's syncVault/cloneVault take an injectable fs
 * (the app omits it → LightningFS's IndexedDB store); the test passes
 * a node-backed shim rooted at a temp dir. THE SEAM IS THE POINT —
 * the orchestration must be testable without the browser store.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { rsaRecipient, fakeRsaCard, envelopeTo } from "./fakecard.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
globalThis.window = globalThis;
globalThis.self = globalThis;
const require = createRequire(import.meta.url);
const git = require("../lib/isogit.umd.min.js");
// git.js's gitLib()/httpLib() read the browser globals the UMD script
// tags set — in node the test sets them from the same bundles.
globalThis.git = git;
globalThis.GitHttp = require("../lib/isogit-http.umd.js").default ||
  require("../lib/isogit-http.umd.js");

const { startSmartHttp, FIXTURE_TOKEN } = await import("./smhttp.mjs");
const { syncVault } = await import("../git.js");

const httpLib = () => require("../lib/isogit-http.umd.js").default ||
  require("../lib/isogit-http.umd.js");

const auth = () => ({ username: "x", password: FIXTURE_TOKEN });

let server, remoteUrl, root;

before(async () => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), "op-sync-"));
  const bare = path.join(root, "test.git");
  execFileSync("git", ["init", "--bare", bare]);
  execFileSync("git", ["-C", bare, "config", "http.receivepack", "true"]);
  server = await startSmartHttp(root, 0);
  remoteUrl = server.url;
});

after(() => { try { server.close(); } catch { /* */ } });

const item = (uuid, name) => ({
  itemId: uuid, shareId: "local", state: 1,
  data: { type: "login",
    metadata: { name, itemUuid: uuid },
    content: { itemUsername: "u", itemEmail: "", password: "pw",
      urls: [], totpUri: "", modifyTime: 1 } } });

test("syncVault: the diverged sides merge (both items survive), the push advances the remote", async () => {
  const recipient = await rsaRecipient();
  const card = fakeRsaCard(recipient, "old");

  // The REMOTE's vault: rev 1, carrying "Remote Item" — seeded via the
  // LOCAL bare-path clone (no HTTP in the seeding; the CLI would prompt
  // at the fixture's auth).
  const remoteEnv = {
    rev: 1, deviceId: "remote-dev", deletedItemUuids: [],
    vaults: { local: { items: [item("r-1", "Remote Item")] } },
  };
  const seed = path.join(root, "seed");
  const bare = path.join(root, "test.git");
  execFileSync("git", ["clone", "--quiet", bare, seed]);
  fs.mkdirSync(path.join(seed, "state"), { recursive: true });
  fs.mkdirSync(path.join(seed, "keys", "encrypt"), { recursive: true });
  // The recipient's PUBLIC key rides in the repo (the seal's source — the
  // same contract app.js's persist uses); the card holds the private side.
  fs.writeFileSync(path.join(seed, "keys/encrypt/test.pub.asc"),
    recipient.key.publicKey.armor());
  fs.writeFileSync(path.join(seed, "state/10.gpg"),
    await envelopeTo([recipient], JSON.stringify(remoteEnv)));
  execFileSync("git", ["-C", seed, "add", "."]);
  execFileSync("git", ["-C", seed, "-c", "user.name=t", "-c", "user.email=t@t",
    "commit", "-m", "the remote's rev 1"]);
  execFileSync("git", ["-C", seed, "push", "--quiet", "origin", "main"]);

  // The LOCAL side: the clone → the rev 2 carrying "Local Item" (the
  // sync's decrypt of BOTH sides then diverges on the rev + the items).
  const dir = path.join(root, "work", "offlinepass");
  fs.mkdirSync(dir, { recursive: true });
  await git.clone({ fs, http: httpLib(),
    url: remoteUrl, dir, ref: "main", singleBranch: true,
    onAuth: auth });
  const localEnv = {
    rev: 2, deviceId: "local-dev", deletedItemUuids: [],
    vaults: { local: { items: [item("l-1", "Local Item")] } },
  };
  await fs.promises.mkdir(path.join(dir, "state"), { recursive: true });
  fs.writeFileSync(path.join(dir, "state/10.gpg"),
    await envelopeTo([recipient], JSON.stringify(localEnv)));
  await git.commit({
    fs, dir,
    message: "the local's rev 2",
    author: { name: "t", email: "t@t" },
  });

  // THE SYNC: the fetch → the both-side decrypts (the fake card) → the
  // union → the commit → the push (the fast-forward on the FETCHED ref).
  const out = await syncVault({
    httpUrl: remoteUrl, token: FIXTURE_TOKEN,
    card,
    fs, repoDir: dir,
    onLog: () => {},
  });

  assert.equal(out.pushed, true, "the push must succeed (the fetch-first)");
  assert.ok(out.merged, "the diverged sides must merge");
  assert.equal(out.rev, 3, "the merged rev = max(1, 2) + 1");

  // The proof on the REMOTE: a fresh clone of the bare (the push landed)
  // → the decrypt → BOTH items.
  const checkDir = path.join(root, "check");
  execFileSync("git", ["clone", "--quiet", bare, checkDir]);
  const pushed = fs.readFileSync(path.join(checkDir, "state/10.gpg"));
  const { decryptWithCard } = await import("../card/decrypt.js");
  const dec = await decryptWithCard(pushed, card, () => {});
  const env = JSON.parse(new TextDecoder().decode(dec.data));
  const names = env.vaults.local.items.map((it) => it.data.metadata.name).sort();
  assert.deepEqual(names, ["Local Item", "Remote Item"],
    "the union must carry BOTH sides' items");
});
