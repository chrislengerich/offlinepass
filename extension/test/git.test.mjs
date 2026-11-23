/**
 * THE GIT SYNC E2E (the tier-2 from the test plan): the smart-HTTP
 * server + the isomorphic-git's clone/commit/push round-trip on Node —
 * the SAME git.js calls the extension pages make, with the node's fs
 * instead of the LightningFS.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
globalThis.window = globalThis;
globalThis.self = globalThis;
// The isomorphic-git's UMD = the require-able; the http client = the built-in.
const require = createRequire(import.meta.url);
const git = require("../lib/isogit.umd.min.js");
const http = require("../lib/isogit-http.umd.js").default ||
  require("../lib/isogit-http.umd.js");

const { startSmartHttp, FIXTURE_TOKEN } = await import("./smhttp.mjs");

let server, remoteUrl, workdir;

before(async () => {
  // The bare repo (the fixture) with the initial commit: the vault file
  // + the keys/ dir (the structure the extension expects).
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "op-git-"));
  const bare = path.join(root, "test.git");
  execFileSync("git", ["init", "--bare", bare]);
  execFileSync("git", ["-C", bare, "config", "http.receivepack", "true"]);
  // The seed: a scratch clone → the commit → the push (the git CLI).
  const seed = path.join(root, "seed");
  execFileSync("git", ["clone", "--quiet", bare, seed]);
  fs.mkdirSync(path.join(seed, "state"), { recursive: true });
  fs.writeFileSync(path.join(seed, "state/10.gpg"), Buffer.from([1, 2, 3]));
  fs.mkdirSync(path.join(seed, "keys"), { recursive: true });
  fs.writeFileSync(path.join(seed, "keys/README"), "the fixture");
  execFileSync("git", ["-C", seed, "add", "."]);
  execFileSync("git", ["-C", seed, "-c", "user.name=t", "-c", "user.email=t@t",
    "commit", "-m", "the fixture seed"]);
  execFileSync("git", ["-C", seed, "push", "--quiet", "origin", "main"]);

  server = await startSmartHttp(root, 0);
  remoteUrl = server.url;
  workdir = path.join(os.tmpdir(), `op-work-${Date.now()}`);
  fs.mkdirSync(workdir, { recursive: true });
});

after(() => { try { server.close(); } catch (e) { /* */ } });

const fsParams = () => fs;   // The node's fs = the isogit's FS for the tests

test("the clone: the fresh dir → the remote's HEAD + the files", async () => {
  const dir = path.join(workdir, "clone");
  fs.mkdirSync(dir, { recursive: true });
  await git.clone({ fs: fsParams(), http, url: remoteUrl, dir,
    ref: "main", singleBranch: true,
    onAuth: () => ({ username: "x", password: FIXTURE_TOKEN }) });
  const blob = await git.readBlob({ fs: fsParams(), dir,
    oid: await git.resolveRef({ fs: fsParams(), dir, ref: "refs/remotes/origin/main" }),
    filepath: "state/10.gpg" });
  assert.deepEqual([...blob.blob], [1, 2, 3]);
});

test("the wrong token: the auth failure surfaces as actionable (no silent retry)", async () => {
  const dir = path.join(workdir, "clone-badtoken");
  fs.mkdirSync(dir, { recursive: true });
  await assert.rejects(
    git.clone({ fs: fsParams(), http, url: remoteUrl, dir,
      ref: "main", singleBranch: true,
      onAuth: () => ({ username: "x", password: "the-wrong-token" }) }),
    (e) => /401|Unauthorized|auth/i.test(String(e.message ?? e)),
    "the wrong token must surface the auth failure — the UI's message builds on it");
});

test("the commit + the push: the tracking ref + the remote advance", async () => {
  const dir = path.join(workdir, "clone");
  // The local commit: the modified vault.
  fs.writeFileSync(path.join(dir, "state/10.gpg"), Buffer.from([9, 9]));
  await git.add({ fs: fsParams(), dir, filepath: "state/10.gpg" });
  await git.commit({ fs: fsParams(), dir,
    message: "Update 10.gpg (the test)",
    author: { name: "offlinepass-extension", email: "offlinepass@ext.local" } });
  await git.push({ fs: fsParams(), http, url: remoteUrl, dir,
    ref: "main", onAuth: () => ({ username: "x", password: FIXTURE_TOKEN }) });

  // THE PUSH-BY-NAME CONTRACT: the tracking ref must advance (the
  // Setup's ahead/behind reads it).
  const tracking = await git.resolveRef({ fs: fsParams(), dir,
    ref: "refs/remotes/origin/main" });
  const head = await git.resolveRef({ fs: fsParams(), dir, ref: "refs/heads/main" });
  assert.equal(tracking, head, "origin/main advanced with the push");

  // THE REMOTE: the ls-remote sees it.
  const ls = await git.getRemoteInfo({ fs: fsParams(), http,
    url: remoteUrl, onAuth: () => ({ username: "x", password: FIXTURE_TOKEN }) });
  assert.equal(ls.refs?.heads?.main, head, "the remote's main = the pushed head");
});

test("the fetch: the remote's new commit arrives via the tracking ref", async () => {
  // The SECOND workdir pushes a newer commit.
  const dir2 = path.join(workdir, "second");
  await git.clone({ fs: fsParams(), http, url: remoteUrl, dir: dir2,
    ref: "main", singleBranch: true,
    onAuth: () => ({ username: "x", password: FIXTURE_TOKEN }) });
  fs.writeFileSync(path.join(dir2, "state/10.gpg"), Buffer.from([7, 7]));
  await git.add({ fs: fsParams(), dir: dir2, filepath: "state/10.gpg" });
  await git.commit({ fs: fsParams(), dir: dir2, message: "the remote's newer",
    author: { name: "t", email: "t@t" } });
  await git.push({ fs: fsParams(), http, url: remoteUrl, dir: dir2,
    ref: "main", onAuth: () => ({ username: "x", password: FIXTURE_TOKEN }) });

  // The FIRST workdir fetches → the tracking ref advances.
  const dir = path.join(workdir, "clone");
  await git.fetch({ fs: fsParams(), http, url: remoteUrl, dir,
    onAuth: () => ({ username: "x", password: FIXTURE_TOKEN }) });
  const tracking = await git.resolveRef({ fs: fsParams(), dir,
    ref: "refs/remotes/origin/main" });
  const head2 = await git.resolveRef({ fs: fsParams(), dir: dir2,
    ref: "refs/heads/main" });
  assert.equal(tracking, head2, "the fetch advanced the tracking ref");
});

test("the push to a diverged remote is REJECTED (the merge path owns it)", async () => {
  const dir = path.join(workdir, "clone");
  // The local commit (the diverged from the remote's newer).
  fs.writeFileSync(path.join(dir, "state/10.gpg"), Buffer.from([5, 5]));
  await git.add({ fs: fsParams(), dir, filepath: "state/10.gpg" });
  await git.commit({ fs: fsParams(), dir, message: "the diverged local",
    author: { name: "t", email: "t@t" } });
  await assert.rejects(
    () => git.push({ fs: fsParams(), http, url: remoteUrl, dir,
      ref: "main", onAuth: () => ({ username: "x", password: FIXTURE_TOKEN }) }),
    /rejected|not a fast-forward|fetch/i,
    "the non-fast-forward push must fail — the merge pipeline owns it");
});
