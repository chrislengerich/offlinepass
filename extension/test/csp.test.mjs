/**
 * THE CSP CONTRACT (the manifest's network surface): repo mode makes the
 * extension's ONLY network calls — to GitHub. The manifest's CSP must
 * allow exactly those hosts and NOTHING broader: no 'none' (the paste
 * era's shape — the sync can't fetch under it), no wildcard host, no
 * scheme shortcuts. This pins the scope so a future edit cannot widen
 * the extension's network surface silently.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const manifest = JSON.parse(readFileSync(
  path.join(path.dirname(fileURLToPath(import.meta.url)),
    "../manifest.json"), "utf8"));

const csp = manifest.content_security_policy?.extension_pages ?? "";

test("the CSP names the GitHub hosts the sync needs (no 'none')", () => {
  assert.ok(!csp.includes("'none'"),
    "connect-src 'none' blocks the repo sync — relax to the GitHub hosts");
  for (const host of ["api.github.com", "github.com", "codeload.github.com"]) {
    assert.ok(csp.includes(host), `connect-src must include ${host}`);
  }
});

test("the CSP stays scoped: no wildcards, no blanket hosts", () => {
  const connect = csp.match(/connect-src ([^;]*)/)?.[1] ?? "";
  assert.ok(connect.length > 0, "a connect-src directive must exist");
  assert.ok(!connect.includes("*"), "no wildcard hosts in connect-src");
  for (const banned of ["http:", "ftp:", "blob:", "data:"]) {
    assert.ok(!connect.includes(banned),
      `connect-src must not allow ${banned}`);
  }
});

test("the CSP keeps the script sources self-hosted", () => {
  assert.ok(csp.includes("script-src 'self'"),
    "the script sources must stay 'self' (the vendoring rule)");
});
