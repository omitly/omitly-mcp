/**
 * Tests for the MCPB bundle's scan notices (omitly#1859 removed the monthly cap and the owner
 * reworded the disclaimer) — run by `npm --prefix mcpb test` (node --test server/*.test.js). The
 * texts must match ../../src/usage.ts, and the bundle must hold no counter, cap or state file.
 */
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const path = require("node:path");

const usage = require("./usage.js");

test("the module exports only the two notices; the cap and counter are gone", () => {
  assert.deepEqual(Object.keys(usage).sort(), ["CHECK_NOTICE", "FIND_NOTICE"]);
});

test("the notices are plain, say nothing is removed, and carry no evaluation or free-tier wording or count", () => {
  assert.equal(usage.FIND_NOTICE, "This scan lists likely sensitive items. It does not remove anything and is not a removal certificate.");
  assert.equal(usage.CHECK_NOTICE, "This check finds likely leaks. It does not remove anything and is not a removal certificate.");
  for (const n of Object.values(usage)) assert.doesNotMatch(n, /evaluation|free tier|\d+\/\d+|this month|counted/i);
});

test("the texts are identical to the full server's (src/usage.ts)", () => {
  // From mcpb/server/ the TS source is at ../../src/usage.ts in the monorepo; the published
  // mirror has no src/, so compare only when it is present.
  let ts;
  try {
    ts = readFileSync(path.join(__dirname, "..", "..", "src", "usage.ts"), "utf8");
  } catch {
    return;
  }
  for (const name of ["FIND_NOTICE", "CHECK_NOTICE"]) {
    const m = new RegExp(name + " =\\s*((?:\"[^\"]*\"\\s*\\+?\\s*)+);").exec(ts);
    assert.ok(m, name + " found in usage.ts");
    const joined = [...m[1].matchAll(/"([^"]*)"/g)].map((x) => x[1]).join("");
    assert.equal(joined, usage[name]);
  }
});

test("the bundle server has no cap, no counter and no purchase link in a scan result", () => {
  const src = readFileSync(path.join(__dirname, "index.js"), "utf8");
  assert.doesNotMatch(src, /free-cap|recordFreeCheck|freeCapRefusal|usage\.json|10 attempts|EVALUATION/);
  // Links in comments are fine; none may sit in a string a tool returns.
  const code = src.split("\n").filter((l) => !/^\s*(\/\/|\/\*|\*)/.test(l)).join("\n");
  assert.doesNotMatch(code, /omitly\.app/);
});
