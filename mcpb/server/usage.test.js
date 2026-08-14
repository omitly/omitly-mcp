/**
 * Unit tests for the MCPB bundle's CJS metering mirror (omitly#226) — run by
 * `npm --prefix mcpb test` (node --test server/*.test.js), same as
 * paths.test.js. Keep behaviour identical to ../../src/usage.test.ts: the two
 * servers share one state file and must agree about it.
 */
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { mkdtempSync, readFileSync, writeFileSync, mkdirSync, statSync } = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  DEFAULT_FREE_CAP,
  freeCap,
  monthKey,
  recordFreeCheck,
  freeCapRefusal,
  evaluationBanner,
  _resetMemCounts,
} = require("./usage.js");

function freshStateDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), "omitly-mcpb-usage-test-"));
  process.env.OMITLY_STATE_DIR = dir;
  _resetMemCounts();
  return dir;
}

test("counts up and refuses past the cap with the structured shape", () => {
  freshStateDir();
  process.env.OMITLY_FREE_CAP = "2";
  try {
    assert.equal(recordFreeCheck().capped, false);
    assert.equal(recordFreeCheck().capped, false);
    const third = recordFreeCheck();
    assert.equal(third.capped, true);
    const refusal = freeCapRefusal("find_sensitive_regions", third);
    assert.equal(refusal.blocked, true);
    assert.equal(refusal.reason, "free-cap");
    assert.match(refusal.message, /counted locally/);
  } finally {
    delete process.env.OMITLY_FREE_CAP;
  }
});

test("persists to usage.json (0600) and survives an in-memory reset", (t) => {
  const dir = freshStateDir();
  process.env.OMITLY_FREE_CAP = "5";
  try {
    recordFreeCheck();
    _resetMemCounts(); // simulated restart
    const second = recordFreeCheck();
    assert.equal(second.used, 2);
    const file = path.join(dir, "usage.json");
    const state = JSON.parse(readFileSync(file, "utf8"));
    assert.equal(state.check_calls[monthKey()], 2);
    assert.equal(state.licensed, false);
    if (process.platform !== "win32") {
      assert.equal(statSync(file).mode & 0o777, 0o600);
    }
  } finally {
    delete process.env.OMITLY_FREE_CAP;
  }
});

test("month rollover resets; corrupt file degrades to fresh", () => {
  const dir = freshStateDir();
  process.env.OMITLY_FREE_CAP = "1";
  try {
    const july = new Date(Date.UTC(2026, 6, 1));
    const august = new Date(Date.UTC(2026, 7, 1));
    recordFreeCheck(july);
    assert.equal(recordFreeCheck(july).capped, true);
    assert.equal(recordFreeCheck(august).capped, false, "new month starts fresh");

    writeFileSync(path.join(dir, "usage.json"), "garbage{{{");
    _resetMemCounts();
    assert.equal(recordFreeCheck(august).used, 1, "corrupt state never crashes, restarts fresh");
  } finally {
    delete process.env.OMITLY_FREE_CAP;
  }
});

test("licensed=true skips the cap; default cap is 10", () => {
  const dir = freshStateDir();
  process.env.OMITLY_FREE_CAP = "1";
  try {
    mkdirSync(dir, { recursive: true });
    writeFileSync(
      path.join(dir, "usage.json"),
      JSON.stringify({ check_calls: { [monthKey()]: 999 }, install_id: "x", licensed: true }),
    );
    assert.equal(recordFreeCheck().capped, false);
  } finally {
    delete process.env.OMITLY_FREE_CAP;
  }
  assert.equal(DEFAULT_FREE_CAP, 10);
  delete process.env.OMITLY_FREE_CAP;
  assert.equal(freeCap(), 10);
});

test("banner is honest about evaluation status and count", () => {
  const banner = evaluationBanner({ capped: false, used: 2, cap: 10, month: "2026-08" });
  assert.match(banner, /EVALUATION/);
  assert.match(banner, /2\/10/);
});
