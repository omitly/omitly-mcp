/**
 * Unit tests for the free-tier metering module (omitly#226).
 *
 * These run in their own process (node --test spawns one per file), so setting
 * OMITLY_STATE_DIR before importing is safe — but the module also reads it
 * lazily per call, which several tests below rely on to re-point the state dir
 * mid-file.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, statSync, writeFileSync, mkdirSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

const {
  DEFAULT_FREE_CAP,
  freeCap,
  loadUsage,
  monthKey,
  recordFreeCheck,
  freeCapRefusal,
  evaluationBanner,
  _resetMemCounts,
} = await import("./usage.js");

function freshStateDir(): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), "omitly-usage-test-"));
  process.env.OMITLY_STATE_DIR = dir;
  _resetMemCounts();
  return dir;
}

test("counts up and refuses past the cap, refusal carries the issue's shape", () => {
  freshStateDir();
  process.env.OMITLY_FREE_CAP = "3";
  try {
    for (let i = 1; i <= 3; i++) {
      const o = recordFreeCheck();
      assert.equal(o.capped, false, `call ${i} must not be capped`);
      assert.equal(o.used, i);
      assert.equal(o.cap, 3);
    }
    const fourth = recordFreeCheck();
    assert.equal(fourth.capped, true, "call cap+1 must be refused");
    const refusal = freeCapRefusal("check_redaction", fourth);
    assert.equal(refusal.blocked, true);
    assert.equal(refusal.reason, "free-cap");
    assert.equal(refusal.tool, "check_redaction");
    assert.match(refusal.message, /counted locally/);
    assert.match(refusal.message, /omitly\.app/);
  } finally {
    delete process.env.OMITLY_FREE_CAP;
  }
});

test("counter persists across module state resets (simulated restart)", () => {
  const dir = freshStateDir();
  process.env.OMITLY_FREE_CAP = "5";
  try {
    recordFreeCheck();
    recordFreeCheck();
    // Simulated restart: wipe the in-memory floor so only the file carries
    // the count forward.
    _resetMemCounts();
    const third = recordFreeCheck();
    assert.equal(third.used, 3, "count must come from the persisted file, not process memory");
    const onDisk = JSON.parse(readFileSync(path.join(dir, "usage.json"), "utf8"));
    assert.equal(onDisk.check_calls[monthKey()], 3);
    assert.equal(typeof onDisk.install_id, "string");
    assert.equal(onDisk.licensed, false);
  } finally {
    delete process.env.OMITLY_FREE_CAP;
  }
});

test("state file is written 0600 (POSIX)", (t) => {
  if (process.platform === "win32") {
    t.skip("no POSIX modes on Windows");
    return;
  }
  const dir = freshStateDir();
  recordFreeCheck();
  const mode = statSync(path.join(dir, "usage.json")).mode & 0o777;
  assert.equal(mode, 0o600);
});

test("month rollover resets the count", () => {
  freshStateDir();
  process.env.OMITLY_FREE_CAP = "2";
  try {
    const july = new Date(Date.UTC(2026, 6, 15));
    const august = new Date(Date.UTC(2026, 7, 15));
    recordFreeCheck(july);
    recordFreeCheck(july);
    assert.equal(recordFreeCheck(july).capped, true, "over cap in July");
    const firstOfAugust = recordFreeCheck(august);
    assert.equal(firstOfAugust.capped, false, "new month starts fresh");
    assert.equal(firstOfAugust.used, 1);
    assert.equal(firstOfAugust.month, "2026-08");
  } finally {
    delete process.env.OMITLY_FREE_CAP;
  }
});

test("corrupt state file degrades to a fresh state, never a crash", () => {
  const dir = freshStateDir();
  writeFileSync(path.join(dir, "usage.json"), "{not json at all");
  const o = recordFreeCheck();
  assert.equal(o.used, 1);
  const reread = loadUsage();
  assert.equal(reread.check_calls[monthKey()], 1);
});

test("licensed=true skips the cap entirely", () => {
  const dir = freshStateDir();
  process.env.OMITLY_FREE_CAP = "1";
  try {
    mkdirSync(dir, { recursive: true });
    writeFileSync(
      path.join(dir, "usage.json"),
      JSON.stringify({ check_calls: { [monthKey()]: 999 }, install_id: "x", licensed: true }),
    );
    const o = recordFreeCheck();
    assert.equal(o.capped, false);
  } finally {
    delete process.env.OMITLY_FREE_CAP;
  }
});

test("unwritable state dir still enforces the cap in-process (in-memory floor)", (t) => {
  if (process.platform === "win32") {
    t.skip("read-only dir semantics differ on Windows");
    return;
  }
  const dir = freshStateDir();
  // Point the state dir INSIDE a read-only directory so mkdir/write fail.
  const ro = path.join(dir, "ro");
  mkdirSync(ro, { mode: 0o500 });
  process.env.OMITLY_STATE_DIR = path.join(ro, "state");
  process.env.OMITLY_FREE_CAP = "2";
  try {
    assert.equal(recordFreeCheck().capped, false);
    assert.equal(recordFreeCheck().capped, false);
    assert.equal(recordFreeCheck().capped, true, "cap holds without any persistence");
  } finally {
    delete process.env.OMITLY_FREE_CAP;
  }
});

test("default cap is 10 and env override must be a positive integer", () => {
  delete process.env.OMITLY_FREE_CAP;
  assert.equal(freeCap(), DEFAULT_FREE_CAP);
  assert.equal(DEFAULT_FREE_CAP, 10);
  process.env.OMITLY_FREE_CAP = "25";
  assert.equal(freeCap(), 25);
  process.env.OMITLY_FREE_CAP = "0";
  assert.equal(freeCap(), DEFAULT_FREE_CAP);
  process.env.OMITLY_FREE_CAP = "banana";
  assert.equal(freeCap(), DEFAULT_FREE_CAP);
  delete process.env.OMITLY_FREE_CAP;
});

test("evaluation banner names the honest limits and the count", () => {
  const banner = evaluationBanner({ capped: false, used: 4, cap: 10, month: "2026-08" });
  assert.match(banner, /EVALUATION/);
  assert.match(banner, /not production reliance/);
  assert.match(banner, /4\/10/);
});
