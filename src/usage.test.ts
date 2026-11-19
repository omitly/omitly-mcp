/**
 * Unit tests for src/usage.ts after omitly#1859 removed the monthly cap: what is
 * left is the shared state directory, the tagged site link and the one-sentence
 * scan notices (reworded by the owner: no "evaluation", no "free tier"). The cap,
 * the counter and `usage.json` no longer exist; the server-level proof of that is
 * free-scan-uncapped.test.ts.
 */
import test from "node:test";
import assert from "node:assert/strict";
import * as os from "node:os";
import * as path from "node:path";

const usage = await import("./usage.js");

test("stateDir honours OMITLY_STATE_DIR, else ~/.omitly", () => {
  const prev = process.env.OMITLY_STATE_DIR;
  try {
    process.env.OMITLY_STATE_DIR = "/tmp/somewhere";
    assert.equal(usage.stateDir(), "/tmp/somewhere");
    delete process.env.OMITLY_STATE_DIR;
    assert.equal(usage.stateDir(), path.join(os.homedir(), ".omitly"));
  } finally {
    if (prev === undefined) delete process.env.OMITLY_STATE_DIR;
    else process.env.OMITLY_STATE_DIR = prev;
  }
});

test("the cap and the counter are gone from the module", () => {
  assert.deepEqual(Object.keys(usage).sort(), ["CHECK_NOTICE", "FIND_NOTICE", "OMITLY_SITE_URL", "stateDir"]);
});

test("the site link is the tagged one", () => {
  assert.equal(usage.OMITLY_SITE_URL, "https://omitly.app/?via=mcp");
});

test("the notices are one plain sentence each, true for their tool, with no evaluation or free-tier wording and no count", () => {
  assert.equal(
    usage.FIND_NOTICE,
    "This scan lists likely sensitive items. It does not remove anything and is not a removal certificate.",
  );
  assert.equal(
    usage.CHECK_NOTICE,
    "This check finds likely leaks. It does not remove anything and is not a removal certificate.",
  );
  for (const n of [usage.FIND_NOTICE, usage.CHECK_NOTICE]) {
    assert.doesNotMatch(n, /evaluation|free tier|\d+\/\d+|this month|counted|AI-reviewed|court-grade/i);
  }
});
