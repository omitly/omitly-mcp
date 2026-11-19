/**
 * omitly#1940: the engine's lowering of a LOST SCAN (a whole image removed from a page that has none left) is
 * on three presented surfaces only (the app's result card, the delivery receipt's view and verdict, the certificate;
 * a fresh `check` of the saved file cannot lower, see omitly#1943), so the CLI JSON this server and the npm wrapper parse is unchanged. These run
 * the REAL parsers over REAL engine output (`lone-scan-fixtures.ts`) and pin that a lone removed scan is accepted
 * as the pass the sealed overall says it is. If the engine ever prints `needs_review` beside a pass overall, this
 * fails; the parsers would then report a contradiction (omitly#1943 is the signed follow-up that makes it legal).
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { LONE_SCAN_REDACT_AUDIT, LONE_SCAN_VERIFY_SEAL } from "./lone-scan-fixtures.js";
import { parseRedactAudit, parseSealReply } from "./replies.js";

test("redact's audit for a lone removed scan parses as the pass its overall says", () => {
  const audit = LONE_SCAN_REDACT_AUDIT as { verdict: string; auditV2Overall: string; userVerdict: string; blocking: boolean };
  assert.equal(audit.verdict, "pass");
  assert.equal(audit.auditV2Overall, "pass");
  assert.equal(audit.userVerdict, "safe_to_send");
  assert.equal(audit.blocking, false);
  const parsed = parseRedactAudit(LONE_SCAN_REDACT_AUDIT, { expected: [{ page: 0 }] });
  assert.equal(parsed.ok, true, JSON.stringify(parsed));
});

test("verify_seal for a lone removed scan parses as the pass its overall says", () => {
  const parsed = parseSealReply(LONE_SCAN_VERIFY_SEAL);
  assert.equal(parsed.ok, true, JSON.stringify(parsed));
});

test("a lowered verdict beside a pass overall is rejected by both parsers (why the CLI must not emit one)", () => {
  const lowered = JSON.parse(JSON.stringify(LONE_SCAN_REDACT_AUDIT)) as Record<string, unknown>;
  lowered.userVerdict = "needs_review";
  assert.equal(parseRedactAudit(lowered, { expected: [{ page: 0 }] }).ok, false);
  const seal = JSON.parse(JSON.stringify(LONE_SCAN_VERIFY_SEAL)) as Record<string, unknown>;
  seal.userVerdict = "needs_review";
  assert.equal(parseSealReply(seal).ok, false);
});
