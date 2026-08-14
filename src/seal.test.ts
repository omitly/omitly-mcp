import assert from "node:assert/strict";
import { test } from "node:test";
import { normalizeSealResult, isSealErrorVerdict } from "./seal.js";

test("normalizeSealResult collapses an unrecognized verdict to seal_invalid, sealValid:false", () => {
  const res = normalizeSealResult({ ok: true, verdict: "bogus", sealValid: true });
  assert.equal(res.verdict, "seal_invalid");
  assert.equal(res.sealValid, false);
});

test("normalizeSealResult keeps sealValid null for seal_unsupported_version", () => {
  const res = normalizeSealResult({ verdict: "seal_unsupported_version" });
  assert.equal(res.verdict, "seal_unsupported_version");
  assert.equal(res.sealValid, null);
});

test("normalizeSealResult surfaces carriesAuditReport only for seal_unsupported_version", () => {
  const unsupported = normalizeSealResult({
    verdict: "seal_unsupported_version",
    sealVersion: "v3",
    carriesAuditReport: true,
  });
  assert.equal(unsupported.carriesAuditReport, true);
  assert.equal(unsupported.sealVersion, "v3");

  const verified = normalizeSealResult({ verdict: "verified", sealValid: true, carriesAuditReport: true });
  assert.equal(verified.carriesAuditReport, null, "carriesAuditReport is only meaningful for the unsupported-version branch");
});

test("isSealErrorVerdict flags failure verdicts but not the indeterminate one", () => {
  assert.equal(isSealErrorVerdict("seal_invalid"), true);
  assert.equal(isSealErrorVerdict("no_report"), true);
  assert.equal(isSealErrorVerdict("incomplete"), true);
  assert.equal(isSealErrorVerdict("seal_unsupported_version"), false);
  assert.equal(isSealErrorVerdict("verified"), false);
});
