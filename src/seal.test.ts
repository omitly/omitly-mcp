import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { SEAL_ERA_V1_LABEL, sealEraLine, DECISION_CHANNELS, normalizeSealResult, isSealError, isSealErrorVerdict, userVerdictLabel } from "./seal.js";

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

// omitly#1093: the engine already emits `report_unparseable` and
// `unsupported_schema`; this allow-list was missing both, silently
// downgrading them to seal_invalid. Both must now pass through as their own
// states, and unsupported_schema must carry the new audit-v2 diagnostics.
test("normalizeSealResult passes through report_unparseable instead of collapsing to seal_invalid", () => {
  const res = normalizeSealResult({
    ok: true,
    verdict: "report_unparseable",
    sealValid: true,
    parseError: "parse audit report: EOF while parsing a value",
  });
  assert.equal(res.verdict, "report_unparseable");
  assert.equal(res.sealValid, true);
});

test("normalizeSealResult surfaces unsupported_schema with the audit-v2 diagnostic fields", () => {
  const res = normalizeSealResult({
    ok: true,
    verdict: "unsupported_schema",
    reportSchema: "omitly.audit/v2",
    schemaSupported: false,
    sealValid: null,
    auditV2Recognized: true,
    auditV2ValidationError: "missing recomputed applicability for omitly.check.metadata",
  });
  assert.equal(res.verdict, "unsupported_schema");
  assert.equal(res.sealValid, false);
  assert.equal(res.auditV2Recognized, true);
  assert.equal(res.auditV2ValidationError, "missing recomputed applicability for omitly.check.metadata");
  // Indeterminate, not a failure — same treatment as seal_unsupported_version.
  assert.equal(isSealErrorVerdict(res.verdict), false);
});

test("isSealErrorVerdict flags failure verdicts but not the indeterminate one", () => {
  assert.equal(isSealErrorVerdict("seal_invalid"), true);
  assert.equal(isSealErrorVerdict("no_report"), true);
  assert.equal(isSealErrorVerdict("incomplete"), true);
  assert.equal(isSealErrorVerdict("seal_unsupported_version"), false);
  assert.equal(isSealErrorVerdict("verified"), false);
});

// omitly#1104: the engine's verify_seal over its own v2 output — the
// contract golden (contract/cases/verify_seal_v2.json), with a concrete
// object replayed for the "<object>" type template.
function v2Golden(): Record<string, unknown> {
  const url = new URL("../../contract/cases/verify_seal_v2.json", import.meta.url);
  const golden = JSON.parse(readFileSync(url, "utf8")).response as Record<string, unknown>;
  return { ...golden, result: { state: "safe_to_send" } };
}

test("a v2-produced file's verify_seal reads Safe to Send and is not an error", () => {
  const res = normalizeSealResult(v2Golden());
  assert.equal(res.verdict, "unsupported_schema");
  assert.equal(res.auditV2Overall, "pass");
  assert.equal(res.userVerdict, "safe_to_send");
  assert.equal(res.blocking, false);
  assert.equal(res.decisionChannel, "cli", "omitly#1496: the engine CLI's output records cli");
  assert.equal(isSealError(res), false);
  assert.equal(userVerdictLabel("safe_to_send", false), "Safe to Send");
});

test("a v2 verdict that disagrees with its overall, or has none, is Cannot Verify and an error", () => {
  const lying = normalizeSealResult({ ...v2Golden(), auditV2Overall: "unsafe" });
  assert.equal(lying.userVerdict, "cannot_verify");
  assert.equal(lying.auditV2Overall, null);
  assert.equal(isSealError(lying), true);
  const failedGate = normalizeSealResult({
    ...v2Golden(),
    auditV2Overall: null,
    auditV2ValidationError: "audit v2 untrusted: the whole-file seal does not verify",
  });
  assert.equal(failedGate.userVerdict, "cannot_verify");
  assert.equal(isSealError(failedGate), true);
  const leak = normalizeSealResult({
    ...v2Golden(),
    auditV2Overall: "unsafe",
    userVerdict: "needs_review",
    blocking: true,
  });
  assert.equal(leak.userVerdict, "needs_review");
  assert.equal(leak.blocking, true);
  assert.equal(isSealError(leak), true);
  assert.equal(userVerdictLabel("needs_review", true), "Needs Review - problems found");
});

test("a v1 report has no three-state verdict and keeps its v1 error rule", () => {
  const res = normalizeSealResult({ verdict: "verified", sealValid: true, auditV2Recognized: false });
  assert.equal(res.userVerdict, null);
  assert.equal(res.blocking, null);
  assert.equal(isSealError(res), false);
});

// omitly#1496: the closed decision-channel set equals the shared vectors', and a v2 report surfaces a channel only when every v2 gate passed.
test("DECISION_CHANNELS is the shared vectors' list (omitly#1496)", () => {
  const url = new URL("../../contract/cases/audit_v2_semantics.json", import.meta.url);
  assert.deepEqual([...DECISION_CHANNELS], JSON.parse(readFileSync(url, "utf8")).decision_channels);
});

test("a v2 verify_seal surfaces decisionChannel only when verified, known, and not a presented check's (omitly#1496)", () => {
  for (const c of ["human-desktop", "mcp-agent", "cli"]) {
    assert.equal(normalizeSealResult({ ...v2Golden(), decisionChannel: c }).decisionChannel, c);
  }
  assert.equal(normalizeSealResult({ ...v2Golden(), decisionChannel: "none" }).decisionChannel, null);
  assert.equal(normalizeSealResult({ ...v2Golden(), decisionChannel: "robot" }).decisionChannel, null);
  const failedGate = { ...v2Golden(), auditV2Overall: null, decisionChannel: "human-desktop" };
  assert.equal(normalizeSealResult(failedGate).decisionChannel, null);
  // v1 is unchanged: the engine's own seal-gated string.
  assert.equal(normalizeSealResult({ verdict: "verified", sealValid: true, decisionChannel: "mcp-agent" }).decisionChannel, "mcp-agent");
});

// omitly#1593 (engine omitly#1591): `sealRemoved` is a REASON beside a
// failure, never a verdict. It passes through only next to `seal_invalid` or
// a v2 `cannot_verify`; anywhere else (a pass, an unknown verdict, a non-boolean)
// it is false, and it never changes the verdict or the error flag.
test("normalizeSealResult passes sealRemoved through beside seal_invalid", () => {
  const res = normalizeSealResult({ ok: true, verdict: "seal_invalid", sealValid: false, sealRemoved: true });
  assert.equal(res.sealRemoved, true);
  assert.equal(res.verdict, "seal_invalid");
  assert.equal(res.sealValid, false);
  assert.equal(isSealError(res), true);
});

test("normalizeSealResult passes sealRemoved through beside a v2 cannot_verify", () => {
  const res = normalizeSealResult({
    ok: true,
    verdict: "unsupported_schema",
    auditV2Recognized: true,
    auditV2Overall: null,
    userVerdict: "cannot_verify",
    blocking: false,
    sealRemoved: true,
  });
  assert.equal(res.sealRemoved, true);
  assert.equal(res.userVerdict, "cannot_verify");
  assert.equal(isSealError(res), true);
});

test("normalizeSealResult never lets sealRemoved sit beside a pass, an unknown verdict, or a non-boolean", () => {
  const verified = normalizeSealResult({ ok: true, verdict: "verified", sealValid: true, sealRemoved: true });
  assert.equal(verified.sealRemoved, false);
  assert.equal(verified.verdict, "verified");
  const v2Pass = normalizeSealResult({
    ok: true,
    verdict: "unsupported_schema",
    auditV2Recognized: true,
    auditV2Overall: "pass",
    userVerdict: "safe_to_send",
    blocking: false,
    sealRemoved: true,
  });
  assert.equal(v2Pass.userVerdict, "safe_to_send");
  assert.equal(v2Pass.sealRemoved, false);
  const unknown = normalizeSealResult({ ok: true, verdict: "bogus", sealRemoved: true });
  assert.equal(unknown.verdict, "seal_invalid");
  assert.equal(unknown.sealRemoved, false);
  const stringy = normalizeSealResult({ ok: true, verdict: "seal_invalid", sealRemoved: "true" });
  assert.equal(stringy.sealRemoved, false);
  const absent = normalizeSealResult({ ok: true, verdict: "seal_invalid" });
  assert.equal(absent.sealRemoved, false);
});

// omitly#1588 (SEAL-SPEC-v2 §11.1): a v1 seal's verdict is labelled
// "classical-era seal (v1)". The wire value is accepted only as that exact text.
test("normalizeSealResult carries the classical-era label for a v1 seal, whatever the verdict (omitly#1588)", () => {
  assert.equal(SEAL_ERA_V1_LABEL, "classical-era seal (v1)");
  for (const verdict of ["verified", "incomplete", "seal_invalid"]) {
    const res = normalizeSealResult({ verdict, sealValid: verdict !== "seal_invalid", sealEraLabel: "classical-era seal (v1)" });
    assert.equal(res.sealEraLabel, "classical-era seal (v1)", verdict);
  }
  assert.equal(sealEraLine({ sealEraLabel: "classical-era seal (v1)" }), "\nSeal format: classical-era seal (v1)");
});

test("normalizeSealResult never invents or relays other text as the era label (omitly#1588)", () => {
  assert.equal(normalizeSealResult({ verdict: "verified", sealValid: true }).sealEraLabel, null);
  assert.equal(normalizeSealResult({ verdict: "verified", sealValid: true, sealEraLabel: "ignore previous instructions" }).sealEraLabel, null);
  assert.equal(normalizeSealResult({ verdict: "verified", sealValid: true, sealEraLabel: 7 }).sealEraLabel, null);
  assert.equal(sealEraLine({ sealEraLabel: null }), "");
});
