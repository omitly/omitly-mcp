/**
 * omitly#1864, docs/pass-contract.md §2, §3, §7.1: unit tests of the issuer (`src/outcome.ts`): `worst`, `capped`, `passOutcome` over every
 * condition C1-C8 and every row 0-4, and the cap tables `sealCaps` (S1-S8), `auditCaps` (A1-A5, W11) and `sidecarCaps` (§3.4). Real goldens are
 * the oracles wherever a real reply exists (testing/goldens); the synthetic legs change ONE thing each, and every case has its positive control.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { auditCaps, auditLabel, BENIGN_DISCLOSURES, capped, isFailure, passOutcome, sealCaps, SEALED_REPORT_PREFIX, sealState, sidecarCaps, WHY, worst, type CheckLeg, type Issued, type Outcome, type ScanLeg } from "./outcome.js";
import { parseRedactAudit, parseSidecarVerifyReply } from "./replies.js";
import { normalizeSealResult } from "./seal.js";
import { notAPassLead } from "./verdict-rule.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const native: any = JSON.parse(readFileSync(path.join(HERE, "..", "src", "testing", "goldens", "native.json"), "utf8"));
const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v));
const SNAP = "a".repeat(64);

const result = (over: Record<string, unknown> = {}) => ({
  state: "safe_to_send", blocking: false, summary: "Every check passed.", checked: [{ text: "Metadata" }], notChecked: [], problems: [], review: [], information: [], decisions: [], reasons: [],
  sha256: SNAP, pagesTotal: 1, pagesRead: 1, ...over,
});
const check = (over: Partial<CheckLeg> = {}): CheckLeg => ({ verdict: "safe_to_send", blocking: false, reasonCode: null, result: result() as any, ...over });
const scan = (over: Partial<ScanLeg> = {}): ScanLeg => ({
  engine: "native", total: 0, survivors: 0, topComplete: true, covComplete: true, notScanned: [], pagesFailed: 0, listsNonEmpty: false, embeddedStreamsFailed: 0, flagsSet: false, ...over,
});
const run = (c: CheckLeg = check(), s: ScanLeg = scan(), caps?: any[], snap = SNAP) => passOutcome({ check: c, scan: s, snapshotSha256: snap, caps });
const issued = (x: ReturnType<typeof run>): Issued => {
  assert.equal(isFailure(x), false, isFailure(x) ? (x as any).failure : "");
  return x as Issued;
};
const outcomeOf = (x: ReturnType<typeof run>): Outcome => issued(x).outcome;

test("worst: the order is not_a_pass > needs_review > incomplete > safe_to_send, for every pair", () => {
  const order: Outcome[] = ["safe_to_send", "incomplete", "needs_review", "not_a_pass"];
  for (let i = 0; i < order.length; i++) for (let j = 0; j < order.length; j++) assert.equal(worst(order[i]!, order[j]!), order[Math.max(i, j)]);
  assert.equal(worst("safe_to_send"), "safe_to_send");
  assert.equal(worst("safe_to_send", "incomplete", "not_a_pass", "needs_review"), "not_a_pass");
});

test("PASS: every condition holds -> safe_to_send, no why, no lead (positive control)", () => {
  const i = issued(run());
  assert.equal(i.outcome, "safe_to_send");
  assert.deepEqual(i.why, []);
  assert.equal(i.lead, "");
  // The benign disclosure is the only line that may sit beside a pass (C5).
  assert.equal(outcomeOf(run(check(), scan({ notScanned: [...BENIGN_DISCLOSURES] }))), "safe_to_send");
});

test("lead === notAPassLead(why); why is empty iff safe_to_send; an issued value is frozen", () => {
  for (const x of [run(), run(check(), scan({ total: 2, listsNonEmpty: true })), run(check({ verdict: "cannot_verify", result: result({ state: "cannot_verify" }) as any }))]) {
    const i = issued(x);
    assert.equal(i.lead, notAPassLead([...i.why]));
    assert.equal(i.why.length === 0, i.outcome === "safe_to_send");
    assert.ok(Object.isFrozen(i));
  }
});

test("C2: the check's verdict is the engine's whole pass contract", () => {
  assert.equal(outcomeOf(run(check({ verdict: "needs_review", result: result({ state: "needs_review" }) as any }))), "needs_review");
  assert.equal(outcomeOf(run(check({ verdict: "needs_review", blocking: true, result: result({ state: "needs_review", blocking: true }) as any }))), "not_a_pass");
  assert.equal(outcomeOf(run(check({ verdict: "cannot_verify", result: result({ state: "cannot_verify" }) as any }))), "incomplete");
  for (const [label, c] of [
    ["a safe verdict that is blocking", check({ blocking: true })],
    ["a safe verdict with a reason code", check({ reasonCode: "check_failed" })],
    ["a safe verdict with no result", check({ result: null })],
    ["the check did not run (check_unavailable)", check({ verdict: "cannot_verify", reasonCode: "check_unavailable", result: null })],
    ["the check's answer failed the allowlist (result_invalid)", check({ verdict: "cannot_verify", reasonCode: "result_invalid", result: null })],
  ] as const) assert.equal(isFailure(run(c)), true, label);
});

test("C2b: the check relied on the file's own bound report -> needs_review (W6), whatever the verdict says", () => {
  const line = { text: `${SEALED_REPORT_PREFIX}ab:cd:12:34. The report records: Safe to Send. A seal shows the file is unchanged.` };
  const i = issued(run(check({ result: result({ information: [line] }) as any })));
  assert.equal(i.outcome, "needs_review");
  assert.ok(i.why.includes(WHY.W6));
  // Positive control: the same result without the line passes; the prefix only, anywhere else in a line, is not the line.
  assert.equal(outcomeOf(run(check({ result: result({ information: [{ text: "The file has document properties or metadata." }] }) as any }))), "safe_to_send");
  assert.equal(outcomeOf(run(check({ result: result({ information: [{ text: `x ${SEALED_REPORT_PREFIX}` }] }) as any }))), "safe_to_send");
});

test("C3: the check is bound to the bytes this server read", () => {
  assert.equal(isFailure(run(check(), scan(), undefined, "b".repeat(64))), true, "a digest that differs");
  assert.equal(isFailure(run(check({ result: result({ sha256: SNAP.slice(0, 63) + "b" }) as any }))), true, "one character off");
  // An empty digest or no result is allowed only for the engine's own refusals, and never satisfies C2.
  const refused = (code: string, withResult: boolean) =>
    check({ verdict: "cannot_verify", reasonCode: code, result: withResult ? (result({ state: "cannot_verify", sha256: "" }) as any) : null });
  for (const code of ["input_too_large", "check_failed"]) for (const withResult of [true, false]) assert.equal(outcomeOf(run(refused(code, withResult))), "incomplete", `${code} ${withResult}`);
  assert.equal(outcomeOf(run(refused("input_too_large", true), scan({ total: 1, survivors: 1, listsNonEmpty: true }))), "not_a_pass", "survivors beside a refusal");
  assert.equal(isFailure(run(check({ verdict: "needs_review", result: result({ state: "needs_review", sha256: "" }) as any }))), true, "empty digest, needs_review");
  assert.equal(isFailure(run(check({ verdict: "needs_review", result: null }))), true, "no result, needs_review");
  assert.equal(isFailure(run(check({ verdict: "safe_to_send", result: result({ sha256: "" }) as any }))), true, "empty digest, safe");
  assert.equal(isFailure(run(check({ verdict: "cannot_verify", reasonCode: null, result: result({ state: "cannot_verify", sha256: "" }) as any }))), true, "an empty digest without a refusal code");
});

test("C4: the scan is empty and complete; either flag absent is incomplete, never a pass; disagreement is row 0", () => {
  assert.equal(outcomeOf(run(check(), scan({ total: 1, listsNonEmpty: true }))), "needs_review");
  assert.equal(outcomeOf(run(check(), scan({ total: 1, survivors: 1, listsNonEmpty: true }))), "not_a_pass");
  for (const [top, cov] of [[null, true], [true, null], [null, null], [false, false], [true, false], [false, true]] as const) {
    if (top !== null && cov !== null && top !== cov) {
      assert.equal(isFailure(run(check(), scan({ topComplete: top, covComplete: cov }))), true, `${top}/${cov}`);
    } else {
      assert.equal(outcomeOf(run(check(), scan({ topComplete: top, covComplete: cov }))), "incomplete", `${top}/${cov}`);
    }
  }
});

test("C5: a line that is not exactly the benign one denies a pass (incomplete; needs_review with findings); the engine-incomplete lines beside a complete scan are row 0", () => {
  for (const line of ["zzz unknown", "text drawn as raster images (needs OCR) ", "text in font(s) \"F1\" that may be drawn as different characters than the text read: not verified as drawn", "1 page(s) are effectively image-only (raster content, fewer than 100 extractable text characters)"]) {
    const complete = !line.includes("effectively image-only");
    if (complete) {
      assert.equal(outcomeOf(run(check(), scan({ notScanned: [line] }))), "incomplete", line);
      assert.equal(outcomeOf(run(check(), scan({ notScanned: [line], total: 1, listsNonEmpty: true }))), "needs_review", `${line} with findings`);
    } else {
      assert.equal(isFailure(run(check(), scan({ notScanned: [line] }))), true, `${line} beside a complete scan`);
      assert.equal(outcomeOf(run(check(), scan({ notScanned: [line], topComplete: false, covComplete: false }))), "incomplete");
    }
  }
  assert.equal(isFailure(run(check(), scan({ notScanned: ["document information, form fields and attachments: x"] }))), true, "the 3869 line beside true");
});

test("C6: typed coverage must be clear: a failed page, failed embedded streams or any unread flag is incomplete", () => {
  for (const over of [{ pagesFailed: 1 }, { embeddedStreamsFailed: 2 }, { flagsSet: true }] as Partial<ScanLeg>[]) {
    assert.equal(outcomeOf(run(check(), scan(over))), "incomplete", JSON.stringify(over));
  }
});

test("C8: a check that lists visible values beside a scan that found none is row 0", () => {
  const visible = result({ information: [{ text: "Sensitive-looking text is visible on page 1 (1 value)." }] }) as any;
  assert.equal(isFailure(run(check({ result: visible }))), true);
  assert.equal(outcomeOf(run(check({ result: visible }), scan({ total: 1, listsNonEmpty: true }))), "needs_review");
});

test("capped: worst(base ?? incomplete, ...caps); never upgrades; capped(null, []) is incomplete with W0", () => {
  const w0 = capped(null, []);
  assert.equal(w0.outcome, "incomplete");
  assert.deepEqual([...w0.why], [WHY.W0]);
  const pass = issued(run());
  assert.equal(capped(pass, []).outcome, "safe_to_send", "no cap leaves a pass");
  assert.equal(capped(pass, [{ at: "needs_review", why: "x" }]).outcome, "needs_review");
  const nr = issued(run(check(), scan({ total: 1, listsNonEmpty: true })));
  assert.equal(capped(nr, [{ at: "incomplete", why: "x" }]).outcome, "needs_review", "a cap at a lower rank never upgrades");
  assert.equal(capped(nr, [{ at: "not_a_pass", why: "x" }]).outcome, "not_a_pass");
  assert.equal(capped(null, [{ at: "needs_review", why: "x" }]).outcome, "needs_review");
  // Caps given to passOutcome are applied after the rows, in the same way.
  assert.equal(outcomeOf(run(check(), scan(), [{ at: "needs_review", why: "x" }])), "needs_review");
  assert.equal(outcomeOf(run(check(), scan(), [{ at: "incomplete", why: "x" }])), "incomplete");
});

// ---- the cap tables ---------------------------------------------------------------------------------------------------------------

const seal = (name: string) => clone(native.verify_seal.find((e: any) => e.pdf.endsWith(name)).reply);
const sealOutcomeOf = (reply: any) => capped(null, sealCaps(normalizeSealResult(reply))).outcome;

test("sealCaps S1-S8 over the real seal goldens: never safe_to_send; the first matching row decides", () => {
  assert.equal(sealOutcomeOf(seal("stripped-seal.pdf")), "not_a_pass", "S1 removed");
  assert.equal(sealOutcomeOf(seal("tampered-content.pdf")), "not_a_pass", "S2 invalid");
  assert.equal(sealOutcomeOf(seal("forged-signature.pdf")), "not_a_pass", "S2 invalid");
  assert.equal(sealOutcomeOf(seal("corrupt-audit-json.pdf")), "incomplete", "S8 report_unparseable with a held seal");
  assert.equal(sealOutcomeOf(seal("clean-sealed.pdf")), "incomplete", "S8: a legacy v1 pass");
  assert.equal(sealOutcomeOf(seal("compat/v5.3.0.pdf")), "incomplete", "S8: a v2 pass");
  assert.equal(sealOutcomeOf(seal("compat/v3.2.0.pdf")), "incomplete", "S8: a v2 report with no overall");
  assert.equal(sealOutcomeOf(seal("positive/seal-at-boundary.pdf")), "incomplete", "S8: no_report");
  // The synthetic rows change one field of a real reply.
  const v1 = () => ({ ...seal("clean-sealed.pdf") });
  assert.equal(sealOutcomeOf({ ...v1(), verdict: "incomplete", allPassed: false }), "not_a_pass", "S3 a held v1 seal over a failed report");
  assert.equal(sealOutcomeOf({ ...v1(), metadataScrubbed: false }), "needs_review", "S6 metadata not scrubbed");
  assert.equal(sealOutcomeOf({ ...v1(), warnings: ["Page 1: an engine warning"] }), "needs_review", "S7 an engine warning in a held v1 report");
  assert.equal(sealOutcomeOf({ ...v1(), warnings: v1().warnings.filter((w: string) => w.startsWith("CAUTION")) }), "incomplete", "a verifier-own line is not an engine warning");
  const v2 = (o: string, uv: string, blocking: boolean) => ({ ...seal("compat/v5.3.0.pdf"), auditV2Overall: o, userVerdict: uv, blocking });
  assert.equal(sealOutcomeOf(v2("unsafe", "needs_review", true)), "not_a_pass", "S4");
  assert.equal(sealOutcomeOf(v2("review_required", "needs_review", false)), "needs_review", "S5");
  assert.equal(sealOutcomeOf(v2("pass_with_operator_decisions", "needs_review", false)), "needs_review", "S5");
  assert.equal(sealOutcomeOf(v2("technical_fail", "cannot_verify", false)), "incomplete", "S8");
  assert.equal(sealOutcomeOf({ ...seal("compat/v5.3.0.pdf"), sealWarnings: ["a verifier note"] }), "needs_review", "S7 sealWarnings");
  // v2Held needs the seal gate and, for a v2 seal, a valid seal verdict: an unheld v2 is S8, never S4/S5.
  assert.equal(sealOutcomeOf({ ...v2("unsafe", "needs_review", true), auditV2SealValid: false }), "incomplete", "no held seal: S8");
  assert.equal(sealOutcomeOf({ ...v2("review_required", "needs_review", false), sealVerdict: "invalid" }), "incomplete", "an invalid v2 seal verdict is not held");
  // W8 is always there, so the outcome is at least incomplete.
  for (const e of native.verify_seal) assert.notEqual(sealOutcomeOf(e.reply), "safe_to_send", e.pdf);
  assert.ok(sealCaps(normalizeSealResult(seal("compat/v5.3.0.pdf"))).some((c) => c.why === WHY.W8));
});

test("sealState: removed / invalid / unsupported / held / none, first match (contract §6.1)", () => {
  const state = (n: string) => sealState(normalizeSealResult(seal(n)));
  assert.equal(state("stripped-seal.pdf"), "removed");
  assert.equal(state("tampered-content.pdf"), "invalid");
  assert.equal(state("clean-sealed.pdf"), "held");
  assert.equal(state("compat/v5.3.0.pdf"), "held");
  assert.equal(state("compat/v3.2.0.pdf"), "held", "v2Held = auditV2Recognized and auditV2SealValid (the report has no overall, which is S8, not an unheld seal)");
  assert.equal(state("positive/seal-at-boundary.pdf"), "held");
  assert.equal(sealState(normalizeSealResult({ ok: true, verdict: "seal_unsupported_version", sealVersion: "9", carriesAuditReport: false, sealValid: null })), "unsupported");
});

const audit = (pdfKey: "redact" | "redact_entities") => clone(native[pdfKey][0].reply.audit);
const auditOutcome = (a: any) => {
  const p = parseRedactAudit(a);
  assert.equal(p.ok, true, p.ok ? "" : p.reason);
  return capped(null, auditCaps((p as any).value.audit)).outcome;
};

test("auditCaps A1-A5 and W11 over the real redact goldens: never above needs_review for a completed redaction", () => {
  assert.equal(auditOutcome(audit("redact_entities")), "needs_review", "A5 + W11");
  assert.equal(auditOutcome(audit("redact")), "needs_review", "A2 + W11: the real review_required audit");
  const pass = () => audit("redact_entities");
  const failing = { ...pass(), verdict: "fail", userVerdict: "needs_review", auditV2Overall: "unsafe", blocking: true, result: { ...pass().result, state: "needs_review", blocking: true, problems: [{ text: "x" }] } };
  failing.regions = [{ ...failing.regions[0], verification: { result: "fail", detail: "x" } }, ...failing.regions.slice(1)];
  assert.equal(auditOutcome(failing), "not_a_pass", "A1");
  const tech = { ...pass(), verdict: "fail", userVerdict: "cannot_verify", auditV2Overall: "technical_fail", result: { ...pass().result, state: "cannot_verify", checked: [], reasons: [{ text: "x" }] } };
  assert.equal(auditOutcome(tech), "needs_review", "A4 is incomplete, W11 lifts it to needs_review");
  const warn = { ...pass(), warnings: [...pass().warnings, "Page 1: an engine warning"] };
  assert.ok(auditCaps(parseRedactAudit(warn).ok ? ((parseRedactAudit(warn) as any).value.audit) : null as any).some((c) => c.why === WHY.W7), "A3");
  assert.equal(auditLabel((parseRedactAudit(pass()) as any).value.audit), "no failed region");
  assert.equal(auditLabel((parseRedactAudit(audit("redact")) as any).value.audit), "items to review");
  assert.equal(auditLabel((parseRedactAudit(failing) as any).value.audit), "a failed redaction");
  assert.equal(auditLabel((parseRedactAudit(tech) as any).value.audit), "could not complete its checks");
});

test("sidecarCaps (§3.4) over the real verify goldens: a pass adds nothing; W9, W16, W10 and W7 lower", () => {
  const pass = () => clone(native.verify[0].reply);
  const fail = () => clone(native.verify[1].reply);
  const caps = (r: any) => sidecarCaps((parseSidecarVerifyReply(r) as any).value.reply);
  assert.deepEqual(caps(pass()), [], "the real pass: its only warning is the trial notice");
  const f = caps(fail());
  assert.ok(f.some((c) => c.at === "not_a_pass" && c.why === WHY.W9(f.length ? 3 : 0)) || f.some((c) => c.at === "not_a_pass"), "a failing region: not_a_pass");
  assert.ok(f.some((c) => c.why === WHY.W10), "the real fail golden has metadataScrubbed false");
  const w = pass();
  w.warnings = [...w.warnings, "Page 1: an engine warning"];
  assert.deepEqual(caps(w).map((c) => c.why), [WHY.W7]);
  const h = pass();
  h.hiddenContent[1].verification = { result: "fail", detail: "x" };
  h.verdict = "fail";
  assert.deepEqual(caps(h).map((c) => [c.at, c.why]), [["needs_review", WHY.W16(1)]]);
  const m = pass();
  m.metadataScrubbed = false;
  m.verdict = "fail";
  assert.deepEqual(caps(m).map((c) => c.why), [WHY.W10]);
});
