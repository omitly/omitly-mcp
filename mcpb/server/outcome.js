/**
 * omitly#1864: the bundle's issuer, a CommonJS hand port of the pass-relevant half of ../../src/outcome.ts (docs/pass-contract.md §2.3,
 * §7.1): `worst`, `passOutcome`, `capped`, the why strings, BENIGN_DISCLOSURES and SEALED_REPORT_PREFIX. Only this module can produce
 * `safe_to_send`; `outcome.test.js` compares it with the TypeScript one over a table when the build is present. The bundle has no seal,
 * redaction or sidecar tool, so `sealCaps`, `auditCaps` and `sidecarCaps` are not ported.
 */
"use strict";

const { engineIncompleteDisclosure } = require("./replies.js");
const { legsDisagree, notAPassLead } = require("./verdict.js");

const RANK = { safe_to_send: 0, incomplete: 1, needs_review: 2, not_a_pass: 3 };
/** The worst of the outcomes: not_a_pass > needs_review > incomplete > safe_to_send. */
function worst(first, ...rest) {
  let w = first;
  for (const o of rest) if (RANK[o] > RANK[w]) w = o;
  return w;
}

const ISSUED = Symbol("issued");
function issue(outcome, why) {
  const w = outcome === "safe_to_send" ? [] : [...why];
  return Object.freeze({ outcome, why: w, lead: notAPassLead(w), [ISSUED]: true });
}

const WHY = {
  W0: "this tool cannot confirm the document is ready to send",
  W1: (n) => `${n} sensitive item(s) found`,
  W2: (n) => `text is still present under a redaction mark (${n} item(s))`,
  W3: "INCOMPLETE SCAN",
  W4: (label) => `Check verdict: ${label}`,
  W5: "part of the file was not read",
  W5b: "the engine could not complete its checks",
  W6: "the file carries its own sealed report, which this check relied on: confirm the key is the sender's",
  W12: "a pattern scan is not a check of the document: run check_redaction",
};
const BENIGN_DISCLOSURES = ["text drawn as raster images (needs OCR)"];
const SEALED_REPORT_PREFIX = "This file carries an Omitly report (omitly-audit.json) sealed with key ";

const CHECK_LABEL = (c) => (c.verdict === "needs_review" ? (c.blocking ? "Needs Review — problems found" : "Needs Review") : "Cannot Verify");
const isFailure = (x) => Object.prototype.hasOwnProperty.call(x, "failure");

/** C2-C8 and rows 0-4, then `worst` with the caps (passOutcome in ../../src/outcome.ts, same order, same strings). */
function passOutcome(i) {
  const { check, scan } = i;
  if (check.reasonCode === "check_unavailable" || check.reasonCode === "result_invalid") return { failure: "the verdict check did not run" };
  const sha = check.result ? check.result.sha256 : undefined;
  const refusal = check.verdict === "cannot_verify" && (check.reasonCode === "input_too_large" || check.reasonCode === "check_failed");
  if (check.result === null || sha === "" || sha === undefined) {
    if (!refusal) return { failure: "the check's answer is not bound to a file digest" };
  } else if (sha !== i.snapshotSha256) {
    return { failure: "the check read different bytes than this server read (its digest does not match)" };
  }
  if (scan.topComplete !== null && scan.covComplete !== null && scan.topComplete !== scan.covComplete) return { failure: "scan_complete disagrees with coverage.scan_complete" };
  const complete = scan.topComplete === true && scan.covComplete === true;
  if (complete && engineIncompleteDisclosure(scan.notScanned) !== null) return { failure: "scan_complete is true beside a disclosure the engine sends only beside an incomplete scan" };
  const legs = legsDisagree(check.result, { found: scan.total, complete });
  if (legs) return { failure: legs };

  const rows = [];
  const add = (at, why) => rows.push({ at, why });
  if (scan.survivors > 0) add("not_a_pass", WHY.W2(scan.survivors));
  if (scan.total > 0) add("needs_review", WHY.W1(scan.total));
  if (check.verdict === "needs_review") add(check.blocking ? "not_a_pass" : "needs_review", WHY.W4(CHECK_LABEL(check)));
  if (check.verdict === "cannot_verify") add("incomplete", WHY.W4(CHECK_LABEL(check)));
  if (check.verdict === "safe_to_send" && (check.blocking || check.reasonCode !== null || check.result === null)) return { failure: "the check's verdict is not a consistent pass" };
  if (check.result && (check.result.information || []).some((x) => x && typeof x.text === "string" && x.text.startsWith(SEALED_REPORT_PREFIX))) add("needs_review", WHY.W6);
  if (!complete) add("incomplete", WHY.W3);
  const denied = scan.notScanned.some((l) => !BENIGN_DISCLOSURES.includes(l)) || scan.pagesFailed > 0 || scan.embeddedStreamsFailed > 0 || scan.flagsSet;
  if (denied) add("incomplete", WHY.W5);
  const all = [...rows, ...(i.caps || [])];
  return issue(worst("safe_to_send", ...all.map((c) => c.at)), all.map((c) => c.why));
}

/** `worst(base outcome or incomplete, ...caps)`; never upgrades. `capped(null, [])` is `incomplete` with W0. */
function capped(base, caps) {
  const outcome = worst(base ? base.outcome : "incomplete", ...caps.map((c) => c.at));
  const why = [...(base ? base.why : caps.length ? [] : [WHY.W0]), ...caps.map((c) => c.why)];
  return issue(outcome, outcome === "safe_to_send" ? [] : why.length ? why : [WHY.W0]);
}

module.exports = { worst, passOutcome, capped, isFailure, WHY, BENIGN_DISCLOSURES, SEALED_REPORT_PREFIX };
