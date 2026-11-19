/**
 * omitly#1864, docs/pass-contract.md §8.1 T15: the bundle's issuer (outcome.js, a CommonJS hand port) gives, over a table of
 * every check verdict x digest binding x scan facts x caps, exactly what the TypeScript issuer (../../dist/outcome.js, built by
 * `tsc`) gives: the same outcome, the same why strings in the same order, the same lead, or the same row-0 failure. A few rows
 * also carry the outcome the contract names, so the two cannot agree on a wrong answer. The `checkOutcome` cases that used to
 * live in verdict.test.js moved here (contract §8.2).
 */
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { existsSync } = require("node:fs");
const path = require("node:path");
const { pathToFileURL } = require("node:url");
const js = require("./outcome.js");
const { notAPassLead } = require("./verdict.js");

const SNAP = "a".repeat(64);
const OTHER = "b".repeat(64);
const SEALED = "This file carries an Omitly report (omitly-audit.json) sealed with key ab:cd:12:34. The report records: Safe to Send. A seal shows the file is unchanged since it was sealed.";
const VISIBLE = { text: "Sensitive-looking text is visible on page 1 (1 value).", pages: [1] };
const result = (sha, information = []) => ({ state: "safe_to_send", blocking: false, summary: "x", pagesTotal: 1, pagesRead: 1, checked: [{ text: "Metadata" }], notChecked: [], problems: [], review: [], information, decisions: [], reasons: [], checkedAt: "2026-11-13T01:00:00Z", omitlyVersion: "5.6.0", sha256: sha, sizeBytes: 40, producer: null });

/** Every check leg the engine can send, with the outcome the contract gives it beside a clean, complete scan. */
const CHECKS = [
  ["safe, bound", { verdict: "safe_to_send", blocking: false, reasonCode: null, result: result(SNAP) }, "safe_to_send"],
  ["safe, other digest", { verdict: "safe_to_send", blocking: false, reasonCode: null, result: result(OTHER) }, "failure"],
  ["safe, empty digest", { verdict: "safe_to_send", blocking: false, reasonCode: null, result: result("") }, "failure"],
  ["safe, no result", { verdict: "safe_to_send", blocking: false, reasonCode: null, result: null }, "failure"],
  ["safe, blocking", { verdict: "safe_to_send", blocking: true, reasonCode: null, result: result(SNAP) }, "failure"],
  ["safe, reason code", { verdict: "safe_to_send", blocking: false, reasonCode: "check_failed", result: result(SNAP) }, "failure"],
  ["safe, sealed-report line (C2b)", { verdict: "safe_to_send", blocking: false, reasonCode: null, result: result(SNAP, [{ text: SEALED }]) }, "needs_review"],
  ["needs_review", { verdict: "needs_review", blocking: false, reasonCode: null, result: result(SNAP) }, "needs_review"],
  ["needs_review, blocking", { verdict: "needs_review", blocking: true, reasonCode: null, result: result(SNAP) }, "not_a_pass"],
  ["cannot_verify", { verdict: "cannot_verify", blocking: false, reasonCode: null, result: result(SNAP) }, "incomplete"],
  ["cannot_verify, no result, no code", { verdict: "cannot_verify", blocking: false, reasonCode: null, result: null }, "failure"],
  ["refusal input_too_large", { verdict: "cannot_verify", blocking: false, reasonCode: "input_too_large", result: null }, "incomplete"],
  ["refusal check_failed, empty digest", { verdict: "cannot_verify", blocking: false, reasonCode: "check_failed", result: result("") }, "incomplete"],
  ["needs_review with an empty digest", { verdict: "needs_review", blocking: false, reasonCode: "input_too_large", result: result("") }, "failure"],
  ["check_unavailable", { verdict: "cannot_verify", blocking: false, reasonCode: "check_unavailable", result: null }, "failure"],
  ["result_invalid", { verdict: "cannot_verify", blocking: false, reasonCode: "result_invalid", result: null }, "failure"],
  ["visible-text line beside a scan that found none", { verdict: "safe_to_send", blocking: false, reasonCode: null, result: result(SNAP, [VISIBLE]) }, "failure"],
];

const scan = (over = {}) => ({ engine: "wasm", total: 0, survivors: 0, topComplete: true, covComplete: true, notScanned: [], pagesFailed: 0, listsNonEmpty: false, embeddedStreamsFailed: 0, flagsSet: false, ...over });
const SCANS = [
  ["clean, complete", scan(), null],
  ["benign raster line (C5)", scan({ notScanned: ["text drawn as raster images (needs OCR)"] }), null],
  ["unknown line beside true (C5)", scan({ notScanned: ["zzz unknown"] }), "failure_or_incomplete"],
  ["suspect-font line (C5)", scan({ notScanned: ["text in font(s) \"F1\" that may be drawn as different characters than the text read: not verified as drawn"] }), "incomplete"],
  ["Set 1 line beside true", scan({ notScanned: ["XMP metadata stream was truncated"] }), "failure"],
  ["Set 1 line beside false", scan({ topComplete: false, covComplete: false, notScanned: ["XMP metadata stream was truncated"] }), "incomplete"],
  ["incomplete (both false)", scan({ topComplete: false, covComplete: false }), "incomplete"],
  ["top absent (C4)", scan({ topComplete: null }), "incomplete"],
  ["coverage absent (C4)", scan({ covComplete: null }), "incomplete"],
  ["both absent (C4)", scan({ topComplete: null, covComplete: null }), "incomplete"],
  ["flags disagree (C4)", scan({ topComplete: true, covComplete: false }), "failure"],
  ["failed page", scan({ pagesFailed: 1 }), "incomplete"],
  ["embedded streams failed", scan({ embeddedStreamsFailed: 2 }), "incomplete"],
  ["a typed unread flag (C6)", scan({ flagsSet: true }), "incomplete"],
  ["findings listed", scan({ total: 2, listsNonEmpty: true }), "needs_review"],
  ["a survivor", scan({ total: 1, survivors: 1, listsNonEmpty: true }), "not_a_pass"],
];

const CAPS = [
  [],
  [{ at: "needs_review", why: "a cap at review" }],
  [{ at: "not_a_pass", why: "a cap at not a pass" }],
  [{ at: "incomplete", why: "a cap at incomplete" }, { at: "needs_review", why: "second" }],
];

/** Reduce an issuer's answer to plain data (the brand symbol is not comparable and is not data). */
const plain = (x) => (Object.prototype.hasOwnProperty.call(x, "failure") ? { failure: x.failure } : { outcome: x.outcome, why: [...x.why], lead: x.lead });

let ts;
const loadTs = async () => {
  if (ts) return ts;
  const built = path.join(__dirname, "..", "..", "dist", "outcome.js");
  assert.ok(existsSync(built), "no dist/outcome.js: run `npx tsc` (npm test builds it first)");
  ts = await import(pathToFileURL(built).href);
  return ts;
};

test("T15: the bundle's passOutcome equals the TypeScript one over every check x scan x caps row", async () => {
  const t = await loadTs();
  let rows = 0;
  for (const [cn, check, want] of CHECKS) {
    for (const [sn, sc, scWant] of SCANS) {
      for (const caps of CAPS) {
        const input = { check, scan: sc, snapshotSha256: SNAP, caps };
        const a = plain(js.passOutcome(input));
        const b = plain(t.passOutcome(input));
        assert.deepEqual(a, b, `${cn} / ${sn} / ${caps.length} caps`);
        rows += 1;
        if (a.outcome === "safe_to_send") assert.deepEqual(a.why, [], `${cn} / ${sn}: a pass has no why`);
        else if (a.outcome) assert.ok(a.why.length > 0 && a.lead === notAPassLead(a.why), `${cn} / ${sn}: the lead is the why`);
        // The independent oracle: the contract's own outcome for the row, when the scan is clean and complete and no cap lowers it.
        if (sn === "clean, complete" && caps.length === 0) {
          if (want === "failure") assert.ok("failure" in a, `${cn}: row 0`);
          else assert.equal(a.outcome, want, `${cn}`);
        }
        if (cn === "safe, bound" && caps.length === 0 && scWant && scWant !== "failure_or_incomplete") {
          if (scWant === "failure") assert.ok("failure" in a, sn);
          else assert.equal(a.outcome, scWant, sn);
        }
      }
    }
  }
  assert.equal(rows, CHECKS.length * SCANS.length * CAPS.length);
});

test("T15: capped and worst: the same answers; a cap never upgrades; capped(null, []) is incomplete with W0", async () => {
  const t = await loadTs();
  const order = ["safe_to_send", "incomplete", "needs_review", "not_a_pass"];
  for (const a of order) for (const b of order) {
    assert.equal(js.worst(a, b), t.worst(a, b), `${a}/${b}`);
    assert.equal(js.worst(a, b), order[Math.max(order.indexOf(a), order.indexOf(b))], `${a}/${b}`);
  }
  const base = js.passOutcome({ check: CHECKS[0][1], scan: scan(), snapshotSha256: SNAP });
  assert.equal(base.outcome, "safe_to_send");
  const tbase = t.passOutcome({ check: CHECKS[0][1], scan: scan(), snapshotSha256: SNAP });
  for (const caps of CAPS) {
    assert.deepEqual(plain(js.capped(base, caps)), plain(t.capped(tbase, caps)), JSON.stringify(caps));
    assert.deepEqual(plain(js.capped(null, caps)), plain(t.capped(null, caps)), `null / ${JSON.stringify(caps)}`);
  }
  const none = js.capped(null, []);
  assert.equal(none.outcome, "incomplete");
  assert.deepEqual([...none.why], [js.WHY.W0]);
  const review = js.capped(base, [{ at: "needs_review", why: "x" }]);
  assert.equal(js.capped(review, [{ at: "incomplete", why: "y" }]).outcome, "needs_review", "a lower cap never upgrades");
});

test("T15: the why strings, the benign list and the sealed-report prefix are the TypeScript ones", async () => {
  const t = await loadTs();
  assert.deepEqual([...js.BENIGN_DISCLOSURES], [...t.BENIGN_DISCLOSURES]);
  assert.equal(js.SEALED_REPORT_PREFIX, t.SEALED_REPORT_PREFIX);
  for (const k of ["W0", "W3", "W5", "W6", "W12"]) assert.equal(js.WHY[k], t.WHY[k], k);
  assert.equal(js.WHY.W1(3), t.WHY.W1(3));
  assert.equal(js.WHY.W2(2), t.WHY.W2(2));
  assert.equal(js.WHY.W4("Cannot Verify"), t.WHY.W4("Cannot Verify"));
});

test("an Issued value is frozen, and its lead is notAPassLead(why)", () => {
  const out = js.passOutcome({ check: CHECKS[7][1], scan: scan(), snapshotSha256: SNAP });
  assert.ok(Object.isFrozen(out));
  assert.equal(out.lead, notAPassLead(out.why));
  assert.throws(() => { "use strict"; out.outcome = "safe_to_send"; }, TypeError);
});
