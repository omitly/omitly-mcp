/**
 * omitly#1864: the MCPB bundle's strict reply parsers (replies.js) give what the full server's
 * (../../src/replies.ts) give, over a table of defects, and each defect is refused.
 */
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { existsSync } = require("node:fs");
const path = require("node:path");
const { parseScanReply, parseLocateReply, parseCheckVerdict, incompleteLine } = require("./replies.js");

const region = { page: 0, x: 1, y: 2, width: 3, height: 4, kind: "email", preview: "•••" };
const good = (over = {}) => ({ ok: true, scan_complete: true, clean: true, count: 0, total_findings: 0, regions: [], survivors: [], off_page: [], coverage: { pages_failed: [], not_scanned: [], pages_total: 1, pages_scanned: 1 }, ...over });
const without = (k) => { const { [k]: _d, ...rest } = good(); return rest; };

const BAD = [
  { ok: true, scan_complete: true },
  good({ regions: "none" }),
  good({ count: "0", total_findings: "0" }),
  without("clean"),
  without("survivors"),
  without("off_page"),
  without("coverage"),
  good({ total_findings: 1 }),
  good({ count: 1, regions: [region] }),
  good({ clean: false }),
  good({ clean: false, count: 1, regions: [region], total_findings: 3 }),
  good({ clean: false, count: 2, regions: [region], total_findings: 1 }),
  good({ clean: false, count: 1, regions: [{ page: "0", kind: "email" }], total_findings: 1 }),
  good({ scan_complete: "true" }),
  good({ scan_complete: true, coverage: { scan_complete: false } }),
  // omitly#1864 round 4: complete beside an unread page, and a coverage that does not add up or is missing a field.
  good({ coverage: { pages_total: 1, pages_scanned: 0, pages_failed: [0], not_scanned: [], scan_complete: true } }),
  good({ coverage: { pages_total: 3, pages_scanned: 2, pages_failed: [1], not_scanned: [] } }),
  good({ coverage: { pages_total: 1, pages_scanned: 1, pages_failed: [], not_scanned: [], raster_only_pages: [0] } }),
  good({ coverage: { pages_total: 1, pages_scanned: 1, pages_failed: [], not_scanned: [], xmp_stream_unread: true } }),
  good({ coverage: { pages_total: 1, pages_scanned: 5, pages_failed: [], not_scanned: [] } }),
  good({ coverage: { pages_total: 1, pages_scanned: 1, not_scanned: [] } }),
  good({ coverage: { pages_total: 1, pages_scanned: 1, pages_failed: [] } }),
  good({ coverage: {} }),
  // omitly#1864 round 5: a completion claim beside a not_scanned disclosure that denies completion (detect.rs).
  good({ coverage: { pages_total: 1, pages_scanned: 1, pages_failed: [], not_scanned: ["Type0/CID text using a named encoding whose codespace ranges could not be verified (present in this file)"] } }),
  good({ coverage: { pages_total: 1, pages_scanned: 1, pages_failed: [], not_scanned: ["1 prior (superseded) revision(s) could not be scanned for leftover PII (x)"] } }),
  good({ coverage: { pages_total: 1, pages_scanned: 1, pages_failed: [], not_scanned: ["attachment 'a.txt' was still compressed"] } }),
  null,
  "x",
  { ok: false, error: "x" },
];
const GOOD = [good(), good({ scan_complete: false }), good({ clean: false, count: 1, regions: [region], total_findings: 1 }), (() => { const g = good(); delete g.scan_complete; return g; })(), good({ coverage: { pages_total: 1, pages_scanned: 1, pages_failed: [], not_scanned: ["text drawn as raster images (needs OCR)"] } }), good({ scan_complete: false, coverage: { pages_total: 1, pages_scanned: 1, pages_failed: [], not_scanned: ["2 embedded content stream(s) that failed to parse or could not be fully decoded"], scan_complete: false } })];

test("every defective scan reply is refused; every consistent one is read", () => {
  for (const r of BAD) assert.equal(parseScanReply(r).ok, false, JSON.stringify(r));
  for (const r of GOOD) assert.equal(parseScanReply(r).ok, true, JSON.stringify(r));
  assert.equal(parseScanReply(good()).value.scanComplete, true);
  assert.equal(parseScanReply(good({ scan_complete: false })).value.scanComplete, false);
  assert.equal(parseScanReply(GOOD[3]).value.scanComplete, null, "not reported is not complete");
});

test("locate replies: the count is the list", () => {
  assert.equal(parseLocateReply({ ok: true, count: 0, regions: [] }).ok, true);
  for (const r of [{ ok: true, count: 0 }, { ok: true, regions: [] }, { ok: true, count: 3, regions: [region] }, { ok: true, count: 0, regions: "none" }]) {
    assert.equal(parseLocateReply(r).ok, false, JSON.stringify(r));
  }
});

test("an incomplete or unreported scan has a warning line; a complete one has none", () => {
  assert.equal(incompleteLine(true), "");
  assert.match(incompleteLine(false), /INCOMPLETE SCAN/);
  assert.match(incompleteLine(null), /NOT REPORTED/);
});

const result = (state, over = {}) => ({
  state, blocking: false, summary: "Every mandatory check that applies to this file passed.", pagesTotal: 1, pagesRead: 1, checked: [{ text: "Metadata" }], notChecked: [],
  problems: [], review: [], information: [], decisions: [], reasons: [], checkedAt: "2026-11-13T01:00:00Z", omitlyVersion: "5.6.0", sha256: "a".repeat(64), sizeBytes: 40, ...over,
});
const cv = (state, blocking = false, over = {}, top = {}) => ({ verdict: state, blocking, reason_code: null, result: result(state, { blocking, ...over }), ...top });
const BAD_VERDICTS = [
  { verdict: "safe_to_send" },
  { ...cv("safe_to_send"), result: result("needs_review", { blocking: true, problems: [{ text: "x" }] }) },
  cv("safe_to_send", true),
  cv("safe_to_send", false, { problems: [{ text: "x" }] }),
  cv("safe_to_send", false, { review: [{ text: "x" }] }),
  cv("safe_to_send", false, { decisions: [{ text: "x" }] }),
  cv("safe_to_send", false, { reasons: [{ text: "x" }] }),
  cv("safe_to_send", false, { pagesTotal: 3, pagesRead: 1 }),
  cv("safe_to_send", false, { checked: [] }),
  cv("safe_to_send", false, { sha256: "" }),
  cv("safe_to_send", false, {}, { reason_code: "check_failed" }),
  cv("cannot_verify", true),
  { verdict: "needs_review", blocking: false, result: null, reason_code: null },
  { verdict: "all_good", blocking: false, result: null },
  null,
];
const GOOD_VERDICTS = [cv("safe_to_send"), cv("needs_review"), cv("needs_review", true, { problems: [{ text: "x" }] }), cv("cannot_verify"), { verdict: "cannot_verify", blocking: false, result: null, reason_code: "check_failed" }];

test("the pass contract of a check verdict: every defect is refused, every consistent verdict read", () => {
  for (const v of BAD_VERDICTS) assert.equal(parseCheckVerdict(v).ok, false, JSON.stringify(v));
  for (const v of GOOD_VERDICTS) assert.equal(parseCheckVerdict(v).ok, true, JSON.stringify(v));
});

test("the CommonJS parsers agree with the TypeScript ones (when the build is present)", async (t) => {
  const built = path.join(__dirname, "..", "..", "dist", "replies.js");
  if (!existsSync(built)) return t.skip("no dist/replies.js (run tsc)");
  const ts = await import(require("node:url").pathToFileURL(built).href);
  for (const r of [...BAD, ...GOOD]) {
    const a = parseScanReply(r);
    const b = ts.parseScanReply(r);
    assert.equal(a.ok, b.ok, JSON.stringify(r));
    if (!a.ok) assert.equal(a.reason, b.reason, JSON.stringify(r));
  }
  for (const r of [{ ok: true, count: 0, regions: [] }, { ok: true, count: 0 }, { ok: true, count: 3, regions: [region] }]) {
    assert.equal(parseLocateReply(r).ok, ts.parseLocateReply(r).ok);
  }
  for (const v of [...BAD_VERDICTS, ...GOOD_VERDICTS]) {
    const a = parseCheckVerdict(v);
    const b = ts.parseCheckVerdict(v);
    assert.equal(a.ok, b.ok, JSON.stringify(v));
    if (!a.ok) assert.equal(a.reason, b.reason, JSON.stringify(v));
  }
});
