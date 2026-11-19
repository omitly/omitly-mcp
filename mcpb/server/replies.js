/**
 * omitly#1864: PARSE, DON'T TRUST, for the MCPB bundle. A CommonJS port of the scan and locate parsers
 * in ../../src/replies.ts (the full server and the result card use that module); `replies.test.js`
 * compares the two over a table of replies when the build is present. A reply that is malformed,
 * incomplete in form or self-contradicting is `{ ok: false, reason }`: the caller returns an
 * execution failure (isError true, no verdict, no "clean"). Also ports `parseCheckVerdict`: the
 * engine's full pass contract for a `check` verdict (crates/omitly-seal/src/check.rs), not the
 * verdict word alone.
 */
"use strict";

const fail = (reason) => ({ ok: false, reason });
const isRecord = (v) => typeof v === "object" && v !== null && !Array.isArray(v);
const isCount = (v) => typeof v === "number" && Number.isInteger(v) && v >= 0;
const isNum = (v) => typeof v === "number" && Number.isFinite(v);

const unusableReplyMessage = (what, reason) =>
  `the ${what} answer was malformed or contradicted itself (${reason}), so no verdict is given. Do not treat this file as checked.`;

const isCountList = (v) => Array.isArray(v) && v.every(isCount);

// The not_scanned lines the engine sends only beside scan_complete:false (ENGINE_INCOMPLETE_DISCLOSURES in ../../src/coverage-rule.ts, from detect.rs).
const ENGINE_INCOMPLETE_DISCLOSURES = [
  /^\d+ page\(s\) are effectively image-only/,
  /^CID\/Identity-H text with a code not covered by the ToUnicode map/,
  /^Type0\/CID text using a named encoding whose codespace ranges could not be verified/,
  /^\d+ embedded content stream\(s\) that failed to parse or could not be fully decoded/,
  /^\d+ Form XObject\(s\) showing text in a font set by the page that draws them/,
  /^embedded-file attachment name tree could not be fully scanned/,
  /^\d+ page\(s\) could not be fully checked for text surviving under a redaction mark/,
  /^\d+ prior \(superseded\) revision\(s\) could not be scanned for leftover PII/,
  /^AcroForm field tree deeper than 16 levels was not fully scanned/,
  /^document information, form fields and attachments: /,
  /^XMP metadata stream (was |could not be read as text)/,
  /^attachment '[\s\S]*' was /,
  /^the file's structure \(object streams, cross-reference data or stream lengths\) did not read the same way twice/,
];

// The engine's `coverage` object (see coverageProblem in ../../src/replies.ts for the Rust it comes from).
/** The first line the engine sends only beside an incomplete scan, or null (`engineIncompleteDisclosure` in ../../src/coverage-rule.ts). */
function engineIncompleteDisclosure(lines) {
  for (const line of lines) if (typeof line === "string" && ENGINE_INCOMPLETE_DISCLOSURES.some((re) => re.test(line))) return line;
  return null;
}

/** Contract §4/§6.4: the text label of a not_scanned line (`disclosureLabel` in ../../src/coverage-rule.ts). */
const DISCLOSURE_LABELS = [
  [/^\d+ page\(s\) are effectively image-only/, "pages that are images only"],
  [/^text drawn as raster images \(needs OCR\)$/, "text drawn as images (not OCR'd)"],
  [/^CID\/Identity-H text with a code not covered by the ToUnicode map/, "text in a font that could not be decoded"],
  [/^text in font\(s\) /, "text whose drawn characters could not be confirmed"],
  [/^Type0\/CID text using a named encoding whose codespace ranges could not be verified/, "text in a font that could not be decoded"],
  [/^\d+ embedded content stream\(s\) that failed to parse or could not be fully decoded/, "content streams that could not be read"],
  [/^\d+ Form XObject\(s\) showing text in a font set by the page that draws them/, "form text that may be misread"],
  [/^embedded-file attachment name tree could not be fully scanned/, "attachments that could not be listed"],
  [/^\d+ page\(s\) could not be fully checked for text surviving under a redaction mark/, "pages where text under a mark could not be checked"],
  [/^\d+ prior \(superseded\) revision\(s\) could not be scanned for leftover PII/, "earlier versions that could not be read"],
  [/^the file's structure \(object streams, cross-reference data or stream lengths\) did not read the same way twice/, "parts of the file structure"],
  [/^AcroForm field tree deeper than 16 levels was not fully scanned/, "form fields nested too deep"],
  [/^document information, form fields and attachments: /, "document information, form fields and attachments"],
  [/^XMP metadata stream (was |could not be read as text)/, "the XMP metadata"],
  [/^attachment '[\s\S]*' was /, "an attachment"],
];
function disclosureLabel(line) {
  if (typeof line !== "string") return "a part of the file this server cannot name";
  for (const [re, label] of DISCLOSURE_LABELS) if (re.test(line)) return label;
  return "a part of the file this server cannot name";
}

function coverageProblem(cov) {
  if (!isCount(cov.pages_total)) return "coverage.pages_total is missing or not a count";
  if (!isCount(cov.pages_scanned)) return "coverage.pages_scanned is missing or not a count";
  if (!isCountList(cov.pages_failed)) return "coverage.pages_failed is missing or not a list of page numbers";
  if (!Array.isArray(cov.not_scanned) || !cov.not_scanned.every((n) => typeof n === "string")) return "coverage.not_scanned is missing or not a list";
  if (cov.pages_failed.some((p) => p >= cov.pages_total) || new Set(cov.pages_failed).size !== cov.pages_failed.length) {
    return "coverage.pages_failed lists a page that is not in the document, or lists one twice";
  }
  if (cov.pages_scanned + cov.pages_failed.length !== cov.pages_total) return "coverage.pages_scanned and pages_failed do not add up to pages_total";
  for (const k of ["raster_pages", "raster_only_pages", "survivor_pages_failed", "prior_revisions_failed"]) {
    if (cov[k] !== undefined && !isCountList(cov[k])) return `coverage.${k} is not a list of page numbers`;
  }
  for (const k of ["metadata_scanned", "acroform_scanned", "attachments_scanned", "prior_revisions_scanned", "acroform_tree_incomplete", "xmp_stream_unread", "attachment_content_unread", "attachment_tree_unread"]) {
    if (cov[k] !== undefined && typeof cov[k] !== "boolean") return `coverage.${k} is not a flag`;
  }
  for (const k of ["form_xobjects_scanned", "annotation_appearances_scanned", "embedded_streams_failed"]) {
    if (cov[k] !== undefined && !isCount(cov[k])) return `coverage.${k} is not a count`;
  }
  if (cov.scan_complete === true) {
    const unread = [];
    if (cov.pages_failed.length) unread.push("a failed page");
    for (const k of ["raster_only_pages", "survivor_pages_failed", "prior_revisions_failed"]) {
      if (Array.isArray(cov[k]) && cov[k].length) unread.push(k);
    }
    if (typeof cov.embedded_streams_failed === "number" && cov.embedded_streams_failed > 0) unread.push("embedded_streams_failed");
    for (const k of ["acroform_tree_incomplete", "xmp_stream_unread", "attachment_content_unread", "attachment_tree_unread"]) {
      if (cov[k] === true) unread.push(k);
    }
    if (engineIncompleteDisclosure(cov.not_scanned) !== null) unread.push("a disclosure that denies completion");
    if (unread.length) return `scan_complete is true beside ${[...new Set(unread)].join(", ")}`;
  }
  return null;
}

function regionList(v, name) {
  if (!Array.isArray(v)) return fail(`${name} is not a list`);
  for (const r of v) {
    if (!isRecord(r) || !isCount(r.page) || typeof r.kind !== "string" || r.kind.length === 0 || typeof r.preview !== "string" || !isNum(r.x) || !isNum(r.y) || !isNum(r.width) || !isNum(r.height)) {
      return fail(`an entry of ${name} is malformed`);
    }
    if (r.under_redaction !== undefined && typeof r.under_redaction !== "boolean") return fail(`an entry of ${name} is malformed`);
  }
  return { ok: true, value: v };
}

// Contract C6 (see NATIVE_COVERAGE_KEYS in ../../src/replies.ts): the coverage keys each engine always sends. `scan_complete` is left out: an
// absent one is "incomplete", never a parse failure (C4).
const NATIVE_COVERAGE_KEYS = [
  "pages_total", "pages_scanned", "pages_failed", "prior_revisions_scanned", "metadata_scanned", "acroform_scanned", "attachments_scanned",
  "form_xobjects_scanned", "annotation_appearances_scanned", "raster_pages", "raster_only_pages", "not_scanned",
];
const WASM_COVERAGE_KEYS = [
  ...NATIVE_COVERAGE_KEYS, "survivor_pages_failed", "prior_revisions_failed", "embedded_streams_failed", "acroform_tree_incomplete",
  "xmp_stream_unread", "attachment_content_unread", "attachment_tree_unread",
];

function parseScanReply(res, opts = {}) {
  if (!isRecord(res) || res.ok !== true) return fail("not an ok reply");
  const regions = regionList(res.regions, "regions");
  if (!regions.ok) return regions;
  const survivors = regionList(res.survivors, "survivors");
  if (!survivors.ok) return survivors;
  if (!Array.isArray(res.off_page)) return fail("off_page is not a list");
  for (const f of res.off_page) {
    if (!isRecord(f) || typeof f.source !== "string" || typeof f.kind !== "string" || f.kind.length === 0 || typeof f.preview !== "string") return fail("an entry of off_page is malformed");
  }
  if (typeof res.clean !== "boolean") return fail("clean is missing or not a flag");
  if (!isCount(res.total_findings)) return fail("total_findings is missing or not a count");
  if (!isCount(res.count)) return fail("count is missing or not a count");
  if (!isRecord(res.coverage)) return fail("coverage is missing");
  if (opts.engine) {
    for (const k of opts.engine === "wasm" ? WASM_COVERAGE_KEYS : NATIVE_COVERAGE_KEYS) {
      if (!(k in res.coverage)) return fail(`coverage.${k} is missing`);
    }
  }
  const covProblem = coverageProblem(res.coverage);
  if (covProblem) return fail(covProblem);
  const listed = regions.value.length + survivors.value.length + res.off_page.length;
  if (res.count !== regions.value.length) return fail("count disagrees with the regions listed");
  if (res.total_findings !== listed) return fail("total_findings disagrees with the items listed");
  if (res.clean !== (res.total_findings === 0)) return fail("clean disagrees with total_findings");
  const top = res.scan_complete;
  const inner = res.coverage.scan_complete;
  if (top !== undefined && typeof top !== "boolean") return fail("scan_complete is not a flag");
  if (inner !== undefined && typeof inner !== "boolean") return fail("coverage.scan_complete is not a flag");
  if (top !== undefined && inner !== undefined && top !== inner) return fail("scan_complete disagrees with coverage.scan_complete");
  const scanComplete = top !== undefined ? top : inner !== undefined ? inner : null;
  if (scanComplete === true && inner === undefined) {
    const unread = coverageProblem({ ...res.coverage, scan_complete: true });
    if (unread) return fail(unread);
  }
  return {
    ok: true,
    value: { regions: regions.value, survivors: survivors.value, offPage: res.off_page, clean: res.clean, total: res.total_findings, count: res.count, scanComplete, topComplete: top !== undefined ? top : null, covComplete: inner !== undefined ? inner : null, coverage: res.coverage },
  };
}

function parseLocateReply(res) {
  if (!isRecord(res) || res.ok !== true) return fail("not an ok reply");
  const regions = regionList(res.regions, "regions");
  if (!regions.ok) return regions;
  if (!isCount(res.count) || res.count !== regions.value.length) return fail("count disagrees with the regions listed");
  return { ok: true, value: { regions: regions.value } };
}

const STATES = ["safe_to_send", "needs_review", "cannot_verify"];
const CHECK_REASON_CODES = ["input_too_large", "check_failed", "check_unavailable", "result_invalid"];
const SECTION_KEYS = ["checked", "notChecked", "problems", "review", "information", "decisions", "reasons"];
const itemList = (v) => Array.isArray(v) && v.every((i) => isRecord(i) && typeof i.text === "string");

/** A `check` verdict, as ../../src/replies.ts `parseCheckVerdict` reads it (same rules, same reasons). */
function parseCheckVerdict(v) {
  if (!isRecord(v) || !STATES.includes(v.verdict)) return fail("verdict is missing or unknown");
  if (typeof v.blocking !== "boolean") return fail("blocking is missing or not a flag");
  const rc = v.reason_code;
  if (rc !== undefined && rc !== null && !(typeof rc === "string" && CHECK_REASON_CODES.includes(rc))) return fail("reason_code is unknown");
  if (rc !== undefined && rc !== null && v.verdict !== "cannot_verify") return fail("a reason code beside a verdict that is not Cannot Verify");
  if (v.verdict === "cannot_verify" && v.blocking) return fail("Cannot Verify is blocking");
  const r = v.result;
  if (r === null || r === undefined) {
    if (v.verdict !== "cannot_verify") return fail("a verdict without its result");
    return { ok: true, value: { verdict: v.verdict, blocking: v.blocking } };
  }
  if (!isRecord(r)) return fail("result is malformed");
  if (r.state !== v.verdict || r.blocking !== v.blocking) return fail("the verdict disagrees with its result");
  for (const k of SECTION_KEYS) if (!itemList(r[k])) return fail(`result.${k} is missing`);
  // v0.2.1 (errata 6): a page list is bounded by the reply itself (src/replies.ts `parseCheckVerdict`).
  for (const k of SECTION_KEYS) {
    for (const it of r[k]) {
      if (it.pages === undefined) continue;
      if (!Array.isArray(it.pages) || !isCount(r.pagesTotal)) return fail(`result.${k} lists pages the reply cannot bound`);
      const seen = new Set();
      for (const pg of it.pages) {
        if (!Number.isInteger(pg) || pg < 1 || pg > r.pagesTotal || seen.has(pg)) return fail(`result.${k} lists a page outside the file, or one twice`);
        seen.add(pg);
      }
    }
  }
  if (typeof r.summary !== "string") return fail("result.summary is missing");
  if (v.verdict === "safe_to_send") {
    if (!isCount(r.pagesTotal) || !isCount(r.pagesRead) || r.pagesRead > r.pagesTotal) return fail("result.pagesTotal or pagesRead is missing or inconsistent");
    if (typeof r.checkedAt !== "string" || typeof r.omitlyVersion !== "string") return fail("result.checkedAt or omitlyVersion is missing");
    if (typeof r.sha256 !== "string" || !/^([0-9a-f]{64})?$/.test(r.sha256)) return fail("result.sha256 is missing or malformed");
    if (!isCount(r.sizeBytes)) return fail("result.sizeBytes is missing");
    if (v.blocking) return fail("a pass is blocking");
    if (rc !== undefined && rc !== null) return fail("a pass with a reason code");
    const lens = (k) => r[k].length;
    if (lens("problems") || lens("review") || lens("reasons") || lens("decisions")) return fail("a pass beside problems, review items, decisions or reasons");
    if (lens("checked") === 0) return fail("a pass with nothing checked");
    if (r.pagesRead !== r.pagesTotal) return fail("a pass with pages not read");
    if (r.sha256.length !== 64 || r.summary.length === 0) return fail("a pass without the file's digest and summary");
  }
  return { ok: true, value: { verdict: v.verdict, blocking: v.blocking } };
}

/** The `ScanLeg` of a parsed scan reply (contract §7.1; `scanLegOf` in ../../src/replies.ts). */
function scanLegOf(v, engine) {
  const cov = v.coverage;
  const n = (k) => (Array.isArray(cov[k]) ? cov[k].length : 0);
  return {
    engine,
    total: v.total,
    survivors: v.survivors.length,
    topComplete: v.topComplete,
    covComplete: v.covComplete,
    notScanned: Array.isArray(cov.not_scanned) ? cov.not_scanned : [],
    pagesFailed: n("pages_failed"),
    listsNonEmpty: v.regions.length + v.survivors.length + v.offPage.length > 0,
    embeddedStreamsFailed: typeof cov.embedded_streams_failed === "number" ? cov.embedded_streams_failed : 0,
    flagsSet:
      n("raster_only_pages") > 0 || n("survivor_pages_failed") > 0 || n("prior_revisions_failed") > 0 ||
      ["acroform_tree_incomplete", "xmp_stream_unread", "attachment_content_unread", "attachment_tree_unread"].some((k) => cov[k] === true),
  };
}

/** The `CheckLeg` of a verdict that passed `parseCheckVerdict` (`checkLegOf` in ../../src/replies.ts). */
function checkLegOf(v) {
  return { verdict: v.verdict, blocking: v.blocking, reasonCode: typeof v.reason_code === "string" ? v.reason_code : null, result: v.result || null };
}

/** The warning line for a scan that did not read everything, or did not say. "" when it did. */
function incompleteLine(scanComplete) {
  return scanComplete === true
    ? ""
    : scanComplete === false
      ? "⛔ INCOMPLETE SCAN — some of this document was not read, so the result below speaks only for what was read (possibly nothing). This is NOT a clean result.\n\n"
      : "⛔ SCAN COMPLETENESS NOT REPORTED — this engine did not say whether every page and stream was read, so the result below is not a pass.\n\n";
}

module.exports = {
  ENGINE_INCOMPLETE_DISCLOSURES,
  NATIVE_COVERAGE_KEYS,
  WASM_COVERAGE_KEYS,
  engineIncompleteDisclosure,
  disclosureLabel,
  scanLegOf,
  checkLegOf,
  parseScanReply,
  parseLocateReply,
  parseCheckVerdict,
  unusableReplyMessage,
  incompleteLine,
};
