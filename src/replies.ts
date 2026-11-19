/**
 * omitly#1864: PARSE, DON'T TRUST. Every reply an engine gives (wasm or native) and every structured
 * result the result card is handed goes through ONE strict parser per reply type before any other code
 * reads it. A parser requires every field a verdict depends on to be present and of the right type,
 * allows no field to default (a missing list is a failure, never an empty list; a missing flag is a
 * failure, never `true`), and checks the reply against itself. A reply that fails is an EXECUTION
 * FAILURE for the caller: isError true, no verdict, no "clean", no green, a plain message.
 *
 * Browser-safe (the card bundle includes it): no Node imports. The MCPB bundle cannot import this
 * module, so `mcpb/server/replies.js` is a CommonJS port, compared with this file over a table of
 * replies by `mcpb/server/replies.test.js`.
 *
 * Fields the engine contract leaves optional, and why:
 *  - scan reply `scan_complete` (and `coverage.scan_complete`): absent on an engine older than
 *    omitly#1473. Absent is read as "not complete" (`scanComplete: null`), never as complete, and the
 *    text says completeness was not reported.
 *  - scan reply `note`: the wasm tier's own remark about region narrowing.
 */

import { legsDisagree, type ResultLike, type VerdictLike } from "./verdict-rule.js";
import { OUTCOMES, type CheckLeg, type ParsedAudit, type ParsedVerify, type ScanLeg } from "./outcome.js";
import { isProductNotice, LEGACY_CAUTION_PREFIX } from "./seal.js";

export type Parsed<T> = { ok: true; value: T } | { ok: false; reason: string };
const fail = <T>(reason: string): Parsed<T> => ({ ok: false, reason });

export const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const isCount = (v: unknown): v is number => typeof v === "number" && Number.isInteger(v) && v >= 0;
const isNum = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v);

/** The plain message every caller shows for a reply that failed its parser. Contains no document text. */
export const unusableReplyMessage = (what: string, reason: string) =>
  `the ${what} answer was malformed or contradicted itself (${reason}), so no verdict is given. Do not treat this file as checked.`;

// ---------------------------------------------------------------------------------------------------
// Scan reply (`find`, and the wasm `scan` after its shape translation)
// ---------------------------------------------------------------------------------------------------

export interface ScanRegion {
  page: number;
  x: number;
  y: number;
  width: number;
  height: number;
  kind: string;
  preview: string;
}
export interface ScanOffPage {
  source: string;
  kind: string;
  preview: string;
}
export interface ScanReply {
  regions: ScanRegion[];
  survivors: ScanRegion[];
  offPage: ScanOffPage[];
  clean: boolean;
  total: number;
  count: number;
  /** `null`: the engine did not say. Treated as not complete. */
  scanComplete: boolean | null;
  /** The two flags as sent (null: absent). C4 needs both `true`. */
  topComplete: boolean | null;
  covComplete: boolean | null;
  coverage: Record<string, unknown>;
}

const isCountList = (v: unknown): v is number[] => Array.isArray(v) && v.every(isCount);

/**
 * The engine's `coverage` object, with the rules both engines' replies obey. Native `find`
 * (crates/omitly-cli/src/main.rs `do_find`, the `"coverage"` object) and the wasm `scan`
 * (crates/leakcheck-wasm/src/lib.rs `ScanResult.coverage`, a `redaction_core::detect::Coverage`,
 * crates/redaction-core/src/detect.rs) both always send `pages_total`, `pages_scanned`,
 * `pages_failed`, `not_scanned` and `scan_complete`; the wasm one also sends the `*_failed` /
 * `*_unread` / `*_incomplete` fields of omitly#1479 and #1518.
 *
 * The scan is complete (detect.rs `scan_complete = pages_failed.is_empty() && survivor_pages_failed
 * .is_empty() && prior_revisions_failed.is_empty() && embedded.failed == 0 && ... &&
 * raster_only_pages.is_empty() && ...`) only when nothing it tried to read went unread, and
 * `pages_scanned = pages_total - pages_failed.len()`. A reply that says complete beside a failed
 * page, an image-only page or an unread stream contradicts itself, so it is no scan result.
 */
import { ENGINE_INCOMPLETE_DISCLOSURES, engineIncompleteDisclosure } from "./coverage-rule.js";
export { ENGINE_INCOMPLETE_DISCLOSURES };

function coverageProblem(cov: Record<string, unknown>): string | null {
  if (!isCount(cov.pages_total)) return "coverage.pages_total is missing or not a count";
  if (!isCount(cov.pages_scanned)) return "coverage.pages_scanned is missing or not a count";
  if (!isCountList(cov.pages_failed)) return "coverage.pages_failed is missing or not a list of page numbers";
  if (!Array.isArray(cov.not_scanned) || !cov.not_scanned.every((n) => typeof n === "string")) return "coverage.not_scanned is missing or not a list";
  if (cov.pages_failed.some((p) => p >= (cov.pages_total as number)) || new Set(cov.pages_failed).size !== cov.pages_failed.length) {
    return "coverage.pages_failed lists a page that is not in the document, or lists one twice";
  }
  if (cov.pages_scanned + cov.pages_failed.length !== cov.pages_total) return "coverage.pages_scanned and pages_failed do not add up to pages_total";
  for (const k of ["raster_pages", "raster_only_pages", "survivor_pages_failed", "prior_revisions_failed"]) {
    if (cov[k] !== undefined && !isCountList(cov[k])) return `coverage.${k} is not a list of page numbers`;
  }
  for (const k of [
    "metadata_scanned",
    "acroform_scanned",
    "attachments_scanned",
    "prior_revisions_scanned",
    "acroform_tree_incomplete",
    "xmp_stream_unread",
    "attachment_content_unread",
    "attachment_tree_unread",
  ]) {
    if (cov[k] !== undefined && typeof cov[k] !== "boolean") return `coverage.${k} is not a flag`;
  }
  for (const k of ["form_xobjects_scanned", "annotation_appearances_scanned", "embedded_streams_failed"]) {
    if (cov[k] !== undefined && !isCount(cov[k])) return `coverage.${k} is not a count`;
  }
  if (cov.scan_complete === true) {
    const unread: string[] = [];
    if (cov.pages_failed.length) unread.push("a failed page");
    for (const k of ["raster_only_pages", "survivor_pages_failed", "prior_revisions_failed"]) {
      if (Array.isArray(cov[k]) && (cov[k] as unknown[]).length) unread.push(k);
    }
    if (typeof cov.embedded_streams_failed === "number" && cov.embedded_streams_failed > 0) unread.push("embedded_streams_failed");
    for (const k of ["acroform_tree_incomplete", "xmp_stream_unread", "attachment_content_unread", "attachment_tree_unread"]) {
      if (cov[k] === true) unread.push(k);
    }
    if (engineIncompleteDisclosure(cov.not_scanned as string[]) !== null) unread.push("a disclosure that denies completion");
    if (unread.length) return `scan_complete is true beside ${[...new Set(unread)].join(", ")}`;
  }
  return null;
}

function regionList(v: unknown, name: string): Parsed<ScanRegion[]> {
  if (!Array.isArray(v)) return fail(`${name} is not a list`);
  for (const r of v) {
    if (
      !isRecord(r) ||
      !isCount(r.page) ||
      typeof r.kind !== "string" ||
      r.kind.length === 0 ||
      typeof r.preview !== "string" ||
      !isNum(r.x) ||
      !isNum(r.y) ||
      !isNum(r.width) ||
      !isNum(r.height)
    ) {
      return fail(`an entry of ${name} is malformed`);
    }
    // Native `find` lists `under_redaction` on page regions (main.rs `do_find`); the wasm one does not.
    if (r.under_redaction !== undefined && typeof r.under_redaction !== "boolean") return fail(`an entry of ${name} is malformed`);
  }
  return { ok: true, value: v as ScanRegion[] };
}

/**
 * `narrowed`: a native `find` with a `regions` filter lists fewer kinds than it counts, so there the
 * total may exceed the items listed; everywhere else the total IS the items listed.
 */
/** Contract C6: the coverage keys each engine always sends (native main.rs:1628-1642; wasm adds the failure and unread flags).
 *  CONTRACT-QUESTION: C6 lists `scan_complete` among the required keys, but C4 reads an absent `scan_complete` as "incomplete,
 *  never a parse failure" (the engines before omitly#1473 sent none), so it is left out of the required set: absent stays
 *  incomplete, which is the fail-safe reading either way. */
export const NATIVE_COVERAGE_KEYS = [
  "pages_total", "pages_scanned", "pages_failed", "prior_revisions_scanned", "metadata_scanned", "acroform_scanned", "attachments_scanned",
  "form_xobjects_scanned", "annotation_appearances_scanned", "raster_pages", "raster_only_pages", "not_scanned",
] as const;
export const WASM_COVERAGE_KEYS = [
  ...NATIVE_COVERAGE_KEYS, "survivor_pages_failed", "prior_revisions_failed", "embedded_streams_failed", "acroform_tree_incomplete",
  "xmp_stream_unread", "attachment_content_unread", "attachment_tree_unread",
] as const;

export function parseScanReply(res: unknown, opts: { narrowed?: boolean; engine?: "native" | "wasm" } = {}): Parsed<ScanReply> {
  if (!isRecord(res) || res.ok !== true) return fail("not an ok reply");
  const regions = regionList(res.regions, "regions");
  if (!regions.ok) return regions;
  const survivors = regionList(res.survivors, "survivors");
  if (!survivors.ok) return survivors;
  if (!Array.isArray(res.off_page)) return fail("off_page is not a list");
  for (const f of res.off_page) {
    if (!isRecord(f) || typeof f.source !== "string" || typeof f.kind !== "string" || f.kind.length === 0 || typeof f.preview !== "string") {
      return fail("an entry of off_page is malformed");
    }
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
  const listed = regions.value.length + survivors.value.length + (res.off_page as unknown[]).length;
  if (res.count !== regions.value.length) return fail("count disagrees with the regions listed");
  if (opts.narrowed ? res.total_findings < listed : res.total_findings !== listed) return fail("total_findings disagrees with the items listed");
  if (res.clean !== (res.total_findings === 0)) return fail("clean disagrees with total_findings");
  const top = res.scan_complete;
  const inner = res.coverage.scan_complete;
  if (top !== undefined && typeof top !== "boolean") return fail("scan_complete is not a flag");
  if (inner !== undefined && typeof inner !== "boolean") return fail("coverage.scan_complete is not a flag");
  if (top !== undefined && inner !== undefined && top !== inner) return fail("scan_complete disagrees with coverage.scan_complete");
  const scanComplete = (top ?? inner ?? null) as boolean | null;
  // A top-level `scan_complete: true` over a coverage that does not say so is the same contradiction.
  if (scanComplete === true && inner === undefined) {
    const unread = coverageProblem({ ...res.coverage, scan_complete: true });
    if (unread) return fail(unread);
  }
  return {
    ok: true,
    value: {
      regions: regions.value,
      survivors: survivors.value,
      offPage: res.off_page as ScanOffPage[],
      clean: res.clean,
      total: res.total_findings,
      count: res.count,
      scanComplete,
      topComplete: (top ?? null) as boolean | null,
      covComplete: (inner ?? null) as boolean | null,
      coverage: res.coverage,
    },
  };
}

/** The `ScanLeg` of a parsed scan reply (contract §7.1), for `passOutcome`. */
export function scanLegOf(v: ScanReply, engine: "native" | "wasm"): ScanLeg {
  const cov = v.coverage;
  const n = (k: string) => (Array.isArray(cov[k]) ? (cov[k] as unknown[]).length : 0);
  return {
    engine,
    total: v.total,
    survivors: v.survivors.length,
    topComplete: v.topComplete,
    covComplete: v.covComplete,
    notScanned: (Array.isArray(cov.not_scanned) ? cov.not_scanned : []) as string[],
    pagesFailed: n("pages_failed"),
    listsNonEmpty: v.regions.length + v.survivors.length + v.offPage.length > 0,
    embeddedStreamsFailed: typeof cov.embedded_streams_failed === "number" ? cov.embedded_streams_failed : 0,
    flagsSet:
      n("raster_only_pages") > 0 || n("survivor_pages_failed") > 0 || n("prior_revisions_failed") > 0 ||
      ["acroform_tree_incomplete", "xmp_stream_unread", "attachment_content_unread", "attachment_tree_unread"].some((k) => cov[k] === true),
  };
}

/** The `CheckLeg` of a verdict that passed `parseCheckVerdict` (the RAW result: information is read before any rewording). */
export function checkLegOf(v: { verdict: string; blocking: boolean; reason_code?: unknown; result: unknown }): CheckLeg {
  return {
    verdict: v.verdict as CheckLeg["verdict"],
    blocking: v.blocking,
    reasonCode: typeof v.reason_code === "string" ? v.reason_code : null,
    result: (v.result ?? null) as ResultLike | null,
  };
}

/** A `locate_text` reply: its count is the occurrences listed. */
export function parseLocateReply(res: unknown): Parsed<{ regions: ScanRegion[] }> {
  if (!isRecord(res) || res.ok !== true) return fail("not an ok reply");
  const regions = regionList(res.regions, "regions");
  if (!regions.ok) return regions;
  if (!isCount(res.count) || res.count !== regions.value.length) return fail("count disagrees with the regions listed");
  return { ok: true, value: { regions: regions.value } };
}

// ---------------------------------------------------------------------------------------------------
// Sidecar `verify` reply (native engine, the file's own audit sidecar)
// ---------------------------------------------------------------------------------------------------

/**
 * The sidecar `verify` reply (crates/omitly-cli/src/main.rs `do_verify`): `scan_performed: false`,
 * `verdict` "pass" | "fail", `regions: [{page, reason, verification}]`, `metadataScrubbed`,
 * `hiddenContent: [{class, verification}]`, always all of them, on a "fail" too.
 * The verdict is `compute_all_pass` (main.rs): every region `verification.result` is "pass", every
 * hidden-content check passes AND `metadataScrubbed` is true (omitly#490). So a "pass" needs both
 * lists, every entry with a result, none failing and `metadataScrubbed === true`, and the verdict
 * word must be what those say: a "fail" beside an all-pass reply is as contradictory as a "pass"
 * beside a failing entry. Any other verdict word is a failure to parse, not a "fail" the text could
 * soften. The reply never reports a whole-file scan (`scan_performed` is false).
 */
const HIDDEN_CONTENT_CLASSES = [
  "thumbnails",
  "document-actions",
  "embedded-files",
  "incremental-revisions",
  "hidden-layers",
  "comment-annotations",
  "signature-identity",
  "semantic-text",
  "labels",
  "redacted-text-in-strings",
];

export function parseSidecarVerifyReply(res: unknown): Parsed<{ verdict: "pass" | "fail"; reply: ParsedVerify }> {
  if (!isRecord(res) || res.ok !== true) return fail("not an ok reply");
  if (res.verdict !== "pass" && res.verdict !== "fail") return fail("verdict is missing or unknown");
  if (res.scan_performed !== undefined && res.scan_performed !== false) return fail("scan_performed is not false");
  if (typeof res.metadataScrubbed !== "boolean") return fail("metadataScrubbed is missing or not a flag");
  // v0.2.1 (errata 1): the sidecar's `warnings` (main.rs:1171) always travel with the reply and are always text; a reply without them, or with
  // anything else, is not the engine's, so no cap could be read from it.
  if (!Array.isArray(res.warnings) || !res.warnings.every((w) => typeof w === "string")) return fail("warnings is missing or not a list of text");
  let anyFail = false;
  for (const key of ["regions", "hiddenContent"] as const) {
    const list = res[key];
    if (!Array.isArray(list)) return fail(`${key} is missing`);
    for (const e of list) {
      const v = isRecord(e) && isRecord(e.verification) ? e.verification : undefined;
      const r = v?.result;
      if (r !== "pass" && r !== "fail") return fail(`an entry of ${key} has no result`);
      if (r === "fail") {
        anyFail = true;
        if (typeof v?.detail !== "string") return fail(`a failing entry of ${key} has no detail`);
      }
    }
  }
  // `verify` always runs the ten hidden-content checks (crates/redaction-core/src/verify.rs:233-308, one per
  // `HiddenContentClass`, warning.rs:43-56): a list with any missing, repeated or unknown class is not the
  // engine's, whatever its entries say.
  const classes = (res.hiddenContent as { class?: unknown }[]).map((c) => c.class);
  if (classes.length !== HIDDEN_CONTENT_CLASSES.length || new Set(classes).size !== classes.length || !classes.every((c) => HIDDEN_CONTENT_CLASSES.includes(c as string))) {
    return fail("hiddenContent is not the engine's ten checks");
  }
  const allPass = !anyFail && res.metadataScrubbed === true;
  if (res.verdict === "pass" && !allPass) return fail(anyFail ? "verdict is pass beside a failing entry" : "verdict is pass beside unscrubbed metadata");
  if (res.verdict === "fail" && allPass) return fail("verdict is fail beside nothing failing");
  return { ok: true, value: { verdict: res.verdict, reply: res as unknown as ParsedVerify } };
}

// ---------------------------------------------------------------------------------------------------
// Seal reply (`verify_seal`, for verify_seal and verify_document)
// ---------------------------------------------------------------------------------------------------

export const SEAL_REPLY_VERDICTS = [
  "no_report",
  "seal_invalid",
  "seal_unsupported_version",
  "report_unparseable",
  "unsupported_schema",
  "incomplete",
  "verified",
] as const;
const USER_VERDICTS = ["safe_to_send", "needs_review", "cannot_verify"];

const V2_OVERALLS: Record<string, [string, boolean]> = {
  pass: ["safe_to_send", false],
  pass_with_operator_decisions: ["needs_review", false],
  review_required: ["needs_review", false],
  unsafe: ["needs_review", true],
  technical_fail: ["cannot_verify", false],
};

/**
 * What the engine's seal reply must hold, and must not contradict (crates/omitly-cli/src/main.rs
 * `do_verify_seal_with`; crates/omitly-seal/src/lib.rs `VerifyResult`, `verify_report_bytes`).
 *
 * v1 vocabulary: "verified" is `seal_valid && all_passed`; "incomplete" is a valid seal over a report
 * that did not pass; "seal_invalid" is an invalid seal. `sealRemoved` (omitly#1591) is a REASON for a
 * failed seal (`with_seal_removed` sets it only beside `seal_valid` false, or `audit_v2_seal_valid`
 * `Some(false)`), so a pass beside `sealRemoved: true` contradicts itself.
 *
 * v2 (verdict "unsupported_schema", `auditV2Recognized`): `audit_v2_overall` is `Some` only when EVERY
 * `verify_v2` gate passed, seal first (lib.rs: `audit_v2_seal_valid = Some(gate.is_ok())`,
 * `audit_v2_overall` set only in the `Ok(trusted)` arm). So a non-null `auditV2Overall` needs
 * `auditV2SealValid: true`, no `auditV2ValidationError` and no removed seal, and its `userVerdict` /
 * `blocking` are `to_user_verdict(overall)` (audit_v2.rs); a recognised report with no overall is
 * always `cannot_verify`, not blocking, with a validation error or a failed seal. The v2 triple's own
 * mapping is also enforced by `v2Verdict` (seal.ts), which answers Cannot Verify for a mismatch: that
 * stays, it never reads positive.
 *
 * `opts.structured`: the tool's own structuredContent, which is the normalised result and does not carry
 * `auditV2Recognized`, `auditV2SealValid` or `auditV2ValidationError`; a user verdict there IS the v2 report.
 */
export function parseSealReply(res: unknown, opts: { structured?: boolean } = {}): Parsed<Record<string, unknown>> {
  if (!isRecord(res) || res.ok !== true) return fail("not an ok reply");
  const verdict = res.verdict;
  if (typeof verdict !== "string" || !(SEAL_REPLY_VERDICTS as readonly string[]).includes(verdict)) return fail("verdict is missing or unknown");
  // The tool's structured result does not carry `auditV2Recognized`: there a user verdict IS the v2 report.
  const v2 = res.auditV2Recognized === true || (opts.structured === true && res.userVerdict !== undefined && res.userVerdict !== null);
  if (res.auditV2Recognized !== undefined && typeof res.auditV2Recognized !== "boolean") return fail("auditV2Recognized is not a flag");
  const sealValid = res.sealValid;
  if (verdict !== "seal_unsupported_version") {
    if (sealValid !== null && typeof sealValid !== "boolean") return fail("sealValid is missing or not a flag");
    if (sealValid === null && verdict !== "unsupported_schema") return fail("sealValid is null for a verdict that needs a flag");
  }
  const uv = res.userVerdict;
  if (uv !== undefined && uv !== null && !USER_VERDICTS.includes(uv as string)) return fail("userVerdict is unknown");
  if (res.blocking !== undefined && res.blocking !== null && typeof res.blocking !== "boolean") return fail("blocking is not a flag");
  if (res.sealRemoved !== undefined && typeof res.sealRemoved !== "boolean") return fail("sealRemoved is not a flag");
  if (res.auditV2SealValid !== undefined && res.auditV2SealValid !== null && typeof res.auditV2SealValid !== "boolean") return fail("auditV2SealValid is not a flag");
  const carriesV2 = v2 || (uv !== undefined && uv !== null) || (res.auditV2Overall !== undefined && res.auditV2Overall !== null);
  const removed = res.sealRemoved === true;
  switch (verdict) {
    case "verified":
      if (sealValid !== true || res.allPassed !== true) return fail("verified without a valid seal and allPassed");
      if (removed) return fail("verified beside a removed seal");
      if (carriesV2) return fail("a v1 verified carries v2 verdict fields");
      if (!opts.structured) {
        // A v1 report's pass is `all_passed` (every region verified, metadata scrubbed unless its preservation was
        // requested, no engine warning: redaction-core engine.rs `all_passed`), gated on the seal (lib.rs). The reply always
        // sends `metadataScrubbed`, the report's `warnings` (its product notices, plus the verifier's legacy CAUTION line
        // exactly when `legacyUnboundVerdict` is true, lib.rs:1087) and `legacyUnboundVerdict` (main.rs verified reply).
        if (typeof res.metadataScrubbed !== "boolean") return fail("verified without metadataScrubbed");
        if (!Array.isArray(res.warnings) || !res.warnings.every((w) => typeof w === "string")) return fail("verified without its warnings list");
        if (typeof res.legacyUnboundVerdict !== "boolean") return fail("verified without legacyUnboundVerdict");
        const ws = res.warnings as string[];
        // errata C1: only the VERIFIER's own caution is tied to the flag: it is inserted at index 0 exactly when `legacyUnboundVerdict` is true
        // (omitly-seal lib.rs:1087). The report's own warnings are copied unchanged from the file (lib.rs:1055), so a self-sealed report may
        // hold a CAUTION-looking line of its own with the flag false; that is a report warning (S7), not a malformed reply.
        if (res.legacyUnboundVerdict === true && !(ws.length > 0 && ws[0]!.startsWith(LEGACY_CAUTION_PREFIX))) return fail("legacyUnboundVerdict is true without the verifier's caution at the head of the warnings");
      } else if (typeof res.metadataScrubbed !== "boolean" || !Array.isArray(res.warnings)) {
        // The tool's own structured result of a v1 pass carries both (the server refused the reply otherwise).
        return fail("a verified result without metadataScrubbed and warnings");
      }
      break;
    case "incomplete":
      if (sealValid !== true || res.allPassed !== false) return fail("incomplete without a valid seal and allPassed false");
      if (removed) return fail("incomplete beside a removed seal");
      if (carriesV2) return fail("a v1 incomplete carries v2 verdict fields");
      break;
    case "seal_invalid":
      if (sealValid !== false) return fail("seal_invalid beside a valid seal");
      if (carriesV2) return fail("seal_invalid carries v2 verdict fields");
      break;
    case "no_report":
    case "report_unparseable":
      if (removed) return fail(`${verdict} beside a removed seal`);
      if (carriesV2) return fail(`${verdict} carries v2 verdict fields`);
      break;
    case "unsupported_schema": {
      if (!v2 && carriesV2) return fail("v2 verdict fields without a recognised v2 report");
      if (!v2) {
        if (removed) return fail("a removed seal beside no recognised report");
        break;
      }
      const overall = res.auditV2Overall;
      if (overall !== undefined && overall !== null && !(typeof overall === "string" && overall in V2_OVERALLS)) return fail("auditV2Overall is unknown");
      if (!opts.structured && typeof res.auditV2SealValid !== "boolean") return fail("auditV2SealValid is missing for a recognised v2 report");
      if (res.auditV2ValidationError !== undefined && res.auditV2ValidationError !== null && typeof res.auditV2ValidationError !== "string") return fail("auditV2ValidationError is not text");
      if (overall !== undefined && overall !== null) {
        // Every gate passed: the seal held, nothing was left unverified, nothing was removed.
        if (res.auditV2SealValid === false) return fail("a v2 verdict beside a failed seal");
        if (typeof res.auditV2ValidationError === "string") return fail("a v2 verdict beside a validation error");
        if (removed) return fail("a v2 verdict beside a removed seal");
        const [wantVerdict, wantBlocking] = V2_OVERALLS[overall as string]!;
        if (uv !== wantVerdict || res.blocking !== wantBlocking) return fail("the v2 verdict is not what its overall maps to");
      } else if (!opts.structured || (uv !== undefined && uv !== null)) {
        // No overall: a gate failed. The only verdict that can carry is Cannot Verify, never blocking.
        if (uv !== "cannot_verify" || res.blocking === true) return fail("a recognised v2 report with no overall is not Cannot Verify");
        if (!opts.structured && res.auditV2SealValid !== false && typeof res.auditV2ValidationError !== "string") {
          return fail("a recognised v2 report with no overall names no failed gate");
        }
      }
      if (removed && res.auditV2SealValid === true) return fail("a removed seal beside a held seal");
      // `result` is the Verify screen's rendering and is present exactly when `userVerdict` is
      // (main.rs `unsupported_schema` reply, "result": audit_v2_view): it must be the very verdict the outer
      // fields give, with the whole pass contract for a Safe to Send. The tool's own structured result carries none.
      if (!opts.structured && typeof uv === "string") {
        const nested = parseCheckVerdict({ verdict: uv, blocking: res.blocking, reason_code: null, result: res.result });
        if (!nested.ok) return fail(`the nested result: ${nested.reason}`);
        if (res.result === null || res.result === undefined) return fail("the nested result is missing");
      }
      break;
    }
    case "seal_unsupported_version":
      if (typeof res.sealVersion !== "string" || res.sealVersion.length === 0) return fail("sealVersion is missing");
      if (typeof res.carriesAuditReport !== "boolean") return fail("carriesAuditReport is missing");
      if (sealValid !== null && sealValid !== undefined) return fail("sealValid is set for an unsupported version");
      if (removed) return fail("an unsupported version beside a removed seal");
      if (carriesV2) return fail("an unsupported version carries v2 verdict fields");
      break;
  }
  return { ok: true, value: res };
}

// ---------------------------------------------------------------------------------------------------
// The write tools' audit (`redact` / `redact_entities`)
// ---------------------------------------------------------------------------------------------------

/**
 * The `audit` object of a `redact` / `redact_entities` reply (crates/omitly-cli/src/main.rs `do_redact`,
 * `publish_v2`). Its legacy `verdict` is "pass" only when the engine's `all_passed` held: every region
 * verified, the metadata scrubbed and no warning (crates/redaction-core/src/model.rs `all_passed`; a v2
 * output: `verdict` is exactly `overall == pass`, main.rs `publish_v2`). So a "pass" beside a failing
 * region or unscrubbed metadata, or a v2 Safe to Send beside a verdict that is not "pass", contradicts
 * itself and is no redaction result: the text would otherwise print `Verification: pass` or
 * `Result: Safe to Send` for it.
 */
export function parseRedactAudit(a: unknown, opts: { expected?: readonly { page: unknown }[] } = {}): Parsed<{ verdict: "pass" | "fail"; audit: ParsedAudit }> {
  if (!isRecord(a)) return fail("audit is missing");
  if (a.verdict !== "pass" && a.verdict !== "fail") return fail("audit.verdict is missing or unknown");
  if (typeof a.metadataScrubbed !== "boolean") return fail("audit.metadataScrubbed is missing or not a flag");
  if (!Array.isArray(a.regions)) return fail("audit.regions is missing");
  let anyFail = false;
  for (const e of a.regions) {
    const r = isRecord(e) && isRecord(e.verification) ? e.verification.result : undefined;
    if (r !== "pass" && r !== "fail") return fail("an audit region has no result");
    if (r === "fail") anyFail = true;
  }
  // One audit entry per requested region, in order (redaction-core engine.rs:1495 maps the request's regions one to one,
  // keeping each page): an empty, short, long or reordered list is not the audit of what was asked.
  if (opts.expected !== undefined) {
    if (a.regions.length !== opts.expected.length) return fail("audit.regions is not one entry per requested region");
    for (let i = 0; i < opts.expected.length; i++) {
      if ((a.regions[i] as { page?: unknown }).page !== opts.expected[i]!.page) return fail("an audit region is for another page than the one requested");
    }
  }
  if (a.verdict === "pass" && (anyFail || a.metadataScrubbed !== true)) return fail("audit.verdict is pass beside a failing region or unscrubbed metadata");
  // A pass needs no ENGINE warning: `all_passed` requires an empty warnings list (redaction-core engine.rs
  // `all_passed = ... && warnings.is_empty()`). The CLI appends product notices AFTER that (main.rs ~440-460: the
  // trial, personal-use and development-key notices), so those, and only those, may sit beside a pass.
  // errata G4: the engine always emits `warnings` on a redaction audit, pass or fail (main.rs:547), so a list of text is required on every
  // audit (`auditCaps` reads it for every outcome).
  if (!Array.isArray(a.warnings) || !a.warnings.every((w) => typeof w === "string")) return fail("audit.warnings is missing or not a list of text");
  if (a.auditSchema === "omitly.audit/v2") {
    const overall = a.auditV2Overall;
    const uv = a.userVerdict;
    if ((uv === "safe_to_send") !== (a.verdict === "pass") || (overall === "pass") !== (a.verdict === "pass")) {
      return fail("audit.verdict, auditV2Overall and userVerdict disagree about a pass");
    }
    // `result` (main.rs `publish_v2`: the receipt's audit_v2_view) is the verdict the outer fields give.
    if (typeof overall !== "string" || !(overall in V2_OVERALLS)) return fail("audit.auditV2Overall is missing or unknown");
    const [wantVerdict, wantBlocking] = V2_OVERALLS[overall]!;
    if (uv !== wantVerdict || a.blocking !== wantBlocking) return fail("audit.userVerdict is not what auditV2Overall maps to");
    const nested = parseCheckVerdict({ verdict: uv, blocking: a.blocking, reason_code: null, result: a.result });
    if (!nested.ok) return fail(`the nested result: ${nested.reason}`);
    if (a.result === null || a.result === undefined) return fail("the nested result is missing");
  }
  return { ok: true, value: { verdict: a.verdict, audit: a as unknown as ParsedAudit } };
}

// ---------------------------------------------------------------------------------------------------
// The structured results the result card receives (the tools' own output, checked again here)
// ---------------------------------------------------------------------------------------------------

const SECTION_KEYS = ["checked", "notChecked", "problems", "review", "information", "decisions", "reasons"] as const;
const STATES = ["safe_to_send", "needs_review", "cannot_verify"];
/** The fixed reason codes: the two the Rust wrapper sets (`omitly_seal::check::FREE_REASON_*`, only on a
 *  Cannot Verify) and the two this server sets when the check did not run. */
const CHECK_REASON_CODES = ["input_too_large", "check_failed", "check_unavailable", "result_invalid"];

function itemList(v: unknown): v is { text: string }[] {
  return Array.isArray(v) && v.every((i) => isRecord(i) && typeof i.text === "string");
}

/**
 * A `check` verdict (crates/omitly-seal/src/check.rs `FreeCheck` + `CheckResult`; the native
 * `check` command's `check` field, the wasm `check` export, and the verdict this server returns): the
 * engine's FULL pass contract, not the verdict word alone. Used for the engine's reply, for the
 * tool's own `verdict` and by the card, so no surface reads a verdict the engine did not give.
 *
 * Shape: `verdict` one of the three states, `blocking` a flag, `reason_code` absent or a fixed code
 * (only on Cannot Verify), and `result` (a `CheckResult`) with its seven item lists, `summary`,
 * `pagesTotal`/`pagesRead`, `checkedAt`, `omitlyVersion`, `sha256` and `sizeBytes`, whose `state` and
 * `blocking` equal the verdict's. A null `result` is only the wasm wrapper's serialisation fallback
 * (lib.rs `check_json`), a Cannot Verify.
 *
 * Safe to Send is `to_user_verdict(Pass)` (audit_v2.rs): not blocking, every check passed or did not
 * apply, so the result lists no problem, review item, decision or reason (check.rs `Sections`: those
 * come only from a non-pass check status), lists what was checked, read every page
 * (`pages_read = page_count - unread_pages`, and an unread page is a technical failure), carries the
 * file's sha256, and has no reason code. Cannot Verify is never blocking (`to_user_verdict`,
 * `Base::cannot_verify`). Anything else is not a pass, so a malformed or contradicting reply is
 * refused whole.
 */
export function parseCheckVerdict(v: unknown): Parsed<{ verdict: string; blocking: boolean }> {
  if (!isRecord(v) || !STATES.includes(v.verdict as string)) return fail("verdict is missing or unknown");
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
  // v0.2.1 (errata 6): a page list is bounded by the reply itself, never by a fixed cap (the engine lists every distinct page it counted,
  // check.rs `visible_text_item`): each page is a whole number from 1 to `pagesTotal`, and none is repeated.
  for (const k of SECTION_KEYS) {
    for (const it of r[k] as { pages?: unknown }[]) {
      if (it.pages === undefined) continue;
      if (!Array.isArray(it.pages) || !isCount(r.pagesTotal)) return fail(`result.${k} lists pages the reply cannot bound`);
      const seen = new Set<unknown>();
      for (const pg of it.pages) {
        if (!Number.isInteger(pg) || (pg as number) < 1 || (pg as number) > (r.pagesTotal as number) || seen.has(pg)) return fail(`result.${k} lists a page outside the file, or one twice`);
        seen.add(pg);
      }
    }
  }
  if (typeof r.summary !== "string") return fail("result.summary is missing");
  if (v.verdict === "safe_to_send") {
    // The result metadata is the proof a pass was made over a real file (the page counts, the digest, the
    // size, when and by what). Only a pass depends on it: a result that is not a pass is drawn without it.
    if (!isCount(r.pagesTotal) || !isCount(r.pagesRead) || r.pagesRead > r.pagesTotal) return fail("result.pagesTotal or pagesRead is missing or inconsistent");
    if (typeof r.checkedAt !== "string" || typeof r.omitlyVersion !== "string") return fail("result.checkedAt or omitlyVersion is missing");
    if (typeof r.sha256 !== "string" || !/^([0-9a-f]{64})?$/.test(r.sha256)) return fail("result.sha256 is missing or malformed");
    if (!isCount(r.sizeBytes)) return fail("result.sizeBytes is missing");
    if (v.blocking) return fail("a pass is blocking");
    if (rc !== undefined && rc !== null) return fail("a pass with a reason code");
    const lens = (k: (typeof SECTION_KEYS)[number]) => (r[k] as unknown[]).length;
    if (lens("problems") || lens("review") || lens("reasons") || lens("decisions")) return fail("a pass beside problems, review items, decisions or reasons");
    if (lens("checked") === 0) return fail("a pass with nothing checked");
    if (r.pagesRead !== r.pagesTotal) return fail("a pass with pages not read");
    if ((r.sha256 as string).length !== 64 || (r.summary as string).length === 0) return fail("a pass without the file's digest and summary");
  }
  return { ok: true, value: { verdict: v.verdict as string, blocking: v.blocking } };
}

/** The `coverage` object of a `check_redaction` structuredContent (`coverageOutputSchema` in index.ts). */
function coverageEnvelopeProblem(c: unknown, scanComplete: boolean): string | null {
  if (!isRecord(c)) return "coverage is missing";
  if (!isCount(c.pagesScanned) || !isCount(c.pagesTotal)) return "coverage.pagesScanned or pagesTotal is missing";
  if (!isCount(c.pagesFailedCount)) return "coverage.pagesFailedCount is missing";
  if (!Array.isArray(c.notScanned) || !c.notScanned.every((n) => typeof n === "string")) return "coverage.notScanned is missing";
  for (const k of ["priorRevisionsScanned", "metadataScanned", "acroformScanned", "attachmentsScanned"]) {
    if (typeof c[k] !== "boolean") return `coverage.${k} is missing`;
  }
  if (!isCount(c.formXobjectsScanned) || !isCount(c.annotationAppearancesScanned)) return "coverage counts are missing";
  if (c.pagesScanned + c.pagesFailedCount !== c.pagesTotal) return "coverage pages do not add up";
  if (scanComplete && c.pagesFailedCount > 0) return "scanComplete beside a failed page";
  // The same disclosures deny completion here as in the engine's own reply (coverage-rule.ts, one definition).
  if (scanComplete && engineIncompleteDisclosure(c.notScanned) !== null) return "scanComplete beside a disclosure that denies completion";
  return null;
}

/**
 * The whole `check_redaction` structuredContent, as the card may draw it. Anything missing, wrong,
 * or not consistent with itself is a failure and the card draws its error state, never a verdict.
 * Consistency: the verdict is a whole, consistent engine verdict (`parseCheckVerdict`); the coverage
 * is present and adds up; Safe to Send needs a complete scan and a clean result with nothing listed;
 * and the `outcome` field, when present, is what the rule gives for the rest.
 */
export function parseCheckEnvelope(sc: unknown): Parsed<Record<string, unknown>> {
  if (!isRecord(sc)) return fail("not an object");
  if (typeof sc.scanComplete !== "boolean") return fail("scanComplete is missing");
  if (typeof sc.clean !== "boolean") return fail("clean is missing");
  if (!isCount(sc.totalFindings)) return fail("totalFindings is missing");
  const regions = regionList(sc.regions, "regions");
  if (!regions.ok) return regions;
  const survivors = regionList(sc.survivors, "survivors");
  if (!survivors.ok) return survivors;
  if (!Array.isArray(sc.offPage) || !sc.offPage.every((f) => isRecord(f) && typeof f.kind === "string" && typeof f.source === "string")) return fail("offPage is malformed");
  const listed = regions.value.length + survivors.value.length + sc.offPage.length;
  if (sc.clean !== (sc.totalFindings === 0)) return fail("clean disagrees with totalFindings");
  if (sc.totalFindings !== listed) return fail("totalFindings disagrees with the items listed");
  if (!isRecord(sc.byKind) || !Object.values(sc.byKind).every(isCount)) return fail("byKind is missing");
  const cov = coverageEnvelopeProblem(sc.coverage, sc.scanComplete);
  if (cov) return fail(cov);
  const v = sc.verdict;
  if (!isRecord(v)) return fail("verdict is missing or malformed");
  // A verdict the check could not produce (it did not run, or its answer failed the allowlist) is no
  // completed check, whatever else the result holds.
  if (v.reason_code === "check_unavailable" || v.reason_code === "result_invalid") return fail("the verdict check did not run");
  const pv = parseCheckVerdict(v);
  if (!pv.ok) return pv;
  if (v.verdict === "safe_to_send" && (sc.scanComplete !== true || sc.clean !== true || listed > 0)) {
    return fail("a pass beside findings or an incomplete scan");
  }
  // The legs of a check agree (verdict-rule.ts `legsDisagree`): the server reconciles a verdict beside findings by
  // moving the engine's visible-text line out of `information`, so one still there beside an empty scan is a
  // pair the server would have refused.
  const legs = legsDisagree(v.result as ResultLike | null, { found: listed, complete: sc.scanComplete });
  if (legs) return fail(legs);
  // Contract §3.8: the card's look is a function of `outcome` alone, so the envelope must carry a known one, and a pass
  // needs the verdict, a complete scan and a clean result to agree with it. (The pass itself is issued by `passOutcome`
  // on the server; the card never re-derives it.)
  if (!(OUTCOMES as readonly unknown[]).includes(sc.outcome)) return fail("outcome is missing or unknown");
  if (sc.outcome === "safe_to_send" && !(v.verdict === "safe_to_send" && sc.scanComplete === true && sc.clean === true)) {
    return fail("outcome says a pass beside a verdict, scan or findings that are not one");
  }
  // Text under a redaction mark is always `not_a_pass` (row 1): an envelope that lists a survivor beside any other outcome would draw a
  // milder card than the file deserves (CONTRACT-QUESTION: the contract does not state this cross-check; it is the fail-safe reading).
  // The verdict is reconciled with the outcome (`reconcileVerdict`): a verdict that still says Safe to Send beside a lower outcome is no result of this server.
  if (sc.outcome !== "safe_to_send" && v.verdict === "safe_to_send") return fail("a verdict that says Safe to Send beside an outcome that is not a pass");
  if (survivors.value.length > 0 && sc.outcome !== "not_a_pass") return fail("a survivor is listed beside an outcome that is not not_a_pass");
  return { ok: true, value: sc };
}

/** The `verify_seal` / `verify_document` structuredContent as the card may draw it (contract §6.1, §3.8): `outcome` (a known
 *  one, never `safe_to_send`: no seal tool issues a pass) and `seal` (its state). The embedded report's own fields sit under
 *  `embeddedReport`, attributed, and decide nothing. */
export function parseSealEnvelope(sc: unknown): Parsed<Record<string, unknown>> {
  if (!isRecord(sc)) return fail("not an object");
  if (!(OUTCOMES as readonly unknown[]).includes(sc.outcome)) return fail("outcome is missing or unknown");
  if (sc.outcome === "safe_to_send") return fail("a seal result cannot be a pass");
  if (!isRecord(sc.seal) || !["held", "invalid", "removed", "none", "unsupported"].includes(sc.seal.state as string)) return fail("seal.state is missing or unknown");
  return { ok: true, value: sc };
}
