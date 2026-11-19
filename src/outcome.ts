/**
 * omitly#1864: THE issuer (docs/pass-contract.md §2.3, §7.1). Only `passOutcome` in this module, and its hand port
 * `mcpb/server/outcome.js`, can produce `safe_to_send`. Every other surface supplies CAPS only (`capped`): a cap can
 * lower an outcome and never raise one. A pass is a fixed set of positive facts the MCP itself obtained from the engine
 * over these bytes (C1-C8); an embedded report, a sidecar, a seal, a fingerprint, a version string in the file, a desktop
 * proposal record or an earlier result is never evidence, and may only add caps.
 *
 * Browser-safe: no Node imports (the card bundle includes it).
 */
import { engineIncompleteDisclosure } from "./coverage-rule.js";
import { isProductNotice, LEGACY_CAUTION_PREFIX, type NormalizedSealResult } from "./seal.js";
import { legsDisagree, notAPassLead, SEALED_REPORT_PREFIX, type ResultLike } from "./verdict-rule.js";

export const OUTCOMES = ["safe_to_send", "needs_review", "not_a_pass", "incomplete"] as const;
export type Outcome = (typeof OUTCOMES)[number];

const RANK: Record<Outcome, number> = { safe_to_send: 0, incomplete: 1, needs_review: 2, not_a_pass: 3 };
/** The worst of the outcomes, in the order not_a_pass > needs_review > incomplete > safe_to_send. */
export function worst(first: Outcome, ...rest: Outcome[]): Outcome {
  let w = first;
  for (const o of rest) if (RANK[o] > RANK[w]) w = o;
  return w;
}

const ISSUED = Symbol("issued");
/** Only this module constructs one (the symbol is not exported). `why` is empty iff outcome === "safe_to_send";
 *  `lead === notAPassLead(why)`. */
export interface Issued {
  readonly outcome: Outcome;
  readonly why: readonly string[];
  readonly lead: string;
  readonly [ISSUED]: true;
}
export interface Cap {
  readonly at: Exclude<Outcome, "safe_to_send">;
  readonly why: string;
}
/** Row 0: the caller returns `isError: true`, text only, no structured result. */
export interface Failure {
  readonly failure: string;
}
export const isFailure = (x: Issued | Failure): x is Failure => "failure" in x;

function issue(outcome: Outcome, why: readonly string[]): Issued {
  const w = outcome === "safe_to_send" ? [] : [...why];
  return Object.freeze({ outcome, why: w, lead: notAPassLead(w), [ISSUED]: true as const });
}

/** The why strings (contract §7.1). `{n}` is a count. W0 is the default of `capped(null, [])`. */
export const WHY = {
  W0: "this tool cannot confirm the document is ready to send",
  W1: (n: number) => `${n} sensitive item(s) found`,
  W2: (n: number) => `text is still present under a redaction mark (${n} item(s))`,
  W3: "INCOMPLETE SCAN",
  W4: (label: string) => `Check verdict: ${label}`,
  W5: "part of the file was not read",
  /** v0.2.1 (errata 8): an audit whose own overall is `technical_fail` (A4): the engine, not the file, could not finish. */
  W5b: "the engine could not complete its checks",
  W6: "the file carries its own sealed report, which this check relied on: confirm the key is the sender's",
  W7: "the engine raised a warning",
  W8: "a seal shows integrity only and is not a check of the content",
  W9: (n: number) => `${n} recorded redaction region(s) failed`,
  W10: "the document's metadata was not scrubbed",
  W11: "a redaction record is not a check of the document: run check_redaction on the output",
  W12: "a pattern scan is not a check of the document: run check_redaction",
  W13: (removed: boolean) => (removed ? "the seal was removed" : "the seal does not verify"),
  W14: "the file's own report records a failed redaction",
  W15: "the file's own report records items to review",
  W16: (n: number) => `${n} hidden-content check(s) failed`,
  W17: "the verifier raised a warning",
} as const;

/** The one `not_scanned` line that is benign (detect.rs:4669): exact string equality; every other line, unknown ones
 *  included, fails C5. */
export const BENIGN_DISCLOSURES: readonly string[] = ["text drawn as raster images (needs OCR)"];
/** The check's information line showing it relied on the file's own bound report (check.rs:753, :1934-1970). */
export { SEALED_REPORT_PREFIX } from "./verdict-rule.js";

/** After `parseCheckVerdict`. `result.information` is RAW: read before any MCP rewording. */
export interface CheckLeg {
  verdict: "safe_to_send" | "needs_review" | "cannot_verify";
  blocking: boolean;
  reasonCode: string | null;
  result: ResultLike | null;
}
/** After `parseScanReply`. */
export interface ScanLeg {
  engine: "native" | "wasm";
  total: number;
  survivors: number;
  topComplete: boolean | null;
  covComplete: boolean | null;
  notScanned: readonly string[];
  pagesFailed: number;
  /** `regions` / `leaks`, `survivors` or `off_page` is non-empty. */
  listsNonEmpty: boolean;
  embeddedStreamsFailed: number;
  /** Any typed coverage failure other than the two above: raster_only_pages, survivor_pages_failed,
   *  prior_revisions_failed non-empty, or any `*_unread` / `*_incomplete` flag set (C6). */
  flagsSet: boolean;
}

const CHECK_LABEL = (c: CheckLeg) => (c.verdict === "needs_review" ? (c.blocking ? "Needs Review — problems found" : "Needs Review") : "Cannot Verify");

/**
 * C2-C8 and rows 0-4 for a check + scan pair, then `worst` with the caps. `snapshotSha256` is lowercase hex of the bytes
 * the MCP read once (C1); the check's own sha must equal it (C3).
 */
export function passOutcome(i: { check: CheckLeg; scan: ScanLeg; snapshotSha256: string; caps?: readonly Cap[] }): Issued | Failure {
  const { check, scan } = i;
  // ---- row 0
  if (check.reasonCode === "check_unavailable" || check.reasonCode === "result_invalid") return { failure: "the verdict check did not run" };
  const sha = check.result?.sha256;
  const refusal = check.verdict === "cannot_verify" && (check.reasonCode === "input_too_large" || check.reasonCode === "check_failed");
  if (check.result === null || sha === "" || sha === undefined) {
    // An empty sha or no result is allowed only for the engine's own refusals (C3).
    if (!refusal) return { failure: "the check's answer is not bound to a file digest" };
  } else if (sha !== i.snapshotSha256) {
    return { failure: "the check read different bytes than this server read (its digest does not match)" };
  }
  if (scan.topComplete !== null && scan.covComplete !== null && scan.topComplete !== scan.covComplete) {
    return { failure: "scan_complete disagrees with coverage.scan_complete" };
  }
  const complete = scan.topComplete === true && scan.covComplete === true;
  if (complete && engineIncompleteDisclosure(scan.notScanned) !== null) return { failure: "scan_complete is true beside a disclosure the engine sends only beside an incomplete scan" };
  const legs = legsDisagree(check.result, { found: scan.total, complete });
  if (legs) return { failure: legs };

  // ---- rows 1-4
  const rows: Cap[] = [];
  const add = (at: Cap["at"], why: string) => rows.push({ at, why });
  if (scan.survivors > 0) add("not_a_pass", WHY.W2(scan.survivors));
  if (scan.total > 0) add("needs_review", WHY.W1(scan.total));
  if (check.verdict === "needs_review") add(check.blocking ? "not_a_pass" : "needs_review", WHY.W4(CHECK_LABEL(check)));
  if (check.verdict === "cannot_verify") add("incomplete", WHY.W4(CHECK_LABEL(check)));
  if (check.verdict === "safe_to_send" && (check.blocking || check.reasonCode !== null || check.result === null)) return { failure: "the check's verdict is not a consistent pass" };
  // C2b: the check relied on something the file says about itself.
  if (check.result && check.result.information.some((x) => typeof x.text === "string" && x.text.startsWith(SEALED_REPORT_PREFIX))) add("needs_review", WHY.W6);
  if (!complete) add("incomplete", WHY.W3);
  // C5 / C6
  const denied =
    scan.notScanned.some((l) => !BENIGN_DISCLOSURES.includes(l)) || scan.pagesFailed > 0 || scan.embeddedStreamsFailed > 0 || scan.flagsSet;
  if (denied) add("incomplete", WHY.W5);

  const all = [...rows, ...(i.caps ?? [])];
  const outcome = worst("safe_to_send", ...all.map((c) => c.at));
  return issue(outcome, all.map((c) => c.why));
}

/** `worst(base?.outcome ?? "incomplete", ...caps)`; never upgrades. `capped(null, [])` is `incomplete` with W0. */
export function capped(base: Issued | null, caps: readonly Cap[]): Issued {
  const outcome = worst(base?.outcome ?? "incomplete", ...caps.map((c) => c.at));
  const why = [...(base?.why ?? (caps.length ? [] : [WHY.W0])), ...caps.map((c) => c.why)];
  return issue(outcome, outcome === "safe_to_send" ? [] : why.length ? why : [WHY.W0]);
}

// ---------------------------------------------------------------------------------------------------
// Seal tools (contract §3.5): a seal is integrity only; the outcome is never safe_to_send.
// ---------------------------------------------------------------------------------------------------

/** The §3.5 table S1-S8 (first match wins), always followed by W8 at `incomplete`. */
export function sealCaps(res: NormalizedSealResult): Cap[] {
  const v1Held = res.sealValid === true && (res.verdict === "verified" || res.verdict === "incomplete" || res.verdict === "no_report");
  const v2Held = res.auditV2Recognized === true && res.auditV2SealValid === true && (res.sealVerdict === null || res.sealVerdict === "valid");
  const w8: Cap = { at: "incomplete", why: WHY.W8 };
  const row = (): Cap | null => {
    if (res.sealRemoved === true) return { at: "not_a_pass", why: WHY.W13(true) }; // S1
    if (res.verdict === "seal_invalid" || (res.verdict === "report_unparseable" && res.sealValid === false)) return { at: "not_a_pass", why: WHY.W13(false) }; // S2
    if (v1Held && res.verdict === "incomplete") return { at: "not_a_pass", why: WHY.W14 }; // S3
    if (v2Held && res.auditV2Overall === "unsafe") return { at: "not_a_pass", why: WHY.W14 }; // S4
    if (v2Held && (res.auditV2Overall === "review_required" || res.auditV2Overall === "pass_with_operator_decisions")) return { at: "needs_review", why: WHY.W15 }; // S5
    if (v1Held && res.verdict === "verified" && res.metadataScrubbed !== true) return { at: "needs_review", why: WHY.W10 }; // S6
    // S7. CONTRACT-QUESTION: the table reads "v1Held, and a warnings entry that is neither a product notice nor a verifier-own
    // line; or any sealWarnings entry". sealWarnings exist only for a v2 seal, so the fail-safe reading applies the second
    // clause whether or not v1Held.
    if (v1Held && (res.warnings ?? []).some((w, i) => !isProductNotice(w) && !(i === 0 && res.legacyUnboundVerdict === true && w.startsWith(LEGACY_CAUTION_PREFIX)))) return { at: "needs_review", why: WHY.W17 };
    if ((res.sealWarnings ?? []).length > 0) return { at: "needs_review", why: WHY.W17 };
    return null; // S8
  };
  const r = row();
  return r ? [r, w8] : [w8];
}

/** `seal.state` of the structured result (contract §6.1): the first match. */
export function sealState(res: NormalizedSealResult): "held" | "invalid" | "removed" | "none" | "unsupported" {
  if (res.sealRemoved === true) return "removed";
  if (res.verdict === "seal_invalid" || (res.verdict === "report_unparseable" && res.sealValid === false)) return "invalid";
  if (res.verdict === "seal_unsupported_version") return "unsupported";
  const v1Held = res.sealValid === true && (res.verdict === "verified" || res.verdict === "incomplete" || res.verdict === "no_report");
  const v2Held = res.auditV2Recognized === true && res.auditV2SealValid === true && (res.sealVerdict === null || res.sealVerdict === "valid");
  return v1Held || v2Held ? "held" : "none";
}

// ---------------------------------------------------------------------------------------------------
// Redaction audit (contract §3.6) and sidecar verify (contract §3.4)
// ---------------------------------------------------------------------------------------------------

/** The parsed `audit` of a redact reply (after `parseRedactAudit`). */
export interface ParsedAudit {
  verdict: "pass" | "fail";
  blocking?: unknown;
  auditSchema?: unknown;
  auditV2Overall?: unknown;
  regions: { verification?: { result?: unknown } }[];
  warnings: unknown[];
}

/** The §3.6 audit table A1-A5, then W11 at `needs_review`. */
export function auditCaps(audit: ParsedAudit): Cap[] {
  const caps: Cap[] = [];
  const failed = audit.regions.some((r) => r.verification?.result === "fail");
  const o = audit.auditV2Overall;
  if (audit.blocking === true || failed) caps.push({ at: "not_a_pass", why: WHY.W14 }); // A1
  else if (o === "review_required" || o === "pass_with_operator_decisions") caps.push({ at: "needs_review", why: WHY.W15 }); // A2
  else if (audit.auditSchema !== "omitly.audit/v2" && audit.verdict === "fail") caps.push({ at: "needs_review", why: WHY.W10 }); // A2 (v1, no failing region: metadata not scrubbed)
  else if (o === "technical_fail") caps.push({ at: "incomplete", why: WHY.W5b }); // A4
  if (audit.warnings.some((w) => typeof w !== "string" || !isProductNotice(w))) caps.push({ at: "needs_review", why: WHY.W7 }); // A3
  caps.push({ at: "needs_review", why: WHY.W11 });
  return caps;
}

/** The engine's record, in words, for the single text line (contract §3.6 A-labels). */
export function auditLabel(audit: ParsedAudit): string {
  const failed = audit.regions.some((r) => r.verification?.result === "fail");
  if (audit.blocking === true || failed) return "a failed redaction";
  const o = audit.auditV2Overall;
  if (o === "review_required" || o === "pass_with_operator_decisions" || (audit.auditSchema !== "omitly.audit/v2" && audit.verdict === "fail")) return "items to review";
  if (audit.warnings.some((w) => typeof w !== "string" || !isProductNotice(w))) return "items to review";
  if (o === "technical_fail") return "could not complete its checks";
  return "no failed region";
}

/** The parsed sidecar `verify` reply (after `parseSidecarVerifyReply`). */
export interface ParsedVerify {
  metadataScrubbed: boolean;
  regions: { verification?: { result?: unknown } }[];
  hiddenContent: { verification?: { result?: unknown } }[];
  warnings?: unknown;
}

/** §3.4: W9 (a failing region), W16 (a failing hidden-content class), W10 (metadata not scrubbed), W7 (a warning that is not exactly a product notice). */
export function sidecarCaps(v: ParsedVerify): Cap[] {
  const caps: Cap[] = [];
  const rf = v.regions.filter((r) => r.verification?.result === "fail").length;
  const hf = v.hiddenContent.filter((r) => r.verification?.result === "fail").length;
  if (rf > 0) caps.push({ at: "not_a_pass", why: WHY.W9(rf) });
  if (hf > 0) caps.push({ at: "needs_review", why: WHY.W16(hf) });
  if (v.metadataScrubbed === false) caps.push({ at: "needs_review", why: WHY.W10 });
  if (Array.isArray(v.warnings) && v.warnings.some((w) => typeof w !== "string" || !isProductNotice(w))) caps.push({ at: "needs_review", why: WHY.W7 });
  return caps;
}
