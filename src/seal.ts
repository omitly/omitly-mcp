/**
 * Response-hardening for `verify_seal`, mirroring `omitly-npm/src/index.ts`'s
 * `verifySeal()` (see #596). The engine's raw JSON is never trusted as-is —
 * an unrecognized `verdict` collapses to the most distrustful state
 * (`seal_invalid`, `sealValid: false`), never a silent pass. This is kept as
 * a standalone, side-effect-free function so it can be unit tested without
 * spawning the engine.
 */

export const SEAL_VERDICTS = [
  "no_report",
  "seal_invalid",
  "seal_unsupported_version",
  "report_unparseable",
  "unsupported_schema",
  "incomplete",
  "verified",
] as const;

export type SealVerdict = (typeof SEAL_VERDICTS)[number];

export interface NormalizedSealResult {
  ok: true;
  verdict: SealVerdict;
  /** `null` ONLY for `seal_unsupported_version` — this verifier checked
   * nothing, so neither `true` (false trust) nor `false` (reads as
   * "tampered") is honest. Every other state keeps the default-to-false
   * discipline: never `true` for an unrecognized verdict. */
  sealValid: boolean | null;
  sealVersion: string | null;
  /** Only meaningful (and only surfaced) alongside `seal_unsupported_version`
   * — whether the file also carries an Omitly audit report, the escalation
   * signal for "altered and relabelled" vs. "genuinely just a newer seal". */
  carriesAuditReport: boolean | null;
  sealFingerprint: string | null;
  allPassed: boolean | null;
  metadataScrubbed: boolean | null;
  /** omitly#228: the sealed report's decision-channel claim — who decided the
   * redactions ("human-desktop" | "mcp-agent" | "cli" | future values). The
   * engine hard-gates it on seal validity; here it is a pass-through string,
   * null when absent (pre-#228 report) or ungated (invalid seal). */
  decisionChannel: string | null;
  regionCount: number | null;
  pageCount: number | null;
  warnings: string[] | null;
  licenseProvenance: {
    valid: boolean;
    licenseId: string;
    licensedTo: string;
    product: string;
    reason: string | null;
  } | null;
  inputSha256: string | null;
  outputSha256: string | null;
  sourceFilename: string | null;
  outputFilename: string | null;
  /** omitly#1093: true only when the embedded report's schema is
   * `omitly.audit/v2`. Purely diagnostic — never gates `verdict`/`sealValid`
   * above. */
  auditV2Recognized: boolean;
  /** omitly#1093: why a recognized v2 report still failed semantic
   * validation. Non-null for every real v2 report today — the spec requires
   * registry-owned code to recompute applicability from the presented PDF,
   * that recomputation does not exist yet (omitly#1102), so verification
   * fails closed rather than silently passing. */
  auditV2ValidationError: string | null;
  /** omitly#1104: the verified v2 overall (spec §5); null unless every v2
   * gate passed. */
  auditV2Overall: AuditV2Overall | null;
  /** omitly#1104: the Safe to Send verdict of a v2 report (the engine's
   * `to_user_verdict`). null for a v1 report. Fail-closed: a v2 report whose
   * engine answer is missing, unknown or inconsistent with `auditV2Overall`
   * reads `cannot_verify`. */
  userVerdict: UserVerdict | null;
  /** omitly#1104: `needs_review` that found a known leak; null exactly when
   * `userVerdict` is. */
  blocking: boolean | null;
  /** omitly#1593 (engine: omitly#1591): the file carries a sealed Omitly
   * report but no seal at all — removed, typically by re-saving the file in
   * another app. A REASON for a failure, never a verdict: true only beside
   * `seal_invalid` or a v2 `cannot_verify`, so it can never sit next to a
   * pass. False when the engine does not say so (older engines included). */
  sealRemoved: boolean;
}

/** omitly#1104: spec §5's overall statuses. */
export const AUDIT_V2_OVERALLS = [
  "pass",
  "pass_with_operator_decisions",
  "review_required",
  "unsafe",
  "technical_fail",
] as const;
export type AuditV2Overall = (typeof AUDIT_V2_OVERALLS)[number];
/** omitly#1104: the three user-facing states. */
export const USER_VERDICTS = ["safe_to_send", "needs_review", "cannot_verify"] as const;
export type UserVerdict = (typeof USER_VERDICTS)[number];
/** omitly#1496: `provenance.decision_channel`'s closed set — v1's values
 * (omitly#228) plus `none` (a presented check: nothing was decided). Equal to
 * `decision_channels` in contract/cases/audit_v2_semantics.json (tested). */
export const DECISION_CHANNELS = ["human-desktop", "mcp-agent", "cli", "none"] as const;
export type DecisionChannel = (typeof DECISION_CHANNELS)[number];

/** omitly#1496: the decision channel a `verify_seal` response may surface.
 * For a v2 report: only when every v2 gate passed (`auditV2Overall`
 * non-null), only a known redaction channel (never `none`). For v1: the
 * engine's own seal-gated string, unchanged (omitly#228). */
export function sealDecisionChannel(
  res: Record<string, unknown>,
  v2: ReturnType<typeof v2Verdict>,
): string | null {
  const raw = typeof res.decisionChannel === "string" ? res.decisionChannel : null;
  if (res.auditV2Recognized !== true) return raw;
  const known = DECISION_CHANNELS.includes(raw as DecisionChannel) && raw !== "none";
  return known && v2.auditV2Overall !== null ? raw : null;
}

/** omitly#1104: the engine's `to_user_verdict`, restated only to CHECK the
 * engine's answer, never to compute one it did not give. */
function expectedVerdict(overall: AuditV2Overall): [UserVerdict, boolean] {
  switch (overall) {
    case "pass":
    case "pass_with_operator_decisions":
      return ["safe_to_send", false];
    case "review_required":
      return ["needs_review", false];
    case "unsafe":
      return ["needs_review", true];
    case "technical_fail":
      return ["cannot_verify", false];
  }
}

/** omitly#1104: the v2 verdict fields of an untrusted engine response. Only a
 * recognized v2 report has one; anything missing, unknown or inconsistent is
 * Cannot Verify. */
export function v2Verdict(res: Record<string, unknown>): {
  auditV2Overall: AuditV2Overall | null;
  userVerdict: UserVerdict | null;
  blocking: boolean | null;
} {
  if (res.auditV2Recognized !== true) {
    return { auditV2Overall: null, userVerdict: null, blocking: null };
  }
  const cannot = { auditV2Overall: null, userVerdict: "cannot_verify" as const, blocking: false };
  const overall = AUDIT_V2_OVERALLS.includes(res.auditV2Overall as AuditV2Overall)
    ? (res.auditV2Overall as AuditV2Overall)
    : null;
  if (overall === null) return cannot;
  const [verdict, blocking] = expectedVerdict(overall);
  if (res.userVerdict !== verdict || res.blocking !== blocking) return cannot;
  return { auditV2Overall: overall, userVerdict: verdict, blocking };
}

const str = (v: unknown): string | null => (typeof v === "string" ? v : null);
const bool = (v: unknown): boolean | null => (typeof v === "boolean" ? v : null);
const num = (v: unknown): number | null => (typeof v === "number" ? v : null);
const strArray = (v: unknown): string[] | null =>
  Array.isArray(v) && v.every((x) => typeof x === "string") ? v : null;

/** Normalize a raw `verify_seal` engine response into a hardened shape.
 * `res` is untrusted wire JSON from the engine process — validate every
 * field, don't just re-shape it. */
export function normalizeSealResult(res: Record<string, unknown>): NormalizedSealResult {
  const verdictRecognized = SEAL_VERDICTS.includes(res.verdict as SealVerdict);
  const verdict: SealVerdict = verdictRecognized ? (res.verdict as SealVerdict) : "seal_invalid";

  const provenance = res.licenseProvenance as unknown;
  const licenseProvenance =
    provenance && typeof provenance === "object"
      ? {
          valid: bool((provenance as Record<string, unknown>).valid) ?? false,
          licenseId: str((provenance as Record<string, unknown>).licenseId) ?? "",
          licensedTo: str((provenance as Record<string, unknown>).licensedTo) ?? "",
          product: str((provenance as Record<string, unknown>).product) ?? "",
          reason: str((provenance as Record<string, unknown>).reason),
        }
      : null;

  const v2 = v2Verdict(res);
  return {
    ok: true,
    verdict,
    sealValid:
      verdict === "seal_unsupported_version"
        ? null
        : verdictRecognized
          ? (bool(res.sealValid) ?? false)
          : false,
    sealVersion: verdict === "seal_unsupported_version" ? str(res.sealVersion) : null,
    carriesAuditReport: verdict === "seal_unsupported_version" ? bool(res.carriesAuditReport) : null,
    sealFingerprint: str(res.sealFingerprint),
    allPassed: bool(res.allPassed),
    metadataScrubbed: bool(res.metadataScrubbed),
    decisionChannel: sealDecisionChannel(res, v2Verdict(res)),
    regionCount: num(res.regionCount),
    pageCount: num(res.pageCount),
    warnings: strArray(res.warnings),
    licenseProvenance,
    inputSha256: str(res.inputSha256),
    outputSha256: str(res.outputSha256),
    sourceFilename: str(res.sourceFilename),
    outputFilename: str(res.outputFilename),
    auditV2Recognized: bool(res.auditV2Recognized) ?? false,
    auditV2ValidationError: str(res.auditV2ValidationError),
    ...v2,
    sealRemoved:
      res.sealRemoved === true &&
      verdictRecognized &&
      (verdict === "seal_invalid" || v2.userVerdict === "cannot_verify"),
  };
}

/** omitly#1593: the summary line for a removed seal (engine omitly#1591). */
export const SEAL_REMOVED_SUMMARY =
  "⚠️ Seal removed — this file carries a sealed Omitly audit report but no seal: it was " +
  "re-saved or changed after it was sealed (often by opening and saving it in another app). " +
  "Do not treat its audit trail as trustworthy; ask the sender for the original file.";

/** Verdicts that should surface as an MCP `isError: true` tool result — a
 * caller reading only `content[].text` (not the JSON) must still see failure
 * as failure. `seal_unsupported_version` is deliberately excluded: it is
 * indeterminate, not a failure, and must render as neither pass nor fail. */
export function isSealErrorVerdict(verdict: SealVerdict): boolean {
  return verdict === "seal_invalid" || verdict === "no_report" || verdict === "incomplete";
}

/** omitly#1104: the error flag for a whole normalized result. A v2 report is
 * an error unless it is Safe to Send (the counterpart of v1's `incomplete`);
 * anything else keeps `isSealErrorVerdict`. */
export function isSealError(res: NormalizedSealResult): boolean {
  if (res.userVerdict !== null) return res.userVerdict !== "safe_to_send";
  return isSealErrorVerdict(res.verdict);
}

/** omitly#1104: the fixed label of a v2 verdict (the Check screen's). */
export function userVerdictLabel(verdict: UserVerdict, blocking: boolean | null): string {
  switch (verdict) {
    case "safe_to_send":
      return "Safe to Send";
    case "needs_review":
      return blocking ? "Needs Review - problems found" : "Needs Review";
    case "cannot_verify":
      return "Cannot Verify";
  }
}
