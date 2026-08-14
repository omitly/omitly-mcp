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
    decisionChannel: str(res.decisionChannel),
    regionCount: num(res.regionCount),
    pageCount: num(res.pageCount),
    warnings: strArray(res.warnings),
    licenseProvenance,
    inputSha256: str(res.inputSha256),
    outputSha256: str(res.outputSha256),
    sourceFilename: str(res.sourceFilename),
    outputFilename: str(res.outputFilename),
  };
}

/** Verdicts that should surface as an MCP `isError: true` tool result — a
 * caller reading only `content[].text` (not the JSON) must still see failure
 * as failure. `seal_unsupported_version` is deliberately excluded: it is
 * indeterminate, not a failure, and must render as neither pass nor fail. */
export function isSealErrorVerdict(verdict: SealVerdict): boolean {
  return verdict === "seal_invalid" || verdict === "no_report" || verdict === "incomplete";
}
