#!/usr/bin/env node
/**
 * Omitly MCP server.
 *
 * Exposes Omitly's local, verifiable PDF redaction to MCP clients (Claude Code,
 * Claude Desktop, etc.) as callable tools. The whole point: an agent can redact a
 * document *without uploading it anywhere* — redaction runs on-device via the
 * Omitly engine and returns a signed audit log proving the data is gone.
 *
 * The natural flow across the three tools:
 *   find_sensitive_regions → the engine extracts text WITH coordinates and
 *     returns PII candidates, so the model works in entity space ("redact every
 *     SSN") and never has to guess PDF point geometry from a rendered image.
 *   redact_pdf            → remove the chosen regions' bytes, verify, audit.
 *   verify_redaction      → independently re-confirm the output.
 *
 * Integration point — the engine binary:
 *   This server shells out to a local CLI (`omitly-redact`) that wraps the
 *   Omitly redaction engine. The engine ships with the Omitly desktop
 *   application and its source is not part of this package; point
 *   OMITLY_REDACT_BIN (or OMITLY_ENGINE_DIR) at the binary to enable the
 *   native-engine tools. The contract is documented in README.md and in
 *   `runEngine()` below: a JSON request on stdin, a JSON response (result +
 *   audit log) on stdout.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { spawn } from "node:child_process";
import { existsSync, readFileSync, realpathSync } from "node:fs";
import { createRequire } from "node:module";
import * as path from "node:path";
import { pathToFileURL } from "node:url";
import { z } from "zod";
import { ENGINE_OUTPUT_CAP_BYTES, resolveEngineTimeoutMs } from "./engine-config.js";
import { allowedRoot, confineInput, confineOutput } from "./paths.js";
import {
  isSealErrorVerdict,
  normalizeSealResult,
  SEAL_VERDICTS,
  type NormalizedSealResult,
} from "./seal.js";
import {
  evaluationBanner,
  freeCapRefusal,
  recordFreeCheck,
  type FreeCheckOutcome,
} from "./usage.js";

/**
 * WASM fallback for the four detection/verify tools — bundled in the npm
 * package (see package.json "files"), so `find_sensitive_regions`,
 * `locate_text`, `check_redaction` and `verify_redaction` work out of the box
 * with NO native engine binary and NO Rust toolchain on the caller's machine.
 * This is the wasm-bindgen twin of `redaction-core`'s detector (same crate
 * already shipped for the web leak-checker at omitly.app) — detection-only,
 * no qpdf/process/filesystem, so it crosses to wasm cleanly.
 *
 * `redact_pdf`/`redact_by_entity`/`create_pdf` still require a configured
 * native engine (ENGINE_BIN/PDF_BIN below) — write access and PDF generation
 * (a real headless browser) can't run in wasm. When a native engine IS
 * configured, it's preferred over wasm for the four tools too (more complete:
 * the native `find` path also covers survivor/off-page detection the exact
 * same way; wasm and native currently agree on output shape for this reason).
 */
const wasmRequire = createRequire(import.meta.url);
type WasmEngine = { scan(bytes: Uint8Array): string; locate(bytes: Uint8Array, needlesJson: string): string };
let wasmEngine: WasmEngine | undefined;
try {
  wasmEngine = wasmRequire("../wasm/leakcheck_wasm.js") as WasmEngine;
} catch {
  // Not built (e.g. local dev before `npm run build`) — tools below fail
  // loudly with a clear message rather than silently no-op.
  wasmEngine = undefined;
}

interface WasmLeak {
  page: number;
  kind: string;
  preview: string;
  x: number;
  y: number;
  width: number;
  height: number;
}
interface WasmScanResult {
  ok: boolean;
  count: number;
  clean: boolean;
  total_findings: number;
  by_kind: Record<string, number>;
  leaks: WasmLeak[];
  survivors: WasmLeak[];
  off_page: { source: string; kind: string; preview: string }[];
  coverage: Record<string, unknown> | null;
  error: string | null;
}

/** Normalises the wasm `ScanResult` to the same field names the native `find`
 *  response already uses (`regions` instead of `leaks`), so every downstream
 *  formatter in this file works unchanged regardless of which engine ran. */
function wasmScanToFindShape(raw: string): any {
  const r = JSON.parse(raw) as WasmScanResult;
  if (!r.ok) return { ok: false, error: r.error ?? "wasm scan failed" };
  return {
    ok: true,
    clean: r.clean,
    count: r.count,
    total_findings: r.total_findings,
    regions: r.leaks,
    survivors: r.survivors,
    off_page: r.off_page,
    coverage: r.coverage,
  };
}

function runWasmScan(bytes: Buffer): any {
  if (!wasmEngine) {
    return { ok: false, error: "bundled wasm engine not found in wasm/ — reinstall the package, or run `npm run build` if working from source" };
  }
  return wasmScanToFindShape(wasmEngine.scan(new Uint8Array(bytes)));
}

function runWasmLocate(bytes: Buffer, needles: string[]): any {
  if (!wasmEngine) {
    return { ok: false, error: "bundled wasm engine not found in wasm/ — reinstall the package, or run `npm run build` if working from source" };
  }
  const raw = JSON.parse(wasmEngine.locate(new Uint8Array(bytes), JSON.stringify(needles))) as WasmScanResult;
  if (!raw.ok) return { ok: false, error: raw.error ?? "wasm locate failed" };
  return { ok: true, count: raw.count, regions: raw.leaks };
}

/** Single source of truth for the server version (keeps the MCP handshake in
 *  lockstep with the published package). */
const VERSION: string = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8"),
).version;

/**
 * Engine discovery — one env var for the common case, two for overrides:
 *   OMITLY_ENGINE_DIR   directory holding both `omitly-redact` and `omitly-pdf`
 *   OMITLY_REDACT_BIN / OMITLY_PDF_BIN   per-binary overrides (win over the dir)
 * Two binaries by design: document generation is a different trust model from
 * the verifiable redaction engine (see crates/omitly-pdf/Cargo.toml).
 */
function discover(explicit: string | undefined, name: string): string | undefined {
  if (explicit) return explicit;
  const dir = process.env.OMITLY_ENGINE_DIR;
  if (!dir) return undefined;
  for (const cand of [path.join(dir, name), path.join(dir, `${name}.exe`)]) {
    if (existsSync(cand)) return cand;
  }
  return undefined;
}

const ENGINE_BIN = discover(process.env.OMITLY_REDACT_BIN, "omitly-redact");
const PDF_BIN = discover(process.env.OMITLY_PDF_BIN, "omitly-pdf");

/** Kill a wedged engine rather than hang the agent's tool call forever. */
const ENGINE_TIMEOUT_MS = resolveEngineTimeoutMs(process.env.OMITLY_ENGINE_TIMEOUT_MS);

/** Filesystem confinement root (see paths.ts) — resolved once at startup so a
 *  misconfigured OMITLY_ALLOWED_DIR fails loudly here, not mid-conversation. */
const ROOT = allowedRoot();

const regionSchema = z.object({
  page: z.number().int().min(0).describe("0-based page index"),
  x: z.number().describe("left, in PDF points (origin bottom-left)"),
  y: z.number().describe("bottom, in PDF points"),
  width: z.number().positive(),
  height: z.number().positive(),
  reason: z.string().optional().describe("audit-log reason, e.g. 'PII: SSN'"),
});

/**
 * Output schemas (#540) — the enforcement point for "no raw text ever leaves
 * this server". Every object is `.strict()` (unknown keys are a validation
 * ERROR, not silently dropped) and preview-carrying fields are always the
 * engine's MASKED preview, never a raw-text field — so an engine or handler
 * regression that starts emitting a raw value fails the tool call instead of
 * quietly shipping it. Handlers below build `structuredContent` by explicit
 * field allowlist (never by spreading the raw engine response), which is the
 * second half of that guarantee: even a schema gap can't leak a field the
 * handler never copied over in the first place.
 *
 * Field shapes here are drawn directly from what `crates/omitly-cli/src/main.rs`
 * actually serializes (see the module doc's JSON contracts) — not guessed from
 * the handler's existing text formatting.
 *
 * IMPORTANT — why every handler calls `checked()` rather than leaving
 * validation to the SDK: `@modelcontextprotocol/sdk`'s `validateToolOutput`
 * (server/mcp.js) opens with `if (result.isError) { return; }`, i.e. it skips
 * `outputSchema` validation entirely whenever a result is flagged as an error.
 * Per #338's policy, "the document is NOT clean" is exactly what sets
 * `isError: true` here — so the SDK would skip validation on precisely the
 * three branches that carry `findings`/`survivors`/`regions`, the ones where a
 * leaked field matters most. Flipping that `isError` policy is not an option
 * (#338 settled it deliberately), so the schemas are enforced here instead of
 * being relied on to fire downstream.
 */

/**
 * Validate a `structuredContent` payload against its declared output schema
 * before it leaves this process — see the note above on the SDK's `isError`
 * bypass. Returns the PARSED value (so any non-strict nested object also has
 * unknown keys stripped), and throws otherwise, which fails the tool call.
 *
 * The thrown message names issue PATHS and zod issue CODES only — never the
 * offending value. Some zod messages (`invalid_enum_value`, `invalid_literal`)
 * embed what they received, and echoing that into an error string would leak
 * the very field the schema just rejected.
 *
 * Exported for `schema-enforcement.test.ts`.
 */
export function checked<T extends z.ZodTypeAny>(schema: T, value: z.input<T>): z.infer<T> {
  const parsed = schema.safeParse(value);
  if (!parsed.success) {
    const where =
      parsed.error.issues
        .map((i) => `${i.path.join(".") || "<root>"}: ${i.code}`)
        .join("; ") || "unknown";
    throw new Error(
      `omitly-mcp internal error: tool output failed its declared outputSchema ` +
        `(${where}). Refusing to return it. This is a bug — please report it; ` +
        `no document content is included in this message by design.`,
    );
  }
  return parsed.data;
}

/** A candidate/found region as `find`/`locate_text` return it — coordinates
 *  plus a MASKED preview (e.g. '•••-••-6789'), never the raw matched text. */
const outputRegionSchema = z
  .object({
    page: z.number().int(),
    x: z.number(),
    y: z.number(),
    width: z.number(),
    height: z.number(),
    kind: z.string(),
    preview: z.string(),
  })
  .strict();

/** Copy only the known-safe fields off an engine-returned region — defense in
 *  depth alongside the `.strict()` schema above: a raw-text field the engine
 *  started emitting is dropped here even before validation would catch it. */
function toOutputRegion(r: any) {
  return {
    page: r.page,
    x: r.x,
    y: r.y,
    width: r.width,
    height: r.height,
    kind: r.kind,
    preview: r.preview,
  };
}

export const findSensitiveRegionsOutputSchema = z
  .object({
    count: z.number().int().min(0),
    regions: z.array(outputRegionSchema),
    note: z.string().optional(),
    /** Present (and true) on free-tier (wasm-served, unlicensed) results —
     *  omitly#226's EVALUATION mark. Never present on native-engine results. */
    evaluation: z.literal(true).optional(),
  })
  .strict();

export const locateTextOutputSchema = z
  .object({
    count: z.number().int().min(0),
    regions: z.array(outputRegionSchema),
  })
  .strict();

const bboxOutputSchema = z
  .object({ x: z.number(), y: z.number(), width: z.number(), height: z.number() })
  .strict();

/** Mirrors `redaction_core::model::Verification` — `{result:"pass"}` or
 *  `{result:"fail",detail}`. `detail` is a structural diagnostic ("page 3
 *  could not be re-read") produced by the verify pass itself, never text
 *  extracted from the document. */
const verificationOutputSchema = z.union([
  z.object({ result: z.literal("pass") }).strict(),
  z.object({ result: z.literal("fail"), detail: z.string() }).strict(),
]);

const auditEntryOutputSchema = z
  .object({
    page: z.number().int(),
    bbox: bboxOutputSchema,
    timestamp: z.string(),
    reason_code: z.string(),
    verification: verificationOutputSchema,
  })
  .strict();

const auditOutputSchema = z
  .object({
    verdict: z.enum(["pass", "fail"]),
    regions: z.array(auditEntryOutputSchema),
    warnings: z.array(z.string()),
    metadataScrubbed: z.boolean(),
    license: z.string(),
    licensedTo: z.string().nullable(),
    disclosures: z.array(z.string()),
  })
  .strict();

/** Copy only the known-safe fields off the engine's `audit` object — same
 *  allowlist defense as `toOutputRegion`. */
function toOutputAudit(a: any) {
  return {
    verdict: a.verdict,
    regions: (a.regions ?? []).map((e: any) => ({
      page: e.page,
      bbox: { x: e.bbox.x, y: e.bbox.y, width: e.bbox.width, height: e.bbox.height },
      timestamp: e.timestamp,
      reason_code: e.reason_code,
      verification:
        e.verification?.result === "fail"
          ? { result: "fail" as const, detail: e.verification.detail }
          : { result: "pass" as const },
    })),
    warnings: a.warnings ?? [],
    metadataScrubbed: a.metadataScrubbed,
    license: a.license,
    licensedTo: a.licensedTo ?? null,
    disclosures: a.disclosures ?? [],
  };
}

export const redactByEntityOutputSchema = z
  .object({
    output: z.string().nullable(),
    redactedCount: z.number().int().min(0),
    redacted: z.array(
      z.object({ page: z.number().int(), kind: z.string(), preview: z.string() }).strict(),
    ),
    verdict: z.enum(["pass", "fail"]).nullable(),
    audit: auditOutputSchema.nullable(),
  })
  .strict();

export const redactPdfOutputSchema = z
  .object({
    output: z.string(),
    regionCount: z.number().int().min(1),
    verdict: z.enum(["pass", "fail"]),
    audit: auditOutputSchema,
  })
  .strict();

/** A single leak/finding surfaced by `verify_redaction` — never the raw
 *  matched text. `reason`/`detail`/`class` are structural (which check
 *  failed, why), `preview` is the engine's masked preview. */
const verifyFindingOutputSchema = z
  .object({
    page: z.number().int().optional(),
    kind: z.string().optional(),
    class: z.string().optional(),
    reason: z.string().optional(),
    detail: z.string().optional(),
    preview: z.string().optional(),
  })
  .strict();

export const verifyRedactionOutputSchema = z
  .object({
    clean: z.boolean(),
    mode: z.enum(["sidecar", "rescan"]),
    verdict: z.enum(["pass", "fail"]).optional(),
    totalFindings: z.number().int().min(0),
    findings: z.array(verifyFindingOutputSchema),
  })
  .strict();

export const createPdfOutputSchema = z.object({ output: z.string() }).strict();

const offPageOutputSchema = z
  .object({ source: z.string(), kind: z.string(), preview: z.string() })
  .strict();

const coverageOutputSchema = z
  .object({
    pagesScanned: z.number().int().nullable(),
    pagesTotal: z.number().int().nullable(),
    notScanned: z.array(z.string()),
    priorRevisionsScanned: z.boolean(),
    metadataScanned: z.boolean(),
    acroformScanned: z.boolean(),
    attachmentsScanned: z.boolean(),
    formXobjectsScanned: z.number().int(),
    annotationAppearancesScanned: z.number().int(),
    pagesFailedCount: z.number().int(),
  })
  .strict();

/** Copy only the known-safe fields off the engine's `coverage` object — same
 *  allowlist defense as the other `toOutput*` helpers, and it doubles as the
 *  camelCase reshape `check_redaction`'s handler already needed. */
function toOutputCoverage(cov: any, notScanned: string[]) {
  return {
    pagesScanned: typeof cov.pages_scanned === "number" ? cov.pages_scanned : null,
    pagesTotal: typeof cov.pages_total === "number" ? cov.pages_total : null,
    notScanned,
    priorRevisionsScanned: !!cov.prior_revisions_scanned,
    metadataScanned: !!cov.metadata_scanned,
    acroformScanned: !!cov.acroform_scanned,
    attachmentsScanned: !!cov.attachments_scanned,
    formXobjectsScanned: cov.form_xobjects_scanned ?? 0,
    annotationAppearancesScanned: cov.annotation_appearances_scanned ?? 0,
    pagesFailedCount: (cov.pages_failed ?? []).length,
  };
}

const licenseProvenanceOutputSchema = z
  .object({
    valid: z.boolean(),
    licenseId: z.string(),
    licensedTo: z.string(),
    product: z.string(),
    reason: z.string().nullable(),
  })
  .strict();

/** Mirrors `NormalizedSealResult` (seal.ts) minus its internal `ok` — every
 *  field here is already hardened by `normalizeSealResult` (unrecognized
 *  verdicts collapse to `seal_invalid`/`sealValid:false`), and this is the
 *  same allowlist discipline as `toOutputRegion`/`toOutputAudit`: fingerprints,
 *  hashes, filenames and structural verdicts only — never document text. */
export const verifySealOutputSchema = z
  .object({
    verdict: z.enum(SEAL_VERDICTS),
    sealValid: z.boolean().nullable(),
    sealVersion: z.string().nullable(),
    carriesAuditReport: z.boolean().nullable(),
    sealFingerprint: z.string().nullable(),
    allPassed: z.boolean().nullable(),
    metadataScrubbed: z.boolean().nullable(),
    /** omitly#228: who decided the redactions this seal covers — engine-gated
     *  on seal validity; null = not recorded (pre-#228) or not surfaced. */
    decisionChannel: z.string().nullable(),
    regionCount: z.number().int().nullable(),
    pageCount: z.number().int().nullable(),
    warnings: z.array(z.string()).nullable(),
    licenseProvenance: licenseProvenanceOutputSchema.nullable(),
    inputSha256: z.string().nullable(),
    outputSha256: z.string().nullable(),
    sourceFilename: z.string().nullable(),
    outputFilename: z.string().nullable(),
  })
  .strict();

/** Copy only the known-safe fields off a `normalizeSealResult()` result —
 *  same allowlist defense as the other `toOutput*` helpers, even though
 *  `normalizeSealResult` itself is already a hardening layer. */
function toOutputSeal(res: NormalizedSealResult) {
  return {
    verdict: res.verdict,
    sealValid: res.sealValid,
    sealVersion: res.sealVersion,
    carriesAuditReport: res.carriesAuditReport,
    sealFingerprint: res.sealFingerprint,
    allPassed: res.allPassed,
    metadataScrubbed: res.metadataScrubbed,
    decisionChannel: res.decisionChannel,
    regionCount: res.regionCount,
    pageCount: res.pageCount,
    warnings: res.warnings,
    licenseProvenance: res.licenseProvenance,
    inputSha256: res.inputSha256,
    outputSha256: res.outputSha256,
    sourceFilename: res.sourceFilename,
    outputFilename: res.outputFilename,
  };
}

export const checkRedactionOutputSchema = z
  .object({
    clean: z.boolean(),
    totalFindings: z.number().int().min(0),
    byKind: z.record(z.string(), z.number().int()),
    regions: z.array(outputRegionSchema),
    survivors: z.array(outputRegionSchema),
    offPage: z.array(offPageOutputSchema),
    coverage: coverageOutputSchema,
    /** Present (and true) on free-tier (wasm-served, unlicensed) results —
     *  omitly#226's EVALUATION mark. Never present on native-engine results. */
    evaluation: z.literal(true).optional(),
  })
  .strict();

/**
 * Free-tier metering gate for the two DETECTION tools only.
 * Applies solely to the wasm-served path (no native engine configured) — the
 * zero-install tier. When a native engine IS configured, the engine's own
 * licence gates apply instead of this counter. Returns the refusal result when
 * capped, undefined when the call may proceed (with the metering outcome
 * recorded on `meter` for the EVALUATION banner).
 */
function freeTierGate(tool: string): { refusal?: ReturnType<typeof capRefusalResult>; meter?: FreeCheckOutcome } {
  if (ENGINE_BIN) return {};
  const meter = recordFreeCheck();
  if (meter.capped) return { refusal: capRefusalResult(tool, meter), meter };
  return { meter };
}

function capRefusalResult(tool: string, meter: FreeCheckOutcome) {
  const refusal = freeCapRefusal(tool, meter);
  return {
    content: [{ type: "text" as const, text: JSON.stringify(refusal, null, 2) }],
    isError: true,
  };
}

/**
 * Invoke the local Omitly engine CLI with a JSON request on stdin and parse the
 * JSON response from stdout. Contract (proposed for the redaction-core CLI):
 *
 *   stdin:  { "command": "redact" | "verify", ...args }
 *   stdout: { "ok": true, "output": "<path>", "audit": { ...signed audit log } }
 *           { "ok": false, "error": "<message>" }
 */
function spawnEngine(bin: string, request: unknown): Promise<any> {
  return new Promise((resolve, reject) => {
    const child = spawn(bin, [], { stdio: ["pipe", "pipe", "pipe"] });
    let out = "";
    let err = "";
    let outBytes = 0;
    let errBytes = 0;
    let settled = false;
    const finish = (fn: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn();
    };
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      finish(() =>
        reject(
          new Error(
            `engine timed out after ${ENGINE_TIMEOUT_MS}ms and was killed ` +
              `(override with OMITLY_ENGINE_TIMEOUT_MS)`,
          ),
        ),
      );
    }, ENGINE_TIMEOUT_MS);
    const capExceeded = (which: "stdout" | "stderr") => {
      child.kill("SIGKILL");
      finish(() =>
        reject(
          new Error(
            `engine ${which} exceeded ${ENGINE_OUTPUT_CAP_BYTES} bytes and was killed`,
          ),
        ),
      );
    };
    child.stdout.on("data", (d) => {
      outBytes += d.length;
      if (outBytes > ENGINE_OUTPUT_CAP_BYTES) {
        capExceeded("stdout");
        return;
      }
      out += d.toString();
    });
    child.stderr.on("data", (d) => {
      errBytes += d.length;
      if (errBytes > ENGINE_OUTPUT_CAP_BYTES) {
        capExceeded("stderr");
        return;
      }
      err += d.toString();
    });
    child.stdin.on("error", () => {}); // EPIPE if the engine dies early; close handles it
    child.on("error", (e) => {
      finish(() => reject(e));
    });
    child.on("close", (code) => {
      finish(() => {
        if (code !== 0) {
          reject(new Error(`engine exited ${code}: ${err.trim() || "no stderr"}`));
          return;
        }
        try {
          resolve(JSON.parse(out));
        } catch {
          reject(new Error(`engine returned non-JSON output: ${out.slice(0, 500)}`));
        }
      });
    });
    child.stdin.write(JSON.stringify(request));
    child.stdin.end();
  });
}

/** Drive the redaction engine (`OMITLY_REDACT_BIN`). */
function runEngine(request: unknown): Promise<any> {
  if (!ENGINE_BIN) {
    return Promise.reject(
      new Error(
        "No redaction engine configured. Set OMITLY_ENGINE_DIR to the directory " +
          "holding the omitly-redact binary (or OMITLY_REDACT_BIN to the binary " +
          "itself). Redaction runs on-device; nothing is uploaded.",
      ),
    );
  }
  return spawnEngine(ENGINE_BIN, request);
}

/** Drive the document generator (`OMITLY_PDF_BIN`). */
function runPdfEngine(request: unknown): Promise<any> {
  if (!PDF_BIN) {
    return Promise.reject(
      new Error(
        "No PDF generator configured. Set OMITLY_ENGINE_DIR to the directory " +
          "holding the omitly-pdf binary (or OMITLY_PDF_BIN to the binary itself). " +
          "PDF generation renders on-device; nothing is uploaded.",
      ),
    );
  }
  return spawnEngine(PDF_BIN, request);
}

const REGIONS = z.enum(["generic", "us", "au"]);

/** Run "find" via the native engine if configured, else the bundled wasm
 *  fallback (see the wasm block near the top of this file). `regions`
 *  narrowing (generic/us/au) only applies to the native path — wasm always
 *  scans every pattern, a safe default (more results, never fewer) rather
 *  than silently dropping the requested narrowing. */
function findViaEngineOrWasm(confinedPath: string, regions: string[] | undefined): Promise<any> | any {
  if (ENGINE_BIN) return runEngine({ command: "find", pdfPath: confinedPath, regions });
  const res = runWasmScan(readFileSync(confinedPath));
  if (res.ok && regions && regions.length) {
    res.note = "Regional narrowing (regions filter) needs a native engine — showing all detected kinds.";
  }
  return res;
}

/**
 * Registers all 8 tools on a given `McpServer` instance. Extracted from
 * module-level top code (#540) so tests can build an in-memory server +
 * client pair and drive the tools directly, without a child-process stdio
 * client. `index.ts`'s own module body stays a thin bin entry — see the
 * `isMainModule` guard at the bottom of this file.
 */
export function registerTools(server: McpServer): void {
server.registerTool(
  "find_sensitive_regions",
  {
    description:
  "Scan a PDF on-device and return candidate regions that look like PII — " +
    "emails, US SSNs, phone numbers, card numbers, and Australian identifiers " +
    "(TFN, ABN, ACN, Medicare, Centrelink CRN, IHI, BSB; kinds 'tfn'/'abn'/" +
    "'acn'/'medicare'/'crn'/'ihi'/'bsb') — each with the page and exact " +
    "coordinates (in PDF " +
    "points) the redaction engine needs. Use this FIRST so you select regions " +
    "by entity ('redact every TFN') and pass the returned coordinates straight " +
    "to redact_pdf, instead of guessing geometry from a rendered page. Numeric " +
    "kinds are check-digit validated where a published algorithm exists (CRN " +
    "has none — its matches are format-only). Candidates are best-effort " +
    "pattern matches for review — not a completeness guarantee and not a " +
    "compliance assessment; the file is never uploaded — detection runs " +
    "locally. Each candidate carries a MASKED preview (e.g. '•••-••-6789'), " +
    "never the raw value: the secret stays on the machine. You don't need the " +
    "plaintext to redact — drive it by page + coordinates. (A human reviewer " +
    "has the file open locally for full context.) Free tier (no native " +
    "engine): results are EVALUATION-marked and limited to a monthly number " +
    "of free checks, counted locally — past the cap this tool returns a " +
    "structured 'free-cap' refusal. A configured licensed engine is not " +
    "capped.",
    inputSchema: {
      pdfPath: z.string().describe("absolute path to the PDF to scan"),
      regions: z
        .array(REGIONS)
        .optional()
        .describe(
          "narrow LISTED pattern kinds to these regional packs (generic kinds " +
            "always listed; confirmed under-mark survivors always report); omit " +
            "to scan everything — the safe default",
        ),
    },
    outputSchema: findSensitiveRegionsOutputSchema,
  },
  async ({ pdfPath, regions }) => {
    try {
      const confined = confineInput(pdfPath, ROOT);
      const { refusal, meter } = freeTierGate("find_sensitive_regions");
      if (refusal) return refusal;
      const res = await findViaEngineOrWasm(confined, regions);
      if (!res?.ok) {
        return {
          content: [{ type: "text", text: `Scan failed: ${res?.error ?? "unknown error"}` }],
          isError: true,
        };
      }
      const found = res.regions ?? [];
      const summary =
        (meter ? `${evaluationBanner(meter)}\n\n` : "") +
        `Found ${found.length} candidate region(s).\n` +
        `Pass any subset to redact_pdf as its "regions" argument (page + x/y/width/height carry over).\n\n` +
        (res.note ? `Note: ${res.note}\n\n` : "") +
        JSON.stringify(found, null, 2);
      const structuredContent = checked(findSensitiveRegionsOutputSchema, {
        count: found.length,
        regions: found.map(toOutputRegion),
        ...(res.note ? { note: res.note as string } : {}),
        ...(meter ? { evaluation: true as const } : {}),
      });
      return { content: [{ type: "text", text: summary }], structuredContent };
    } catch (e) {
      return {
        content: [{ type: "text", text: `Could not scan: ${(e as Error).message}` }],
        isError: true,
      };
    }
  },
);

server.registerTool(
  "locate_text",
  {
    description:
      "Locate exact text strings in a PDF and return each occurrence's page and " +
      "coordinates (in PDF points). Use this for what pattern-matching can't catch " +
      "— names, addresses, account references — by doing the entity recognition " +
      "YOURSELF and passing the literal strings here; the engine resolves where " +
      "they sit so you never guess geometry from a rendered page. Feed the returned " +
      "regions straight to redact_pdf. Case-insensitive; a string the PDF splits " +
      "across text operators may not match as one run. Each hit returns a masked " +
      "preview, not the raw text. Nothing is uploaded.",
    inputSchema: {
      pdfPath: z.string().describe("absolute path to the PDF to search"),
      texts: z.array(z.string()).min(1).describe("literal strings to locate"),
    },
    outputSchema: locateTextOutputSchema,
  },
  async ({ pdfPath, texts }) => {
    try {
      const confined = confineInput(pdfPath, ROOT);
      const res = ENGINE_BIN
        ? await runEngine({ command: "locate_text", pdfPath: confined, texts })
        : runWasmLocate(readFileSync(confined), texts);
      if (!res?.ok) {
        return {
          content: [{ type: "text", text: `Search failed: ${res?.error ?? "unknown error"}` }],
          isError: true,
        };
      }
      const regions = res.regions ?? [];
      const summary =
        `Located ${regions.length} occurrence(s). Pass any subset to redact_pdf as "regions".\n\n` +
        JSON.stringify(regions, null, 2);
      const structuredContent = checked(locateTextOutputSchema, {
        count: regions.length,
        regions: regions.map(toOutputRegion),
      });
      return { content: [{ type: "text", text: summary }], structuredContent };
    } catch (e) {
      return {
        content: [{ type: "text", text: `Could not search: ${(e as Error).message}` }],
        isError: true,
      };
    }
  },
);

server.registerTool(
  "redact_by_entity",
  {
    description:
      "Find and redact PII in a PDF in ONE on-device step: scan, keep only the " +
      "requested entity kinds (email/ssn/phone/card plus the Australian " +
      "tfn/abn/acn/medicare/crn/ihi/bsb — omit `kinds` to redact every kind " +
      "detected), remove them, verify, and return what was redacted plus the " +
      "audit log. This is the 'just scrub the obvious PII' shortcut; when you need " +
      "to review before removing, call find_sensitive_regions first. Same caveat as " +
      "the detector: matches are best-effort pattern matching, not a completeness " +
      "guarantee and not a compliance assessment. Nothing is uploaded.",
    inputSchema: {
      pdfPath: z.string().describe("absolute path to the source PDF"),
      outputPath: z.string().describe("absolute path to write the redacted PDF"),
      kinds: z
        .array(
          z.enum([
            "email",
            "ssn",
            "phone",
            "card",
            "tfn",
            "abn",
            "acn",
            "medicare",
            "crn",
            "ihi",
            "bsb",
          ]),
        )
        .optional()
        .describe("entity kinds to redact; omit to redact all detected"),
      regions: z
        .array(REGIONS)
        .optional()
        .describe("narrow to these regional packs (intersects with `kinds`); omit for all"),
      drawBox: z.boolean().optional().describe("also paint a black bar (default: opaque fill only)"),
    },
    outputSchema: redactByEntityOutputSchema,
  },
  async ({ pdfPath, outputPath, kinds, regions, drawBox }) => {
    try {
      const res = await runEngine({
        command: "redact_entities",
        pdfPath: confineInput(pdfPath, ROOT),
        outputPath: confineOutput(outputPath, ROOT),
        kinds,
        regions,
        drawBox,
        // omitly#228: these redactions are AGENT-decided — the model picked
        // the entities. The engine records the channel so the output (and,
        // once the CLI path seals, the certificate) is distinguishable from
        // a human-decided desktop removal. Never omit or spoof this.
        decisionChannel: "mcp-agent",
      });
      if (!res?.ok) {
        return {
          content: [{ type: "text", text: `Redaction failed: ${res?.error ?? "unknown error"}` }],
          isError: true,
        };
      }
      const redacted = res.redacted ?? [];
      if (redacted.length === 0) {
        const structuredContent = checked(redactByEntityOutputSchema, {
          output: null,
          redactedCount: 0,
          redacted: [],
          verdict: null,
          audit: null,
        });
        return {
          content: [{ type: "text", text: `No matching entities found — nothing was written.` }],
          structuredContent,
        };
      }
      const audit = toOutputAudit(res.audit);
      const redactedOut = redacted.map((r: any) => ({ page: r.page, kind: r.kind, preview: r.preview }));
      const structuredContent = checked(redactByEntityOutputSchema, {
        output: res.output,
        redactedCount: redactedOut.length,
        redacted: redactedOut,
        verdict: audit.verdict,
        audit,
      });
      return {
        content: [
          {
            type: "text",
            text:
              `Redacted ${redacted.length} entit${redacted.length === 1 ? "y" : "ies"} → ${res.output}\n` +
              `Verification: ${res.audit?.verdict ?? "see audit log"}\n\n` +
              `Removed:\n${JSON.stringify(redacted, null, 2)}\n\n` +
              `Audit log:\n${JSON.stringify(res.audit, null, 2)}`,
          },
        ],
        structuredContent,
      };
    } catch (e) {
      return {
        content: [{ type: "text", text: `Could not run redaction: ${(e as Error).message}` }],
        isError: true,
      };
    }
  },
);

server.registerTool(
  "redact_pdf",
  {
    description:
      "Permanently redact regions of a PDF on-device using Omitly. Removes the " +
      "underlying text and image data (not a black box over it), verifies nothing " +
      "survives in each region, and returns a signed audit log. The file is never " +
      "uploaded — redaction happens locally.",
    inputSchema: {
      pdfPath: z.string().describe("absolute path to the source PDF"),
      outputPath: z.string().describe("absolute path to write the redacted PDF"),
      regions: z.array(regionSchema).min(1).describe("regions to remove"),
    },
    outputSchema: redactPdfOutputSchema,
  },
  async ({ pdfPath, outputPath, regions }) => {
    try {
      const res = await runEngine({
        command: "redact",
        pdfPath: confineInput(pdfPath, ROOT),
        outputPath: confineOutput(outputPath, ROOT),
        regions,
        // omitly#228: agent-driven write — see redact_by_entity's note.
        decisionChannel: "mcp-agent",
      });
      if (!res?.ok) {
        return {
          content: [{ type: "text", text: `Redaction failed: ${res?.error ?? "unknown error"}` }],
          isError: true,
        };
      }
      const audit = toOutputAudit(res.audit);
      const structuredContent = checked(redactPdfOutputSchema, {
        output: res.output,
        regionCount: regions.length,
        verdict: audit.verdict,
        audit,
      });
      return {
        structuredContent,
        content: [
          {
            type: "text",
            text:
              `Redacted ${regions.length} region(s) → ${res.output}\n` +
              `Verification: ${res.audit?.verdict ?? "see audit log"}\n\n` +
              `Audit log:\n${JSON.stringify(res.audit, null, 2)}`,
          },
        ],
      };
    } catch (e) {
      return {
        content: [{ type: "text", text: `Could not run redaction: ${(e as Error).message}` }],
        isError: true,
      };
    }
  },
);

server.registerTool(
  "verify_redaction",
  {
    description:
      "Re-scan an already-redacted PDF on-device and confirm nothing recoverable " +
      "remains. With a configured native engine and this file's own " +
      "`<path>.audit.json` sidecar (written by redact_pdf/redact_by_entity), this " +
      "re-checks exactly the regions that were redacted — the strongest form of " +
      "this check. Without a native engine (or without that sidecar — e.g. the " +
      "file wasn't redacted by this tool), it falls back to a general on-device " +
      "re-scan of the whole file and reports whether anything is still " +
      "detectable — a good-faith re-check, not a claim of the same rigor as the " +
      "sidecar-based path.",
    inputSchema: {
      pdfPath: z.string().describe("absolute path to the redacted PDF to verify"),
    },
    outputSchema: verifyRedactionOutputSchema,
  },
  async ({ pdfPath }) => {
    try {
      const confined = confineInput(pdfPath, ROOT);
      if (ENGINE_BIN) {
        const hasSidecar = existsSync(`${confined}.audit.json`);
        if (hasSidecar) {
          const res = await runEngine({ command: "verify", pdfPath: confined });
          if (!res?.ok) {
            return {
              content: [
                { type: "text", text: `Could not verify: ${res?.error ?? "unknown error"}` },
              ],
              isError: true,
            };
          }
          // Strict allowlist — this is the one branch that used to forward the
          // raw engine response verbatim (JSON.stringify(res)) with no field
          // filter at all. `findings` only ever carries structural
          // page/reason/class/detail strings, never document text.
          const verdict: "pass" | "fail" = res.verdict === "pass" ? "pass" : "fail";
          const findings: z.infer<typeof verifyFindingOutputSchema>[] = [
            ...((res.regions ?? []) as any[])
              .filter((r) => r.verification?.result === "fail")
              .map((r) => ({
                page: r.page,
                reason: r.reason,
                detail: r.verification.detail,
              })),
            ...((res.hiddenContent ?? []) as any[])
              .filter((c) => c.verification?.result === "fail")
              .map((c) => ({
                class: c.class,
                detail: c.verification.detail,
              })),
          ];
          const structuredContent = checked(verifyRedactionOutputSchema, {
            clean: verdict === "pass",
            mode: "sidecar",
            verdict,
            totalFindings: findings.length,
            findings,
          });
          return {
            content: [{ type: "text", text: JSON.stringify(res, null, 2) }],
            structuredContent,
            isError: res?.ok === false || verdict === "fail",
          };
        }
      }
      // Fallback: general re-scan (wasm if no native engine; the native `find`
      // command otherwise) — no sidecar, so nothing to check regions against,
      // but a non-empty result still means recoverable PII survived.
      const res = ENGINE_BIN
        ? await runEngine({ command: "find", pdfPath: confined })
        : runWasmScan(readFileSync(confined));
      if (!res?.ok) {
        return {
          content: [{ type: "text", text: `Could not verify: ${res?.error ?? "unknown error"}` }],
          isError: true,
        };
      }
      const foundRegions = res.regions ?? [];
      // `res.clean`/`res.total_findings` only exist on the WASM scan shape —
      // the native engine's plain "find" command returns just {ok,count,
      // regions} (see the module doc's JSON contract), so falling back to
      // `0` here always read as "clean" regardless of `regions.length` when
      // a native engine was configured. Fall back to the regions actually
      // returned, not a bare 0.
      const clean = res.clean ?? (res.total_findings ?? foundRegions.length) === 0;
      const summary = clean
        ? `✅ No recoverable PII found on the surfaces scanned (general re-scan — no redaction sidecar to check specific regions against).`
        : `⚠️ Found ${res.total_findings ?? foundRegions.length ?? 0} recoverable item(s) — this file is not clean.\n\n${JSON.stringify(res, null, 2)}`;
      const structuredContent = checked(verifyRedactionOutputSchema, {
        clean,
        mode: "rescan",
        totalFindings: res.total_findings ?? foundRegions.length,
        findings: foundRegions.map((r: any) => ({
          page: r.page,
          kind: r.kind,
          preview: r.preview,
        })),
      });
      return { content: [{ type: "text", text: summary }], structuredContent, isError: !clean };
    } catch (e) {
      return {
        content: [{ type: "text", text: `Could not verify: ${(e as Error).message}` }],
        isError: true,
      };
    }
  },
);

server.registerTool(
  "verify_seal",
  {
    description:
      "Verify a PDF's embedded Omitly audit report and trailing Ed25519 " +
      "tamper-evidence seal — on-device, nothing uploaded. Distinct from " +
      "`verify_redaction`: that tool re-checks whether redacted regions are " +
      "still empty; this tool cryptographically checks whether the delivered " +
      "bytes have changed since they were sealed. The seal proves INTEGRITY, " +
      "NOT IDENTITY: the signing key is per-install and travels with the file, " +
      "so a valid seal means 'unchanged since sealed by the holder of this " +
      "key', never 'produced by Omitly'. Compare `sealFingerprint` " +
      "out-of-band against the fingerprint the sender published if origin " +
      "matters. " +
      "Requires a configured native engine — there is no wasm seal-verification " +
      "path, so this always needs OMITLY_ENGINE_DIR/OMITLY_REDACT_BIN. A " +
      "`seal_unsupported_version` verdict means this verifier is too old to " +
      "check the seal at all — that is neither a pass nor a fail; update the " +
      "verifier rather than trusting or rejecting the file on that basis.",
    inputSchema: {
      pdfPath: z.string().describe("absolute path to the PDF to check for an Omitly audit report and seal"),
    },
    outputSchema: verifySealOutputSchema,
  },
  async ({ pdfPath }) => {
    try {
      const confined = confineInput(pdfPath, ROOT);
      const raw = await runEngine({ command: "verify_seal", pdfPath: confined });
      if (!raw?.ok) {
        return {
          content: [{ type: "text", text: `Could not verify seal: ${raw?.error ?? "unknown error"}` }],
          isError: true,
        };
      }
      const res = normalizeSealResult(raw);
      const structuredContent = checked(verifySealOutputSchema, toOutputSeal(res));
      if (res.verdict === "seal_unsupported_version") {
        return {
          content: [
            {
              type: "text",
              text:
                `⚠️ This file carries a seal version (${res.sealVersion ?? "unknown"}) this verifier ` +
                "does not implement. Nothing was cryptographically checked — this is " +
                "neither a pass nor a fail. Update the verifier to get a real verdict." +
                (res.carriesAuditReport
                  ? " The file DOES carry an Omitly audit report, which raises the stakes: " +
                    "an altered-and-relabelled Omitly output can look exactly like this " +
                    "to a verifier that's too old to check the seal — treat this as needing " +
                    "escalation, not a benign version mismatch."
                  : " No Omitly audit report was found alongside it.") +
                `\n\n${JSON.stringify(res, null, 2)}`,
            },
          ],
          structuredContent,
        };
      }
      // Invariant #2 (CLAUDE.md): the seal key is PER-INSTALL and rides inside
      // the artifact, so a valid seal proves the bytes are unchanged since
      // sealing — it does NOT prove Omitly produced them. Saying "produced by
      // Omitly" here would be the exact overclaim `forged_key_seal_verifies_
      // but_fingerprint_differs` exists to prevent, so the pass line states
      // integrity only and points at the fingerprint for out-of-band origin.
      const summary =
        res.verdict === "verified"
          ? `✅ Seal valid — these bytes are unchanged since they were sealed. That is an ` +
            `INTEGRITY check, not proof of origin: the signing key is per-install and ships ` +
            `with the file, so compare the fingerprint (${res.sealFingerprint ?? "none reported"}) ` +
            `out-of-band against what the sender published if you need to know who sealed it.`
          : `⚠️ Seal verdict: ${res.verdict} — do not treat this file's audit trail as trustworthy.`;
      return {
        content: [{ type: "text", text: `${summary}\n\n${JSON.stringify(res, null, 2)}` }],
        structuredContent,
        isError: isSealErrorVerdict(res.verdict),
      };
    } catch (e) {
      return {
        content: [{ type: "text", text: `Could not verify seal: ${(e as Error).message}` }],
        isError: true,
      };
    }
  },
);

server.registerTool(
  "create_pdf",
  {
    description:
      "Generate a clean PDF from Markdown (or raw HTML) on-device, rendered through " +
      "a real browser engine so it looks printed — not like a script's best guess. " +
      "Give it Markdown inline via `source` (or a file via `sourcePath`) and an " +
      "`outputPath`; it writes the PDF and returns the path. Use this instead of " +
      "writing a one-off reportlab/LaTeX/pandoc script. Nothing is uploaded.",
    inputSchema: {
      outputPath: z.string().describe("absolute path to write the PDF"),
      source: z.string().optional().describe("inline Markdown/HTML (omit if using sourcePath)"),
      sourcePath: z.string().optional().describe("absolute path to a Markdown/HTML file"),
      format: z.enum(["markdown", "html"]).optional().describe("input format (default: markdown)"),
      title: z.string().optional().describe("document <title> / metadata"),
      css: z.string().optional().describe("extra CSS appended after the default print styles"),
    },
    outputSchema: createPdfOutputSchema,
  },
  async ({ outputPath, source, sourcePath, format, title, css }) => {
    try {
      const res = await runPdfEngine({
        command: "create",
        outputPath: confineOutput(outputPath, ROOT),
        source,
        sourcePath: sourcePath === undefined ? undefined : confineInput(sourcePath, ROOT),
        format,
        title,
        css,
      });
      if (!res?.ok) {
        return {
          content: [{ type: "text", text: `PDF generation failed: ${res?.error ?? "unknown error"}` }],
          isError: true,
        };
      }
      const structuredContent = checked(createPdfOutputSchema, { output: res.output });
      return { content: [{ type: "text", text: `Created PDF → ${res.output}` }], structuredContent };
    } catch (e) {
      return {
        content: [{ type: "text", text: `Could not generate PDF: ${(e as Error).message}` }],
        isError: true,
      };
    }
  },
);

server.registerTool(
  "check_redaction",
  {
    description:
      "Audit an ALREADY-redacted PDF and report whether sensitive text still survives " +
      "underneath the redaction — the 'did my black boxes actually remove the data?' " +
      "check. Most tools redact by drawing a rectangle over text while leaving the " +
      "characters in the file, where they stay selectable and extractable. This " +
      "re-extracts the text on-device and flags any emails, SSNs, phone or card " +
      "numbers that are still present, each with a MASKED preview — the raw value " +
      "never leaves the machine. It checks the page text layer, text surviving UNDER " +
      "redaction marks, incremental-update prior revisions (the classic 'redacted then " +
      "saved, original still in the file' failure), document metadata, AcroForm field " +
      "values and embedded attachments, and returns a coverage report so a clean result " +
      "is scoped to what was inspected. A non-empty result means the redaction leaked. " +
      "Nothing is uploaded. (Pattern-based: names/addresses, image-only text, and the " +
      "surfaces listed as not-inspected aren't covered; absence of hits isn't proof of " +
      "completeness.) Free tier (no native engine): reports are EVALUATION-marked — " +
      "for evaluation, not production reliance — and limited to a monthly number of " +
      "free checks, counted locally; past the cap this tool returns a structured " +
      "'free-cap' refusal. A configured licensed engine is not capped.",
    inputSchema: {
      pdfPath: z.string().describe("absolute path to the supposedly-redacted PDF to audit"),
    },
    outputSchema: checkRedactionOutputSchema,
  },
  async ({ pdfPath }) => {
    try {
      const confined = confineInput(pdfPath, ROOT);
      const { refusal, meter } = freeTierGate("check_redaction");
      if (refusal) return refusal;
      const res = await findViaEngineOrWasm(confined, undefined);
      if (!res?.ok) {
        return {
          content: [{ type: "text", text: `Audit failed: ${res?.error ?? "unknown error"}` }],
          isError: true,
        };
      }
      const regions = res.regions ?? [];
      const survivors = res.survivors ?? [];
      const offPage = res.off_page ?? [];
      const cov = res.coverage ?? {};
      const total = res.total_findings ?? regions.length;
      const clean = res.clean ?? total === 0;

      // Honest coverage disclosure — what was inspected, and what was NOT, so a
      // "clean" result is scoped and never reads as "no PII anywhere".
      const scanned = [
        `${cov.pages_scanned ?? "?"}/${cov.pages_total ?? "?"} page text layer`,
        cov.prior_revisions_scanned && "prior (superseded) revisions",
        cov.metadata_scanned && "metadata",
        cov.acroform_scanned && "form fields",
        cov.attachments_scanned && "attachments",
        (cov.form_xobjects_scanned ?? 0) > 0 && `${cov.form_xobjects_scanned} Form XObject(s)`,
        (cov.annotation_appearances_scanned ?? 0) > 0 &&
          `${cov.annotation_appearances_scanned} annotation appearance(s)`,
      ].filter(Boolean);
      const notScanned = [
        ...(cov.not_scanned ?? []),
        ...((cov.pages_failed ?? []).length
          ? [`${cov.pages_failed.length} page(s) that could not be parsed`]
          : []),
      ];
      const scope =
        `Scanned: ${scanned.join(", ")}.` +
        (notScanned.length ? `\nNOT inspected: ${notScanned.join("; ")}.` : "");
      const coverage = toOutputCoverage(cov, notScanned);

      if (clean) {
        const structuredContent = checked(checkRedactionOutputSchema, {
          clean: true,
          totalFindings: 0,
          byKind: {},
          regions: [],
          survivors: [],
          offPage: [],
          coverage,
          ...(meter ? { evaluation: true as const } : {}),
        });
        return {
          content: [
            {
              type: "text",
              text:
                (meter ? `${evaluationBanner(meter)}\n\n` : "") +
                `✅ No recoverable PII found on the surfaces scanned in ${pdfPath}.\n\n` +
                `${scope}\n\n` +
                `This is a scoped result, not a completeness guarantee — the surfaces listed as ` +
                `NOT inspected, plus names/addresses (which need human or model review), are out of ` +
                `scope. For a removed-and-verified result with a signed audit log, use the Omitly app.`,
            },
          ],
          structuredContent,
        };
      }

      const byKind: Record<string, number> = {};
      for (const r of [...regions, ...survivors, ...offPage]) byKind[r.kind] = (byKind[r.kind] ?? 0) + 1;
      const tally = Object.entries(byKind)
        .map(([k, n]) => `${n} ${k}${n > 1 ? "s" : ""}`)
        .join(", ");
      const parts: string[] = [];
      if (regions.length) parts.push(`Text layer (${regions.length}):\n${JSON.stringify(regions, null, 2)}`);
      if (survivors.length)
        parts.push(`Surviving UNDER a redaction mark (${survivors.length}):\n${JSON.stringify(survivors, null, 2)}`);
      if (offPage.length)
        parts.push(
          `Off-page — prior revisions / metadata / form fields / attachments (${offPage.length}):\n` +
            `${JSON.stringify(offPage, null, 2)}`,
        );
      const structuredContent = checked(checkRedactionOutputSchema, {
        clean: false,
        totalFindings: total,
        byKind,
        regions: regions.map(toOutputRegion),
        survivors: survivors.map(toOutputRegion),
        offPage: offPage.map((f: any) => ({ source: f.source, kind: f.kind, preview: f.preview })),
        coverage,
        ...(meter ? { evaluation: true as const } : {}),
      });
      return {
        content: [
          {
            type: "text",
            text:
              (meter ? `${evaluationBanner(meter)}\n\n` : "") +
              `⚠️ LEAK: this "redacted" PDF still contains ${total} sensitive item(s) (${tally}) — ` +
              `the redaction did not actually remove the data.\n\n` +
              `${parts.join("\n\n")}\n\n` +
              `${scope}\n\n` +
              `Previews are masked; the raw values stayed on-device. To actually remove this data ` +
              `(not just cover it) and get an independent verification + signed audit log, redact it ` +
              `with Omitly — https://omitly.app`,
          },
        ],
        structuredContent,
        isError: true,
      };
    } catch (e) {
      return {
        content: [{ type: "text", text: `Could not audit: ${(e as Error).message}` }],
        isError: true,
      };
    }
  },
);
} // end registerTools

/** Create a fresh `McpServer` with all 8 tools registered — used by both the
 *  bin entry below and tests. */
export function createServer(): McpServer {
  const server = new McpServer({ name: "omitly-mcp", version: VERSION });
  registerTools(server);
  return server;
}

/**
 * Thin bin entry: only connect stdio when this file is run directly (`npx
 * omitly-mcp` / the `bin` entry), never when a test imports it.
 *
 * `process.argv[1]` MUST be resolved through `realpathSync` before the
 * comparison — this is Node's own documented form of the check ("Determining
 * if a module is the entry point"). npm, npx and `npm link` all install a
 * `bin` as a SYMLINK (`node_modules/.bin/omitly-mcp` → `../omitly-mcp/dist/
 * index.js`), and Node resolves `import.meta.url` THROUGH that symlink while
 * leaving `process.argv[1]` as the unresolved link path. Comparing the two raw
 * therefore evaluates FALSE on the single most common real invocation
 * (`npx omitly-mcp`), and the server would exit silently — no stdio
 * connection, no error, no stderr. Measured on node v25.9.0: raw comparison
 * false via both an absolute and a relative `.bin`-style symlink, true with
 * `realpathSync`. `bin-entry.test.ts` runs the BUILT bin through a
 * `.bin`-style symlink and speaks real MCP stdio to it, so this cannot regress
 * silently again.
 */
function computeIsMainModule(): boolean {
  const entry = process.argv[1];
  if (entry === undefined) return false;
  try {
    return import.meta.url === pathToFileURL(realpathSync(entry)).href;
  } catch {
    // argv[1] isn't a resolvable path (`node --eval`, a deleted file) — then
    // this module was not the entry point.
    return false;
  }
}

if (computeIsMainModule()) {
  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
