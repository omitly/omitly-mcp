#!/usr/bin/env node
/**
 * Omitly MCP server.
 *
 * Exposes Omitly's local, verifiable PDF redaction to MCP clients (Claude Code,
 * Claude Desktop, etc.) as callable tools. The whole point: an agent can redact a
 * document *without uploading it anywhere* — redaction runs on-device via the
 * Omitly engine, which removes the data, checks the file for copies left behind,
 * and returns a signed audit log of what it did.
 *
 * The natural flow across the three tools:
 *   find_sensitive_regions → the engine extracts text WITH coordinates and
 *     returns PII candidates, so the model works in entity space ("redact every
 *     SSN") and never has to guess PDF point geometry from a rendered image.
 *   redact_pdf            → remove the chosen regions' bytes, check for copies left behind, audit.
 *   verify_redaction      → re-run the checks on the output.
 *
 * Integration point — the engine binary:
 *   This server shells out to a local CLI (`omitly-redact`, in
 *   crates/omitly-cli) that wraps the `redaction-core` Rust crate. Build it with
 *   `cargo build -p omitly-cli` and point OMITLY_REDACT_BIN at the binary. The
 *   contract is documented in README.md and in `runEngine()` below: a JSON
 *   request on stdin, a JSON response (result + audit log) on stdout.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, realpathSync } from "node:fs";
import { createRequire } from "node:module";
import * as path from "node:path";
import { pathToFileURL } from "node:url";
import { z } from "zod";
import { ENGINE_OUTPUT_CAP_BYTES, resolveEngineTimeoutMs } from "./engine-config.js";
import { allowedRoot, assertSidecarUnchanged, confineInput, confineOutput, confineSidecar } from "./paths.js";
import { annotations } from "./annotations.js";
import { registerEditTools } from "./edit-tools.js";
import { registerSkillPrompt } from "./skill-prompt.js";
import {
  getUiCapability,
  registerAppResource,
  registerAppTool,
  RESOURCE_MIME_TYPE,
} from "@modelcontextprotocol/ext-apps/server";
import { withVersion } from "./result-card.js";
import { applyScanToVerdict, engineLine, reconcileVerdict, safeText, textOffPage, textRegions } from "./verdict-rule.js";
import { auditCaps, auditLabel, BENIGN_DISCLOSURES, capped, isFailure, OUTCOMES, passOutcome, sealCaps, sealState, sidecarCaps, WHY, type Cap, type Issued, type ParsedAudit } from "./outcome.js";
import { disclosureLabel } from "./coverage-rule.js";
import { checkLegOf, parseCheckVerdict, parseLocateReply, parseRedactAudit, parseScanReply, parseSealReply, parseSidecarVerifyReply, scanLegOf, unusableReplyMessage, type ScanReply } from "./replies.js";
import { CardPathAllowlist, logOpen, systemOpener, type FileOpener } from "./open-in-omitly.js";
import {
  userVerdictLabel,
  v2Verdict,
  AUDIT_V2_OVERALLS,
  USER_VERDICTS,
  DECISION_CHANNELS,
  isProductNotice,
  normalizeSealResult,
  SEAL_REMOVED_SUMMARY,
  sealEraLine,
  sealKeyLine,
  SEAL_KEY_KINDS,
  SEAL_VERDICTS,
  type DecisionChannel,
  type NormalizedSealResult,
} from "./seal.js";
import { CHECK_NOTICE, FIND_NOTICE } from "./usage.js";
import {
  engineOnlyText,
  pendingText,
  isTrialOver,
  proposeUnavailableText,
  queuedNote,
  queuedText,
  removalTrialOverText,
  TRIAL_TERMS,
  removalUnavailableText,
  trialClause,
} from "./removal.js";
import { outcomeView, readMailboxFacts, readOutcome } from "./decisions.js";
import {
  enqueueProposal,
  readDesktopPresence,
  readProposal,
  recordAnalysisOf,
  sha256Hex,
  startClientHeartbeat,
  type ProposalClient,
  type ProposalTool,
} from "./desktop.js";

/**
 * WASM fallback for five detection/verify/extract tools — bundled in the npm
 * package (see package.json "files"/"build:wasm"), so `find_sensitive_regions`,
 * `locate_text`, `check_redaction`, `verify_redaction` and `extract_pdf_text`
 * (omitly#1169 — the last of the free tools to gain this, see that issue for
 * why it didn't ship with the others) work out of the box with NO native
 * engine binary and NO Rust toolchain on the caller's machine.
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
type WasmEngine = {
  scan(bytes: Uint8Array): string;
  locate(bytes: Uint8Array, needlesJson: string): string;
  extract_text(bytes: Uint8Array, masked: boolean): string;
  /** omitly#1267: the Safe to Send verdict. Optional because a wasm build
   *  that predates it has no such export — that is `check_unavailable`,
   *  never a thrown error. */
  check?(bytes: Uint8Array): string;
};
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
  /** omitly#1473: absent on a result from a build that predates the field. */
  scan_complete?: boolean;
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
    scan_complete: r.scan_complete,
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
    return { ok: false, error: "bundled wasm engine not built — run `npm run build` (needs wasm-pack + Rust)" };
  }
  return wasmScanToFindShape(wasmEngine.scan(new Uint8Array(bytes)));
}

function runWasmLocate(bytes: Buffer, needles: string[]): any {
  if (!wasmEngine) {
    return { ok: false, error: "bundled wasm engine not built — run `npm run build` (needs wasm-pack + Rust)" };
  }
  const raw = JSON.parse(wasmEngine.locate(new Uint8Array(bytes), JSON.stringify(needles))) as WasmScanResult;
  if (!raw.ok) return { ok: false, error: raw.error ?? "wasm locate failed" };
  return { ok: true, count: raw.count, regions: raw.leaks };
}

/** Wasm `extract_text`'s output shape is already identical to the native
 *  `extract_text` command's (`{ ok, masked, pages }`, camelCase — see
 *  `crates/leakcheck-wasm/src/lib.rs`'s doc comment on why that binding
 *  doesn't just derive `Serialize` on the crate's own snake_case types), so
 *  unlike `runWasmScan`/`runWasmLocate` there is no shape translation here —
 *  `extract_pdf_text`'s handler below works unchanged regardless of engine. */
function runWasmExtractText(bytes: Buffer, masked: boolean): any {
  if (!wasmEngine) {
    return { ok: false, error: "bundled wasm engine not built — run `npm run build` (needs wasm-pack + Rust)" };
  }
  return JSON.parse(wasmEngine.extract_text(new Uint8Array(bytes), masked));
}

/** omitly#1267: the wasm `check` export's JSON, parsed — see
 *  `checkViaEngineOrWasm`. */
function runWasmCheck(bytes: Buffer): any {
  if (!wasmEngine?.check) return undefined;
  return JSON.parse(wasmEngine.check(new Uint8Array(bytes)));
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

/**
 * omitly#1890 (X2, K9): the provenance words that say a PERSON decided about a region: an AI proposal
 * a person accepted, an OCR box a person corrected, a box a person drew. The desktop app writes them
 * into a sealed report; a caller of this server or of the engine CLI never may, because the report
 * would then say a person confirmed what an AI client sent. The CLI (`crates/omitly-cli`,
 * `reserved_provenance`) is the authoritative gate; this is the same rule worded for the agent
 * before anything is queued or run, so `redact_pdf` and `propose_redactions` answer alike with and
 * without the desktop app. Keep the two in step: `contract/cases/error-redact-reserved-reason.json`.
 */
const RESERVED_PROVENANCE: readonly string[] = ["AI_PROPOSAL", "OCR_CORRECTED", "MANUAL"];

/** Rust's `char::is_whitespace` (Unicode White_Space), which the CLI's `trim()` removes. Not JS's
 *  `trim()`: that also removes U+FEFF and keeps U+0085, so the two sides would disagree on a reason. */
const WHITE_SPACE = /^[\t\n\v\f\r \u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+|[\t\n\v\f\r \u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+$/g;

/** The reserved word a caller-supplied `reason` claims, if any: its provenance part (the text before
 *  the first `|` or `=>`, as `provenance_token` in the desktop's `pending_delivery.rs` reads it),
 *  trimmed and ASCII-uppercased (not `toUpperCase()`, which maps `ı` to `I` where the CLI does not). */
export function reservedProvenance(reason: string): string | undefined {
  const provenance = reason
    .split("=>")[0]!
    .split("|")[0]!
    .replace(WHITE_SPACE, "")
    .replace(/[a-z]/g, (c) => c.toUpperCase());
  return RESERVED_PROVENANCE.find((token) => token === provenance);
}

/** E17 (design 5.13), word for word the engine CLI's refusal; `n` counts from 0, like `page`. */
export function reservedReasonRefusal(n: number): string {
  return (
    `The reason for region ${n} uses a word Omitly reserves for what a person decided ` +
    `(AI_PROPOSAL, MANUAL, OCR_CORRECTED). Use a descriptive reason such as 'PII: SSN'. ` +
    `Nothing was redacted.`
  );
}

/** omitly#1857: the result card's resource URI (MCP Apps: a `ui://` resource). */
const RESULT_CARD_URI = "ui://omitly/result-card.html";

/** The card page `npm run build:view` writes next to this file (`dist/result-card.html`).
 *  Fail-soft like the skill prompt: a tree that has not built it (a tsc-only dev loop, the
 *  Windows CI leg) serves every tool as before, text only, without a card or the app-only
 *  `open_in_omitly` tool. `result-card.test.ts` asserts the built package has it. */
function loadResultCardHtml(): string | undefined {
  try {
    return readFileSync(new URL("./result-card.html", import.meta.url), "utf8");
  } catch {
    process.stderr.write("[omitly-mcp] result card not built (dist/result-card.html missing); tools return text only\n");
    return undefined;
  }
}

/** omitly#1857: `open_in_omitly`'s output. `unsupported` is a normal answer, not an error. */
export const openInOmitlyOutputSchema = z.object({ status: z.enum(["opened", "unsupported"]) }).strict();

const regionSchema = z.object({
  page: z.number().int().min(0).describe("0-based page index"),
  x: z.number().describe("left, in PDF points (origin bottom-left)"),
  y: z.number().describe("bottom, in PDF points"),
  width: z.number().positive(),
  height: z.number().positive(),
  reason: z
    .string()
    .optional()
    .describe(
      "audit-log reason, e.g. 'PII: SSN'. Never AI_PROPOSAL, MANUAL or OCR_CORRECTED (before any | or =>, " +
        "in any case): those words are reserved for what a person decided in the Omitly app, and a request " +
        "that uses one is refused",
    ),
});

/** The `regions` argument of the two tools that take caller regions. The reserved-word rule is checked
 *  here, on the array, not on `regionSchema.reason`, because its refusal names the region's position
 *  (E17), which a refinement on the string cannot know. The first offending region is reported. */
const regionsArg = (what: string) =>
  z
    .array(regionSchema)
    .min(1)
    .superRefine((regions, ctx) => {
      const n = regions.findIndex((r) => r.reason !== undefined && reservedProvenance(r.reason) !== undefined);
      if (n >= 0) ctx.addIssue({ code: "custom", path: [n, "reason"], message: reservedReasonRefusal(n) });
    })
    .describe(what);

/** omitly#1890: the scan a proposal's regions came from. Read only when the call would be queued for
 *  the desktop app; without the app it is ignored. */
const ANALYSIS_ID_ARG = z
  .string()
  .optional()
  .describe(
    "the analysisId returned by find_sensitive_regions or locate_text for THIS document; required when " +
      "the Omitly desktop app is running and the regions would be queued for a person to accept " +
      "(it ties the coordinates to the bytes you scanned); ignored otherwise",
  );

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
 * Per #338's policy, "the document is NOT clean" sets `isError: true` on the
 * tools that still follow it (`find_sensitive_regions`, `redact_*`,
 * `verify_redaction`) — so the SDK would skip validation on precisely the
 * branches that carry `findings`/`survivors`/`regions`, the ones where a
 * leaked field matters most. (omitly#1857: the three card-linked tools,
 * `check_redaction`, `verify_seal` and `verify_document`, now return a COMPLETED
 * check with `isError: false`, because Claude Desktop renders no MCP Apps view
 * for an error result; `isError: true` is kept there for execution failures.)
 * The schemas are enforced here instead of being relied on to fire downstream.
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
    /** omitly#1473: false = some page or stream could not be read, so `count`
     *  speaks only for what was read. Read this before `count`. */
    scanComplete: z.boolean(),
    count: z.number().int().min(0),
    regions: z.array(outputRegionSchema),
    /** omitly#1890: names THIS scan, so a later proposal's coordinates are tied to the bytes it read.
     *  Absent only when the engine reported no document digest (an engine older than this server). */
    analysisId: z.string().optional(),
    /** Contract §3.2: never `safe_to_send`. A pattern scan is not a check of the document. */
    outcome: z.enum(OUTCOMES).refine((o) => o !== "safe_to_send", "a pattern scan is never a pass"),
    note: z.string().optional(),
    /** Present (and true) on free-tier (wasm-served, unlicensed) results —
     *  the free-tier mark (omitly#226; its visible wording was reworded in omitly#1859, the field
     *  keeps its name). Never present on native-engine results. */
    evaluation: z.literal(true).optional(),
  })
  .strict();

export const locateTextOutputSchema = z
  .object({
    count: z.number().int().min(0),
    regions: z.array(outputRegionSchema),
    /** omitly#1890: as on `find_sensitive_regions`. */
    analysisId: z.string().optional(),
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
    /** omitly#1104: the report format the engine embedded. */
    auditSchema: z.enum(["omitly.audit/v1", "omitly.audit/v2"]).nullable(),
    /** omitly#1104: the Safe to Send verdict of a v2 output, computed by the
     *  engine from the published bytes; null for a v1 output. */
    userVerdict: z.enum(USER_VERDICTS).nullable(),
    blocking: z.boolean().nullable(),
    /** omitly#1496 (v1: omitly#228): the channel the engine recorded for
     *  this redaction — `mcp-agent` for this server's write tools. null for
     *  anything outside the closed set. */
    decisionChannel: z.enum(DECISION_CHANNELS).nullable(),
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
    ...auditVerdict(a),
    decisionChannel: DECISION_CHANNELS.includes(a.decisionChannel) && a.decisionChannel !== "none"
      ? (a.decisionChannel as DecisionChannel)
      : null,
  };
}

/** omitly#1104: the v2 verdict of an engine `audit` object, fail-closed
 *  through the same check `verify_seal` uses (`v2Verdict`). */
function auditVerdict(a: any): {
  auditSchema: "omitly.audit/v1" | "omitly.audit/v2" | null;
  userVerdict: (typeof USER_VERDICTS)[number] | null;
  blocking: boolean | null;
} {
  const schema = a?.auditSchema;
  if (schema === "omitly.audit/v2") {
    const v = v2Verdict(
      {
        auditV2Recognized: true,
        auditV2Overall: a.auditV2Overall,
        userVerdict: a.userVerdict,
        blocking: a.blocking,
      },
      { requireGates: false },
    );
    return { auditSchema: schema, userVerdict: v.userVerdict, blocking: v.blocking };
  }
  return {
    auditSchema: schema === "omitly.audit/v1" ? schema : null,
    userVerdict: null,
    blocking: null,
  };
}

/** Contract §3.6: the ONE line of a redaction's text about the engine's own record. It is not a check of the document. */
function redactRecordLine(audit: ParsedAudit): string {
  return `The engine's record of this redaction: ${auditLabel(audit)}. This is not a check of the document: run check_redaction on the output.\n`;
}

/** Contract §3.7: what the desktop app recorded for a proposal, in words that do not read as a verdict. The file is written by another
 *  process, so only known values get a label; anything else reads as not recorded. */
export function proposalRecordLabel(v: unknown): string {
  switch (v) {
    case "safe_to_send":
      return "nothing to review";
    case "needs_review":
      return "items to review";
    case "cannot_verify":
      return "could not check";
    case "pass":
      return "no failed region (legacy report)";
    case "fail":
      return "a failed region (legacy report)";
    default:
      return "not recorded";
  }
}

export const redactByEntityDoneSchema = z
  .object({
    status: z.literal("done"),
    output: z.string().nullable(),
    redactedCount: z.number().int().min(0),
    redacted: z.array(
      z.object({ page: z.number().int(), kind: z.string(), preview: z.string() }).strict(),
    ),
    /** Contract §6.1: the engine's record of this redaction, NOT a check of the document. */
    engineAudit: auditOutputSchema.nullable(),
    outcome: z.enum(OUTCOMES).refine((o) => o !== "safe_to_send", "a redaction record is never a pass"),
  })
  .strict();

export const redactPdfDoneSchema = z
  .object({
    status: z.literal("done"),
    output: z.string(),
    regionCount: z.number().int().min(1),
    engineAudit: auditOutputSchema,
    outcome: z.enum(OUTCOMES).refine((o) => o !== "safe_to_send", "a redaction record is never a pass"),
  })
  .strict();

/**
 * omitly#1643 — accept-in-app. While the Omitly desktop app is running with
 * "Accept proposals in Omitly" on, a redaction write does NOT run: it is queued
 * as a proposal for a person to accept in the app, and this is what the tool
 * returns instead of an audit. Nothing has been written. The desktop then runs
 * the verified-removal core itself and the sealed record says `human-desktop`.
 */
export const queuedProposalOutputSchema = z
  .object({
    status: z.literal("queued"),
    proposalId: z.string(),
    /** omitly#1890 (X9): SHA-256 of the exact bytes written to the proposal file. */
    revision: z.string(),
    tool: z.enum(["redact_pdf", "redact_by_entity"]),
    client: z.object({ name: z.string(), version: z.string() }).strict(),
    pdfPath: z.string(),
    note: z.string(),
  })
  .strict();

/**
 * The SDK registers an OBJECT schema per tool (no unions), so the two write
 * tools declare this superset: `status` says which shape the rest is. Every
 * result is still built through `checked()` against the strict shape for its
 * status (`*DoneSchema` or `queuedProposalOutputSchema`) before it leaves.
 */
const queuedFields = {
  tool: z.enum(["redact_pdf", "redact_by_entity"]).optional(),
  proposalId: z.string().optional(),
  revision: z.string().optional(),
  client: z.object({ name: z.string(), version: z.string() }).strict().optional(),
  pdfPath: z.string().optional(),
  note: z.string().optional(),
};
export const redactByEntityOutputSchema = z
  .object({
    status: z.enum(["done", "queued"]),
    output: z.string().nullable().optional(),
    redactedCount: z.number().int().min(0).optional(),
    redacted: z
      .array(z.object({ page: z.number().int(), kind: z.string(), preview: z.string() }).strict())
      .optional(),
    engineAudit: auditOutputSchema.nullable().optional(),
    outcome: z.enum(OUTCOMES).optional(),
    ...queuedFields,
  })
  .strict();
export const redactPdfOutputSchema = z
  .object({
    status: z.enum(["done", "queued"]),
    output: z.string().optional(),
    regionCount: z.number().int().min(1).optional(),
    engineAudit: auditOutputSchema.optional(),
    outcome: z.enum(OUTCOMES).optional(),
    ...queuedFields,
  })
  .strict();

export const proposalStatusOutputSchema = z
  .object({
    proposalId: z.string(),
    status: z.enum(["pending", "accepted", "rejected", "applied", "failed", "expired"]),
    // omitly#1890 (S6): null only for a decision recorded before the desktop's decision log existed.
    tool: z.enum(["redact_pdf", "redact_by_entity"]).nullable(),
    createdAt: z.string().nullable(),
    resolvedAt: z.string().nullable(),
    output: z.string().nullable(),
    /** Contract §3.7: what the desktop app recorded: a claim of another process, not this server's verdict. */
    recordedByDesktop: z.string().nullable(),
    note: z.string().nullable(),
    // The revision of the proposal the decision applied to; null while undecided or for a legacy decision.
    decidedRevision: z.string().nullable(),
    // Present (true) only for a decision recorded before the desktop kept its own decision record:
    // Omitly cannot confirm it, and its verdict is not reported (omitly#1890, R2-1).
    unverified: z.literal(true).optional(),
  })
  .strict();

/**
 * omitly#1473 (owner decision, option b): `clean` keeps its #538 meaning
 * ("nothing found where we looked") and a SEPARATE field says whether the scan
 * was complete — every page and content stream read. Every text surface shows
 * completeness BEFORE the clean/count headline, because "No recoverable PII
 * found" over a document where no page could be read is a false clean.
 *
 * `complete` is true only when the engine said so. An engine that does not
 * report the field (a build older than this change) cannot vouch for
 * completeness, so it is `complete: false, reported: false` — fail closed, with
 * wording that does not claim a page failed.
 */
export function scanCompleteness(res: any): { complete: boolean; reported: boolean } {
  // Contract C4: complete only when BOTH flags say so; either one absent is "not complete", never a parse failure.
  const top = res?.scan_complete;
  const inner = res?.coverage?.scan_complete;
  if (top === true && inner === true) return { complete: true, reported: true };
  const said = (typeof top === "boolean" ? 1 : 0) + (typeof inner === "boolean" ? 1 : 0);
  return { complete: false, reported: top === false || inner === false || said === 2 };
}

/** The warning for an incomplete scan; "" when the scan was complete. */
export function incompleteScanBanner(res: any): string {
  const { complete, reported } = scanCompleteness(res);
  if (complete) return "";
  if (!reported) {
    return (
      "⛔ SCAN COMPLETENESS NOT REPORTED — this engine did not say whether every page and " +
      "stream was read, so the result below is not a pass."
    );
  }
  const cov = res?.coverage ?? {};
  const failed = Array.isArray(cov.pages_failed) ? cov.pages_failed.length : 0;
  const rasterOnly = Array.isArray(cov.raster_only_pages) ? cov.raster_only_pages.length : 0;
  // WHY it is incomplete, from the coverage the engine already reports. The
  // image-only and generic OCR lines are restated from the structured counts.
  const why = [
    failed > 0 && `${failed} page(s) could not be parsed`,
    rasterOnly > 0 && `${rasterOnly} page(s) are images only and were not text-scanned (no OCR)`,
    // Contract §6.4: the text shows a fixed label for each disclosure, never the engine's line (it can hold a filename).
    ...[...new Set(((Array.isArray(cov.not_scanned) ? cov.not_scanned : []) as string[]).filter((n) => !/effectively image-only|needs OCR/.test(n)).map(disclosureLabel))],
  ].filter(Boolean) as string[];
  const read =
    typeof cov.pages_scanned === "number" && typeof cov.pages_total === "number"
      ? ` ${cov.pages_scanned} of ${cov.pages_total} page(s) had readable text.`
      : "";
  return (
    "⛔ INCOMPLETE SCAN — some of this document was not read, so the result below speaks " +
    `only for what was read (possibly nothing).${read}` +
    (why.length ? ` Why: ${why.join("; ")}.` : "") +
    " This is NOT a clean result."
  );
}

/** v0.2.2 (errata G1-G2, class sweep): every non-constant string that reaches a tool's text is passed through `safeText`: engine errors,
 *  exception messages, output paths. Raw values stay in `structuredContent`. */
const errText = (e: unknown): string => safeText(e instanceof Error ? e.message : String(e));
/** The §3.6 text of a redaction whose output was written but whose audit could not be used. */
const writtenOutputText = (output: unknown): string =>
  `The output was written to ${safeText(output)}, but its audit could not be read. Do not use it until check_redaction has checked it.`;

/** v0.2.4 (errata 2): a proposal id in text only in the shape the desktop mints it (`newProposalId`, desktop.ts: 12 random bytes as 24 lowercase
 *  hex). The readers already require the record's own `id` to equal the requested one and the request to have this shape (`readProposal`,
 *  `readOutcome`), so this is a second, local guarantee: anything else reads as fixed wording. */
const idText = (id: unknown): string => (typeof id === "string" && /^[0-9a-f]{24}$/.test(id) ? id : "(unrecognised id)");

/** Contract §3.4: the single note a sidecar-mode `verify_redaction` text ends with. */
export const sidecarNote = (regions: number): string =>
  `ℹ️ Region check: the ${regions} regions recorded in this file's sidecar were re-checked, plus ten hidden-content checks. ` +
  `The sidecar is not evidence: the outcome above comes from this server's own check of the file.`;

/** The line every text surface leads with: the incomplete-scan warning, or an
 *  explicit statement that the scan was complete. Never empty. */
export function scanStatusLine(res: any): string {
  return incompleteScanBanner(res) || "ℹ️ The pattern scan read every page and stream it found. Images are not OCR'd."; // claims-lint:allow -- "read" describes the text scan; this says images are NOT OCR'd, no recognised-text claim (omitly#1675)
}

/** A single leak/finding surfaced by `verify_redaction` — never the raw
 *  matched text. `reason`/`detail`/`class` are structural (which check
 *  failed, why), `preview` is the engine's masked preview. */
const verifyFindingOutputSchema = z
  .object({
    /** errata G3: which list of the scan the item came from, as on `check_redaction` (`regions`, `survivors`, `offPage`). */
    where: z.enum(["regions", "survivors", "offPage"]).optional(),
    /** errata G3: an off-page item's raw `source` (structured only). */
    source: z.string().optional(),
    page: z.number().int().optional(),
    kind: z.string().optional(),
    class: z.string().optional(),
    reason: z.string().optional(),
    detail: z.string().optional(),
    preview: z.string().optional(),
  })
  .strict();

/** errata G3: everything `totalFindings` counts, each tagged with the list it came from. */
const scanFindings = (res: any): z.infer<typeof verifyFindingOutputSchema>[] => [
  ...(res.regions as any[]).map((r: any) => ({ where: "regions" as const, page: r.page, kind: r.kind, preview: r.preview })),
  ...(res.survivors as any[]).map((r: any) => ({ where: "survivors" as const, page: r.page, kind: r.kind, preview: r.preview })),
  ...(res.off_page as any[]).map((f: any) => ({ where: "offPage" as const, source: f.source, kind: f.kind, preview: f.preview })),
];

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
    // omitly#446: buyer-asserted, never an identity claim.
    licensedTo: z
      .string()
      .describe(
        "The name the buyer entered at checkout. The vendor licence chain signs it, but Omitly does not verify who the buyer is: report it as the name given by the buyer, never as a verified identity.",
      ),
    product: z.string(),
    reason: z.string().nullable(),
  })
  .strict();

/** Mirrors `NormalizedSealResult` (seal.ts) minus its internal `ok` — every
 *  field here is already hardened by `normalizeSealResult` (unrecognized
 *  verdicts collapse to `seal_invalid`/`sealValid:false`), and this is the
 *  same allowlist discipline as `toOutputRegion`/`toOutputAudit`: fingerprints,
 *  hashes, filenames and structural verdicts only — never document text. */
/** omitly#87. `.strict()` is load-bearing, not stylistic: it is what makes an
 *  accidentally-added field (a fingerprint, a raw licence blob) a hard schema
 *  failure instead of a silent extra key in a model transcript. */
export const checkLicenseOutputSchema = z
  .object({
    state: z.enum(["licensed", "trial", "trial_expired", "updates_lapsed", "invalid"]),
    tier: z.enum(["pro", "personal", "standard"]).nullable(),
    daysLeft: z.number().int().nullable(),
    /** The vendor-SIGNED display name — the one identity field the root attests. */
    licensedTo: z.string().nullable(),
    expiresAt: z.string().nullable(),
    /** Which of LICENSE-RESOLUTION.md §1's three steps produced the licence. */
    resolutionStep: z.string().nullable(),
    /** Bound to one machine? A BOOLEAN — the fingerprint hash is never reported. */
    deviceBound: z.boolean(),
    provenanceAvailable: z.boolean(),
    renewalNotice: z.string().nullable(),
    reason: z.string().nullable(),
  })
  .strict();

/** Contract §6.1: the seal tools' result. `outcome` is the only verdict field and is never `safe_to_send` (a seal is integrity, not
 *  a check of the content, §3.5). Every field the embedded report or the file claims sits under `embeddedReport`, attributed; the
 *  engine's own word for the verification is `verifierVerdict`. `seal.fingerprint` is null on every v2 reply (F6 adds it). */
const embeddedReportSchema = z
  .object({
    verifierVerdict: z.enum(SEAL_VERDICTS),
    sealValid: z.boolean().nullable(),
    carriesAuditReport: z.boolean().nullable(),
    allPassed: z.boolean().nullable(),
    metadataScrubbed: z.boolean().nullable(),
    /** omitly#228: who decided the redactions this seal covers; a claim of the file's report. */
    decisionChannel: z.string().nullable(),
    regionCount: z.number().int().nullable(),
    pageCount: z.number().int().nullable(),
    warnings: z.array(z.string()).nullable(),
    licenseProvenance: licenseProvenanceOutputSchema.nullable(),
    inputSha256: z.string().nullable(),
    outputSha256: z.string().nullable(),
    sourceFilename: z.string().nullable(),
    outputFilename: z.string().nullable(),
    /** omitly#1104: the file's own report's verdict, as the verifier read it. NOT this server's verdict. */
    auditV2Overall: z.enum(AUDIT_V2_OVERALLS).nullable(),
    userVerdict: z.enum(USER_VERDICTS).nullable(),
    blocking: z.boolean().nullable(),
  })
  .strict();

export const verifySealOutputSchema = z
  .object({
    outcome: z.enum(OUTCOMES),
    seal: z
      .object({
        state: z.enum(["held", "invalid", "removed", "none", "unsupported"]),
        version: z.string().nullable(),
        /** omitly#1588 (SEAL-SPEC-v2 §11.1): "classical-era seal (v1)" for a v1 seal, whatever its verdict; null otherwise. */
        eraLabel: z.string().nullable(),
        fingerprint: z.string().nullable(),
        /** omitly#1792: "one_time" = made for this one output; "install" = no one-time marker; null = v1 / not verified. A label. */
        keyKind: z.enum(SEAL_KEY_KINDS).nullable(),
      })
      .strict(),
    embeddedReport: embeddedReportSchema.nullable(),
  })
  .strict()
  .superRefine((v, ctx) => {
    if (v.outcome === "safe_to_send") ctx.addIssue({ code: "custom", path: ["outcome"], message: "a seal tool never issues a pass (a seal is integrity only)" });
  });

/** The structured result of a seal tool (contract §6.1, §3.5): the outcome is `worst(first S-row, incomplete)`, never a pass. */
function toOutputSeal(res: NormalizedSealResult, issued: Issued) {
  const noReport = res.verdict === "no_report" || (res.verdict === "seal_unsupported_version" && res.carriesAuditReport !== true);
  return {
    outcome: issued.outcome,
    seal: {
      state: sealState(res),
      version: res.sealVersion,
      eraLabel: res.sealEraLabel,
      fingerprint: res.sealFingerprint,
      keyKind: res.sealKeyKind,
    },
    embeddedReport: noReport
      ? null
      : {
          verifierVerdict: res.verdict,
          sealValid: res.sealValid,
          carriesAuditReport: res.carriesAuditReport,
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
          auditV2Overall: res.auditV2Overall,
          userVerdict: res.userVerdict,
          blocking: res.blocking,
        },
  };
}

/** What the file's own report records, in the contract's words (§3.6 labels): never the file's own strings. */
function reportLabel(res: NormalizedSealResult): string | null {
  if (res.userVerdict === "safe_to_send") return "nothing to review";
  if (res.userVerdict === "needs_review") return res.blocking ? "a failed redaction" : "items to review";
  if (res.userVerdict === "cannot_verify") return "that it could not be checked";
  if (res.verdict === "verified") return "no failed region";
  if (res.verdict === "incomplete") return "a failed region";
  return null;
}

/** Contract §3.5, §6.2: the text of a seal tool. A seal shows the bytes are unchanged since they were sealed by the holder of a key,
 *  and anyone can seal a file with their own key: it is never a check of the content, and no ✅ line is printed. No dump of the engine's reply. */
function sealText(res: NormalizedSealResult, issued: Issued, tool: "verify_seal" | "verify_document"): string {
  const state = sealState(res);
  const fp = res.sealFingerprint !== null && /^[0-9A-Fa-f:]{1,200}$/.test(res.sealFingerprint) ? res.sealFingerprint : "a key this engine does not report"; // errata G2: colon-hex or fixed wording
  let body: string;
  if (state === "removed") body = SEAL_REMOVED_SUMMARY;
  else if (state === "invalid") body = "⚠️ The seal does not verify: the file was changed after it was sealed, or the seal is not genuine. Do not rely on its audit trail.";
  else if (state === "unsupported") {
    body =
      // v0.2.1 (errata 3): the version token is the file's own string, so it stays in `seal.version` (structured) and is not shown here.
      `⚠️ This file carries a seal version this verifier does not implement. Nothing was cryptographically checked.` +
      (res.carriesAuditReport ? " The file DOES carry an Omitly audit report, which raises the stakes: treat this as needing escalation." : " No Omitly audit report was found alongside it.");
  } else if (state === "none") {
    body = "⚠️ No Omitly audit report or seal that this verifier can check was found in this document, so there is nothing here for this tool to verify.";
  } else {
    const label = reportLabel(res);
    body =
      `ℹ️ The seal checks out: these bytes are unchanged since they were sealed by the holder of ${fp}. Anyone can seal a file with their own key, ` +
      `so this is not a check of the content: run check_redaction.` +
      (label ? `\nThe file's own report records: ${label}.` : "");
  }
  return (
    issued.lead +
    body +
    sealEraLine(res) +
    sealKeyLine(res) +
    (tool === "verify_document" ? "\nThis does not check the document's content. Run check_redaction for that." : "")
  );
}

/** Shared core for `verify_seal` and `verify_document` (omitly#113) — both
 *  tools check exactly the same thing (the CLI's `verify_seal` engine
 *  command: the embedded audit report + whole-file seal, v1 or v2) and only
 *  differ in their tool name/description and the wording of their summary
 *  text, so the confine → runEngine → normalize → schema-check pipeline
 *  lives here once. Currently native-engine-only — there is no wasm
 *  seal-verification path yet (omitly-seal itself has no filesystem/process
 *  dependency and could in principle cross to wasm, but that compilation
 *  work has not been done; see the #113 issue thread's 2026-08-14 note). */
async function runSealVerification(
  pdfPath: string,
): Promise<
  | { ok: true; res: NormalizedSealResult; issued: Issued; structuredContent: ReturnType<typeof toOutputSeal> }
  | { ok: false; errorText: string }
> {
  const confined = confineInput(pdfPath, ROOT);
  // omitly#1861: no engine is a designed answer, not the engine-config error.
  if (!ENGINE_BIN) return { ok: false, errorText: engineOnlyText("verify_seal") };
  const raw = await runEngine({ command: "verify_seal", pdfPath: confined });
  if (!raw?.ok) {
    return { ok: false, errorText: safeText(raw?.error ?? "unknown error") };
  }
  // omitly#1857: an engine answer with no recognised verdict is no check result at all, not a failed
  // seal. `normalizeSealResult` would fail closed to `seal_invalid`, which, now that a completed
  // check is `isError: false`, would present an unusable answer as a completed tamper verdict.
  if (typeof raw.verdict !== "string" || !(SEAL_VERDICTS as readonly string[]).includes(raw.verdict)) {
    return { ok: false, errorText: "Seal check failed to run: the engine returned no recognised verdict." };
  }
  // omitly#1864: parse, don't trust. A v1 pass needs a valid seal and allPassed; no verdict word may
  // carry the other vocabulary's pass. Anything else is a failure to run, never a seal verdict.
  const parsedSeal = parseSealReply(raw);
  if (!parsedSeal.ok) {
    return { ok: false, errorText: `Seal check failed to run: ${unusableReplyMessage("seal", parsedSeal.reason)}` };
  }
  const res = normalizeSealResult(raw);
  // Contract §3.5: the outcome is the seal table's first row, then at least `incomplete`: only the seal caps speak here.
  const issued = capped(null, sealCaps(res));
  const structuredContent = checked(verifySealOutputSchema, toOutputSeal(res, issued));
  return { ok: true, res, issued, structuredContent };
}

/** One PII span located within a page's extracted text — CHAR (Unicode
 *  scalar value) offsets, never byte offsets (mirrors `redaction_core::
 *  detect::TextSpan`; see that type's doc comment for why). Never a raw
 *  value: just the kind and where it sits, so a caller receiving MASKED
 *  text still learns what was found and where. */
const textSpanOutputSchema = z
  .object({ kind: z.string(), start: z.number().int().min(0), end: z.number().int().min(0) })
  .strict();

const extractedPageOutputSchema = z
  .object({
    page: z.number().int(),
    /** `false` ⇒ this page's content stream could not be read (size cap or
     *  parse failure) — `text` is empty because it was never scanned, not
     *  because the page is blank. */
    contentDecoded: z.boolean(),
    /** Masked (default) or raw text, per the `masked` tool argument. */
    text: z.string(),
    spans: z.array(textSpanOutputSchema),
  })
  .strict();

export const extractPdfTextOutputSchema = z
  .object({
    /** Echoes which mode actually ran — `true` unless the caller explicitly
     *  passed `masked: false`. */
    masked: z.boolean(),
    pages: z.array(extractedPageOutputSchema),
    /** Set when a `regions` filter was requested but ignored — the wasm
     *  fallback (no native engine configured) always scans every pattern,
     *  same posture as `findSensitiveRegionsOutputSchema`'s `note`. */
    note: z.string().optional(),
  })
  .strict();

/** Copy only the known-safe fields off an engine-returned extracted page —
 *  same allowlist defense as `toOutputRegion`/`toOutputAudit`. */
function toOutputExtractedPage(p: any) {
  return {
    page: p.page,
    contentDecoded: p.contentDecoded,
    text: p.text,
    spans: (p.spans ?? []).map((s: any) => ({ kind: s.kind, start: s.start, end: s.end })),
  };
}

/** omitly#1267: the three verdicts, exactly as the engine and wasm spell them
 *  (`omitly_seal::audit_v2::CheckState`). Never reconstructed here. */
const CHECK_STATE = z.enum(["safe_to_send", "needs_review", "cannot_verify"]);

/** The fixed reason codes a verdict can carry: the two the shared Rust
 *  wrapper sets (`omitly_seal::check::FREE_REASON_*`) and the one this
 *  server sets when the configured engine or the bundled wasm has no `check`
 *  (an older build). */
const CHECK_REASON_CODE = z.enum(["input_too_large", "check_failed", "check_unavailable", "result_invalid"]);

/** Engine output, even when it is "fixed copy": at most 1 KiB, no control
 *  characters (C0, DEL, C1) and no line or paragraph separators, so a line
 *  can neither carry a payload nor forge extra lines in the text output. The
 *  longest line in `omitly_seal::check::COPY` is about 250 bytes. */
const COPY_LINE = z
  .string()
  .max(1024)
  .regex(/^[^\u0000-\u001f\u007f-\u009f\u2028\u2029]*$/);
const ITEMS_MAX = 1024;

const checkItemSchema = z
  .object({
    /** A fixed line from the engine's own copy table — never document text. */
    text: COPY_LINE,
    /** 1-based page numbers, when the line concerns specific pages. */
    pages: z.array(z.number().int().min(1).max(1_000_000)).optional(), // v0.2.1: bound by the reply (replies.ts parseCheckVerdict: 1..pagesTotal, no repeats), not by a fixed cap
  })
  .strict();

/** The desktop Check screen's `CheckResult`, field for field, minus the two
 *  desktop-only fields (`canWrite`, `producer`). */
const checkResultOutputSchema = z
  .object({
    state: CHECK_STATE,
    blocking: z.boolean(),
    summary: COPY_LINE,
    pagesTotal: z.number().int().min(0).max(1_000_000),
    pagesRead: z.number().int().min(0).max(1_000_000),
    checked: z.array(checkItemSchema).max(ITEMS_MAX),
    notChecked: z.array(checkItemSchema).max(ITEMS_MAX),
    problems: z.array(checkItemSchema).max(ITEMS_MAX),
    review: z.array(checkItemSchema).max(ITEMS_MAX),
    information: z.array(checkItemSchema).max(ITEMS_MAX),
    decisions: z.array(checkItemSchema).max(ITEMS_MAX),
    reasons: z.array(checkItemSchema).max(ITEMS_MAX),
    /** RFC 3339 UTC, as both engines write it. */
    checkedAt: z.string().regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$/),
    omitlyVersion: z.string().max(64).regex(/^[0-9A-Za-z.+-]+$/),
    /** Empty only when the file was refused unread (`input_too_large`). */
    sha256: z.string().regex(/^([0-9a-f]{64})?$/),
    sizeBytes: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
    /** omitly#1496: the verified report's `provenance.decision_channel` —
     *  a closed-set code (`none` for a presented check: nothing was
     *  decided). A record of process, not proof. null when the engine sent
     *  none (an older engine, or a report that predates the field). */
    decisionChannel: z.enum(DECISION_CHANNELS).nullable(),
  })
  .strict();

/** What the engine and wasm actually send: the output shape plus the two
 *  desktop-only fields, which are dropped on the way out, and
 *  `decisionChannel` omitted when there is none. Strict — any other field
 *  fails the whole result. */
const checkResultEngineSchema = checkResultOutputSchema
  .extend({
    canWrite: z.literal(false),
    producer: z.null(),
    decisionChannel: z.enum(DECISION_CHANNELS).optional(),
  })
  .strict();

/**
 * omitly#1267: the Safe to Send verdict — the same object the browser
 * checker's wasm `check` and `omitly-redact`'s `check` command return. The
 * states are verdicts about THIS CHECK, scoped to what it covered (see
 * `result.checked` / `result.notChecked`); none of them says the document is
 * safe.
 *
 * The engine's audit v2 report is deliberately NOT part of this output
 * (coordinator decision on the #1267 review): it is engine output this server
 * cannot validate — the shared validator needs applicability recomputed from
 * the PDF, which only the Rust engine can do — and a model-facing tool needs
 * the verdict and the validated fixed-copy `result`, not the report. The
 * report is available from `omitly-redact check` and the desktop app.
 */
export const checkVerdictOutputSchema = z
  .object({
    verdict: CHECK_STATE,
    blocking: z.boolean(),
    result: checkResultOutputSchema.nullable(),
    reason_code: CHECK_REASON_CODE.nullable(),
  })
  .strict();

export const checkRedactionOutputSchema = z
  .object({
    /** omitly#1473: false = some page or stream could not be read, so `clean`
     *  speaks only for what was read (possibly nothing). Read before `clean`. */
    scanComplete: z.boolean(),
    clean: z.boolean(),
    totalFindings: z.number().int().min(0),
    byKind: z.record(z.string(), z.number().int()),
    regions: z.array(outputRegionSchema),
    survivors: z.array(outputRegionSchema),
    offPage: z.array(offPageOutputSchema),
    coverage: coverageOutputSchema,
    /** omitly#1267: the Safe to Send verdict over the same file, from the
     *  same presented check the desktop "Check any PDF" runs. */
    verdict: checkVerdictOutputSchema,
    /** omitly#1864: the ONE structured answer to "is this a pass?": `safe_to_send` only when every pass
     *  condition holds; otherwise `needs_review`, `not_a_pass` (a failed redaction) or `incomplete`
     *  (see `Outcome` in verdict-rule.ts). The tool result's `isError` is false for a completed check
     *  whatever it found, so this is the field to branch on, with `verdict.verdict` and the text. */
    outcome: z.enum(OUTCOMES),
    /** Present (and true) on free-tier (wasm-served, unlicensed) results —
     *  the free-tier mark (omitly#226; its visible wording was reworded in omitly#1859, the field
     *  keeps its name). Never present on native-engine results. */
    evaluation: z.literal(true).optional(),
  })
  .strict()
  // omitly#1864: a result that lists sensitive items is never also Safe to Send. The tool reconciles
  // the verdict before it builds this object (`reconcileVerdictWithFindings`); this check is the
  // last line, so no code path can return both. A violation is refused like any other bad output.
  .superRefine((v, ctx) => {
    const listed = v.regions.length + v.survivors.length + v.offPage.length;
    const bad = (path: string[], message: string) => ctx.addIssue({ code: "custom", path, message });
    if ((!v.clean || v.totalFindings > 0 || listed > 0 || !v.scanComplete) && v.verdict.verdict === "safe_to_send") {
      bad(["verdict", "verdict"], "a result with findings, or from a scan that did not read everything, cannot carry Safe to Send");
    }
    // The whole verdict is the engine's whole pass contract (replies.ts `parseCheckVerdict`): a Safe to
    // Send that is blocking, or lists problems, review items, decisions or reasons, is refused here too.
    const parsed = parseCheckVerdict(v.verdict);
    if (!parsed.ok) bad(["verdict"], parsed.reason);
    if ((v.outcome === "safe_to_send") !== (v.verdict.verdict === "safe_to_send")) {
      bad(["outcome"], "outcome and verdict.verdict disagree about a pass");
    }
    if (v.survivors.length > 0 && v.outcome !== "not_a_pass") bad(["outcome"], "text confirmed under a redaction mark is not a pass");
  });

/** Contract §6.1: the `verify_redaction` result. `verdict` is the reconciled check verdict (never a pass the outcome denies); the old
 *  `verdict: "pass" | "fail"` is gone. `sidecar` (sidecar mode) holds counts only: the sidecar is not evidence. */
export const verifyRedactionOutputSchema = z
  .object({
    outcome: z.enum(OUTCOMES),
    mode: z.enum(["sidecar", "rescan"]),
    /** The pattern scan read every page and stream it found. A scan fact, not a verdict. */
    scanComplete: z.boolean(),
    /** The pattern scan listed nothing: a scan fact, not a verdict. */
    clean: z.boolean(),
    totalFindings: z.number().int().min(0),
    findings: z.array(verifyFindingOutputSchema),
    verdict: checkVerdictOutputSchema,
    sidecar: z
      .object({
        regions: z.number().int().min(0),
        regionsFailed: z.number().int().min(0),
        hiddenContentFailed: z.number().int().min(0),
        metadataScrubbed: z.boolean(),
        engineWarnings: z.number().int().min(0),
        disclosures: z.number().int().min(0),
      })
      .strict()
      .optional(),
  })
  .strict()
  .superRefine((v, ctx) => {
    if ((v.outcome === "safe_to_send") !== (v.verdict.verdict === "safe_to_send")) {
      ctx.addIssue({ code: "custom", path: ["outcome"], message: "outcome and verdict.verdict disagree about a pass" });
    }
    if (v.outcome === "safe_to_send" && (!v.scanComplete || !v.clean)) ctx.addIssue({ code: "custom", path: ["outcome"], message: "a pass needs a complete, clean scan" });
  });

const UNAVAILABLE = {
  verdict: "cannot_verify" as const,
  blocking: false,
  result: null,
  reason_code: "check_unavailable" as const,
};

/** Validate an engine/wasm verdict before any of it reaches the model — the
 *  same allowlist defence as `toOutputRegion`, but strict: a `result` that is
 *  not exactly the CheckResult shape (unknown field, control character,
 *  over-long line, malformed digest or time, or a state/blocking that
 *  disagrees with the verdict), or an unknown `reason_code`, drops the result
 *  and forces `cannot_verify` / `result_invalid`. The engine's `report` is
 *  never copied. A missing verdict is
 *  `check_unavailable`. Never a pass on bad input. */
function toOutputVerdict(raw: any) {
  if (!raw || typeof raw !== "object" || !CHECK_STATE.safeParse(raw.verdict).success) {
    return UNAVAILABLE;
  }
  const invalid = {
    verdict: "cannot_verify" as const,
    blocking: false,
    result: null,
    reason_code: "result_invalid" as const,
  };
  if (typeof raw.blocking !== "boolean") return invalid;
  const reason = raw.reason_code === null || raw.reason_code === undefined ? null : CHECK_REASON_CODE.safeParse(raw.reason_code);
  if (reason && !reason.success) return invalid;
  let result: z.infer<typeof checkResultOutputSchema> | null = null;
  if (raw.result !== null && raw.result !== undefined) {
    const parsed = checkResultEngineSchema.safeParse(raw.result);
    if (!parsed.success) return invalid;
    const { canWrite: _canWrite, producer: _producer, decisionChannel, ...rest } = parsed.data;
    if (rest.state !== raw.verdict || rest.blocking !== raw.blocking) return invalid;
    result = { ...rest, decisionChannel: decisionChannel ?? null };
  } else if (raw.verdict !== "cannot_verify") {
    // Only a refusal may come without its result.
    return invalid;
  }
  const out = {
    verdict: raw.verdict as z.infer<typeof CHECK_STATE>,
    blocking: raw.blocking as boolean,
    result,
    // `raw.report` is never copied: see checkVerdictOutputSchema.
    reason_code: reason ? reason.data : null,
  };
  // omitly#1864: the engine's FULL pass contract, not the verdict word alone (replies.ts
  // `parseCheckVerdict`, from crates/omitly-seal/src/check.rs): a Safe to Send that is blocking, lists a
  // problem, review item, decision or reason, read fewer pages than the file has, or has no digest is a
  // reply that contradicts itself, so it is no verdict.
  if (!parseCheckVerdict(out).ok) return invalid;
  return out;
}

/** The verdict as text: the heading (the same three states the desktop
 *  shows), the check's own summary, then its sections exactly as the engine
 *  wrote them — fixed lines with page numbers, never document text. */
export function verdictHeading(v: z.infer<typeof checkVerdictOutputSchema>): string {
  const r = v.result;
  const lines = (title: string, items: { text: string; pages?: number[] }[] | undefined) =>
    items && items.length
      ? `\n  ${title}:\n` +
        items.map((i) => `    - ${engineLine(i.text)}${i.pages ? ` (pages ${i.pages.join(", ")})` : ""}`).join("\n")
      : "";
  return (
    verdictHeadline(v) +
    lines("Checked", r?.checked) +
    lines("Problems", r?.problems) +
    lines("Review", r?.review) +
    lines("Could not be checked", v.verdict === "cannot_verify" ? r?.reasons : r?.notChecked) +
    lines("Information", r?.information)
  );
}

function verdictLabel(v: z.infer<typeof checkVerdictOutputSchema>): string {
  return v.verdict === "safe_to_send"
    ? "Safe to Send"
    : v.verdict === "needs_review"
      ? v.blocking
        ? "Needs Review — problems found"
        : "Needs Review"
      : "Cannot Verify";
}

function verdictHeadline(v: z.infer<typeof checkVerdictOutputSchema>): string {
  const label = verdictLabel(v);
  return (
    `Check verdict: ${label}.` +
    (v.result?.summary ? ` ${engineLine(v.result.summary)}` : "") +
    ` (A verdict about this check, limited to what it covered: hidden, covered and ` +
    `recoverable content, and the sensitive-looking text the pattern scan lists. ` +
    `It is not a statement that the document is safe.)`
  );
}

/** omitly#1267: the verdict via the native engine's `check` command when one
 *  is configured, else the bundled wasm's `check` export — the same Rust
 *  function (`omitly_seal::check::free_check`) either way. An engine or wasm
 *  build without `check`, or any failure to run it, is `check_unavailable`. */
async function checkViaEngineOrWasm(B: Buffer, confinedPath: string): Promise<{
  verdict: z.infer<typeof checkVerdictOutputSchema>;
  /** omitly#1857: true when the verdict check was ATTEMPTED and FAILED TO EXECUTE (see below). */
  executionFailed: boolean;
}> {
  let raw: any;
  try {
    if (ENGINE_BIN) {
      const res = await runEngine({ command: "check", pdfPath: confinedPath });
      raw = res?.ok === true ? res.check : undefined;
    } else {
      raw = runWasmCheck(B);
    }
  } catch {
    raw = undefined;
  }
  const verdict = checked(checkVerdictOutputSchema, toOutputVerdict(raw));
  // A verdict the ENGINE gave, even Cannot Verify with its own reason code (`input_too_large`,
  // `check_failed`: the only two the Rust side sends), is a check that COMPLETED. The two codes below
  // are made here, never by the engine, and mean the check did not run or its answer could not be
  // trusted: the subprocess exited non-zero, timed out, threw, answered `ok: false` or no `check`
  // object, no verdict engine exists (a wasm build without `check`), or the answer failed the
  // allowlist. That is an execution failure: the caller returns `isError: true`.
  const executionFailed = verdict.reason_code === "check_unavailable" || verdict.reason_code === "result_invalid";
  return { verdict, executionFailed };
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
async function findViaEngineOrWasm(B: Buffer, confinedPath: string, regions: string[] | undefined): Promise<any> {
  // An empty `regions` list IS a narrowing: the engine reads `Some([])` as the generic kinds only
  // (crates/omitly-cli/src/main.rs `allowed_kinds`, detect.rs `kinds_for_regions`), so its reply lists fewer
  // kinds than it counts, exactly as for ["us"].
  const narrowed = Boolean(ENGINE_BIN && Array.isArray(regions));
  const raw = ENGINE_BIN
    ? await runEngine({ command: "find", pdfPath: confinedPath, regions })
    : runWasmScan(B);
  const res = validatedScan(raw, { narrowed });
  // omitly#1890: the digest of the bytes this scan read. For wasm that is B (read once, C1); the native engine reports `inputSha256` itself.
  if (res.ok && !ENGINE_BIN) res.inputSha256 = sha256Hex(B);
  if (res.ok && !ENGINE_BIN && regions && regions.length) {
    res.note = "Regional narrowing (regions filter) needs a native engine — showing all detected kinds.";
  }
  // omitly#1864 round 5 (review K2): a narrowed native scan lists fewer items than it counts (the count and any pass
  // stay unfiltered), so the text says how many are listed of how many found, on this path as on the wasm one.
  if (res.ok && narrowed) {
    const listed = res.regions.length + res.survivors.length + res.off_page.length;
    if (listed < res.total_findings) {
      res.note = `Narrowed to the requested regions: ${listed} of ${res.total_findings} item(s) found are listed; the rest are of kinds outside them and still count against a pass.`;
    }
  }
  return res;
}

/** omitly#1864: a scan reply is read only through its strict parser (replies.ts). One that is
 *  malformed, incomplete in form or self-contradicting is `{ ok: false }`, never a result. */
function validatedScan(raw: any, opts: { narrowed?: boolean } = {}): any {
  if (!raw?.ok) return raw ?? { ok: false, error: "the engine gave no answer" };
  const parsed = parseScanReply(raw, { ...opts, engine: ENGINE_BIN ? "native" : "wasm" });
  return parsed.ok ? raw : { ok: false, error: unusableReplyMessage("scan", parsed.reason) };
}


// ---------------------------------------------------------------------------------------------------
// The check pipeline (contract §2, §3.1, §3.3): ONE function runs it, for check_redaction and the verify_redaction re-scan.
// ---------------------------------------------------------------------------------------------------

type CheckVerdictOut = z.infer<typeof checkVerdictOutputSchema>;
interface PipelineOk {
  ok: true;
  issued: Issued;
  /** The engine's verdict as validated (output form); `verdict` is what a client sees: reconciled with the issued outcome. */
  engineVerdict: CheckVerdictOut;
  verdict: CheckVerdictOut;
  res: any;
  scan: ScanReply;
  complete: boolean;
  evaluation: boolean;
}
interface PipelineFail {
  ok: false;
  text: string;
}

/**
 * C1: the file is read ONCE into `B` (its sha256 is the snapshot digest the check must carry, C3); both wasm legs receive `B`
 * (the native engine still receives the confined path tonight, F3). The scan runs, then the check; `passOutcome` (outcome.ts) is
 * the only issuer; `verdict` is the engine's verdict reconciled with it (`reconcileVerdict`). A row-0 case is a `PipelineFail`:
 * `isError: true`, text only.
 */
async function runCheckPipeline(confined: string, extraCaps: readonly Cap[] = []): Promise<PipelineOk | PipelineFail> {
  const B = readFileSync(confined);
  const snapshotSha256 = sha256Hex(B);
  const evaluation = !ENGINE_BIN;
  const engine = ENGINE_BIN ? ("native" as const) : ("wasm" as const);
  const res = await findViaEngineOrWasm(B, confined, undefined);
  if (!res?.ok) return { ok: false, text: `Audit failed: ${safeText(res?.error ?? "unknown error")}` };
  const parsed = parseScanReply(res, { engine });
  if (!parsed.ok) return { ok: false, text: `Audit failed: ${unusableReplyMessage("scan", parsed.reason)}` };
  const { verdict: engineVerdict, executionFailed } = await checkViaEngineOrWasm(B, confined);
  if (executionFailed) {
    return {
      ok: false,
      text:
        `⚠️ NOT A PASS — the verdict check could not run${parsed.value.total > 0 ? `; ${WHY.W1(parsed.value.total)}` : ""}.\n\n` +
        `The verdict check did not run, so this is not a clean result. Do not treat this file as checked.`,
    };
  }
  const leg = scanLegOf(parsed.value, engine);
  const issued = passOutcome({ check: checkLegOf(engineVerdict), scan: leg, snapshotSha256, caps: extraCaps });
  if (isFailure(issued)) return { ok: false, text: `Audit failed: ${unusableReplyMessage("check", issued.failure)}` };
  const complete = leg.topComplete === true && leg.covComplete === true;
  const verdict = reconcileVerdict(
    applyScanToVerdict(engineVerdict, { found: parsed.value.total, complete, survivors: parsed.value.survivors.length }),
    issued,
  );
  return { ok: true, issued, engineVerdict, verdict, res, scan: parsed.value, complete, evaluation };
}

/** §6.4: an off-page finding's source is shown as its category (the part before the first ":"), never the raw value. */
const sourceCategory = (source: unknown): string => {
  // errata G5: the engine's real sources (redaction-core detect.rs): `prior-revision` (:3688), `form-field` (:3803), `metadata:{key}` /
  // `metadata:XMP` (:3893, :3944), `attachment:{name}` (:4031), `annotation:page{N}` (:4198), `form-xobject:page{N}/{name}` (:4249).
  const head = typeof source === "string" ? source.split(":")[0]! : "";
  const map: Record<string, string> = { "prior-revision": "revision", "form-field": "form", "form-xobject": "form-xobject", annotation: "annotation", metadata: "metadata", attachment: "attachment" };
  return Object.prototype.hasOwnProperty.call(map, head) ? map[head]! : "other";
};

/** The text and structured result of a completed check pipeline (check_redaction, and the verify_redaction re-scan). */
function buildCheckResult(p: PipelineOk, pdfPath: string): { text: string; structured: z.infer<typeof checkRedactionOutputSchema> } {
  const { res, issued, verdict, complete, evaluation } = p;
  const regions = res.regions as any[];
  const survivors = res.survivors as any[];
  const offPage = res.off_page as any[];
  const cov = res.coverage as any;
  const total = res.total_findings as number;
  const clean = total === 0;
  const pass = issued.outcome === "safe_to_send";
  const incomplete = scanStatusLine(res);
  const lead = issued.lead + (incomplete ? `${incomplete}\n\n` : "") + (evaluation ? `${CHECK_NOTICE}\n\n` : "");

  // Honest coverage disclosure: what was inspected, and what was NOT, so a result is scoped. Contract §6.4: the engine's own
  // `not_scanned` lines never reach the text (they can carry filenames and font names); each shows as a fixed label.
  const scanned = [
    `${cov.pages_scanned ?? "?"}/${cov.pages_total ?? "?"} page text layer`,
    cov.prior_revisions_scanned && "prior (superseded) revisions",
    cov.metadata_scanned && "metadata",
    cov.acroform_scanned && "form fields",
    cov.attachments_scanned && "attachments",
    (cov.form_xobjects_scanned ?? 0) > 0 && `${cov.form_xobjects_scanned} Form XObject(s)`,
    (cov.annotation_appearances_scanned ?? 0) > 0 && `${cov.annotation_appearances_scanned} annotation appearance(s)`,
  ].filter(Boolean);
  const rawNotScanned = [...(cov.not_scanned ?? []), ...((cov.pages_failed ?? []).length ? [`${cov.pages_failed.length} page(s) that could not be parsed`] : [])];
  const labels = [...new Set([...((cov.not_scanned ?? []) as string[]).map(disclosureLabel), ...((cov.pages_failed ?? []).length ? [`${cov.pages_failed.length} page(s) that could not be parsed`] : [])])];
  const scope = `Scanned: ${scanned.join(", ")}.` + (labels.length ? `\nNOT inspected: ${labels.join("; ")}.` : "");
  const coverage = toOutputCoverage(cov, rawNotScanned);

  const byKind: Record<string, number> = {};
  for (const r of [...regions, ...survivors, ...offPage]) byKind[r.kind] = (byKind[r.kind] ?? 0) + 1;
  const structured = checked(checkRedactionOutputSchema, {
    scanComplete: complete,
    clean,
    totalFindings: total,
    byKind,
    regions: regions.map(toOutputRegion),
    survivors: survivors.map(toOutputRegion),
    offPage: offPage.map((f: any) => ({ source: f.source, kind: f.kind, preview: f.preview })),
    coverage,
    verdict,
    outcome: issued.outcome,
    ...(evaluation ? { evaluation: true as const } : {}),
  });
  if (clean) {
    const text =
      lead +
      (pass
        ? `✅ Safe to Send: the engine's check passed and the pattern scan read every page and found nothing in this file.\n\n`
        : `The pattern scan listed nothing in the part of this file that it read.\n\n`) +
      `${verdictHeading(verdict)}\n\n${scope}\n\n` +
      `This is a scoped result, not a completeness guarantee — the surfaces listed as NOT inspected, plus names/addresses (which need human or model review), are out of scope.`;
    return { text, structured };
  }
  const tally = Object.entries(byKind).map(([k, n]) => `${n} ${safeText(k)}${n > 1 ? "s" : ""}`).join(", ");
  const parts: string[] = [];
  if (regions.length) parts.push(`Text layer (${regions.length}):\n${JSON.stringify(textRegions(regions), null, 2)}`);
  if (survivors.length) parts.push(`Surviving UNDER a redaction mark (${survivors.length}):\n${JSON.stringify(textRegions(survivors), null, 2)}`);
  if (offPage.length) {
    parts.push(
      `Off-page — prior revisions / metadata / form fields / attachments (${offPage.length}):\n` +
        JSON.stringify(offPage.map((f: any) => textOffPage(f, sourceCategory)), null, 2),
    );
  }
  const text =
    lead +
    `⚠️ LEAK: this "redacted" PDF still contains ${total} sensitive item(s) (${tally}) — the redaction did not actually remove the data.\n\n` +
    `${verdictHeading(verdict)}\n\n${parts.join("\n\n")}\n\n${scope}\n\n` +
    `Previews are masked; the raw values stayed on-device. This check does not remove anything. Omitly can remove what was found if the user asks.`;
  return { text, structured };
}

/** Run "extract_text" via the native engine if configured, else the bundled
 *  wasm fallback (omitly#1169) — same posture as `findViaEngineOrWasm`:
 *  regional narrowing only applies natively, wasm always scans every
 *  pattern (more results, never fewer) rather than silently dropping the
 *  requested narrowing. */
function extractTextViaEngineOrWasm(
  confinedPath: string,
  regions: string[] | undefined,
  masked: boolean,
): Promise<any> | any {
  if (ENGINE_BIN) return runEngine({ command: "extract_text", pdfPath: confinedPath, regions, masked });
  const res = runWasmExtractText(readFileSync(confinedPath), masked);
  if (res.ok && regions && regions.length) {
    res.note = "Regional narrowing (regions filter) needs a native engine — showing all detected kinds.";
  }
  return res;
}

/**
 * Registers every tool (the redaction/check tools here, and the five free
 * page tools from `edit-tools.ts`, omitly#1841) on a given `McpServer` instance. Extracted from
 * module-level top code (#540) so tests can build an in-memory server +
 * client pair and drive the tools directly, without a child-process stdio
 * client. `index.ts`'s own module body stays a thin bin entry — see the
 * `isMainModule` guard at the bottom of this file.
 */
export function registerTools(server: McpServer, options: { opener?: FileOpener } = {}): void {
  // omitly#1643: the initialize `clientInfo` — who is proposing. Recorded in
  // the proposal file and the desktop's LOCAL run log only, never in a seal.
  const clientOf = (): ProposalClient => {
    const c = server.server.getClientVersion();
    return c ? { name: c.name, version: c.version } : { name: "unknown MCP client", version: "" };
  };

  /** omitly#1861: a removal request this server cannot run (no engine) and cannot queue (the app
   *  is closed, or accept-in-app is off). Nothing was written; the text says what to do next.
   *  `maybeQueue` has just read the heartbeat, so this second read can differ (the app may have
   *  become ready in between): the text depends on `accept_in_app` itself, case by case. */
  function removalUnavailable() {
    return {
      content: [{ type: "text" as const, text: removalUnavailableText(readDesktopPresence()) }],
      isError: true,
    };
  }

  // omitly#1857: the MCP Apps result card. A client that advertises the extension renders
  // `ui://omitly/result-card.html` for check_redaction, verify_seal and verify_document; any other
  // client ignores the link and shows the unchanged text. The card reads only the existing
  // structuredContent and the tool's input: nothing is added to an output schema.
  const cardHtml = loadResultCardHtml();
  const cardMeta = cardHtml ? { ui: { resourceUri: RESULT_CARD_URI } } : {};
  const cardPaths = new CardPathAllowlist();
  /** Remember a `pdfPath` this server returned a card-linked result for: the only paths
   *  `open_in_omitly` will open. */
  const rememberCard = (pdfPath: string): void => {
    if (cardHtml) cardPaths.remember(pdfPath);
  };
  if (cardHtml) {
    registerAppResource(
      server,
      "Omitly result card",
      RESULT_CARD_URI,
      {
        description: "Read-only card for an Omitly check or seal result.",
        _meta: { ui: { prefersBorder: false, csp: { connectDomains: [], resourceDomains: [] } } },
      },
      async (uri) => ({
        contents: [
          {
            uri: uri.href,
            mimeType: RESOURCE_MIME_TYPE,
            text: withVersion(cardHtml, VERSION),
            // No network and no external resource: the host's own CSP (connect-src 'none') is
            // what the page was built for, and nothing here widens it.
            _meta: { ui: { prefersBorder: false, csp: { connectDomains: [], resourceDomains: [] } } },
          },
        ],
      }),
    );
  }

  /** Queue a redaction write as a proposal when the desktop is present with
   *  accept-in-app on. Returns the tool result to send, or null to run the
   *  engine as before. Paths are already confined by the caller. */
  function maybeQueue(
    tool: ProposalTool,
    input: { pdfPath: string; outputPath: string; regions?: unknown; kinds?: string[]; analysisId?: string },
  ) {
    const presence = readDesktopPresence();
    if (!presence || !presence.accept_in_app) return null;
    // omitly#1870: the app says its trial is over, so it would refuse to accept this proposal.
    // Answer directly instead of stranding it. This only ever does LESS (no proposal is written);
    // it neither runs the engine nor unlocks anything.
    if (isTrialOver(presence)) {
      return { content: [{ type: "text" as const, text: removalTrialOverText() }], isError: true };
    }
    // omitly#1890: coordinates need the analysisId of the scan they came from (refused here if not);
    // a kinds-only proposal has none and is bound at queue time.
    const base = { client: clientOf(), tool, pdfPath: input.pdfPath, outputPath: input.outputPath };
    const { proposal, revision } = enqueueProposal(
      Array.isArray(input.regions)
        ? { ...base, regions: input.regions as any, analysisId: input.analysisId }
        : { ...base, ...(input.kinds ? { kinds: input.kinds } : {}) },
    );
    const structuredContent = checked(queuedProposalOutputSchema, {
      status: "queued",
      proposalId: proposal.id,
      revision,
      tool,
      client: proposal.client,
      pdfPath: proposal.pdfPath,
      note: queuedNote(tool),
    });
    return {
      structuredContent,
      content: [
        {
          type: "text" as const,
          text: queuedText(tool, proposal.id, proposal.pdfPath, presence.licence),
        },
      ],
    };
  }

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
    "engine): results carry a short notice that the scan removes nothing; there is no usage limit.",
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
    annotations: annotations("Find sensitive regions", true),
  },
  async ({ pdfPath, regions }) => {
    try {
      const confined = confineInput(pdfPath, ROOT);
      // omitly#1859: no cap, no counter. The free (wasm) tier carries a short notice.
      const evaluation = !ENGINE_BIN;
      const B = readFileSync(confined);
      const res = await findViaEngineOrWasm(B, confined, regions);
      if (!res?.ok) {
        return {
          content: [{ type: "text", text: `Scan failed: ${safeText(res?.error ?? "unknown error")}` }],
          isError: true,
        };
      }
      const engine = ENGINE_BIN ? ("native" as const) : ("wasm" as const);
      const parsed = parseScanReply(res, { narrowed: Boolean(ENGINE_BIN && Array.isArray(regions)), engine });
      if (!parsed.ok) return { content: [{ type: "text", text: `Scan failed: ${unusableReplyMessage("scan", parsed.reason)}` }], isError: true };
      const leg = scanLegOf(parsed.value, engine);
      const found = res.regions as any[];
      const completeness = scanCompleteness(res);
      const incomplete = scanStatusLine(res);
      // Contract §3.2: the outcome of a scan is capped (survivors: not_a_pass; findings: needs_review; an incomplete scan or a
      // disclosure that is not benign: incomplete) and ALWAYS at most `incomplete` (W12): a pattern scan is not a check.
      const caps: Cap[] = [];
      if (leg.survivors > 0) caps.push({ at: "not_a_pass", why: WHY.W2(leg.survivors) });
      if (leg.total > 0) caps.push({ at: "needs_review", why: WHY.W1(leg.total) });
      if (!completeness.complete) caps.push({ at: "incomplete", why: WHY.W3 });
      if (leg.notScanned.some((l) => !BENIGN_DISCLOSURES.includes(l)) || leg.pagesFailed > 0 || leg.embeddedStreamsFailed > 0 || leg.flagsSet) caps.push({ at: "incomplete", why: WHY.W5 });
      caps.push({ at: "incomplete", why: WHY.W12 });
      const issued = capped(null, caps);
      // omitly#1890: names this scan, so coordinates proposed later are tied to the bytes it read.
      const analysisId = recordAnalysisOf(confined, res.inputSha256);
      const summary =
        issued.lead +
        (incomplete ? `${incomplete}\n\n` : "") +
        (evaluation ? `${FIND_NOTICE}\n\n` : "") +
        `Found ${found.length} candidate region(s)${completeness.complete ? "" : " in the part of the document that could be read"}.\n` +
        `Pass any subset to redact_pdf as its "regions" argument (page + x/y/width/height carry over).\n` +
        (analysisId ? `analysisId: ${analysisId} (pass it with those regions to redact_pdf or propose_redactions).\n` : "") +
        `\n` +
        (res.note ? `Note: ${safeText(res.note)}\n\n` : "") +
        JSON.stringify(textRegions(found), null, 2);
      const structuredContent = checked(findSensitiveRegionsOutputSchema, {
        scanComplete: completeness.complete,
        count: found.length,
        regions: found.map(toOutputRegion),
        outcome: issued.outcome,
        ...(analysisId ? { analysisId } : {}),
        ...(res.note ? { note: res.note as string } : {}),
        ...(evaluation ? { evaluation: true as const } : {}),
      });
      return { content: [{ type: "text", text: summary }], structuredContent, isError: false };
    } catch (e) {
      return {
        content: [{ type: "text", text: `Could not scan: ${errText(e)}` }],
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
    annotations: annotations("Locate text", true, true),
  },
  async ({ pdfPath, texts }) => {
    try {
      const confined = confineInput(pdfPath, ROOT);
      let res: any;
      if (ENGINE_BIN) {
        res = await runEngine({ command: "locate_text", pdfPath: confined, texts });
      } else {
        // omitly#1890: the digest of the very buffer the wasm locate holds.
        const bytes = readFileSync(confined);
        res = runWasmLocate(bytes, texts);
        if (res.ok) res.inputSha256 = sha256Hex(bytes);
      }
      if (!res?.ok) {
        return {
          content: [{ type: "text", text: `Search failed: ${safeText(res?.error ?? "unknown error")}` }],
          isError: true,
        };
      }
      const parsedLocate = parseLocateReply(res);
      if (!parsedLocate.ok) {
        return {
          content: [{ type: "text", text: `Search failed: ${unusableReplyMessage("search", parsedLocate.reason)}` }],
          isError: true,
        };
      }
      const regions = parsedLocate.value.regions;
      const analysisId = recordAnalysisOf(confined, res.inputSha256);
      const summary =
        `Located ${regions.length} occurrence(s). Pass any subset to redact_pdf as "regions".\n` +
        (analysisId ? `analysisId: ${analysisId} (pass it with those regions to redact_pdf or propose_redactions).\n` : "") +
        `\n` +
        JSON.stringify(textRegions(regions), null, 2);
      const structuredContent = checked(locateTextOutputSchema, {
        count: regions.length,
        regions: regions.map(toOutputRegion),
        ...(analysisId ? { analysisId } : {}),
      });
      return { content: [{ type: "text", text: summary }], structuredContent };
    } catch (e) {
      return {
        content: [{ type: "text", text: `Could not search: ${errText(e)}` }],
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
    annotations: annotations("Redact PII by type", false),
  },
  async ({ pdfPath, outputPath, kinds, regions, drawBox }) => {
    let written: unknown; // set once the engine has written the output (errata G4)
    try {
      const queuedByEntity = maybeQueue("redact_by_entity", {
        pdfPath: confineInput(pdfPath, ROOT),
        outputPath: confineOutput(outputPath, ROOT),
        kinds,
      });
      if (queuedByEntity) return queuedByEntity;
      // omitly#1861: no engine and nothing to queue to: a designed answer, not the engine-config error.
      if (!ENGINE_BIN) return removalUnavailable();
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
          content: [{ type: "text", text: `Redaction failed: ${safeText(res?.error ?? "unknown error")}` }],
          isError: true,
        };
      }
      const redacted = res.redacted ?? [];
      if (redacted.length > 0) written = res.output; // errata G4: from here the output exists; any later failure says so
      if (redacted.length === 0) {
        const structuredContent = checked(redactByEntityDoneSchema, {
          status: "done",
          output: null,
          redactedCount: 0,
          redacted: [],
          engineAudit: null,
          // CONTRACT-QUESTION: §3.6 caps a completed redaction at needs_review (W11); here nothing was written or checked, so the
          // fail-safe `incomplete` (capped(null, []), W0) is issued rather than a pass-shaped or review-shaped value.
          outcome: capped(null, []).outcome,
        });
        return {
          content: [{ type: "text", text: `⚠️ NOT A PASS — ${WHY.W0}.\n\nNo matching entities found — nothing was written.` }],
          structuredContent,
        };
      }
      // omitly#1864: parse, don't trust: an audit that says pass beside a failing region, or a v2 Safe to Send
      // beside a verdict that is not a pass, is no redaction result (no "Verification: pass" is printed for it).
      const parsedAudit = parseRedactAudit(res.audit, { expected: redacted as { page: unknown }[] });
      if (!parsedAudit.ok) {
        return {
          content: [{ type: "text", text: writtenOutputText(res.output) }],
          isError: true,
        };
      }
      const issued = capped(null, auditCaps(parsedAudit.value.audit));
      const audit = toOutputAudit(res.audit);
      const redactedOut = redacted.map((r: any) => ({ page: r.page, kind: r.kind, preview: r.preview }));
      const structuredContent = checked(redactByEntityDoneSchema, {
          status: "done",
        output: res.output,
        redactedCount: redactedOut.length,
        redacted: redactedOut,
        engineAudit: audit,
        outcome: issued.outcome,
      });
      return {
        content: [
          {
            type: "text",
            text:
              issued.lead +
              `Redacted ${redacted.length} entit${redacted.length === 1 ? "y" : "ies"} → ${safeText(res.output)}\n` +
              redactRecordLine(parsedAudit.value.audit) +
              `\n` +
              `Removed:\n${JSON.stringify(textRegions(redacted), null, 2)}`,
          },
        ],
        structuredContent,
      };
    } catch (e) {
      return {
        content: [{ type: "text", text: written !== undefined ? writtenOutputText(written) : `Could not run redaction: ${errText(e)}` }],
        isError: true,
      };
    }
  },
);

server.registerTool(
  "redact_pdf",
  {
    description:
      "Redact regions of a PDF on-device using Omitly. Removes the " +
      "underlying text and image data (not a black box over it), checks the file " +
      "for copies of the removed text that editing software leaves behind, and " +
      "returns a signed audit log. The file is never " +
      "uploaded — redaction happens locally. A region's `reason` is your own audit " +
      "label (e.g. 'PII: SSN'); the words AI_PROPOSAL, MANUAL and OCR_CORRECTED are " +
      "reserved for what a person decided in the Omitly app, and a request using one " +
      "is refused whole, with nothing written.",
    inputSchema: {
      pdfPath: z.string().describe("absolute path to the source PDF"),
      outputPath: z.string().describe("absolute path to write the redacted PDF"),
      regions: regionsArg("regions to remove"),
      analysisId: ANALYSIS_ID_ARG,
    },
    outputSchema: redactPdfOutputSchema,
    annotations: annotations("Redact PDF regions", false),
  },
  async ({ pdfPath, outputPath, regions, analysisId }) => {
    let written: unknown; // set once the engine has written the output (errata G4)
    try {
      const queuedPdf = maybeQueue("redact_pdf", {
        pdfPath: confineInput(pdfPath, ROOT),
        outputPath: confineOutput(outputPath, ROOT),
        regions,
        analysisId,
      });
      if (queuedPdf) return queuedPdf;
      if (!ENGINE_BIN) return removalUnavailable();
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
          content: [{ type: "text", text: `Redaction failed: ${safeText(res?.error ?? "unknown error")}` }],
          isError: true,
        };
      }
      written = res.output; // errata G4: the engine has written the output; any later failure says so
      const parsedAudit = parseRedactAudit(res.audit, { expected: regions });
      if (!parsedAudit.ok) {
        return {
          content: [{ type: "text", text: writtenOutputText(res.output) }],
          isError: true,
        };
      }
      const issued = capped(null, auditCaps(parsedAudit.value.audit));
      const audit = toOutputAudit(res.audit);
      const structuredContent = checked(redactPdfDoneSchema, {
        status: "done",
        output: res.output,
        regionCount: regions.length,
        engineAudit: audit,
        outcome: issued.outcome,
      });
      return {
        structuredContent,
        content: [
          {
            type: "text",
            text:
              issued.lead +
              `Redacted ${regions.length} region(s) → ${safeText(res.output)}\n` +
              redactRecordLine(parsedAudit.value.audit),
          },
        ],
      };
    } catch (e) {
      return {
        content: [{ type: "text", text: written !== undefined ? writtenOutputText(written) : `Could not run redaction: ${errText(e)}` }],
        isError: true,
      };
    }
  },
);

server.registerTool(
  "verify_redaction",
  {
    description:
      "Re-scan an already-redacted PDF on-device and report whether anything " +
      "recoverable is still found. With a configured native engine and this file's own " +
      "`<path>.audit.json` sidecar (written by redact_pdf/redact_by_entity), this " +
      "re-checks exactly the regions that were redacted — the strongest form of " +
      "this check. Without a native engine (or without that sidecar — e.g. the " +
      "file wasn't redacted by this tool), it falls back to a general on-device " +
      "re-scan of the whole file and reports whether anything is still " +
      "detectable — a good-faith re-check, not a claim of the same rigor as the " +
      "sidecar-based path. This is a self-check for the person who just " +
      "redacted, typically the one holding the sidecar file — a third-party " +
      "recipient who only has the delivered PDF should use `verify_document` " +
      "instead, which checks the embedded audit report and seal rather than " +
      "re-scanning region bytes.",
    inputSchema: {
      pdfPath: z.string().describe("absolute path to the redacted PDF to verify"),
    },
    outputSchema: verifyRedactionOutputSchema,
    annotations: annotations("Verify redaction", true, true),
  },
  async ({ pdfPath }) => {
    try {
      const confined = confineInput(pdfPath, ROOT);
      if (ENGINE_BIN) {
        // #1563: the engine derives `<pdf>.audit.json` itself and follows
        // symlinks, so vet the sidecar here, before it runs. A link (or any
        // non-regular entry) is refused with no content; no entry at all falls
        // through to the re-scan below, as before.
        const sidecar = confineSidecar(confined, ROOT);
        if (sidecar) {
          let res: any;
          try {
            res = await runEngine({ command: "verify", pdfPath: confined });
          } catch (engineError) {
            // A rejection carries the engine's stderr or non-JSON stdout, which
            // can hold bytes it read through a swapped-in link. If the sidecar
            // changed, the refusal replaces the engine's text; if not, the
            // engine's own error propagates as before.
            assertSidecarUnchanged(sidecar);
            throw engineError;
          }
          // Withhold everything the engine returned if the sidecar was swapped
          // for something else while it ran.
          assertSidecarUnchanged(sidecar);
          if (!res?.ok) {
            return {
              content: [
                // v0.2.1 (errata 2): the engine's error can quote the sidecar (an unknown-variant message holds its text), so it is never printed.
                { type: "text", text: "Could not verify: the engine could not check this file's sidecar, so no result could be given. Do not treat this file as checked." },
              ],
              isError: true,
            };
          }
          // omitly#1864: the reply is read only through its strict parser. A "pass" needs its region and
          // hidden-content lists, every entry with a result, and none failing.
          const parsedVerify = parseSidecarVerifyReply(res);
          if (!parsedVerify.ok) {
            return {
              content: [{ type: "text", text: `Could not verify: ${unusableReplyMessage("verify", parsedVerify.reason)}` }],
              isError: true,
            };
          }
          // Contract §3.4: the sidecar is attacker-writable and is not evidence. The outcome comes from this server's own check of the
          // file (`runCheckPipeline`), lowered by the sidecar's caps (a failing region, a failing hidden-content class, unscrubbed
          // metadata, an engine warning). `verify` reads the original path and its sidecar, and its reply has no digest: it is exempt from C3.
          const reply = parsedVerify.value.reply;
          const p = await runCheckPipeline(confined, sidecarCaps(reply));
          if (!p.ok) return { content: [{ type: "text", text: p.text }], isError: true };
          rememberCard(pdfPath);
          const built = buildCheckResult(p, pdfPath);
          const failedRegions = ((reply.regions ?? []) as any[]).filter((r) => r.verification?.result === "fail");
          const failedHidden = ((reply.hiddenContent ?? []) as any[]).filter((c) => c.verification?.result === "fail");
          const findings: z.infer<typeof verifyFindingOutputSchema>[] = [
            ...scanFindings(p.res),
            ...failedRegions.map((r) => ({ page: r.page, reason: r.reason, detail: r.verification.detail })),
            ...failedHidden.map((c) => ({ class: c.class, detail: c.verification.detail })),
          ];
          const structuredContent = checked(verifyRedactionOutputSchema, {
            outcome: p.issued.outcome,
            mode: "sidecar",
            scanComplete: p.complete,
            clean: (p.res.total_findings as number) === 0,
            totalFindings: p.res.total_findings as number,
            findings,
            verdict: p.verdict,
            sidecar: {
              regions: (reply.regions as unknown[]).length,
              regionsFailed: failedRegions.length,
              hiddenContentFailed: failedHidden.length,
              metadataScrubbed: reply.metadataScrubbed,
              engineWarnings: (Array.isArray(reply.warnings) ? reply.warnings : []).filter((w) => typeof w !== "string" || !isProductNotice(w)).length,
              disclosures: Array.isArray((res as any).disclosures) ? (res as any).disclosures.length : 0,
            },
          });
          return {
            content: [{ type: "text", text: `${built.text}\n\n${sidecarNote((reply.regions as unknown[]).length)}` }],
            structuredContent,
            isError: false,
          };
        }
      }
      // Re-scan (no sidecar, or no native engine). Contract §3.3: it runs the same check pipeline as check_redaction, because a clean
      // scan does not make a file safe to send (an invisible-text file has a clean scan and a Needs Review check on both engines).
      const p = await runCheckPipeline(confined);
      if (!p.ok) return { content: [{ type: "text", text: p.text }], isError: true };
      rememberCard(pdfPath);
      const built = buildCheckResult(p, pdfPath);
      const structuredContent = checked(verifyRedactionOutputSchema, {
        outcome: p.issued.outcome,
        mode: "rescan",
        scanComplete: p.complete,
        clean: (p.res.total_findings as number) === 0,
        totalFindings: p.res.total_findings as number,
        findings: scanFindings(p.res),
        verdict: p.verdict,
      });
      return { content: [{ type: "text", text: built.text }], structuredContent, isError: false };
    } catch (e) {
      return {
        content: [{ type: "text", text: `Could not verify: ${errText(e)}` }],
        isError: true,
      };
    }
  },
);

server.registerTool(
  "check_license",
  {
    description:
      "Report Omitly's current licence or trial state on this machine — free, " +
      "takes no arguments, and reads no document. Use it to answer 'am I " +
      "licensed?', to see how many trial days are left, or to confirm a licence " +
      "the user just saved has been picked up. Re-resolved on EVERY call, so " +
      "buy → save the licence file → call again works without restarting this " +
      "server. Reports which resolution step supplied the licence " +
      "(OMITLY_LICENSE_FILE, the activated desktop licence, or the import " +
      "inbox ~/.omitly/omitly.license), the tier, the vendor-signed licensee " +
      "name, whether the licence is bound to this one machine, and whether " +
      "this build can make licensed-provenance claims at all. It deliberately " +
      "NEVER returns the device fingerprint (a stable machine identifier) or " +
      "the licence file's contents — 'device-bound' is reported as a yes/no. " +
      "Requires a configured native engine (OMITLY_ENGINE_DIR/OMITLY_REDACT_BIN): " +
      "the wasm free tier has no licence concept, so there is nothing to report " +
      "without one.",
    inputSchema: {},
    outputSchema: checkLicenseOutputSchema,
    annotations: annotations("Check licence state", false, true),
  },
  async () => {
    try {
      // omitly#1861: without an engine the server cannot read licence state (and must not guess it).
      if (!ENGINE_BIN) {
        return {
          content: [{ type: "text", text: `Could not read licence state: ${engineOnlyText("check_license")}` }],
          isError: true,
        };
      }
      const raw = await runEngine({ command: "check_license" });
      if (!raw?.ok) {
        return {
          content: [{ type: "text", text: `Could not read licence state: ${raw?.error ?? "unknown error"}` }],
          isError: true,
        };
      }
      const res = checked(checkLicenseOutputSchema, {
        state: raw.state,
        tier: raw.tier ?? null,
        daysLeft: raw.daysLeft ?? null,
        licensedTo: raw.licensedTo ?? null,
        expiresAt: raw.expiresAt ?? null,
        resolutionStep: raw.resolutionStep ?? null,
        deviceBound: raw.deviceBound === true,
        provenanceAvailable: raw.provenanceAvailable === true,
        renewalNotice: raw.renewalNotice ?? null,
        reason: raw.reason ?? null,
      });

      const summary =
        res.state === "licensed"
          ? `✅ Licensed — Omitly ${res.tier ?? "unknown tier"}` +
            (res.licensedTo ? `, licensed to ${res.licensedTo}` : "") +
            `${res.expiresAt ? `, until ${res.expiresAt.slice(0, 10)}` : ", perpetual"}` +
            `${res.deviceBound ? " (bound to this machine)" : ""}.` +
            `${res.resolutionStep ? ` Source: ${res.resolutionStep}.` : ""}`
          : res.state === "trial"
            ? `⏳ Free trial — ${res.daysLeft} day${res.daysLeft === 1 ? "" : "s"} left (the trial ends after ${TRIAL_TERMS}). ` +
              "Everything works; audit output is marked as evaluation until a licence is activated."
            : res.state === "trial_expired"
              ? `⛔ The free trial has ended (${TRIAL_TERMS}). Redaction needs a licence; verification stays free.`
              : res.state === "updates_lapsed"
              ? `⚠️ Pro updates ended before this build was released: ${res.reason ?? "redaction works, output is marked as evaluation; install an earlier version or renew updates for unmarked output"}`
              : `⚠️ A licence file was found but did not verify: ${res.reason ?? "no reason given"}`;

      // §1's renewal rule: surfaced, never silently adopted (omitly#86 owns adoption).
      const renewal = res.renewalNotice ? `\n\nℹ️ ${res.renewalNotice}` : "";
      // Invariant #12: a release build on the public dev key must say so rather
      // than let a "licensed" line read as a trustworthy provenance claim.
      const untrusted = res.provenanceAvailable
        ? ""
        : "\n\n⚠️ This build cannot make licensed-provenance claims (it carries the public " +
          "development key). Treat any licensed status here as informational only.";

      return {
        content: [{ type: "text", text: `${summary}${renewal}${untrusted}\n\n${JSON.stringify(res, null, 2)}` }],
        structuredContent: res,
      };
    } catch (e) {
      return {
        content: [{ type: "text", text: `Could not read licence state: ${errText(e)}` }],
        isError: true,
      };
    }
  },
);

registerAppTool(
  server,
  "verify_seal",
  {
    description:
      "Verify a PDF's embedded Omitly audit report and whole-file " +
      "tamper-evidence seal (v1: Ed25519; v2: ML-DSA-87 with ECDSA P-384) — on-device, nothing uploaded. Distinct from " +
      "`verify_redaction`: that tool re-checks whether redacted regions are " +
      "still empty; this tool cryptographically checks whether the delivered " +
      "bytes have changed since they were sealed. The seal proves INTEGRITY, " +
      "NOT IDENTITY: the signing key travels with the file (per-install, or " +
      "one-time for a single output), " +
      "so a valid seal means 'unchanged since sealed by the holder of this " +
      "key', never 'produced by Omitly'. Compare `sealFingerprint` " +
      "out-of-band against the fingerprint the sender published if origin " +
      "matters. " +
      "Requires a configured native engine — there is no wasm seal-verification " +
      "path, so this always needs OMITLY_ENGINE_DIR/OMITLY_REDACT_BIN. A " +
      "`seal_unsupported_version` verdict means this verifier is too old to " +
      "check the seal at all — that is neither a pass nor a fail; update the " +
      "verifier rather than trusting or rejecting the file on that basis. " +
      "`outcome` is the only verdict field and a seal tool never gives `safe_to_send`: a seal is integrity, not a check of the content (run `check_redaction`). isError false does not mean the file is safe. isError true means the check could not run.",
    inputSchema: {
      pdfPath: z.string().describe("absolute path to the PDF to check for an Omitly audit report and seal"),
    },
    outputSchema: verifySealOutputSchema,
    annotations: annotations("Verify seal", true, true),
    _meta: cardMeta,
  },
  async ({ pdfPath }) => {
    try {
      const result = await runSealVerification(pdfPath);
      if (!result.ok) {
        return {
          content: [{ type: "text", text: `Could not verify seal: ${result.errorText}` }],
          isError: true,
        };
      }
      const { res, issued, structuredContent } = result;
      rememberCard(pdfPath);
      // omitly#1857 + contract §3: a completed check is `isError: false`; the outcome (never a pass) and the lead say what it is.
      return { content: [{ type: "text", text: sealText(res, issued, "verify_seal") }], structuredContent, isError: false };
    } catch (e) {
      return {
        content: [{ type: "text", text: `Could not verify seal: ${errText(e)}` }],
        isError: true,
      };
    }
  },
);

registerAppTool(
  server,
  "verify_document",
  {
    description:
      "Reports whether a received PDF's embedded Omitly audit report and whole-file seal still verify " +
      "(v1: Ed25519; v2: ML-DSA-87 with ECDSA P-384) — on-device, needs the native engine, no licence required. " +
      "A seal shows integrity, not origin, and is not a check of the content: the signing key travels with the file, " +
      "so a valid seal means 'unchanged since sealed by the holder of this key', never 'produced by Omitly', and anyone can seal a file with " +
      "their own key. This tool never gives `safe_to_send`; for the content, run `check_redaction`. A `seal_unsupported_version` verdict " +
      "means this verifier is too old to check the seal at all; update the verifier rather than trusting or rejecting the file on that basis. " +
      "`outcome` is the only verdict field; isError false does not mean the file is safe. isError true means the check could not run.",
    inputSchema: {
      pdfPath: z.string().describe("absolute path to the PDF to check for an Omitly audit report and seal"),
    },
    outputSchema: verifySealOutputSchema,
    annotations: annotations("Verify document", true, true),
    _meta: cardMeta,
  },
  async ({ pdfPath }) => {
    try {
      const result = await runSealVerification(pdfPath);
      if (!result.ok) {
        return {
          content: [{ type: "text", text: `Could not verify document: ${result.errorText}` }],
          isError: true,
        };
      }
      const { res, issued, structuredContent } = result;
      rememberCard(pdfPath);
      // omitly#1857 + contract §3: a completed check is `isError: false`; the outcome (never a pass) and the lead say what it is.
      return { content: [{ type: "text", text: sealText(res, issued, "verify_document") }], structuredContent, isError: false };
    } catch (e) {
      return {
        content: [{ type: "text", text: `Could not verify document: ${errText(e)}` }],
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
    annotations: annotations("Create PDF", false),
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
          content: [{ type: "text", text: `PDF generation failed: ${safeText(res?.error ?? "unknown error")}` }],
          isError: true,
        };
      }
      const structuredContent = checked(createPdfOutputSchema, { output: res.output });
      return { content: [{ type: "text", text: `Created PDF → ${safeText(res.output)}` }], structuredContent };
    } catch (e) {
      return {
        content: [{ type: "text", text: `Could not generate PDF: ${errText(e)}` }],
        isError: true,
      };
    }
  },
);

registerAppTool(
  server,
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
      "completeness.) Free tier (no native engine): reports carry a short notice that the " +
      "check removes nothing and is not a removal certificate; there is no usage limit. " +
      "`scanComplete` is false when some page or stream could not be read; then `clean` " +
      "only means nothing was found in what WAS read (possibly nothing) and the text leads " +
      "with an INCOMPLETE SCAN warning. `clean` is a scan fact (the pattern scan listed nothing), not a verdict. " +
      "The result also carries `verdict`, the engine's presented-document check as 'needs_review' or 'cannot_verify' (or 'safe_to_send' only beside a pass), " +
      "which covers hidden, covered and recoverable content (text under boxes, metadata, layers, attachments, earlier versions, comments, alternate text). " +
      "`outcome` is the only verdict field. `safe_to_send` is given only when the engine's check passed, the scan read the whole file and found nothing, and the file's own seal or report played no part. " +
      "`needs_review`, `not_a_pass` and `incomplete` are not passes. isError false does not mean the file is safe; isError true means the check could not run. " +
      "The full audit v2 report behind the verdict is not returned here; it is available " +
      "from the engine's `check` command (`omitly-redact`) and the desktop app.",
    inputSchema: {
      pdfPath: z.string().describe("absolute path to the supposedly-redacted PDF to audit"),
    },
    outputSchema: checkRedactionOutputSchema,
    annotations: annotations("Check redaction for leaks", true),
    _meta: cardMeta,
  },
  async ({ pdfPath }) => {
    try {
      const confined = confineInput(pdfPath, ROOT);
      const p = await runCheckPipeline(confined);
      if (!p.ok) return { content: [{ type: "text", text: p.text }], isError: true };
      rememberCard(pdfPath);
      const { text, structured } = buildCheckResult(p, pdfPath);
      // omitly#1857 + contract §3: a COMPLETED check is not an error whatever it found; `structuredContent.outcome` carries the verdict.
      return { content: [{ type: "text", text }], structuredContent: structured, isError: false };
    } catch (e) {
      return {
        content: [{ type: "text", text: `Could not audit: ${errText(e)}` }],
        isError: true,
      };
    }
  },
);
server.registerTool(
  "extract_pdf_text",
  {
    description:
      "Extract a PDF's text, page by page, for reading or summarizing — PII-MASKED " +
      "BY DEFAULT, so detected emails, SSNs, phone/card numbers and Australian " +
      "identifiers (TFN/ABN/ACN/Medicare/CRN/IHI/BSB) never flood your context window " +
      "as raw values. Each page returns its (masked, unless you opt out) text plus " +
      "'spans': the CHAR offset (not byte offset — matters for any non-ASCII text) of " +
      "every detected PII value with its kind, so you can still reason about WHERE " +
      "something was found even though the value itself reads as a masked preview " +
      "(e.g. '•••-••-6789'). Pass 'masked: false' ONLY when you deliberately need the " +
      "raw text for genuine content review and understand the raw PII values will then " +
      "appear verbatim in this response and in your context — that is the explicit, " +
      "documented opt-in this tool requires; the default is always masked. A page " +
      "whose text could not be fully read (a corrupt or size-capped content stream, or " +
      "characters whose meaning the font does not define) reports " +
      "'contentDecoded: false' rather than being silently skipped or counted as blank; " +
      "any text that was read is still returned, so treat that page as incomplete, not " +
      "as the whole page. Does NOT render pages to images — text only. Free tier, no " +
      "licence required; works zero-install via the bundled wasm engine, same as " +
      "find_sensitive_regions/locate_text/check_redaction/verify_redaction — a " +
      "configured native engine (OMITLY_ENGINE_DIR) is preferred when available (also " +
      "enables the 'regions' filter, wasm-only ignores it and scans every pattern) but " +
      "not required. The file is never uploaded: extraction runs entirely on-device.",
    inputSchema: {
      pdfPath: z.string().describe("absolute path to the PDF to extract text from"),
      regions: z
        .array(REGIONS)
        .optional()
        .describe(
          "narrow which PII kinds are detected/masked to these regional packs (generic " +
            "kinds like email/card always apply regardless); omit to scan everything — " +
            "the safe default",
        ),
      masked: z
        .boolean()
        .optional()
        .describe(
          "false is an explicit opt-in to RAW (unmasked) text — the raw PII values will " +
            "then appear verbatim in this response. Omit, or pass true, for the default " +
            "masked behaviour.",
        ),
    },
    outputSchema: extractPdfTextOutputSchema,
    annotations: annotations("Extract PDF text", true, true),
  },
  async ({ pdfPath, regions, masked }) => {
    try {
      const confined = confineInput(pdfPath, ROOT);
      const wantMasked = masked ?? true;
      const res = await extractTextViaEngineOrWasm(confined, regions, wantMasked);
      if (!res?.ok) {
        return {
          content: [{ type: "text", text: `Extraction failed: ${safeText(res?.error ?? "unknown error")}` }],
          isError: true,
        };
      }
      const pages = res.pages ?? [];
      const totalSpans = pages.reduce(
        (n: number, p: any) => n + (Array.isArray(p.spans) ? p.spans.length : 0),
        0,
      );
      const summary =
        `Extracted ${pages.length} page(s).\n` +
        (wantMasked
          ? `${totalSpans} PII span(s) masked — pass masked:false for raw text (raw PII ` +
            `values will then appear in this response).\n\n`
          : `⚠️ RAW TEXT requested (masked:false) — ${totalSpans} PII span(s) are flagged ` +
            `in "spans" but "text" itself is UNMASKED.\n\n`) +
        (res.note ? `Note: ${safeText(res.note)}\n\n` : "") +
        JSON.stringify(pages, null, 2);
      const structuredContent = checked(extractPdfTextOutputSchema, {
        masked: wantMasked,
        ...(res.note ? { note: res.note as string } : {}),
        pages: pages.map(toOutputExtractedPage),
      });
      return { content: [{ type: "text", text: summary }], structuredContent };
    } catch (e) {
      return {
        content: [{ type: "text", text: `Could not extract text: ${errText(e)}` }],
        isError: true,
      };
    }
  },
);

server.registerTool(
  "propose_redactions",
  {
    description:
      "Propose regions to redact for a PERSON to accept in the Omitly desktop app " +
      "(omitly#1643, bring your own AI). The explicit, preferred form for agents " +
      "working alongside a lawyer: nothing is written by this call. The desktop " +
      "app shows the proposal, the person accepts or rejects, and on acceptance " +
      "Omitly removes the content, checks the file for copies left behind and seals the output " +
      "with a record that a person decided. Requires the Omitly desktop app to be " +
      "running on this computer; use get_proposal_status to follow the outcome. " +
      "Same inputs as redact_pdf (a region `reason` may not be AI_PROPOSAL, MANUAL or " +
      "OCR_CORRECTED: those words are reserved for what a person decides, and the request is " +
      "refused). The regions must come from a scan of this document: pass the " +
      "analysisId that find_sensitive_regions or locate_text returned with them. Nothing is uploaded.",
    inputSchema: {
      pdfPath: z.string().describe("absolute path to the source PDF"),
      outputPath: z.string().describe("your suggested path for the redacted PDF; the person picks the real one in Omitly's save dialog"),
      regions: regionsArg("regions proposed for removal"),
      analysisId: ANALYSIS_ID_ARG,
    },
    outputSchema: queuedProposalOutputSchema,
    annotations: annotations("Propose redactions", false),
  },
  async ({ pdfPath, outputPath, regions, analysisId }) => {
    try {
      const presence = readDesktopPresence();
      if (!presence || !presence.accept_in_app || isTrialOver(presence)) {
        return {
          content: [{ type: "text", text: proposeUnavailableText(presence, Boolean(ENGINE_BIN)) }],
          isError: true,
        };
      }
      const { proposal, revision } = enqueueProposal({
        client: clientOf(),
        tool: "redact_pdf",
        pdfPath: confineInput(pdfPath, ROOT),
        outputPath: confineOutput(outputPath, ROOT),
        regions,
        analysisId,
      });
      const structuredContent = checked(queuedProposalOutputSchema, {
        status: "queued",
        proposalId: proposal.id,
        revision,
        tool: "redact_pdf",
        client: proposal.client,
        pdfPath: proposal.pdfPath,
        note: "Queued for a person to accept in the Omitly desktop app. Nothing has been written.",
      });
      return {
        structuredContent,
        content: [
          {
            type: "text",
            text:
              `Proposal ${proposal.id} queued in Omitly (${regions.length} region(s) on ${safeText(proposal.pdfPath)}). ` +
              `Nothing has been written until a person accepts it. Follow it with get_proposal_status.` +
              trialClause(presence.licence),
          },
        ],
      };
    } catch (e) {
      return {
        content: [{ type: "text", text: `Could not queue the proposal: ${errText(e)}` }],
        isError: true,
      };
    }
  },
);

server.registerTool(
  "get_proposal_status",
  {
    description:
      "Report what happened to a proposal queued by propose_redactions (or by " +
      "redact_pdf / redact_by_entity while accept-in-app was on): pending, " +
      "accepted, rejected, applied (removed and sealed by the desktop " +
      "app, with the output path and verdict), failed, or expired. Free; reads " +
      "no document.",
    inputSchema: {
      proposalId: z.string().describe("the proposalId returned when the proposal was queued"),
    },
    outputSchema: proposalStatusOutputSchema,
    annotations: annotations("Get proposal status", true, true),
  },
  async ({ proposalId }) => {
    try {
    // omitly#1890: a decided proposal is answered from the desktop's outcome file, never from the
    // AI-writable proposal file (which a rewrite can turn back to `pending`), and never as `pending`.
    const outcome = readOutcome(proposalId);
    if (outcome) {
      const v = outcomeView(outcome, readMailboxFacts(proposalId));
      const structuredContent = checked(proposalStatusOutputSchema, {
        proposalId: outcome.id,
        status: v.status,
        tool: v.tool,
        createdAt: v.createdAt,
        resolvedAt: v.resolvedAt,
        output: v.output,
        recordedByDesktop: v.verdict, // contract §3.7: what the desktop recorded, attributed; never a verdict of this server
        note: v.note,
        decidedRevision: v.decidedRevision,
        ...(v.unverified ? { unverified: true as const } : {}),
      });
      // Contract §3.7 and the v0.2.3 class rule: every file- or desktop-derived string (the output path, the person's note, a legacy record's
      // claims) goes through `safeText`, no verdict word is printed (the desktop's record is a labelled attribution, never "Result:"), and the
      // text starts with the lead of a non-pass. The structured fields keep the raw values. A legacy outcome has its own wording and never
      // says sealed, a verdict, or that a person accepted it.
      const note = v.note ? ` ${safeText(v.note)}` : "";
      const decidedLine = v.unverified
        ? // R3-1: the status is from a fixed set, the time only if it is an ISO timestamp, the output path only as a JSON-escaped quotation and
          // only if short; the structured fields carry the rest.
          `Old record, unverified: it says ${v.status}${v.output && v.output.length <= 300 ? `, output ${safeText(JSON.stringify(v.output))}` : ""}${v.resolvedAt && /^\d{4}-\d\d-\d\dT[\d:.]+(Z|[+-]\d\d:\d\d)$/.test(v.resolvedAt) ? `, recorded ${v.resolvedAt}` : ""}.${note}`.trim()
        : v.status === "applied"
          ? `Applied: a person accepted it in Omitly; redacted and sealed → ${v.output !== null ? safeText(v.output) : "(output path not recorded)"}. The desktop app recorded: ${proposalRecordLabel(v.verdict)}. Run check_redaction on the output for this server's own result.${note}`
          : `${v.status[0]!.toUpperCase()}${v.status.slice(1)}${v.note ? `:${note}` : "."}`;
      return { structuredContent, content: [{ type: "text", text: `${capped(null, []).lead}Proposal ${idText(outcome.id)} — ${decidedLine}` }] };
    }
    const p = readProposal(proposalId);
    if (!p) {
      return {
        content: [{ type: "text", text: "No proposal with that id (ids are 24 hex characters; resolved proposals are swept after a day, pending ones expire after seven)." }],
        isError: true,
      };
    }
    const structuredContent = checked(proposalStatusOutputSchema, {
      proposalId: p.id,
      status: p.status,
      tool: p.tool,
      createdAt: p.created_at,
      resolvedAt: p.resolved_at ?? null,
      output: p.output ?? null,
      recordedByDesktop: p.verdict ?? null,
      note: p.note ?? null,
      decidedRevision: readMailboxFacts(p.id)?.decidedRevision ?? null,
    });
    const line =
      p.status === "applied"
        ? `Applied: a person accepted it in Omitly; the output is at ${p.output !== undefined && p.output !== null ? safeText(p.output) : "(output path not recorded)"}. The desktop app recorded: ${proposalRecordLabel(p.verdict)}. Run check_redaction on the output for this server's own result.`
        : p.status === "pending"
          ? pendingText(p.tool)
          : `${p.status[0].toUpperCase()}${p.status.slice(1)}${p.note ? " (see `note`)." : "."}`;
    // errata C5: no outcome of its own, so it is always a non-pass text: it starts with the lead of `capped(null, [])` (W0).
    return { structuredContent, content: [{ type: "text", text: `${capped(null, []).lead}Proposal ${idText(p.id)} — ${line}` }] };
    } catch (e) {
      return {
        content: [{ type: "text", text: `Could not read the proposal: ${errText(e)}` }],
        isError: true,
      };
    }
  },
);

  // omitly#1857: the card's "Open in Omitly" action. APP-ONLY (`visibility: ["app"]`): the model
  // never sees it, and a client that does not advertise MCP Apps neither lists nor can call it.
  // It opens ONLY a pdfPath this connection already returned a card-linked result for, and
  // re-confines that path first. See open-in-omitly.ts.
  if (cardHtml) {
    const opener = options.opener ?? systemOpener();
    // The extension key alone is not enough: the client must say it renders the MCP Apps MIME type.
    const uiCapable = (): boolean => {
      const mimeTypes = getUiCapability(server.server.getClientCapabilities())?.mimeTypes;
      return Array.isArray(mimeTypes) && mimeTypes.includes(RESOURCE_MIME_TYPE);
    };
    const openTool = registerAppTool(
      server,
      "open_in_omitly",
      {
        title: "Open in Omitly",
        description:
          "App-only action behind the Omitly result card: opens a PDF the card was just shown for in the " +
          "Omitly desktop app (macOS). Opens a window and writes nothing.",
        inputSchema: { pdfPath: z.string().describe("the same pdfPath the card was shown for") },
        outputSchema: openInOmitlyOutputSchema,
        annotations: annotations("Open in Omitly", false, true),
        _meta: { ui: { visibility: ["app"] } },
      },
      async ({ pdfPath }) => {
        // Belt and braces: a disabled tool is already refused by the SDK.
        if (!uiCapable()) {
          return {
            content: [{ type: "text" as const, text: "open_in_omitly is only available to MCP Apps views." }],
            isError: true,
          };
        }
        logOpen(pdfPath);
        if (!cardPaths.has(pdfPath)) {
          return {
            content: [
              { type: "text" as const, text: "That file was not checked in this session, so it cannot be opened from here." },
            ],
            isError: true,
          };
        }
        let confined: string;
        try {
          confined = confineInput(pdfPath, ROOT);
        } catch {
          return { content: [{ type: "text" as const, text: "That file is no longer available." }], isError: true };
        }
        if (!opener.supported) {
          return {
            content: [{ type: "text" as const, text: "Opening Omitly from here is not supported on this platform yet." }],
            structuredContent: checked(openInOmitlyOutputSchema, { status: "unsupported" }),
          };
        }
        try {
          await opener.open(confined);
        } catch {
          return {
            content: [{ type: "text" as const, text: "Could not open Omitly. Is the Omitly desktop app installed?" }],
            isError: true,
          };
        }
        return {
          content: [{ type: "text" as const, text: "Opened in Omitly." }],
          structuredContent: checked(openInOmitlyOutputSchema, { status: "opened" }),
        };
      },
    );
    // Listed and callable only once the client has said it renders MCP Apps (its `initialize`
    // capabilities carry the `io.modelcontextprotocol/ui` extension). Off until then.
    openTool.disable();
    const prevInitialized = server.server.oninitialized;
    server.server.oninitialized = () => {
      prevInitialized?.();
      // Only a change is announced (`tools/list_changed`); a client without MCP Apps hears nothing.
      if (uiCapable() && !openTool.enabled) openTool.enable();
      else if (!uiCapable() && openTool.enabled) openTool.disable();
    };
  }

  // omitly#1841: five free page tools. Their own module: no desktop queue, no licence,
  // no usage meter (decisions 2C and 3B). The ROOT is passed so they share this
  // server's confinement exactly.
  registerEditTools(server, { root: ROOT });
} // end registerTools

/** Create a fresh `McpServer` with every tool registered — used by both the
 *  bin entry below and tests. */
export function createServer(options: { opener?: FileOpener } = {}): McpServer {
  const server = new McpServer({ name: "omitly-mcp", version: VERSION });
  registerTools(server, options);
  // omitly#1641: the shipped skill/SKILL.md, offered as a prompt so MCP
  // clients other than Claude Code (Desktop, Cursor, …) can find it.
  registerSkillPrompt(server);
  // omitly#1642: tell the desktop app which client is connected (Connect your
  // AI → "Connected clients"). Written on initialize and refreshed on a timer;
  // cleared on close. Best effort — never affects a tool call.
  const heartbeat = startClientHeartbeat(() => {
    const c = server.server.getClientVersion();
    return c ? { name: c.name, version: c.version } : undefined;
  });
  const prevInit = server.server.oninitialized;
  server.server.oninitialized = () => {
    prevInit?.();
    heartbeat.tick();
  };
  const prevClose = server.server.onclose;
  server.server.onclose = () => {
    heartbeat.stop();
    prevClose?.();
  };
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
