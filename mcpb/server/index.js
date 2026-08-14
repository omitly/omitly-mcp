#!/usr/bin/env node
/**
 * Omitly Redaction Leak Check — MCPB bundle server (free tier, diagnosis only).
 *
 * This is a DELIBERATELY SEPARATE, smaller server from ../../src/index.ts (the
 * full omitly-mcp package). It exists so the one-click Claude Desktop install
 * (the .mcpb produced by `npm run mcpb:pack`) exposes ONLY the four read-only
 * diagnosis tools that already work with zero native toolchain — never the
 * write tools (redact_pdf / redact_by_entity / create_pdf), which need a
 * separately-installed native engine binary and are Pro/licensed. See
 * omitly#225.
 *
 * Detection runs on the same wasm-bindgen detector the full server falls back
 * to (crates/leakcheck-wasm) and the web leak-checker at omitly.app use.
 * The wasm bundle ships prebuilt in the parent omitly-mcp package and is copied into
 * ../wasm; `npm run mcpb:pack` copies that build into ./wasm here before
 * packing, so the shipped .mcpb is fully self-contained — the end user's
 * machine needs no Rust/wasm-pack/native toolchain at all, only Node
 * (already bundled inside Claude Desktop).
 *
 * Nothing is uploaded: every tool takes a local file path, reads it on-device,
 * and returns text. No document bytes ever leave the process.
 */
"use strict";

const { readFileSync } = require("node:fs");
const path = require("node:path");
const { McpServer } = require("@modelcontextprotocol/sdk/server/mcp.js");
const { StdioServerTransport } = require("@modelcontextprotocol/sdk/server/stdio.js");
const { z } = require("zod");
const { allowedRoot, readConfinedInput } = require("./paths.js");
const { evaluationBanner, freeCapRefusal, recordFreeCheck } = require("./usage.js");

/** Free-tier metering gate (omitly#226) for the two DETECTION tools only —
 *  this bundle is always the free wasm tier, so unlike the full server there
 *  is no native-engine bypass to consider. `verify_redaction` and
 *  `locate_text` are deliberately never metered. Returns the refusal result
 *  when capped, otherwise the metering outcome for the EVALUATION banner. */
function freeTierGate(tool) {
  const meter = recordFreeCheck();
  if (meter.capped) {
    return {
      refusal: {
        content: [{ type: "text", text: JSON.stringify(freeCapRefusal(tool, meter), null, 2) }],
        isError: true,
      },
      meter,
    };
  }
  return { meter };
}

const VERSION = JSON.parse(readFileSync(path.join(__dirname, "..", "manifest.json"), "utf8")).version;

let wasmEngine;
try {
  // Copied in by `npm run mcpb:pack` from ../wasm (shipped prebuilt in
  // the parent omitly-mcp package) — see wasm/README in this directory. Not
  // present in the source tree itself (gitignored, same as the parent
  // package's own wasm/ — no committed binaries, see CLAUDE.md invariant #5).
  wasmEngine = require("../wasm/leakcheck_wasm.js");
} catch (e) {
  wasmEngine = undefined;
  // Fails loudly per tool call below rather than silently no-op-ing.
  console.error("[omitly-leak-check] bundled wasm detector failed to load:", e && e.message);
}

const ROOT = allowedRoot();

function wasmScanToFindShape(raw) {
  const r = JSON.parse(raw);
  if (!r.ok) return { ok: false, error: r.error || "wasm scan failed" };
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

function runWasmScan(bytes) {
  if (!wasmEngine) {
    return { ok: false, error: "bundled wasm detector not available — reinstall the extension" };
  }
  return wasmScanToFindShape(wasmEngine.scan(new Uint8Array(bytes)));
}

function runWasmLocate(bytes, needles) {
  if (!wasmEngine) {
    return { ok: false, error: "bundled wasm detector not available — reinstall the extension" };
  }
  const raw = JSON.parse(wasmEngine.locate(new Uint8Array(bytes), JSON.stringify(needles)));
  if (!raw.ok) return { ok: false, error: raw.error || "wasm locate failed" };
  return { ok: true, count: raw.count, regions: raw.leaks };
}

const server = new McpServer({ name: "omitly-leak-check", version: VERSION });

server.tool(
  "find_sensitive_regions",
  "Scan a PDF on-device and return candidate regions that look like PII — " +
    "emails, US SSNs, phone numbers, card numbers, and Australian identifiers " +
    "(TFN, ABN, ACN, Medicare, Centrelink CRN, IHI, BSB) — each with the page " +
    "and coordinates (in PDF points). Diagnosis only: this tool never redacts " +
    "anything. Candidates are best-effort pattern matches for review — not a " +
    "completeness guarantee and not a compliance assessment. The file is never " +
    "uploaded — detection runs locally. Each candidate carries a MASKED preview " +
    "(e.g. '•••-••-6789'), never the raw value. Free tier: results are " +
    "EVALUATION-marked and limited to a monthly number of free checks, counted " +
    "locally — past the cap this tool returns a structured 'free-cap' refusal.",
  {
    pdfPath: z.string().describe("absolute path to the PDF to scan"),
  },
  async ({ pdfPath }) => {
    try {
      const bytes = readConfinedInput(pdfPath, ROOT);
      const { refusal, meter } = freeTierGate("find_sensitive_regions");
      if (refusal) return refusal;
      const res = runWasmScan(bytes);
      if (!res.ok) {
        return { content: [{ type: "text", text: `Scan failed: ${res.error || "unknown error"}` }], isError: true };
      }
      const found = res.regions || [];
      const summary =
        `${evaluationBanner(meter)}\n\n` +
        `Found ${found.length} candidate region(s). Diagnosis only — this free ` +
        `tool does not redact. Removing the data for real, with a verified audit ` +
        `trail, is the licensed Omitly desktop app (https://omitly.app).\n\n` +
        JSON.stringify(found, null, 2);
      return { content: [{ type: "text", text: summary }] };
    } catch (e) {
      return { content: [{ type: "text", text: `Could not scan: ${e.message}` }], isError: true };
    }
  },
);

server.tool(
  "locate_text",
  "Locate exact text strings in a PDF on-device and return each occurrence's " +
    "page and coordinates (in PDF points). Use this for what pattern-matching " +
    "can't catch — names, addresses, account references — by supplying the " +
    "literal strings yourself. Diagnosis only: this tool never redacts anything. " +
    "Case-insensitive; a string the PDF splits across text operators may not " +
    "match as one run. Each hit returns a masked preview, not the raw text. " +
    "Nothing is uploaded.",
  {
    pdfPath: z.string().describe("absolute path to the PDF to search"),
    texts: z.array(z.string()).min(1).describe("literal strings to locate"),
  },
  async ({ pdfPath, texts }) => {
    try {
      const res = runWasmLocate(readConfinedInput(pdfPath, ROOT), texts);
      if (!res.ok) {
        return { content: [{ type: "text", text: `Search failed: ${res.error || "unknown error"}` }], isError: true };
      }
      const regions = res.regions || [];
      const summary = `Located ${regions.length} occurrence(s). Diagnosis only — this free tool does not redact.\n\n${JSON.stringify(regions, null, 2)}`;
      return { content: [{ type: "text", text: summary }] };
    } catch (e) {
      return { content: [{ type: "text", text: `Could not search: ${e.message}` }], isError: true };
    }
  },
);

server.tool(
  "verify_redaction",
  "Re-scan an already-redacted PDF on-device and report whether anything " +
    "recoverable remains. This bundle has no native engine or redaction " +
    "sidecar, so it always runs a general re-scan of the whole file (not the " +
    "sidecar-scoped re-check the full omitly-mcp/desktop app can do) — a " +
    "good-faith re-check, not a certificate. Works offline; nothing is uploaded.",
  {
    pdfPath: z.string().describe("absolute path to the redacted PDF to verify"),
  },
  async ({ pdfPath }) => {
    try {
      const res = runWasmScan(readConfinedInput(pdfPath, ROOT));
      if (!res.ok) {
        return { content: [{ type: "text", text: `Could not verify: ${res.error || "unknown error"}` }], isError: true };
      }
      const total = res.total_findings !== undefined ? res.total_findings : (res.regions || []).length;
      const clean = res.clean !== undefined ? res.clean : total === 0;
      const summary = clean
        ? `✅ No recoverable PII found on the surfaces scanned (general re-scan — no redaction sidecar to check specific regions against).`
        : `⚠️ Found ${total} recoverable item(s) — this file is not clean.\n\n${JSON.stringify(res, null, 2)}`;
      return { content: [{ type: "text", text: summary }], isError: !clean };
    } catch (e) {
      return { content: [{ type: "text", text: `Could not verify: ${e.message}` }], isError: true };
    }
  },
);

server.tool(
  "check_redaction",
  "Audit an ALREADY-redacted PDF on-device and report whether sensitive text " +
    "still survives underneath the redaction — the 'did my black boxes " +
    "actually remove the data?' check. Most tools redact by drawing a " +
    "rectangle over text while leaving the characters in the file, where they " +
    "stay selectable and extractable. This re-extracts the text on-device and " +
    "flags any emails, SSNs, phone or card numbers still present, each with a " +
    "MASKED preview — the raw value never leaves the machine. It checks the " +
    "page text layer, text surviving UNDER redaction marks, incremental-update " +
    "prior revisions (the classic 'redacted then saved, original still in the " +
    "file' failure), document metadata, AcroForm field values and embedded " +
    "attachments, and returns a coverage report so a clean result is scoped to " +
    "what was inspected. A non-empty result means the redaction leaked. " +
    "Diagnosis only — this tool never redacts anything and never issues a " +
    "certificate. Nothing is uploaded. (Pattern-based: names/addresses, " +
    "image-only text, and the surfaces listed as not-inspected aren't covered; " +
    "absence of hits isn't proof of completeness.) Free tier: reports are " +
    "EVALUATION-marked — for evaluation, not production reliance — and limited " +
    "to a monthly number of free checks, counted locally; past the cap this " +
    "tool returns a structured 'free-cap' refusal.",
  {
    pdfPath: z.string().describe("absolute path to the supposedly-redacted PDF to audit"),
  },
  async ({ pdfPath }) => {
    try {
      const bytes = readConfinedInput(pdfPath, ROOT);
      const { refusal, meter } = freeTierGate("check_redaction");
      if (refusal) return refusal;
      const res = runWasmScan(bytes);
      if (!res.ok) {
        return { content: [{ type: "text", text: `Audit failed: ${res.error || "unknown error"}` }], isError: true };
      }
      const regions = res.regions || [];
      const survivors = res.survivors || [];
      const offPage = res.off_page || [];
      const cov = res.coverage || {};
      const total = res.total_findings !== undefined ? res.total_findings : regions.length;
      const clean = res.clean !== undefined ? res.clean : total === 0;

      const scanned = [
        `${cov.pages_scanned !== undefined ? cov.pages_scanned : "?"}/${cov.pages_total !== undefined ? cov.pages_total : "?"} page text layer`,
        cov.prior_revisions_scanned && "prior (superseded) revisions",
        cov.metadata_scanned && "metadata",
        cov.acroform_scanned && "form fields",
        cov.attachments_scanned && "attachments",
        (cov.form_xobjects_scanned || 0) > 0 && `${cov.form_xobjects_scanned} Form XObject(s)`,
        (cov.annotation_appearances_scanned || 0) > 0 &&
          `${cov.annotation_appearances_scanned} annotation appearance(s)`,
      ].filter(Boolean);
      const notScanned = [
        ...(cov.not_scanned || []),
        ...(((cov.pages_failed || []).length ? [`${cov.pages_failed.length} page(s) that could not be parsed`] : [])),
      ];

      const panel =
        `What this checks / does not check:\n` +
        `  Scanned: ${scanned.join(", ") || "(coverage unavailable)"}\n` +
        (notScanned.length ? `  Not scanned: ${notScanned.join(", ")}\n` : "") +
        `  Pattern-based detection — names, addresses, and image-only text are ` +
        `not covered. A clean result means "nothing this scan can see", not ` +
        `"nothing is left".\n`;

      const verdict = clean
        ? `✅ No recoverable PII found in this audit's scope.`
        : `⚠️ Found ${total} recoverable item(s) still in the file.`;

      const summary =
        `${evaluationBanner(meter)}\n\n` +
        `${verdict}\n\n${panel}\n` +
        (survivors.length ? `Survivors (under redaction marks): ${JSON.stringify(survivors, null, 2)}\n\n` : "") +
        (offPage.length ? `Off-page findings (metadata/attachments/etc.): ${JSON.stringify(offPage, null, 2)}\n\n` : "") +
        (regions.length ? `Regions:\n${JSON.stringify(regions, null, 2)}\n\n` : "") +
        `Diagnosis only — this free tool does not redact and does not issue a ` +
        `certificate. To remove the data for real, with an offline-verifiable, ` +
        `tamper-evident audit trail, use the licensed Omitly desktop app ` +
        `(https://omitly.app).`;

      return { content: [{ type: "text", text: summary }], isError: !clean };
    } catch (e) {
      return { content: [{ type: "text", text: `Could not audit: ${e.message}` }], isError: true };
    }
  },
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  console.error("[omitly-leak-check] fatal:", err);
  process.exit(1);
});
