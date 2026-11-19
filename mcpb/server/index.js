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
const { CHECK_NOTICE, FIND_NOTICE } = require("./usage.js");
const { createHash } = require("node:crypto");
const { applyScanToVerdict, reconcileVerdict, safeText, textRegions, textOffPage, engineLine } = require("./verdict.js");
const { parseScanReply, parseLocateReply, parseCheckVerdict, scanLegOf, checkLegOf, disclosureLabel, unusableReplyMessage, incompleteLine } = require("./replies.js");
const { passOutcome, capped, isFailure, WHY, BENIGN_DISCLOSURES } = require("./outcome.js");

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
    scan_complete: r.scan_complete,
    coverage: r.coverage,
  };
}

function runWasmScan(bytes) {
  if (!wasmEngine) {
    return { ok: false, error: "bundled wasm detector not available — reinstall the extension" };
  }
  return wasmScanToFindShape(wasmEngine.scan(new Uint8Array(bytes)));
}

/** omitly#1267: the Safe to Send verdict from the bundled wasm's `check` —
 *  the same presented check the desktop "Check any PDF" and the full
 *  server's `check_redaction` run. A wasm build without `check`, or any
 *  failure, is Cannot Verify (`check_unavailable`), never a pass. */
function runWasmCheck(bytes) {
  const unavailable = { verdict: "cannot_verify", blocking: false, result: null, report: null, reason_code: "check_unavailable" };
  if (!wasmEngine || typeof wasmEngine.check !== "function") return unavailable;
  try {
    const v = JSON.parse(wasmEngine.check(new Uint8Array(bytes)));
    // omitly#1864: the engine's FULL pass contract (replies.js `parseCheckVerdict`), not the verdict word
    // alone: a bare `safe_to_send`, or a Safe to Send wrapped around a blocking result or one that lists
    // problems, is a reply that contradicts itself, so it is no verdict.
    return parseCheckVerdict(v).ok ? v : unavailable;
  } catch {
    return unavailable;
  }
}

/** The verdict as text: the heading, the check's own summary, and the
 *  sections as the engine wrote them (fixed lines, never document text). */
function verdictLabel(v) {
  return v.verdict === "safe_to_send"
    ? "Safe to Send"
    : v.verdict === "needs_review"
      ? v.blocking
        ? "Needs Review — problems found"
        : "Needs Review"
      : "Cannot Verify";
}

function verdictText(engineVerdict, facts, reconciled) {
  // omitly#1864: a verdict printed beside findings, or beside a scan that did not read the file, is
  // never Safe to Send: `reconciled` is the engine's verdict after the scan facts AND the issued outcome (contract §7.1).
  const v = reconciled || applyScanToVerdict(engineVerdict, facts);
  const label = verdictLabel(v);
  const r = v.result || {};
  const lines = (title, items) =>
    Array.isArray(items) && items.length
      ? `  ${title}:\n` +
        items.map((i) => `    - ${engineLine(i.text)}${i.pages ? ` (pages ${i.pages.join(", ")})` : ""}`).join("\n") +
        "\n"
      : "";
  return (
    `Check verdict: ${label}.` +
    (r.summary ? ` ${engineLine(r.summary)}` : "") +
    ` (A verdict about this check, limited to what it covered: hidden, covered and recoverable ` +
    `content, and the sensitive-looking text the pattern scan lists. It is not a ` +
    `statement that the document is safe.)\n` +
    lines("Checked", r.checked) +
    lines("Problems", r.problems) +
    lines("Review", r.review) +
    lines("Could not be checked", v.verdict === "cannot_verify" ? r.reasons : r.notChecked) +
    lines("Information", r.information)
  );
}

function runWasmLocate(bytes, needles) {
  if (!wasmEngine) {
    return { ok: false, error: "bundled wasm detector not available — reinstall the extension" };
  }
  const raw = JSON.parse(wasmEngine.locate(new Uint8Array(bytes), JSON.stringify(needles)));
  if (!raw.ok) return { ok: false, error: raw.error || "wasm locate failed" };
  return { ok: true, count: raw.count, regions: raw.leaks };
}


// ---------------------------------------------------------------------------------------------------
// The check pipeline (docs/pass-contract.md §2, §3.1, §3.3): ONE function for check_redaction and the verify_redaction re-scan.
// ---------------------------------------------------------------------------------------------------

/** C1: the file is read ONCE into `bytes`; both wasm legs receive it, and its sha256 is the digest the check must carry (C3). */
function runCheckPipeline(bytes) {
  const snapshotSha256 = createHash("sha256").update(bytes).digest("hex");
  const res = runWasmScan(bytes);
  if (!res.ok) return { ok: false, text: `Audit failed: ${safeText(res.error || "unknown error")}` };
  const parsed = parseScanReply(res, { engine: "wasm" });
  if (!parsed.ok) return { ok: false, text: `Audit failed: ${unusableReplyMessage("scan", parsed.reason)}` };
  const engineVerdict = runWasmCheck(bytes);
  if (engineVerdict.reason_code === "check_unavailable") {
    return {
      ok: false,
      text:
        `⚠️ NOT A PASS — the verdict check could not run${parsed.value.total > 0 ? `; ${WHY.W1(parsed.value.total)}` : ""}.\n\n` +
        `The verdict check did not run, so this is not a clean result. Do not treat this file as checked.`,
    };
  }
  const leg = scanLegOf(parsed.value, "wasm");
  const issued = passOutcome({ check: checkLegOf(engineVerdict), scan: leg, snapshotSha256 });
  if (isFailure(issued)) return { ok: false, text: `Audit failed: ${unusableReplyMessage("check", issued.failure)}` };
  const complete = leg.topComplete === true && leg.covComplete === true;
  const facts = { found: parsed.value.total, complete, survivors: parsed.value.survivors.length };
  const verdict = reconcileVerdict(applyScanToVerdict(engineVerdict, facts), issued);
  return { ok: true, issued, engineVerdict, verdict, res, parsed, complete, facts };
}

/** Contract §6.4: an off-page finding's source is shown as its category, never the raw value. */
const sourceCategory = (source) => {
  // errata G5 (src/index.ts `sourceCategory`): the engine's real sources, by their prefix before ":".
  const head = typeof source === "string" ? source.split(":")[0] : "";
  const map = { "prior-revision": "revision", "form-field": "form", "form-xobject": "form-xobject", annotation: "annotation", metadata: "metadata", attachment: "attachment" };
  return Object.prototype.hasOwnProperty.call(map, head) ? map[head] : "other";
};

/** The text of a completed check pipeline (check_redaction and the re-scan). */
function renderCheck(p, pdfPath) {
  const { res, issued, verdict, complete } = p;
  const regions = res.regions || [];
  const survivors = res.survivors || [];
  const offPage = res.off_page || [];
  const cov = res.coverage || {};
  const total = res.total_findings;
  const clean = total === 0;
  const pass = issued.outcome === "safe_to_send";
  const scanned = [
    `${cov.pages_scanned !== undefined ? cov.pages_scanned : "?"}/${cov.pages_total !== undefined ? cov.pages_total : "?"} page text layer`,
    cov.prior_revisions_scanned && "prior (superseded) revisions",
    cov.metadata_scanned && "metadata",
    cov.acroform_scanned && "form fields",
    cov.attachments_scanned && "attachments",
    (cov.form_xobjects_scanned || 0) > 0 && `${cov.form_xobjects_scanned} Form XObject(s)`,
    (cov.annotation_appearances_scanned || 0) > 0 && `${cov.annotation_appearances_scanned} annotation appearance(s)`,
  ].filter(Boolean);
  // §6.4: the engine's not_scanned lines never reach the text; each shows as a fixed label.
  const labels = [...new Set([...(cov.not_scanned || []).map(disclosureLabel), ...((cov.pages_failed || []).length ? [`${cov.pages_failed.length} page(s) that could not be parsed`] : [])])];
  const panel =
    `What this checks / does not check:\n` +
    `  Scanned: ${scanned.join(", ") || "(coverage unavailable)"}\n` +
    (labels.length ? `  Not scanned: ${labels.join(", ")}\n` : "") +
    `  Pattern-based detection — names, addresses, and image-only text are not covered. A scan that lists nothing means "nothing this scan can see", not "nothing is left".\n`;
  const headline = clean
    ? pass
      ? `✅ Safe to Send: the engine's check passed and the pattern scan read every page and found nothing.`
      : `The pattern scan listed nothing in the part of this file that it read.`
    : `⚠️ Found ${total} recoverable item(s) still in the file.`;
  return (
    issued.lead +
    `${CHECK_NOTICE}\n\n` +
    `${headline}\n\n${verdictText(p.engineVerdict, p.facts, verdict)}\n${panel}\n` +
    (survivors.length ? `Survivors (under redaction marks): ${JSON.stringify(textRegions(survivors), null, 2)}\n\n` : "") +
    (offPage.length ? `Off-page findings: ${JSON.stringify(offPage.map((f) => textOffPage(f, sourceCategory)), null, 2)}\n\n` : "") +
    (regions.length ? `Regions:\n${JSON.stringify(textRegions(regions), null, 2)}\n\n` : "") +
    `Diagnosis only — this free tool does not redact and does not issue a certificate. Omitly can remove what was found if the user asks.`
  );
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
    "results carry a short notice that the scan removes nothing; there is no usage limit.",
  {
    pdfPath: z.string().describe("absolute path to the PDF to scan"),
  },
  { title: "Find sensitive regions", readOnlyHint: true, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  async ({ pdfPath }) => {
    try {
      const bytes = readConfinedInput(pdfPath, ROOT);
      const res = runWasmScan(bytes);
      if (!res.ok) {
        return { content: [{ type: "text", text: `Scan failed: ${safeText(res.error || "unknown error")}` }], isError: true };
      }
      const parsed = parseScanReply(res, { engine: "wasm" });
      if (!parsed.ok) {
        return { content: [{ type: "text", text: `Scan failed: ${unusableReplyMessage("scan", parsed.reason)}` }], isError: true };
      }
      const found = parsed.value.regions;
      const leg = scanLegOf(parsed.value, "wasm");
      const complete = leg.topComplete === true && leg.covComplete === true;
      // Contract §3.2: capped scan facts, and ALWAYS at most `incomplete` (W12): a pattern scan is not a check of the document.
      const caps = [];
      if (leg.survivors > 0) caps.push({ at: "not_a_pass", why: WHY.W2(leg.survivors) });
      if (leg.total > 0) caps.push({ at: "needs_review", why: WHY.W1(leg.total) });
      if (!complete) caps.push({ at: "incomplete", why: WHY.W3 });
      if (leg.notScanned.some((l) => !BENIGN_DISCLOSURES.includes(l)) || leg.pagesFailed > 0 || leg.embeddedStreamsFailed > 0 || leg.flagsSet) caps.push({ at: "incomplete", why: WHY.W5 });
      caps.push({ at: "incomplete", why: WHY.W12 });
      const issued = capped(null, caps);
      const summary =
        issued.lead +
        incompleteLine(parsed.value.scanComplete) +
        `${FIND_NOTICE}\n\n` +
        `Found ${found.length} candidate region(s). Diagnosis only — this free ` +
        `tool does not redact. Omitly can remove what was found if the user asks.\n\n` +
        JSON.stringify(textRegions(found), null, 2);
      return { content: [{ type: "text", text: summary }], structuredContent: { outcome: issued.outcome }, isError: false };
    } catch (e) {
      return { content: [{ type: "text", text: `Could not scan: ${safeText(e.message)}` }], isError: true };
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
  { title: "Locate text", readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  async ({ pdfPath, texts }) => {
    try {
      const res = runWasmLocate(readConfinedInput(pdfPath, ROOT), texts);
      if (!res.ok) {
        return { content: [{ type: "text", text: `Search failed: ${safeText(res.error || "unknown error")}` }], isError: true };
      }
      const parsedLocate = parseLocateReply(res);
      if (!parsedLocate.ok) {
        return { content: [{ type: "text", text: `Search failed: ${unusableReplyMessage("search", parsedLocate.reason)}` }], isError: true };
      }
      const regions = parsedLocate.value.regions;
      const summary = `Located ${regions.length} occurrence(s). Diagnosis only — this free tool does not redact.\n\n${JSON.stringify(textRegions(regions), null, 2)}`;
      return { content: [{ type: "text", text: summary }] };
    } catch (e) {
      return { content: [{ type: "text", text: `Could not search: ${safeText(e.message)}` }], isError: true };
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
  { title: "Verify redaction", readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  async ({ pdfPath }) => {
    try {
      // Contract §3.3: the re-scan runs the same check pipeline as check_redaction, because a clean scan does not make a file safe to send.
      const p = runCheckPipeline(readConfinedInput(pdfPath, ROOT));
      if (!p.ok) return { content: [{ type: "text", text: p.text }], isError: true };
      return { content: [{ type: "text", text: renderCheck(p) }], structuredContent: { outcome: p.issued.outcome }, isError: false };
    } catch (e) {
      return { content: [{ type: "text", text: `Could not verify: ${safeText(e.message)}` }], isError: true };
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
    "absence of hits isn't proof of completeness.) Free tier: reports carry " +
    "a short notice that the check removes nothing and is not a removal certificate; " +
    "there is no usage limit. `outcome` is the only verdict field. `safe_to_send` is given only when the engine's check passed, " +
    "the scan read the whole file and found nothing, and the file's own seal or report played no part. `needs_review`, `not_a_pass` and " +
    "`incomplete` are not passes. A finished check is a result, not a tool failure: isError is false even when it found a leak, so " +
    "isError false does not mean the file is safe: read the first line and `outcome` in the structured result. isError true means the check could not run.",
  {
    pdfPath: z.string().describe("absolute path to the supposedly-redacted PDF to audit"),
  },
  { title: "Check redaction for leaks", readOnlyHint: true, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  async ({ pdfPath }) => {
    try {
      const p = runCheckPipeline(readConfinedInput(pdfPath, ROOT));
      if (!p.ok) return { content: [{ type: "text", text: p.text }], isError: true };
      // omitly#1857/#1864 + contract §3: a COMPLETED check is not an error, whatever it found: the text opens with NOT A PASS and
      // `structuredContent.outcome` carries the verdict. A row-0 case (the check did not run, a contradiction, a digest mismatch) is `isError: true`, text only.
      return { content: [{ type: "text", text: renderCheck(p, pdfPath) }], structuredContent: { outcome: p.issued.outcome }, isError: false };
    } catch (e) {
      return { content: [{ type: "text", text: `Could not audit: ${safeText(e.message)}` }], isError: true };
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
