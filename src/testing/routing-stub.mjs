#!/usr/bin/env node
/**
 * Native-engine stand-in used ONLY by `routing.test.ts` (omitly#193) to prove
 * which engine — native or the bundled wasm fallback — a given tool call
 * actually reached.
 *
 * Unlike `testing/fake-engine.mjs` (which tries to emulate real detection so
 * the leak-canary suite can prove masking end-to-end on realistic content),
 * this stub does NOT read or interpret the input document at all: every
 * "find"/"locate_text" response is a fixed, distinctive marker
 * (kind "native-stub-marker", preview "•NATIVE•") that could never be
 * mistaken for the bundled wasm engine's real detection output. That is
 * deliberate — it turns "did routing pick native or wasm?" into a content
 * comparison a test can assert on directly (feed BOTH engines the exact same
 * real-PII fixture and see which answer comes back), rather than something
 * that has to be inferred from module internals.
 *
 * Every invocation is also appended as one JSON line to the file named by
 * OMITLY_ROUTING_STUB_LOG (if set) — `{command, ts}` — so a test can
 * additionally assert exactly which commands reached the native engine and
 * how many times, independent of the response content.
 */
import { appendFileSync, writeFileSync } from "node:fs";

function log(command) {
  const logPath = process.env.OMITLY_ROUTING_STUB_LOG;
  if (!logPath) return;
  appendFileSync(logPath, JSON.stringify({ command, ts: Date.now() }) + "\n");
}

function markerRegion() {
  return { page: 0, x: 1, y: 2, width: 3, height: 4, kind: "native-stub-marker", preview: "•NATIVE•" };
}

function markerAuditEntries() {
  return [
    {
      page: 0,
      bbox: { x: 1, y: 2, width: 3, height: 4 },
      timestamp: new Date(0).toISOString(),
      reason_code: "NATIVE-STUB",
      verification: { result: "pass" },
    },
  ];
}

function handle(req) {
  log(req.command);
  switch (req.command) {
    case "find":
      return { ok: true, count: 1, regions: [markerRegion()] };
    case "locate_text":
      return { ok: true, count: 1, regions: [markerRegion()] };
    case "redact": {
      writeFileSync(req.outputPath, "NATIVE-STUB-REDACTED-OUTPUT");
      const auditEntries = markerAuditEntries();
      writeFileSync(`${req.outputPath}.audit.json`, JSON.stringify(auditEntries));
      return {
        ok: true,
        output: req.outputPath,
        audit: {
          verdict: "pass",
          regions: auditEntries,
          warnings: [],
          metadataScrubbed: true,
          license: "licensed",
          licensedTo: null,
          disclosures: [],
        },
      };
    }
    case "redact_entities": {
      writeFileSync(req.outputPath, "NATIVE-STUB-REDACTED-OUTPUT");
      const auditEntries = markerAuditEntries();
      writeFileSync(`${req.outputPath}.audit.json`, JSON.stringify(auditEntries));
      return {
        ok: true,
        output: req.outputPath,
        redacted: [{ page: 0, kind: "native-stub-marker", preview: "•NATIVE•" }],
        audit: {
          verdict: "pass",
          regions: auditEntries,
          warnings: [],
          metadataScrubbed: true,
          license: "licensed",
          licensedTo: null,
          disclosures: [],
        },
      };
    }
    case "verify":
      // A fixed, always-clean verdict — sufficient to prove THIS command (the
      // sidecar-present native path) was the one reached, distinct from
      // "find" (native's no-sidecar fallback) and from a wasm rescan.
      return { ok: true, verdict: "pass", regions: [], hiddenContent: [] };
    case "create":
      writeFileSync(req.outputPath, "NATIVE-STUB-CREATED-PDF");
      return { ok: true, output: req.outputPath };
    case "extract_text":
      // omitly#114: distinct marker text (never the wasm/real detector's
      // output) plus a matching span, so a test can tell native routing from
      // "no wasm fallback exists so this would otherwise be unreachable".
      return {
        ok: true,
        masked: req.masked !== false,
        pages: [
          {
            page: 0,
            contentDecoded: true,
            text: "NATIVE-STUB-EXTRACTED-TEXT",
            spans: [{ kind: "native-stub-marker", start: 0, end: 11 }],
          },
        ],
      };
    default:
      return { ok: false, error: `routing-stub: unhandled command ${req.command}` };
  }
}

let raw = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (d) => (raw += d));
process.stdin.on("end", () => {
  try {
    const req = JSON.parse(raw);
    process.stdout.write(JSON.stringify(handle(req)));
  } catch (e) {
    process.stdout.write(JSON.stringify({ ok: false, error: String(e && e.message ? e.message : e) }));
  }
});
