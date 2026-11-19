#!/usr/bin/env node
/**
 * omitly#1864: captures the REAL engines' replies into `goldens/native.json` and `goldens/wasm.json`, the
 * oracle `real-engine-goldens.test.ts` parses with the strict parsers. A fake written beside the parser
 * cannot show the parser is right; these are what the built `omitly-redact` and the built wasm
 * (`npm run build:wasm`) actually send for the repository's test PDFs.
 *
 *   cargo build -p omitly-cli && (cd omitly-mcp && npm run build:wasm) && node omitly-mcp/src/testing/capture-goldens.mjs
 *
 * `goldens/redact-entities-output.pdf` is the real redaction output (needs qpdf to REGENERATE; the tests only read it).
 * Only repository test files are read. A `redact_entities` run (for the v2 sealed output and the sidecar
 * `verify`) uses a throwaway OMITLY_DATA_DIR, so no real licence or trial state is touched. The check
 * reply's `report` (the audit v2 report) is elided: the server never reads it.
 */
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(HERE, "..", "..", "..");
const ENGINE = process.env.OMITLY_TEST_REDACT_BIN ?? path.join(ROOT, "target", "debug", "omitly-redact");
const wasm = createRequire(import.meta.url)(path.join(HERE, "..", "..", "wasm", "leakcheck_wasm.js"));
const tmp = mkdtempSync(path.join(tmpdir(), "omitly-goldens-"));
const env = { ...process.env, OMITLY_DATA_DIR: path.join(tmp, "data") };
mkdirSync(env.OMITLY_DATA_DIR, { recursive: true });

const run = (req) => {
  const r = spawnSync(ENGINE, [], { input: JSON.stringify(req), env, encoding: "utf8", maxBuffer: 1 << 26 });
  if (r.status !== 0) throw new Error(`engine ${req.command}: ${r.stderr}`);
  return JSON.parse(r.stdout);
};
const rel = (p) => path.relative(ROOT, p);
const abs = (p) => path.join(ROOT, p);
const stripReport = (reply) => {
  if (reply?.check) delete reply.check.report;
  if (reply?.report) delete reply.report;
  return reply;
};

const SCAN_PDFS = [
  "tests/fixtures/sample.pdf",
  "tests/fixtures/clean-text.pdf", // the positive control that reaches Safe to Send (contract T17)
  "tests/fixtures/covered-text.pdf",
  "tests/fixtures/invisible-text.pdf",
  "tests/fixtures/encrypted-aes256-survivor.pdf",
  "tests/fixtures/au-corpus/05-scanned-raster.pdf",
  "tests/fixtures/au-corpus/07-incremental-update-prior-revision.pdf",
  "tests/fixtures/au-corpus/08-acroform-fields.pdf",
  "scripts/fixtures/leakcheck/form-xobject-under-box.pdf",
];
const SEAL_PDFS = [
  "docs/test-vectors/positive/clean-sealed.pdf",
  "docs/test-vectors/positive/seal-at-boundary.pdf",
  "docs/test-vectors/compat/v3.2.0.pdf",
  "docs/test-vectors/compat/v5.3.0.pdf",
  "docs/test-vectors/negative/stripped-seal.pdf",
  "docs/test-vectors/negative/tampered-content.pdf",
  "docs/test-vectors/negative/forged-signature.pdf",
  "docs/test-vectors/negative/corrupt-audit-json.pdf",
  "tests/fixtures/sample.pdf",
];

const native = { engine: "omitly-redact (cargo build -p omitly-cli)", find: [], check: [], locate_text: [], verify_seal: [], verify: [], redact_entities: [], redact: [] };
for (const f of SCAN_PDFS) {
  native.find.push({ pdf: f, reply: run({ command: "find", pdfPath: abs(f) }) });
  native.check.push({ pdf: f, reply: stripReport(run({ command: "check", pdfPath: abs(f) })) });
}
// A region narrowing lists fewer kinds than it counts (main.rs `do_find`).
native.find.push({ pdf: "tests/fixtures/sample.pdf", regions: ["au"], reply: run({ command: "find", pdfPath: abs("tests/fixtures/sample.pdf"), regions: ["au"] }) });
// `regions: []` is a narrowing to the generic kinds only (main.rs `allowed_kinds`: `Some([])`), not "no narrowing".
native.find.push({ pdf: "tests/fixtures/sample.pdf", regions: [], reply: run({ command: "find", pdfPath: abs("tests/fixtures/sample.pdf"), regions: [] }) });
native.locate_text.push({ pdf: "tests/fixtures/sample.pdf", texts: ["Statement"], reply: run({ command: "locate_text", pdfPath: abs("tests/fixtures/sample.pdf"), texts: ["Statement"] }) });
for (const f of SEAL_PDFS) native.verify_seal.push({ pdf: f, reply: run({ command: "verify_seal", pdfPath: abs(f) }) });

// A real redaction (throwaway trial state): the v2 sealed output, and the sidecar `verify` over it.
const out = path.join(tmp, "sample.out.pdf");
const redacted = run({ command: "redact_entities", pdfPath: abs("tests/fixtures/sample.pdf"), outputPath: out });
// Paths of the throwaway run and the audit report (never read by the server) are elided.
const sanitise = (r) => {
  delete r.report;
  if (r.output) r.output = "<output>";
  if (r.auditLogPath) r.auditLogPath = "<output>.audit.json";
  return r;
};
native.redact_entities.push({ pdf: "tests/fixtures/sample.pdf", reply: sanitise(redacted) });
// The redaction's own OUTPUT, kept as a binary golden (a real sealed v2 file): tests that need "a file the engine redacted" read this instead of
// running `redact_entities`, which needs the qpdf sidecar a plain Node image does not have (the CI `npm-packages` job).
copyFileSync(out, path.join(HERE, "goldens", "redact-entities-output.pdf"));
// A region over one line only: the engine's own audit says review_required (verdict "fail"): a real non-pass redaction.
native.redact.push({
  pdf: "tests/fixtures/sample.pdf",
  regions: [{ page: 0, x: 200, y: 600, width: 100, height: 20 }],
  reply: sanitise(run({ command: "redact", pdfPath: abs("tests/fixtures/sample.pdf"), outputPath: path.join(tmp, "sample.region.pdf"), regions: [{ page: 0, x: 200, y: 600, width: 100, height: 20 }] })),
});
// The redaction's own OUTPUT through the pipeline legs (contract T16/T17b): it carries the engine's own bound report.
const OUT_NAME = "(redact_entities output of tests/fixtures/sample.pdf)";
native.find.push({ pdf: OUT_NAME, reply: run({ command: "find", pdfPath: out }) });
native.check.push({ pdf: OUT_NAME, reply: stripReport(run({ command: "check", pdfPath: out })) });
native.verify_seal.push({ pdf: "(redact_entities output of tests/fixtures/sample.pdf)", reply: run({ command: "verify_seal", pdfPath: out }) });
native.verify.push({ pdf: "(redact_entities output of tests/fixtures/sample.pdf)", reply: run({ command: "verify", pdfPath: out }) });
// The same sidecar beside the UNREDACTED file: every recorded region still holds text, so `verify` fails.
const unredacted = path.join(tmp, "unredacted.pdf");
copyFileSync(abs("tests/fixtures/sample.pdf"), unredacted);
copyFileSync(`${out}.audit.json`, `${unredacted}.audit.json`);
native.verify.push({ pdf: "(tests/fixtures/sample.pdf with the sidecar of its redaction)", reply: run({ command: "verify", pdfPath: unredacted }) });

// A file over the free check's 64 MiB limit (check.rs FREE_CHECK_MAX_BYTES) that still has text under a box: covered-text.pdf with
// a 66 MiB unreferenced stream. The check refuses it unread (`input_too_large`); the scan still reads it and lists the survivor.
const { PDFDocument } = createRequire(import.meta.url)(path.join(HERE, "..", "..", "node_modules", "pdf-lib"));
const bigDoc = await PDFDocument.load(readFileSync(abs("tests/fixtures/covered-text.pdf")));
bigDoc.context.register(bigDoc.context.stream(Buffer.alloc(66 * 1024 * 1024, 0x41)));
const bigPath = path.join(tmp, "covered-big.pdf");
writeFileSync(bigPath, await bigDoc.save({ useObjectStreams: false }));
const BIG = "(generated: tests/fixtures/covered-text.pdf plus a 66 MiB unreferenced stream)";
native.find.push({ pdf: BIG, reply: run({ command: "find", pdfPath: bigPath }) });
native.check.push({ pdf: BIG, reply: stripReport(run({ command: "check", pdfPath: bigPath })) });

const w = { engine: "leakcheck-wasm (npm run build:wasm)", scan: [], check: [], locate: [] };
{
  const bytes = new Uint8Array(readFileSync(out));
  w.scan.push({ pdf: OUT_NAME, reply: JSON.parse(wasm.scan(bytes)) });
  w.check.push({ pdf: OUT_NAME, reply: stripReport(JSON.parse(wasm.check(bytes))) });
}
for (const f of SCAN_PDFS) {
  const bytes = new Uint8Array(readFileSync(abs(f)));
  w.scan.push({ pdf: f, reply: JSON.parse(wasm.scan(bytes)) });
  w.check.push({ pdf: f, reply: stripReport(JSON.parse(wasm.check(bytes))) });
}
{
  const bytes = new Uint8Array(readFileSync(bigPath));
  w.scan.push({ pdf: BIG, reply: JSON.parse(wasm.scan(bytes)) });
  w.check.push({ pdf: BIG, reply: stripReport(JSON.parse(wasm.check(bytes))) });
}
w.locate.push({ pdf: "tests/fixtures/sample.pdf", needles: ["Statement"], reply: JSON.parse(wasm.locate(new Uint8Array(readFileSync(abs("tests/fixtures/sample.pdf"))), JSON.stringify(["Statement"]))) });

const dir = path.join(HERE, "goldens");
mkdirSync(dir, { recursive: true });
writeFileSync(path.join(dir, "native.json"), JSON.stringify(native, null, 1) + "\n");
writeFileSync(path.join(dir, "wasm.json"), JSON.stringify(w, null, 1) + "\n");
console.log(`wrote ${rel(path.join(dir, "native.json"))} and ${rel(path.join(dir, "wasm.json"))}`);
