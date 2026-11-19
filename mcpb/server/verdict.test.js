/**
 * omitly#1864: the MCPB bundle's check_redaction never prints a finding beside Safe to Send.
 * Run by `node --test mcpb/server/*.test.js`. Two parts: the pure rule over every verdict x finds
 * combination, and the real bundle server (spawned over stdio, bundled wasm detector) over a PDF
 * built here with pdf-lib holding made-up values. The wasm is copied from ../wasm (built by
 * `npm run build:wasm`) into mcpb/wasm for the run when it is not already there, as `mcpb:prep` does.
 */
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { cpSync, existsSync, mkdtempSync, realpathSync, rmSync, writeFileSync } = require("node:fs");
const { tmpdir } = require("node:os");
const path = require("node:path");
const { applyScanToVerdict, scanFactsOfReply, VISIBLE_SENSITIVE_SUMMARY, VISIBLE_TEXT_INFO_PREFIX, INCOMPLETE_SUMMARY, NOT_READ_LINE, UNDER_MARK_SUMMARY } = require("./verdict.js");

const EMBEDDED =
  "This file carries an Omitly report (omitly-audit.json) sealed with key ab:cd:12:34. The report records: Safe to Send. A seal shows the file is unchanged since it was sealed, not who sealed it, so check that key is the sender's before relying on the report.";
const result = (state, blocking, word = "Safe to Send") => ({
  state,
  blocking,
  summary: "Fixed summary.",
  checked: [{ text: "Metadata" }],
  notChecked: [],
  problems: blocking ? [{ text: "Text under a box on page 1" }] : [],
  review: [],
  information: [
    { text: "Sensitive-looking text is visible on page 1 (1 value).", pages: [1] },
    { text: "The file has document properties." },
    { text: EMBEDDED.replace("Safe to Send", word) },
  ],
  decisions: [],
  reasons: [],
});
const verdicts = (word) => [
  { verdict: "safe_to_send", blocking: false, result: result("safe_to_send", false, word), reason_code: null },
  { verdict: "needs_review", blocking: false, result: result("needs_review", false, word), reason_code: null },
  { verdict: "needs_review", blocking: true, result: result("needs_review", true, word), reason_code: null },
  { verdict: "cannot_verify", blocking: false, result: null, reason_code: "check_unavailable" },
];

test("every verdict x found x complete: Safe to Send survives only with nothing found and a complete scan", () => {
  for (const v of verdicts("Needs Review")) {
    for (const found of [0, 1, 4]) {
      for (const complete of [true, false]) {
        const out = applyScanToVerdict(v, { found, complete });
        const name = `${v.verdict}/${v.blocking}/${found}/${complete}`;
        if (v.verdict === "safe_to_send") {
          assert.equal(out.verdict === "safe_to_send", found === 0 && complete, name);
          if (found > 0) {
            assert.equal(out.verdict, "needs_review");
            assert.equal(out.result.summary, VISIBLE_SENSITIVE_SUMMARY);
            assert.deepEqual(out.result.review, [{ text: `Sensitive-looking text is visible (${found} ${found === 1 ? "item" : "items"}).` }]);
            assert.ok(!out.result.information.some((i) => i.text.startsWith(VISIBLE_TEXT_INFO_PREFIX)));
          } else if (!complete) {
            assert.equal(out.verdict, "cannot_verify");
            assert.equal(out.result.summary, INCOMPLETE_SUMMARY);
          }
        } else {
          assert.equal(out.verdict, v.verdict, name);
          assert.equal(out.blocking, v.blocking, name);
        }
        if (out.result) assert.equal(out.result.notChecked.some((i) => i.text === NOT_READ_LINE), !complete, name);
      }
    }
  }
});

test("an embedded report's positive verdict is reworded beside a verdict that is not Safe to Send", () => {
  for (const word of ["Safe to Send", "all redactions verified"]) {
    const said = word === "Safe to Send" ? "nothing to review" : "no failed region"; // the closed map of contract §6.2
    const v = verdicts(word)[0];
    const out = applyScanToVerdict(v, { found: 2, complete: true });
    const text = out.result.information.map((i) => i.text).join("|");
    assert.doesNotMatch(text, /The report records:/);
    assert.match(text, /A report embedded in this file \(sealed with key ab:cd:12:34\) is not evidence for this check\. This check's own result is Needs Review\./); // v0.2.3: replaced, never quoted
    void said;
    // Beside a Safe to Send that stands, it is left as the engine wrote it.
    const kept = applyScanToVerdict(v, { found: 0, complete: true });
    assert.ok(kept.result.information.some((i) => i.text.includes(`The report records: ${word}.`)));
  }
  const neg = applyScanToVerdict(verdicts("Needs Review")[0], { found: 2, complete: true });
  assert.ok(!neg.result.information.some((i) => i.text.includes("The report records:")), "v0.2.3: a non-positive quote is replaced too");
});

test("a scan reply that contradicts itself is an error, never a pass; a consistent one gives facts", () => {
  const r = (x) => ({ ok: true, regions: [], survivors: [], off_page: [], total_findings: 0, clean: true, count: 0, scan_complete: true, coverage: { pages_total: 1, pages_scanned: 1, pages_failed: [], not_scanned: [], prior_revisions_scanned: false, metadata_scanned: false, acroform_scanned: false, attachments_scanned: false, form_xobjects_scanned: 0, annotation_appearances_scanned: 0, raster_pages: [], raster_only_pages: [], survivor_pages_failed: [], prior_revisions_failed: [], embedded_streams_failed: 0, acroform_tree_incomplete: false, xmp_stream_unread: false, attachment_content_unread: false, attachment_tree_unread: false, scan_complete: true }, ...x });
  const reg = { page: 0, x: 1, y: 2, width: 3, height: 4, kind: "email", preview: "•••" };
  for (const bad of [
    r({ clean: true, regions: [reg], count: 1 }),
    r({ clean: true, total_findings: 1 }),
    r({ clean: false }),
    r({ clean: false, regions: [reg], count: 1, total_findings: 3 }),
    r({ clean: false, regions: [reg], count: 2, total_findings: 1 }),
  ]) assert.match(scanFactsOfReply(bad).error, /contradicted itself/, JSON.stringify(bad));
  assert.deepEqual(scanFactsOfReply(r({})), { found: 0, complete: true, scanComplete: true, survivors: 0 });
  assert.deepEqual(scanFactsOfReply(r({ scan_complete: undefined })), { found: 0, complete: false, scanComplete: null, survivors: 0 });
  assert.deepEqual(scanFactsOfReply(r({ clean: false, regions: [reg], count: 1, total_findings: 1 })), { found: 1, complete: true, scanComplete: true, survivors: 0 });
});

test("the CommonJS rule gives what the TypeScript rule gives (when the build is present)", async (t) => {
  const built = path.join(__dirname, "..", "..", "dist", "verdict-rule.js");
  if (!existsSync(built)) return t.skip("no dist/verdict-rule.js (run tsc)");
  const ts = await import(require("node:url").pathToFileURL(built).href);
  for (const word of ["Safe to Send", "all redactions verified", "Needs Review"]) {
    for (const v of verdicts(word)) {
      for (const found of [0, 3]) {
        for (const complete of [true, false]) {
          assert.deepEqual(applyScanToVerdict(v, { found, complete }), ts.applyScanToVerdict(v, { found, complete }), `${word}/${v.verdict}/${found}/${complete}`);
        }
      }
    }
  }
});

test("the fixed lines are identical to the full server's (src/verdict-rule.ts)", () => {
  let src;
  try {
    src = require("node:fs").readFileSync(path.join(__dirname, "..", "..", "src", "verdict-rule.ts"), "utf8");
  } catch {
    return; // the published mirror has no src/
  }
  for (const line of [VISIBLE_SENSITIVE_SUMMARY, INCOMPLETE_SUMMARY, NOT_READ_LINE, VISIBLE_TEXT_INFO_PREFIX, UNDER_MARK_SUMMARY]) assert.ok(src.includes(`"${line}"`), line);
  assert.ok(src.includes("`Text is still present under a redaction mark (${n} ${n === 1 ? \"item\" : \"items\"}).`"));
  assert.ok(src.includes("`Sensitive-looking text is visible (${found} ${found === 1 ? \"item\" : \"items\"}).`"));
  assert.ok(src.includes("`A report embedded in this file (${key}) is not evidence for this check. This check's own result is ${own}. `"));
});

const ROOT = path.join(__dirname, "..");
const WASM_DEST = path.join(ROOT, "wasm");
const WASM_SRC = path.join(ROOT, "..", "wasm");

test("the real bundle server: a file with made-up values is Needs Review, never Safe to Send", async (t) => {
  const copied = !existsSync(WASM_DEST) && existsSync(WASM_SRC);
  if (copied) cpSync(WASM_SRC, WASM_DEST, { recursive: true });
  if (!existsSync(WASM_DEST)) return t.skip("no bundled wasm (run `npm run build:wasm`)");
  let client;
  try {
    const { PDFDocument, StandardFonts } = require("pdf-lib");
    const { Client } = require("@modelcontextprotocol/sdk/client/index.js");
    const { StdioClientTransport } = require("@modelcontextprotocol/sdk/client/stdio.js");
    const dir = realpathSync(mkdtempSync(path.join(tmpdir(), "omitly-mcpb-1864-")));
    const doc = await PDFDocument.create();
    const font = await doc.embedFont(StandardFonts.Helvetica);
    const page = doc.addPage([400, 400]);
    ["Contact: jordan.sample@example.test", "TFN: 123 456 782", "Card: 4111 1111 1111 1111"].forEach((l, i) =>
      page.drawText(l, { x: 20, y: 350 - i * 30, size: 12, font }),
    );
    const pdf = path.join(dir, "leaky.pdf");
    writeFileSync(pdf, await doc.save());
    client = new Client({ name: "mcpb-verdict-test", version: "0.0.0" });
    await client.connect(
      new StdioClientTransport({
        command: process.execPath,
        args: [path.join(__dirname, "index.js")],
        env: { ...process.env, OMITLY_ALLOWED_DIR: dir },
        stderr: "ignore",
      }),
    );
    const res = await client.callTool({ name: "check_redaction", arguments: { pdfPath: pdf } });
    const text = res.content.map((c) => c.text).join("\n");
    assert.match(text, /Found 3 recoverable item\(s\)/, text);
    assert.match(text, /Check verdict: Needs Review\. Sensitive-looking text is visible in this file\./, text);
    assert.doesNotMatch(text, /Safe to Send/, text);
    assert.match(text, /Review:\n    - Sensitive-looking text is visible on page 1 \(3 values\)\./);
    // A clean file keeps its verdict.
    const clean = await PDFDocument.create();
    const cf = await clean.embedFont(StandardFonts.Helvetica);
    clean.addPage([400, 400]).drawText("Quarterly summary", { x: 20, y: 350, size: 12, font: cf });
    const cleanPdf = path.join(dir, "clean.pdf");
    writeFileSync(cleanPdf, await clean.save());
    const ok = await client.callTool({ name: "check_redaction", arguments: { pdfPath: cleanPdf } });
    assert.match(ok.content.map((c) => c.text).join("\n"), /Check verdict: Safe to Send\./);
    // omitly#1864: the real wasm's replies pass the strict parsers on the other tools too.
    const v = await client.callTool({ name: "verify_redaction", arguments: { pdfPath: cleanPdf } });
    // Contract §3.3: the re-scan runs the same check, so a clean file reaches the same pass.
    assert.match(v.content.map((c) => c.text).join("\n"), /✅ Safe to Send/);
    assert.ok(!v.isError);
    const f = await client.callTool({ name: "find_sensitive_regions", arguments: { pdfPath: pdf } });
    assert.match(f.content.map((c) => c.text).join("\n"), /Found 3 candidate region\(s\)/);
    assert.ok(!f.isError);
    const l = await client.callTool({ name: "locate_text", arguments: { pdfPath: pdf, texts: ["TFN"] } });
    assert.ok(!l.isError, l.content.map((c) => c.text).join("\n"));
  } finally {
    if (client) await client.close();
    if (copied) rmSync(WASM_DEST, { recursive: true, force: true });
  }
});
