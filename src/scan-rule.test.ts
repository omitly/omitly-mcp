/**
 * omitly#1864, review round 1 (Codex on d55a0bc4):
 *  1. an incomplete or unknown-coverage scan is never Safe to Send, in the text, the structured result
 *     and the card, decided by one function (verdict-rule.ts) that both use;
 *  2. `clean: true` never hides findings: what the scan found is derived from its arrays and counts,
 *     and a reply that contradicts itself is an execution failure, not a pass;
 *  3. an embedded report's own "Safe to Send" is reworded beside a verdict that is not Safe to Send.
 * These drive the real handler (a scripted native engine, and the real wasm) and the real card.
 */
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { test } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { buildModel, renderCardHtml, type CardContext } from "./result-card.js";

const ENV_KEYS = ["OMITLY_ALLOWED_DIR", "OMITLY_REDACT_BIN", "OMITLY_PDF_BIN", "OMITLY_ENGINE_DIR", "OMITLY_STATE_DIR"] as const;
const CTX: CardContext = { version: "5.6.0", deviceNoun: "Mac", now: new Date(2026, 10, 13, 9, 0, 0), canOpen: true };
const textOf = (res: any) => (res.content ?? []).filter((c: any) => c.type === "text").map((c: any) => c.text).join("\n");
let counter = 0;

const EMBEDDED_SAFE =
  "This file carries an Omitly report (omitly-audit.json) sealed with key ab:cd:12:34. The report records: Safe to Send. " +
  "A seal shows the file is unchanged since it was sealed, not who sealed it, so check that key is the sender's before relying on the report.";
const EMBEDDED_VERIFIED = EMBEDDED_SAFE.replace("Safe to Send", "all redactions verified");

const engineResult = (state: string, extra: Record<string, unknown> = {}) => ({
  state,
  blocking: false,
  summary: "Every mandatory check that applies to this file passed. 1 page checked.",
  pagesTotal: 1,
  pagesRead: 1,
  checked: [{ text: "Metadata" }],
  notChecked: [],
  problems: [],
  review: [],
  information: [],
  decisions: [],
  reasons: [],
  checkedAt: "2026-11-13T01:00:00Z",
  omitlyVersion: "5.6.0",
  sha256: "a".repeat(64),
  sizeBytes: 40,
  canWrite: false,
  producer: null,
  decisionChannel: "none",
  ...extra,
});
const safe = (extra: Record<string, unknown> = {}) => ({ verdict: "safe_to_send", blocking: false, result: engineResult("safe_to_send", extra), reason_code: null });
const region = (kind = "email", page = 0) => ({ page, x: 1, y: 2, width: 3, height: 4, kind, preview: "•••" });
const FIND0 = (over: Record<string, unknown> = {}) => ({
  ok: true,
  count: 0,
  regions: [],
  survivors: [],
  off_page: [],
  total_findings: 0,
  clean: true,
  scan_complete: true,
  coverage: { pages_total: 1, pages_scanned: 1, pages_failed: [], not_scanned: [], prior_revisions_scanned: false, metadata_scanned: false, acroform_scanned: false, attachments_scanned: false, form_xobjects_scanned: 0, annotation_appearances_scanned: 0, raster_pages: [], raster_only_pages: [], scan_complete: true },
  ...over,
});
// Contract C4: both completeness flags travel together here; a test that sets the top-level one sets the inner one to match.
const FIND = (over: Record<string, unknown> = {}) => {
  const f: any = FIND0(over);
  if ("scan_complete" in over && !("coverage" in over)) {
    f.coverage = { ...f.coverage };
    if (over.scan_complete === undefined) delete f.coverage.scan_complete;
    else f.coverage.scan_complete = over.scan_complete;
  }
  return f;
};

async function rig() {
  const root = realpathSync(mkdtempSync(path.join(tmpdir(), "omitly-scanrule-")));
  for (const k of ENV_KEYS) delete process.env[k];
  process.env.OMITLY_ALLOWED_DIR = root;
  process.env.OMITLY_STATE_DIR = path.join(root, "state");
  const bin = path.join(root, "stub-engine.mjs");
  const cfgPath = path.join(root, "config.json");
  writeFileSync(
    bin,
    `#!/usr/bin/env node
import { readFileSync } from "node:fs";
const req = JSON.parse(readFileSync(0, "utf8"));
const cfg = JSON.parse(readFileSync(${JSON.stringify(cfgPath)}, "utf8"));
const sent = cfg[req.command] ?? { ok: false, error: "no scripted reply for " + req.command };
// Contract C3: a scripted check reply is bound to the bytes of the doc it is asked about (cfg.noBind leaves the digest as written).
if (req.command === "check" && !cfg.noBind && typeof sent?.check?.result?.sha256 === "string" && sent.check.result.sha256.length === 64) {
  const { createHash } = await import("node:crypto");
  sent.check.result.sha256 = createHash("sha256").update(readFileSync(req.pdfPath)).digest("hex");
}
process.stdout.write(JSON.stringify(sent));
`,
    { mode: 0o755 },
  );
  chmodSync(bin, 0o755);
  process.env.OMITLY_REDACT_BIN = bin;
  const doc = path.join(root, "doc.pdf");
  writeFileSync(doc, "%PDF-1.4\n% not parsed: the engine is scripted\n");
  counter += 1;
  const mod = (await import(`./index.js?scan-rule=${counter}`)) as typeof import("./index.js");
  const server = mod.createServer();
  const client = new Client({ name: "t", version: "0" });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(a), client.connect(b)]);
  return {
    doc,
    script: (cfg: Record<string, unknown>) => writeFileSync(cfgPath, JSON.stringify(cfg)),
    call: (): Promise<any> => client.callTool({ name: "check_redaction", arguments: { pdfPath: doc } }),
    close: async () => {
      await client.close();
      await server.close();
    },
  };
}

const card = (doc: string, sc: unknown) => renderCardHtml(buildModel({ arguments: { pdfPath: doc } }, { structuredContent: sc }, CTX));
const headings = (h: string) => [...h.matchAll(/<span>([^<]*)<\/span><span class="cnt/g)].map((m) => m[1]);

// ---- 1. incomplete or unknown coverage is never Safe to Send ---------------------------------------

test("P1: an incomplete scan beside an engine Safe to Send reads Cannot Verify in text, structure and card, and lists what was not read", async () => {
  const r = await rig();
  try {
    for (const [label, scan] of [
      ["scan_complete false", { scan_complete: false }],
      ["scan_complete missing (an older engine)", { scan_complete: undefined }],
    ] as const) {
      r.script({ find: FIND(scan), check: { ok: true, check: safe() } });
      const res = await r.call();
      const text = textOf(res);
      assert.equal(res.structuredContent.scanComplete, false, label);
      assert.equal(res.structuredContent.verdict.verdict, "cannot_verify", `${label}\n${text}`);
      assert.equal(res.structuredContent.verdict.result.state, "cannot_verify", label);
      assert.doesNotMatch(text, /Safe to Send/, `${label}\n${text}`);
      assert.match(text, /Check verdict: Cannot Verify\. Part of this file could not be read/, label);
      assert.ok(res.structuredContent.verdict.result.notChecked.some((i: any) => /could not read all of this file/.test(i.text)), label);
      const html = card(r.doc, res.structuredContent);
      assert.match(html, /data-look="cannot"/, label);
      assert.doesNotMatch(html, /data-look="safe"|<h3>Safe to Send/, label);
      assert.ok(html.includes("COULD NOT BE CHECKED"), label);
    }
    // The card alone, handed an old server's green: it is still not green.
    const sc = { scanComplete: false, clean: true, totalFindings: 0, byKind: {}, regions: [], survivors: [], offPage: [], coverage: { pagesScanned: 1, pagesTotal: 1, notScanned: [], priorRevisionsScanned: true, metadataScanned: true, acroformScanned: true, attachmentsScanned: true, formXobjectsScanned: 0, annotationAppearancesScanned: 0, pagesFailedCount: 0 }, verdict: { ...safe(), result: { ...engineResult("safe_to_send"), canWrite: undefined, producer: undefined } } };
    // omitly#1864 (parse, don't trust): a result that disagrees with itself is the error state.
    assert.match(card(r.doc, sc), /data-look="error"/);
    // And a card with no scanComplete field at all is "unknown": the error state, never green.
    const { scanComplete: _drop, ...unknown } = sc;
    assert.match(card(r.doc, unknown), /data-look="error"/);
  } finally {
    await r.close();
  }
});

test("P1: an incomplete scan WITH findings is amber and shows COULD NOT BE CHECKED too", async () => {
  const r = await rig();
  try {
    r.script({ find: FIND({ scan_complete: false, count: 1, regions: [region()], total_findings: 1, clean: false }), check: { ok: true, check: safe() } });
    const res = await r.call();
    assert.equal(res.structuredContent.verdict.verdict, "needs_review");
    const html = card(r.doc, res.structuredContent);
    assert.match(html, /data-look="visible"/);
    assert.deepEqual(headings(html), ["SENSITIVE TEXT STILL VISIBLE", "WHAT WAS CHECKED", "COULD NOT BE CHECKED"]);
    assert.match(html, /data-toggle="notChecked" aria-expanded="false"/);
  } finally {
    await r.close();
  }
});

test("P1: the amber card lists the engine's own could-not-check lines, and red keeps them too", async () => {
  const r = await rig();
  try {
    const nc = [{ text: "Text inside images is not read: this check does no OCR." }];
    r.script({ find: FIND({ count: 1, regions: [region()], total_findings: 1, clean: false }), check: { ok: true, check: safe({ notChecked: nc }) } });
    const amber = card(r.doc, (await r.call()).structuredContent);
    assert.match(amber, /data-look="visible"/);
    assert.ok(amber.includes("COULD NOT BE CHECKED") && amber.includes("this check does no OCR"));
    const blocking = { verdict: "needs_review", blocking: true, reason_code: null, result: engineResult("needs_review", { blocking: true, problems: [{ text: "Text under a box on page 1" }], notChecked: nc }) };
    r.script({ find: FIND(), check: { ok: true, check: blocking } });
    const red = card(r.doc, (await r.call()).structuredContent);
    assert.match(red, /data-look="blocking"/);
    assert.ok(red.includes("COULD NOT BE CHECKED"));
  } finally {
    await r.close();
  }
});

// ---- 2. `clean: true` never hides findings --------------------------------------------------------

test("P2: a native reply with clean:true and a finding is an execution failure: isError true, no verdict, no structured result", async () => {
  const r = await rig();
  try {
    const replies: [string, Record<string, unknown>][] = [
      ["clean true, one region", FIND({ clean: true, count: 1, regions: [region()], total_findings: 0 })],
      ["clean true, count says 1, no arrays", FIND({ clean: true, total_findings: 1 })],
      ["clean true, survivor listed", FIND({ clean: true, survivors: [region("ssn")] })],
      ["clean true, off-page listed", FIND({ clean: true, off_page: [{ source: "metadata", kind: "email", preview: "•••" }] })],
      ["clean false, nothing listed", FIND({ clean: false })],
      ["total says 3, one region listed", FIND({ clean: false, count: 1, regions: [region()], total_findings: 3 })],
      ["count says 2, one region listed", FIND({ clean: false, count: 2, regions: [region()], total_findings: 1 })],
    ];
    for (const [label, find] of replies) {
      r.script({ find, check: { ok: true, check: safe() } });
      const res = await r.call();
      const text = textOf(res);
      assert.equal(res.isError, true, `${label}\n${text}`);
      assert.equal(res.structuredContent, undefined, label);
      assert.doesNotMatch(text, /Safe to Send|No recoverable PII/, `${label}\n${text}`);
      assert.match(text, /contradicted itself/, label);
    }
    // A consistent clean reply is untouched.
    r.script({ find: FIND(), check: { ok: true, check: safe() } });
    const ok = await r.call();
    assert.equal(ok.isError, false);
    assert.equal(ok.structuredContent.verdict.verdict, "safe_to_send");
  } finally {
    await r.close();
  }
});

// ---- 3. an embedded report's own verdict is never left to read as this check's ----------------------

test("P3: an embedded report's Safe to Send / all redactions verified is reworded beside a non-Safe verdict, in text, structure and card", async () => {
  const r = await rig();
  try {
    for (const embedded of [EMBEDDED_SAFE, EMBEDDED_VERIFIED]) {
      const quoted = embedded.includes("Safe to Send") ? "nothing to review" : "no failed region"; // the closed map of contract §6.2
      r.script({
        find: FIND({ count: 1, regions: [region()], total_findings: 1, clean: false }),
        check: { ok: true, check: safe({ information: [{ text: embedded }] }) },
      });
      const res = await r.call();
      const text = textOf(res);
      const info = res.structuredContent.verdict.result.information.map((i: any) => i.text);
      assert.equal(info.length, 1);
      assert.ok(!info[0].startsWith("This file carries an Omitly report"), info[0]);
      // v0.2.3: the sealed-report line is REPLACED by fixed wording; the report's own words are not quoted at all.
      assert.match(info[0], /^A report embedded in this file \(sealed with key ab:cd:12:34\) is not evidence for this check\. This check's own result is Needs Review\./);
      assert.doesNotMatch(text, /The report records:/);
      assert.ok(text.includes(info[0]));
      // omitly#1864: no "Safe to Send" is left in the text at all, not even a quoted one.
      assert.doesNotMatch(text, /Safe to Send/, text);
      const html = card(r.doc, res.structuredContent);
      assert.ok(html.includes("A report embedded in this file") || !/INFORMATION/.test(html));
      assert.doesNotMatch(html, /The report records:/);
      assert.match(html, /data-look="visible"/);
    }
    // v0.2.3: a line that quotes a verdict that is not positive is replaced too: no sealed-report line is ever printed as the file wrote it.
    const needs = EMBEDDED_SAFE.replace("Safe to Send", "Needs Review");
    r.script({ find: FIND({ count: 1, regions: [region()], total_findings: 1, clean: false }), check: { ok: true, check: safe({ information: [{ text: needs }] }) } });
    assert.match((await r.call()).structuredContent.verdict.result.information[0].text, /^A report embedded in this file .* is not evidence for this check\./);
    // Contract C2b: even beside a clean, complete scan the check relied on the file's own sealed report, so it is capped at needs_review
    // (W6) and the report's word is reworded like any other.
    r.script({ find: FIND(), check: { ok: true, check: safe({ information: [{ text: EMBEDDED_SAFE }] }) } });
    const capped = await r.call();
    assert.equal(capped.structuredContent.outcome, "needs_review");
    assert.match(capped.structuredContent.verdict.result.information[0].text, /^A report embedded in this file .* is not evidence for this check\. This check's own result is Needs Review\./);
  } finally {
    await r.close();
  }
});

// ---- the shared rule, over every combination ----------------------------------------------------------

import { applyScanToVerdict, scanFactsOf } from "./verdict-rule.js";

test("the rule: Safe to Send survives only when nothing was found AND the scan read everything; idempotent; engine states otherwise untouched", () => {
  const states: [string, boolean][] = [["safe_to_send", false], ["needs_review", false], ["needs_review", true], ["cannot_verify", false]];
  const words = ["Safe to Send", "all redactions verified", "Needs Review", "Cannot Verify", "not every redaction verified"];
  for (const [state, blocking] of states) {
    for (const found of [0, 2]) {
      for (const complete of [true, false]) {
        for (const word of words) {
          const v: any = { verdict: state, blocking, reason_code: null, result: engineResult(state, { blocking, information: [{ text: EMBEDDED_SAFE.replace("Safe to Send", word) }] }) };
          const out: any = applyScanToVerdict(v, { found, complete });
          const name = `${state}/${blocking}/found ${found}/complete ${complete}/${word}`;
          const keepsSafe = state === "safe_to_send" && found === 0 && complete;
          if (state === "safe_to_send") assert.equal(out.verdict === "safe_to_send", keepsSafe, name);
          else assert.equal(out.verdict, state, name);
          assert.equal(out.result.state, out.verdict, name);
          assert.equal(out.blocking, out.verdict === "needs_review" ? blocking : false, name);
          assert.deepEqual(applyScanToVerdict(out, { found, complete }), out, `${name}: idempotent`);
          const info = out.result.information.map((i: any) => i.text).join("|");
          const positive = word === "Safe to Send" || word === "all redactions verified";
          if (out.verdict !== "safe_to_send") {
            // v0.2.3: any sealed-report line beside a verdict that is not Safe to Send is replaced, whatever it records.
            assert.doesNotMatch(info, /The report records:/, name);
            assert.match(info, /is not evidence for this check\. This check's own result is /, name);
          } else {
            assert.ok(info.includes(`The report records: ${word}.`), `${name}: left as the engine wrote it`);
          }
          assert.equal(out.result.notChecked.some((i: any) => i.text.includes("could not read all of this file")), !complete, name);
        }
      }
    }
  }
});

test("scanFactsOf: anything but scanComplete:true is incomplete; findings come from arrays and counts", () => {
  assert.deepEqual(scanFactsOf({ scanComplete: true, clean: true, regions: [], survivors: [], offPage: [] }), { found: 0, complete: true, survivors: 0 });
  assert.equal(scanFactsOf({ scanComplete: "true" }).complete, false);
  assert.equal(scanFactsOf({}).complete, false);
  assert.equal(scanFactsOf({ scanComplete: true, clean: true, regions: [{}], survivors: [{}], offPage: [{}] }).found, 3);
  assert.equal(scanFactsOf({ scanComplete: true, clean: false }).found, 1);
  assert.equal(scanFactsOf({ scanComplete: true, totalFindings: 5 }).found, 5);
});
