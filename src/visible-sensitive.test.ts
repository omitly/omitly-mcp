/**
 * omitly#1864: a file the pattern scan lists findings in is never also Safe to Send, and the result
 * card says so in the approved amber state (owner, 13 November 2026).
 *
 * The cause: `check_redaction` ran two passes over one file. The engine's presented check judges
 * hidden, covered and recoverable content and counts visible sensitive-looking text only as an
 * INFORMATION line (omitly#1499); the pattern scan lists the findings. Both were printed, so one
 * answer could say "LEAK: 4 sensitive item(s)" and "Check verdict: Safe to Send". The rule now lives
 * in `reconcileVerdictWithFindings` (index.ts), is applied before any line is built, and is checked a
 * second time by the tool's output schema.
 *
 * These tests drive the REAL functions: the real wasm detector and presented check over a PDF built
 * here with pdf-lib, the real native `omitly-redact` when it is built, the real tool handler through an
 * in-memory client, and the real card functions. Every value in a fixture is made up.
 */
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { PDFDocument, StandardFonts, rgb } from "pdf-lib";
import { checkRedactionOutputSchema, verdictHeading } from "./index.js";
import { applyScanToVerdict } from "./verdict-rule.js";
import { worst, type Outcome } from "./outcome.js";
import {
  VISIBLE_COPY,
  buildModel,
  pagesPhrase,
  renderCardHtml,
  sensitiveRows,
  type CardContext,
} from "./result-card.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const WORKSPACE = path.join(HERE, "..", "..");
const EXE = process.platform === "win32" ? ".exe" : "";
const ENGINE =
  process.env.OMITLY_TEST_REDACT_BIN ??
  [
    path.join(WORKSPACE, "target", "debug", `omitly-redact${EXE}`),
    path.join(WORKSPACE, "target", "release", `omitly-redact${EXE}`),
  ].find((p) => existsSync(p));
const skipNative = !ENGINE && !(existsSync(path.join(WORKSPACE, "Cargo.toml")) && process.env.CI)
  ? "no omitly-redact build (run `cargo build -p omitly-cli`)"
  : false;

const ENV_KEYS = ["OMITLY_ALLOWED_DIR", "OMITLY_REDACT_BIN", "OMITLY_PDF_BIN", "OMITLY_ENGINE_DIR", "OMITLY_STATE_DIR"] as const;
let counter = 0;

/** The rule with a scan that read everything: the findings-only dimension of the tests below. */
const reconcile = <V extends Parameters<typeof applyScanToVerdict>[0]>(v: V, found: number): V => applyScanToVerdict(v, { found, complete: true });

const CTX: CardContext = { version: "5.6.0", deviceNoun: "Mac", now: new Date(2026, 10, 13, 9, 0, 0), canOpen: true };
const textOf = (res: any) => (res.content ?? []).filter((c: any) => c.type === "text").map((c: any) => c.text).join("\n");

// ---- fixtures: made-up values --------------------------------------------------------------------

const EMAIL = "jordan.sample@example.test";
const PHONE = "0412 345 678";
const TFN = "123 456 782";
const CARD = "4111 1111 1111 1111";
const VALUES = [EMAIL, PHONE, TFN, CARD];

async function pdfWith(pages: string[][]): Promise<Buffer> {
  const doc = await PDFDocument.create();
  const font = await doc.embedFont(StandardFonts.Helvetica);
  for (const lines of pages) {
    const page = doc.addPage([400, 400]);
    lines.forEach((l, i) => page.drawText(l, { x: 20, y: 350 - i * 30, size: 12, font }));
  }
  return Buffer.from(await doc.save());
}

async function callCheck(env: Record<string, string>, pdf: Buffer): Promise<any> {
  const root = realpathSync(mkdtempSync(path.join(tmpdir(), "omitly-1864-")));
  for (const k of ENV_KEYS) delete process.env[k];
  process.env.OMITLY_ALLOWED_DIR = root;
  process.env.OMITLY_STATE_DIR = path.join(root, "state");
  Object.assign(process.env, env);
  const doc = path.join(root, "doc.pdf");
  writeFileSync(doc, pdf);
  counter += 1;
  const mod = (await import(`./index.js?visible-sensitive=${counter}`)) as typeof import("./index.js");
  const server = mod.createServer();
  const client = new Client({ name: "visible-sensitive-test", version: "0.0.0" });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(a), client.connect(b)]);
  try {
    const res: any = await client.callTool({ name: "check_redaction", arguments: { pdfPath: doc } });
    return { res, doc };
  } finally {
    await client.close();
    await server.close();
  }
}

/** Every string a value could be searched for: the value, its digits, and the masked previews. */
function leaksAny(html: string, res: any): string[] {
  const needles = [...VALUES, ...VALUES.map((v) => v.replace(/\D/g, "")).filter((d) => d.length >= 8)];
  for (const r of [...res.structuredContent.regions, ...res.structuredContent.survivors, ...res.structuredContent.offPage]) {
    needles.push(r.preview);
  }
  return needles.filter((n) => n.length > 0 && html.includes(n));
}

const cardFor = (doc: string, res: any, ctx: CardContext = CTX) =>
  renderCardHtml(buildModel({ arguments: { pdfPath: doc } }, { structuredContent: res.structuredContent }, ctx));

// ---- 1. the reproduction, through the real wasm path (and the real native engine) ----------------

for (const [label, env, skip] of [
  ["wasm", {}, false],
  ["native engine", { OMITLY_REDACT_BIN: ENGINE ?? "", OMITLY_PDF_BIN: ENGINE ?? "" }, skipNative],
] as const) {
  test(`[${label}] an unredacted file with four made-up values is Needs Review, never Safe to Send, in text and structure`, { skip }, async () => {
    const { res, doc } = await callCheck(env, await pdfWith([[`Contact: ${EMAIL}`, `Mobile: ${PHONE}`, `TFN: ${TFN}`, `Card: ${CARD}`]]));
    const sc = res.structuredContent;
    assert.equal(sc.clean, false);
    assert.equal(sc.totalFindings, 4, JSON.stringify(sc.byKind));
    assert.equal(sc.verdict.verdict, "needs_review");
    assert.equal(sc.verdict.blocking, false);
    assert.equal(sc.verdict.result.state, "needs_review");
    assert.equal(sc.verdict.result.blocking, false);
    const text = textOf(res);
    assert.doesNotMatch(text, /Safe to Send/, text);
    assert.match(text, /LEAK: this "redacted" PDF still contains 4 sensitive item\(s\)/);
    assert.match(text, /Check verdict: Needs Review\. Sensitive-looking text is visible in this file\./);
    // omitly#1930: the engine's own "visible" line is now a REVIEW line (the engine lowers the verdict itself);
    // it is not repeated under INFORMATION, and the MCP adds no second line of its own.
    assert.match(text, /Review:\n    - Sensitive-looking text is visible on page 1 \(4 values\)\./);
    assert.equal((text.match(/Sensitive-looking text is visible on page/g) ?? []).length, 1, text);
    assert.doesNotMatch(text, /Information:[\s\S]*Sensitive-looking text is visible/);

    // The card, light and dark share one HTML; the dark variant is CSS.
    const html = cardFor(doc, res);
    assert.match(html, /data-look="visible"/);
    assert.ok(html.includes("<h3>Needs Review — sensitive text is visible (4)</h3>"), html);
    assert.ok(html.includes("<p>This file still shows 4 items that look sensitive. Do not send it until they are removed.</p>"), html);
    assert.ok(html.includes("SENSITIVE TEXT STILL VISIBLE"), html);
    assert.ok(html.includes('class="cnt c-amber">4 ⚠</span>'), html);
    assert.ok(html.includes("1 email address, 1 phone number, 1 tax file number and 1 card number on page 1"), html);
    assert.match(html, /data-toggle="sensitive" aria-expanded="true"/);
    assert.match(html, /data-toggle="checked" aria-expanded="false"/);
    assert.match(html, /data-toggle="information" aria-expanded="false"/);
    assert.ok(html.includes(">Open in Omitly to redact</button>"), html);
    assert.ok(html.includes("Checked on this Mac by Omitly"), "the existing footer");
    assert.deepEqual(leaksAny(html, res), [], "a detected value (or its masked preview) reached the card");
    assert.ok(!/data-look="safe"|<h3>Safe to Send/.test(html));
  });
}

test("[wasm] one finding reads in the singular", async () => {
  const { res, doc } = await callCheck({}, await pdfWith([[`Contact: ${EMAIL}`]]));
  assert.equal(res.structuredContent.totalFindings, 1);
  const html = cardFor(doc, res);
  assert.ok(html.includes("<h3>Needs Review — sensitive text is visible (1)</h3>"), html);
  assert.ok(html.includes("<p>This file still shows 1 item that looks sensitive. Do not send it until it is removed.</p>"), html);
  assert.ok(html.includes('class="cnt c-amber">1 ⚠</span>'), html);
  assert.ok(html.includes("1 email address on page 1"), html);
  assert.match(textOf(res), /Sensitive-looking text is visible on page 1 \(1 value\)\./);
  assert.deepEqual(leaksAny(html, res), []);
});

test("[wasm] a clean file keeps its Safe to Send and its green card", async () => {
  const { res, doc } = await callCheck({}, await pdfWith([["Quarterly summary", "No identifiers on this page"]]));
  assert.equal(res.structuredContent.clean, true);
  assert.equal(res.structuredContent.verdict.verdict, "safe_to_send");
  assert.match(textOf(res), /Check verdict: Safe to Send\./);
  assert.match(cardFor(doc, res), /data-look="safe"/);
});

test("[wasm] findings on several pages: one row per group of kinds, with its pages", async () => {
  const { res, doc } = await callCheck({}, await pdfWith([[`Mail ${EMAIL}`, `Card ${CARD}`], [`Mail ${EMAIL}`], ["nothing"], [`Card ${CARD}`]]));
  const html = cardFor(doc, res);
  assert.ok(html.includes("2 email addresses on pages 1 and 2"), html);
  assert.ok(html.includes("2 card numbers on pages 1 and 4"), html);
  assert.deepEqual(leaksAny(html, res), []);
});

// ---- 2. the contradiction cannot be produced: every verdict x every finds combination -------------

const result = (state: string, blocking: boolean, extra: Record<string, unknown> = {}) => ({
  state,
  blocking,
  summary: "Fixed summary.",
  pagesTotal: 1,
  pagesRead: 1,
  checked: [{ text: "Metadata" }],
  notChecked: [],
  problems: blocking ? [{ text: "Text under a box on page 1" }] : [],
  review: [],
  information: [{ text: "Sensitive-looking text is visible on page 1 (1 value).", pages: [1] }],
  decisions: [],
  reasons: state === "cannot_verify" ? [{ text: "Could not complete" }] : [],
  checkedAt: "2026-11-13T01:00:00Z",
  omitlyVersion: "5.6.0",
  sha256: "a".repeat(64),
  sizeBytes: 40,
  decisionChannel: "none",
  ...extra,
});
const verdictOf = (state: "safe_to_send" | "needs_review" | "cannot_verify", blocking: boolean, withResult = true) => ({
  verdict: state,
  blocking,
  result: withResult ? result(state, blocking) : null,
  reason_code: null,
});
const region = (kind: string, page = 0) => ({ page, x: 1, y: 2, width: 3, height: 4, kind, preview: "•••" });

const VERDICTS = [
  ["safe_to_send", verdictOf("safe_to_send", false)],
  ["needs_review", verdictOf("needs_review", false)],
  ["needs_review blocking", verdictOf("needs_review", true)],
  ["cannot_verify", verdictOf("cannot_verify", false)],
  ["cannot_verify, no result", verdictOf("cannot_verify", false, false)],
] as const;

const FINDS = [
  ["none", { clean: true, total: 0, regions: [], survivors: [], offPage: [] }],
  ["one visible", { clean: false, total: 1, regions: [region("email")], survivors: [], offPage: [] }],
  ["four visible", { clean: false, total: 4, regions: [region("email"), region("phone"), region("tfn"), region("card")], survivors: [], offPage: [] }],
  ["under a mark", { clean: false, total: 1, regions: [], survivors: [region("ssn")], offPage: [] }],
  ["off page", { clean: false, total: 1, regions: [], survivors: [], offPage: [{ source: "metadata", kind: "email", preview: "•••" }] }],
  ["total only", { clean: false, total: 3, regions: [], survivors: [], offPage: [] }],
] as const;

test("every verdict x every finds combination: through the real functions, Safe to Send never appears beside a finding", () => {
  let combos = 0;
  for (const [vName, v] of VERDICTS) {
    for (const [fName, f] of FINDS) {
      combos += 1;
      const name = `${vName} / ${fName}`;
      const found = f.clean ? 0 : Math.max(1, f.total, f.regions.length + f.survivors.length + f.offPage.length);
      const out = reconcile(v as any, found);
      const heading = verdictHeading(out);
      const line = "";
      const structured = {
        scanComplete: true,
        clean: f.clean,
        totalFindings: f.total,
        byKind: {},
        regions: f.regions,
        survivors: f.survivors,
        offPage: f.offPage,
        coverage: { pagesScanned: 1, pagesTotal: 1, notScanned: [], priorRevisionsScanned: true, metadataScanned: true, acroformScanned: true, attachmentsScanned: true, formXobjectsScanned: 0, annotationAppearancesScanned: 0, pagesFailedCount: 0 },
        verdict: out,
        // The outcome this pair has (the issuer's rows 1-4, restated for a table that scripts verdicts directly).
        outcome: worst(
          "safe_to_send",
          ...([
            f.survivors.length > 0 ? "not_a_pass" : "safe_to_send",
            found > 0 ? "needs_review" : "safe_to_send",
            v.verdict === "needs_review" ? (v.blocking ? "not_a_pass" : "needs_review") : v.verdict === "cannot_verify" ? "incomplete" : "safe_to_send",
          ] as Outcome[]),
        ),
      };
      const schema = checkRedactionOutputSchema.safeParse(structured);
      if (found > 0) {
        assert.notEqual(out.verdict, "safe_to_send", name);
        assert.doesNotMatch(heading, /Safe to Send/, name);
        assert.doesNotMatch(line, /Safe to Send/, name);
        assert.ok(schema.success, `${name}: ${JSON.stringify(schema.error?.issues)}`);
        // The raw, unreconciled pair is refused by the output schema itself.
        const raw = checkRedactionOutputSchema.safeParse({ ...structured, verdict: v });
        assert.equal(raw.success, v.verdict !== "safe_to_send", `${name}: the schema must refuse Safe to Send beside a finding`);
        if (v.verdict === "safe_to_send") assert.ok(raw.error?.issues.some((i) => i.path.join(".") === "verdict.verdict"));
      } else {
        // Nothing found: the engine's verdict is returned untouched.
        assert.deepEqual(out, v, name);
        assert.ok(schema.success, name);
      }
      // Whatever else was reported stays what the engine said.
      if (v.verdict !== "safe_to_send") assert.deepEqual(out, v, `${name}: only Safe to Send is changed`);
    }
  }
  assert.equal(combos, VERDICTS.length * FINDS.length);
});

test("a reconciled verdict is Needs Review, not blocking, with fixed text and the engine's own information line moved", () => {
  const out = reconcile(verdictOf("safe_to_send", false) as any, 4);
  assert.equal(out.verdict, "needs_review");
  assert.equal(out.blocking, false);
  assert.equal(out.result?.state, "needs_review");
  assert.equal(out.result?.blocking, false);
  assert.equal(out.result?.summary, "Sensitive-looking text is visible in this file. Review it before sending.");
  assert.deepEqual(out.result?.review, [{ text: "Sensitive-looking text is visible (4 items)." }]);
  assert.deepEqual(out.result?.information, []);
  assert.deepEqual(out.result?.checked, [{ text: "Metadata" }], "what was checked is unchanged");
});

// ---- 3. through the real handler with a scripted engine: both tools' paths, every combination ------

function stubEngine(root: string): (cfg: Record<string, unknown>) => void {
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
  return (cfg) => writeFileSync(cfgPath, JSON.stringify(cfg));
}

test("through the real handler: no scripted engine verdict x finds pair returns Safe to Send beside a finding", async () => {
  const root = realpathSync(mkdtempSync(path.join(tmpdir(), "omitly-1864-stub-")));
  for (const k of ENV_KEYS) delete process.env[k];
  process.env.OMITLY_ALLOWED_DIR = root;
  process.env.OMITLY_STATE_DIR = path.join(root, "state");
  const script = stubEngine(root);
  const doc = path.join(root, "doc.pdf");
  writeFileSync(doc, "%PDF-1.4\n% not parsed: the engine is scripted\n");
  counter += 1;
  const mod = (await import(`./index.js?visible-sensitive=${counter}`)) as typeof import("./index.js");
  const server = mod.createServer();
  const client = new Client({ name: "t", version: "0" });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(a), client.connect(b)]);
  try {
    for (const [vName, v] of VERDICTS) {
      for (const [fName, f] of FINDS) {
        const name = `${vName} / ${fName}`;
        // The check's own scan writes the "visible" information line only when it counted a value, and the two legs
        // see one file: beside a scan that found nothing (omitly#1864 round 5) the line is the pair the server
        // refuses, so for that case the fixture is the engine's honest check without it.
        const quiet = (r: any) => r && { ...r, information: r.information.filter((i: any) => !i.text.startsWith("Sensitive-looking text is visible")) };
        const sent = f.clean ? { ...v, result: quiet(v.result) } : v;
        script({
          find: { ok: true, count: f.regions.length, regions: f.regions, survivors: f.survivors, off_page: f.offPage, total_findings: f.total, clean: f.clean, scan_complete: true, coverage: { pages_total: 1, pages_scanned: 1, pages_failed: [], not_scanned: [], prior_revisions_scanned: false, metadata_scanned: false, acroform_scanned: false, attachments_scanned: false, form_xobjects_scanned: 0, annotation_appearances_scanned: 0, raster_pages: [], raster_only_pages: [], scan_complete: true } },
          // The engine's own shape: the two desktop-only fields are sent and dropped by the allowlist.
          check: { ok: true, check: { ...sent, result: sent.result && { ...sent.result, canWrite: false, producer: null } } },
        });
        if (f.clean && v.result) {
          // The pair that cannot come from one file: refused, whatever the verdict.
          script({ find: { ok: true, count: 0, regions: [], survivors: [], off_page: [], total_findings: 0, clean: true, scan_complete: true, coverage: { pages_total: 1, pages_scanned: 1, pages_failed: [], not_scanned: [], prior_revisions_scanned: false, metadata_scanned: false, acroform_scanned: false, attachments_scanned: false, form_xobjects_scanned: 0, annotation_appearances_scanned: 0, raster_pages: [], raster_only_pages: [], scan_complete: true } }, check: { ok: true, check: { ...v, result: { ...v.result, canWrite: false, producer: null } } } });
          const bad: any = await client.callTool({ name: "check_redaction", arguments: { pdfPath: doc } });
          assert.equal(bad.isError, true, `${name}: a check listing visible values beside an empty scan`);
          assert.doesNotMatch(textOf(bad), /Safe to Send/, name);
          script({
            find: { ok: true, count: f.regions.length, regions: f.regions, survivors: f.survivors, off_page: f.offPage, total_findings: f.total, clean: f.clean, scan_complete: true, coverage: { pages_total: 1, pages_scanned: 1, pages_failed: [], not_scanned: [], prior_revisions_scanned: false, metadata_scanned: false, acroform_scanned: false, attachments_scanned: false, form_xobjects_scanned: 0, annotation_appearances_scanned: 0, raster_pages: [], raster_only_pages: [], scan_complete: true } },
            check: { ok: true, check: { ...sent, result: sent.result && { ...sent.result, canWrite: false, producer: null } } },
          });
        }
        const res: any = await client.callTool({ name: "check_redaction", arguments: { pdfPath: doc } });
        const text = textOf(res);
        const sc = res.structuredContent;
        if (v.result === null && !["input_too_large", "check_failed"].includes(String(v.reason_code))) {
          // Contract C3: a check with no result carries no digest, which only a refusal (input_too_large, check_failed) may: row 0.
          assert.equal(res.isError, true, name);
          assert.equal(sc, undefined, name);
          assert.doesNotMatch(text, /Safe to Send/, name);
          continue;
        }
        if (fName === "total only") {
          // A count with no items behind it contradicts itself: an execution failure, never a verdict.
          assert.equal(res.isError, true, name);
          assert.equal(sc, undefined, name);
          assert.doesNotMatch(text, /Safe to Send/, name);
          continue;
        }
        assert.ok(sc, `${name}: no structured result\n${text}`);
        const finding = !f.clean;
        if (finding) {
          assert.notEqual(sc.verdict.verdict, "safe_to_send", name);
          assert.doesNotMatch(text, /Safe to Send/, `${name}\n${text}`);
          if (v.verdict === "safe_to_send") assert.equal(sc.verdict.verdict, "needs_review", name);
        } else if (v.verdict === "safe_to_send") {
          assert.equal(sc.verdict.verdict, "safe_to_send", name);
          assert.match(text, /Check verdict: Safe to Send\./, name);
        }
      }
    }
  } finally {
    await client.close();
    await server.close();
  }
});

// ---- 4. the card ---------------------------------------------------------------------------------

const sc = (verdict: any, scan: Record<string, unknown> = {}) => ({
  scanComplete: true,
  clean: true,
  totalFindings: 0,
  byKind: {},
  regions: [],
  survivors: [],
  offPage: [],
  coverage: { pagesScanned: 1, pagesTotal: 1, notScanned: [], priorRevisionsScanned: true, metadataScanned: true, acroformScanned: true, attachmentsScanned: true, formXobjectsScanned: 0, annotationAppearancesScanned: 0, pagesFailedCount: 0 },
  verdict,
  // `outcome` is what the server issues (contract §3.8): the verdict's state, with a blocking one a failed redaction.
  outcome: verdict.verdict === "safe_to_send" ? "safe_to_send" : verdict.verdict === "cannot_verify" ? "incomplete" : verdict.blocking ? "not_a_pass" : "needs_review",
  ...scan,
});
const html = (s: unknown, ctx: CardContext = CTX) => renderCardHtml(buildModel({ arguments: { pdfPath: "/x/Statement.pdf" } }, { structuredContent: s }, ctx));
const headings = (h: string) => [...h.matchAll(/<span>([^<]*)<\/span><span class="cnt/g)].map((m) => m[1]);

test("card: amber copy is exact for N = 1 and N = 4", () => {
  assert.equal(VISIBLE_COPY.title(1), "Needs Review — sensitive text is visible (1)");
  assert.equal(VISIBLE_COPY.line(1), "This file still shows 1 item that looks sensitive. Do not send it until it is removed.");
  assert.equal(VISIBLE_COPY.title(4), "Needs Review — sensitive text is visible (4)");
  assert.equal(VISIBLE_COPY.line(4), "This file still shows 4 items that look sensitive. Do not send it until they are removed.");
  assert.equal(VISIBLE_COPY.heading, "SENSITIVE TEXT STILL VISIBLE");
  assert.equal(VISIBLE_COPY.button, "Open in Omitly to redact");
  const one = html(sc(reconcile(verdictOf("safe_to_send", false) as any, 1), { clean: false, totalFindings: 1, regions: [region("email")] }));
  assert.deepEqual(headings(one), ["SENSITIVE TEXT STILL VISIBLE", "WHAT WAS CHECKED"]);
  assert.ok(one.includes("1 email address on page 1"));
  const four = html(sc(reconcile(verdictOf("safe_to_send", false) as any, 4), { clean: false, totalFindings: 4, regions: [region("email"), region("phone"), region("tfn"), region("card")] }));
  assert.ok(four.includes('class="cnt c-amber">4 ⚠</span>'));
  assert.ok(four.includes("1 email address, 1 phone number, 1 tax file number and 1 card number on page 1"));
});

test("card: amber sections are open for the items, collapsed for what was checked and information", () => {
  const v = reconcile({ ...verdictOf("safe_to_send", false), result: result("safe_to_send", false, { information: [{ text: "The file has document properties." }] }) } as any, 2);
  const h = html(sc(v, { clean: false, totalFindings: 2, regions: [region("email"), region("email", 2)] }));
  assert.deepEqual(headings(h), ["SENSITIVE TEXT STILL VISIBLE", "WHAT WAS CHECKED", "INFORMATION (does not affect the result)"]);
  assert.match(h, /data-toggle="sensitive" aria-expanded="true"/);
  assert.match(h, /data-toggle="checked" aria-expanded="false"/);
  assert.match(h, /data-toggle="information" aria-expanded="false"/);
  assert.ok(h.includes("2 email addresses on pages 1 and 3"));
  // Contract §3.8: on a non-pass the checked list is neutral, never green.
  assert.match(h, /WHAT WAS CHECKED<\/span><span class="cnt c-neutral">1</);
  assert.doesNotMatch(h, /Sensitive-looking text is visible \(/, "the engine's own line is not repeated beside the section");
});

test("card: red wins when both apply, and lists the visible items as a section under it", () => {
  const blocking = verdictOf("needs_review", true);
  const h = html(sc(blocking, { clean: false, totalFindings: 3, regions: [region("email"), region("card")], survivors: [region("ssn")] }));
  assert.match(h, /data-look="blocking"/);
  assert.ok(h.includes("<h3>Needs Review — problems found</h3>"));
  assert.doesNotMatch(h, /sensitive text is visible \(/);
  assert.deepEqual(headings(h), ["PROBLEMS FOUND", "SENSITIVE TEXT STILL VISIBLE"]);
  assert.match(h, /data-toggle="problems" aria-expanded="true"/);
  assert.match(h, /data-toggle="sensitive" aria-expanded="true"/);
  // The failed redaction (text under a mark) is the red part; the section lists only what is visible.
  assert.ok(h.includes("1 email address and 1 card number on page 1"));
  assert.ok(h.includes('class="cnt c-amber">2 ⚠</span>'));
  assert.ok(h.includes(">Open in Omitly to fix</button>"));
  // Without visible items, red has no such section.
  const plain = html(sc(blocking, { clean: false, totalFindings: 1, survivors: [region("ssn")] }));
  assert.doesNotMatch(plain, /SENSITIVE TEXT STILL VISIBLE/);
});

test("card: a result that lists findings is never green, even if it arrives with Safe to Send", () => {
  const h = html(sc(verdictOf("safe_to_send", false), { clean: false, totalFindings: 1, regions: [region("email")] }));
  // omitly#1864: Safe to Send beside a finding disagrees with itself: the error state, never green.
  assert.match(h, /data-look="error"/);
  assert.doesNotMatch(h, /data-look="safe"|<h3>Safe to Send/);
});

test("card: Needs Review without findings and Cannot Verify keep their own looks", () => {
  assert.match(html(sc({ ...verdictOf("needs_review", false), result: result("needs_review", false, { information: [] }) })), /data-look="review"/);
  assert.match(html(sc(verdictOf("cannot_verify", false), { clean: false, totalFindings: 1, regions: [region("email")] })), /data-look="cannot"/);
});

test("card: only kind and page are read: a hostile preview, kind and coordinates never reach the HTML", () => {
  const hostile = "<img src=x onerror=alert(1)> jordan.sample@example.test";
  const h = html(
    sc(reconcile(verdictOf("safe_to_send", false) as any, 4), {
      clean: false,
      totalFindings: 4,
      regions: [{ ...region("email"), preview: hostile }, { ...region(hostile), preview: hostile }, { ...region("<script>"), page: 4 }],
      offPage: [{ source: hostile, kind: "email", preview: hostile }],
    }),
  );
  assert.ok(!h.includes("onerror") && !h.includes("jordan.sample") && !h.includes("<script>") && !h.includes("<img"), h);
  assert.match(h, /other sensitive items/);
  // A malformed page (negative) makes the whole result the error state, still with nothing leaked.
  const bad = html(sc(reconcile(verdictOf("safe_to_send", false) as any, 1), { clean: false, totalFindings: 1, regions: [{ ...region("email"), page: -4, preview: hostile }] }));
  assert.match(bad, /data-look="error"/);
  assert.ok(!bad.includes("jordan.sample") && !bad.includes("onerror"));
});

test("sensitiveRows: groups kinds by their pages, counts, and phrases pages", () => {
  const rows = sensitiveRows(
    {
      regions: [region("email"), region("phone"), region("email", 1), region("card", 1), region("card", 1)],
      survivors: [region("ssn", 4)],
      offPage: [{ source: "metadata", kind: "email", preview: "x" }],
    },
    true,
  );
  assert.equal(rows.total, 7);
  assert.deepEqual(rows.rows, [
    "2 email addresses on pages 1 and 2",
    "1 phone number on page 1",
    "2 card numbers on page 2",
    "1 social security number on page 5",
    "1 email address outside the page text",
  ]);
  assert.equal(sensitiveRows({ regions: [region("ssn", 3)] }, false).rows[0], "1 social security number on page 4");
  assert.equal(sensitiveRows({ survivors: [region("ssn")] }, false).total, 0, "red's failed redaction is not counted as visible text");
  assert.equal(pagesPhrase([3]), "page 3");
  assert.equal(pagesPhrase([5, 1, 3, 3]), "pages 1, 3 and 5");
  assert.equal(pagesPhrase(Array.from({ length: 12 }, (_, i) => i + 1)), "12 pages");
});

test("[wasm] a failed redaction (text under a black box) plus visible text: red wins, the covered value is not listed as visible", async () => {
  const doc = await PDFDocument.create();
  const font = await doc.embedFont(StandardFonts.Helvetica);
  const page = doc.addPage([400, 400]);
  page.drawText("Fake Name 000-00-0000", { x: 100, y: 380, size: 12, font });
  page.drawText(`Mail ${EMAIL}`, { x: 20, y: 300, size: 12, font });
  page.drawRectangle({ x: 95, y: 374, width: 160, height: 20, color: rgb(0, 0, 0) });
  const { res, doc: file } = await callCheck({}, Buffer.from(await doc.save()));
  const sc = res.structuredContent;
  assert.equal(sc.verdict.verdict, "needs_review");
  assert.equal(sc.verdict.blocking, true, "the engine itself reports the failed redaction");
  assert.ok(sc.survivors.length >= 1, "fixture: a value under the box");
  const html = cardFor(file, res);
  assert.match(html, /data-look="blocking"/);
  assert.ok(html.includes("<h3>Needs Review — problems found</h3>"));
  assert.ok(html.includes("SENSITIVE TEXT STILL VISIBLE"));
  assert.ok(html.includes('class="cnt c-amber">1 ⚠</span>'), html);
  assert.ok(html.includes("1 email address on page 1"), html);
  assert.ok(!html.includes("social security number"), "the value under the box is the failure, not visible text");
  assert.ok(html.includes(">Open in Omitly to fix</button>"));
  assert.deepEqual(leaksAny(html, res), []);
});

test("sensitiveRows: a text-layer entry inside a survivor of the same kind and page is the same value", () => {
  const box = (kind: string, x: number, w: number, page = 0) => ({ page, x, y: 376.4, width: w, height: 14.4, kind, preview: "•••" });
  const survivor = box("ssn", 100, 133.4);
  const inside = box("ssn", 165.35, 68.04);
  assert.equal(sensitiveRows({ regions: [inside], survivors: [survivor] }, false).total, 0);
  assert.equal(sensitiveRows({ regions: [inside], survivors: [survivor] }, true).total, 1, "counted once, as the survivor");
  // Another page, another kind or a box outside the survivor is a different value.
  assert.equal(sensitiveRows({ regions: [box("ssn", 165.35, 68.04, 1)], survivors: [survivor] }, false).total, 1);
  assert.equal(sensitiveRows({ regions: [box("email", 165.35, 68.04)], survivors: [survivor] }, false).total, 1);
  assert.equal(sensitiveRows({ regions: [box("ssn", 300, 40)], survivors: [survivor] }, false).total, 1);
});
