/**
 * omitly#1864, round 5 (Codex gpt-6.1-sol on 717e13a0, 7 findings): each test reproduces one finding with REAL
 * captured replies (testing/goldens/*.json) changed in the one way the finding names, and passes only when
 * the reply no longer reads as a pass. Positive controls use the unchanged goldens.
 */
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { buildModel, renderCardHtml, type CardContext } from "./result-card.js";
import { auditCaps, WHY } from "./outcome.js";
import { PRODUCT_NOTICES } from "./seal.js";
import { parseCheckEnvelope, parseRedactAudit, parseScanReply, parseSealEnvelope, parseSealReply, parseSidecarVerifyReply } from "./replies.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const native: any = JSON.parse(readFileSync(path.join(HERE, "..", "src", "testing", "goldens", "native.json"), "utf8"));
const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v));
const gold = (list: any[], pdfEnds: string) => clone(list.find((e) => e.pdf.endsWith(pdfEnds))!.reply);
const ENV_KEYS = ["OMITLY_ALLOWED_DIR", "OMITLY_REDACT_BIN", "OMITLY_PDF_BIN", "OMITLY_ENGINE_DIR", "OMITLY_STATE_DIR"] as const;
const CTX: CardContext = { version: "5.6.0", deviceNoun: "Mac", now: new Date(2026, 10, 13, 9, 0, 0), canOpen: true };
const textOf = (res: any) => (res.content ?? []).filter((c: any) => c.type === "text").map((c: any) => c.text).join("\n");
const cardOf = (sc: unknown, isError?: boolean) => renderCardHtml(buildModel({ arguments: { pdfPath: "/x/a.pdf" } }, { structuredContent: sc, isError }, CTX));
let counter = 0;

async function rig() {
  const root = realpathSync(mkdtempSync(path.join(tmpdir(), "omitly-r5-")));
  for (const k of ENV_KEYS) delete process.env[k];
  process.env.OMITLY_ALLOWED_DIR = root;
  process.env.OMITLY_STATE_DIR = path.join(root, "state");
  const bin = path.join(root, "stub-engine.mjs");
  const cfgPath = path.join(root, "config.json");
  writeFileSync(bin, `#!/usr/bin/env node
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
`, { mode: 0o755 });
  chmodSync(bin, 0o755);
  process.env.OMITLY_REDACT_BIN = bin;
  const doc = path.join(root, "doc.pdf");
  writeFileSync(doc, "%PDF-1.4\n% not parsed: the engine is scripted\n");
  counter += 1;
  const mod = (await import(`./index.js?r5=${counter}`)) as typeof import("./index.js");
  const server = mod.createServer();
  const client = new Client({ name: "t", version: "0" });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(a), client.connect(b)]);
  return {
    doc,
    script: (cfg: Record<string, unknown>) => writeFileSync(cfgPath, JSON.stringify(cfg)),
    sidecar: () => writeFileSync(`${doc}.audit.json`, "[]"),
    call: (name: string, args: Record<string, unknown> = {}): Promise<any> => client.callTool({ name, arguments: { pdfPath: doc, ...args } }),
    close: async () => {
      await client.close();
      await server.close();
    },
  };
}
const POSITIVE = /Safe to Send|No recoverable PII|✅|Verification: pass/; // contract §8.2: the seal wording "these bytes are unchanged" is no longer a pass marker

// ---- 1. [P1] the nested `result` of a v2 seal reply and of a redaction audit ------------------------------------------------

const BLOCKING_RESULT = (r: any) => ({ ...r, state: "needs_review", blocking: true, problems: [{ text: "Text under a box on page 1" }], summary: "This file should not be sent." });
const SEAL_V2 = () => gold(native.verify_seal, "compat/v5.3.0.pdf");
const NESTED_SEAL: [string, (g: any) => void][] = [
  ["result replaced by a blocking Needs Review with a problem", (g) => { g.result = BLOCKING_RESULT(g.result); }],
  ["result deleted", (g) => { delete g.result; }],
  ["result null", (g) => { g.result = null; }],
  ["result is Safe to Send but lists a problem", (g) => { g.result.problems = [{ text: "x" }]; }],
  ["result is Safe to Send but lists a review item", (g) => { g.result.review = [{ text: "x" }]; }],
  ["result state disagrees with the userVerdict", (g) => { g.result.state = "needs_review"; }],
  ["result blocking disagrees with blocking", (g) => { g.result.blocking = true; }],
  ["result read fewer pages than the file has", (g) => { g.result.pagesRead = 0; }],
];

test("1a: a v2 seal reply whose nested result is not the Safe to Send its outer fields claim is no pass (real v5.3.0 golden, changed)", async () => {
  assert.equal(parseSealReply(SEAL_V2()).ok, true, "positive control: the real reply");
  const r = await rig();
  try {
    r.script({ verify_seal: SEAL_V2() });
    for (const tool of ["verify_seal", "verify_document"]) {
      const ok = await r.call(tool);
      // Contract §3.5: a seal is integrity only, so even the real v5.3.0 pass is `incomplete`, never `safe_to_send`.
      assert.equal(ok.structuredContent.outcome, "incomplete", `${tool}: positive control`);
    }
    for (const [label, mutate] of NESTED_SEAL) {
      const g = SEAL_V2();
      mutate(g);
      assert.equal(parseSealReply(g).ok, false, label);
      r.script({ verify_seal: g });
      for (const tool of ["verify_seal", "verify_document"]) {
        const res = await r.call(tool);
        assert.doesNotMatch(textOf(res), POSITIVE, `${tool} / ${label}\n${textOf(res)}`);
        assert.notEqual(res.structuredContent?.outcome, "safe_to_send", `${tool} / ${label}`);
        assert.equal(res.isError, true, `${tool} / ${label}: contradicting reply is an execution failure`);
      }
    }
  } finally {
    await r.close();
  }
});

test("1b: a redaction audit's nested result must be the verdict its outer fields claim (real redact_entities and redact goldens)", async () => {
  const pass = () => clone(native.redact_entities[0].reply);
  const review = () => clone(native.redact[0].reply);
  assert.equal(parseRedactAudit(pass().audit).ok, true, "positive control: Safe to Send");
  assert.equal(parseRedactAudit(review().audit).ok, true, "positive control: a real review_required audit");
  const defects: [string, any][] = [
    ["result replaced by a blocking Needs Review", (() => { const g = pass(); g.audit.result = BLOCKING_RESULT(g.audit.result); return g; })()],
    ["result deleted", (() => { const g = pass(); delete g.audit.result; return g; })()],
    ["result lists a problem", (() => { const g = pass(); g.audit.result.problems = [{ text: "x" }]; return g; })()],
  ];
  const r = await rig();
  try {
    for (const [label, g] of defects) {
      assert.equal(parseRedactAudit(g.audit).ok, false, label);
      r.script({ redact: g, redact_entities: g });
      const a = await r.call("redact_pdf", { outputPath: r.doc + ".o.pdf", regions: [{ page: 0, x: 1, y: 2, width: 3, height: 4 }] });
      assert.equal(a.isError, true, `${label}\n${textOf(a)}`);
      assert.doesNotMatch(textOf(a), /Safe to Send|Verification: pass/, label);
    }
  } finally {
    await r.close();
  }
});

// ---- 2. [P1] redaction warnings -----------------------------------------------------------------------------------------------

test("2: an engine warning beside a redaction pass is read (it caps at needs_review, W7); a missing or non-text warning list is no audit; the appended licence notices are not engine warnings", () => {
  const pass = () => clone(native.redact_entities[0].reply.audit);
  assert.match(pass().warnings[0], /^Marked as evaluation output\./, "the real pass carries the trial notice: positive control");
  assert.equal(parseRedactAudit(pass()).ok, true);
  const caps = (a: any) => auditCaps((parseRedactAudit(a) as any).value.audit);
  // Contract §3.6 (A3): the parser's "pass beside an engine warning" failure is gone; the warning is a cap.
  for (const [label, mutate] of [
    ["an engine warning beside the notice", (a: any) => { a.warnings.push("Page 1: inline image content could not be analysed"); }],
    ["an engine warning alone", (a: any) => { a.warnings = ["Page 1: content could not be parsed"]; }],
  ] as [string, (a: any) => void][]) {
    const a = pass();
    mutate(a);
    assert.equal(parseRedactAudit(a).ok, true, label);
    assert.ok(caps(a).some((c) => c.why === WHY.W7), label);
  }
  for (const [label, mutate] of [
    ["no warnings field", (a: any) => { delete a.warnings; }],
    ["warnings null", (a: any) => { a.warnings = null; }],
    ["a warning that is not text", (a: any) => { a.warnings = [7]; }],
  ] as [string, (a: any) => void][]) {
    const a = pass();
    mutate(a);
    assert.equal(parseRedactAudit(a).ok, false, label);
  }
  // Each product notice the CLI appends is not an engine warning.
  for (const notice of PRODUCT_NOTICES) {
    const a = pass();
    a.warnings = [notice];
    assert.equal(parseRedactAudit(a).ok, true, notice.slice(0, 30));
    assert.ok(!caps(a).some((c) => c.why === WHY.W7), notice.slice(0, 30));
  }
  // A non-pass audit keeps its warnings.
  const fail = clone(native.redact[0].reply.audit);
  fail.warnings.push("Page 1: a warning");
  assert.equal(parseRedactAudit(fail).ok, true);
});

// ---- 3. [P1] not_scanned disclosures that deny completion -----------------------------------------------------------------------

/** The `not_scanned` lines detect.rs adds exactly when it holds `scan_complete` false (detect.rs:4596-4612, 4640-4745). */
const BLOCKING_DISCLOSURES = [
  "1 page(s) are effectively image-only (raster content, fewer than 100 extractable text characters) — this build never OCRs, so any text inside those images was not read",
  "CID/Identity-H text with a code not covered by the ToUnicode map, simple-font text whose declared ToUnicode map could not be read, or simple-font text with a code its encoding does not determine (present in this file)",
  "Type0/CID text using a named encoding whose codespace ranges could not be verified (present in this file)",
  "2 embedded content stream(s) that failed to parse or could not be fully decoded",
  "1 Form XObject(s) showing text in a font set by the page that draws them (that text may be misread)",
  "embedded-file attachment name tree could not be fully scanned",
  "1 page(s) could not be fully checked for text surviving under a redaction mark (the content stream failed to decode, a cover could not be followed, or the characters under it could not be determined) — a redaction on this page is unproven, not confirmed clean",
  "1 prior (superseded) revision(s) could not be scanned for leftover PII (an object or content stream in that revision failed to parse or decode, exceeded the size cap, or held text this build cannot read) — a prior revision left unscanned is unproven, not confirmed clean",
  "AcroForm field tree deeper than 16 levels was not fully scanned",
  "XMP metadata stream was truncated",
  "XMP metadata stream could not be read as text (invalid UTF-16); only its raw bytes and decoded text were scanned",
  "attachment 'a.txt' was still compressed",
  "the file's structure (object streams, cross-reference data or stream lengths) did not read the same way twice, so some objects may not have been read: object 1 is listed in the cross-reference table but could not be read",
];
/** Disclosures that do NOT deny completion (detect.rs: they are not inputs of `scan_complete`). */
const LEGITIMATE_LIMITS = [
  "text drawn as raster images (needs OCR)",
  "text in font(s) \"F1\" that may be drawn as different characters than the text read (a code's glyph is a digit under a letter, a different digit, or the font's .notdef glyph): not verified as drawn",
];

test("3: scan_complete true beside a not_scanned disclosure that denies completion is no scan result, in the parser, the tools and the bundle port", async () => {
  const sample = () => {
    const g = native.find.find((e: any) => e.pdf.endsWith("sample.pdf") && !e.regions).reply;
    return clone(g);
  };
  assert.equal(sample().scan_complete, true, "the real sample.pdf scan is complete: positive control");
  assert.equal(parseScanReply(sample()).ok, true);
  for (const line of LEGITIMATE_LIMITS) {
    const g = sample();
    g.coverage.not_scanned = [line];
    assert.equal(parseScanReply(g).ok, true, `a legitimate limit: ${line.slice(0, 40)}`);
  }
  const r = await rig();
  try {
    for (const line of BLOCKING_DISCLOSURES) {
      const g = sample();
      g.coverage.not_scanned = [line];
      assert.equal(parseScanReply(g).ok, false, line.slice(0, 50));
      // The same line beside an honest scan_complete false is a normal incomplete scan.
      const honest = sample();
      honest.coverage.not_scanned = [line];
      honest.scan_complete = false;
      honest.coverage.scan_complete = false;
      assert.equal(parseScanReply(honest).ok, true, `honest: ${line.slice(0, 50)}`);
    }
    const g = sample();
    g.coverage.not_scanned = [BLOCKING_DISCLOSURES[2]];
    r.script({ find: g, check: { ok: true, check: clone(native.check[0].reply.check) } });
    for (const tool of ["check_redaction", "find_sensitive_regions", "verify_redaction"]) {
      const res = await r.call(tool);
      assert.equal(res.isError, true, `${tool}\n${textOf(res)}`);
      assert.doesNotMatch(textOf(res), POSITIVE, tool);
    }
  } finally {
    await r.close();
  }
  // The bundle's CommonJS port holds the same rule.
  const cjs = await import("node:module").then((m) => m.createRequire(import.meta.url)(path.join(HERE, "..", "mcpb", "server", "replies.js")));
  for (const line of BLOCKING_DISCLOSURES) {
    const g = sample();
    g.coverage.not_scanned = [line];
    assert.equal(cjs.parseScanReply(g).ok, false, `bundle: ${line.slice(0, 50)}`);
    assert.equal(cjs.parseScanReply(g).reason, parseScanReply(g).ok ? "" : (parseScanReply(g) as any).reason);
  }
  for (const line of LEGITIMATE_LIMITS) {
    const g = sample();
    g.coverage.not_scanned = [line];
    assert.equal(cjs.parseScanReply(g).ok, true, `bundle limit: ${line.slice(0, 40)}`);
  }
});

// ---- 4. [P1] the ten hidden-content checks of a sidecar verify -------------------------------------------------------------------

test("4: a sidecar verify 'pass' needs the complete, unique set of ten hidden-content checks (verify.rs:233-308); the real reply has them", async () => {
  const pass = () => clone(native.verify[0].reply);
  const CLASSES = pass().hiddenContent.map((c: any) => c.class);
  assert.equal(CLASSES.length, 10, "the real engine sends ten");
  assert.equal(parseSidecarVerifyReply(pass()).ok, true, "positive control");
  const dup = pass();
  dup.hiddenContent[9] = clone(dup.hiddenContent[0]);
  const unknown = pass();
  unknown.hiddenContent[3].class = "something-new";
  const missingOne = pass();
  missingOne.hiddenContent.splice(4, 1);
  const none = pass();
  none.hiddenContent = [];
  const reordered = pass();
  reordered.hiddenContent.reverse();
  for (const [label, g, ok] of [
    ["empty hiddenContent with a pass", none, false],
    ["one class missing", missingOne, false],
    ["a class twice", dup, false],
    ["an unknown class", unknown, false],
    ["the same ten in another order", reordered, true],
  ] as const) assert.equal(parseSidecarVerifyReply(g).ok, ok, label);
  const r = await rig();
  try {
    r.sidecar();
    const clean = { find: clone(native.find.find((e: any) => e.pdf.endsWith("clean-text.pdf") && !e.regions).reply), check: clone(native.check.find((e: any) => e.pdf.endsWith("clean-text.pdf")).reply) };
    r.script({ ...clean, verify: none });
    const res = await r.call("verify_redaction");
    assert.equal(res.isError, true, textOf(res));
    assert.notEqual(res.structuredContent?.clean, true);
    r.script({ ...clean, verify: pass() });
    const ok = await r.call("verify_redaction");
    assert.equal(ok.isError, false, "positive control through the tool");
    assert.equal(ok.structuredContent.outcome, "safe_to_send", "a real passing sidecar adds nothing to a passing pipeline");
  } finally {
    await r.close();
  }
});

// ---- 5. [P1] the two scan legs of check_redaction -------------------------------------------------------------------------------

test("5: a real check that lists visible values beside an empty, complete scan is an execution failure, never Safe to Send (a standalone check stays valid)", async () => {
  const sampleCheck = () => ({ ok: true, check: clone(native.check.find((e: any) => e.pdf.endsWith("tests/fixtures/sample.pdf")).reply.check) });
  const lines = sampleCheck().check.result.information.map((i: any) => i.text);
  assert.ok(lines.some((t: string) => t.startsWith("Sensitive-looking text is visible on pages 1 and 2 (3 values)")), "the real check lists 3 visible values");
  const emptyScan = clone(native.find.find((e: any) => e.pdf.endsWith("invisible-text.pdf")).reply);
  assert.equal(emptyScan.total_findings, 0);
  const r = await rig();
  try {
    r.script({ find: emptyScan, check: sampleCheck() });
    const res = await r.call("check_redaction");
    assert.equal(res.isError, true, textOf(res));
    assert.doesNotMatch(textOf(res), POSITIVE, textOf(res));
    assert.equal(res.structuredContent, undefined, "no structured result");
    assert.match(textOf(res), /disagree/);
    // Positive controls: the same check beside the scan that found the 3 values is a result (not a pass); a standalone check is valid.
    const found = clone(native.find.find((e: any) => e.pdf.endsWith("tests/fixtures/sample.pdf") && !e.regions).reply);
    r.script({ find: found, check: sampleCheck() });
    const both = await r.call("check_redaction");
    assert.equal(both.isError, false);
    assert.equal(both.structuredContent.outcome, "needs_review");
    // The card handed such an envelope draws the error state, not green.
    const env = clone(both.structuredContent);
    Object.assign(env, { clean: true, totalFindings: 0, regions: [], byKind: {}, outcome: "needs_review" });
    env.verdict.result.information = [{ text: "Sensitive-looking text is visible on pages 1 and 2 (3 values).", pages: [1, 2] }];
    assert.equal(parseCheckEnvelope(env).ok, false, "an engine's visible-text line beside an empty scan");
    assert.match(cardOf(env), /data-look="error"/);
    env.verdict.result.information = [];
    assert.equal(parseCheckEnvelope(env).ok, true, "the same envelope without the line is read");
  } finally {
    await r.close();
  }
});

// ---- 6. [P2] the seal-card envelope's outcome ----------------------------------------------------------------------------------------

test("6: the seal envelope's outcome must be one the seal table issues: a missing, unknown or safe_to_send outcome is the error state; the look follows the outcome", () => {
  const sc = (over: Record<string, unknown> = {}) => ({
    outcome: "incomplete",
    seal: { state: "held", version: null, eraLabel: null, fingerprint: "ab12cd34ef56", keyKind: null },
    embeddedReport: null,
    ...over,
  });
  const look = (o: unknown) => /data-look="(\w+)"/.exec(cardOf(o))![1];
  assert.equal(look(sc()), "cannot", "positive control");
  assert.equal(look(sc({ outcome: "needs_review" })), "review");
  assert.equal(look(sc({ outcome: "not_a_pass" })), "blocking");
  for (const outcome of [undefined, "safe_to_send", "fine", 7, null]) {
    assert.equal(parseSealEnvelope(sc({ outcome })).ok, false, String(outcome));
    assert.equal(look(sc({ outcome })), "error", String(outcome));
  }
  assert.equal(parseSealEnvelope(sc({ seal: { state: "fine" } })).ok, false);
});

// ---- 7. [P2] `regions: []` is a narrowing ---------------------------------------------------------------------------------------------

test("7: a native find asked for `regions: []` lists the generic kinds only and keeps the unfiltered total; that real reply is read (main.rs:822-831, detect.rs:2875-2880)", async () => {
  const golden = clone(native.find.find((e: any) => e.regions && e.regions.length === 0).reply);
  assert.deepEqual(golden.regions.map((x: any) => x.kind), ["email", "card"], "sample.pdf: Rust lists email and card");
  assert.equal(golden.total_findings, 3, "and keeps the unfiltered total");
  assert.equal(parseScanReply(golden, { narrowed: true }).ok, true);
  const r = await rig();
  try {
    r.script({ find: golden });
    const res = await r.call("find_sensitive_regions", { regions: [] });
    assert.ok(!res.isError, textOf(res));
    assert.equal(res.structuredContent.count, 2);
    // Not asking for a narrowing: the same reply is a count that disagrees with its list.
    const plain = await r.call("find_sensitive_regions");
    assert.equal(plain.isError, true);
  } finally {
    await r.close();
  }
});

// ---- K1 [MED, Kimi]: the card agrees with `outcome`; text under a mark is never "visible" ------------------------------------------

test("K1: a survivor-only scan beside an engine Safe to Send is a failed redaction everywhere: red card, blocking Needs Review, not_a_pass; never amber 'visible' (real covered-text golden, regions removed)", async () => {
  const covered = clone(native.find.find((e: any) => e.pdf.endsWith("covered-text.pdf")).reply);
  assert.equal(covered.survivors.length, 1, "the real scan lists one value under the box");
  const onlySurvivor = { ...covered, regions: [], count: 0, total_findings: 1 };
  assert.equal(parseScanReply(onlySurvivor).ok, true);
  const safeCheck = () => {
    const c = clone(native.check.find((e: any) => e.pdf.endsWith("tests/fixtures/sample.pdf")).reply.check);
    c.result.information = c.result.information.filter((i: any) => !i.text.startsWith("Sensitive-looking text is visible"));
    return { ok: true, check: c };
  };
  const r = await rig();
  try {
    r.script({ find: onlySurvivor, check: safeCheck() });
    const res = await r.call("check_redaction");
    const sc = res.structuredContent;
    assert.equal(res.isError, false, textOf(res));
    assert.equal(sc.outcome, "not_a_pass");
    assert.equal(sc.verdict.verdict, "needs_review");
    assert.equal(sc.verdict.blocking, true, "text under a mark is a failed redaction: blocking, as the outcome says");
    assert.equal(sc.verdict.result.blocking, true);
    assert.ok(sc.verdict.result.problems.some((p: any) => /under a redaction mark/.test(p.text)), JSON.stringify(sc.verdict.result.problems));
    assert.match(textOf(res), /^⚠️ NOT A PASS — text is still present under a redaction mark \(1 item\(s\)\); 1 sensitive item\(s\) found\./);
    const html = cardOf(sc, res.isError);
    assert.match(html, /data-look="blocking"/, "red, like the outcome");
    assert.doesNotMatch(html, /sensitive text is visible|SENSITIVE TEXT STILL VISIBLE|data-look="visible"/, "never counted as visible text");
    // The card handed a result from an older server (no outcome) is the error state (contract §3.8: the look is a function of `outcome`).
    const old = clone(sc);
    delete old.outcome;
    assert.match(cardOf(old), /data-look="error"/);
    assert.doesNotMatch(cardOf(old), /sensitive text is visible/);
    // And the card never draws a result whose outcome is not_a_pass as anything but red.
    const sameOutcome = clone(sc);
    sameOutcome.outcome = "needs_review";
    assert.match(cardOf(sameOutcome), /data-look="error"/, "an outcome that disagrees is the error state");
    // A refusal with no result and a survivor is still red.
    const refusal = clone(sc);
    refusal.verdict = { verdict: "cannot_verify", blocking: false, result: null, reason_code: "input_too_large" };
    assert.match(cardOf(refusal), /data-look="blocking"/);
  } finally {
    await r.close();
  }
});

// ---- K2 [LOW, Kimi]: a narrowed native find says what it lists ---------------------------------------------------------------------

test("K2: a narrowed native find's NOT A PASS count and its note agree: '3 found', '2 listed of 3' (real regions: [\"au\"] golden)", async () => {
  const golden = clone(native.find.find((e: any) => e.regions && e.regions[0] === "au").reply);
  assert.equal(golden.total_findings, 3);
  assert.equal(golden.regions.length, 2);
  const r = await rig();
  try {
    r.script({ find: golden });
    const res = await r.call("find_sensitive_regions", { regions: ["au"] });
    const text = textOf(res);
    assert.ok(!res.isError, text);
    assert.match(text, /^⚠️ NOT A PASS — 3 sensitive item\(s\) found[.;]/, text);
    assert.match(text, /Found 2 candidate region\(s\)/);
    assert.match(text, /Note: Narrowed to the requested regions: 2 of 3 item\(s\) found are listed/, text);
    assert.match(res.structuredContent.note, /2 of 3/);
    // Not narrowed: no note, and the count is the list.
    r.script({ find: clone(native.find.find((e: any) => e.pdf.endsWith("sample.pdf") && !e.regions).reply) });
    const plain = await r.call("find_sensitive_regions");
    assert.doesNotMatch(textOf(plain), /Narrowed/);
  } finally {
    await r.close();
  }
});
