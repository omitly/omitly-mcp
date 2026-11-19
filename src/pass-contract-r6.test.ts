/**
 * omitly#1864, round 6 (Codex gpt-6.1-sol on d48d5ac1, 5 findings): each test reproduces one finding with REAL
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
import { parseCheckEnvelope, parseRedactAudit, parseScanReply, parseSealEnvelope, parseSealReply } from "./replies.js";

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
  const root = realpathSync(mkdtempSync(path.join(tmpdir(), "omitly-r6-")));
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
  const mod = (await import(`./index.js?r6=${counter}`)) as typeof import("./index.js");
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


const BIG = "(generated: tests/fixtures/covered-text.pdf plus a 66 MiB unreferenced stream)";
const sealGold = (end: string) => gold(native.verify_seal, end);

// ---- 1. [P1] legacy v1 seal replies -------------------------------------------------------------------------------------------------

/** What a CURRENT-build v1 seal reply looks like: the real legacy golden without the legacy flag and its CAUTION line
 *  (omitly-seal lib.rs:1087 adds that line exactly when `legacy_unbound_verdict` is true). Real v1 seals are no longer minted. */
const currentV1 = () => {
  const g = sealGold("positive/clean-sealed.pdf");
  g.legacyUnboundVerdict = false;
  g.warnings = g.warnings.filter((w: string) => !w.startsWith("CAUTION:"));
  return g;
};

test("1: a v1 'verified' needs metadataScrubbed and no engine warning to read as a pass, and a legacy integrity-only seal is not a clean pass (real clean-sealed golden)", async () => {
  const legacy = sealGold("positive/clean-sealed.pdf");
  assert.equal(legacy.legacyUnboundVerdict, true, "the real vector is a pre-#506 seal");
  assert.equal(parseSealReply(legacy).ok, true, "a real reply is read");
  assert.equal(parseSealReply(currentV1()).ok, true, "positive control: a current-build v1 pass");
  const DEFECTS: [string, (g: any) => void][] = [
    ["metadataScrubbed false", (g) => { g.metadataScrubbed = false; }],
    ["an engine warning", (g) => { g.warnings.push("Page 1: inline image content could not be analysed"); }],
    ["metadataScrubbed and warnings deleted", (g) => { delete g.metadataScrubbed; delete g.warnings; }],
    ["warnings deleted", (g) => { delete g.warnings; }],
    ["metadataScrubbed null", (g) => { g.metadataScrubbed = null; }],
    ["the legacy flag deleted", (g) => { delete g.legacyUnboundVerdict; }],
    ["a CAUTION line without the legacy flag", (g) => { g.warnings.push("CAUTION: this file was sealed by a build predating the omitly#506 sign-path gate — a valid seal here proves integrity since sealing, not that the verdict describes this content"); }],
  ];
  const r = await rig();
  try {
    r.script({ verify_seal: currentV1() });
    for (const tool of ["verify_seal", "verify_document"]) {
      const ok = await r.call(tool);
      // Contract §3.5: no seal result is a pass; a current-build v1 pass is S8, `incomplete`, look `cannot`.
      assert.equal(ok.structuredContent.outcome, "incomplete", `${tool}: positive control`);
      assert.match(cardOf(ok.structuredContent), /data-look="cannot"/);
    }
    for (const [label, mutate] of DEFECTS) {
      const g = currentV1();
      mutate(g);
      // A reply with a field missing, an engine warning or a legacy flag that contradicts its caution is no seal reply (execution
      // failure); metadata that was not scrubbed is a reply, read as a review.
      const read = label === "metadataScrubbed false" || label === "an engine warning" || label === "a CAUTION line without the legacy flag"; // errata C1: a report's own CAUTION-looking line is a report warning (S7) // contract §3.5: S6 and S7 are reads (needs_review), not failures
      assert.equal(parseSealReply(g).ok, read, label);
      r.script({ verify_seal: g });
      for (const tool of ["verify_seal", "verify_document"]) {
        const res = await r.call(tool);
        if (!read) assert.equal(res.isError, true, `${tool} / ${label}\n${textOf(res)}`);
        assert.doesNotMatch(textOf(res), POSITIVE, `${tool} / ${label}\n${textOf(res)}`);
        assert.notEqual(res.structuredContent?.outcome, "safe_to_send", `${tool} / ${label}`);
        if (label === "an engine warning" || label === "a CAUTION line without the legacy flag") assert.equal(res.structuredContent.outcome, "needs_review", `${tool} / ${label}: S7`);
        if (res.structuredContent) assert.doesNotMatch(cardOf(res.structuredContent, res.isError), /data-look="safe"/, `${tool} / ${label}: a green card`);
      }
    }
    // The real legacy seal: integrity only, never a clean document pass, and said so.
    r.script({ verify_seal: legacy });
    for (const tool of ["verify_seal", "verify_document"]) {
      const res = await r.call(tool);
      assert.equal(res.isError, false, tool);
      assert.equal(res.structuredContent.outcome, "incomplete", `${tool}: a legacy seal`);
      assert.ok(textOf(res).startsWith("⚠️"), textOf(res));
      assert.doesNotMatch(textOf(res), POSITIVE, textOf(res));
      assert.doesNotMatch(cardOf(res.structuredContent), /data-look="safe"/);
    }
    // Metadata not scrubbed (a request to preserve it is not told apart from a failure): needs review, not green.
    const g = currentV1();
    g.metadataScrubbed = false;
    r.script({ verify_seal: g });
    const m = await r.call("verify_seal");
    assert.equal(m.isError, false);
    assert.equal(m.structuredContent.outcome, "needs_review");
    assert.doesNotMatch(cardOf(m.structuredContent), /data-look="safe"/);
  } finally {
    await r.close();
  }
});

// ---- 2 + 3. [P1][P2] the card's coverage and the dotall disclosure patterns -------------------------------------------------------------

const cleanEnvelope = (notScanned: string[]) => {
  const covered = clone(native.check.find((e: any) => e.pdf.endsWith("tests/fixtures/sample.pdf")).reply.check);
  covered.result.information = [];
  return {
    scanComplete: true, clean: true, totalFindings: 0, byKind: {}, regions: [], survivors: [], offPage: [],
    coverage: { pagesScanned: 1, pagesTotal: 1, notScanned, priorRevisionsScanned: false, metadataScanned: true, acroformScanned: false, attachmentsScanned: false, formXobjectsScanned: 0, annotationAppearancesScanned: 0, pagesFailedCount: 0 },
    verdict: { verdict: "safe_to_send", blocking: false, reason_code: null, result: (({ canWrite: _w, producer: _p, ...x }) => ({ ...x, decisionChannel: "none" }))(covered.result) },
    outcome: "safe_to_send",
  };
};
const envLook = (sc: unknown) => /data-look="(\w+)"/.exec(cardOf(sc))![1];

test("2: the card refuses a complete, clean envelope whose coverage.notScanned holds a disclosure that denies completion; a legitimate limit is still green", () => {
  assert.equal(envLook(cleanEnvelope([])), "safe", "positive control");
  assert.equal(envLook(cleanEnvelope(["text drawn as raster images (needs OCR)"])), "safe", "a legitimate limit");
  for (const line of [
    "XMP metadata stream was truncated",
    "1 page(s) are effectively image-only (raster content, fewer than 100 extractable text characters) — this build never OCRs, so any text inside those images was not read",
    "Type0/CID text using a named encoding whose codespace ranges could not be verified (present in this file)",
  ]) {
    const env = cleanEnvelope([line]);
    assert.equal(parseCheckEnvelope(env).ok, false, line.slice(0, 40));
    assert.equal(envLook(env), "error", line.slice(0, 40));
  }
  // The same line beside an honest incomplete scan is an ordinary incomplete result.
  const honest: any = cleanEnvelope(["XMP metadata stream was truncated"]);
  honest.scanComplete = false;
  honest.verdict = { verdict: "cannot_verify", blocking: false, reason_code: null, result: { ...honest.verdict.result, state: "cannot_verify", summary: "x", reasons: [{ text: "Could not complete" }] } };
  honest.outcome = "incomplete";
  assert.equal(parseCheckEnvelope(honest).ok, true);
});

test("3: a completion-denying disclosure is matched across line terminators in the interpolated attachment name (detect.rs:4024), in the parser, the card and the bundle port", async () => {
  const sample = () => clone(native.find.find((e: any) => e.pdf.endsWith("sample.pdf") && !e.regions).reply);
  const cjs = (await import("node:module")).createRequire(import.meta.url)(path.join(HERE, "..", "mcpb", "server", "replies.js"));
  for (const name of ["sensitive\nnotes.txt", "a\r\nb.txt", "a\u2028b.txt", "a\u2029b.txt", "plain.txt"]) {
    const line = `attachment '${name}' was truncated`;
    const g = sample();
    g.coverage.not_scanned = [line];
    assert.equal(parseScanReply(g).ok, false, JSON.stringify(line));
    assert.equal(cjs.parseScanReply(g).ok, false, `bundle: ${JSON.stringify(line)}`);
    assert.equal(envLook(cleanEnvelope([line])), "error", `card: ${JSON.stringify(line)}`);
  }
  // Sweep: no pattern uses a bare wildcard (`.` stops at a line terminator), in either port.
  const { ENGINE_INCOMPLETE_DISCLOSURES } = await import("./replies.js");
  const sources = [...ENGINE_INCOMPLETE_DISCLOSURES.map((r) => r.source), ...cjs.ENGINE_INCOMPLETE_DISCLOSURES.map((r: RegExp) => r.source)];
  for (const src of sources) assert.doesNotMatch(src.replace(/\\./g, ""), /\.[*+?{]/, `a bare wildcard in ${src}`);
  assert.deepEqual(cjs.ENGINE_INCOMPLETE_DISCLOSURES.map((r: RegExp) => r.source), ENGINE_INCOMPLETE_DISCLOSURES.map((r) => r.source), "the bundle port holds the same patterns");
});

// ---- 4. [P1] redaction audit regions must match what was asked ---------------------------------------------------------------------------

test("4: a redaction audit has one entry per requested region (engine.rs:1495); an empty, short, long or reordered list is an execution failure (real redact and redact_entities goldens)", async () => {
  const request = clone(native.redact[0].regions) as { page: number; x: number; y: number; width: number; height: number }[];
  const redactReply = () => clone(native.redact[0].reply);
  const entityReply = () => clone(native.redact_entities[0].reply);
  assert.equal(request.length, redactReply().audit.regions.length, "the real engine: one entry per request region");
  const r = await rig();
  try {
    r.script({ redact: redactReply(), redact_entities: entityReply() });
    const ok = await r.call("redact_pdf", { outputPath: r.doc + ".o.pdf", regions: request });
    assert.ok(!ok.isError, textOf(ok));
    const okEntity = await r.call("redact_by_entity", { outputPath: r.doc + ".o2.pdf" });
    assert.ok(!okEntity.isError, textOf(okEntity));
    const entityN = entityReply().redacted.length;
    assert.ok(entityN >= 2 && entityReply().audit.regions.length === entityN, "the real engine: one entry per selection");
    const mutations: [string, (g: any) => void][] = [
      ["audit.regions emptied", (g) => { g.audit.regions = []; }],
      ["one entry dropped", (g) => { g.audit.regions = g.audit.regions.slice(0, -1); }],
      ["an extra entry", (g) => { g.audit.regions = [...g.audit.regions, g.audit.regions[0]]; }],
      ["an entry for another page", (g) => { g.audit.regions[0].page = 9; }],
    ];
    for (const [label, mutate] of mutations) {
      const a = redactReply();
      mutate(a);
      r.script({ redact: a });
      const res = await r.call("redact_pdf", { outputPath: r.doc + ".o.pdf", regions: request });
      assert.equal(res.isError, true, `redact_pdf / ${label}\n${textOf(res)}`);
      assert.doesNotMatch(textOf(res), /Verification: pass|Safe to Send/, `redact_pdf / ${label}`);
      const e = entityReply();
      mutate(e);
      r.script({ redact_entities: e });
      const eres = await r.call("redact_by_entity", { outputPath: r.doc + ".o2.pdf" });
      assert.equal(eres.isError, true, `redact_by_entity / ${label}\n${textOf(eres)}`);
      assert.doesNotMatch(textOf(eres), /Verification: pass|Safe to Send/, `redact_by_entity / ${label}`);
    }
    // The parser itself, with the expectation.
    assert.equal(parseRedactAudit(redactReply().audit, { expected: request }).ok, true);
    assert.equal(parseRedactAudit({ ...redactReply().audit, regions: [] }, { expected: request }).ok, false);
  } finally {
    await r.close();
  }
});

// ---- 5. [P1] survivor promotion beside an engine refusal ---------------------------------------------------------------------------------

test("5: a file over the free check's size limit with survivors from the scan is a consistent blocking not_a_pass verdict, not an output the validator rejects (real captured pair)", async () => {
  const find = clone(native.find.find((e: any) => e.pdf === BIG).reply);
  const check = clone(native.check.find((e: any) => e.pdf === BIG).reply);
  assert.equal(check.check.reason_code, "input_too_large", "the real engine refuses it unread");
  assert.equal(find.survivors.length, 1, "and the scan still lists the survivor");
  const r = await rig();
  try {
    r.script({ find, check });
    const res = await r.call("check_redaction");
    const text = textOf(res);
    assert.equal(res.isError, false, text);
    const sc = res.structuredContent;
    assert.equal(sc.outcome, "not_a_pass");
    assert.equal(sc.verdict.verdict, "needs_review");
    assert.equal(sc.verdict.blocking, true);
    assert.equal(sc.verdict.reason_code, null, "a reason code is legal only with Cannot Verify");
    // The refusal evidence stays, in a legal form.
    assert.match(JSON.stringify(sc.verdict.result.notChecked), /larger than this checker accepts/, "listed under what could not be checked");
    assert.match(text, /^⚠️ NOT A PASS — /);
    assert.doesNotMatch(text, /Safe to Send/);
    assert.match(cardOf(sc), /data-look="blocking"/);
    // Positive control: the same refusal beside a clean scan is still Cannot Verify with its own code.
    r.script({ find: clone(native.find.find((e: any) => e.pdf.endsWith("invisible-text.pdf")).reply), check });
    const clean = await r.call("check_redaction");
    assert.equal(clean.isError, false);
    assert.equal(clean.structuredContent.verdict.verdict, "cannot_verify");
    assert.equal(clean.structuredContent.verdict.reason_code, "input_too_large");
  } finally {
    await r.close();
  }
});
