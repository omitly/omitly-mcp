/**
 * omitly#1864, round 4: a reply reads as a PASS (Safe to Send, verified, clean) only when the engine's FULL
 * pass contract holds, whichever tool, parser or surface it reaches. One test per review finding (Codex 1-8,
 * Kimi 3); each fails on the round-3 code (a9fd9135) and passes on this one. The Rust each rule comes from is
 * cited at the rule, in replies.ts.
 *
 * The scripted engine here sends DEFECTIVE replies the real engines never send (the goldens in
 * real-engine-goldens.test.ts are what they do send); every one must come out as no pass, and every
 * consistent reply built from the same pieces must still pass (the positive controls), so a parser that
 * refused everything would fail too.
 */
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { test } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { buildModel, renderCardHtml, type CardContext } from "./result-card.js";
import { parseCheckEnvelope, parseCheckVerdict, parseRedactAudit, parseScanReply, parseSealReply, parseSidecarVerifyReply } from "./replies.js";
import { normalizeSealResult } from "./seal.js";

const ENV_KEYS = ["OMITLY_ALLOWED_DIR", "OMITLY_REDACT_BIN", "OMITLY_PDF_BIN", "OMITLY_ENGINE_DIR", "OMITLY_STATE_DIR"] as const;
const CTX: CardContext = { version: "5.6.0", deviceNoun: "Mac", now: new Date(2026, 10, 13, 9, 0, 0), canOpen: true };
const textOf = (res: any) => (res.content ?? []).filter((c: any) => c.type === "text").map((c: any) => c.text).join("\n");
let counter = 0;

const COV = { pages_total: 1, pages_scanned: 1, pages_failed: [] as number[], not_scanned: [], prior_revisions_scanned: false, metadata_scanned: false, acroform_scanned: false, attachments_scanned: false, form_xobjects_scanned: 0, annotation_appearances_scanned: 0, raster_pages: [], raster_only_pages: [] as string[], scan_complete: true };
const FIND = (over: Record<string, unknown> = {}) => ({
  ok: true, scan_complete: true, clean: true, count: 0, total_findings: 0, regions: [], survivors: [], off_page: [], coverage: { ...COV }, ...over,
});
const region = (kind = "email") => ({ page: 0, x: 1, y: 2, width: 3, height: 4, kind, preview: "•••" });
const resultOf = (state: string, extra: Record<string, unknown> = {}) => ({
  state, blocking: false, summary: "Every mandatory check that applies to this file passed. 1 page checked.", pagesTotal: 1, pagesRead: 1,
  checked: [{ text: "Metadata" }], notChecked: [], problems: [], review: [], information: [], decisions: [], reasons: [],
  checkedAt: "2026-11-13T01:00:00Z", omitlyVersion: "5.6.0", sha256: "a".repeat(64), sizeBytes: 40, canWrite: false, producer: null, decisionChannel: "none", ...extra,
});
const verdictOf = (state: string, blocking = false, resultExtra: Record<string, unknown> = {}, over: Record<string, unknown> = {}) => ({
  verdict: state, blocking, reason_code: null, result: resultOf(state, { blocking, ...resultExtra }), ...over,
});
const CHECK = (v: unknown) => ({ ok: true, check: v });
/** The structured form (no desktop-only fields), as the card receives it. */
const outputResult = (state: string, extra: Record<string, unknown> = {}) => (({ canWrite: _w, producer: _p, ...x }) => x)(resultOf(state, extra));

async function rig() {
  const root = realpathSync(mkdtempSync(path.join(tmpdir(), "omitly-passcontract-")));
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
  const mod = (await import(`./index.js?pass-contract=${counter}`)) as typeof import("./index.js");
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
const look = (sc: unknown, isError?: boolean) =>
  /data-look="(\w+)"/.exec(renderCardHtml(buildModel({ arguments: { pdfPath: "/x/a.pdf" } }, { structuredContent: sc, isError }, CTX)))![1];

/** The invariant behind every case: no text holds a finding or an unread file beside Safe to Send, and the
 *  structure is no pass. */
function assertNoPass(name: string, res: any) {
  const text = textOf(res);
  assert.doesNotMatch(text, /Safe to Send|No recoverable PII|✅ Seal|Seal valid|these bytes are unchanged|seal are intact/, `${name}: a positive word\n${text}`);
  const sc = res.structuredContent;
  if (sc) {
    if (typeof sc.outcome === "string") assert.notEqual(sc.outcome, "safe_to_send", name);
    if (sc.verdict && typeof sc.verdict === "object") assert.notEqual(sc.verdict.verdict, "safe_to_send", name);
    assert.notEqual(sc.userVerdict, "safe_to_send", name);
    assert.notEqual(sc.verdict, "verified", name);
    assert.doesNotMatch(renderCardHtml(buildModel({ arguments: { pdfPath: "/x/a.pdf" } }, { structuredContent: sc, isError: res.isError }, CTX)), /data-look="safe"/, `${name}: a green card`);
  }
}

// ---- Codex 1 and 2: the verdict is the engine's whole pass contract, not its word ------------------------

const SAFE_DEFECTS: [string, any][] = [
  ["a bare safe_to_send word", { verdict: "safe_to_send" }],
  ["a safe wrapper around a blocking result", { ...verdictOf("safe_to_send"), result: resultOf("needs_review", { blocking: true, problems: [{ text: "Text under a box on page 1" }] }) }],
  ["Safe to Send with blocking true (wrapper and result)", verdictOf("safe_to_send", true)],
  ["Safe to Send with blocking true on the wrapper only", { ...verdictOf("safe_to_send"), blocking: true }],
  ["Safe to Send that lists a problem", verdictOf("safe_to_send", false, { problems: [{ text: "Text under a box on page 1" }] })],
  ["Safe to Send that lists a review item", verdictOf("safe_to_send", false, { review: [{ text: "Look at page 2" }] })],
  ["Safe to Send that lists a decision", verdictOf("safe_to_send", false, { decisions: [{ text: "Kept on purpose" }] })],
  ["Safe to Send that lists a reason it could not check", verdictOf("safe_to_send", false, { reasons: [{ text: "Could not complete" }] })],
  ["Safe to Send over pages that were not read", verdictOf("safe_to_send", false, { pagesTotal: 3, pagesRead: 1 })],
  ["Safe to Send with nothing checked", verdictOf("safe_to_send", false, { checked: [] })],
  ["Safe to Send with no file digest", verdictOf("safe_to_send", false, { sha256: "" })],
  ["Safe to Send with a reason code", verdictOf("safe_to_send", false, {}, { reason_code: "check_failed" })],
  ["Cannot Verify that says it is blocking", verdictOf("cannot_verify", true, { reasons: [{ text: "x" }] })],
];

test("Codex 1+2 (full server): a check verdict that is not the engine's whole pass contract is never Safe to Send, and says the check could not run", async () => {
  const r = await rig();
  try {
    for (const [label, check] of SAFE_DEFECTS) {
      r.script({ find: FIND(), check: CHECK(check) });
      const res = await r.call("check_redaction");
      assertNoPass(`check_redaction / ${label}`, res);
      // A verdict that fails the contract is no verdict: the check did not run (contract row 0: an execution failure, text only).
      assert.equal(res.isError, true, `${label}\n${textOf(res)}`);
      assert.equal(res.structuredContent, undefined, label);
    }
    // Positive control: the same pieces, consistent, are a pass.
    r.script({ find: FIND(), check: CHECK(verdictOf("safe_to_send")) });
    const ok = await r.call("check_redaction");
    assert.equal(ok.isError, false);
    assert.equal(ok.structuredContent.outcome, "safe_to_send");
    assert.ok(textOf(ok).includes("✅ Safe to Send"), textOf(ok));
  } finally {
    await r.close();
  }
});

test("Codex 2 (output schema): a Safe to Send result that is blocking or lists problems is refused by the tool's own outputSchema", async () => {
  const { checkRedactionOutputSchema } = await import("./index.js");
  const base = {
    scanComplete: true, clean: true, totalFindings: 0, byKind: {}, regions: [], survivors: [], offPage: [],
    coverage: { pagesScanned: 1, pagesTotal: 1, notScanned: [], priorRevisionsScanned: false, metadataScanned: true, acroformScanned: false, attachmentsScanned: false, formXobjectsScanned: 0, annotationAppearancesScanned: 0, pagesFailedCount: 0 },
    outcome: "safe_to_send",
  };
  const out = (state: string, blocking: boolean, extra: Record<string, unknown> = {}) => ({ verdict: state, blocking, reason_code: null, result: outputResult(state, { blocking, ...extra }) });
  assert.equal(checkRedactionOutputSchema.safeParse({ ...base, verdict: out("safe_to_send", false) }).success, true, "positive control");
  for (const [label, verdict] of [
    ["blocking", out("safe_to_send", true)],
    ["problems", out("safe_to_send", false, { problems: [{ text: "x" }] })],
    ["review items", out("safe_to_send", false, { review: [{ text: "x" }] })],
    ["decisions", out("safe_to_send", false, { decisions: [{ text: "x" }] })],
    ["reasons", out("safe_to_send", false, { reasons: [{ text: "x" }] })],
  ] as const) {
    assert.equal(checkRedactionOutputSchema.safeParse({ ...base, verdict }).success, false, label);
  }
  // `outcome` and the verdict cannot disagree about a pass, in either direction.
  assert.equal(checkRedactionOutputSchema.safeParse({ ...base, verdict: out("safe_to_send", false), outcome: "needs_review" }).success, false);
  assert.equal(checkRedactionOutputSchema.safeParse({ ...base, verdict: out("needs_review", false), outcome: "safe_to_send" }).success, false);
});

// ---- Codex 3: seal replies --------------------------------------------------------------------------------

/** The Verify screen's nested `result` of a v2 seal reply (`audit_v2_view`, main.rs `unsupported_schema` reply): a whole CheckResult of the state. */
const v2res = (state: string, blocking = false) => ({
  state, blocking, summary: "Fixed summary.", pagesTotal: 2, pagesRead: 2, checked: [{ text: "Metadata" }], notChecked: [],
  problems: blocking ? [{ text: "Text under a box on page 1" }] : [], review: state === "needs_review" && !blocking ? [{ text: "Look at page 2" }] : [], information: [], decisions: [],
  reasons: state === "cannot_verify" ? [{ text: "Could not complete" }] : [], checkedAt: "2026-11-13T01:00:00Z", omitlyVersion: "5.6.0", sha256: "a".repeat(64), sizeBytes: 40, canWrite: false, producer: null,
});
const V2_PASS = { result: v2res("safe_to_send"), auditV2Recognized: true, auditV2Overall: "pass", userVerdict: "safe_to_send", blocking: false, auditV2SealValid: true, auditV2ValidationError: null, sealKeyKind: "install" };
const SEAL_V2 = (over: Record<string, unknown> = {}) => ({ ok: true, verdict: "unsupported_schema", sealValid: null, sealFingerprint: "ab12cd34ef56", pageCount: 2, ...V2_PASS, ...over });
const SEAL_V1 = (over: Record<string, unknown> = {}) => ({ ok: true, verdict: "verified", sealValid: true, allPassed: true, metadataScrubbed: true, warnings: [], legacyUnboundVerdict: false, sealFingerprint: "ab12cd34ef56", pageCount: 2, ...over });
const SEAL_DEFECTS: [string, Record<string, unknown>][] = [
  ["a v2 Safe to Send beside auditV2SealValid false (the seal gate failed)", SEAL_V2({ auditV2SealValid: false })],
  ["a v2 Safe to Send with no auditV2SealValid at all", (({ auditV2SealValid: _a, ...x }) => x)(SEAL_V2())],
  ["a v2 Safe to Send beside a validation error", SEAL_V2({ auditV2ValidationError: "applicability could not be recomputed" })],
  ["a v2 Safe to Send beside sealRemoved true", SEAL_V2({ sealRemoved: true })],
  ["a v1 verified reply with sealRemoved true", SEAL_V1({ sealRemoved: true })],
  ["a v1 incomplete reply with sealRemoved true", SEAL_V1({ verdict: "incomplete", allPassed: false, sealRemoved: true })],
  ["a v2 report with no overall that still says Safe to Send", SEAL_V2({ auditV2Overall: null })],
  ["a v2 report with no overall and no failed gate named", SEAL_V2({ auditV2Overall: null, userVerdict: "cannot_verify", auditV2SealValid: true })],
  ["a v2 needs_review that is blocking for a non-blocking overall", SEAL_V2({ auditV2Overall: "review_required", userVerdict: "needs_review", blocking: true })],
];

test("Codex 3 (full server, both seal tools): a seal reply that contradicts itself is never Safe to Send or verified", async () => {
  const r = await rig();
  try {
    for (const tool of ["verify_seal", "verify_document"] as const) {
      for (const [label, reply] of SEAL_DEFECTS) {
        r.script({ verify_seal: reply });
        const res = await r.call(tool);
        assertNoPass(`${tool} / ${label}`, res);
        assert.equal(res.isError, true, `${tool} / ${label}: an execution failure, not a verdict\n${textOf(res)}`);
        assert.equal(res.structuredContent, undefined, `${tool} / ${label}`);
        assert.equal(parseSealReply(reply).ok, false, label);
      }
      // Positive controls (contract §3.5): a v1 and a v2 pass are integrity only, `incomplete`; the file's own word is attributed.
      r.script({ verify_seal: SEAL_V1() });
      assert.equal((await r.call(tool)).structuredContent.outcome, "incomplete");
      r.script({ verify_seal: SEAL_V2() });
      const v2 = await r.call(tool);
      assert.equal(v2.structuredContent.outcome, "incomplete");
      assert.equal(v2.structuredContent.embeddedReport.userVerdict, "safe_to_send");
      // A failed seal that says it was removed is a failure, and is wording only.
      r.script({ verify_seal: { ok: true, verdict: "seal_invalid", sealValid: false, sealRemoved: true } });
      const removed = await r.call(tool);
      assert.equal(removed.structuredContent.outcome, "not_a_pass");
      assert.equal(removed.isError, false);
    }
  } finally {
    await r.close();
  }
});

test("Codex 3 (normaliser): a v2 pass needs the seal gate; a removed seal beside it is Cannot Verify, never Safe to Send", () => {
  assert.equal(normalizeSealResult(SEAL_V2()).userVerdict, "safe_to_send");
  for (const over of [{ auditV2SealValid: false }, { auditV2SealValid: undefined }, { auditV2ValidationError: "x" }, { sealRemoved: true }]) {
    assert.equal(normalizeSealResult(SEAL_V2(over)).userVerdict, "cannot_verify", JSON.stringify(over));
  }
  // The card's structured form has no gate fields and is checked by parseSealReply's `structured` rules instead.
  assert.equal(parseSealReply({ ok: true, verdict: "unsupported_schema", sealValid: false, sealRemoved: true, auditV2Overall: "pass", userVerdict: "safe_to_send", blocking: false }, { structured: true }).ok, false);
});

// ---- Codex 4: the sidecar verify requires the metadata to be scrubbed -------------------------------------

test("Codex 4: a sidecar verify 'pass' needs metadataScrubbed true (main.rs compute_all_pass); the tool never prints a pass without it", async () => {
  const r = await rig();
  try {
    r.sidecar();
    const pass = (extra: Record<string, unknown> = {}) => ({
      ok: true, scan_performed: false, verdict: "pass", metadataScrubbed: true,
      regions: [{ page: 0, reason: "X", verification: { result: "pass" } }],
      hiddenContent: ["thumbnails", "document-actions", "embedded-files", "incremental-revisions", "hidden-layers", "comment-annotations", "signature-identity", "semantic-text", "labels", "redacted-text-in-strings"].map((c) => ({ class: c, verification: { result: "pass" } })), disclosures: [], license: null, warnings: [], ...extra,
    });
    for (const [label, reply] of [
      ["pass beside metadataScrubbed false", pass({ metadataScrubbed: false })],
      ["pass with no metadataScrubbed", (({ metadataScrubbed: _m, ...x }) => x)(pass())],
      ["pass with metadataScrubbed a string", pass({ metadataScrubbed: "true" })],
      ["fail beside nothing failing", pass({ verdict: "fail" })],
      ["a failing entry with no detail", pass({ verdict: "fail", regions: [{ page: 0, reason: "X", verification: { result: "fail" } }] })],
      ["a reply that says a scan ran", pass({ scan_performed: true })],
    ] as const) {
      assert.equal(parseSidecarVerifyReply(reply).ok, false, label);
      r.script({ find: FIND(), check: CHECK(verdictOf("safe_to_send")), verify: reply });
      const res = await r.call("verify_redaction");
      assert.equal(res.isError, true, `${label}\n${textOf(res)}`);
      assert.doesNotMatch(textOf(res), /"verdict": "pass"/, label);
      assert.notEqual(res.structuredContent?.clean, true, label);
    }
    // Positive controls: a consistent pass, and a consistent fail over unscrubbed metadata.
    const pipeline = { find: FIND(), check: CHECK(verdictOf("safe_to_send")) };
    r.script({ ...pipeline, verify: pass() });
    const ok = await r.call("verify_redaction");
    assert.equal(ok.isError, false);
    assert.equal(ok.structuredContent.clean, true);
    assert.equal(ok.structuredContent.outcome, "safe_to_send", "contract §3.4: a passing sidecar adds nothing to a passing pipeline");
    r.script({ ...pipeline, verify: pass({ verdict: "fail", metadataScrubbed: false }) });
    const bad = await r.call("verify_redaction");
    assert.equal(bad.isError, false, "contract §3.4: a completed check is isError false");
    assert.equal(bad.structuredContent.outcome, "needs_review", "W10: the metadata was not scrubbed");
    assert.ok(textOf(bad).startsWith("⚠️ NOT A PASS"), textOf(bad));
  } finally {
    await r.close();
  }
});

// ---- Codex 5: scan_complete true beside an unread page --------------------------------------------------------

const COMPLETE_BESIDE_UNREAD: [string, Record<string, unknown>][] = [
  ["scan_complete true, pages_scanned 0 and a failed page", { pages_total: 1, pages_scanned: 0, pages_failed: [0], not_scanned: [], prior_revisions_scanned: false, metadata_scanned: false, acroform_scanned: false, attachments_scanned: false, form_xobjects_scanned: 0, annotation_appearances_scanned: 0, raster_pages: [], raster_only_pages: [], scan_complete: true }],
  ["scan_complete true over a failed page (counts agree)", { pages_total: 3, pages_scanned: 2, pages_failed: [1], not_scanned: [], prior_revisions_scanned: false, metadata_scanned: false, acroform_scanned: false, attachments_scanned: false, form_xobjects_scanned: 0, annotation_appearances_scanned: 0, raster_pages: [], raster_only_pages: [], scan_complete: true }],
  ["scan_complete true over an image-only page", { ...COV, raster_only_pages: [0] }],
  ["scan_complete true over a survivor page that failed to decode", { ...COV, survivor_pages_failed: [0] }],
  ["scan_complete true over a prior revision that failed", { ...COV, prior_revisions_failed: [0] }],
  ["scan_complete true over unread embedded streams", { ...COV, embedded_streams_failed: 2 }],
  ["scan_complete true over an unread XMP stream", { ...COV, xmp_stream_unread: true }],
  ["scan_complete true over an unread attachment tree", { ...COV, attachment_tree_unread: true }],
  ["pages that do not add up to the total", { ...COV, pages_scanned: 5 }],
  ["a failed page that is not in the document", { ...COV, pages_failed: [7], pages_scanned: 0 }],
];

test("Codex 5: scan_complete true beside a failed or unread page is a reply that contradicts itself, in both scan parsers (server and bundle port)", async () => {
  // Top-level flag only, inner flag only, or both: each form the two engines send.
  for (const [label, coverage] of COMPLETE_BESIDE_UNREAD) {
    for (const form of ["both", "top-level only", "coverage only"] as const) {
      const cov: Record<string, unknown> = { ...coverage };
      const reply: Record<string, unknown> = FIND({ coverage: cov });
      if (form === "top-level only") delete cov.scan_complete;
      if (form === "coverage only") delete reply.scan_complete;
      if (form !== "coverage only") reply.scan_complete = true;
      if (form === "top-level only") cov.scan_complete = undefined;
      assert.equal(parseScanReply(reply).ok, false, `${label} / ${form}`);
    }
  }
  // Positive controls: the real shapes of an incomplete scan (nothing read) and a complete one.
  assert.equal(parseScanReply(FIND({ scan_complete: false, coverage: { pages_total: 1, pages_scanned: 0, pages_failed: [0], not_scanned: [], prior_revisions_scanned: false, metadata_scanned: false, acroform_scanned: false, attachments_scanned: false, form_xobjects_scanned: 0, annotation_appearances_scanned: 0, raster_pages: [], raster_only_pages: [], scan_complete: false } })).ok, true);
  assert.equal(parseScanReply(FIND()).ok, true);
  // Through the tools: an execution failure, no clean text, no structured result.
  const r = await rig();
  try {
    for (const [label, coverage] of COMPLETE_BESIDE_UNREAD) {
      r.script({ find: FIND({ coverage }), check: CHECK(verdictOf("safe_to_send")) });
      for (const tool of ["check_redaction", "find_sensitive_regions", "verify_redaction"]) {
        const res = await r.call(tool);
        assertNoPass(`${tool} / ${label}`, res);
        assert.equal(res.isError, true, `${tool} / ${label}\n${textOf(res)}`);
        assert.equal(res.structuredContent, undefined, `${tool} / ${label}`);
      }
    }
  } finally {
    await r.close();
  }
});

// ---- Codex 6: the card ------------------------------------------------------------------------------------------

test("Codex 6: the card refuses a minimal 'safe' envelope that lacks its coverage and its result metadata (error state, never green)", () => {
  const coverage = { pagesScanned: 1, pagesTotal: 1, notScanned: [], priorRevisionsScanned: false, metadataScanned: true, acroformScanned: false, attachmentsScanned: false, formXobjectsScanned: 0, annotationAppearancesScanned: 0, pagesFailedCount: 0 };
  const sc = (over: Record<string, unknown> = {}) => ({
    scanComplete: true, clean: true, totalFindings: 0, byKind: {}, regions: [], survivors: [], offPage: [], coverage,
    verdict: { verdict: "safe_to_send", blocking: false, reason_code: null, result: outputResult("safe_to_send") }, outcome: "safe_to_send", ...over,
  });
  assert.equal(look(sc()), "safe", "positive control");
  assert.equal(look(sc({ outcome: undefined })), "error", "contract §3.8: a result with no outcome is the error state");
  const minimalResult = { state: "safe_to_send", blocking: false, summary: "", checked: [], notChecked: [], problems: [], review: [], information: [], decisions: [], reasons: [] };
  for (const [label, envelope] of [
    ["no coverage at all", (({ coverage: _c, ...x }) => x)(sc())],
    ["an empty coverage", sc({ coverage: {} })],
    ["a coverage whose pages do not add up", sc({ coverage: { ...coverage, pagesScanned: 0 } })],
    ["a complete scan over a failed page", sc({ coverage: { ...coverage, pagesScanned: 0, pagesFailedCount: 1 } })],
    ["no byKind", (({ byKind: _b, ...x }) => x)(sc())],
    ["a minimal safe result: no page counts, digest, size or time", sc({ verdict: { verdict: "safe_to_send", blocking: false, reason_code: null, result: minimalResult } })],
    ["a safe result with a checked line but no page counts, digest, size or time", sc({ verdict: { verdict: "safe_to_send", blocking: false, reason_code: null, result: { ...minimalResult, checked: [{ text: "Metadata" }], summary: "Every mandatory check passed." } } })],
    ["a safe result with nothing checked", sc({ verdict: { verdict: "safe_to_send", blocking: false, reason_code: null, result: outputResult("safe_to_send", { checked: [] }) } })],
    ["a safe result with no digest", sc({ verdict: { verdict: "safe_to_send", blocking: false, reason_code: null, result: outputResult("safe_to_send", { sha256: "" }) } })],
    ["a safe result over unread pages", sc({ verdict: { verdict: "safe_to_send", blocking: false, reason_code: null, result: outputResult("safe_to_send", { pagesTotal: 4, pagesRead: 1 }) } })],
    ["an outcome that says needs_review beside Safe to Send", sc({ outcome: "needs_review" })],
    ["an outcome that says safe_to_send beside Needs Review", sc({ outcome: "safe_to_send", verdict: { verdict: "needs_review", blocking: false, reason_code: null, result: outputResult("needs_review") } })],
    ["an unknown outcome", sc({ outcome: "fine" })],
  ] as const) {
    assert.equal(parseCheckEnvelope(envelope).ok, false, label);
    assert.equal(look(envelope), "error", label);
  }
  // A result that is not a pass is still drawn without its footer metadata (a card does not need it to warn).
  assert.equal(look(sc({ verdict: { verdict: "needs_review", blocking: false, reason_code: null, result: { ...minimalResult, state: "needs_review", review: [{ text: "x" }] } }, outcome: "needs_review" })), "review");
});

// ---- Codex 7: the text of a non-pass opens with NOT A PASS --------------------------------------------------------

test("Codex 7: find_sensitive_regions, the re-scan and the sidecar fail open their text with NOT A PASS (and a pass does not)", async () => {
  const r = await rig();
  try {
    const cases: [string, string, Record<string, unknown>, RegExp][] = [
      ["find_sensitive_regions", "findings", { find: FIND({ clean: false, count: 1, total_findings: 1, regions: [region()] }) }, /^⚠️ NOT A PASS — 1 sensitive item\(s\) found; a pattern scan is not a check of the document: run check_redaction\.\n\n/],
      ["find_sensitive_regions", "incomplete", { find: FIND({ scan_complete: false, coverage: { ...COV, pages_scanned: 0, pages_failed: [0], scan_complete: false } }) }, /^⚠️ NOT A PASS — INCOMPLETE SCAN; /],
      ["find_sensitive_regions", "not reported", { find: (({ scan_complete: _s, ...x }) => x)(FIND({ coverage: (({ scan_complete: _c, ...c }) => c)(COV) })) }, /^⚠️ NOT A PASS — INCOMPLETE SCAN; /],
      ["verify_redaction", "re-scan findings", { find: FIND({ clean: false, count: 1, total_findings: 1, regions: [region()] }), check: CHECK(verdictOf("safe_to_send")) }, /^⚠️ NOT A PASS — 1 sensitive item\(s\) found\.\n\n/],
      ["verify_redaction", "re-scan incomplete", { find: FIND({ scan_complete: false, coverage: { ...COV, pages_scanned: 0, pages_failed: [0], scan_complete: false } }), check: CHECK(verdictOf("safe_to_send")) }, /^⚠️ NOT A PASS — INCOMPLETE SCAN; /],
      ["check_redaction", "findings", { find: FIND({ clean: false, count: 1, total_findings: 1, regions: [region()] }), check: CHECK(verdictOf("safe_to_send")) }, /^⚠️ NOT A PASS — 1 sensitive item\(s\) found\.\n\n/],
    ];
    for (const [tool, label, cfg, want] of cases) {
      r.script(cfg);
      const text = textOf(await r.call(tool));
      assert.match(text, want, `${tool} / ${label}\n${text}`);
      assert.doesNotMatch(text, /Safe to Send/, `${tool} / ${label}`);
    }
    // The sidecar fail: no pass wording; a pass: no NOT A PASS.
    r.sidecar();
    const verify = (verdict: string, scrubbed: boolean) => ({ ok: true, scan_performed: false, verdict, metadataScrubbed: scrubbed, regions: [], hiddenContent: ["thumbnails", "document-actions", "embedded-files", "incremental-revisions", "hidden-layers", "comment-annotations", "signature-identity", "semantic-text", "labels", "redacted-text-in-strings"].map((c) => ({ class: c, verification: { result: "pass" } })), disclosures: [], license: null, warnings: [] });
    const pipeline = { find: FIND(), check: CHECK(verdictOf("safe_to_send")) };
    r.script({ ...pipeline, verify: verify("fail", false) });
    assert.match(textOf(await r.call("verify_redaction")), /^⚠️ NOT A PASS — the document's metadata was not scrubbed\.\n\n/);
    r.script({ ...pipeline, verify: verify("pass", true) });
    assert.doesNotMatch(textOf(await r.call("verify_redaction")), /NOT A PASS/);
    // Positive controls: a clean, complete scan opens with no NOT A PASS.
    r.script({ find: FIND(), check: CHECK(verdictOf("safe_to_send")) });
    for (const tool of ["verify_redaction", "check_redaction"]) assert.doesNotMatch(textOf(await r.call(tool)), /NOT A PASS/, tool);
    // Contract §3: a pattern scan is never a pass (W12), even a clean, complete one.
    assert.match(textOf(await r.call("find_sensitive_regions")), /^⚠️ NOT A PASS — a pattern scan is not a check of the document: run check_redaction\.\n\n/);
  } finally {
    await r.close();
  }
});

// ---- Codex 8: the sweep ---------------------------------------------------------------------------------------------

test("Codex 8 (sweep): the write tools' audit never prints Verification: pass or Result: Safe to Send beside a failing region or a verdict that is not a pass", async () => {
  const entry = (result: string) => ({ page: 0, bbox: { x: 1, y: 2, width: 3, height: 4 }, timestamp: "2026-11-13T01:00:00Z", reason_code: "PII.SSN", verification: result === "pass" ? { result } : { result, detail: "text still renders" } });
  const v1 = (over: Record<string, unknown> = {}) => ({ verdict: "pass", regions: [entry("pass")], warnings: [], metadataScrubbed: true, license: "licensed", licensedTo: null, disclosures: [], ...over });
  const v2 = (over: Record<string, unknown> = {}) => v1({ auditSchema: "omitly.audit/v2", auditV2Overall: "pass", userVerdict: "safe_to_send", blocking: false, sealFingerprint: "ab12", result: v2res("safe_to_send"), ...over });
  const DEFECTS: [string, any][] = [
    ["v1 pass beside a failing region", v1({ regions: [entry("fail")] })],
    ["v1 pass beside unscrubbed metadata", v1({ metadataScrubbed: false })],
    ["v1 pass with no region list", (({ regions: _r, ...x }) => x)(v1())],
    ["v2 Safe to Send beside a v1 verdict of fail", v2({ verdict: "fail" })],
    ["v2 Safe to Send beside a failing region", v2({ regions: [entry("fail")] })],
    ["v2 needs_review beside a v1 verdict of pass", v2({ userVerdict: "needs_review", auditV2Overall: "review_required" })],
  ];
  for (const [label, audit] of DEFECTS) assert.equal(parseRedactAudit(audit).ok, false, label);
  assert.equal(parseRedactAudit(v1()).ok, true);
  assert.equal(parseRedactAudit(v2()).ok, true);
  assert.equal(parseRedactAudit(v2({ verdict: "fail", userVerdict: "needs_review", auditV2Overall: "review_required", result: v2res("needs_review") })).ok, true);
  const r = await rig();
  try {
    for (const [label, audit] of DEFECTS) {
      r.script({ redact: { ok: true, output: r.doc + ".out.pdf", audit }, redact_entities: { ok: true, output: r.doc + ".out.pdf", redacted: [{ page: 0, kind: "ssn", preview: "•••" }], audit } });
      const a = await r.call("redact_pdf", { outputPath: r.doc + ".out.pdf", regions: [{ page: 0, x: 1, y: 2, width: 3, height: 4 }] });
      const b = await r.call("redact_by_entity", { outputPath: r.doc + ".out.pdf" });
      for (const [tool, res] of [["redact_pdf", a], ["redact_by_entity", b]] as const) {
        assert.equal(res.isError, true, `${tool} / ${label}\n${textOf(res)}`);
        assert.doesNotMatch(textOf(res), /Verification: pass|Safe to Send/, `${tool} / ${label}`);
        assert.equal(res.structuredContent, undefined, `${tool} / ${label}`);
      }
    }
    r.script({ redact: { ok: true, output: r.doc + ".out.pdf", audit: v2() } });
    const ok = await r.call("redact_pdf", { outputPath: r.doc + ".out.pdf", regions: [{ page: 0, x: 1, y: 2, width: 3, height: 4 }] });
    assert.equal(ok.isError, undefined);
    // Contract §3.6: the engine's record is attributed and the outcome is capped at needs_review (W11); there is no "Result:" line.
    assert.equal(ok.structuredContent.outcome, "needs_review");
    assert.match(textOf(ok), /The engine's record of this redaction: no failed region\./);
    assert.doesNotMatch(textOf(ok), /Result: Safe to Send|Safe to Send/);
  } finally {
    await r.close();
  }
});

test("Codex 8 (sweep): no check_redaction text holds a finding, a leak or an unread file beside Safe to Send, over every engine verdict x finds x coverage", async () => {
  const r = await rig();
  try {
    const verdicts: [string, any][] = [
      ["safe", verdictOf("safe_to_send")],
      ["safe, embedded report says Safe to Send", verdictOf("safe_to_send", false, { information: [{ text: "This file carries an Omitly report (omitly-audit.json) sealed with key ab:cd:12:34. The report records: Safe to Send. A seal shows the file is unchanged." }] })],
      ["needs_review", verdictOf("needs_review")],
      ["blocking", verdictOf("needs_review", true, { problems: [{ text: "Text under a box on page 1" }] })],
      ["cannot_verify", verdictOf("cannot_verify", false, { reasons: [{ text: "Could not complete" }] })],
    ];
    const finds: [string, any][] = [
      ["clean", FIND()],
      ["visible", FIND({ clean: false, count: 1, total_findings: 1, regions: [region()] })],
      ["under a box", FIND({ clean: false, count: 0, total_findings: 1, survivors: [region("ssn")] })],
      ["off page", FIND({ clean: false, count: 0, total_findings: 1, off_page: [{ source: "metadata", kind: "email", preview: "•••" }] })],
      ["incomplete", FIND({ scan_complete: false, coverage: { ...COV, pages_scanned: 0, pages_failed: [0], scan_complete: false } })],
      ["not reported", (({ scan_complete: _s, ...x }) => x)(FIND({ coverage: (({ scan_complete: _c, ...c }) => c)(COV) }))],
    ];
    for (const [vn, v] of verdicts) {
      for (const [fn, f] of finds) {
        r.script({ find: f, check: CHECK(v) });
        const res = await r.call("check_redaction");
        const text = textOf(res);
        const name = `${vn} / ${fn}`;
        const pass = vn === "safe" && fn === "clean"; // C2b: the engine relying on the file's own sealed report caps at needs_review
        if (pass) {
          assert.equal(res.structuredContent.outcome, "safe_to_send", name);
          assert.ok(text.includes("✅ Safe to Send"), name);
          continue;
        }
        assert.ok(text.startsWith("⚠️ NOT A PASS — "), `${name}\n${text}`);
        assert.doesNotMatch(text, /Safe to Send/, `${name}\n${text}`);
        assert.notEqual(res.structuredContent.outcome, "safe_to_send", name);
        // Whatever it found shows in the outcome: a failed redaction is not a pass; a listed item needs review.
        if (fn === "under a box") assert.equal(res.structuredContent.outcome, "not_a_pass", name);
        if (vn === "blocking") assert.equal(res.structuredContent.outcome, "not_a_pass", name);
        if (["visible", "off page"].includes(fn) && !["blocking"].includes(vn)) assert.equal(res.structuredContent.outcome, "needs_review", name);
        if (fn === "incomplete" && vn === "safe") assert.equal(res.structuredContent.outcome, "incomplete", name);
        if (vn.startsWith("safe, embedded") && fn === "clean") assert.equal(res.structuredContent.outcome, "needs_review", name);
      }
    }
  } finally {
    await r.close();
  }
});

// ---- Kimi MED: the strict scan parser matches what the engines send -----------------------------------------------

test("Kimi MED: a real, correct scan reply is never refused: the native find and the wasm scan send every field (see real-engine-goldens.test.ts for the captured replies)", () => {
  // The shapes the two engines send, field for field (main.rs do_find; leakcheck-wasm lib.rs ScanResult), including the narrowed native find.
  const native = FIND({
    clean: false, count: 1, total_findings: 3, regions: [{ ...region(), under_redaction: false }], survivors: [region("ssn")], off_page: [{ source: "metadata", kind: "email", preview: "•••" }],
    coverage: { pages_total: 1, pages_scanned: 1, pages_failed: [], prior_revisions_scanned: false, metadata_scanned: true, acroform_scanned: false, attachments_scanned: false, form_xobjects_scanned: 0, annotation_appearances_scanned: 0, raster_pages: [], raster_only_pages: [], not_scanned: [], scan_complete: true },
  });
  assert.equal(parseScanReply(native).ok, true);
  const wasm = FIND({
    coverage: { ...COV, survivor_pages_failed: [], prior_revisions_scanned: false, prior_revisions_failed: [], metadata_scanned: false, acroform_scanned: false, attachments_scanned: false, form_xobjects_scanned: 0, annotation_appearances_scanned: 0, embedded_streams_failed: 0, acroform_tree_incomplete: false, xmp_stream_unread: false, attachment_content_unread: false, attachment_tree_unread: false, raster_pages: [], raster_only_pages: [] },
  });
  assert.equal(parseScanReply(wasm).ok, true);
  // And the old "only ok, count and regions" shape is not what either sends: it is refused (fail closed), because a verdict
  // cannot be given from a reply with no survivors, off-page list or coverage.
  assert.equal(parseScanReply({ ok: true, count: 1, regions: [region()] }).ok, false);
  // A narrowed native find lists fewer than it counts; the un-narrowed parse refuses that.
  const narrowed = { ...native, count: 0, regions: [] , total_findings: 3 };
  assert.equal(parseScanReply(narrowed, { narrowed: true }).ok, true);
  assert.equal(parseScanReply(narrowed).ok, false);
});

// ---- the verdict-level parser, directly ---------------------------------------------------------------------------

test("parseCheckVerdict: every defect of the Safe to Send contract is refused; real-shaped verdicts of every state are read", () => {
  for (const [label, v] of SAFE_DEFECTS) assert.equal(parseCheckVerdict(v).ok, false, label);
  assert.equal(parseCheckVerdict(verdictOf("safe_to_send")).ok, true);
  assert.equal(parseCheckVerdict(verdictOf("needs_review")).ok, true);
  assert.equal(parseCheckVerdict(verdictOf("needs_review", true, { problems: [{ text: "x" }] })).ok, true);
  assert.equal(parseCheckVerdict(verdictOf("cannot_verify", false, { reasons: [{ text: "x" }] })).ok, true);
  assert.equal(parseCheckVerdict({ verdict: "cannot_verify", blocking: false, result: null, reason_code: "check_failed" }).ok, true, "the wasm wrapper's serialisation fallback");
  assert.equal(parseCheckVerdict({ verdict: "needs_review", blocking: false, result: null, reason_code: null }).ok, false, "only Cannot Verify may come without its result");
});
