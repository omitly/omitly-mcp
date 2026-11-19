/**
 * omitly#1864, round 2: PARSE, DON'T TRUST. A reply that is malformed, incomplete or contradicts itself
 * must never come out positive. Every tool that gives a verdict or a clean/found answer is driven
 * through the real handler with a scripted engine, over a table of reply defects; the result card is
 * driven with the structured results (and an isError flag) the same way. For every case:
 *   - the text holds no positive word;
 *   - the structure holds no positive verdict and no clean-and-complete claim;
 *   - a reply that cannot be parsed is isError true with no structured result at all;
 *   - the card is in the error state, or at least never green.
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
const POSITIVE = /Safe to Send|No recoverable PII|✅ Seal|Seal valid|these bytes are unchanged|Seal intact|seal are intact|Verified/;
let counter = 0;

const region = (kind = "email") => ({ page: 0, x: 1, y: 2, width: 3, height: 4, kind, preview: "•••" });
const FIND = (over: Record<string, unknown> = {}) => ({
  ok: true,
  scan_complete: true,
  clean: true,
  count: 0,
  total_findings: 0,
  regions: [],
  survivors: [],
  off_page: [],
  coverage: { pages_total: 1, pages_scanned: 1, pages_failed: [], not_scanned: [], prior_revisions_scanned: false, metadata_scanned: false, acroform_scanned: false, attachments_scanned: false, form_xobjects_scanned: 0, annotation_appearances_scanned: 0, raster_pages: [], raster_only_pages: [], scan_complete: true },
  ...over,
});
const resultOf = (state: string, extra: Record<string, unknown> = {}) => ({
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
const CHECK_SAFE = { ok: true, check: { verdict: "safe_to_send", blocking: false, reason_code: null, result: resultOf("safe_to_send") } };

async function rig() {
  const root = realpathSync(mkdtempSync(path.join(tmpdir(), "omitly-parse-")));
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
  const mod = (await import(`./index.js?parse-dont-trust=${counter}`)) as typeof import("./index.js");
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

const card = (doc: string, res: any) =>
  renderCardHtml(buildModel({ arguments: { pdfPath: doc } }, { structuredContent: res.structuredContent, isError: res.isError }, CTX));

/** The common assertions for a case that must not come out positive. */
function assertNotPositive(name: string, res: any, doc: string, opts: { mustBeError: boolean }) {
  const text = textOf(res);
  assert.doesNotMatch(text, POSITIVE, `${name}: a positive word\n${text}`);
  const sc = res.structuredContent;
  if (opts.mustBeError) {
    assert.equal(res.isError, true, `${name}: must be an execution failure\n${text}`);
    assert.equal(sc, undefined, `${name}: an execution failure carries no structured result`);
    return;
  }
  if (sc) {
    const v = sc.verdict;
    if (v && typeof v === "object") assert.notEqual(v.verdict, "safe_to_send", name);
    if (typeof v === "string") assert.ok(!["verified"].includes(v) && sc.userVerdict !== "safe_to_send", name);
    if (sc.mode === "rescan" || sc.clean !== undefined) assert.ok(!(sc.clean === true && sc.scanComplete === true && sc.verdict === "pass"), name);
    assert.doesNotMatch(card(doc, res), /data-look="safe"/, `${name}: a green card`);
  }
}

// ---- scan replies: check_redaction, find_sensitive_regions, verify_redaction (re-scan) ----------------

const SCAN_DEFECTS: [string, Record<string, unknown>][] = [
  ["bare {ok, scan_complete}: no findings fields", { ok: true, scan_complete: true }],
  ["regions is a string", FIND({ regions: "none" })],
  ["counts are strings", FIND({ count: "0", total_findings: "0" })],
  ["clean missing", (({ clean: _c, ...r }) => r)(FIND())],
  ["survivors missing", (({ survivors: _s, ...r }) => r)(FIND())],
  ["off_page missing", (({ off_page: _o, ...r }) => r)(FIND())],
  ["coverage missing", (({ coverage: _c, ...r }) => r)(FIND())],
  ["clean true beside a positive total", FIND({ total_findings: 1 })],
  ["clean true beside a listed region", FIND({ count: 1, regions: [region()] })],
  ["clean false, nothing listed", FIND({ clean: false })],
  ["total disagrees with the lists", FIND({ clean: false, count: 1, regions: [region()], total_findings: 3 })],
  ["count disagrees with the regions", FIND({ clean: false, count: 2, regions: [region()], total_findings: 1 })],
  ["a malformed region entry", FIND({ clean: false, count: 1, regions: [{ page: "0", kind: "email" }], total_findings: 1 })],
  ["scan_complete is a string", FIND({ scan_complete: "true" })],
  ["scan_complete disagrees with coverage", FIND({ scan_complete: true, coverage: { scan_complete: false } })],
];

for (const tool of ["check_redaction", "find_sensitive_regions", "verify_redaction"] as const) {
  test(`${tool}: every malformed or contradicting scan reply is an execution failure, never a pass`, async () => {
    const r = await rig();
    try {
      for (const [label, find] of SCAN_DEFECTS) {
        r.script({ find, check: CHECK_SAFE });
        const res = await r.call(tool);
        assertNotPositive(`${tool} / ${label}`, res, r.doc, { mustBeError: true });
      }
    } finally {
      await r.close();
    }
  });

  test(`${tool}: an incomplete scan, or one that does not say, is never positive`, async () => {
    const r = await rig();
    try {
      const withoutFlag = FIND();
      delete (withoutFlag as any).scan_complete;
      for (const [label, find] of [
        ["scan_complete false", FIND({ scan_complete: false })],
        ["scan_complete not reported", withoutFlag],
      ] as const) {
        r.script({ find, check: CHECK_SAFE });
        const res = await r.call(tool);
        assertNotPositive(`${tool} / ${label}`, res, r.doc, { mustBeError: false });
      }
    } finally {
      await r.close();
    }
  });
}

test("check_redaction: malformed verdict replies are never Safe to Send", async () => {
  const r = await rig();
  try {
    const safeResult = resultOf("safe_to_send");
    const cases: [string, unknown][] = [
      ["no check object", { ok: true }],
      ["unknown verdict word", { ok: true, check: { verdict: "all_good", blocking: false, reason_code: null, result: safeResult } }],
      ["safe wrapper around a blocking needs_review result", { ok: true, check: { verdict: "safe_to_send", blocking: false, reason_code: null, result: resultOf("needs_review", { blocking: true, problems: [{ text: "Text under a box on page 1" }] }) } }],
      ["safe with no result", { ok: true, check: { verdict: "safe_to_send", blocking: false, reason_code: null, result: null } }],
      ["blocking flag a string", { ok: true, check: { verdict: "safe_to_send", blocking: "no", reason_code: null, result: safeResult } }],
      ["ok:false", { ok: false, error: "x" }],
    ];
    for (const [label, check] of cases) {
      r.script({ find: FIND(), check });
      assertNotPositive(`check_redaction / ${label}`, await r.call("check_redaction"), r.doc, { mustBeError: false });
    }
  } finally {
    await r.close();
  }
});

// ---- sidecar verify reply ---------------------------------------------------------------------------

/** The ten checks the real `verify` always sends (crates/redaction-core/src/verify.rs:233-308), all passing. */
const HIDDEN_TEN = ["thumbnails", "document-actions", "embedded-files", "incremental-revisions", "hidden-layers", "comment-annotations", "signature-identity", "semantic-text", "labels", "redacted-text-in-strings"].map((c) => ({ class: c, verification: { result: "pass" } }));

test("verify_redaction (sidecar): a verify reply that is not a consistent pass is never a pass", async () => {
  const r = await rig();
  try {
    r.sidecar();
    const pass = (extra: Record<string, unknown> = {}) => ({ ok: true, scan_performed: false, verdict: "pass", metadataScrubbed: true, warnings: [], regions: [{ page: 0, reason: "X", verification: { result: "pass" } }], hiddenContent: HIDDEN_TEN, ...extra });
    const cases: [string, unknown][] = [
      ["pass with no region list", { ok: true, verdict: "pass" }],
      ["pass with no hidden-content list", (({ hiddenContent: _h, ...x }) => x)(pass())],
      ["pass beside a failing region", pass({ regions: [{ page: 0, reason: "X", verification: { result: "fail", detail: "d" } }] })],
      ["pass beside a failing hidden-content class", pass({ hiddenContent: [{ class: "thumbnails", verification: { result: "fail", detail: "d" } }, ...HIDDEN_TEN.slice(1)] })],
      ["an entry with no result", pass({ regions: [{ page: 0, reason: "X" }] })],
      ["an unknown result word", pass({ regions: [{ page: 0, reason: "X", verification: { result: "skipped" } }] })],
      ["unknown verdict word", pass({ verdict: "ok" })],
    ];
    for (const [label, verify] of cases) {
      r.script({ find: FIND(), check: CHECK_SAFE, verify });
      const res = await r.call("verify_redaction");
      assert.equal(res.isError, true, `${label}\n${textOf(res)}`);
      assert.doesNotMatch(textOf(res), /"verdict": "pass"|clean/i, label);
      if (res.structuredContent) assert.notEqual(res.structuredContent.clean, true, label);
    }
    // A consistent pass is still a pass.
    // (contract §3.4: the outcome is this server's own check of the file; a passing sidecar adds nothing.)
    r.script({ find: FIND(), check: CHECK_SAFE, verify: pass() });
    const ok = await r.call("verify_redaction");
    assert.equal(ok.isError, false, textOf(ok));
    assert.equal(ok.structuredContent.mode, "sidecar");
    assert.equal(ok.structuredContent.outcome, "safe_to_send");
    // ... and a sidecar that fails a region lowers it.
    r.script({ find: FIND(), check: CHECK_SAFE, verify: pass({ regions: [{ page: 0, reason: "X", verification: { result: "fail", detail: "d" } }], verdict: "fail" }) });
    const failed = await r.call("verify_redaction");
    assert.equal(failed.structuredContent.outcome, "not_a_pass");
  } finally {
    await r.close();
  }
});

// ---- seal replies: verify_seal, verify_document -----------------------------------------------------

const SEAL_OK = { ok: true, verdict: "verified", sealValid: true, allPassed: true, metadataScrubbed: true, warnings: [], legacyUnboundVerdict: false, sealFingerprint: "ab12cd34ef56", pageCount: 2 };
/** The Verify screen's nested `result` of a v2 seal reply (`audit_v2_view`, main.rs `unsupported_schema` reply): a whole CheckResult of the state. */
const v2res = (state: string, blocking = false) => ({
  state, blocking, summary: "Fixed summary.", pagesTotal: 2, pagesRead: 2, checked: [{ text: "Metadata" }], notChecked: [],
  problems: blocking ? [{ text: "Text under a box on page 1" }] : [], review: state === "needs_review" && !blocking ? [{ text: "Look at page 2" }] : [], information: [], decisions: [],
  reasons: state === "cannot_verify" ? [{ text: "Could not complete" }] : [], checkedAt: "2026-11-13T01:00:00Z", omitlyVersion: "5.6.0", sha256: "a".repeat(64), sizeBytes: 40, canWrite: false, producer: null,
});
const V2_PASS = { result: v2res("safe_to_send"), auditV2Recognized: true, auditV2Overall: "pass", userVerdict: "safe_to_send", blocking: false, auditV2SealValid: true, sealKeyKind: "install" };
const SEAL_DEFECTS: [string, Record<string, unknown>][] = [
  ["bare {ok, verdict: verified}", { ok: true, verdict: "verified" }],
  ["verified with sealValid false", { ...SEAL_OK, sealValid: false }],
  ["verified with sealValid missing", (({ sealValid: _s, ...x }) => x)(SEAL_OK)],
  ["verified with allPassed missing", (({ allPassed: _a, ...x }) => x)(SEAL_OK)],
  ["verified with allPassed false", { ...SEAL_OK, allPassed: false }],
  ["sealValid is a string", { ...SEAL_OK, sealValid: "true" }],
  ["seal_invalid carrying the v2 pass values", { ok: true, verdict: "seal_invalid", sealValid: false, ...V2_PASS }],
  ["seal_invalid with a valid seal", { ok: true, verdict: "seal_invalid", sealValid: true }],
  ["v1 verified carrying v2 pass values", { ...SEAL_OK, ...V2_PASS }],
  ["unknown verdict word", { ...SEAL_OK, verdict: "valid" }],
  ["verdict missing", (({ verdict: _v, ...x }) => x)(SEAL_OK)],
  ["unsupported version with no version", { ok: true, verdict: "seal_unsupported_version", sealValid: null }],
  ["v2 with a userVerdict the overall does not map to", { ok: true, verdict: "unsupported_schema", sealValid: null, ...V2_PASS, auditV2Overall: "unsafe" }],
  ["v2 user verdict a string it should not be", { ok: true, verdict: "unsupported_schema", sealValid: null, ...V2_PASS, userVerdict: "fine" }],
];
for (const tool of ["verify_seal", "verify_document"] as const) {
  test(`${tool}: a malformed or contradicting seal reply is never a pass`, async () => {
    const r = await rig();
    try {
      for (const [label, reply] of SEAL_DEFECTS) {
        r.script({ verify_seal: reply });
        const res = await r.call(tool);
        const text = textOf(res);
        assert.doesNotMatch(text, POSITIVE, `${tool} / ${label}\n${text}`);
        const sc = res.structuredContent;
        if (sc) {
          assert.notEqual(sc.verdict, "verified", `${tool} / ${label}`);
          assert.notEqual(sc.userVerdict, "safe_to_send", `${tool} / ${label}`);
          assert.doesNotMatch(card(r.doc, res), /data-look="safe"/, `${tool} / ${label}`);
        } else {
          assert.equal(res.isError, true, `${tool} / ${label}`);
        }
        // The two the review named must be execution failures, not a completed verdict.
        if (label.startsWith("bare") || label.startsWith("verified with sealValid false") || label.startsWith("seal_invalid carrying")) {
          assert.equal(res.isError, true, `${tool} / ${label}`);
          assert.equal(sc, undefined, `${tool} / ${label}`);
        }
      }
      // A consistent v1 pass and a consistent v2 pass still pass.
      r.script({ verify_seal: SEAL_OK });
      const v1 = await r.call(tool);
      // Contract §3.5: a seal is integrity only. A consistent reply is a completed result, and still never a pass.
      assert.equal(v1.isError, false);
      assert.equal(v1.structuredContent.outcome, "incomplete");
      assert.equal(v1.structuredContent.embeddedReport.verifierVerdict, "verified");
      r.script({ verify_seal: { ok: true, verdict: "unsupported_schema", sealValid: null, sealFingerprint: "ab12", ...V2_PASS } });
      const v2 = await r.call(tool);
      assert.equal(v2.structuredContent.outcome, "incomplete");
      assert.equal(v2.structuredContent.embeddedReport.userVerdict, "safe_to_send");
    } finally {
      await r.close();
    }
  });
}

// ---- locate_text ------------------------------------------------------------------------------------

test("locate_text: a reply whose count disagrees with its list, or has no list, is an execution failure", async () => {
  const r = await rig();
  try {
    for (const [label, reply] of [
      ["no list", { ok: true, count: 0 }],
      ["no count", { ok: true, regions: [] }],
      ["count disagrees", { ok: true, count: 3, regions: [region()] }],
      ["regions a string", { ok: true, count: 0, regions: "none" }],
    ] as const) {
      r.script({ locate_text: reply });
      const res = await r.call("locate_text", { texts: ["x"] });
      assert.equal(res.isError, true, `${label}\n${textOf(res)}`);
      assert.equal(res.structuredContent, undefined, label);
    }
  } finally {
    await r.close();
  }
});

// ---- the card ---------------------------------------------------------------------------------------

const cardSc = (over: Record<string, unknown> = {}, verdict: Record<string, unknown> | null = null) => ({
  outcome: "safe_to_send",
  scanComplete: true,
  clean: true,
  totalFindings: 0,
  byKind: {},
  regions: [],
  survivors: [],
  offPage: [],
  coverage: { pagesScanned: 1, pagesTotal: 1, notScanned: [], priorRevisionsScanned: true, metadataScanned: true, acroformScanned: true, attachmentsScanned: true, formXobjectsScanned: 0, annotationAppearancesScanned: 0, pagesFailedCount: 0 },
  verdict: verdict ?? { verdict: "safe_to_send", blocking: false, reason_code: null, result: (({ canWrite: _w, producer: _p, ...x }) => x)(resultOf("safe_to_send")) },
  ...over,
});
const look = (sc: unknown, isError?: boolean) =>
  /data-look="(\w+)"/.exec(renderCardHtml(buildModel({ arguments: { pdfPath: "/x/a.pdf" } }, { structuredContent: sc, isError }, CTX)))![1];

test("card: parses the whole envelope: a wrapper that disagrees with its result, a missing field or an error flag is the error state", () => {
  assert.equal(look(cardSc()), "safe");
  const nested = { verdict: "safe_to_send", blocking: false, reason_code: null, result: (({ canWrite: _w, producer: _p, ...x }) => x)(resultOf("needs_review", { blocking: true, problems: [{ text: "Text under a box on page 1" }] })) };
  assert.equal(look(cardSc({}, nested)), "error", "a Safe wrapper around a blocking Needs Review result");
  const base: any = cardSc();
  for (const key of ["scanComplete", "clean", "totalFindings", "regions", "survivors", "offPage"]) {
    const { [key]: _drop, ...rest } = base;
    assert.equal(look(rest), "error", `missing ${key}`);
  }
  assert.equal(look(cardSc({ regions: "none" })), "error");
  assert.equal(look(cardSc({ totalFindings: "0" })), "error");
  assert.equal(look(cardSc({ clean: true, totalFindings: 1 })), "error");
  assert.equal(look(cardSc({ scanComplete: false })), "error", "Safe beside an incomplete scan");
  assert.equal(look(cardSc({ clean: false, totalFindings: 1, regions: [region()] })), "error", "Safe beside a finding");
  assert.equal(look(cardSc(), true), "error", "the host flagged the result as an error");
  // The same result with the problem sections non-empty is not a Safe to Send either.
  const withReview = { verdict: "safe_to_send", blocking: false, reason_code: null, result: (({ canWrite: _w, producer: _p, ...x }) => x)(resultOf("safe_to_send", { review: [{ text: "Look at page 2" }] })) };
  assert.equal(look(cardSc({}, withReview)), "error");
});

test("card: a seal result that disagrees with itself, lacks a field, or carries an error flag is the error state", () => {
  const sealSc = (over: Record<string, unknown> = {}) => ({
    outcome: "incomplete",
    seal: { state: "held", version: null, eraLabel: "classical-era seal (v1)", fingerprint: "ab12cd34ef56", keyKind: null },
    embeddedReport: null,
    ...over,
  });
  assert.equal(look(sealSc()), "cannot");
  assert.equal(look(sealSc({ outcome: "safe_to_send" })), "error", "a seal result is never a pass (contract §3.5)");
  assert.equal(look(sealSc({ outcome: undefined })), "error");
  assert.equal(look(sealSc({ outcome: "fine" })), "error");
  assert.equal(look(sealSc({ seal: { state: "fine" } })), "error");
  assert.equal(look(sealSc({ seal: undefined })), "error");
  assert.equal(look(sealSc(), true), "error", "the host flagged the result as an error");
});

// ---- owner decision, 13 November 2026: a completed check is not an error, and the card decides from the content ----

test("a completed check is isError false whatever it found, and the card draws it from the structured result; one that could not run is the error state", async () => {
  const r = await rig();
  try {
    const run = async (find: unknown, check: unknown) => {
      r.script({ find, check });
      const res = await r.call("check_redaction");
      return { res, look: look(res.structuredContent, res.isError) };
    };
    // A leak: not flagged, structured result present, amber card, text opens with the warning.
    const leak = await run(FIND({ clean: false, count: 1, regions: [region()], total_findings: 1 }), CHECK_SAFE);
    assert.equal(leak.res.isError, false);
    assert.ok(leak.res.structuredContent);
    assert.ok(textOf(leak.res).startsWith("⚠️ NOT A PASS"));
    assert.equal(leak.look, "visible");
    // A failed redaction (blocking verdict, text under a box): red card.
    const blocking = { ok: true, check: { verdict: "needs_review", blocking: true, reason_code: null, result: resultOf("needs_review", { blocking: true, problems: [{ text: "Text under a box on page 1" }] }) } };
    const red = await run(FIND({ clean: false, count: 1, regions: [region()], total_findings: 1 }), blocking);
    assert.equal(red.res.isError, false);
    assert.equal(red.look, "blocking");
    // The verdict check could not run: an execution failure (flagged), and the card is the error state.
    const couldNotRun = await run(FIND({ clean: false, count: 1, regions: [region()], total_findings: 1 }), { ok: false, error: "x" });
    assert.equal(couldNotRun.res.isError, true);
    assert.equal(couldNotRun.look, "error");
    // An execution failure has no structured result: the error state.
    r.script({ find: { ok: false, error: "x" }, check: CHECK_SAFE });
    const failed = await r.call("check_redaction");
    assert.equal(failed.isError, true);
    assert.equal(failed.structuredContent, undefined);
    assert.equal(look(failed.structuredContent, failed.isError), "error");
  } finally {
    await r.close();
  }
});

test("seal results that are not a pass are isError false with a structured result and a ⚠️ first line; the card draws them; a flagged pass is the error state", async () => {
  const r = await rig();
  try {
    const cases: [string, Record<string, unknown>, string][] = [
      ["seal_invalid", { ok: true, verdict: "seal_invalid", sealValid: false }, "blocking"],
      ["no_report", { ok: true, verdict: "no_report", sealValid: false }, "cannot"],
      ["v2 needs_review", { ok: true, verdict: "unsupported_schema", sealValid: null, auditV2Recognized: true, auditV2Overall: "review_required", userVerdict: "needs_review", blocking: false, auditV2SealValid: true, result: v2res("needs_review"), sealKeyKind: "install" }, "review"],
      ["v2 blocking", { ok: true, verdict: "unsupported_schema", sealValid: null, auditV2Recognized: true, auditV2Overall: "unsafe", userVerdict: "needs_review", blocking: true, auditV2SealValid: true, result: v2res("needs_review", true), sealKeyKind: "install" }, "blocking"],
    ];
    for (const tool of ["verify_seal", "verify_document"] as const) {
      for (const [label, reply, want] of cases) {
        r.script({ verify_seal: reply });
        const res = await r.call(tool);
        assert.equal(res.isError, false, `${tool} / ${label}`);
        assert.ok(res.structuredContent, `${tool} / ${label}: structured result produced`);
        assert.ok(textOf(res).startsWith("⚠️"), `${tool} / ${label}: the first line warns\n${textOf(res)}`);
        assert.equal(look(res.structuredContent, res.isError), want, `${tool} / ${label}`);
      }
    }
    // A pass the host flagged as an error disagrees with itself.
    r.script({ verify_seal: SEAL_OK });
    const ok = await r.call("verify_seal");
    assert.equal(look(ok.structuredContent, true), "error");
  } finally {
    await r.close();
  }
});
