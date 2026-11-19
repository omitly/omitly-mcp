/**
 * omitly#1857: a COMPLETED check is a result, not a tool failure.
 *
 * Claude Desktop renders no MCP Apps view for a tool result with `isError: true`, so for the three
 * card-linked tools (`check_redaction`, `verify_seal`, `verify_document`) every completed verdict
 * returns `isError: false`, and the verdict travels in the text and in `structuredContent`.
 * `isError: true` is kept for execution failures: the file could not be read or found,
 * confinement refused it, the engine said `ok: false` or crashed, or the free cap refused the call.
 *
 * Because `isError` no longer carries the signal, the TEXT must: every non-pass text begins with
 * the ⚠️ marker and names the verdict, so an agent that reads only the text cannot mistake it for
 * a pass. A pass begins with ✅. This table drives the real server over an in-memory client with a
 * scripted native engine (rewritten between calls) and pins both, for every verdict.
 */
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { test } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

const ENV_KEYS = ["OMITLY_ALLOWED_DIR", "OMITLY_REDACT_BIN", "OMITLY_PDF_BIN", "OMITLY_ENGINE_DIR", "OMITLY_STATE_DIR", "OMITLY_FREE_CAP"] as const;
let counter = 0;

const textOf = (res: any) => (res.content ?? []).filter((c: any) => c.type === "text").map((c: any) => c.text).join("\n");

/** A scripted engine: each command's reply is read from config.json beside it, per call. */
function stubEngine(root: string): { bin: string; script: (cfg: Record<string, unknown>) => void } {
  const bin = path.join(root, "stub-engine.mjs");
  const cfgPath = path.join(root, "config.json");
  writeFileSync(
    bin,
    `#!/usr/bin/env node
import { readFileSync } from "node:fs";
const req = JSON.parse(readFileSync(0, "utf8"));
const cfg = JSON.parse(readFileSync(${JSON.stringify(cfgPath)}, "utf8"));
if (cfg.crash) { process.stderr.write("boom"); process.exit(3); }
const mode = cfg.modes?.[req.command];
if (mode === "exit3") { process.stderr.write("boom"); process.exit(3); }
if (mode === "garbage") { process.stdout.write("this is not json {"); process.exit(0); }
if (mode === "hang-then-empty") { process.exit(0); }
const reply = cfg[req.command];
const sent = reply ?? { ok: false, error: "no scripted reply for " + req.command };
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
  return { bin, script: (cfg) => writeFileSync(cfgPath, JSON.stringify(cfg)) };
}

async function rig() {
  const root = realpathSync(mkdtempSync(path.join(tmpdir(), "omitly-completed-")));
  const { bin, script } = stubEngine(root);
  for (const k of ENV_KEYS) delete process.env[k];
  process.env.OMITLY_ALLOWED_DIR = root;
  process.env.OMITLY_STATE_DIR = path.join(root, "state");
  process.env.OMITLY_REDACT_BIN = bin;
  const doc = path.join(root, "doc.pdf");
  writeFileSync(doc, "%PDF-1.4\n% not parsed: the engine is scripted\n");
  counter += 1;
  const mod = (await import(`./index.js?completed-verdicts=${counter}`)) as typeof import("./index.js");
  const server = mod.createServer();
  const client = new Client({ name: "completed-verdicts-test", version: "0.0.0" });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(a), client.connect(b)]);
  return { root, doc, script, client, close: async () => { await client.close(); await server.close(); } };
}

// ---- verify_seal / verify_document ------------------------------------------

const SEAL_BASE = { ok: true, sealValid: false, sealFingerprint: "ab12cd34ef56", pageCount: 2 };
/** The Verify screen's nested `result` of a v2 seal reply (`audit_v2_view`, main.rs `unsupported_schema` reply): a whole CheckResult of the state. */
const v2res = (state: string, blocking = false) => ({
  state, blocking, summary: "Fixed summary.", pagesTotal: 2, pagesRead: 2, checked: [{ text: "Metadata" }], notChecked: [],
  problems: blocking ? [{ text: "Text under a box on page 1" }] : [], review: state === "needs_review" && !blocking ? [{ text: "Look at page 2" }] : [], information: [], decisions: [],
  reasons: state === "cannot_verify" ? [{ text: "Could not complete" }] : [], checkedAt: "2026-11-13T01:00:00Z", omitlyVersion: "5.6.0", sha256: "a".repeat(64), sizeBytes: 40, canWrite: false, producer: null,
});
const V2 = { verdict: "unsupported_schema", sealValid: null, auditV2Recognized: true, auditV2SealValid: true, sealKeyKind: "install" };

/** Every completed verdict of the seal tools, as the ENGINE sends it. `pass` = begins with ✅. */
const SEAL_CASES: { name: string; reply: Record<string, unknown>; pass: boolean; says: RegExp }[] = [
  { name: "v1 verified", reply: { verdict: "verified", sealValid: true, allPassed: true, metadataScrubbed: true, warnings: [], legacyUnboundVerdict: false, sealEraLabel: "classical-era seal (v1)" }, pass: false, says: /integrity only/ },
  { name: "v1 incomplete (seal valid, redaction did not fully pass)", reply: { verdict: "incomplete", sealValid: true, allPassed: false }, pass: false, says: /failed redaction/ },
  { name: "seal_invalid", reply: { verdict: "seal_invalid", sealValid: false }, pass: false, says: /does not verify/ },
  { name: "seal removed", reply: { verdict: "seal_invalid", sealValid: false, sealRemoved: true }, pass: false, says: /Seal removed/ },
  { name: "no_report", reply: { verdict: "no_report", sealValid: false }, pass: false, says: /No Omitly audit report|Seal verdict: no_report/ },
  { name: "report_unparseable", reply: { verdict: "report_unparseable", sealValid: true }, pass: false, says: /No Omitly audit report or seal/ },
  { name: "unsupported_schema (not a v2 report)", reply: { verdict: "unsupported_schema", sealValid: null }, pass: false, says: /No Omitly audit report or seal/ },
  { name: "seal_unsupported_version", reply: { verdict: "seal_unsupported_version", sealValid: null, sealVersion: "9", carriesAuditReport: true }, pass: false, says: /seal version this verifier does not implement/ },
  { name: "v2 safe_to_send", reply: { ...V2, auditV2Overall: "pass", userVerdict: "safe_to_send", blocking: false, result: v2res("safe_to_send") }, pass: false, says: /integrity only/ },
  { name: "v2 needs_review", reply: { ...V2, auditV2Overall: "review_required", userVerdict: "needs_review", blocking: false, result: v2res("needs_review") }, pass: false, says: /items to review/ },
  { name: "v2 needs_review, problems found", reply: { ...V2, auditV2Overall: "unsafe", userVerdict: "needs_review", blocking: true, result: v2res("needs_review", true) }, pass: false, says: /failed redaction/ },
  { name: "v2 cannot_verify", reply: { ...V2, auditV2Overall: null, userVerdict: "cannot_verify", blocking: false, auditV2SealValid: false, result: v2res("cannot_verify") }, pass: false, says: /No Omitly audit report or seal/ },
];

for (const tool of ["verify_seal", "verify_document"] as const) {
  test(`${tool}: every completed verdict is isError:false, and the text starts with its marker and names the verdict`, async () => {
    const r = await rig();
    const misses: string[] = [];
    try {
      for (const c of SEAL_CASES) {
        r.script({ verify_seal: { ...SEAL_BASE, ...c.reply } });
        const res: any = await r.client.callTool({ name: tool, arguments: { pdfPath: r.doc } });
        const text = textOf(res);
        assert.equal(res.isError, false, `${tool} / ${c.name}: a completed check is not a tool failure\n${text}`);
        assert.ok(res.structuredContent, `${tool} / ${c.name}: no structuredContent`);
        assert.ok(text.startsWith(c.pass ? "✅" : "⚠️"), `${tool} / ${c.name}: text must start with ${c.pass ? "✅" : "⚠️"}\n${text}`);
        // The flag no longer warns, so the first line must, and the structure must agree (omitly#1864).
        if (!c.pass) {
          const sc = res.structuredContent;
          assert.ok(sc.outcome !== "safe_to_send" && sc.verdict === undefined, `${tool} / ${c.name}: a non-pass is not a pass in the structure`);
          assert.ok(!text.split("\n")[0]!.startsWith("✅"), `${tool} / ${c.name}`);
        }
        if (!c.says.test(text)) misses.push(`${tool} / ${c.name}: ${c.says}\n${text}`);
      }
      assert.deepEqual(misses, []);
    } finally {
      await r.close();
    }
  });
}

// ---- check_redaction ----------------------------------------------------------

const checkResult = (state: string, blocking: boolean, extra: Record<string, unknown> = {}) => ({
  state,
  blocking,
  summary: "Fixed summary.",
  pagesTotal: 1,
  pagesRead: 1,
  checked: [{ text: "Metadata" }],
  notChecked: [],
  problems: blocking ? [{ text: "Text under a box on page 1" }] : [],
  review: [],
  information: [],
  decisions: [],
  reasons: state === "cannot_verify" ? [{ text: "Could not complete" }] : [],
  checkedAt: "2026-11-11T06:02:00Z",
  omitlyVersion: "5.5.0",
  sha256: "a".repeat(64),
  sizeBytes: 40,
  canWrite: false,
  producer: null,
  ...extra,
});
const verdict = (state: string, blocking: boolean) => ({ verdict: state, blocking, result: checkResult(state, blocking), reason_code: null });
const FIND_CLEAN = { ok: true, count: 0, regions: [], survivors: [], off_page: [], total_findings: 0, clean: true, scan_complete: true, coverage: { scan_complete: true, pages_total: 1, pages_scanned: 1, pages_failed: [], not_scanned: [], prior_revisions_scanned: false, metadata_scanned: false, acroform_scanned: false, attachments_scanned: false, form_xobjects_scanned: 0, annotation_appearances_scanned: 0, raster_pages: [], raster_only_pages: [] } };
const FIND_LEAK = { ...FIND_CLEAN, count: 1, total_findings: 1, clean: false, regions: [{ page: 0, x: 1, y: 2, width: 3, height: 4, kind: "ssn", preview: "•••-••-6789" }] };
const FIND_INCOMPLETE = { ...FIND_CLEAN, scan_complete: false, coverage: { scan_complete: false, pages_scanned: 0, pages_total: 1, pages_failed: [0], not_scanned: [], prior_revisions_scanned: false, metadata_scanned: false, acroform_scanned: false, attachments_scanned: false, form_xobjects_scanned: 0, annotation_appearances_scanned: 0, raster_pages: [], raster_only_pages: [] } };

const CHECK_CASES: { name: string; cfg: Record<string, unknown>; pass: boolean; says: string[] }[] = [
  { name: "clean, Safe to Send", cfg: { find: FIND_CLEAN, check: { ok: true, check: verdict("safe_to_send", false) } }, pass: true, says: [] },
  { name: "clean, Needs Review", cfg: { find: FIND_CLEAN, check: { ok: true, check: verdict("needs_review", false) } }, pass: false, says: ["Check verdict: Needs Review"] },
  { name: "clean, Needs Review with problems (blocking)", cfg: { find: FIND_CLEAN, check: { ok: true, check: verdict("needs_review", true) } }, pass: false, says: ["Check verdict: Needs Review — problems found"] },
  { name: "clean, Cannot Verify", cfg: { find: FIND_CLEAN, check: { ok: true, check: verdict("cannot_verify", false) } }, pass: false, says: ["Check verdict: Cannot Verify"] },
  // A Rust-side Cannot Verify with the engine's own reason code is a check that COMPLETED.
  { name: "clean, Cannot Verify: input_too_large (engine reason code)", cfg: { find: FIND_CLEAN, check: { ok: true, check: { verdict: "cannot_verify", blocking: false, result: null, reason_code: "input_too_large" } } }, pass: false, says: ["Check verdict: Cannot Verify"] },
  { name: "clean, Cannot Verify: check_failed (engine reason code)", cfg: { find: FIND_CLEAN, check: { ok: true, check: { verdict: "cannot_verify", blocking: false, result: null, reason_code: "check_failed" } } }, pass: false, says: ["Check verdict: Cannot Verify"] },
  { name: "findings, Cannot Verify: input_too_large (engine reason code)", cfg: { find: FIND_LEAK, check: { ok: true, check: { verdict: "cannot_verify", blocking: false, result: null, reason_code: "input_too_large" } } }, pass: false, says: ["1 sensitive item(s) found", "Check verdict: Cannot Verify"] },
  { name: "findings (leak), Safe to Send", cfg: { find: FIND_LEAK, check: { ok: true, check: verdict("safe_to_send", false) } }, pass: false, says: ["1 sensitive item(s) found", "Check verdict: Needs Review"] },  // omitly#1864: findings are never Safe to Send
  { name: "findings (leak), Needs Review with problems", cfg: { find: FIND_LEAK, check: { ok: true, check: verdict("needs_review", true) } }, pass: false, says: ["1 sensitive item(s) found", "Check verdict: Needs Review — problems found"] },
  { name: "incomplete scan, Cannot Verify", cfg: { find: FIND_INCOMPLETE, check: { ok: true, check: verdict("cannot_verify", false) } }, pass: false, says: ["INCOMPLETE SCAN", "Check verdict: Cannot Verify"] },
];

test("check_redaction: every completed verdict is isError:false, and the text starts with its marker and names the verdict", async () => {
  const r = await rig();
  try {
    for (const c of CHECK_CASES) {
      r.script(c.cfg);
      const res: any = await r.client.callTool({ name: "check_redaction", arguments: { pdfPath: r.doc } });
      const text = textOf(res);
      assert.equal(res.isError, false, `${c.name}: a completed check is not a tool failure\n${text}`);
      assert.ok(res.structuredContent?.verdict, `${c.name}: no structuredContent verdict`);
      if (c.pass) {
        assert.ok(text.includes("✅ Safe to Send"), `${c.name}: a pass says so\n${text}`);
        assert.equal(res.structuredContent.outcome, "safe_to_send", c.name);
        assert.ok(!text.includes("NOT A PASS"), c.name);
      } else {
                assert.ok(text.startsWith("⚠️ NOT A PASS — "), `${c.name}: text must start with the NOT A PASS marker\n${text}`);
        assert.notEqual(res.structuredContent.verdict.verdict, "safe_to_send", `${c.name}: the structured verdict of a non-pass is not Safe to Send`);
        for (const s of c.says) assert.ok(text.includes(s), `${c.name}: the text must name "${s}"\n${text}`);
        // The rest of the text is unchanged: the engine's own lines still follow.
        assert.ok(text.includes("Check verdict:"), c.name);
      }
    }
  } finally {
    await r.close();
  }
});

test("check_redaction: the real wasm engine's leak is isError:false with the NOT A PASS line", async () => {
  const root = realpathSync(mkdtempSync(path.join(tmpdir(), "omitly-completed-wasm-")));
  for (const k of ENV_KEYS) delete process.env[k];
  process.env.OMITLY_ALLOWED_DIR = root;
  process.env.OMITLY_STATE_DIR = path.join(root, "state");
  process.env.OMITLY_FREE_CAP = "1000";
  const content = "BT /F1 12 Tf 100 680 Td (SSN 123-45-6789) Tj ET\n";
  const objs = [
    "<< /Type /Catalog /Pages 2 0 R >>",
    "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
    `<< /Length ${content.length} >>\nstream\n${content}endstream`,
    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
  ];
  let pdf = "%PDF-1.5\n";
  const offs: number[] = [];
  objs.forEach((b, i) => { offs.push(pdf.length); pdf += `${i + 1} 0 obj\n${b}\nendobj\n`; });
  const x = pdf.length;
  pdf += `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n` + offs.map((o) => `${String(o).padStart(10, "0")} 00000 n \n`).join("");
  pdf += `trailer\n<< /Root 1 0 R /Size ${objs.length + 1} >>\nstartxref\n${x}\n%%EOF\n`;
  const doc = path.join(root, "leak.pdf");
  writeFileSync(doc, Buffer.from(pdf, "latin1"));
  counter += 1;
  const mod = (await import(`./index.js?completed-verdicts=${counter}`)) as typeof import("./index.js");
  const server = mod.createServer();
  const client = new Client({ name: "t", version: "0" });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(a), client.connect(b)]);
  try {
    const res: any = await client.callTool({ name: "check_redaction", arguments: { pdfPath: doc } });
    assert.equal(res.structuredContent.clean, false);
    assert.equal(res.isError, false);
    assert.ok(textOf(res).startsWith("⚠️ NOT A PASS — "), textOf(res));
    assert.match(textOf(res).split("\n\n")[0]!, /sensitive item\(s\) found/);
  } finally {
    await client.close();
    await server.close();
  }
});

test("execution failures are still isError:true on all three tools", async () => {
  const r = await rig();
  try {
    const tools = ["check_redaction", "verify_seal", "verify_document"];
    const outside = path.join(path.dirname(r.root), "outside.pdf");
    for (const tool of tools) {
      // Confinement refuses a path outside the allowed folder; a missing file is not found.
      for (const [label, p] of [["outside the allowed folder", outside], ["missing file", path.join(r.root, "missing.pdf")], ["etc/passwd", "/etc/passwd"]] as const) {
        const res: any = await r.client.callTool({ name: tool, arguments: { pdfPath: p } });
        assert.equal(res.isError, true, `${tool}: ${label} must stay an error\n${textOf(res)}`);
      }
      // Invalid input (the SDK rejects it before the handler).
      const bad: any = await r.client.callTool({ name: tool, arguments: { pdfPath: 42 } }).catch((e: Error) => ({ isError: true, content: [{ text: e.message }] }));
      assert.equal(bad.isError, true, `${tool}: invalid input`);
      // The engine says ok:false, or crashes.
      r.script({ find: { ok: false, error: "engine said no" }, check: { ok: false, error: "x" }, verify_seal: { ok: false, error: "engine said no" } });
      const refused: any = await r.client.callTool({ name: tool, arguments: { pdfPath: r.doc } });
      assert.equal(refused.isError, true, `${tool}: engine ok:false\n${textOf(refused)}`);
      assert.equal(refused.structuredContent, undefined, `${tool}: an execution failure carries no verdict`);
      r.script({ crash: true });
      const crashed: any = await r.client.callTool({ name: tool, arguments: { pdfPath: r.doc } });
      assert.equal(crashed.isError, true, `${tool}: engine crash\n${textOf(crashed)}`);
    }
  } finally {
    await r.close();
  }
});

// ---- the verdict check was ATTEMPTED and failed to execute -----------------------

const FAILURES: { name: string; cfg: Record<string, unknown> }[] = [
  { name: "check exits non-zero", cfg: { modes: { check: "exit3" } } },
  { name: "check answers ok:false", cfg: { check: { ok: false, error: "no check command" } } },
  { name: "check throws (stdout is not JSON)", cfg: { modes: { check: "garbage" } } },
  { name: "check answers ok:true with no check object", cfg: { check: { ok: true } } },
  { name: "check answers a result the allowlist rejects", cfg: { check: { ok: true, check: { verdict: "safe_to_send", blocking: false, result: { state: "safe_to_send", blocking: false, extra: 1 }, reason_code: null } } } },
];

test("check_redaction: find succeeds but the verdict check fails to execute -> isError:true, row 0, text only", async () => {
  const r = await rig();
  try {
    for (const f of FAILURES) {
      for (const [label, find, finding] of [["clean", FIND_CLEAN, false], ["findings", FIND_LEAK, true]] as const) {
        r.script({ find, ...f.cfg });
        const res: any = await r.client.callTool({ name: "check_redaction", arguments: { pdfPath: r.doc } });
        const text = textOf(res);
        assert.equal(res.isError, true, `${f.name} / ${label}: an attempted check that failed to execute is an execution failure\n${text}`);
        // Contract §3 (row 0): an execution failure is text only. It says the check did not run; no verdict, no structured result, no findings dump.
        assert.ok(text.startsWith("⚠️ NOT A PASS — "), `${f.name} / ${label}\n${text}`);
        assert.equal(res.structuredContent, undefined, `${f.name} / ${label}: no structured result`);
        assert.ok(/could not run|did not run|Do not treat this file as checked/.test(text), `${f.name} / ${label}\n${text}`);
        assert.ok(!text.includes("Check verdict:"), `${f.name} / ${label}: no verdict is given\n${text}`);
        void finding;
      }
    }
  } finally {
    await r.close();
  }
});

test("check_redaction: a Cannot Verify the engine reports itself stays isError:false", async () => {
  const r = await rig();
  try {
    for (const code of ["input_too_large", "check_failed"]) {
      r.script({ find: FIND_CLEAN, check: { ok: true, check: { verdict: "cannot_verify", blocking: false, result: null, reason_code: code } } });
      const res: any = await r.client.callTool({ name: "check_redaction", arguments: { pdfPath: r.doc } });
      assert.equal(res.isError, false, `${code}\n${textOf(res)}`);
      assert.equal(res.structuredContent.verdict.reason_code, code);
    }
  } finally {
    await r.close();
  }
});

// ---- an engine answer with no usable verdict is an execution failure ----------------

test("verify_seal and verify_document: an engine answer with no recognised verdict is isError:true, with no structuredContent", async () => {
  const r = await rig();
  try {
    const answers: [string, Record<string, unknown>][] = [
      ["{ok:true}", { ok: true }],
      ["verdict missing, other fields present", { ok: true, sealValid: true, allPassed: true, sealFingerprint: "ab12" }],
      ["verdict:42", { ok: true, verdict: 42 }],
      ["verdict:null", { ok: true, verdict: null }],
      ["verdict:{}", { ok: true, verdict: {} }],
      ['verdict:"bogus"', { ok: true, verdict: "bogus" }],
      ['verdict:"VERIFIED"', { ok: true, verdict: "VERIFIED" }],
      ['verdict:""', { ok: true, verdict: "" }],
    ];
    for (const tool of ["verify_seal", "verify_document"] as const) {
      for (const [label, reply] of answers) {
        r.script({ verify_seal: reply });
        const res: any = await r.client.callTool({ name: tool, arguments: { pdfPath: r.doc } });
        const text = textOf(res);
        assert.equal(res.isError, true, `${tool} / ${label}: no usable result is an execution failure\n${text}`);
        assert.equal(res.structuredContent, undefined, `${tool} / ${label}: no structuredContent`);
        assert.match(text, /Seal check failed to run/, `${tool} / ${label}\n${text}`);
        assert.ok(!/seal_invalid/.test(text), `${tool} / ${label}: must not present an invented tamper verdict\n${text}`);
      }
    }
  } finally {
    await r.close();
  }
});
