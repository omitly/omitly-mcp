/**
 * omitly#1864, round 4: the MCPB bundle's check_redaction, find_sensitive_regions and verify_redaction read the
 * wasm's replies through the same pass contract as the full server (replies.js `parseCheckVerdict`,
 * `parseScanReply`), and a result that is not a pass opens with NOT A PASS. The bundle server is started for real
 * (stdio, MCP client) from a copy of this directory with a STUB wasm that sends the DEFECTIVE replies the real
 * wasm never sends; the real wasm's own replies are in ../../src/real-engine-goldens.test.ts and in
 * verdict.test.js ("the real bundle server").
 */
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, realpathSync, symlinkSync, writeFileSync } = require("node:fs");
const { tmpdir } = require("node:os");
const path = require("node:path");
const { parseCheckVerdict } = require("./replies.js");
const { notAPassLead } = require("./verdict.js");
const { passOutcome, capped, isFailure } = require("./outcome.js");

const OMITLY_MCP = path.join(__dirname, "..", "..");
const NODE_MODULES = path.join(OMITLY_MCP, "node_modules");
const skip = existsSync(NODE_MODULES) ? false : "no node_modules (run npm ci)";

// Every key the wasm scan sends (contract C6): a reply that lacks one is no scan reply.
const COV = {
  pages_total: 1, pages_scanned: 1, pages_failed: [], not_scanned: [], prior_revisions_scanned: false, metadata_scanned: false, acroform_scanned: false, attachments_scanned: false,
  form_xobjects_scanned: 0, annotation_appearances_scanned: 0, raster_pages: [], raster_only_pages: [], survivor_pages_failed: [], prior_revisions_failed: [], embedded_streams_failed: 0,
  acroform_tree_incomplete: false, xmp_stream_unread: false, attachment_content_unread: false, attachment_tree_unread: false, scan_complete: true,
};
const scan = (over = {}) => ({ ok: true, scan_complete: true, count: 0, clean: true, total_findings: 0, by_kind: {}, leaks: [], survivors: [], off_page: [], coverage: { ...COV }, error: null, ...over });
const leak = { page: 0, kind: "email", preview: "•••", x: 1, y: 2, width: 3, height: 4 };
const result = (state, over = {}) => ({
  state, blocking: false, summary: "Every mandatory check that applies to this file passed. 1 page checked.", pagesTotal: 1, pagesRead: 1,
  checked: [{ text: "Metadata" }], notChecked: [], problems: [], review: [], information: [], decisions: [], reasons: [],
  checkedAt: "2026-11-13T01:00:00Z", omitlyVersion: "5.6.0", sha256: "a".repeat(64), sizeBytes: 40, canWrite: false, producer: null, ...over,
});
const verdict = (state, blocking = false, over = {}, top = {}) => ({ verdict: state, blocking, result: result(state, { blocking, ...over }), report: null, reason_code: null, ...top });

/** A copy of the bundle server beside a stub wasm whose replies come from a JSON file, started over stdio. */
async function start() {
  const { Client } = require("@modelcontextprotocol/sdk/client/index.js");
  const { StdioClientTransport } = require("@modelcontextprotocol/sdk/client/stdio.js");
  const root = realpathSync(mkdtempSync(path.join(tmpdir(), "omitly-mcpb-passcontract-")));
  const app = path.join(root, "app");
  mkdirSync(path.join(app, "server"), { recursive: true });
  mkdirSync(path.join(app, "wasm"), { recursive: true });
  for (const f of readdirSync(__dirname)) if (f.endsWith(".js") && !f.endsWith(".test.js")) cpSync(path.join(__dirname, f), path.join(app, "server", f));
  cpSync(path.join(__dirname, "..", "manifest.json"), path.join(app, "manifest.json"));
  symlinkSync(NODE_MODULES, path.join(app, "node_modules"));
  const cfg = path.join(root, "wasm.json");
  writeFileSync(
    path.join(app, "wasm", "leakcheck_wasm.js"),
    `const fs = require("node:fs");
const cfg = () => JSON.parse(fs.readFileSync(${JSON.stringify(cfg)}, "utf8"));
// Contract C3: a scripted check is bound to the bytes it is asked about (cfg.noBind leaves the digest as written).
const check = (bytes) => {
  const c = cfg();
  const v = c.check;
  if (!c.noBind && v && v.result && typeof v.result.sha256 === "string" && v.result.sha256.length === 64) v.result.sha256 = require("node:crypto").createHash("sha256").update(Buffer.from(bytes)).digest("hex");
  return JSON.stringify(v);
};
module.exports = { scan: () => JSON.stringify(cfg().scan), check, locate: () => JSON.stringify(cfg().locate) };
`,
  );
  const doc = path.join(root, "doc.pdf");
  writeFileSync(doc, "%PDF-1.4\n% not parsed: the wasm is scripted\n");
  const client = new Client({ name: "mcpb-pass-contract", version: "0.0.0" });
  await client.connect(new StdioClientTransport({ command: process.execPath, args: [path.join(app, "server", "index.js")], env: { ...process.env, OMITLY_ALLOWED_DIR: root }, stderr: "ignore" }));
  return {
    script: (c) => writeFileSync(cfg, JSON.stringify(c)),
    call: async (name, args = {}) => {
      const res = await client.callTool({ name, arguments: { pdfPath: doc, ...args } });
      return { res, text: res.content.map((c) => c.text).join("\n") };
    },
    close: () => client.close(),
  };
}

const SAFE_DEFECTS = [
  ["a bare safe_to_send word", { verdict: "safe_to_send" }],
  ["a safe wrapper around a blocking result", { ...verdict("safe_to_send"), result: result("needs_review", { blocking: true, problems: [{ text: "Text under a box on page 1" }] }) }],
  ["Safe to Send with blocking true", verdict("safe_to_send", true)],
  ["Safe to Send that lists a problem", verdict("safe_to_send", false, { problems: [{ text: "Text under a box on page 1" }] })],
  ["Safe to Send that lists a review item", verdict("safe_to_send", false, { review: [{ text: "Look at page 2" }] })],
  ["Safe to Send over pages that were not read", verdict("safe_to_send", false, { pagesTotal: 3, pagesRead: 1 })],
  ["Safe to Send with no digest", verdict("safe_to_send", false, { sha256: "" })],
];

test("Codex 1 (bundle): a check verdict that is not the engine's whole pass contract is never Safe to Send (row 0: the check did not run)", { skip }, async () => {
  const s = await start();
  try {
    for (const [label, check] of SAFE_DEFECTS) {
      assert.equal(parseCheckVerdict(check).ok, false, label);
      s.script({ scan: scan(), check });
      const { res, text } = await s.call("check_redaction");
      assert.doesNotMatch(text, /Safe to Send/, `${label}\n${text}`);
      // Contract row 0: a verdict that fails the contract is no verdict: an execution failure, text only.
      assert.equal(res.isError, true, `${label}\n${text}`);
      assert.equal(res.structuredContent, undefined, label);
    }
    // Positive control: the same pieces, consistent, are Safe to Send.
    s.script({ scan: scan(), check: verdict("safe_to_send") });
    const ok = await s.call("check_redaction");
    assert.match(ok.text, /Check verdict: Safe to Send\./);
    assert.doesNotMatch(ok.text, /NOT A PASS/);
    assert.equal(ok.res.structuredContent.outcome, "safe_to_send");
  } finally {
    await s.close();
  }
});

test("Codex 5 (bundle): scan_complete true beside a failed page is an execution failure on all three scan tools", { skip }, async () => {
  const s = await start();
  try {
    for (const coverage of [
      { ...COV, pages_scanned: 0, pages_failed: [0] },
      { ...COV, pages_total: 3, pages_scanned: 2, pages_failed: [1] },
      { ...COV, raster_only_pages: [0] },
    ]) {
      s.script({ scan: scan({ coverage }), check: verdict("safe_to_send") });
      for (const tool of ["check_redaction", "find_sensitive_regions", "verify_redaction"]) {
        const { res, text } = await s.call(tool);
        assert.equal(res.isError, true, `${tool}\n${text}`);
        assert.doesNotMatch(text, /Safe to Send|No recoverable PII/, `${tool}\n${text}`);
        assert.match(text, /contradicted itself/, `${tool}\n${text}`);
      }
    }
  } finally {
    await s.close();
  }
});

test("Codex 7 (bundle): find_sensitive_regions, verify_redaction and check_redaction open a non-pass with NOT A PASS (a pass does not)", { skip }, async () => {
  const s = await start();
  try {
    const found = scan({ clean: false, count: 1, total_findings: 1, leaks: [leak] });
    const unread = scan({ scan_complete: false, coverage: { ...COV, pages_scanned: 0, pages_failed: [0], scan_complete: false } });
    const cases = [
      ["find_sensitive_regions", found, /^⚠️ NOT A PASS — 1 sensitive item\(s\) found; a pattern scan is not a check of the document: run check_redaction\.\n\n/],
      ["find_sensitive_regions", unread, /^⚠️ NOT A PASS — INCOMPLETE SCAN; /],
      ["verify_redaction", found, /^⚠️ NOT A PASS — 1 sensitive item\(s\) found\.\n\n/],
      ["verify_redaction", unread, /^⚠️ NOT A PASS — INCOMPLETE SCAN; part of the file was not read\.\n\n/],
      ["check_redaction", found, /^⚠️ NOT A PASS — 1 sensitive item\(s\) found\.\n\n/],
      ["check_redaction", unread, /^⚠️ NOT A PASS — INCOMPLETE SCAN; part of the file was not read\.\n\n/],
    ];
    for (const [tool, sc, want] of cases) {
      s.script({ scan: sc, check: verdict("safe_to_send") });
      const { text } = await s.call(tool);
      assert.match(text, want, `${tool}\n${text}`);
      assert.doesNotMatch(text, /Safe to Send/, `${tool}\n${text}`);
    }
    s.script({ scan: scan(), check: verdict("safe_to_send") });
    for (const tool of ["verify_redaction", "check_redaction"]) assert.doesNotMatch((await s.call(tool)).text, /NOT A PASS/, tool);
    // Contract §3: a pattern scan is never a pass (W12), even a clean, complete one.
    assert.match((await s.call("find_sensitive_regions")).text, /^⚠️ NOT A PASS — a pattern scan is not a check of the document: run check_redaction\.\n\n/);
    // The structured outcome of the bundle's check, beside a leak under a box: not a pass.
    s.script({ scan: scan({ clean: false, count: 0, total_findings: 1, survivors: [leak] }), check: verdict("safe_to_send") });
    assert.equal((await s.call("check_redaction")).res.structuredContent.outcome, "not_a_pass");
  } finally {
    await s.close();
  }
});

test("the bundle's lead is the full server's (the outcome table is in outcome.test.js)", () => {
  assert.equal(notAPassLead([]), "");
  assert.equal(notAPassLead(["a", "b"]), "⚠️ NOT A PASS — a; b.\n\n");
  // The one issuer: a bare cap list never reaches safe_to_send, and an issued value carries its own lead.
  assert.equal(capped(null, []).outcome, "incomplete");
  const out = capped(null, [{ at: "needs_review", why: "x" }]);
  assert.equal(out.lead, notAPassLead(["x"]));
  assert.equal(isFailure(out), false);
  let src;
  try {
    src = require("node:fs").readFileSync(path.join(__dirname, "..", "..", "src", "verdict-rule.ts"), "utf8");
  } catch {
    return; // the published mirror has no src/
  }
  assert.ok(src.includes('return why.length ? `⚠️ NOT A PASS — ${why.join("; ")}.\\n\\n` : "";'));
});

test("owner decision (bundle): a COMPLETED check_redaction is isError false whatever it found; only a check that could not run is isError true", { skip }, async () => {
  const s = await start();
  try {
    const found = scan({ clean: false, count: 1, total_findings: 1, leaks: [leak] });
    const under = scan({ clean: false, count: 0, total_findings: 1, survivors: [leak] });
    const unread = scan({ scan_complete: false, coverage: { ...COV, pages_scanned: 0, pages_failed: [0], scan_complete: false } });
    for (const [label, sc, check, want] of [
      ["findings, Safe to Send from the engine", found, verdict("safe_to_send"), "needs_review"],
      ["text under a box, blocking verdict", under, verdict("needs_review", true, { problems: [{ text: "Text under a box on page 1" }] }), "not_a_pass"],
      ["an unread file", unread, verdict("safe_to_send"), "incomplete"],
      ["engine Cannot Verify (it reported its own reason)", scan(), { verdict: "cannot_verify", blocking: false, result: null, reason_code: "input_too_large" }, "incomplete"],
      ["a clean pass", scan(), verdict("safe_to_send"), "safe_to_send"],
    ]) {
      s.script({ scan: sc, check });
      const { res, text } = await s.call("check_redaction");
      assert.equal(res.isError, false, `${label}: a completed check is not a tool failure\n${text}`);
      assert.equal(res.structuredContent.outcome, want, label);
      if (want !== "safe_to_send") assert.ok(text.startsWith("⚠️ NOT A PASS — "), `${label}\n${text}`);
    }
    // Execution failures stay isError true: the verdict check could not run (wasm without `check`, or a reply that fails the contract) ...
    for (const check of [{ verdict: "safe_to_send" }, verdict("safe_to_send", true), null]) {
      s.script({ scan: scan(), check });
      const { res } = await s.call("check_redaction");
      assert.equal(res.isError, true, JSON.stringify(check));
    }
    // ... and a scan reply that contradicts itself.
    s.script({ scan: scan({ coverage: { ...COV, pages_scanned: 0, pages_failed: [0] } }), check: verdict("safe_to_send") });
    assert.equal((await s.call("check_redaction")).res.isError, true);
    // Contract §3.3: the re-scan runs the same pipeline, so a finding is a completed check too: isError false, needs_review.
    s.script({ scan: found, check: verdict("safe_to_send") });
    const re = await s.call("verify_redaction");
    assert.equal(re.res.isError, false);
    assert.equal(re.res.structuredContent.outcome, "needs_review");
  } finally {
    await s.close();
  }
});

test("round 5 (bundle): a check that lists visible values beside a scan that found none is an execution failure, never Safe to Send (finding 5)", { skip }, async () => {
  const s = await start();
  try {
    const visible = { text: "Sensitive-looking text is visible on page 1 (3 values).", pages: [1] }; // pages are bound by the result's pagesTotal (1): v0.2.1 errata 6
    s.script({ scan: scan(), check: verdict("safe_to_send", false, { information: [visible] }) });
    const { res, text } = await s.call("check_redaction");
    assert.equal(res.isError, true, text);
    assert.doesNotMatch(text, /Safe to Send|No recoverable PII/, text);
    assert.match(text, /disagree/);
    assert.equal(res.structuredContent, undefined);
    // Positive controls: beside the scan that found the values it is a result (not a pass); a check with no such line is a pass.
    s.script({ scan: scan({ clean: false, count: 3, total_findings: 3, leaks: [leak, leak, leak] }), check: verdict("safe_to_send", false, { information: [visible] }) });
    const both = await s.call("check_redaction");
    assert.equal(both.res.isError, false);
    assert.equal(both.res.structuredContent.outcome, "needs_review");
    s.script({ scan: scan(), check: verdict("safe_to_send") });
    assert.equal((await s.call("check_redaction")).res.structuredContent.outcome, "safe_to_send");
  } finally {
    await s.close();
  }
});

test("round 5 (bundle): scan_complete true beside a not_scanned disclosure that denies completion is an execution failure on the three scan tools (finding 3)", { skip }, async () => {
  const s = await start();
  try {
    for (const line of [
      "Type0/CID text using a named encoding whose codespace ranges could not be verified (present in this file)",
      "2 embedded content stream(s) that failed to parse or could not be fully decoded",
    ]) {
      s.script({ scan: scan({ coverage: { ...COV, not_scanned: [line] } }), check: verdict("safe_to_send") });
      for (const tool of ["check_redaction", "find_sensitive_regions", "verify_redaction"]) {
        const { res, text } = await s.call(tool);
        assert.equal(res.isError, true, `${tool}\n${text}`);
        assert.doesNotMatch(text, /Safe to Send|No recoverable PII/, `${tool}\n${text}`);
      }
    }
    // A legitimate limit beside a complete scan is read.
    s.script({ scan: scan({ coverage: { ...COV, not_scanned: ["text drawn as raster images (needs OCR)"] } }), check: verdict("safe_to_send") });
    assert.equal((await s.call("find_sensitive_regions")).res.isError, false);
  } finally {
    await s.close();
  }
});

test("round 5 K1 (bundle): text confirmed under a redaction mark is a blocking Needs Review and not_a_pass, beside an engine Safe to Send", { skip }, async () => {
  const s = await start();
  try {
    s.script({ scan: scan({ clean: false, count: 0, total_findings: 1, survivors: [leak] }), check: verdict("safe_to_send") });
    const { res, text } = await s.call("check_redaction");
    assert.equal(res.structuredContent.outcome, "not_a_pass");
    assert.match(text, /^⚠️ NOT A PASS — text is still present under a redaction mark \(1 item\(s\)\); 1 sensitive item\(s\) found\./, text);
    assert.match(text, /Check verdict: Needs Review — problems found\. This file should not be sent\. Text is still present under a redaction mark\./, text);
    assert.doesNotMatch(text, /Safe to Send|Sensitive-looking text is visible \(/, text);
  } finally {
    await s.close();
  }
});

test("round 6 (bundle): survivors beside an engine refusal give a consistent blocking verdict with no reason code, and the same as the full server's (finding 5)", async (t) => {
  const refusal = {
    verdict: "cannot_verify", blocking: false, reason_code: "input_too_large",
    result: result("cannot_verify", { pagesTotal: 0, pagesRead: 0, checked: [], sha256: "", reasons: [{ text: "The file is larger than this checker accepts, so it was not read." }] }),
  };
  assert.equal(parseCheckVerdict(refusal).ok, true, "the real engine's refusal is read");
  const facts = { found: 2, complete: true, survivors: 1 };
  const out = require("./verdict.js").applyScanToVerdict(refusal, facts);
  assert.equal(out.verdict, "needs_review");
  assert.equal(out.blocking, true);
  assert.equal(out.reason_code, null, "a reason code is legal only with Cannot Verify");
  assert.ok(out.result.notChecked.some((i) => /larger than this checker accepts/.test(i.text)), "the refusal evidence is kept");
  assert.equal(parseCheckVerdict(out).ok, true, "the promoted verdict passes the contract");
  assert.equal(passOutcome({ check: { verdict: refusal.verdict, blocking: false, reasonCode: refusal.reason_code, result: refusal.result }, scan: { engine: "wasm", total: 2, survivors: 1, topComplete: true, covComplete: true, notScanned: [], pagesFailed: 0, listsNonEmpty: true, embeddedStreamsFailed: 0, flagsSet: false }, snapshotSha256: "b".repeat(64) }).outcome, "not_a_pass", "an empty digest is allowed under C3 for an input_too_large refusal");
  // The same promotion in the full server's rule (when the build is present).
  const built = path.join(__dirname, "..", "..", "dist", "verdict-rule.js");
  if (!existsSync(built)) return t.skip("no dist/verdict-rule.js (run tsc)");
  const ts = await import(require("node:url").pathToFileURL(built).href);
  assert.deepEqual(ts.applyScanToVerdict(refusal, facts), out);
});

test("round 6 (bundle): the scan tools refuse a completion claim beside an attachment disclosure whose name holds a line terminator (finding 3)", { skip }, async () => {
  const s = await start();
  try {
    for (const name of ["sensitive\nnotes.txt", "a b.txt"]) {
      s.script({ scan: scan({ coverage: { ...COV, not_scanned: [`attachment '${name}' was truncated`] } }), check: verdict("safe_to_send") });
      for (const tool of ["check_redaction", "find_sensitive_regions", "verify_redaction"]) {
        const { res, text } = await s.call(tool);
        assert.equal(res.isError, true, `${tool}\n${text}`);
        assert.doesNotMatch(text, /Safe to Send|No recoverable PII/, text);
      }
    }
  } finally {
    await s.close();
  }
});
