/**
 * omitly#1864, round 4: the strict parsers against what the REAL engines send. `testing/goldens/*.json` are
 * captured from the built native `omitly-redact` and the built wasm (`testing/capture-goldens.mjs`) over the
 * repository's test PDFs: scans, checks, locates, seal verifications (real v1 and v2 seals, a removed seal,
 * a forged and a tampered one) and sidecar verifies. A parser written beside a fake cannot show it is right;
 * these show that every real reply is READ (never refused) and gives the verdict its content gives, and that
 * the same replies with one field taken away are refused (fail closed).
 *
 * The Rust each rule comes from is cited in replies.ts. This file also settles which fields each engine sends
 * on a scan (the review asked): the native `find` (crates/omitly-cli/src/main.rs `do_find`) and the wasm
 * `scan` (crates/leakcheck-wasm/src/lib.rs `ScanResult`) BOTH send `ok`, `clean`, `count`, `total_findings`,
 * `regions` (wasm: `leaks`), `survivors`, `off_page`, `coverage` and `scan_complete`. The older note that the
 * native `find` returns only `{ok, count, regions}` is the contract golden's floor
 * (contract/cases/find.json lists only those keys; extra keys are allowed), not what the engine sends.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import * as path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { parseCheckVerdict, parseLocateReply, parseRedactAudit, parseScanReply, parseSealReply, parseSidecarVerifyReply } from "./replies.js";
import { createHash } from "node:crypto";
import { normalizeSealResult } from "./seal.js";
import { capped, isFailure, passOutcome, sealCaps, type Issued } from "./outcome.js";
import { checkLegOf, scanLegOf } from "./replies.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const GOLDENS = path.join(HERE, "..", "src", "testing", "goldens");
const WORKSPACE = path.join(HERE, "..", "..");
const EXE = process.platform === "win32" ? ".exe" : "";
const ENGINE =
  process.env.OMITLY_TEST_REDACT_BIN ??
  [path.join(WORKSPACE, "target", "debug", `omitly-redact${EXE}`), path.join(WORKSPACE, "target", "release", `omitly-redact${EXE}`)].find((p) => existsSync(p));
const IN_WORKSPACE = existsSync(path.join(WORKSPACE, "Cargo.toml"));
const skipEngine = !ENGINE && !(IN_WORKSPACE && process.env.CI) ? "no omitly-redact build (run `cargo build -p omitly-cli`)" : false;

const native: any = JSON.parse(readFileSync(path.join(GOLDENS, "native.json"), "utf8"));
const wasm: any = JSON.parse(readFileSync(path.join(GOLDENS, "wasm.json"), "utf8"));

/** What the wasm `scan` sends, in the shape the server reads (`wasmScanToFindShape` in index.ts). */
const wasmAsFind = (r: any) => ({
  ok: true,
  scan_complete: r.scan_complete,
  clean: r.clean,
  count: r.count,
  total_findings: r.total_findings,
  regions: r.leaks,
  survivors: r.survivors,
  off_page: r.off_page,
  coverage: r.coverage,
});

/** Expected outcome per test PDF: the real engine's verdict beside what its own scan found. The same table
 *  holds for the native engine and the wasm (they are one Rust function). */
const OUTCOME: Record<string, string> = {
  "tests/fixtures/sample.pdf": "needs_review", // engine: Safe to Send, but the scan lists 3 visible items
  "tests/fixtures/covered-text.pdf": "not_a_pass", // text under a box: blocking
  "tests/fixtures/invisible-text.pdf": "needs_review",
  "tests/fixtures/encrypted-aes256-survivor.pdf": "incomplete", // nothing could be read
  "tests/fixtures/au-corpus/05-scanned-raster.pdf": "needs_review", // image-only: the engine asks for review; scan incomplete
  "tests/fixtures/au-corpus/07-incremental-update-prior-revision.pdf": "needs_review",
  "tests/fixtures/au-corpus/08-acroform-fields.pdf": "needs_review",
  "scripts/fixtures/leakcheck/form-xobject-under-box.pdf": "not_a_pass",
  // The check refuses it unread (`input_too_large`), but the scan lists the survivor: a failed redaction.
  "(generated: tests/fixtures/covered-text.pdf plus a 66 MiB unreferenced stream)": "not_a_pass",
  "tests/fixtures/clean-text.pdf": "safe_to_send", // the positive control (contract T17): the only golden that reaches a pass
  // The redaction's own output carries the engine's bound report: the check relied on it (C2b, W6), so it is needs_review (T16, T17b).
  "(redact_entities output of tests/fixtures/sample.pdf)": "needs_review",
};

/** The pipeline over a real golden pair (contract §2): the snapshot digest is the sha256 of the real fixture file; the files that are
 *  not in the repository (the generated big file, the redaction's output) use the digest their check reported. */
function pipelineOutcome(pdf: string, check: any, scan: any, engine: "native" | "wasm"): Issued {
  const file = path.join(WORKSPACE, pdf);
  const snap = existsSync(file) ? createHash("sha256").update(readFileSync(file)).digest("hex") : (check.result?.sha256 ?? "");
  const parsed = parseScanReply(scan, { engine });
  if (!parsed.ok) throw new Error(`${pdf}: ${parsed.reason}`);
  const out = passOutcome({ check: checkLegOf(check), scan: scanLegOf(parsed.value, engine), snapshotSha256: snap });
  if (isFailure(out)) throw new Error(`${pdf}: row 0: ${out.failure}`);
  return out;
}

test("native goldens: every real `find` reply is read, and says what its content gives", () => {
  assert.ok(native.find.length >= 9);
  for (const e of native.find) {
    const p = parseScanReply(e.reply, { narrowed: Boolean(e.regions) });
    assert.equal(p.ok, true, `${e.pdf}: ${p.ok ? "" : p.reason}`);
    if (p.ok) {
      assert.equal(p.value.clean, p.value.total === 0, e.pdf);
      assert.equal(p.value.scanComplete, e.reply.scan_complete, e.pdf);
    }
  }
  // A region narrowing lists fewer items than it counts (main.rs `do_find`): a strict parser for the
  // un-narrowed reply would refuse it.
  const narrowed = native.find.find((e: any) => e.regions);
  assert.ok(narrowed.reply.total_findings > narrowed.reply.regions.length + narrowed.reply.survivors.length + narrowed.reply.off_page.length);
  assert.equal(parseScanReply(narrowed.reply).ok, false, "the same reply is refused when no narrowing was asked for");
});

test("native goldens: every real `check` reply is read, and every outcome is the one its content gives", () => {
  const finds = new Map<string, any>(native.find.filter((e: any) => !e.regions).map((e: any) => [e.pdf, e.reply]));
  for (const e of native.check) {
    const c = e.reply.check;
    const p = parseCheckVerdict(c);
    assert.equal(p.ok, true, `${e.pdf}: ${p.ok ? "" : p.reason}`);
    const f = finds.get(e.pdf);
    assert.equal(pipelineOutcome(e.pdf, c, f, "native").outcome, OUTCOME[e.pdf], e.pdf);
  }
  // Positive controls: the engine's Safe to Send is real (sample.pdf, which the scan beside it lowers; clean-text.pdf, which reaches a pass).
  const sample = native.check.find((e: any) => e.pdf === "tests/fixtures/sample.pdf").reply.check;
  assert.equal(sample.verdict, "safe_to_send");
  const clean = native.check.find((e: any) => e.pdf === "tests/fixtures/clean-text.pdf").reply.check;
  assert.equal(pipelineOutcome("tests/fixtures/clean-text.pdf", clean, finds.get("tests/fixtures/clean-text.pdf"), "native").outcome, "safe_to_send");
});

test("native goldens: every real `locate_text` reply is read", () => {
  for (const e of native.locate_text) assert.equal(parseLocateReply(e.reply).ok, true, e.pdf);
});

/** What each real seal reply is, through the whole chain: parser, normaliser, outcome. */
const SEAL_EXPECT: Record<string, { verdict: string; userVerdict: string | null; sealRemoved: boolean; outcome: string }> = {
  // A real pre-#506 seal: integrity since sealing only, not a clean document pass (lib.rs:1087 adds the CAUTION line).
  "docs/test-vectors/positive/clean-sealed.pdf": { verdict: "verified", userVerdict: null, sealRemoved: false, outcome: "incomplete" },
  "docs/test-vectors/positive/seal-at-boundary.pdf": { verdict: "no_report", userVerdict: null, sealRemoved: false, outcome: "incomplete" },
  "docs/test-vectors/compat/v3.2.0.pdf": { verdict: "unsupported_schema", userVerdict: "cannot_verify", sealRemoved: false, outcome: "incomplete" },
  "docs/test-vectors/compat/v5.3.0.pdf": { verdict: "unsupported_schema", userVerdict: "safe_to_send", sealRemoved: false, outcome: "incomplete" }, // the file's own report says nothing to review; a seal is not a check
  "docs/test-vectors/negative/stripped-seal.pdf": { verdict: "seal_invalid", userVerdict: null, sealRemoved: true, outcome: "not_a_pass" },
  "docs/test-vectors/negative/tampered-content.pdf": { verdict: "seal_invalid", userVerdict: null, sealRemoved: false, outcome: "not_a_pass" },
  "docs/test-vectors/negative/forged-signature.pdf": { verdict: "seal_invalid", userVerdict: null, sealRemoved: false, outcome: "not_a_pass" },
  "docs/test-vectors/negative/corrupt-audit-json.pdf": { verdict: "report_unparseable", userVerdict: null, sealRemoved: false, outcome: "incomplete" },
  "tests/fixtures/sample.pdf": { verdict: "no_report", userVerdict: null, sealRemoved: false, outcome: "incomplete" },
  "(redact_entities output of tests/fixtures/sample.pdf)": { verdict: "unsupported_schema", userVerdict: "safe_to_send", sealRemoved: false, outcome: "incomplete" },
};

test("native goldens: every real `verify_seal` reply (v1, v2, removed, forged, tampered) is read and gives its outcome", () => {
  assert.equal(native.verify_seal.length, Object.keys(SEAL_EXPECT).length);
  for (const e of native.verify_seal) {
    const want = SEAL_EXPECT[e.pdf]!;
    const p = parseSealReply(e.reply);
    assert.equal(p.ok, true, `${e.pdf}: ${p.ok ? "" : p.reason}`);
    const n = normalizeSealResult(e.reply);
    assert.equal(n.verdict, want.verdict, e.pdf);
    assert.equal(n.userVerdict, want.userVerdict, e.pdf);
    assert.equal(n.sealRemoved, want.sealRemoved, e.pdf);
    // Contract §3.5: a seal is integrity only: the outcome is the seal table's row, then at least `incomplete`; never safe_to_send.
    assert.equal(capped(null, sealCaps(n)).outcome, want.outcome, e.pdf);
  }
  // The real v2 pass carries the gate fields the v2 rules read (omitly-seal lib.rs `verify_report_bytes`).
  const v2 = native.verify_seal.find((e: any) => e.pdf.startsWith("docs/test-vectors/compat/v5.3.0")).reply;
  assert.equal(v2.auditV2SealValid, true);
  assert.equal(v2.auditV2ValidationError, null);
  assert.equal(v2.auditV2Overall, "pass");
});

test("native goldens: the real sidecar `verify` replies (a pass, and a fail over text that still renders) are read", () => {
  const [pass, fail] = native.verify;
  assert.equal(parseSidecarVerifyReply(pass.reply).ok, true);
  assert.equal(pass.reply.verdict, "pass");
  assert.equal(pass.reply.metadataScrubbed, true);
  assert.equal(parseSidecarVerifyReply(fail.reply).ok, true);
  assert.equal(fail.reply.verdict, "fail");
  // The engine's verdict is `compute_all_pass` (main.rs): the same pass with the metadata not scrubbed is a fail, and the
  // reply that says pass beside it contradicts itself.
  assert.equal(parseSidecarVerifyReply({ ...pass.reply, metadataScrubbed: false }).ok, false);
  assert.equal(parseSidecarVerifyReply({ ...pass.reply, metadataScrubbed: false, verdict: "fail" }).ok, true);
});

test("wasm goldens: every real `scan`, `check` and `locate` reply is read, and gives the same outcomes as the native engine", () => {
  const scans = new Map<string, any>(wasm.scan.map((e: any) => [e.pdf, e.reply]));
  for (const e of wasm.scan) {
    const p = parseScanReply(wasmAsFind(e.reply));
    assert.equal(p.ok, true, `${e.pdf}: ${p.ok ? "" : p.reason}`);
  }
  for (const e of wasm.check) {
    const p = parseCheckVerdict(e.reply);
    assert.equal(p.ok, true, `${e.pdf}: ${p.ok ? "" : p.reason}`);
    assert.equal(pipelineOutcome(e.pdf, e.reply, wasmAsFind(scans.get(e.pdf)), "wasm").outcome, OUTCOME[e.pdf], e.pdf);
  }
  for (const e of wasm.locate) assert.equal(parseLocateReply({ ok: e.reply.ok, count: e.reply.count, regions: e.reply.leaks }).ok, true);
});

test("both engines send every field a scan verdict depends on: taking any one away makes the strict parser refuse (fail closed)", () => {
  const REQUIRED = ["ok", "clean", "count", "total_findings", "regions", "survivors", "off_page", "coverage"];
  const COVERAGE = ["pages_total", "pages_scanned", "pages_failed", "not_scanned"];
  const replies: [string, any][] = [
    ...native.find.filter((e: any) => !e.regions).map((e: any) => [`native ${e.pdf}`, e.reply] as [string, any]),
    ...wasm.scan.map((e: any) => [`wasm ${e.pdf}`, wasmAsFind(e.reply)] as [string, any]),
  ];
  for (const [name, reply] of replies) {
    // Present in the real reply (this is the answer to "what does each engine send"), and the reply is read.
    for (const k of REQUIRED) assert.ok(k in reply, `${name}: the engine sends ${k}`);
    for (const k of COVERAGE) assert.ok(k in reply.coverage, `${name}: the engine sends coverage.${k}`);
    assert.equal(typeof reply.scan_complete, "boolean", `${name}: the engine sends scan_complete`);
    assert.equal(parseScanReply(reply).ok, true, name);
    for (const k of REQUIRED) {
      const { [k]: _gone, ...rest } = reply;
      assert.equal(parseScanReply(rest).ok, false, `${name}: without ${k}`);
    }
    for (const k of COVERAGE) {
      const { [k]: _gone, ...cov } = reply.coverage;
      assert.equal(parseScanReply({ ...reply, coverage: cov }).ok, false, `${name}: without coverage.${k}`);
    }
  }
  // The one field an older engine may lack is `scan_complete`, and then the scan reads as not complete: never complete.
  const { scan_complete: _s, ...noFlag } = native.find[0].reply;
  const { scan_complete: _c, ...noInner } = noFlag.coverage;
  const old = parseScanReply({ ...noFlag, coverage: noInner });
  assert.equal(old.ok && old.value.scanComplete, null);
});

test("native `find` sends under_redaction on page regions only (main.rs do_find); a survivor and a wasm leak carry none", () => {
  const sample = native.find.find((e: any) => e.pdf === "tests/fixtures/covered-text.pdf").reply;
  assert.equal(typeof sample.regions[0].under_redaction, "boolean");
  assert.equal("under_redaction" in sample.survivors[0], false);
  assert.equal("under_redaction" in wasm.scan.find((e: any) => e.reply.leaks?.length > 0).reply.leaks[0], false);
  assert.equal(parseScanReply({ ...sample, regions: [{ ...sample.regions[0], under_redaction: "yes" }] }).ok, false);
});

test("[real engines] the goldens are what the built engines send today (no drift)", { skip: skipEngine }, () => {
  const run = (req: unknown) => JSON.parse(spawnSync(ENGINE!, [], { input: JSON.stringify(req), encoding: "utf8", maxBuffer: 1 << 26 }).stdout);
  const keys = (o: any): string[] => Object.keys(o).sort();
  const covered = path.join(WORKSPACE, "tests", "fixtures", "covered-text.pdf");
  const find = run({ command: "find", pdfPath: covered });
  const golden = native.find.find((e: any) => e.pdf === "tests/fixtures/covered-text.pdf").reply;
  assert.deepEqual(keys(find), keys(golden));
  assert.deepEqual(keys(find.coverage), keys(golden.coverage));
  assert.deepEqual(find, golden);
  const check = run({ command: "check", pdfPath: covered }).check;
  delete check.report;
  const gc = native.check.find((e: any) => e.pdf === "tests/fixtures/covered-text.pdf").reply.check;
  assert.deepEqual(keys(check.result), keys(gc.result));
  assert.equal(check.verdict, gc.verdict);
  assert.equal(parseCheckVerdict(check).ok, true);
  const w = createRequire(import.meta.url)(path.join(HERE, "..", "wasm", "leakcheck_wasm.js"));
  const scan = JSON.parse(w.scan(new Uint8Array(readFileSync(covered))));
  const gs = wasm.scan.find((e: any) => e.pdf === "tests/fixtures/covered-text.pdf").reply;
  assert.deepEqual(keys(scan), keys(gs));
  assert.deepEqual(keys(scan.coverage), keys(gs.coverage));
});

// ---- the test stubs say what the real engine says (review: Kimi LOW) ---------------------------------------------

const STUBS = path.join(HERE, "..", "src", "testing");
const runStub = (file: string, req: unknown, env: Record<string, string> = {}) =>
  JSON.parse(spawnSync(process.execPath, [path.join(STUBS, file)], { input: JSON.stringify(req), encoding: "utf8", env: { ...process.env, ...env } }).stdout);
const keySet = (o: any) => new Set(Object.keys(o));
const subset = (a: Set<string>, b: Set<string>) => [...a].filter((k) => !b.has(k));

test("the test stubs (routing-stub, fake-engine) invent no field the real engine does not send, and send every field the strict parsers need", async () => {
  const { mkdtempSync, writeFileSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const dir = mkdtempSync(path.join(tmpdir(), "omitly-stubs-"));
  const doc = path.join(dir, "doc.txt");
  writeFileSync(doc, "contact fake.canary@example.test here");
  const realFind = native.find[0].reply;
  const realCovered = native.find.find((e: any) => e.pdf === "tests/fixtures/covered-text.pdf").reply;
  const realVerify = native.verify[0].reply;
  const realCheck = native.check[0].reply.check;
  for (const [name, reply] of [
    ["routing-stub", runStub("routing-stub.mjs", { command: "find", pdfPath: doc }, { OMITLY_ROUTING_STUB_SCAN_COMPLETE: "true" })],
    ["fake-engine", runStub("fake-engine.mjs", { command: "find", pdfPath: doc }, { FAKE_ENGINE_CANARY_EMAIL: "fake.canary@example.test" })],
  ] as const) {
    assert.deepEqual(subset(keySet(reply), keySet(realFind)), [], `${name} find: a field the real engine does not send`);
    assert.deepEqual(subset(keySet(reply.coverage), keySet(realFind.coverage)), [], `${name} find coverage`);
    assert.deepEqual(subset(keySet(reply.regions[0]), keySet(realCovered.regions[0])), [], `${name} find region`);
    assert.deepEqual(subset(keySet(realCovered.regions[0]), keySet(reply.regions[0])), [], `${name} find region lacks a field the real one has`);
    const parsed = parseScanReply(reply);
    assert.equal(parsed.ok, true, `${name}: ${parsed.ok ? "" : parsed.reason}`);
  }
  const stubVerify = runStub("routing-stub.mjs", { command: "verify", pdfPath: doc });
  assert.deepEqual(subset(keySet(stubVerify), keySet(realVerify)), [], "routing-stub verify");
  assert.equal(parseSidecarVerifyReply(stubVerify).ok, true);
  const stubCheck = runStub("fake-engine.mjs", { command: "check", pdfPath: doc }).check;
  assert.deepEqual(subset(keySet(stubCheck.result), keySet(realCheck.result)), [], "fake-engine check result");
  assert.equal(parseCheckVerdict(stubCheck).ok, true);
  const stubSeal = runStub("fake-engine.mjs", { command: "verify_seal", pdfPath: doc });
  const realSeal = native.verify_seal.find((e: any) => e.pdf.endsWith("clean-sealed.pdf")).reply;
  assert.deepEqual(subset(keySet(stubSeal), keySet(realSeal)), [], "fake-engine verify_seal");
  assert.equal(parseSealReply(stubSeal).ok, true);
});

test("native goldens: the real redaction audits (a v2 pass, and a real review_required) are read; the pass carries the whole nested result and only the trial notice as a warning", async () => {
  const pass = native.redact_entities[0].reply.audit;
  const review = native.redact[0].reply.audit;
  assert.equal(parseRedactAudit(pass).ok, true);
  assert.equal(parseRedactAudit(review).ok, true);
  assert.equal(pass.verdict, "pass");
  assert.equal(review.verdict, "fail");
  assert.equal(review.userVerdict, "needs_review");
  assert.deepEqual(pass.warnings.filter((w: string) => !w.startsWith("Marked as evaluation output.")), []);
  // The fake engine's redaction audit is read too (it is what the leak-canary suite drives).
  const { mkdtempSync, writeFileSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const dir = mkdtempSync(path.join(tmpdir(), "omitly-stubs-redact-"));
  const doc = path.join(dir, "doc.txt");
  writeFileSync(doc, "x");
  const fake = runStub("fake-engine.mjs", { command: "redact", pdfPath: doc, outputPath: path.join(dir, "out.txt"), regions: [{ page: 0, x: 1, y: 2, width: 3, height: 4 }] });
  assert.equal(parseRedactAudit(fake.audit).ok, true);
});
