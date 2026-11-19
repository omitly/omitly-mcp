// omitly#1890 step 2 (D3, X4, X9): a proposal's coordinates are bound to the bytes the scan that
// produced them actually loaded.
//
// Oracles: the real server over an in-memory MCP client, the real bundled wasm detector on a real PDF
// (tests/fixtures/sample.pdf, as free-scan-uncapped.test.ts), real files in a temp state dir, real
// hashing checked against node:crypto in the test. The native half uses a stub engine (a real child
// process speaking the engine's stdin/stdout contract) because this package's tests cannot require a
// Rust build; the real CLI's digest is proven by crates/omitly-cli/tests/analysis_digest.rs.
// Every negative test below says what to break so that it goes red.

import assert from "node:assert/strict";
import { test } from "node:test";
import { createHash } from "node:crypto";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { PDFDocument } from "pdf-lib";

import { ANALYSES_MAX, enqueueProposal, readProposal, recordAnalysis, recordAnalysisOf, sha256OfFile } from "./desktop.js";

// The two refusal texts, spelled out here on purpose (not imported): the design fixes the wording.
const NEEDS_SCAN =
  "Scan this document with find_sensitive_regions or locate_text and pass its analysisId before proposing boxes for it.";
const CHANGED = "The document changed since you looked at it; scan it again.";

const ENV_KEYS = ["OMITLY_ALLOWED_DIR", "OMITLY_REDACT_BIN", "OMITLY_PDF_BIN", "OMITLY_ENGINE_DIR", "OMITLY_STATE_DIR"] as const;
const HEX64 = /^[0-9a-f]{64}$/;
const ID32 = /^[0-9a-f]{32}$/;

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SAMPLE = [path.join(HERE, "..", "tests", "fixtures", "sample.pdf"), path.join(HERE, "..", "..", "tests", "fixtures", "sample.pdf")].find(
  (p) => existsSync(p),
);
assert.ok(SAMPLE, "the shared sample.pdf fixture must exist");

// The real engine, as verdict-parity.test.ts finds it (the workspace build, or OMITLY_TEST_REDACT_BIN).
// Outside the workspace there is none and the test is skipped; inside it, under CI, a missing binary
// FAILS: a check that could not run is not a pass.
const WORKSPACE = path.join(HERE, "..", "..");
const EXE = process.platform === "win32" ? ".exe" : "";
const REAL_ENGINE =
  process.env.OMITLY_TEST_REDACT_BIN ??
  [path.join(WORKSPACE, "target", "debug", `omitly-redact${EXE}`), path.join(WORKSPACE, "target", "release", `omitly-redact${EXE}`)].find((p) =>
    existsSync(p),
  );
const SKIP_REAL = !REAL_ENGINE && !(existsSync(path.join(WORKSPACE, "Cargo.toml")) && process.env.CI)
  ? "no omitly-redact build (run `cargo build -p omitly-cli`)"
  : false;

let counter = 0;
const sha = (b: Uint8Array) => createHash("sha256").update(b).digest("hex");
const shaFile = (f: string) => sha(readFileSync(f));
const textOf = (res: any): string => (res.content ?? []).filter((c: any) => c.type === "text").map((c: any) => c.text).join("\n");

function freshRoot(prefix: string): string {
  return realpathSync(mkdtempSync(path.join(tmpdir(), prefix)));
}

/** Document A is the shared sample; document B is a different, valid PDF. */
async function docB(): Promise<Buffer> {
  const d = await PDFDocument.create();
  d.addPage([200, 200]);
  return Buffer.from(await d.save());
}

function writePresence(stateDir: string): void {
  writeFileSync(
    path.join(stateDir, "desktop.json"),
    JSON.stringify({ pid: 4242, version: "5.6.0", accept_in_app: true, updated_at: new Date().toISOString() }),
  );
}

/** A stand-in engine: a real child process speaking the contract (JSON on stdin and stdout). `find` and
 *  `locate_text` read the file ONCE and report the digest of those bytes as `inputSha256`; every
 *  request is appended to `log`. `swapFrom` makes it overwrite the input with another file right
 *  after its one read: the file changing while a scan runs. `noDigest` models an engine older than
 *  this server. */
function stubEngine(root: string, opts: { swapFrom?: string; noDigest?: boolean } = {}): { bin: string; requests: () => any[] } {
  const bin = path.join(root, "stub-engine.mjs");
  const log = path.join(root, "engine-requests.log");
  writeFileSync(
    bin,
    `#!/usr/bin/env node
import { appendFileSync, copyFileSync, readFileSync } from "node:fs";
import { createHash } from "node:crypto";
const req = JSON.parse(readFileSync(0, "utf8"));
appendFileSync(${JSON.stringify(log)}, JSON.stringify(req) + "\\n");
if (req.command === "find" || req.command === "locate_text") {
  const bytes = readFileSync(req.pdfPath);
  const out = {
    ok: true,
    count: 1,
    regions: [{ page: 0, x: 10, y: 20, width: 30, height: 12, kind: req.command === "find" ? "email" : "text", preview: "ja••••om" }],
  };
  if (req.command === "find") {
    // The native find reply in full (contract C4/C6: the strict scan parser needs every field the real engine sends).
    Object.assign(out, {
      survivors: [], off_page: [], total_findings: 1, clean: false, scan_complete: true,
      coverage: { pages_total: 1, pages_scanned: 1, pages_failed: [], not_scanned: [], prior_revisions_scanned: false, metadata_scanned: false, acroform_scanned: false, attachments_scanned: false, form_xobjects_scanned: 0, annotation_appearances_scanned: 0, raster_pages: [], raster_only_pages: [], scan_complete: true },
    });
  }
  ${opts.noDigest ? "" : 'out.inputSha256 = createHash("sha256").update(bytes).digest("hex");'}
  ${opts.swapFrom ? `copyFileSync(${JSON.stringify(opts.swapFrom)}, req.pdfPath);` : ""}
  process.stdout.write(JSON.stringify(out));
} else {
  process.stdout.write(JSON.stringify({ ok: false, error: "stub engine: not implemented" }));
}
`,
    { mode: 0o755 },
  );
  chmodSync(bin, 0o755);
  return {
    bin,
    requests: () => (existsSync(log) ? readFileSync(log, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)) : []),
  };
}

interface Setup {
  root: string;
  stateDir: string;
  /** Present: the stub engine's binary path is configured, so the scan tools take the native path. */
  engineBin?: string;
  desktop?: boolean;
}

async function withServer<T>(s: Setup, fn: (call: (name: string, args: Record<string, unknown>) => Promise<any>) => Promise<T>): Promise<T> {
  for (const k of ENV_KEYS) delete process.env[k];
  process.env.OMITLY_ALLOWED_DIR = s.root;
  process.env.OMITLY_STATE_DIR = s.stateDir;
  if (s.engineBin) process.env.OMITLY_REDACT_BIN = s.engineBin;
  mkdirSync(s.stateDir, { recursive: true });
  if (s.desktop ?? true) writePresence(s.stateDir);
  counter += 1;
  const mod = (await import(`./index.js?analysis-binding=${counter}`)) as typeof import("./index.js");
  const server = mod.createServer();
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "Claude Desktop", version: "9.9.9" });
  await Promise.all([server.connect(a), client.connect(b)]);
  try {
    return await fn((name, args) => client.callTool({ name, arguments: args }));
  } finally {
    await client.close();
    await server.close();
  }
}

const proposalFiles = (stateDir: string): string[] =>
  existsSync(path.join(stateDir, "proposals")) ? readdirSync(path.join(stateDir, "proposals")) : [];

const REGION = { page: 0, x: 10, y: 20, width: 30, height: 12 };

// ------------------------------------------------------------------ scans ----

test("scan_returns_an_analysis_id_and_the_digest_of_the_bytes_it_read", async () => {
  // Free (wasm) path: no engine configured. The id's digest must be the digest of the bytes the scan
  // held, observed through what a proposal against that id records.
  {
    const root = freshRoot("omitly-ab-wasm-");
    const stateDir = path.join(root, "state");
    const pdf = path.join(root, "doc.pdf");
    copyFileSync(SAMPLE!, pdf);
    const want = shaFile(pdf);
    await withServer({ root, stateDir }, async (call) => {
      for (const [scan, args] of [
        ["find_sensitive_regions", { pdfPath: pdf }],
        ["locate_text", { pdfPath: pdf, texts: ["jane.doe@example.com"] }],
      ] as const) {
        const res = await call(scan, { ...args });
        assert.ok(!res.isError, textOf(res));
        const id = res.structuredContent.analysisId;
        assert.match(id, ID32, `${scan} returns an opaque 128-bit analysisId`);
        assert.ok(textOf(res).includes(id), `${scan} also names the id in its text`);
        const q = await call("propose_redactions", { pdfPath: pdf, outputPath: path.join(root, `${scan}.pdf`), regions: [REGION], analysisId: id });
        assert.ok(!q.isError, textOf(q));
        process.env.OMITLY_STATE_DIR = stateDir;
        assert.equal(readProposal(q.structuredContent.proposalId)?.pdfSha256, want, `${scan}: the id's digest is the digest of the bytes read`);
      }
    });
  }

  // Native path: the digest is the engine's `inputSha256`, from the one read it parsed. The stub
  // overwrites the file right after that read, so the file ON DISK afterwards is not what was scanned.
  // An id that hashed the path afterwards would certify the new bytes and the proposal would be queued.
  {
    const root = freshRoot("omitly-ab-native-");
    const stateDir = path.join(root, "state");
    const pdf = path.join(root, "doc.pdf");
    const other = path.join(root, "other.bin");
    copyFileSync(SAMPLE!, pdf);
    writeFileSync(other, await docB());
    const scanned = shaFile(pdf);
    const engine = stubEngine(root, { swapFrom: other });
    await withServer({ root, stateDir, engineBin: engine.bin }, async (call) => {
      const res = await call("find_sensitive_regions", { pdfPath: pdf });
      assert.ok(!res.isError, textOf(res));
      assert.deepEqual(engine.requests().map((r) => r.command), ["find"]);
      assert.notEqual(shaFile(pdf), scanned, "precondition: the file changed during the scan");
      const q = await call("propose_redactions", { pdfPath: pdf, outputPath: path.join(root, "o.pdf"), regions: [REGION], analysisId: res.structuredContent.analysisId });
      assert.equal(q.isError, true, "the id certifies the bytes the engine read, not whatever is on disk afterwards");
      assert.ok(textOf(q).includes(CHANGED), textOf(q));
      assert.deepEqual(proposalFiles(stateDir), []);
    });
  }
});

test("native scans return an analysis id whose digest is the engine's inputSha256 (find and locate_text)", async () => {
  const root = freshRoot("omitly-ab-native2-");
  const stateDir = path.join(root, "state");
  const pdf = path.join(root, "doc.pdf");
  copyFileSync(SAMPLE!, pdf);
  const want = shaFile(pdf);
  const engine = stubEngine(root);
  await withServer({ root, stateDir, engineBin: engine.bin }, async (call) => {
    for (const [scan, args] of [
      ["find_sensitive_regions", { pdfPath: pdf }],
      ["locate_text", { pdfPath: pdf, texts: ["x"] }],
    ] as const) {
      const res = await call(scan, { ...args });
      assert.ok(!res.isError, textOf(res));
      assert.match(res.structuredContent.analysisId, ID32);
      const q = await call("redact_pdf", { pdfPath: pdf, outputPath: path.join(root, `${scan}.pdf`), regions: [REGION], analysisId: res.structuredContent.analysisId });
      assert.ok(!q.isError, textOf(q));
      assert.equal(q.structuredContent.status, "queued");
      process.env.OMITLY_STATE_DIR = stateDir;
      assert.equal(readProposal(q.structuredContent.proposalId)?.pdfSha256, want);
    }
    assert.ok(!engine.requests().some((r) => r.command === "redact"), "a queued proposal never reaches the engine's redact");
  });
});

test("an engine that reports no document digest yields no analysis id, so nothing can be proposed against its scan", async () => {
  const root = freshRoot("omitly-ab-old-engine-");
  const stateDir = path.join(root, "state");
  const pdf = path.join(root, "doc.pdf");
  copyFileSync(SAMPLE!, pdf);
  const engine = stubEngine(root, { noDigest: true });
  await withServer({ root, stateDir, engineBin: engine.bin }, async (call) => {
    const res = await call("find_sensitive_regions", { pdfPath: pdf });
    assert.ok(!res.isError, "the scan itself still works");
    assert.equal(res.structuredContent.analysisId, undefined);
    const q = await call("propose_redactions", { pdfPath: pdf, outputPath: path.join(root, "o.pdf"), regions: [REGION] });
    assert.equal(q.isError, true);
    assert.ok(textOf(q).includes(NEEDS_SCAN));
  });
  assert.equal(recordAnalysisOf(pdf, undefined), undefined);
  assert.equal(recordAnalysisOf(pdf, "A".repeat(64)), undefined, "upper case is not a digest this server accepts");
  assert.equal(recordAnalysisOf(pdf, "g".repeat(64)), undefined);
  assert.throws(() => recordAnalysis(pdf, "abc"), /not a SHA-256/);
});

// ----------------------------------------------------------------- enqueue ---

test("enqueue_requires_an_analysis_id_naming_this_path", async () => {
  const root = freshRoot("omitly-ab-req-");
  const stateDir = path.join(root, "state");
  const pdf = path.join(root, "doc.pdf");
  const otherPdf = path.join(root, "other.pdf");
  copyFileSync(SAMPLE!, pdf);
  copyFileSync(SAMPLE!, otherPdf); // identical bytes: only the PATH differs, so only the path check can refuse
  await withServer({ root, stateDir }, async (call) => {
    const scanOfOther = await call("find_sensitive_regions", { pdfPath: otherPdf });
    const otherId = scanOfOther.structuredContent.analysisId;
    assert.match(otherId, ID32);
    // This document HAS been scanned, so a lookup by path would find an analysis for it: only the
    // missing, unknown or foreign id can make the calls below refuse.
    const own = await call("find_sensitive_regions", { pdfPath: pdf });
    const ownId = own.structuredContent.analysisId;
    assert.match(ownId, ID32);
    assert.notEqual(ownId, otherId);
    const attempts: Array<[string, string | undefined]> = [
      ["no id", undefined],
      ["an unknown id", "0".repeat(32)],
      ["an id that is not hex", "../../etc/passwd"],
      ["another document's id", otherId],
    ];
    for (const tool of ["propose_redactions", "redact_pdf"] as const) {
      for (const [what, id] of attempts) {
        const res = await call(tool, { pdfPath: pdf, outputPath: path.join(root, "o.pdf"), regions: [REGION], ...(id ? { analysisId: id } : {}) });
        assert.equal(res.isError, true, `${tool} with ${what} is refused`);
        assert.ok(textOf(res).includes(NEEDS_SCAN), `${tool} with ${what}: ${textOf(res)}`);
        assert.equal(res.structuredContent, undefined);
      }
    }
    assert.deepEqual(proposalFiles(stateDir), [], "nothing was written for any of the refused attempts");
    // The id of the document itself is accepted (control: the refusals above are about the id).
    const ok = await call("propose_redactions", { pdfPath: pdf, outputPath: path.join(root, "o.pdf"), regions: [REGION], analysisId: ownId });
    assert.ok(!ok.isError, textOf(ok));
    assert.equal(proposalFiles(stateDir).length, 1);
  });
});

test("enqueue_refuses_when_the_file_changed_since_analysis", async () => {
  const root = freshRoot("omitly-ab-changed-");
  const stateDir = path.join(root, "state");
  const pdf = path.join(root, "doc.pdf");
  copyFileSync(SAMPLE!, pdf);
  await withServer({ root, stateDir }, async (call) => {
    const scan = await call("find_sensitive_regions", { pdfPath: pdf }); // scan A
    const idA = scan.structuredContent.analysisId;
    writeFileSync(pdf, await docB()); // replace the file with B
    for (const tool of ["propose_redactions", "redact_pdf"] as const) {
      const res = await call(tool, { pdfPath: pdf, outputPath: path.join(root, "o.pdf"), regions: [REGION], analysisId: idA });
      assert.equal(res.isError, true, `${tool}: A's coordinates with A's id after the file became B`);
      assert.ok(textOf(res).includes(CHANGED), textOf(res));
    }
    assert.deepEqual(proposalFiles(stateDir), [], "nothing was queued");
  });
  // The file removed: also "changed", never a crash or a queued proposal.
  const root2 = freshRoot("omitly-ab-gone-");
  const stateDir2 = path.join(root2, "state");
  const pdf2 = path.join(root2, "doc.pdf");
  copyFileSync(SAMPLE!, pdf2);
  await withServer({ root: root2, stateDir: stateDir2 }, async (call) => {
    const scan = await call("find_sensitive_regions", { pdfPath: pdf2 });
    const out = path.join(root2, "o.pdf");
    // Confinement needs the input to exist when a tool is called, so call enqueue directly: it is
    // where the file is hashed.
    process.env.OMITLY_STATE_DIR = stateDir2;
    unlinkSync(pdf2);
    assert.throws(
      () => enqueueProposal({ client: { name: "t", version: "1" }, tool: "redact_pdf", pdfPath: pdf2, outputPath: out, regions: [REGION], analysisId: scan.structuredContent.analysisId }),
      (e: Error) => e.message === CHANGED,
    );
    assert.deepEqual(proposalFiles(stateDir2), []);
  });
});

test("a_later_scan_of_the_same_path_does_not_certify_an_earlier_analysis", async () => {
  const root = freshRoot("omitly-ab-later-");
  const stateDir = path.join(root, "state");
  const pdf = path.join(root, "doc.pdf");
  copyFileSync(SAMPLE!, pdf);
  const b = await docB();
  await withServer({ root, stateDir }, async (call) => {
    const scanA = await call("find_sensitive_regions", { pdfPath: pdf });
    const idA = scanA.structuredContent.analysisId;
    writeFileSync(pdf, b); // replace with B
    const scanB = await call("find_sensitive_regions", { pdfPath: pdf }); // scan B
    const idB = scanB.structuredContent.analysisId;
    assert.notEqual(idA, idB, "two scans are two analyses even for one path");

    for (const tool of ["propose_redactions", "redact_pdf"] as const) {
      const stale = await call(tool, { pdfPath: pdf, outputPath: path.join(root, "o.pdf"), regions: [REGION], analysisId: idA });
      assert.equal(stale.isError, true, `${tool}: A's coordinates with A's id, after B was scanned`);
      assert.ok(textOf(stale).includes(CHANGED), textOf(stale));
    }
    assert.deepEqual(proposalFiles(stateDir), [], "nothing written for A's id");

    // Control: B's own id is accepted, and records B's digest: the refusal above is about A's id.
    const fresh = await call("propose_redactions", { pdfPath: pdf, outputPath: path.join(root, "o2.pdf"), regions: [REGION], analysisId: idB });
    assert.ok(!fresh.isError, textOf(fresh));
    process.env.OMITLY_STATE_DIR = stateDir;
    assert.equal(readProposal(fresh.structuredContent.proposalId)?.pdfSha256, sha(b));
  });
});

test("enqueue_writes_the_analysis_digest_not_the_hash_taken_now", async () => {
  const root = freshRoot("omitly-ab-digest-");
  const stateDir = path.join(root, "state");
  process.env.OMITLY_STATE_DIR = stateDir;
  const pdf = path.join(root, "doc.pdf");
  copyFileSync(SAMPLE!, pdf);
  // An analysis whose digest is the file's: queued, and the record carries exactly the analysis digest.
  const digest = shaFile(pdf);
  const { proposal } = enqueueProposal({
    client: { name: "t", version: "1" },
    tool: "redact_pdf",
    pdfPath: pdf,
    outputPath: path.join(root, "o.pdf"),
    regions: [REGION],
    analysisId: recordAnalysis(pdf, digest),
  });
  assert.equal(proposal.pdfSha256, digest);
  assert.equal(readProposal(proposal.id)?.pdfSha256, digest, "and so does the file on disk");
  assert.equal(readProposal(proposal.id)?.binding, undefined, "a proposal with coordinates is not 'at-queue'");
  // An analysis of other bytes can never be "corrected" by hashing the file now: it is refused, and no
  // record is written with the hash taken at enqueue.
  const before = proposalFiles(stateDir).length;
  assert.throws(
    () => enqueueProposal({ client: { name: "t", version: "1" }, tool: "redact_pdf", pdfPath: pdf, outputPath: path.join(root, "o.pdf"), regions: [REGION], analysisId: recordAnalysis(pdf, "0".repeat(64)) }),
    (e: Error) => e.message === CHANGED,
  );
  assert.equal(proposalFiles(stateDir).length, before);
});

test("enqueue_returns_revision_equal_to_sha256_of_written_bytes", async () => {
  const root = freshRoot("omitly-ab-rev-");
  const stateDir = path.join(root, "state");
  process.env.OMITLY_STATE_DIR = stateDir;
  const pdf = path.join(root, "doc.pdf");
  copyFileSync(SAMPLE!, pdf);
  // Directly: the revision is the digest of the exact bytes now on disk.
  const q = enqueueProposal({
    client: { name: "t", version: "1" },
    tool: "redact_pdf",
    pdfPath: pdf,
    outputPath: path.join(root, "o.pdf"),
    regions: [REGION],
    analysisId: recordAnalysis(pdf, shaFile(pdf)),
  });
  const file = path.join(stateDir, "proposals", `${q.proposal.id}.json`);
  assert.match(q.revision, HEX64);
  assert.equal(q.revision, sha(readFileSync(file)));
  assert.ok(sha(Buffer.from(JSON.stringify(q.proposal))) !== q.revision, "the revision is of the written bytes, not of a re-serialisation");

  // Through every tool that queues: the queued output carries the same value.
  await withServer({ root, stateDir }, async (call) => {
    const scan = await call("find_sensitive_regions", { pdfPath: pdf });
    const id = scan.structuredContent.analysisId;
    const queued = [
      await call("propose_redactions", { pdfPath: pdf, outputPath: path.join(root, "a.pdf"), regions: [REGION], analysisId: id }),
      await call("redact_pdf", { pdfPath: pdf, outputPath: path.join(root, "b.pdf"), regions: [REGION], analysisId: id }),
      await call("redact_by_entity", { pdfPath: pdf, outputPath: path.join(root, "c.pdf"), kinds: ["email"] }),
    ];
    for (const r of queued) {
      assert.ok(!r.isError, textOf(r));
      const sc = r.structuredContent;
      assert.equal(sc.status, "queued");
      assert.match(sc.revision, HEX64);
      assert.equal(sc.revision, shaFile(path.join(stateDir, "proposals", `${sc.proposalId}.json`)), `${sc.tool}: revision names the exact bytes written`);
    }
  });
});

// ------------------------------------------------------------- kinds only ----

test("a kinds-only proposal (redact_by_entity) is bound at queue time and says so", async () => {
  const root = freshRoot("omitly-ab-kinds-");
  const stateDir = path.join(root, "state");
  const pdf = path.join(root, "doc.pdf");
  copyFileSync(SAMPLE!, pdf);
  await withServer({ root, stateDir }, async (call) => {
    const res = await call("redact_by_entity", { pdfPath: pdf, outputPath: path.join(root, "o.pdf"), kinds: ["email", "tfn"] }); // no analysisId needed
    assert.ok(!res.isError, textOf(res));
    process.env.OMITLY_STATE_DIR = stateDir;
    const rec = readProposal(res.structuredContent.proposalId)!;
    assert.deepEqual(rec.kinds, ["email", "tfn"]);
    assert.equal(rec.regions, undefined);
    assert.equal(rec.pdfSha256, shaFile(pdf));
    assert.equal(rec.binding, "at-queue");
  });
});

// -------------------------------------------------------------- the map ------

test("the analyses map keeps 256 entries and forgets the oldest", () => {
  const root = freshRoot("omitly-ab-evict-");
  process.env.OMITLY_STATE_DIR = path.join(root, "state");
  const pdf = path.join(root, "doc.pdf");
  copyFileSync(SAMPLE!, pdf);
  const digest = sha256OfFile(pdf);
  assert.equal(ANALYSES_MAX, 256);
  const ids = Array.from({ length: ANALYSES_MAX + 1 }, () => recordAnalysis(pdf, digest));
  const input = (analysisId: string) => ({ client: { name: "t", version: "1" }, tool: "redact_pdf" as const, pdfPath: pdf, outputPath: path.join(root, "o.pdf"), regions: [REGION], analysisId });
  assert.throws(() => enqueueProposal(input(ids[0])), (e: Error) => e.message === NEEDS_SCAN, "the oldest of 257 is evicted");
  assert.ok(enqueueProposal(input(ids[1])).revision, "the second oldest is kept");
  assert.ok(enqueueProposal(input(ids[ANALYSES_MAX])).revision, "the newest is kept");
});

// ---------------------------------------------------- wire hygiene -----------

test("analysisId is read only when the call would queue: without a desktop it is not forwarded to the engine", async () => {
  const root = freshRoot("omitly-ab-nodesktop-");
  const stateDir = path.join(root, "state");
  const pdf = path.join(root, "doc.pdf");
  copyFileSync(SAMPLE!, pdf);
  const engine = stubEngine(root);
  await withServer({ root, stateDir, engineBin: engine.bin, desktop: false }, async (call) => {
    const res = await call("redact_pdf", { pdfPath: pdf, outputPath: path.join(root, "o.pdf"), regions: [REGION], analysisId: "whatever" });
    assert.equal(res.isError, true, "the stub engine refuses a redact, which is all this test needs");
    const redact = engine.requests().filter((r) => r.command === "redact");
    assert.equal(redact.length, 1, "the direct path ran as before");
    assert.ok(!JSON.stringify(redact[0]).includes("analysisId"), "the id is never forwarded to the engine");
    assert.deepEqual(proposalFiles(stateDir), []);
  });
});

// ------------------------------------------------------------ real engine ----

test("with the real omitly-redact, both scans bind a proposal to the digest of the file the engine read", { skip: SKIP_REAL }, async () => {
  assert.ok(REAL_ENGINE, "the real engine must exist when this test is not skipped");
  const root = freshRoot("omitly-ab-real-");
  const stateDir = path.join(root, "state");
  const pdf = path.join(root, "doc.pdf");
  copyFileSync(SAMPLE!, pdf);
  const want = shaFile(pdf);
  await withServer({ root, stateDir, engineBin: REAL_ENGINE }, async (call) => {
    for (const [scan, args] of [
      ["find_sensitive_regions", { pdfPath: pdf }],
      ["locate_text", { pdfPath: pdf, texts: ["jane.doe@example.com"] }],
    ] as const) {
      const res = await call(scan, { ...args });
      assert.ok(!res.isError, textOf(res));
      assert.match(res.structuredContent.analysisId, ID32, scan);
      const q = await call("propose_redactions", { pdfPath: pdf, outputPath: path.join(root, `${scan}.pdf`), regions: [REGION], analysisId: res.structuredContent.analysisId });
      assert.ok(!q.isError, textOf(q));
      process.env.OMITLY_STATE_DIR = stateDir;
      assert.equal(readProposal(q.structuredContent.proposalId)?.pdfSha256, want, `${scan}: the real CLI's inputSha256 is the file's digest`);
    }
    // And the real engine's id goes stale when the file changes.
    const res = await call("find_sensitive_regions", { pdfPath: pdf });
    writeFileSync(pdf, await docB());
    const stale = await call("propose_redactions", { pdfPath: pdf, outputPath: path.join(root, "stale.pdf"), regions: [REGION], analysisId: res.structuredContent.analysisId });
    assert.equal(stale.isError, true);
    assert.ok(textOf(stale).includes(CHANGED));
  });
});
