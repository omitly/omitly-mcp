/**
 * #1563: `verify_redaction` vetted the PDF path but not the `<pdf>.audit.json`
 * sidecar the engine derives and reads itself with `fs::read` (which follows
 * symlinks). A link planted at that name read a file outside OMITLY_ALLOWED_DIR
 * and the engine's response — reason codes included — went back to the model.
 *
 * The "engine" is a throwaway script that does what the real one does on
 * `verify`: read `<pdfPath>.audit.json` (following links) and report each
 * entry's `reason_code`. It logs every command it is sent, so a refusal can be
 * shown to have happened BEFORE the engine ran. `FAKE_SWAP_SIDECAR_TO` makes it
 * swap the sidecar for a link mid-call, i.e. the check-then-use window.
 * Everything runs through a real in-memory MCP client, the way a model calls it.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

const CANARY = "SECRET-CANARY-REASON-1563";

const ENV_KEYS = [
  "OMITLY_ALLOWED_DIR",
  "OMITLY_REDACT_BIN",
  "OMITLY_PDF_BIN",
  "OMITLY_ENGINE_DIR",
  "OMITLY_STATE_DIR",
  "OMITLY_FREE_CAP",
  "FAKE_ENGINE_LOG",
  "FAKE_SWAP_SIDECAR_TO",
  "FAKE_FAIL_MODE",
] as const;

let importCounter = 0;
async function importFresh(env: Partial<Record<(typeof ENV_KEYS)[number], string>>) {
  for (const key of ENV_KEYS) delete process.env[key];
  for (const [k, v] of Object.entries(env)) process.env[k] = v;
  importCounter += 1;
  return (await import("./index.js?sidecar-confinement=" + importCounter)) as typeof import("./index.js");
}

const ENGINE_SOURCE = `#!/usr/bin/env node
import { appendFileSync, readFileSync, rmSync, symlinkSync } from "node:fs";
let raw = "";
process.stdin.on("data", (d) => (raw += d));
process.stdin.on("end", () => {
  const req = JSON.parse(raw);
  appendFileSync(process.env.FAKE_ENGINE_LOG, req.command + "\\n");
  let out;
  if (req.command === "find") {
    out = { ok: true, clean: true, count: 0, total_findings: 0, regions: [],
            coverage: { pages_total: 1, pages_scanned: 1, pages_failed: [], not_scanned: [] } };
  } else if (req.command === "verify") {
    const sidecar = req.pdfPath + ".audit.json";
    if (process.env.FAKE_SWAP_SIDECAR_TO) {
      rmSync(sidecar);
      symlinkSync(process.env.FAKE_SWAP_SIDECAR_TO, sidecar);
    }
    const entries = JSON.parse(readFileSync(sidecar, "utf8"));
    if (process.env.FAKE_FAIL_MODE === "stderr") {
      process.stderr.write("engine failed after reading: " + JSON.stringify(entries));
      process.exit(3);
    }
    if (process.env.FAKE_FAIL_MODE === "stdout") {
      process.stdout.write("not json: " + JSON.stringify(entries));
      process.exit(0);
    }
    out = { ok: true, verdict: "fail",
            regions: entries.map((e) => ({ page: e.page, reason: e.reason_code, verification: { result: "fail", detail: "x" } })),
            metadataScrubbed: true, hiddenContent: [], disclosures: [] };
  } else {
    out = { ok: false, error: "unhandled " + req.command };
  }
  process.stdout.write(JSON.stringify(out));
});
`;

const entry = (reason: string) => [
  { page: 0, bbox: { x: 1, y: 1, width: 5, height: 5 }, timestamp: "2026-01-01T00:00:00Z", reason_code: reason, verification: { result: "pass" } },
];

async function prepared() {
  const base = realpathSync(mkdtempSync(path.join(tmpdir(), "omitly-sidecar-1563-")));
  const root = path.join(base, "root");
  const outside = path.join(base, "outside");
  mkdirSync(root);
  mkdirSync(outside);
  const bin = path.join(base, "fake-verify-engine.mjs");
  writeFileSync(bin, ENGINE_SOURCE);
  chmodSync(bin, 0o755);
  const log = path.join(base, "engine.log");
  writeFileSync(log, "");
  const pdf = path.join(root, "doc.pdf");
  writeFileSync(pdf, "%PDF-1.4\nplaceholder");
  // The file a link would exfiltrate: audit-shaped, so the engine would echo it.
  const outsideSidecar = path.join(outside, "other-matter.audit.json");
  writeFileSync(outsideSidecar, JSON.stringify(entry(CANARY)));
  return { base, root, outside, bin, log, pdf, outsideSidecar };
}

async function call(
  env: Partial<Record<(typeof ENV_KEYS)[number], string>>,
  name: string,
  args: Record<string, unknown>,
): Promise<any> {
  const { createServer } = await importFresh(env);
  const server = createServer();
  const [serverTransport, clientTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "sidecar-confinement-test", version: "0.0.0" });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  try {
    return await client.callTool({ name, arguments: args });
  } finally {
    await client.close();
    await server.close();
  }
}

const envFor = (p: { root: string; bin: string; base: string; log: string }) => ({
  OMITLY_ALLOWED_DIR: p.root,
  OMITLY_REDACT_BIN: p.bin,
  OMITLY_STATE_DIR: path.join(p.base, "state"),
  FAKE_ENGINE_LOG: p.log,
});

const commandsRun = (log: string) => readFileSync(log, "utf8").split("\n").filter(Boolean);

function assertRefusedWithoutContent(res: any, log: string) {
  assert.equal(res.isError, true);
  const everything = JSON.stringify(res);
  assert.ok(!everything.includes(CANARY), `canary reached the response: ${everything.slice(0, 1500)}`);
  assert.match(res.content[0].text, /refusing to verify against .*audit\.json/);
  assert.deepEqual(commandsRun(log).filter((c) => c === "verify"), [], "the engine must not run `verify` at all");
}

test("verify_redaction: a sidecar symlinked OUTSIDE the root is refused, engine never runs, no canary", async () => {
  const p = await prepared();
  symlinkSync(p.outsideSidecar, `${p.pdf}.audit.json`);
  const res = await call(envFor(p), "verify_redaction", { pdfPath: p.pdf });
  assertRefusedWithoutContent(res, p.log);
});

test("verify_redaction: a sidecar symlinked to another file INSIDE the root is refused too", async () => {
  const p = await prepared();
  const other = path.join(p.root, "matter-b.pdf.audit.json");
  writeFileSync(other, JSON.stringify(entry(CANARY)));
  symlinkSync(other, `${p.pdf}.audit.json`);
  const res = await call(envFor(p), "verify_redaction", { pdfPath: p.pdf });
  assertRefusedWithoutContent(res, p.log);
});

test("verify_redaction: a DANGLING sidecar symlink is refused, not treated as 'no sidecar'", async () => {
  const p = await prepared();
  symlinkSync(path.join(p.outside, "not-there-yet.json"), `${p.pdf}.audit.json`);
  const res = await call(envFor(p), "verify_redaction", { pdfPath: p.pdf });
  assertRefusedWithoutContent(res, p.log);
  assert.deepEqual(commandsRun(p.log), [], "not even the fallback re-scan may run");
});

test("verify_redaction: a normal in-root sidecar is still verified (mode sidecar)", async () => {
  const p = await prepared();
  writeFileSync(`${p.pdf}.audit.json`, JSON.stringify(entry("PII.EMAIL")));
  const res = await call(envFor(p), "verify_redaction", { pdfPath: p.pdf });
  assert.equal(res.structuredContent.mode, "sidecar");
  assert.deepEqual(commandsRun(p.log), ["verify"]);
  assert.ok(res.content[0].text.includes("PII.EMAIL"));
});

test("verify_redaction: a PDF that is itself an in-root symlink still verifies against ITS real name's sidecar", async () => {
  const p = await prepared();
  writeFileSync(`${p.pdf}.audit.json`, JSON.stringify(entry("PII.EMAIL")));
  const alias = path.join(p.root, "alias.pdf");
  symlinkSync(p.pdf, alias);
  const res = await call(envFor(p), "verify_redaction", { pdfPath: alias });
  assert.equal(res.structuredContent.mode, "sidecar");
  assert.ok(res.content[0].text.includes("PII.EMAIL"));
});

test("verify_redaction: no sidecar behaves as before (general re-scan)", async () => {
  const p = await prepared();
  const res = await call(envFor(p), "verify_redaction", { pdfPath: p.pdf });
  assert.equal(res.structuredContent.mode, "rescan");
  assert.equal(res.structuredContent.clean, true);
  assert.deepEqual(commandsRun(p.log), ["find"]);
});

test("verify_redaction: a sidecar swapped for an outside link WHILE the engine runs is discarded unread", async () => {
  const p = await prepared();
  writeFileSync(`${p.pdf}.audit.json`, JSON.stringify(entry("PII.EMAIL")));
  const res = await call(
    { ...envFor(p), FAKE_SWAP_SIDECAR_TO: p.outsideSidecar },
    "verify_redaction",
    { pdfPath: p.pdf },
  );
  assert.equal(res.isError, true);
  assert.ok(!JSON.stringify(res).includes(CANARY), "the swapped-in file's content must not reach the model");
  assert.match(res.content[0].text, /changed while the engine was reading/);
});

test("redact_pdf: an output whose .audit.json name is an outside link is refused, nothing written (existing guard)", async () => {
  const p = await prepared();
  const out = path.join(p.root, "out.pdf");
  const victim = path.join(p.outside, "victim.json");
  writeFileSync(victim, "untouched");
  symlinkSync(victim, `${out}.audit.json`);
  const res = await call(envFor(p), "redact_pdf", {
    pdfPath: p.pdf,
    outputPath: out,
    regions: [{ page: 0, x: 1, y: 1, width: 5, height: 5, reason: "r" }],
  });
  assert.equal(res.isError, true);
  assert.match(res.content[0].text, /refusing to overwrite/);
  assert.equal(readFileSync(victim, "utf8"), "untouched");
  assert.equal(existsSync(out), false);
  assert.deepEqual(commandsRun(p.log), []);
});

for (const mode of ["stderr", "stdout"] as const) {
  test(`verify_redaction: a sidecar swapped to an outside link, then the engine FAILS with the content on ${mode}, drops the engine's text`, async () => {
    const p = await prepared();
    writeFileSync(`${p.pdf}.audit.json`, JSON.stringify(entry("PII.EMAIL")));
    const res = await call(
      { ...envFor(p), FAKE_SWAP_SIDECAR_TO: p.outsideSidecar, FAKE_FAIL_MODE: mode },
      "verify_redaction",
      { pdfPath: p.pdf },
    );
    assert.equal(res.isError, true);
    assert.ok(!JSON.stringify(res).includes(CANARY), `canary escaped via engine ${mode}: ${JSON.stringify(res).slice(0, 800)}`);
    assert.match(res.content[0].text, /changed while the engine was reading/);
  });
}

test("verify_redaction: an engine failure with the sidecar UNCHANGED still propagates the engine's own error", async () => {
  const p = await prepared();
  writeFileSync(`${p.pdf}.audit.json`, JSON.stringify(entry("PII.EMAIL")));
  const res = await call(
    { ...envFor(p), FAKE_FAIL_MODE: "stderr" },
    "verify_redaction",
    { pdfPath: p.pdf },
  );
  assert.equal(res.isError, true);
  assert.match(res.content[0].text, /engine exited 3: engine failed after reading/);
});
