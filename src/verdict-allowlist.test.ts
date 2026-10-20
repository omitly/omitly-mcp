/**
 * omitly#1267 review: `check_redaction`'s `verdict.result` is engine output,
 * and the MCP's output allowlist exists so a malformed or hostile engine
 * binary cannot ship arbitrary content to the model. A `result` that is not
 * exactly the CheckResult shape — an unknown field, a control character, an
 * over-long string, a state that disagrees with the verdict — is dropped:
 * `result: null`, `reason_code: "result_invalid"`, verdict forced to
 * `cannot_verify`. The genuine wasm result still passes.
 *
 * The "engine" here is a throwaway script that answers `find` with a clean
 * scan and `check` with the JSON in FAKE_CHECK_RESPONSE.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { chmodSync, existsSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SECRET = "078-05-1120";

const ENV_KEYS = [
  "OMITLY_ALLOWED_DIR",
  "OMITLY_REDACT_BIN",
  "OMITLY_PDF_BIN",
  "OMITLY_ENGINE_DIR",
  "OMITLY_STATE_DIR",
  "OMITLY_FREE_CAP",
  "FAKE_CHECK_RESPONSE",
] as const;

let importCounter = 0;
async function importFresh(env: Partial<Record<(typeof ENV_KEYS)[number], string>>) {
  for (const key of ENV_KEYS) delete process.env[key];
  for (const [k, v] of Object.entries(env)) process.env[k] = v;
  importCounter += 1;
  return (await import("./index.js?verdict-allowlist=" + importCounter)) as typeof import("./index.js");
}

function fakeEngine(root: string): string {
  const bin = path.join(root, "fake-check-engine.mjs");
  writeFileSync(
    bin,
    `#!/usr/bin/env node
let raw = "";
process.stdin.on("data", (d) => (raw += d));
process.stdin.on("end", () => {
  const req = JSON.parse(raw);
  const clean = { pages_total: 1, pages_scanned: 1, pages_failed: [], not_scanned: [] };
  const out =
    req.command === "find"
      ? { ok: true, clean: true, count: 0, total_findings: 0, regions: [], survivors: [], off_page: [], coverage: clean }
      : req.command === "check"
        ? JSON.parse(process.env.FAKE_CHECK_RESPONSE)
        : { ok: false, error: "unhandled" };
  process.stdout.write(JSON.stringify(out));
});
`,
  );
  chmodSync(bin, 0o755);
  return bin;
}

async function callCheck(env: Partial<Record<(typeof ENV_KEYS)[number], string>>, pdfPath: string): Promise<any> {
  const { createServer } = await importFresh(env);
  const server = createServer();
  const [serverTransport, clientTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "verdict-allowlist-test", version: "0.0.0" });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  try {
    return await client.callTool({ name: "check_redaction", arguments: { pdfPath } });
  } finally {
    await client.close();
    await server.close();
  }
}

/** A result the engine really produces (shape), for mutation. */
function genuineResult(): Record<string, unknown> {
  return {
    state: "needs_review",
    blocking: true,
    summary: "Omitly found information in this file that a recipient could recover.",
    pagesTotal: 1,
    pagesRead: 1,
    checked: [{ text: "Text still under black or white boxes" }],
    notChecked: [{ text: "Text inside images is not read: this check does no OCR." }],
    problems: [{ text: "Text is still in the file under a painted box on these pages.", pages: [1] }],
    review: [],
    information: [],
    decisions: [],
    reasons: [],
    checkedAt: "2026-09-30T00:00:00Z",
    omitlyVersion: "0.1.0",
    sha256: "a".repeat(64),
    canWrite: false,
    sizeBytes: 100,
    producer: null,
  };
}

function checkResponse(result: unknown, verdict = "needs_review", blocking = true) {
  return JSON.stringify({ ok: true, check: { verdict, blocking, result, report: null, reason_code: null } });
}

function setup() {
  const root = realpathSync(mkdtempSync(path.join(tmpdir(), "omitly-verdict-allowlist-")));
  const doc = path.join(root, "doc.pdf");
  writeFileSync(doc, "%PDF-1.4\nplaceholder");
  return { root, doc, bin: fakeEngine(root) };
}

const HOSTILE: [string, () => unknown, string?, boolean?][] = [
  ["an unknown field carrying text", () => ({ ...genuineResult(), rawText: `SSN ${SECRET}` })],
  ["an unknown field on an item", () => ({ ...genuineResult(), problems: [{ text: "x", rawText: SECRET }] })],
  ["a control character in a line", () => ({ ...genuineResult(), summary: `line\u0007${SECRET}` })],
  ["a newline in a line", () => ({ ...genuineResult(), summary: `line\nSSN ${SECRET}` })],
  ["an over-long line", () => ({ ...genuineResult(), summary: `${SECRET} `.repeat(400) })],
  ["a malformed sha256", () => ({ ...genuineResult(), sha256: SECRET })],
  ["a malformed checkedAt", () => ({ ...genuineResult(), checkedAt: SECRET })],
  ["a state that disagrees with the verdict", () => genuineResult(), "safe_to_send", false],
  ["a blocking flag that disagrees with the verdict", () => genuineResult(), "needs_review", false],
  ["a page number of 0", () => ({ ...genuineResult(), problems: [{ text: "x", pages: [0] }] })],
  ["a result that is not an object", () => SECRET],
  // omitly#1496: `decisionChannel` is a closed set, and omitted (never null) when absent.
  ["an unknown decisionChannel", () => ({ ...genuineResult(), decisionChannel: `robot ${SECRET}` })],
  ["a null decisionChannel", () => ({ ...genuineResult(), decisionChannel: null })],
];

for (const [name, make, verdict, blocking] of HOSTILE) {
  test(`check_redaction drops an engine result with ${name}`, async () => {
    const { root, doc, bin } = setup();
    const res = await callCheck(
      {
        OMITLY_ALLOWED_DIR: root,
        OMITLY_REDACT_BIN: bin,
        FAKE_CHECK_RESPONSE: checkResponse(make(), verdict, blocking),
      },
      doc,
    );
    const v = res.structuredContent?.verdict;
    assert.ok(v, `no verdict: ${JSON.stringify(res.content)}`);
    assert.equal(v.verdict, "cannot_verify");
    assert.equal(v.blocking, false);
    assert.equal(v.result, null);
    assert.equal("report" in v, false);
    assert.equal(v.reason_code, "result_invalid");
    assert.ok(!JSON.stringify(res).includes(SECRET), "engine text reached the tool output");
  });
}

test("check_redaction keeps a genuine-shaped engine result", async () => {
  const { root, doc, bin } = setup();
  const res = await callCheck(
    { OMITLY_ALLOWED_DIR: root, OMITLY_REDACT_BIN: bin, FAKE_CHECK_RESPONSE: checkResponse(genuineResult()) },
    doc,
  );
  const v = res.structuredContent.verdict;
  assert.equal(v.verdict, "needs_review");
  assert.equal(v.blocking, true);
  assert.equal(v.reason_code, null);
  assert.equal(v.result.problems[0].pages[0], 1);
  assert.equal("canWrite" in v.result, false);
});

// omitly#1496: a known decisionChannel passes through; an older engine that sends none reads null.
test("check_redaction carries the result's decisionChannel, null when the engine sent none", async () => {
  for (const [sent, expected] of [["none", "none"], [undefined, null]] as const) {
    const { root, doc, bin } = setup();
    const result = sent === undefined ? genuineResult() : { ...genuineResult(), decisionChannel: sent };
    const res = await callCheck(
      { OMITLY_ALLOWED_DIR: root, OMITLY_REDACT_BIN: bin, FAKE_CHECK_RESPONSE: checkResponse(result) },
      doc,
    );
    const v = res.structuredContent.verdict;
    assert.equal(v.reason_code, null, String(sent));
    assert.equal(v.result.decisionChannel, expected, String(sent));
  }
});

test("check_redaction keeps the genuine wasm check result", async () => {
  const fixture = [path.join(HERE, "..", "tests", "fixtures", "sample.pdf"), path.join(HERE, "..", "..", "tests", "fixtures", "sample.pdf")].find(
    (p) => existsSync(p),
  );
  assert.ok(fixture, "sample.pdf fixture not found");
  const { root } = setup();
  const doc = path.join(root, "sample.pdf");
  writeFileSync(doc, readFileSync(fixture));
  const res = await callCheck(
    { OMITLY_ALLOWED_DIR: root, OMITLY_STATE_DIR: path.join(root, "state"), OMITLY_FREE_CAP: "1000" },
    doc,
  );
  const v = res.structuredContent.verdict;
  assert.equal(v.verdict, "safe_to_send");
  assert.equal(v.reason_code, null);
  assert.ok(v.result && v.result.checked.length > 0);
  // omitly#1496: the wasm's presented check records that nothing was decided.
  assert.equal(v.result.decisionChannel, "none");
});

/** Codex review input: the engine's `check` carries a `report` holding
 *  document text. check_redaction does not return the audit v2 report at all
 *  (it is available from `omitly-redact check`), so none of it may reach the
 *  tool output, and the verdict and result are unaffected. */
for (const [name, result, verdict, blocking] of [
  ["with no result (the Codex input)", null, "cannot_verify", false],
  ["beside a genuine result", genuineResult(), "needs_review", true],
] as const) {
  test(`check_redaction never returns the engine's report — ${name}`, async () => {
    const { root, doc, bin } = setup();
    const res = await callCheck(
      {
        OMITLY_ALLOWED_DIR: root,
        OMITLY_REDACT_BIN: bin,
        FAKE_CHECK_RESPONSE: JSON.stringify({
          ok: true,
          check: { verdict, blocking, result, report: { rawText: `SSN ${SECRET}` }, reason_code: null },
        }),
      },
      doc,
    );
    const v = res.structuredContent?.verdict;
    assert.ok(v, `no verdict: ${JSON.stringify(res.content)}`);
    assert.equal("report" in v, false, "the verdict carries no report");
    assert.equal(v.verdict, verdict);
    assert.equal(v.blocking, blocking);
    assert.equal(v.reason_code, null);
    assert.equal(v.result === null, result === null);
    assert.ok(!JSON.stringify(res).includes(SECRET), "report text reached the tool output");
  });
}
