/**
 * omitly#1267: `check_redaction`'s `verdict` is the same object whichever
 * engine serves it — the native `omitly-redact check` command or the bundled
 * wasm `check` export — apart from the time of the check. Both are the one
 * Rust function `omitly_seal::check::free_check`; this drives the REAL binary
 * and the REAL wasm through the MCP tool, so the request plumbing, the
 * allowlist copy (`toOutputVerdict`) and the output schema are covered on
 * both paths.
 *
 * The native engine is the workspace build of `omitly-redact`
 * (`cargo build -p omitly-cli`), or `OMITLY_TEST_REDACT_BIN`. Outside the
 * Cargo workspace (the standalone omitly-mcp repository) there is no engine to
 * build and the test is skipped; inside it, under CI, a missing binary FAILS —
 * a parity check that could not run is not a pass.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { existsSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const WORKSPACE = path.join(HERE, "..", "..");
const IN_WORKSPACE = existsSync(path.join(WORKSPACE, "Cargo.toml"));
const EXE = process.platform === "win32" ? ".exe" : "";
const ENGINE =
  process.env.OMITLY_TEST_REDACT_BIN ??
  [
    path.join(WORKSPACE, "target", "debug", `omitly-redact${EXE}`),
    path.join(WORKSPACE, "target", "release", `omitly-redact${EXE}`),
  ].find((p) => existsSync(p));

const skip = !ENGINE && !(IN_WORKSPACE && process.env.CI)
  ? "no omitly-redact build (run `cargo build -p omitly-cli`)"
  : false;

const ENV_KEYS = [
  "OMITLY_ALLOWED_DIR",
  "OMITLY_REDACT_BIN",
  "OMITLY_PDF_BIN",
  "OMITLY_ENGINE_DIR",
  "OMITLY_STATE_DIR",
  "OMITLY_FREE_CAP",
] as const;

let importCounter = 0;
async function importFresh(env: Partial<Record<(typeof ENV_KEYS)[number], string>>) {
  for (const key of ENV_KEYS) delete process.env[key];
  for (const [k, v] of Object.entries(env)) process.env[k] = v;
  importCounter += 1;
  return (await import("./index.js?verdict-parity=" + importCounter)) as typeof import("./index.js");
}

async function checkVia(
  env: Partial<Record<(typeof ENV_KEYS)[number], string>>,
  pdfPath: string,
): Promise<any> {
  const { createServer } = await importFresh(env);
  const server = createServer();
  const [serverTransport, clientTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "verdict-parity-test", version: "0.0.0" });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  try {
    const res: any = await client.callTool({ name: "check_redaction", arguments: { pdfPath } });
    assert.ok(res.structuredContent, `no structured result: ${JSON.stringify(res.content)}`);
    return res.structuredContent.verdict;
  } finally {
    await client.close();
    await server.close();
  }
}

function withoutTime(v: any): any {
  const copy = JSON.parse(JSON.stringify(v));
  if (copy.result) delete copy.result.checkedAt;
  return copy;
}

/** One page: "Fake Name 000-00-0000" as live text with a black box painted
 *  over it — text recoverable under a cover. Offsets computed, so the xref
 *  is exact. */
function blackBoxOverText(): Buffer {
  const content = "BT /F1 12 Tf 100 680 Td (Fake Name 000-00-0000) Tj ET\n0 g 95 674 160 20 re f\n";
  const objects = [
    "<< /Type /Catalog /Pages 2 0 R >>",
    "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R " +
      "/Resources << /Font << /F1 5 0 R >> >> >>",
    `<< /Length ${content.length} >>\nstream\n${content}endstream`,
    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
  ];
  let pdf = "%PDF-1.5\n";
  const offsets: number[] = [];
  objects.forEach((body, i) => {
    offsets.push(pdf.length);
    pdf += `${i + 1} 0 obj\n${body}\nendobj\n`;
  });
  const xref = pdf.length;
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const o of offsets) pdf += `${String(o).padStart(10, "0")} 00000 n \n`;
  pdf += `trailer\n<< /Root 1 0 R /Size ${objects.length + 1} >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.from(pdf, "latin1");
}

const FIXTURE_DIR = [path.join(HERE, "..", "tests", "fixtures"), path.join(WORKSPACE, "tests", "fixtures")].find(
  (p) => existsSync(path.join(p, "sample.pdf")),
);

test("check_redaction's verdict is identical from the native engine and the wasm", { skip }, async () => {
  assert.ok(ENGINE, "omitly-redact is not built — `cargo build -p omitly-cli` before `npm test` in CI");
  assert.ok(FIXTURE_DIR, "sample.pdf fixture not found");
  const root = realpathSync(mkdtempSync(path.join(tmpdir(), "omitly-verdict-parity-")));
  const docs: [string, Buffer, string, boolean][] = [
    ["sample.pdf", readFileSync(path.join(FIXTURE_DIR, "sample.pdf")), "safe_to_send", false],
    ["sample.redacted.pdf", readFileSync(path.join(FIXTURE_DIR, "sample.redacted.pdf")), "safe_to_send", false],
    ["black-box.pdf", blackBoxOverText(), "needs_review", true],
    // No `cannot_verify` row: a file the v1 scan cannot parse fails the whole
    // tool before a verdict is taken (existing behaviour). The CLI and wasm
    // outputs for such files are compared in crates/omitly-cli/tests/check.rs.
  ];
  for (const [name, bytes, verdict, blocking] of docs) {
    const doc = path.join(root, name);
    writeFileSync(doc, bytes);
    const native = await checkVia({ OMITLY_ALLOWED_DIR: root, OMITLY_REDACT_BIN: ENGINE! }, doc);
    const wasm = await checkVia(
      { OMITLY_ALLOWED_DIR: root, OMITLY_STATE_DIR: path.join(root, "state"), OMITLY_FREE_CAP: "1000" },
      doc,
    );
    assert.deepEqual(withoutTime(native), withoutTime(wasm), `${name}: native and wasm verdicts differ`);
    assert.equal(wasm.verdict, verdict, name);
    assert.equal(wasm.blocking, blocking, name);
    assert.equal(wasm.reason_code, null, `${name}: the check ran on both paths`);
    assert.ok(!JSON.stringify(wasm).includes("000-00-0000"), `${name}: document text in the verdict`);
  }
});
