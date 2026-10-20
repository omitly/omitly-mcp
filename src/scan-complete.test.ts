/**
 * omitly#1473 (owner decision, option b): `clean` keeps its #538 meaning and a
 * separate `scan_complete` says whether every page and stream was read. Every
 * text surface must show completeness BEFORE the clean/count headline — an
 * incomplete scan must never read as "No recoverable PII found" on its own.
 *
 * Two engines are driven through the MCP tools:
 *  - the REAL native `omitly-redact` (workspace build, or OMITLY_TEST_REDACT_BIN)
 *    over a PDF whose only page cannot be read (built in code, fake values).
 *    Skipped when no build exists outside CI, like verdict-parity.test.ts. The
 *    wasm `scan` carries the same field (leakcheck-wasm, covered by the Rust
 *    test in crates/omitly-cli/tests/check.rs);
 *  - the routing stub (`testing/routing-stub.mjs`) for the passthrough,
 *    including an engine that does not report the field at all.
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
const skip =
  !ENGINE && !(IN_WORKSPACE && process.env.CI) ? "no omitly-redact build (run `cargo build -p omitly-cli`)" : false;
const ROUTING_STUB = path.join(HERE, "..", "src", "testing", "routing-stub.mjs");

const ENV_KEYS = [
  "OMITLY_ALLOWED_DIR",
  "OMITLY_REDACT_BIN",
  "OMITLY_PDF_BIN",
  "OMITLY_ENGINE_DIR",
  "OMITLY_STATE_DIR",
  "OMITLY_FREE_CAP",
  "OMITLY_ROUTING_STUB_SCAN_COMPLETE",
] as const;

let importCounter = 0;
async function importFresh(env: Partial<Record<(typeof ENV_KEYS)[number], string>>) {
  for (const key of ENV_KEYS) delete process.env[key];
  for (const [k, v] of Object.entries(env)) process.env[k] = v;
  importCounter += 1;
  return (await import("./index.js?scan-complete=" + importCounter)) as typeof import("./index.js");
}

async function withClient<T>(
  createServer: () => import("@modelcontextprotocol/sdk/server/mcp.js").McpServer,
  fn: (client: InstanceType<typeof Client>) => Promise<T>,
): Promise<T> {
  const server = createServer();
  const [serverTransport, clientTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "scan-complete-test", version: "0.0.0" });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  try {
    return await fn(client);
  } finally {
    await client.close();
    await server.close();
  }
}

function textOf(res: any): string {
  return (res.content ?? [])
    .filter((c: any) => c.type === "text")
    .map((c: any) => c.text)
    .join("\n");
}

/** A one-page PDF (xref computed) whose only content stream starts with a
 *  stray `)` — the parser stops there, so no page text is read. */
function unreadablePdf(): Buffer {
  const content = ")\nBT /F1 12 Tf 72 700 Td (fixture, all values fake) Tj ET\n";
  const objs = [
    "<< /Type /Catalog /Pages 2 0 R >>",
    "<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>",
    "<< /Type /Page /Parent 2 0 R /Contents 4 0 R /Resources << >> >>",
    `<< /Length ${content.length} >>\nstream\n${content}endstream`,
  ];
  let out = "%PDF-1.4\n";
  const offsets: number[] = [];
  objs.forEach((o, i) => {
    offsets.push(out.length);
    out += `${i + 1} 0 obj\n${o}\nendobj\n`;
  });
  const xref = out.length;
  out += `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n`;
  for (const off of offsets) out += `${String(off).padStart(10, "0")} 00000 n \n`;
  out += `trailer\n<< /Size ${objs.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.from(out, "latin1");
}

/** A one-page PDF that is a single 1x1 image and no text: readable, but all of
 *  its content is an image this build never OCRs. */
function imageOnlyPdf(): Buffer {
  const content = "q 100 0 0 100 0 0 cm /Im0 Do Q";
  const objs = [
    "<< /Type /Catalog /Pages 2 0 R >>",
    "<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 600 200] >>",
    "<< /Type /Page /Parent 2 0 R /Contents 4 0 R /Resources << /XObject << /Im0 5 0 R >> >> >>",
    `<< /Length ${content.length} >>\nstream\n${content}\nendstream`,
    "<< /Type /XObject /Subtype /Image /Width 1 /Height 1 /ColorSpace /DeviceGray /BitsPerComponent 8 /Length 1 >>\nstream\n\u0000\nendstream",
  ];
  let out = "%PDF-1.4\n";
  const offsets: number[] = [];
  objs.forEach((o, i) => {
    offsets.push(out.length);
    out += `${i + 1} 0 obj\n${o}\nendobj\n`;
  });
  const xref = out.length;
  out += `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n`;
  for (const off of offsets) out += `${String(off).padStart(10, "0")} 00000 n \n`;
  out += `trailer\n<< /Size ${objs.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.from(out, "latin1");
}

function setup(prefix: string) {
  const root = realpathSync(mkdtempSync(path.join(tmpdir(), prefix)));
  const doc = path.join(root, "unreadable.pdf");
  writeFileSync(doc, unreadablePdf());
  return { root, doc };
}

const realEnv = (root: string) => ({ OMITLY_ALLOWED_DIR: root, OMITLY_REDACT_BIN: ENGINE! }) as const;

/** Index of the first occurrence, or fail the test. */
function at(text: string, needle: string): number {
  const i = text.indexOf(needle);
  assert.ok(i >= 0, `expected ${JSON.stringify(needle)} in:\n${text}`);
  return i;
}

test("[real engine] check_redaction over an unreadable page shows INCOMPLETE before any clean wording", { skip }, async () => {
  const { root, doc } = setup("omitly-1473-check-");
  const { createServer } = await importFresh(realEnv(root));
  await withClient(createServer, async (client) => {
    const res: any = await client.callTool({ name: "check_redaction", arguments: { pdfPath: doc } });
    const text = textOf(res);
    assert.equal(res.structuredContent.scanComplete, false);
    assert.equal(res.structuredContent.clean, true, "clean keeps its #538 meaning");
    assert.equal(res.structuredContent.coverage.pagesScanned, 0, "fixture premise: nothing was read");
    assert.ok(text.startsWith("⛔ INCOMPLETE SCAN"), text);
    assert.ok(!text.includes("✅ No recoverable PII found"), text);
    assert.ok(at(text, "INCOMPLETE SCAN") < at(text, "Nothing found in the part"), text);
  });
});

test("[real engine] find_sensitive_regions over an unreadable page leads with INCOMPLETE, before the count", { skip }, async () => {
  const { root, doc } = setup("omitly-1473-find-");
  const { createServer } = await importFresh(realEnv(root));
  await withClient(createServer, async (client) => {
    const res: any = await client.callTool({ name: "find_sensitive_regions", arguments: { pdfPath: doc } });
    const text = textOf(res);
    assert.equal(res.structuredContent.scanComplete, false);
    assert.equal(res.structuredContent.count, 0);
    assert.ok(at(text, "INCOMPLETE SCAN") < at(text, "Found 0 candidate region(s)"), text);
    assert.ok(text.includes("in the part of the document that could be read"), text);
  });
});

test("[real engine] verify_redaction rescan over an unreadable page never says 'No recoverable PII found'", { skip }, async () => {
  const { root, doc } = setup("omitly-1473-verify-");
  const { createServer } = await importFresh(realEnv(root));
  await withClient(createServer, async (client) => {
    const res: any = await client.callTool({ name: "verify_redaction", arguments: { pdfPath: doc } });
    const text = textOf(res);
    assert.equal(res.structuredContent.mode, "rescan");
    assert.equal(res.structuredContent.scanComplete, false);
    assert.equal(res.structuredContent.clean, true);
    assert.ok(text.startsWith("⛔ INCOMPLETE SCAN"), text);
    assert.ok(!text.includes("No recoverable PII found"), text);
  });
});

test("[native] scan_complete: false from the engine leads find_sensitive_regions; true adds no banner", async () => {
  const { root, doc } = setup("omitly-1473-native-");
  for (const [flag, complete] of [["false", false], ["true", true]] as const) {
    const { createServer } = await importFresh({
      OMITLY_ALLOWED_DIR: root,
      OMITLY_REDACT_BIN: ROUTING_STUB,
      OMITLY_PDF_BIN: ROUTING_STUB,
      OMITLY_ROUTING_STUB_SCAN_COMPLETE: flag,
    });
    await withClient(createServer, async (client) => {
      const res: any = await client.callTool({ name: "find_sensitive_regions", arguments: { pdfPath: doc } });
      const text = textOf(res);
      assert.equal(res.structuredContent.scanComplete, complete);
      assert.equal(text.includes("INCOMPLETE SCAN"), !complete, text);
      if (!complete) assert.ok(text.startsWith("⛔ INCOMPLETE SCAN"), text);
    });
  }
});

test("[native] an engine that does not report completeness is treated as not complete", async () => {
  const { root, doc } = setup("omitly-1473-native-unreported-");
  const { createServer } = await importFresh({
    OMITLY_ALLOWED_DIR: root,
    OMITLY_REDACT_BIN: ROUTING_STUB,
    OMITLY_PDF_BIN: ROUTING_STUB,
  });
  await withClient(createServer, async (client) => {
    const res: any = await client.callTool({ name: "find_sensitive_regions", arguments: { pdfPath: doc } });
    const text = textOf(res);
    assert.equal(res.structuredContent.scanComplete, false);
    assert.ok(text.startsWith("⛔ SCAN COMPLETENESS NOT REPORTED"), text);
  });
});

test("[real engine] an image-only PDF is clean:true but incomplete, and the text says why (check_redaction + find)", { skip }, async () => {
  const root = realpathSync(mkdtempSync(path.join(tmpdir(), "omitly-1473-image-")));
  const doc = path.join(root, "image-only.pdf");
  writeFileSync(doc, imageOnlyPdf());
  const { createServer } = await importFresh(realEnv(root));
  await withClient(createServer, async (client) => {
    const res: any = await client.callTool({ name: "check_redaction", arguments: { pdfPath: doc } });
    const text = textOf(res);
    assert.equal(res.structuredContent.clean, true);
    assert.equal(res.structuredContent.scanComplete, false);
    assert.ok(text.startsWith("⛔ INCOMPLETE SCAN"), text);
    assert.ok(text.includes("1 page(s) are images only and were not text-scanned"), text);
    assert.ok(!text.includes("✅ No recoverable PII found"), text);
    const found: any = await client.callTool({ name: "find_sensitive_regions", arguments: { pdfPath: doc } });
    assert.ok(textOf(found).startsWith("⛔ INCOMPLETE SCAN"), textOf(found));
    assert.equal(found.structuredContent.scanComplete, false);
  });
});

test("[real engine] a complete scan says so before the headline in all three surfaces", { skip }, async () => {
  const fixture = path.join(WORKSPACE, "tests", "fixtures", "sample.pdf");
  const root = realpathSync(mkdtempSync(path.join(tmpdir(), "omitly-1473-complete-")));
  const doc = path.join(root, "sample.pdf");
  writeFileSync(doc, readFileSync(fixture));
  const { createServer } = await importFresh(realEnv(root));
  await withClient(createServer, async (client) => {
    for (const [name, headline] of [
      ["find_sensitive_regions", "Found "],
      ["check_redaction", "LEAK"],
      ["verify_redaction", "recoverable item"],
    ] as const) {
      const res: any = await client.callTool({ name, arguments: { pdfPath: doc } });
      const text = textOf(res);
      assert.equal(res.structuredContent.scanComplete, true, `${name}: ${text}`);
      assert.ok(
        at(text, "Scan complete: all text on every page and in every stream was read. Images are not OCR'd.") < at(text, headline),
        `${name}: ${text}`,
      );
    }
  });
});

test("[native] a complete scan states it first (stub, scan_complete true)", async () => {
  const { root, doc } = setup("omitly-1473-native-complete-");
  const { createServer } = await importFresh({
    OMITLY_ALLOWED_DIR: root,
    OMITLY_REDACT_BIN: ROUTING_STUB,
    OMITLY_PDF_BIN: ROUTING_STUB,
    OMITLY_ROUTING_STUB_SCAN_COMPLETE: "true",
  });
  await withClient(createServer, async (client) => {
    const res: any = await client.callTool({ name: "find_sensitive_regions", arguments: { pdfPath: doc } });
    assert.ok(textOf(res).startsWith("✅ Scan complete: all text on every page and in every stream was read. Images are not OCR'd."), textOf(res));
  });
});

test("[native] sidecar verify is a region check: no scanComplete, and its text says no document scan ran", async () => {
  const { root, doc } = setup("omitly-1473-sidecar-");
  writeFileSync(`${doc}.audit.json`, "[]");
  const { createServer } = await importFresh({
    OMITLY_ALLOWED_DIR: root,
    OMITLY_REDACT_BIN: ROUTING_STUB,
    OMITLY_PDF_BIN: ROUTING_STUB,
  });
  await withClient(createServer, async (client) => {
    const res: any = await client.callTool({ name: "verify_redaction", arguments: { pdfPath: doc } });
    const text = textOf(res);
    assert.equal(res.structuredContent.mode, "sidecar");
    assert.equal(res.structuredContent.scanComplete, undefined);
    assert.ok(text.startsWith("ℹ️ Region check only"), text);
    assert.ok(text.includes("did NOT scan the whole document"), text);
    assert.ok(!/no recoverable pii|scan complete/i.test(text), text);
  });
});
