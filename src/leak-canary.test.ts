/**
 * Leak-canary test (#540): drives all 9 tools against a document containing
 * distinctive canary values through an in-memory MCP client, and asserts for
 * each response that (a) it validates against the tool's declared
 * `outputSchema`, and (b) the FULL response — `content[].text` AND
 * `structuredContent` — never contains a canary substring verbatim.
 *
 * Uses `fake-engine.mjs` (see that file's doc comment) as a stand-in for the
 * native `omitly-redact`/`omitly-pdf` binaries so this runs without a Rust
 * toolchain; the real engine's own correctness is covered by
 * `crates/redaction-core`'s Rust tests. This test is about the MCP layer:
 * schemas as a contract, and masking enforced at the boundary, not just
 * documented.
 *
 * Design note (see #540): the canary used for the LEAK assertion must be a
 * string the caller did not itself supply as input, or `locate_text` (whose
 * `texts` argument comes from the caller) would trivially and legitimately
 * echo it back. `SENTINEL` is a document-only marker never passed as a tool
 * argument; `EMAIL`/`SSN`/`PHONE` are excluded from the assertion only for
 * the one `locate_text` call that searches for them.
 */
import assert from "node:assert/strict";
import { mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FAKE_ENGINE = path.join(HERE, "..", "src", "testing", "fake-engine.mjs");

const CANARY_EMAIL = "shepherd.canary@leak-test.example";
const CANARY_SSN = "078-05-1120";
const CANARY_PHONE = "202-555-0199";
// A plain, non-PII marker. Never detected as a "kind" by the fake engine and
// never passed as a tool argument — its only job is to prove no code path
// dumps the raw document text wholesale.
const SENTINEL = "OMITLY-540-SENTINEL-4f8b9c";

const ALL_CANARIES = [CANARY_EMAIL, CANARY_SSN, CANARY_PHONE, SENTINEL];

function assertNoLeak(label: string, response: unknown, excluded: string[] = []) {
  const text = JSON.stringify(response);
  for (const canary of ALL_CANARIES) {
    if (excluded.includes(canary)) continue;
    assert.ok(
      !text.includes(canary),
      `${label}: response leaked canary "${canary}"\n${text.slice(0, 3000)}`,
    );
  }
}

// --- Fixture setup: env vars must be in place BEFORE index.ts is imported,
// since ENGINE_BIN/PDF_BIN/ROOT are resolved at module load. ---
const root = realpathSync(mkdtempSync(path.join(tmpdir(), "omitly-mcp-canary-")));
process.env.OMITLY_ALLOWED_DIR = root;
process.env.OMITLY_REDACT_BIN = FAKE_ENGINE;
process.env.OMITLY_PDF_BIN = FAKE_ENGINE;
process.env.FAKE_ENGINE_CANARY_EMAIL = CANARY_EMAIL;
process.env.FAKE_ENGINE_CANARY_SSN = CANARY_SSN;
process.env.FAKE_ENGINE_CANARY_PHONE = CANARY_PHONE;
process.env.FAKE_ENGINE_SENTINEL = SENTINEL;

const docPath = path.join(root, "canary.pdf");
writeFileSync(
  docPath,
  [
    "%PDF-1.4 (fixture — not a real PDF, the fake engine reads this as text)",
    `Contact: ${CANARY_EMAIL}`,
    `SSN: ${CANARY_SSN}`,
    `Phone: ${CANARY_PHONE}`,
    `Marker: ${SENTINEL}`,
  ].join("\n"),
);

const {
  createServer,
  findSensitiveRegionsOutputSchema,
  locateTextOutputSchema,
  redactByEntityOutputSchema,
  redactPdfOutputSchema,
  verifyRedactionOutputSchema,
  verifySealOutputSchema,
  createPdfOutputSchema,
  checkRedactionOutputSchema,
} = await import("./index.js");
const { Client } = await import("@modelcontextprotocol/sdk/client/index.js");
const { InMemoryTransport } = await import("@modelcontextprotocol/sdk/inMemory.js");

async function withClient<T>(fn: (client: InstanceType<typeof Client>) => Promise<T>): Promise<T> {
  const server = createServer();
  const [serverTransport, clientTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "leak-canary-test", version: "0.0.0" });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  try {
    return await fn(client);
  } finally {
    await client.close();
    await server.close();
  }
}

test("find_sensitive_regions: validates outputSchema and leaks nothing", async () => {
  await withClient(async (client) => {
    const res: any = await client.callTool({
      name: "find_sensitive_regions",
      arguments: { pdfPath: docPath },
    });
    assert.equal(res.isError, undefined);
    assert.equal(findSensitiveRegionsOutputSchema.safeParse(res.structuredContent).success, true);
    assert.equal(res.structuredContent.count, 3); // email, ssn, phone — not the sentinel
    assertNoLeak("find_sensitive_regions", res);
  });
});

test("locate_text: validates outputSchema and leaks nothing outside its own input", async () => {
  await withClient(async (client) => {
    const res: any = await client.callTool({
      name: "locate_text",
      arguments: { pdfPath: docPath, texts: [CANARY_EMAIL, CANARY_SSN] },
    });
    assert.equal(res.isError, undefined);
    assert.equal(locateTextOutputSchema.safeParse(res.structuredContent).success, true);
    assert.equal(res.structuredContent.count, 2);
    // Excluded: the caller supplied these as search input. Everything else
    // (phone, sentinel) must still never appear.
    assertNoLeak("locate_text", res, [CANARY_EMAIL, CANARY_SSN]);
  });
});

test("redact_by_entity: validates outputSchema and leaks nothing", async () => {
  await withClient(async (client) => {
    const outputPath = path.join(root, "redact-by-entity-out.pdf");
    const res: any = await client.callTool({
      name: "redact_by_entity",
      arguments: { pdfPath: docPath, outputPath },
    });
    assert.equal(res.isError, undefined);
    assert.equal(redactByEntityOutputSchema.safeParse(res.structuredContent).success, true);
    assert.equal(res.structuredContent.redactedCount, 3);
    assert.equal(res.structuredContent.verdict, "pass");
    assertNoLeak("redact_by_entity", res);
  });
});

test("redact_pdf: validates outputSchema and leaks nothing", async () => {
  await withClient(async (client) => {
    const outputPath = path.join(root, "redact-pdf-out.pdf");
    const res: any = await client.callTool({
      name: "redact_pdf",
      arguments: {
        pdfPath: docPath,
        outputPath,
        regions: [{ page: 0, x: 10, y: 700, width: 200, height: 12, reason: "PII: email" }],
      },
    });
    assert.equal(res.isError, undefined);
    assert.equal(redactPdfOutputSchema.safeParse(res.structuredContent).success, true);
    assert.equal(res.structuredContent.regionCount, 1);
    assertNoLeak("redact_pdf", res);
  });
});

test("verify_redaction (sidecar path): validates outputSchema and leaks nothing", async () => {
  await withClient(async (client) => {
    const outputPath = path.join(root, "verify-sidecar-out.pdf");
    await client.callTool({
      name: "redact_by_entity",
      arguments: { pdfPath: docPath, outputPath },
    });
    const res: any = await client.callTool({
      name: "verify_redaction",
      arguments: { pdfPath: outputPath },
    });
    assert.equal(verifyRedactionOutputSchema.safeParse(res.structuredContent).success, true);
    assert.equal(res.structuredContent.mode, "sidecar");
    assert.equal(res.structuredContent.clean, true);
    assertNoLeak("verify_redaction (sidecar)", res);
  });
});

test("verify_redaction (rescan path, no sidecar): validates outputSchema and leaks nothing", async () => {
  await withClient(async (client) => {
    // No sidecar exists for docPath itself, so this exercises the "find"
    // rescan fallback branch — which finds the still-present canaries and
    // must report unclean without leaking them.
    const res: any = await client.callTool({
      name: "verify_redaction",
      arguments: { pdfPath: docPath },
    });
    assert.equal(res.isError, true);
    assert.equal(verifyRedactionOutputSchema.safeParse(res.structuredContent).success, true);
    assert.equal(res.structuredContent.mode, "rescan");
    assert.equal(res.structuredContent.clean, false);
    assertNoLeak("verify_redaction (rescan)", res);
  });
});

test("verify_seal: validates outputSchema and leaks nothing", async () => {
  await withClient(async (client) => {
    const res: any = await client.callTool({
      name: "verify_seal",
      arguments: { pdfPath: docPath },
    });
    // Unlike the other tools' plain-pass branches, verify_seal always sets
    // `isError` explicitly (mirrors verify_redaction's sidecar branch) —
    // `false` here, not absent — so this checks the verdict instead.
    assert.equal(res.isError, false);
    assert.equal(verifySealOutputSchema.safeParse(res.structuredContent).success, true);
    assert.equal(res.structuredContent.verdict, "verified");
    assert.equal(res.structuredContent.sealValid, true);
    assertNoLeak("verify_seal", res);
  });
});

test("create_pdf: validates outputSchema and leaks nothing", async () => {
  await withClient(async (client) => {
    const outputPath = path.join(root, "created.pdf");
    const res: any = await client.callTool({
      name: "create_pdf",
      arguments: { outputPath, source: "# Hello\n\nNo PII here." },
    });
    assert.equal(res.isError, undefined);
    assert.equal(createPdfOutputSchema.safeParse(res.structuredContent).success, true);
    assert.equal(res.structuredContent.output, outputPath);
    assertNoLeak("create_pdf", res);
  });
});

test("check_redaction: validates outputSchema and leaks nothing (dirty doc)", async () => {
  await withClient(async (client) => {
    const res: any = await client.callTool({
      name: "check_redaction",
      arguments: { pdfPath: docPath },
    });
    assert.equal(res.isError, true);
    assert.equal(checkRedactionOutputSchema.safeParse(res.structuredContent).success, true);
    assert.equal(res.structuredContent.clean, false);
    assert.equal(res.structuredContent.totalFindings, 3);
    assertNoLeak("check_redaction (dirty)", res);
  });
});

test("check_redaction: validates outputSchema and leaks nothing (clean doc)", async () => {
  await withClient(async (client) => {
    const cleanPath = path.join(root, "clean.pdf");
    writeFileSync(cleanPath, "%PDF-1.4\nNothing sensitive in here.");
    const res: any = await client.callTool({
      name: "check_redaction",
      arguments: { pdfPath: cleanPath },
    });
    assert.equal(res.isError, undefined);
    assert.equal(checkRedactionOutputSchema.safeParse(res.structuredContent).success, true);
    assert.equal(res.structuredContent.clean, true);
    assertNoLeak("check_redaction (clean)", res);
  });
});
