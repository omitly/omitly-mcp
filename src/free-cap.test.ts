/**
 * Integration tests for the free-tier cap (omitly#226) driven through the real
 * MCP server with an in-memory client — the same harness as
 * leak-canary.test.ts, but deliberately WITHOUT a native engine configured, so
 * the two detection tools take the free (wasm) path where the meter applies.
 *
 * These tests are written to hold with OR without the wasm engine built: the
 * gate fires BEFORE the scan (an attempt is an attempt), so under-cap calls may
 * legitimately error on a missing wasm build while the cap/refusal behaviour —
 * what this file proves — is unaffected.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

// realpathSync: on macOS mkdtemp returns /var/... but the server resolves its
// allowed root to /private/var/..., which would fail confinement spuriously.
const root = realpathSync(mkdtempSync(path.join(os.tmpdir(), "omitly-free-cap-test-")));
const stateDir = path.join(root, "state");
process.env.OMITLY_ALLOWED_DIR = root;
process.env.OMITLY_STATE_DIR = stateDir;
process.env.OMITLY_FREE_CAP = "3";
// The whole point of this file: NO native engine. Guard against ambient env.
delete process.env.OMITLY_REDACT_BIN;
delete process.env.OMITLY_PDF_BIN;
delete process.env.OMITLY_ENGINE_DIR;

const docPath = path.join(root, "doc.pdf");
writeFileSync(docPath, "%PDF-1.4\nnot a real pdf — the meter fires before any scan\n");

const { createServer } = await import("./index.js");
const { Client } = await import("@modelcontextprotocol/sdk/client/index.js");
const { InMemoryTransport } = await import("@modelcontextprotocol/sdk/inMemory.js");

async function withClient<T>(fn: (client: InstanceType<typeof Client>) => Promise<T>): Promise<T> {
  const server = createServer();
  const [serverTransport, clientTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "free-cap-test", version: "0.0.0" });
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

test("free detection calls are metered and the cap+1th returns the structured free-cap refusal", async () => {
  await withClient(async (client) => {
    // Calls 1..3 (cap=3) are allowed through the gate — split across both
    // metered tools to prove they share one bucket.
    for (const name of ["check_redaction", "find_sensitive_regions", "check_redaction"]) {
      const res: any = await client.callTool({ name, arguments: { pdfPath: docPath } });
      assert.ok(
        !textOf(res).includes('"free-cap"'),
        `call via ${name} under the cap must not be refused`,
      );
    }
    // Call 4: refused, with the issue's structured shape.
    const res: any = await client.callTool({
      name: "check_redaction",
      arguments: { pdfPath: docPath },
    });
    assert.equal(res.isError, true);
    const refusal = JSON.parse(textOf(res));
    assert.equal(refusal.blocked, true);
    assert.equal(refusal.reason, "free-cap");
    assert.equal(refusal.cap, 3);
    assert.ok(refusal.used > refusal.cap);
    assert.match(refusal.message, /omitly\.app/);

    // find_sensitive_regions shares the bucket, so it is refused too.
    const res2: any = await client.callTool({
      name: "find_sensitive_regions",
      arguments: { pdfPath: docPath },
    });
    assert.equal(JSON.parse(textOf(res2)).reason, "free-cap");
  });
});

test("the count persisted to usage.json", () => {
  const state = JSON.parse(readFileSync(path.join(stateDir, "usage.json"), "utf8"));
  const month = Object.keys(state.check_calls)[0];
  assert.ok(state.check_calls[month] >= 4, "all metered attempts recorded");
  assert.equal(state.licensed, false);
});

test("verify_redaction is NEVER capped, even far past the cap", async () => {
  await withClient(async (client) => {
    for (let i = 0; i < 6; i++) {
      const res: any = await client.callTool({
        name: "verify_redaction",
        arguments: { pdfPath: docPath },
      });
      const text = textOf(res);
      assert.ok(!text.includes("free-cap"), "verify_redaction must not be metered");
      assert.ok(!text.includes("EVALUATION"), "verify_redaction must not be EVALUATION-marked");
    }
  });
});

test("locate_text is not metered either (only the two detection tools are)", async () => {
  await withClient(async (client) => {
    const res: any = await client.callTool({
      name: "locate_text",
      arguments: { pdfPath: docPath, texts: ["anything"] },
    });
    assert.ok(!textOf(res).includes("free-cap"));
  });
});

test("a capped refusal never includes document-derived content", async () => {
  await withClient(async (client) => {
    const res: any = await client.callTool({
      name: "check_redaction",
      arguments: { pdfPath: docPath },
    });
    assert.equal(res.isError, true);
    assert.ok(!textOf(res).includes("not a real pdf"), "refusal must not echo file content");
  });
});
