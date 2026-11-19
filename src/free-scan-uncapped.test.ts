/**
 * Integration tests for the free leak scans (omitly#1859: no cap) driven through
 * the real MCP server with an in-memory client — the same harness as
 * leak-canary.test.ts, deliberately WITHOUT a native engine configured, so the
 * two scan tools take the free (wasm) path that used to be capped at 10 a month.
 *
 * Oracle: the real server and the real bundled wasm detector on a real PDF
 * (tests/fixtures/sample.pdf, the fixture routing.test.ts uses). Nothing is mocked.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { copyFileSync, existsSync, mkdtempSync, readdirSync, realpathSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

// realpathSync: on macOS mkdtemp returns /var/... but the server resolves its
// allowed root to /private/var/..., which would fail confinement spuriously.
const root = realpathSync(mkdtempSync(path.join(os.tmpdir(), "omitly-free-scan-test-")));
const stateDir = path.join(root, "state");
process.env.OMITLY_ALLOWED_DIR = root;
process.env.OMITLY_STATE_DIR = stateDir;
// The old cap variable must have no effect any more: set it low to prove it.
process.env.OMITLY_FREE_CAP = "1";
// The whole point of this file: NO native engine. Guard against ambient env.
delete process.env.OMITLY_REDACT_BIN;
delete process.env.OMITLY_PDF_BIN;
delete process.env.OMITLY_ENGINE_DIR;

// Same two candidate layouts as routing.test.ts (standalone repo / workspace root).
const HERE = path.dirname(fileURLToPath(import.meta.url));
const fixture = [
  path.join(HERE, "..", "tests", "fixtures", "sample.pdf"),
  path.join(HERE, "..", "..", "tests", "fixtures", "sample.pdf"),
].find((p) => existsSync(p));
assert.ok(fixture, "the shared sample.pdf fixture must exist");
const docPath = path.join(root, "doc.pdf");
copyFileSync(fixture, docPath);

const { createServer } = await import("./index.js");
const { Client } = await import("@modelcontextprotocol/sdk/client/index.js");
const { InMemoryTransport } = await import("@modelcontextprotocol/sdk/inMemory.js");

async function withClient<T>(fn: (client: InstanceType<typeof Client>) => Promise<T>): Promise<T> {
  const server = createServer();
  const [serverTransport, clientTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "free-scan-test", version: "0.0.0" });
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

const N = 25;
const FIND = "This scan lists likely sensitive items. It does not remove anything and is not a removal certificate.";
const CHECK = "This check finds likely leaks. It does not remove anything and is not a removal certificate.";

test(`${N} free scans in a row, split across both tools, all succeed: no refusal, no count, no link`, async () => {
  await withClient(async (client) => {
    for (let i = 0; i < N; i++) {
      const name = i % 2 === 0 ? "check_redaction" : "find_sensitive_regions";
      const res: any = await client.callTool({ name, arguments: { pdfPath: docPath } });
      const text = textOf(res);
      assert.ok(!text.includes("free-cap"), `call ${i + 1} (${name}) was refused: ${text.slice(0, 200)}`);
      assert.ok(!/Free-tier limit|free redaction checks|Free check \d+\/\d+|this month/i.test(text), `call ${i + 1}: cap or count wording`);
      assert.ok(
        text.includes(name === "check_redaction" ? CHECK : FIND),
        `call ${i + 1}: the reworded one-sentence notice for ${name}`,
      );
      assert.ok(!/EVALUATION|free tier/i.test(text), `call ${i + 1}: no "evaluation" or "free tier" wording`);
      assert.ok(!/omitly\.app/.test(text), `call ${i + 1}: a scan result carries no link (omitly#1860)`);
      assert.equal(res.structuredContent.evaluation, true);
      assert.ok(
        res.structuredContent.count >= 1 || res.structuredContent.totalFindings >= 1,
        "the scan really ran and found the values in the fixture",
      );
    }
  });
});

test("the scans write no usage counter, and nothing else at the top of the state directory", () => {
  assert.ok(!existsSync(path.join(stateDir, "usage.json")), "no usage.json");
  // The only thing the server itself writes here is the connected-client heartbeat (clients/).
  const top = existsSync(stateDir) ? readdirSync(stateDir) : [];
  assert.deepEqual(top.filter((n) => n !== "clients"), [], `unexpected state files: ${top.join(", ")}`);
});

test("verify_redaction and locate_text carry no evaluation line or cap either", async () => {
  await withClient(async (client) => {
    for (let i = 0; i < 12; i++) {
      const res: any = await client.callTool({ name: "verify_redaction", arguments: { pdfPath: docPath } });
      assert.ok(!/free-cap|EVALUATION/.test(textOf(res)));
    }
    const res: any = await client.callTool({ name: "locate_text", arguments: { pdfPath: docPath, texts: ["anything"] } });
    assert.ok(!textOf(res).includes("free-cap"));
  });
});
