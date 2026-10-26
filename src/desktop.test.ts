// omitly#1642 / #1643 — the desktop proposal channel and the accept-in-app
// gate. Real files in a temp state dir, a real in-memory MCP client; the only
// stub is the engine, which must NEVER be invoked while a proposal is queued.

import assert from "node:assert/strict";
import { test } from "node:test";
import { chmodSync, existsSync, mkdtempSync, readdirSync, readFileSync, realpathSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

import {
  PRESENCE_FRESH_MS,
  acceptInApp,
  enqueueProposal,
  listProposals,
  readDesktopPresence,
  readProposal,
  writeClientHeartbeat,
} from "./desktop.js";

const ENV_KEYS = [
  "OMITLY_ALLOWED_DIR",
  "OMITLY_REDACT_BIN",
  "OMITLY_PDF_BIN",
  "OMITLY_ENGINE_DIR",
  "OMITLY_STATE_DIR",
  "OMITLY_FREE_CAP",
] as const;

let counter = 0;

function freshRoot(prefix = "omitly-desktop-"): string {
  return realpathSync(mkdtempSync(path.join(tmpdir(), prefix)));
}

function writePresence(stateDir: string, opts: { acceptInApp?: boolean; ageMs?: number } = {}): void {
  const updated = new Date(Date.now() - (opts.ageMs ?? 0)).toISOString();
  writeFileSync(
    path.join(stateDir, "desktop.json"),
    JSON.stringify({ pid: 4242, version: "4.3.0", accept_in_app: opts.acceptInApp ?? true, updated_at: updated }),
  );
}

/** An engine stub that records every invocation; a queued proposal must leave
 *  it untouched. */
function recordingEngine(root: string): { bin: string; calls: () => string[] } {
  const bin = path.join(root, "stub-engine.mjs");
  const log = path.join(root, "engine-calls.log");
  writeFileSync(
    bin,
    `#!/usr/bin/env node
import { appendFileSync, readFileSync } from "node:fs";
const req = JSON.parse(readFileSync(0, "utf8"));
appendFileSync(${JSON.stringify(log)}, req.command + "\\n");
process.stdout.write(JSON.stringify({ ok: false, error: "stub engine: should not be reached" }));
`,
    { mode: 0o755 },
  );
  chmodSync(bin, 0o755);
  return { bin, calls: () => (existsSync(log) ? readFileSync(log, "utf8").trim().split("\n").filter(Boolean) : []) };
}

async function withServer<T>(
  root: string,
  stateDir: string,
  fn: (client: Client) => Promise<T>,
  clientInfo = { name: "Claude Desktop", version: "1.4.2" },
): Promise<T> {
  for (const k of ENV_KEYS) delete process.env[k];
  process.env.OMITLY_ALLOWED_DIR = root;
  process.env.OMITLY_STATE_DIR = stateDir;
  const engine = recordingEngine(root);
  process.env.OMITLY_REDACT_BIN = engine.bin;
  counter += 1;
  const mod = (await import(`./index.js?desktop-variant=${counter}`)) as typeof import("./index.js");
  const server = mod.createServer();
  const [serverTransport, clientTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client(clientInfo);
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  try {
    const out = await fn(client);
    assert.deepEqual(engine.calls(), [], "the engine must not run while a proposal is queued");
    return out;
  } finally {
    await client.close();
    await server.close();
  }
}

function textOf(res: any): string {
  return (res.content ?? []).filter((c: any) => c.type === "text").map((c: any) => c.text).join("\n");
}

// ---------------------------------------------------------------- module ----

test("presence: missing, malformed and stale heartbeats all read as no desktop", () => {
  const dir = freshRoot();
  process.env.OMITLY_STATE_DIR = dir;
  assert.equal(readDesktopPresence(), null, "missing");
  writeFileSync(path.join(dir, "desktop.json"), "{not json");
  assert.equal(readDesktopPresence(), null, "malformed");
  writeFileSync(path.join(dir, "desktop.json"), JSON.stringify({ pid: "x", version: 1, accept_in_app: "yes", updated_at: "now" }));
  assert.equal(readDesktopPresence(), null, "wrong types");
  writePresence(dir, { ageMs: PRESENCE_FRESH_MS + 1_000 });
  assert.equal(readDesktopPresence(), null, "stale");
  assert.equal(acceptInApp(), false);
  writePresence(dir, { ageMs: 1_000 });
  assert.equal(readDesktopPresence()?.pid, 4242, "fresh");
  assert.equal(acceptInApp(), true);
  writePresence(dir, { acceptInApp: false });
  assert.equal(acceptInApp(), false, "present but accept-in-app off");
});

test("enqueue writes a 0600 pending file in a 0700 dir and reads back by id only", () => {
  const dir = freshRoot();
  process.env.OMITLY_STATE_DIR = dir;
  const p = enqueueProposal({
    client: { name: "Cursor", version: "2.0" },
    tool: "redact_pdf",
    pdfPath: "/tmp/in.pdf",
    outputPath: "/tmp/out.pdf",
    regions: [{ page: 0, x: 1, y: 2, width: 3, height: 4, reason: "name" }],
  });
  assert.match(p.id, /^[0-9a-f]{24}$/);
  assert.equal(p.status, "pending");
  const file = path.join(dir, "proposals", `${p.id}.json`);
  assert.ok(existsSync(file));
  if (process.platform !== "win32") {
    assert.equal(statSync(file).mode & 0o777, 0o600);
    assert.equal(statSync(path.join(dir, "proposals")).mode & 0o777, 0o700);
  }
  assert.deepEqual(readProposal(p.id), p);
  assert.equal(readProposal("../desktop"), null, "an id is validated, never joined");
  assert.equal(readProposal("0".repeat(24)), null, "unknown id");
  assert.equal(readdirSync(path.join(dir, "proposals")).filter((n) => n.includes(".tmp-")).length, 0, "no temp files left");
  assert.equal(listProposals().length, 1);
});

test("client heartbeat lands under clients/<slug>.json with the pid", () => {
  const dir = freshRoot();
  process.env.OMITLY_STATE_DIR = dir;
  const file = writeClientHeartbeat({ name: "Claude Desktop", version: "1.4.2" });
  assert.equal(path.basename(file), `claude-desktop-${process.pid}.json`);
  const j = JSON.parse(readFileSync(file, "utf8"));
  assert.equal(j.name, "Claude Desktop");
  assert.equal(j.pid, process.pid);
  assert.ok(Date.parse(j.updated_at) > 0);
});

// ------------------------------------------------------------ the gate -----

test("redact_pdf becomes a proposal while the desktop is present with accept-in-app on", async () => {
  const root = freshRoot();
  const stateDir = freshRoot("omitly-state-");
  writePresence(stateDir);
  writeFileSync(path.join(root, "in.pdf"), "%PDF-1.4 stub");
  let heartbeatWhileConnected = false;
  const res = await withServer(root, stateDir, async (client) => {
    const r = await client.callTool({
      name: "redact_pdf",
      arguments: {
        pdfPath: path.join(root, "in.pdf"),
        outputPath: path.join(root, "out.pdf"),
        regions: [{ page: 0, x: 10, y: 10, width: 50, height: 12, reason: "PII: name" }],
      },
    });
    // The heartbeat file exists while the client is connected and is cleared on close.
    heartbeatWhileConnected = existsSync(path.join(stateDir, "clients", `claude-desktop-${process.pid}.json`));
    return r;
  });
  assert.equal(res.isError, undefined, textOf(res));
  const sc: any = res.structuredContent;
  assert.equal(sc.status, "queued");
  assert.match(sc.proposalId, /^[0-9a-f]{24}$/);
  assert.equal(sc.tool, "redact_pdf");
  assert.deepEqual(sc.client, { name: "Claude Desktop", version: "1.4.2" }, "clientInfo from initialize");
  assert.match(textOf(res), /nothing has been written/i);
  process.env.OMITLY_STATE_DIR = stateDir;
  const stored = readProposal(sc.proposalId);
  assert.equal(stored?.status, "pending");
  assert.equal(stored?.regions?.length, 1);
  assert.equal(stored?.client.name, "Claude Desktop");
  assert.equal(heartbeatWhileConnected, true, "client heartbeat written on initialize");
  assert.equal(existsSync(path.join(stateDir, "clients", `claude-desktop-${process.pid}.json`)), false, "client heartbeat cleared on close");
});

test("redact_by_entity queues too, carrying the requested kinds", async () => {
  const root = freshRoot();
  const stateDir = freshRoot("omitly-state-");
  writePresence(stateDir);
  writeFileSync(path.join(root, "in.pdf"), "%PDF-1.4 stub");
  const res = await withServer(root, stateDir, (client) =>
    client.callTool({
      name: "redact_by_entity",
      arguments: { pdfPath: path.join(root, "in.pdf"), outputPath: path.join(root, "out.pdf"), kinds: ["email", "tfn"] },
    }),
  );
  assert.equal(res.isError, undefined, textOf(res));
  const sc: any = res.structuredContent;
  assert.equal(sc.status, "queued");
  process.env.OMITLY_STATE_DIR = stateDir;
  assert.deepEqual(readProposal(sc.proposalId)?.kinds, ["email", "tfn"]);
});

test("propose_redactions always queues when the desktop is present, and says so when it is not", async () => {
  const root = freshRoot();
  const stateDir = freshRoot("omitly-state-");
  writeFileSync(path.join(root, "in.pdf"), "%PDF-1.4 stub");
  const args = {
    pdfPath: path.join(root, "in.pdf"),
    outputPath: path.join(root, "out.pdf"),
    regions: [{ page: 2, x: 1, y: 1, width: 5, height: 5 }],
  };
  // Absent desktop: an honest refusal, not a silent direct write.
  const absent = await withServer(root, stateDir, (client) => client.callTool({ name: "propose_redactions", arguments: args }));
  assert.equal(absent.isError, true);
  assert.match(textOf(absent), /Omitly desktop app is not running/i);
  // Present: queued.
  writePresence(stateDir);
  const res = await withServer(root, stateDir, (client) => client.callTool({ name: "propose_redactions", arguments: args }));
  assert.equal(res.isError, undefined, textOf(res));
  assert.equal((res.structuredContent as any).status, "queued");
});

test("get_proposal_status reflects what the desktop wrote back, and rejects a bad id", async () => {
  const root = freshRoot();
  const stateDir = freshRoot("omitly-state-");
  writePresence(stateDir);
  process.env.OMITLY_STATE_DIR = stateDir;
  const p = enqueueProposal({ client: { name: "t", version: "1" }, tool: "redact_pdf", pdfPath: "/a.pdf", outputPath: "/b.pdf", regions: [] });
  // Simulate the desktop's decision.
  const file = path.join(stateDir, "proposals", `${p.id}.json`);
  writeFileSync(file, JSON.stringify({ ...p, status: "applied", output: "/b.pdf", verdict: "pass", resolved_at: new Date().toISOString() }));
  const res = await withServer(root, stateDir, (client) => client.callTool({ name: "get_proposal_status", arguments: { proposalId: p.id } }));
  assert.equal(res.isError, undefined, textOf(res));
  const sc: any = res.structuredContent;
  assert.equal(sc.status, "applied");
  assert.equal(sc.output, "/b.pdf");
  assert.equal(sc.verdict, "pass");
  assert.match(textOf(res), /Result: verified \(legacy report\)\./);
  // omitly#676: a v2 Needs Review outcome reads as Needs Review, never as
  // "verified" or a bare "fail".
  writeFileSync(file, JSON.stringify({ ...p, status: "applied", output: "/b.pdf", verdict: "needs_review", resolved_at: new Date().toISOString() }));
  const review = await withServer(root, stateDir, (client) => client.callTool({ name: "get_proposal_status", arguments: { proposalId: p.id } }));
  assert.match(textOf(review), /Result: Needs Review\./);
  assert.doesNotMatch(textOf(review), /verified|verdict fail/);
  const bad = await withServer(root, stateDir, (client) => client.callTool({ name: "get_proposal_status", arguments: { proposalId: "../../etc/passwd" } }));
  assert.equal(bad.isError, true);
});

test("with no desktop heartbeat, redact_pdf takes today's direct path (engine invoked, mcp-agent)", async () => {
  const root = freshRoot();
  const stateDir = freshRoot("omitly-state-");
  writeFileSync(path.join(root, "in.pdf"), "%PDF-1.4 stub");
  for (const k of ENV_KEYS) delete process.env[k];
  process.env.OMITLY_ALLOWED_DIR = root;
  process.env.OMITLY_STATE_DIR = stateDir;
  const engine = recordingEngine(root);
  process.env.OMITLY_REDACT_BIN = engine.bin;
  counter += 1;
  const mod = (await import(`./index.js?desktop-variant=${counter}`)) as typeof import("./index.js");
  const server = mod.createServer();
  const [st, ct] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "t", version: "1" });
  await Promise.all([server.connect(st), client.connect(ct)]);
  try {
    const res = await client.callTool({
      name: "redact_pdf",
      arguments: { pdfPath: path.join(root, "in.pdf"), outputPath: path.join(root, "out.pdf"), regions: [{ page: 0, x: 1, y: 1, width: 2, height: 2 }] },
    });
    assert.equal(res.isError, true, "the stub engine answers ok:false");
    assert.deepEqual(engine.calls(), ["redact"], "the direct path still reaches the engine");
    assert.equal(readdirSync(stateDir).includes("proposals"), false, "no proposal was written");
  } finally {
    await client.close();
    await server.close();
  }
});
