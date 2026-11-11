/**
 * omitly#1853: every tool the REAL server registers carries MCP annotations
 * (a human title plus all four hints), so a client can show a tool's
 * read-only/closed-world nature and decide what to auto-approve.
 *
 * The tool list is read from the server over `tools/list`, never from a
 * hard-coded list, so a tool added later without annotations fails the first
 * test. The expected values live in ONE table (EXPECTED) and the second test
 * pins every registered tool to it, so a hint changed by accident, or a new
 * tool missing from the table, fails here and has to be decided on purpose.
 *
 * Why these values (decided from the code, see #1853):
 * - destructiveHint false everywhere: `confineOutput` refuses an output (or its
 *   `.audit.json`) that already exists, so no tool overwrites or deletes user
 *   data; the page tools write new files only.
 * - openWorldHint false everywhere: nothing is uploaded; `create_pdf` runs its
 *   browser with all network routed to a dead proxy.
 * - readOnlyHint true for the check/verify/read tools. `find_sensitive_regions`
 *   and `check_redaction` bump a LOCAL free-tier usage counter (not a change
 *   to the user's documents), so they stay read-only but NOT idempotent: each
 *   call consumes one of the capped monthly checks. `check_license` is NOT
 *   read-only: with no licence its first call creates the shared trial.json,
 *   which starts the 14-day trial clock (idempotent after that).
 * - idempotentHint false for every writer: repeating it with the same
 *   arguments is refused (the output exists) or queues another proposal.
 */
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createServer } from "./index.js";

type Hints = { readOnly: boolean; idempotent: boolean };

const EXPECTED: Record<string, Hints> = {
  find_sensitive_regions: { readOnly: true, idempotent: false },
  locate_text: { readOnly: true, idempotent: true },
  redact_by_entity: { readOnly: false, idempotent: false },
  redact_pdf: { readOnly: false, idempotent: false },
  verify_redaction: { readOnly: true, idempotent: true },
  check_license: { readOnly: false, idempotent: true },
  verify_seal: { readOnly: true, idempotent: true },
  verify_document: { readOnly: true, idempotent: true },
  create_pdf: { readOnly: false, idempotent: false },
  check_redaction: { readOnly: true, idempotent: false },
  extract_pdf_text: { readOnly: true, idempotent: true },
  propose_redactions: { readOnly: false, idempotent: false },
  get_proposal_status: { readOnly: true, idempotent: true },
  // The five free page tools (omitly#1841) keep their original hints, except pdf_info (idempotent: reads only, uncapped).
  pdf_info: { readOnly: true, idempotent: true },
  merge_pdfs: { readOnly: false, idempotent: false },
  extract_pages: { readOnly: false, idempotent: false },
  split_pdf: { readOnly: false, idempotent: false },
  edit_pages: { readOnly: false, idempotent: false },
};

async function listRealTools() {
  // The server writes a client heartbeat on initialize; keep it out of ~/.omitly.
  const state = mkdtempSync(path.join(tmpdir(), "omitly-annot-"));
  const prev = process.env.OMITLY_STATE_DIR;
  process.env.OMITLY_STATE_DIR = state;
  const server = createServer();
  const client = new Client({ name: "annotations-test", version: "0.0.0" });
  const [a, b] = InMemoryTransport.createLinkedPair();
  try {
    await server.connect(a);
    await client.connect(b);
    return (await client.listTools()).tools;
  } finally {
    await client.close();
    await server.close();
    if (prev === undefined) delete process.env.OMITLY_STATE_DIR;
    else process.env.OMITLY_STATE_DIR = prev;
    rmSync(state, { recursive: true, force: true });
  }
}

test("every tool the real server registers has a title and all four boolean hints", async () => {
  const tools = await listRealTools();
  assert.ok(tools.length >= Object.keys(EXPECTED).length, "tools/list returned the full set");
  for (const t of tools) {
    const a = t.annotations;
    assert.ok(a, `${t.name} has annotations`);
    assert.equal(typeof a.title, "string", `${t.name} title is a string`);
    assert.ok(a.title!.trim().length > 0, `${t.name} has a non-empty title`);
    for (const hint of ["readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"] as const) {
      assert.equal(typeof a[hint], "boolean", `${t.name} ${hint} is a boolean`);
    }
  }
});

test("each tool's hints match the table (and no tool is missing from it)", async () => {
  const tools = await listRealTools();
  assert.deepEqual(tools.map((t) => t.name).sort(), Object.keys(EXPECTED).sort());
  for (const t of tools) {
    const want = EXPECTED[t.name];
    const a = t.annotations!;
    assert.equal(a.readOnlyHint, want.readOnly, `${t.name} readOnlyHint`);
    assert.equal(a.idempotentHint, want.idempotent, `${t.name} idempotentHint`);
    assert.equal(a.destructiveHint, false, `${t.name} destructiveHint`);
    assert.equal(a.openWorldHint, false, `${t.name} openWorldHint`);
  }
});
