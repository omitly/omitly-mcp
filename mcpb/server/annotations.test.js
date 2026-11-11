"use strict";
// omitly#1853: every tool the MCPB bundle server registers carries MCP
// annotations. The server is started as a real stdio child and the tools are
// read over `tools/list`, so a tool added without annotations fails here. All
// four tools are diagnosis-only: read-only, non-destructive, closed-world.
// find_sensitive_regions and check_redaction bump a LOCAL free-tier counter,
// which is not a change to the user's documents, but each call consumes one
// capped monthly check, so those two are read-only and NOT idempotent.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { mkdtempSync, rmSync } = require("node:fs");
const { tmpdir } = require("node:os");
const path = require("node:path");

const METERED = ["check_redaction", "find_sensitive_regions"];
const EXPECTED = ["check_redaction", "find_sensitive_regions", "locate_text", "verify_redaction"];

test("every MCPB tool has a title and the four boolean hints", async () => {
  const { Client } = await import("@modelcontextprotocol/sdk/client/index.js");
  const { StdioClientTransport } = await import("@modelcontextprotocol/sdk/client/stdio.js");
  const state = mkdtempSync(path.join(tmpdir(), "omitly-mcpb-annot-"));
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [path.join(__dirname, "index.js")],
    env: { PATH: process.env.PATH ?? "", OMITLY_STATE_DIR: state, OMITLY_ALLOWED_DIR: state },
    stderr: "ignore",
  });
  const client = new Client({ name: "mcpb-annotations-test", version: "0.0.0" });
  try {
    await client.connect(transport);
    const { tools } = await client.listTools();
    assert.deepEqual(tools.map((t) => t.name).sort(), EXPECTED);
    for (const t of tools) {
      const a = t.annotations;
      assert.ok(a, `${t.name} has annotations`);
      assert.ok(typeof a.title === "string" && a.title.trim().length > 0, `${t.name} has a title`);
      for (const h of ["readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"]) {
        assert.equal(typeof a[h], "boolean", `${t.name} ${h} is a boolean`);
      }
      assert.equal(a.readOnlyHint, true, `${t.name} readOnlyHint`);
      assert.equal(a.destructiveHint, false, `${t.name} destructiveHint`);
      // The two metered tools consume one of the capped monthly checks per call.
      assert.equal(a.idempotentHint, !METERED.includes(t.name), `${t.name} idempotentHint`);
      assert.equal(a.openWorldHint, false, `${t.name} openWorldHint`);
    }
  } finally {
    await client.close();
    rmSync(state, { recursive: true, force: true });
  }
});
