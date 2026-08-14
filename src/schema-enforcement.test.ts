/**
 * Output-schema ENFORCEMENT test (#540 follow-up).
 *
 * `leak-canary.test.ts` proves the 7 real tools emit schema-valid, leak-free
 * payloads — but it validates them itself, with its own `safeParse` calls. That
 * is test-side coverage; it says nothing about what happens at RUNTIME if a
 * future handler regression starts emitting a raw field.
 *
 * The obvious answer — "the declared `outputSchema` catches it" — is false on
 * exactly the branches that matter. `@modelcontextprotocol/sdk`'s
 * `validateToolOutput` begins `if (result.isError) { return; }`, so it skips
 * output validation on every error-flagged result. Per #338's settled policy,
 * "this document is NOT clean" is precisely what sets `isError: true` here, so
 * the SDK skips validation on the three branches carrying
 * `findings`/`survivors`/`regions`.
 *
 * `checked()` in index.ts is the compensating control. These tests hold it to
 * the guarantee the module doc claims: a payload carrying a field the schema
 * does not declare fails the tool call, and the resulting error message does
 * not itself echo the offending value.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { z } from "zod";
import { checked, checkRedactionOutputSchema } from "./index.js";

/** A value that must never appear in any output — stands in for raw document
 *  text a regressed handler might start copying through. */
const RAW = "RAW-DOCUMENT-TEXT-a1b2c3-must-never-appear";

/** Minimal schema-valid fillers, so each test's only defect is the one it is about. */
const COVERAGE = {
  pagesScanned: 1,
  pagesTotal: 1,
  notScanned: [],
  priorRevisionsScanned: true,
  metadataScanned: true,
  acroformScanned: true,
  attachmentsScanned: true,
  formXobjectsScanned: 0,
  annotationAppearancesScanned: 0,
  pagesFailedCount: 0,
};
const REGION = { page: 0, x: 1, y: 2, width: 3, height: 4, kind: "EMAIL", preview: "\u2022\u2022\u2022@\u2022\u2022\u2022" };

test("checked() returns the parsed value for a payload that satisfies the schema", () => {
  const ok = checked(checkRedactionOutputSchema, {
    clean: true,
    totalFindings: 0,
    byKind: {},
    regions: [],
    survivors: [],
    offPage: [],
    coverage: COVERAGE,
  });
  assert.equal(ok.clean, true);
  assert.equal(ok.totalFindings, 0);
});

test("checked() throws on an undeclared field, and names paths/codes but NOT the value", () => {
  assert.throws(
    () =>
      checked(checkRedactionOutputSchema, {
        clean: false,
        totalFindings: 1,
        byKind: { EMAIL: 1 },
        regions: [REGION],
        survivors: [],
        offPage: [],
        coverage: COVERAGE,
        // The regression this whole mechanism exists for.
        rawText: RAW,
      } as z.input<typeof checkRedactionOutputSchema>),
    (e: Error) => {
      assert.match(e.message, /failed its declared outputSchema/);
      assert.match(e.message, /unrecognized_keys/);
      assert.ok(!e.message.includes(RAW), `error message echoed the offending value: ${e.message}`);
      return true;
    },
  );
});

test("an isError result carrying an undeclared field fails the tool call instead of shipping it", async () => {
  // Reproduces the exact shape the SDK does NOT validate: outputSchema declared,
  // isError: true, structuredContent present. Without checked() the raw field
  // would travel to the client untouched.
  const server = new McpServer({ name: "schema-enforcement-test", version: "0.0.0" });
  server.registerTool(
    "leaky_check",
    {
      description: "test double for a regressed handler on the 'PII found' branch",
      inputSchema: {},
      outputSchema: checkRedactionOutputSchema,
    },
    async () => {
      const structuredContent = checked(checkRedactionOutputSchema, {
        clean: false,
        totalFindings: 1,
        byKind: { EMAIL: 1 },
        regions: [REGION],
        survivors: [],
        offPage: [],
        coverage: COVERAGE,
        rawText: RAW,
      } as z.input<typeof checkRedactionOutputSchema>);
      return {
        content: [{ type: "text" as const, text: "⚠️ not clean" }],
        structuredContent,
        isError: true,
      };
    },
  );

  const [serverTransport, clientTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "schema-enforcement-test", version: "0.0.0" });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  try {
    const res: any = await client.callTool({ name: "leaky_check", arguments: {} });
    assert.equal(res.isError, true, "the call must be reported as failed");
    assert.equal(res.structuredContent, undefined, "no structuredContent may be returned");
    const serialized = JSON.stringify(res);
    assert.ok(!serialized.includes(RAW), `the raw value reached the client:\n${serialized}`);
    assert.match(serialized, /failed its declared outputSchema/);
  } finally {
    await client.close();
    await server.close();
  }
});
