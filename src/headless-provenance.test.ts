/**
 * omitly#1890 step 3 (X2, K9): the MCP server refuses a region `reason` that claims a person-confirmed
 * provenance (`AI_PROPOSAL`, `OCR_CORRECTED`, `MANUAL`: the text before the first `|` or `=>`, trimmed,
 * case-insensitive) before it queues a proposal or runs the engine, with and without the desktop app.
 * The engine CLI is the authoritative gate (`crates/omitly-cli/tests/headless_provenance.rs`); this is
 * the same rule worded for the agent, so `redact_pdf` and `propose_redactions` answer alike in every
 * desktop state.
 *
 * Oracle: the real server (a fresh `index.js` per scenario), a real in-memory MCP client, real
 * heartbeat and proposal files in a temp state dir. The only stub is an engine that records whether it
 * was invoked, as in `removal-flow.test.ts`.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { chmodSync, existsSync, mkdtempSync, readFileSync, readdirSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import * as path from "node:path";
import { recordAnalysis, sha256OfFile } from "./desktop.js";
import { reservedProvenance, reservedReasonRefusal } from "./index.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

const ENV_KEYS = ["OMITLY_ALLOWED_DIR", "OMITLY_REDACT_BIN", "OMITLY_PDF_BIN", "OMITLY_ENGINE_DIR", "OMITLY_STATE_DIR"] as const;
let counter = 0;

const freshRoot = (prefix = "omitly-hp1890-") => realpathSync(mkdtempSync(path.join(tmpdir(), prefix)));
const textOf = (res: any): string =>
  (res.content ?? []).filter((c: any) => c.type === "text").map((c: any) => c.text).join("\n");

function writePresence(stateDir: string, acceptInApp: boolean): void {
  writeFileSync(
    path.join(stateDir, "desktop.json"),
    JSON.stringify({ pid: 4242, version: "5.5.0", accept_in_app: acceptInApp, updated_at: new Date().toISOString() }),
  );
}

/** An engine that records every invocation and answers `ok:false`: reaching it is what the tests count. */
function recordingEngine(root: string): { bin: string; calls: () => string[] } {
  const bin = path.join(root, "stub-engine.mjs");
  const log = path.join(root, "engine-calls.log");
  writeFileSync(
    bin,
    `#!/usr/bin/env node
import { appendFileSync, readFileSync } from "node:fs";
const req = JSON.parse(readFileSync(0, "utf8"));
appendFileSync(${JSON.stringify(log)}, JSON.stringify(req) + "\\n");
process.stdout.write(JSON.stringify({ ok: false, error: "stub engine reached" }));
`,
    { mode: 0o755 },
  );
  chmodSync(bin, 0o755);
  return { bin, calls: () => (existsSync(log) ? readFileSync(log, "utf8").trim().split("\n").filter(Boolean) : []) };
}

type Scenario = { presence: "none" | "accept-off" | "accept-on"; engine: boolean };
type Ctx = { root: string; stateDir: string; pdf: string; engineCalls: () => string[]; proposals: () => string[] };

async function run<T>(sc: Scenario, fn: (client: Client, ctx: Ctx) => Promise<T>): Promise<T> {
  const root = freshRoot();
  const stateDir = freshRoot("omitly-hp1890-state-");
  const pdf = path.join(root, "in.pdf");
  writeFileSync(pdf, "%PDF-1.4 stub");
  if (sc.presence !== "none") writePresence(stateDir, sc.presence === "accept-on");
  for (const k of ENV_KEYS) delete process.env[k];
  process.env.OMITLY_ALLOWED_DIR = root;
  process.env.OMITLY_STATE_DIR = stateDir;
  const engine = recordingEngine(root);
  if (sc.engine) process.env.OMITLY_REDACT_BIN = engine.bin;
  counter += 1;
  const mod = (await import(`./index.js?headless-provenance=${counter}`)) as typeof import("./index.js");
  const server = mod.createServer();
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "Claude Desktop", version: "1.4.2" });
  await Promise.all([server.connect(a), client.connect(b)]);
  try {
    return await fn(client, {
      root,
      stateDir,
      pdf,
      engineCalls: engine.calls,
      proposals: () => (existsSync(path.join(stateDir, "proposals")) ? readdirSync(path.join(stateDir, "proposals")) : []),
    });
  } finally {
    await client.close();
    await server.close();
  }
}

const region = { page: 0, x: 1, y: 1, width: 5, height: 5 };

/** Every spelling of a reserved word the rule must catch (the same set as the CLI test). */
function spellings(token: string): string[] {
  const lower = token.toLowerCase();
  const mixed = [...token].map((c, i) => (i % 2 === 0 ? c : c.toLowerCase())).join("");
  return [
    token,
    lower,
    mixed,
    `  ${token}\t`,
    `\n ${lower} \r\n`,
    ` ${token}　`,
    `${token}|CODE`,
    `${lower}|code`,
    `${token} | CODE`,
    `${token}=>Person A`,
    `${mixed}|CODE=>Person A`,
    ` ${lower} =>x`,
  ];
}

const TOKENS = ["AI_PROPOSAL", "OCR_CORRECTED", "MANUAL"];

/** The scenarios of the test name: no desktop (with and without an engine), desktop with accept-in-app off, on. */
const SCENARIOS: Scenario[] = [
  { presence: "none", engine: true },
  { presence: "none", engine: false },
  { presence: "accept-off", engine: true },
  { presence: "accept-on", engine: true },
  { presence: "accept-on", engine: false },
];

test("mcp_refuses_reserved_reasons_with_and_without_a_desktop", async () => {
  for (const sc of SCENARIOS) {
    await run(sc, async (client, { pdf, root, engineCalls, proposals }) => {
      // A real analysis id, so that with the desktop on, a call that passed the rule WOULD queue (the
      // positive control below proves it does).
      const analysisId = recordAnalysis(pdf, sha256OfFile(pdf));
      for (const name of ["redact_pdf", "propose_redactions"]) {
        for (const token of TOKENS) {
          for (const reason of spellings(token)) {
            // The offending region is the second of three: any region counts, and N names it.
            const res: any = await client
              .callTool({
                name,
                arguments: {
                  pdfPath: pdf,
                  outputPath: path.join(root, "o.pdf"),
                  regions: [{ ...region, reason: "PII.SSN" }, { ...region, reason }, region],
                  analysisId,
                },
              })
              .catch((e: Error) => ({ isError: true, content: [{ type: "text", text: e.message }] }));
            const where = `${JSON.stringify(sc)} ${name} ${JSON.stringify(reason)}`;
            assert.equal(res.isError, true, `${where}: refused`);
            assert.ok(textOf(res).includes(reservedReasonRefusal(1)), `${where}: names region 1 in the E17 text: ${textOf(res)}`);
          }
        }
      }
      assert.deepEqual(proposals(), [], `${JSON.stringify(sc)}: nothing was queued`);
      assert.deepEqual(engineCalls(), [], `${JSON.stringify(sc)}: the engine was never invoked`);
    });
  }

  // Positive control: the same calls with an honest reason are NOT refused by this rule, so the
  // refusals above are the rule and not a broken harness. Direct path: the engine is reached.
  await run({ presence: "none", engine: true }, async (client, { pdf, root, engineCalls }) => {
    const res: any = await client.callTool({
      name: "redact_pdf",
      arguments: { pdfPath: pdf, outputPath: path.join(root, "o.pdf"), regions: [{ ...region, reason: "PII.SSN" }, region] },
    });
    assert.doesNotMatch(textOf(res), /reserves for what a person decided/);
    assert.equal(engineCalls().length, 1, "an honest reason reaches the engine");
  });
  // Desktop on: both tools queue.
  await run({ presence: "accept-on", engine: true }, async (client, { pdf, root, proposals }) => {
    const analysisId = recordAnalysis(pdf, sha256OfFile(pdf));
    for (const name of ["redact_pdf", "propose_redactions"]) {
      const res: any = await client.callTool({
        name,
        arguments: { pdfPath: pdf, outputPath: path.join(root, "o.pdf"), regions: [{ ...region, reason: "PII.SSN" }, region], analysisId },
      });
      assert.ok(!res.isError, `${name}: ${textOf(res)}`);
      assert.equal(res.structuredContent.status, "queued", name);
    }
    assert.equal(proposals().length, 2, "an honest reason is queued");
  });
});

test("mcp_still_accepts_free_reasons_and_no_reason", async () => {
  // The same set as the CLI's `cli_still_accepts_free_reasons`, plus no reason at all (the engine's
  // own default is UNSPECIFIED) and reasons that only CONTAIN a reserved word.
  await run({ presence: "none", engine: true }, async (client, { pdf, root, engineCalls }) => {
    const free: (string | undefined)[] = [
      "PII.SSN",
      "PII: SSN",
      "UNSPECIFIED",
      "OCR",
      "FULL_PAGE",
      "REPLACE",
      "NAME_LIST",
      "",
      "   ",
      "PII|MANUAL",
      "MANUAL REVIEW",
      "MANUALLY",
      undefined,
    ];
    for (const reason of free) {
      const res: any = await client.callTool({
        name: "redact_pdf",
        arguments: { pdfPath: pdf, outputPath: path.join(root, "o.pdf"), regions: [reason === undefined ? region : { ...region, reason }] },
      });
      assert.doesNotMatch(textOf(res), /reserves for what a person decided/, JSON.stringify(reason));
    }
    assert.equal(engineCalls().length, free.length, "every free reason reached the engine");
  });
});

test("the reserved-word rule decides like the engine CLI", () => {
  // The cases of the CLI's unit test `reserved_provenance_reads_the_provenance_part_trimmed_and_uppercased`.
  const table: [string, string | undefined][] = [
    ["AI_PROPOSAL", "AI_PROPOSAL"],
    ["OCR_CORRECTED", "OCR_CORRECTED"],
    ["MANUAL", "MANUAL"],
    ["manual", "MANUAL"],
    ["Ai_Proposal", "AI_PROPOSAL"],
    ["  ocr_corrected\t", "OCR_CORRECTED"],
    ["\n MANUAL \r\n", "MANUAL"],
    [" MANUAL　", "MANUAL"],
    ["\u0085manual", "MANUAL"],
    ["MANUAL|CODE", "MANUAL"],
    ["AI_PROPOSAL | CODE", "AI_PROPOSAL"],
    ["manual=>Person A", "MANUAL"],
    ["OCR_CORRECTED|CODE=>Person A", "OCR_CORRECTED"],
    ["MANUAL=>x|y", "MANUAL"],
    ["PII.SSN", undefined],
    ["PII: SSN", undefined],
    ["UNSPECIFIED", undefined],
    ["OCR", undefined],
    ["FULL_PAGE", undefined],
    ["REPLACE", undefined],
    ["NAME_LIST", undefined],
    ["", undefined],
    ["   ", undefined],
    ["PII|MANUAL", undefined],
    ["PII=>MANUAL", undefined],
    ["|MANUAL", undefined],
    ["=>MANUAL", undefined],
    ["MANUALLY", undefined],
    ["MANUAL REVIEW", undefined],
    ["NOT_MANUAL", undefined],
    ["AI PROPOSAL", undefined],
    ["MAN​UAL", undefined],
    // Where JS and Rust differ by default, the rule follows Rust: U+FEFF is not white space to the CLI,
    // and `ı` (dotless i) and `ſ` (long s) uppercase to ASCII letters in JS but not in Rust.
    ["﻿MANUAL", undefined],
    ["Aı_PROPOSAL", undefined],
    ["AI_PROPOſAL", undefined],
  ];
  for (const [reason, want] of table) assert.equal(reservedProvenance(reason), want, JSON.stringify(reason));
});

test("the refusal text is the engine contract's, word for word", () => {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const file = path.join(here, "..", "..", "contract", "cases", "error-redact-reserved-reason.json");
  // The public mirror holds omitly-mcp alone: there the contract file does not exist.
  if (!existsSync(file)) return;
  const golden = JSON.parse(readFileSync(file, "utf8"));
  assert.equal(golden.response.error, reservedReasonRefusal(1));
});
