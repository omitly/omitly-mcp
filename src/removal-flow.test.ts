/**
 * omitly#1861 / #1860 / #1866: what the MCP server answers to a REMOVAL request in each state it
 * can observe: engine configured or not, desktop app running or not, accept-in-app on or off.
 *
 * Oracle: the real server (a fresh `index.js` instance per scenario, so ENGINE_BIN is resolved
 * from that scenario's env), a real in-memory MCP client, and real heartbeat/proposal files in a
 * temp state dir. The only stub is an engine that records whether it was invoked.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { chmodSync, existsSync, mkdtempSync, readFileSync, readdirSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import * as path from "node:path";
import { recordAnalysis, sha256OfFile } from "./desktop.js";
import { removalUnavailableText, proposeUnavailableText } from "./removal.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

const ENV_KEYS = ["OMITLY_ALLOWED_DIR", "OMITLY_REDACT_BIN", "OMITLY_PDF_BIN", "OMITLY_ENGINE_DIR", "OMITLY_STATE_DIR"] as const;
const LINK = "https://omitly.app/?via=mcp";
let counter = 0;

const freshRoot = (prefix = "omitly-removal-") => realpathSync(mkdtempSync(path.join(tmpdir(), prefix)));
const textOf = (res: any): string =>
  (res.content ?? []).filter((c: any) => c.type === "text").map((c: any) => c.text).join("\n");

function writePresence(stateDir: string, acceptInApp: boolean): void {
  writeFileSync(
    path.join(stateDir, "desktop.json"),
    JSON.stringify({ pid: 4242, version: "5.5.0", accept_in_app: acceptInApp, updated_at: new Date().toISOString() }),
  );
}

function recordingEngine(root: string): { bin: string; calls: () => string[]; requests: () => any[] } {
  const bin = path.join(root, "stub-engine.mjs");
  const log = path.join(root, "engine-calls.log");
  // omitly#1890 step 1: the whole request, one JSON line per invocation, for the probe below.
  const requestLog = path.join(root, "engine-requests.log");
  writeFileSync(
    bin,
    `#!/usr/bin/env node
import { appendFileSync, readFileSync } from "node:fs";
const req = JSON.parse(readFileSync(0, "utf8"));
appendFileSync(${JSON.stringify(log)}, req.command + "\\n");
appendFileSync(${JSON.stringify(requestLog)}, JSON.stringify(req) + "\\n");
process.stdout.write(JSON.stringify({ ok: false, error: "stub engine reached" }));
`,
    { mode: 0o755 },
  );
  chmodSync(bin, 0o755);
  return {
    bin,
    calls: () => (existsSync(log) ? readFileSync(log, "utf8").trim().split("\n").filter(Boolean) : []),
    requests: () =>
      existsSync(requestLog) ? readFileSync(requestLog, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)) : [],
  };
}

type Scenario = { presence: "none" | "accept-off" | "accept-on"; engine: boolean };

async function run<T>(sc: Scenario, fn: (client: Client, ctx: { root: string; stateDir: string; pdf: string; engineCalls: () => string[]; engineRequests: () => any[] }) => Promise<T>): Promise<T> {
  const root = freshRoot();
  const stateDir = freshRoot("omitly-removal-state-");
  const pdf = path.join(root, "in.pdf");
  writeFileSync(pdf, "%PDF-1.4 stub");
  if (sc.presence !== "none") writePresence(stateDir, sc.presence === "accept-on");
  for (const k of ENV_KEYS) delete process.env[k];
  process.env.OMITLY_ALLOWED_DIR = root;
  process.env.OMITLY_STATE_DIR = stateDir;
  const engine = recordingEngine(root);
  if (sc.engine) process.env.OMITLY_REDACT_BIN = engine.bin;
  counter += 1;
  const mod = (await import(`./index.js?removal-flow=${counter}`)) as typeof import("./index.js");
  const server = mod.createServer();
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "Claude Desktop", version: "1.4.2" });
  await Promise.all([server.connect(a), client.connect(b)]);
  try {
    return await fn(client, { root, stateDir, pdf, engineCalls: engine.calls, engineRequests: engine.requests });
  } finally {
    await client.close();
    await server.close();
  }
}

const region = { page: 0, x: 1, y: 1, width: 5, height: 5 };
/** omitly#1890: what a scan of `pdf` registers, so a queued proposal can name it (the scan tools have their own tests). */
const aid = (pdf: string) => recordAnalysis(pdf, sha256OfFile(pdf));
const proposalFiles = (stateDir: string) => (existsSync(path.join(stateDir, "proposals")) ? readdirSync(path.join(stateDir, "proposals")) : []);

// ----- no engine, desktop app not running ------------------------------------------------

test("no engine, app not running: every removal tool says the app does it, free to try for 14 days or 5 redacted documents, the tagged link, 'open it and ask again'", async () => {
  await run({ presence: "none", engine: false }, async (client, { pdf, root, stateDir, engineCalls }) => {
    const calls: [string, Record<string, unknown>][] = [
      ["redact_pdf", { pdfPath: pdf, outputPath: path.join(root, "o.pdf"), regions: [region] }],
      ["redact_by_entity", { pdfPath: pdf, outputPath: path.join(root, "o.pdf") }],
      ["propose_redactions", { pdfPath: pdf, outputPath: path.join(root, "o.pdf"), regions: [region] }],
    ];
    for (const [name, args] of calls) {
      const res: any = await client.callTool({ name, arguments: args });
      const t = textOf(res);
      assert.equal(res.isError, true, `${name}: nothing was removed, so not a success`);
      assert.match(t, /^Nothing was removed\./, `${name}: leads with the fact that nothing was removed`);
      assert.match(t, /done by the Omitly desktop app on this computer/, name);
      assert.match(t, /free to try for 14 days or 5 redacted documents, whichever comes first:/, name);
      assert.ok(t.includes(LINK), `${name}: the tagged link`);
      assert.match(t, /If Omitly is already installed, open it and ask again\./, name);
      // Not led by environment-variable advice, and one short final sentence for pipeline users.
      assert.ok(t.indexOf("OMITLY_ENGINE_DIR") > t.indexOf("open it and ask again"), `${name}: engine advice comes last`);
      assert.ok(t.trimEnd().endsWith("omitly-redact."), `${name}: engine advice is the final sentence`);
      assert.doesNotMatch(t, /No redaction engine configured/, name);
      assert.doesNotMatch(t, /call redact_pdf/i, `${name}: no dead-end advice`);
    }
    assert.deepEqual(proposalFiles(stateDir), [], "nothing was queued");
    assert.deepEqual(engineCalls(), []);
  });
});

// ----- no engine, app running, switch off -------------------------------------------------

test("no engine, app running, accept-in-app off: says where the switch is; no link; no dead-end advice", async () => {
  await run({ presence: "accept-off", engine: false }, async (client, { pdf, root, stateDir }) => {
    const calls: [string, Record<string, unknown>][] = [
      ["redact_pdf", { pdfPath: pdf, outputPath: path.join(root, "o.pdf"), regions: [region] }],
      ["redact_by_entity", { pdfPath: pdf, outputPath: path.join(root, "o.pdf") }],
      ["propose_redactions", { pdfPath: pdf, outputPath: path.join(root, "o.pdf"), regions: [region] }],
    ];
    for (const [name, args] of calls) {
      const res: any = await client.callTool({ name, arguments: args });
      const t = textOf(res);
      assert.equal(res.isError, true, name);
      assert.match(t, /^Nothing was removed\./, name);
      assert.ok(t.includes('Settings → Connect your AI → "Accept proposals in Omitly"'), `${name}: where the switch is`);
      assert.ok(!t.includes("omitly.app"), `${name}: Omitly is installed, so no trial link`);
      assert.doesNotMatch(t, /call redact_pdf|No redaction engine configured/i, name);
    }
    assert.deepEqual(proposalFiles(stateDir), []);
  });
});

// ----- app running, switch on: the existing proposal path ---------------------------------

test("app running, accept-in-app on: redact_pdf and redact_by_entity queue; the stored proposal format is unchanged", async () => {
  await run({ presence: "accept-on", engine: false }, async (client, { pdf, root, stateDir, engineCalls }) => {
    const pdfRes: any = await client.callTool({ name: "redact_pdf", arguments: { pdfPath: pdf, outputPath: path.join(root, "o.pdf"), regions: [region], analysisId: aid(pdf) } });
    assert.ok(!pdfRes.isError, textOf(pdfRes));
    assert.equal(pdfRes.structuredContent.status, "queued");
    assert.match(textOf(pdfRes), /a person must accept it in the Omitly desktop app, which then removes, verifies and seals/);
    assert.doesNotMatch(textOf(pdfRes), /Auto-redact/, "a region proposal can be accepted as sent: no extra steps");

    const entRes: any = await client.callTool({ name: "redact_by_entity", arguments: { pdfPath: pdf, outputPath: path.join(root, "e.pdf"), kinds: ["email"] } });
    assert.ok(!entRes.isError, textOf(entRes));
    assert.equal(entRes.structuredContent.status, "queued");

    const files = proposalFiles(stateDir);
    assert.equal(files.length, 2);
    for (const f of files) {
      const p = JSON.parse(readFileSync(path.join(stateDir, "proposals", f), "utf8"));
      // omitly#1890: `pdfSha256` (and `binding` on a kinds-only proposal) are the two deliberate additions.
      const allowed = new Set(["id", "created_at", "client", "tool", "pdfPath", "outputPath", "regions", "kinds", "status", "pdfSha256", "binding"]);
      assert.deepEqual(Object.keys(p).filter((k) => !allowed.has(k)), [], "no new proposal field");
      assert.equal(p.status, "pending");
    }
    assert.deepEqual(engineCalls(), []);
  });
});

// ----- #1866 ------------------------------------------------------------------------------

test("a queued redact_by_entity proposal says the person must open the document, run Auto-redact and review; get_proposal_status says so while pending", async () => {
  await run({ presence: "accept-on", engine: false }, async (client, { pdf, root }) => {
    const res: any = await client.callTool({ name: "redact_by_entity", arguments: { pdfPath: pdf, outputPath: path.join(root, "e.pdf") } });
    const t = textOf(res);
    assert.match(t, /queued in Omitly for redact_by_entity/);
    assert.match(t, /Nothing has been written\./);
    assert.match(t, /cannot accept it as sent/);
    assert.match(t, /open the document in Omitly \(Show\), run Auto-redact and review what it finds, and then accept/);
    assert.match(res.structuredContent.note, /Auto-redact/);
    assert.doesNotMatch(t, /a person must accept it in the Omitly desktop app, which then removes/, "the old text that said it could be accepted as sent");

    const st: any = await client.callTool({ name: "get_proposal_status", arguments: { proposalId: res.structuredContent.proposalId } });
    assert.equal(st.structuredContent.status, "pending");
    assert.match(textOf(st), /Pending: .*open the document in Omitly \(Show\), run Auto-redact and review what it finds before they can accept it/);

    // A region proposal's pending text is unchanged.
    const reg: any = await client.callTool({ name: "redact_pdf", arguments: { pdfPath: pdf, outputPath: path.join(root, "r.pdf"), regions: [region], analysisId: aid(pdf) } });
    const st2: any = await client.callTool({ name: "get_proposal_status", arguments: { proposalId: reg.structuredContent.proposalId } });
    assert.match(textOf(st2), /Pending: waiting for a person to accept or reject it in the Omitly desktop app\.$/);
  });
});

// ----- engine configured: the direct write is real, and is the only place redact_pdf is suggested ----

test("engine configured, app not running: redact_pdf writes through the engine; propose_redactions may suggest redact_pdf", async () => {
  await run({ presence: "none", engine: true }, async (client, { pdf, root, engineCalls }) => {
    const prop: any = await client.callTool({ name: "propose_redactions", arguments: { pdfPath: pdf, outputPath: path.join(root, "o.pdf"), regions: [region] } });
    assert.equal(prop.isError, true);
    assert.match(textOf(prop), /Omitly desktop app is not running/);
    assert.match(textOf(prop), /call redact_pdf: this server has an engine configured/);
    const direct: any = await client.callTool({ name: "redact_pdf", arguments: { pdfPath: pdf, outputPath: path.join(root, "o.pdf"), regions: [region] } });
    assert.deepEqual(engineCalls(), ["redact"], "the configured engine is reached (the stub answers ok:false)");
    assert.doesNotMatch(textOf(direct), /^Nothing was removed\./, "the designed no-engine text is not used when an engine is configured");
  });
});

test("engine configured, app running, accept-in-app off: propose_redactions names the switch and the direct write", async () => {
  await run({ presence: "accept-off", engine: true }, async (client, { pdf, root }) => {
    const prop: any = await client.callTool({ name: "propose_redactions", arguments: { pdfPath: pdf, outputPath: path.join(root, "o.pdf"), regions: [region] } });
    assert.equal(prop.isError, true);
    assert.ok(textOf(prop).includes('Settings → Connect your AI → "Accept proposals in Omitly"'));
    assert.match(textOf(prop), /call redact_pdf/);
  });
});

// ----- engine-only tools ------------------------------------------------------------------

test("verify_seal, verify_document and check_license with no engine: say where the seal is checked in the app, no link, no pass or fail", async () => {
  await run({ presence: "none", engine: false }, async (client, { pdf }) => {
    for (const name of ["verify_seal", "verify_document"]) {
      const res: any = await client.callTool({ name, arguments: { pdfPath: pdf } });
      const t = textOf(res);
      assert.equal(res.isError, true, name);
      assert.ok(t.includes('Home → "Verify a redacted PDF"'), name);
      assert.match(t, /needs the pipeline engine/, name);
      assert.ok(!t.includes("omitly.app"), `${name}: no trial link on a check`);
      assert.doesNotMatch(t, /No redaction engine configured|OMITLY_ENGINE_DIR/, name);
    }
    const lic: any = await client.callTool({ name: "check_license", arguments: {} });
    assert.equal(lic.isError, true);
    assert.match(textOf(lic), /needs the pipeline engine/);
    assert.match(textOf(lic), /shown in the Omitly desktop app/);
    assert.ok(!textOf(lic).includes("omitly.app"));
  });
});

// ----- leak results carry no link (omitly#1860) ------------------------------------------

test("a leak-found result says Omitly can remove what was found if the user asks, with no link", async () => {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const sample = [path.join(here, "..", "tests", "fixtures", "sample.pdf"), path.join(here, "..", "..", "tests", "fixtures", "sample.pdf")].find((p) => existsSync(p));
  assert.ok(sample);
  await run({ presence: "none", engine: false }, async (client, { root }) => {
    const doc = path.join(root, "sample.pdf");
    writeFileSync(doc, readFileSync(sample));
    const res: any = await client.callTool({ name: "check_redaction", arguments: { pdfPath: doc } });
    const t = textOf(res);
    // omitly#1857: a completed check is a result, not a tool failure (the card needs isError:false).
    assert.equal(res.isError, false, "findings: a result, flagged by its text");
    assert.match(t, /LEAK:/);
    assert.match(t, /This check does not remove anything\. Omitly can remove what was found if the user asks\./);
    assert.ok(!t.includes("omitly.app") && !t.includes("via=mcp"), "no URL on a scan result");
    assert.doesNotMatch(t, /AI-reviewed|court-grade/i);
  });
});

// ----- the three heartbeat cases of removalUnavailableText, one by one ----------------------

const beat = (acceptInApp: boolean) => ({ pid: 1, version: "5.5.0", accept_in_app: acceptInApp, updated_at: new Date().toISOString() });

test("removalUnavailableText case 1: no heartbeat -> the app is not running, trial link", () => {
  const t = removalUnavailableText(null);
  assert.match(t, /^Nothing was removed\./);
  assert.match(t, /it is not running/);
  assert.ok(t.includes(LINK));
});

test("removalUnavailableText case 2: heartbeat with accept-in-app OFF -> says where the switch is", () => {
  const t = removalUnavailableText(beat(false));
  assert.match(t, /^Nothing was removed\./);
  assert.ok(t.includes('Settings → Connect your AI → "Accept proposals in Omitly"'));
  assert.match(t, /switch .* is off/);
  assert.ok(!t.includes("omitly.app"));
});

test("removalUnavailableText case 3: heartbeat with accept-in-app ON (app became ready between the two reads) -> never tells the user to turn on a switch that is on", () => {
  const t = removalUnavailableText(beat(true));
  assert.match(t, /^Nothing was removed\./);
  assert.match(t, /now running and ready/);
  assert.match(t, /Ask again\.$/);
  assert.doesNotMatch(t, /is off|Settings → Connect your AI|omitly\.app/);
  // propose_redactions' text has the same property, with and without an engine.
  for (const engine of [false, true]) {
    const p = proposeUnavailableText(beat(true), engine);
    assert.match(p, /^Nothing was removed\./);
    assert.doesNotMatch(p, /is off|switched off/);
  }
});

// ----- omitly#1890 build step 1: probe 10 (design 8.0), an assertion since step 3 ----------------

// X2. With no desktop heartbeat the MCP server runs the engine itself, and `redact_pdf` used to forward
// the caller's free-text `reason` (here the provenance token AI_PROPOSAL) to the engine request
// unchanged, so a caller could mint that label with no proposal and no person. Step 3 refuses it
// (E17, design 5.13) before the engine is invoked. The OBSERVED prints stay and show the refusal; the
// assertions pin it. The full matrix (every token and spelling, `propose_redactions`, every desktop
// state, nothing queued) is `headless-provenance.test.ts`.
test("probe_1890_mcp_direct_redact_forwards_ai_proposal_reason", async () => {
  await run({ presence: "none", engine: true }, async (client, { pdf, root, engineCalls, engineRequests }) => {
    const direct: any = await client.callTool({
      name: "redact_pdf",
      arguments: { pdfPath: pdf, outputPath: path.join(root, "o.pdf"), regions: [{ ...region, reason: "AI_PROPOSAL" }] },
    });
    const reqs = engineRequests();
    console.log(
      `probe_1890_mcp_direct_redact_forwards_ai_proposal_reason: OBSERVED: engine requests=${reqs.length} (calls=${JSON.stringify(engineCalls())}); ` +
        `tool answered isError=${JSON.stringify(direct.isError)}: ${textOf(direct).slice(0, 300)}`,
    );
    for (const r of reqs) {
      console.log(
        `probe_1890_mcp_direct_redact_forwards_ai_proposal_reason: OBSERVED: engine request command=${JSON.stringify(r.command)} ` +
          `regions=${JSON.stringify(r.regions)} decisionChannel=${JSON.stringify(r.decisionChannel)}`,
      );
    }
    assert.deepEqual(reqs, [], "the reserved reason never reaches the engine");
    assert.deepEqual(engineCalls(), []);
    assert.equal(direct.isError, true);
    assert.match(
      textOf(direct),
      /The reason for region 0 uses a word Omitly reserves for what a person decided \(AI_PROPOSAL, MANUAL, OCR_CORRECTED\)\. .*Nothing was redacted\./,
    );
  });
});
