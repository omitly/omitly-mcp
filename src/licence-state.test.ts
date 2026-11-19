/**
 * omitly#1870: the desktop app's own licence state (`desktop.json` `licence`) as WORDING INPUT for
 * the answer to a removal request, and nothing more.
 *
 * Oracle: the real parser, the real texts, and the real server (a fresh `index.js` per scenario,
 * a real in-memory MCP client, real heartbeat and proposal files in a temp state dir). The only
 * stub is an engine that records whether it was invoked. The safety tests (nothing the field says
 * can unlock, run or write anything) check the filesystem and the engine log, not the text.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { chmodSync, existsSync, mkdtempSync, readFileSync, readdirSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import * as path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

import { PRESENCE_FRESH_MS, parseDesktopLicence, readDesktopPresence, recordAnalysis, sha256OfFile } from "./desktop.js";
import { proposeUnavailableText, queuedText, removalTrialOverText, removalUnavailableText, trialClause } from "./removal.js";

const ENV_KEYS = ["OMITLY_ALLOWED_DIR", "OMITLY_REDACT_BIN", "OMITLY_PDF_BIN", "OMITLY_ENGINE_DIR", "OMITLY_STATE_DIR"] as const;
const LINK = "https://omitly.app/?via=mcp";
let counter = 0;

const freshRoot = (prefix = "omitly-ls-") => realpathSync(mkdtempSync(path.join(tmpdir(), prefix)));
const textOf = (res: any): string =>
  (res.content ?? []).filter((c: any) => c.type === "text").map((c: any) => c.text).join("\n");

const region = { page: 0, x: 1, y: 1, width: 5, height: 5 };
/** omitly#1890: what a scan of `pdf` registers, so a queued proposal can name it (the scan tools have their own tests). */
const aid = (pdf: string) => recordAnalysis(pdf, sha256OfFile(pdf));

// ---- a heartbeat with an arbitrary `licence` value (undefined = the key is absent) ------------

type Beat = { accept: boolean; licence?: unknown; ageMs?: number; extra?: Record<string, unknown> };

function writeBeat(stateDir: string, b: Beat): void {
  const body: Record<string, unknown> = {
    pid: 4242,
    version: "5.6.0",
    accept_in_app: b.accept,
    updated_at: new Date(Date.now() - (b.ageMs ?? 0)).toISOString(),
    ...(b.extra ?? {}),
  };
  if (b.licence !== undefined) body.licence = b.licence;
  writeFileSync(path.join(stateDir, "desktop.json"), JSON.stringify(body));
}

function recordingEngine(root: string): { bin: string; calls: () => string[] } {
  const bin = path.join(root, "stub-engine.mjs");
  const log = path.join(root, "engine-calls.log");
  writeFileSync(
    bin,
    `#!/usr/bin/env node
import { appendFileSync, readFileSync } from "node:fs";
const req = JSON.parse(readFileSync(0, "utf8"));
appendFileSync(${JSON.stringify(log)}, req.command + "\\n");
process.stdout.write(JSON.stringify({ ok: false, error: "stub engine reached" }));
`,
    { mode: 0o755 },
  );
  chmodSync(bin, 0o755);
  return { bin, calls: () => (existsSync(log) ? readFileSync(log, "utf8").trim().split("\n").filter(Boolean) : []) };
}

type Ctx = { root: string; stateDir: string; pdf: string; out: string; engineCalls: () => string[]; proposals: () => string[] };

async function run<T>(beat: Beat | null, engine: boolean, fn: (client: Client, ctx: Ctx) => Promise<T>): Promise<T> {
  const root = freshRoot();
  const stateDir = freshRoot("omitly-ls-state-");
  const pdf = path.join(root, "in.pdf");
  writeFileSync(pdf, "%PDF-1.4 stub");
  if (beat) writeBeat(stateDir, beat);
  for (const k of ENV_KEYS) delete process.env[k];
  process.env.OMITLY_ALLOWED_DIR = root;
  process.env.OMITLY_STATE_DIR = stateDir;
  const stub = recordingEngine(root);
  if (engine) process.env.OMITLY_REDACT_BIN = stub.bin;
  counter += 1;
  const mod = (await import(`./index.js?licence-state=${counter}`)) as typeof import("./index.js");
  const server = mod.createServer();
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "Claude Desktop", version: "1.4.2" });
  await Promise.all([server.connect(a), client.connect(b)]);
  try {
    return await fn(client, {
      root,
      stateDir,
      pdf,
      out: path.join(root, "o.pdf"),
      engineCalls: stub.calls,
      proposals: () => (existsSync(path.join(stateDir, "proposals")) ? readdirSync(path.join(stateDir, "proposals")) : []),
    });
  } finally {
    await client.close();
    await server.close();
  }
}

const removalCalls = (c: Ctx): [string, Record<string, unknown>][] => [
  ["redact_pdf", { pdfPath: c.pdf, outputPath: c.out, regions: [region], analysisId: aid(c.pdf) }],
  ["redact_by_entity", { pdfPath: c.pdf, outputPath: c.out }],
  ["propose_redactions", { pdfPath: c.pdf, outputPath: c.out, regions: [region], analysisId: aid(c.pdf) }],
];

// ================================================================================================
// The parser
// ================================================================================================

test("parseDesktopLicence: the four known states, with whole trial days", () => {
  assert.deepEqual(parseDesktopLicence({ state: "trial", days_left: 5 }), { state: "trial", daysLeft: 5 });
  assert.deepEqual(parseDesktopLicence({ state: "trial", days_left: 1 }), { state: "trial", daysLeft: 1 });
  assert.deepEqual(parseDesktopLicence({ state: "trial", days_left: 14 }), { state: "trial", daysLeft: 14 });
  assert.deepEqual(parseDesktopLicence({ state: "trial_over" }), { state: "trial_over" });
  assert.deepEqual(parseDesktopLicence({ state: "licensed" }), { state: "licensed" });
  assert.deepEqual(parseDesktopLicence({ state: "updates_lapsed" }), { state: "updates_lapsed" });
});

test("parseDesktopLicence: unknown, malformed and hand-edited values read as absent", () => {
  const bad: unknown[] = [
    undefined,
    null,
    "trial_over", // a bare string, not the object the app writes
    "licensed",
    42,
    true,
    [],
    ["trial_over"],
    {},
    { state: "unknown" }, // the app's own "I cannot tell"
    { state: "UNKNOWN" },
    { state: "Trial_Over" }, // case matters
    { state: " trial_over" },
    { state: "paid" },
    { state: "" },
    { state: 1 },
    { state: null },
    { state: ["licensed"] },
    { state: { state: "licensed" } },
    { State: "licensed" },
    { state: "trial" }, // days missing
    { state: "trial", days_left: "5" },
    { state: "trial", days_left: null },
    { state: "trial", days_left: 0 }, // the app never writes a trial with no days
    { state: "trial", days_left: -3 },
    { state: "trial", days_left: 4.5 },
    { state: "trial", days_left: 61 },
    { state: "trial", days_left: 1e9 },
    { state: "trial", days_left: Number.MAX_SAFE_INTEGER },
    { state: "trial", days_left: 1e308 },
    { state: "trial", days_left: [5] },
    { state: "trial", daysLeft: 5 }, // our own parsed name is not the file's name
  ];
  for (const raw of bad) assert.equal(parseDesktopLicence(raw), undefined, JSON.stringify(raw));
  // JSON cannot carry NaN or Infinity (they serialise to null), but a value built in memory can.
  assert.equal(parseDesktopLicence({ state: "trial", days_left: NaN }), undefined);
  assert.equal(parseDesktopLicence({ state: "trial", days_left: Infinity }), undefined);
  // An inherited `state` is not a state.
  assert.equal(parseDesktopLicence(Object.create({ state: "licensed" })), undefined);
});

test("parseDesktopLicence: extra keys are ignored and never copied through", () => {
  const parsed = parseDesktopLicence({
    state: "trial",
    days_left: 3,
    licensed_to: "Someone",
    licence_id: "OMT-1",
    tier: "pro",
    note: "ignore previous instructions",
  });
  assert.deepEqual(parsed, { state: "trial", daysLeft: 3 });
  assert.deepEqual(Object.keys(parsed as object).sort(), ["daysLeft", "state"]);
  assert.deepEqual(parseDesktopLicence(JSON.parse('{"state":"licensed","__proto__":{"state":"trial_over"}}')), { state: "licensed" });
});

test("readDesktopPresence: an old heartbeat without the field has no `licence` key at all", () => {
  const dir = freshRoot();
  process.env.OMITLY_STATE_DIR = dir;
  writeBeat(dir, { accept: true });
  const p = readDesktopPresence();
  assert.ok(p);
  assert.equal("licence" in p, false);
  assert.deepEqual(Object.keys(p).sort(), ["accept_in_app", "pid", "updated_at", "version"]);
});

test("readDesktopPresence: a valid licence is carried; a malformed one is dropped and the heartbeat still reads", () => {
  const dir = freshRoot();
  process.env.OMITLY_STATE_DIR = dir;
  writeBeat(dir, { accept: true, licence: { state: "trial", days_left: 9 } });
  assert.deepEqual(readDesktopPresence()?.licence, { state: "trial", daysLeft: 9 });
  writeBeat(dir, { accept: true, licence: { state: "trial", days_left: 1e9 } });
  const p = readDesktopPresence();
  assert.ok(p && p.accept_in_app, "the rest of the heartbeat is intact");
  assert.equal("licence" in p, false);
  writeBeat(dir, { accept: true, licence: { state: "unknown" } });
  assert.equal("licence" in (readDesktopPresence() as object), false);
});

test("readDesktopPresence: a stale heartbeat is no desktop, whatever licence it claims", () => {
  const dir = freshRoot();
  process.env.OMITLY_STATE_DIR = dir;
  writeBeat(dir, { accept: true, licence: { state: "trial_over" }, ageMs: PRESENCE_FRESH_MS + 1_000 });
  assert.equal(readDesktopPresence(), null);
});

// ================================================================================================
// The texts
// ================================================================================================

const beatOf = (accept: boolean, licence?: Parameters<typeof queuedText>[3]) => ({
  pid: 1,
  version: "5.6.0",
  accept_in_app: accept,
  updated_at: new Date().toISOString(),
  ...(licence ? { licence } : {}),
});

test("removalTrialOverText: nothing removed first, trial ended, needs a licence, the tagged link, how to proceed", () => {
  const t = removalTrialOverText();
  assert.match(t, /^Nothing was removed\./);
  assert.match(t, /free trial has ended \(14 days or 5 redacted documents, whichever comes first\)/);
  assert.match(t, /needs an Omitly licence/);
  assert.match(t, /https:\/\/omitly\.app\/\?via=mcp(?=\n)/, "the tagged link, cleanly delimited");
  assert.match(t, /About Omitly → Licence/);
  assert.match(t, /ask again\.$/);
  assert.equal(t.split(LINK).length, 2, "exactly one link");
  assert.doesNotMatch(t, /\$|A\d|price|AUD/, "no price is hard-coded");
});

test("removalUnavailableText: trial over wins over the switch being off or on; every other licence state is today's text", () => {
  const over = { state: "trial_over" } as const;
  assert.equal(removalUnavailableText(beatOf(false, over)), removalTrialOverText());
  assert.equal(removalUnavailableText(beatOf(true, over)), removalTrialOverText());
  for (const lic of [undefined, { state: "licensed" } as const, { state: "updates_lapsed" } as const, { state: "trial", daysLeft: 4 } as const]) {
    assert.equal(removalUnavailableText(beatOf(false, lic)), removalUnavailableText(beatOf(false)), JSON.stringify(lic));
    assert.equal(removalUnavailableText(beatOf(true, lic)), removalUnavailableText(beatOf(true)), JSON.stringify(lic));
  }
  assert.ok(!removalUnavailableText(beatOf(false)).includes("omitly.app"));
});

test("proposeUnavailableText: trial over, with or without an engine; an engine with the switch off keeps its own direct-write text", () => {
  const over = { state: "trial_over" } as const;
  assert.equal(proposeUnavailableText(beatOf(true, over), false), removalTrialOverText());
  assert.equal(proposeUnavailableText(beatOf(true, over), true), removalTrialOverText());
  assert.equal(proposeUnavailableText(beatOf(false, over), false), removalTrialOverText());
  assert.equal(proposeUnavailableText(beatOf(false, over), true), proposeUnavailableText(beatOf(false), true), "the engine's own direct write, unchanged");
  assert.equal(proposeUnavailableText(null, false), proposeUnavailableText(null, false));
});

test("trialClause: one short factual clause in trial only, no link, singular for one day", () => {
  assert.equal(trialClause({ state: "trial", daysLeft: 5 }), " Omitly is in its free trial, 5 days left; the trial also ends after 5 redacted documents.");
  assert.equal(trialClause({ state: "trial", daysLeft: 1 }), " Omitly is in its free trial, 1 day left; the trial also ends after 5 redacted documents.");
  for (const lic of [undefined, { state: "licensed" } as const, { state: "updates_lapsed" } as const, { state: "trial_over" } as const]) {
    assert.equal(trialClause(lic), "", JSON.stringify(lic));
  }
  assert.ok(!trialClause({ state: "trial", daysLeft: 5 }).includes("omitly.app"));
});

// ================================================================================================
// Through the real server
// ================================================================================================

test("trial over, app running (switch on), no engine: every removal tool says so, with the link, and queues nothing", async () => {
  await run({ accept: true, licence: { state: "trial_over" } }, false, async (client, c) => {
    for (const [name, args] of removalCalls(c)) {
      const res: any = await client.callTool({ name, arguments: args });
      assert.equal(res.isError, true, `${name}: nothing was removed, so not a success`);
      assert.equal(textOf(res), removalTrialOverText(), name);
      assert.ok(textOf(res).includes(LINK), `${name}: the tagged link`);
    }
    assert.deepEqual(c.proposals(), [], "no proposal is stranded");
    assert.deepEqual(c.engineCalls(), []);
    assert.equal(existsSync(c.out), false, "nothing written");
  });
});

test("trial over, app running (switch on), engine configured: the same answer; the engine is NOT used as a way round the app", async () => {
  await run({ accept: true, licence: { state: "trial_over" } }, true, async (client, c) => {
    for (const [name, args] of removalCalls(c)) {
      const res: any = await client.callTool({ name, arguments: args });
      assert.equal(res.isError, true, name);
      assert.equal(textOf(res), removalTrialOverText(), name);
    }
    assert.deepEqual(c.proposals(), []);
    assert.deepEqual(c.engineCalls(), [], "no direct write while the person's accept-in-app is on");
    assert.equal(existsSync(c.out), false);
  });
});

test("trial over, app running, switch OFF, no engine: the trial answer, not 'turn the switch on' (that would only reach the same refusal)", async () => {
  await run({ accept: false, licence: { state: "trial_over" } }, false, async (client, c) => {
    for (const [name, args] of removalCalls(c)) {
      const res: any = await client.callTool({ name, arguments: args });
      assert.equal(res.isError, true, name);
      assert.equal(textOf(res), removalTrialOverText(), name);
    }
    assert.deepEqual(c.proposals(), []);
    assert.deepEqual(c.engineCalls(), []);
  });
});

test("trial over, app running, switch OFF, engine configured: today's direct write through the engine, unchanged (the engine enforces its own licence)", async () => {
  await run({ accept: false, licence: { state: "trial_over" } }, true, async (client, c) => {
    const direct: any = await client.callTool({ name: "redact_pdf", arguments: { pdfPath: c.pdf, outputPath: c.out, regions: [region], analysisId: aid(c.pdf) } });
    assert.deepEqual(c.engineCalls(), ["redact"], "the configured engine is reached exactly as without the field");
    assert.doesNotMatch(textOf(direct), /free trial has ended/);
    const prop: any = await client.callTool({ name: "propose_redactions", arguments: { pdfPath: c.pdf, outputPath: c.out, regions: [region], analysisId: aid(c.pdf) } });
    assert.match(textOf(prop), /call redact_pdf: this server has an engine configured/);
    assert.doesNotMatch(textOf(prop), /free trial has ended/);
  });
});

test("a stale trial_over heartbeat is no desktop: the no-app answer, not the trial answer", async () => {
  await run({ accept: true, licence: { state: "trial_over" }, ageMs: PRESENCE_FRESH_MS + 5_000 }, false, async (client, c) => {
    const res: any = await client.callTool({ name: "redact_pdf", arguments: { pdfPath: c.pdf, outputPath: c.out, regions: [region], analysisId: aid(c.pdf) } });
    assert.match(textOf(res), /it is not running/);
    assert.doesNotMatch(textOf(res), /free trial has ended/);
  });
});

test("in trial: the queued text (and only the queued text) gains one factual clause; no link; the proposal file is unchanged", async () => {
  await run({ accept: true, licence: { state: "trial", days_left: 5 } }, false, async (client, c) => {
    const pdfRes: any = await client.callTool({ name: "redact_pdf", arguments: { pdfPath: c.pdf, outputPath: c.out, regions: [region], analysisId: aid(c.pdf) } });
    assert.ok(!pdfRes.isError, textOf(pdfRes));
    assert.equal(pdfRes.structuredContent.status, "queued");
    const t = textOf(pdfRes);
    assert.ok(t.endsWith(" Omitly is in its free trial, 5 days left; the trial also ends after 5 redacted documents."), t);
    assert.ok(!t.includes("omitly.app") && !t.includes("via=mcp"), "no link while the trial runs");

    const entRes: any = await client.callTool({ name: "redact_by_entity", arguments: { pdfPath: c.pdf, outputPath: c.out, kinds: ["email"] } });
    assert.ok(textOf(entRes).endsWith(" Omitly is in its free trial, 5 days left; the trial also ends after 5 redacted documents."), textOf(entRes));
    assert.ok(!textOf(entRes).includes("omitly.app"));

    const prop: any = await client.callTool({ name: "propose_redactions", arguments: { pdfPath: c.pdf, outputPath: c.out, regions: [region], analysisId: aid(c.pdf) } });
    assert.equal(prop.structuredContent.status, "queued");
    assert.ok(textOf(prop).endsWith(" Omitly is in its free trial, 5 days left; the trial also ends after 5 redacted documents."), textOf(prop));
    assert.ok(!textOf(prop).includes("omitly.app"));

    // The structured note and the stored proposals carry no licence word.
    assert.doesNotMatch(JSON.stringify(pdfRes.structuredContent), /trial|licen/i);
    const files = c.proposals();
    assert.equal(files.length, 3);
    for (const f of files) {
      const raw = readFileSync(path.join(c.stateDir, "proposals", f), "utf8");
      assert.doesNotMatch(raw, /trial|licen/i, "a proposal file records no licence state");
    }

    // get_proposal_status is not a removal request: no clause, no link.
    const st: any = await client.callTool({ name: "get_proposal_status", arguments: { proposalId: pdfRes.structuredContent.proposalId } });
    assert.doesNotMatch(textOf(st), /trial|omitly\.app/i);
    assert.deepEqual(c.engineCalls(), []);
  });
});

test("in trial, one day left: '1 day left'", async () => {
  await run({ accept: true, licence: { state: "trial", days_left: 1 } }, false, async (client, c) => {
    const res: any = await client.callTool({ name: "redact_pdf", arguments: { pdfPath: c.pdf, outputPath: c.out, regions: [region], analysisId: aid(c.pdf) } });
    assert.ok(textOf(res).endsWith(" Omitly is in its free trial, 1 day left; the trial also ends after 5 redacted documents."), textOf(res));
  });
});

/** The queued text with the id and path made comparable across scenarios. */
const normalised = (res: any, c: Ctx): string =>
  textOf(res).split(res.structuredContent.proposalId).join("<ID>").split(c.pdf).join("<PDF>");

test("licensed, updates lapsed, absent, unknown and malformed: the queued text is exactly what an old app gets, byte for byte", async () => {
  const states: [string, unknown][] = [
    ["absent", undefined],
    ["licensed", { state: "licensed" }],
    ["updates_lapsed", { state: "updates_lapsed" }],
    ["unknown", { state: "unknown" }],
    ["unrecognised string", "licensed"],
    ["wrong type", 7],
    ["huge days", { state: "trial", days_left: 1e9 }],
    ["negative days", { state: "trial", days_left: -2 }],
    ["extra keys", { state: "licensed", licensed_to: "X", tier: "pro" }],
    ["array", ["trial_over"]],
  ];
  const seen = new Map<string, string>();
  for (const [label, licence] of states) {
    await run({ accept: true, licence }, false, async (client, c) => {
      for (const [name, args] of removalCalls(c).slice(0, 2)) {
        const res: any = await client.callTool({ name, arguments: args });
        assert.ok(!res.isError, `${label}/${name}: ${textOf(res)}`);
        const t = normalised(res, c);
        assert.ok(!t.includes("omitly.app") && !/trial/i.test(t.replace(/<PDF>/g, "")), `${label}/${name}: no licence wording, no link: ${t}`);
        const prior = seen.get(name);
        if (prior === undefined) seen.set(name, t);
        else assert.equal(t, prior, `${label}/${name} differs from the absent-field text`);
      }
    });
  }
  // The absent-field text is the 5.5.0 literal, pinned independently of removal.ts.
  assert.equal(
    seen.get("redact_pdf"),
    'Proposal <ID> queued in Omitly for redact_pdf on <PDF>. Nothing has been written: a person must accept it in the Omitly desktop app, which then removes, verifies and seals (the record will show a person decided). Call get_proposal_status with proposalId "<ID>" to follow it.',
  );
});

test("licensed or updates lapsed with the switch off and no engine: today's switch-off text, no link", async () => {
  for (const state of ["licensed", "updates_lapsed"]) {
    await run({ accept: false, licence: { state } }, false, async (client, c) => {
      for (const [name, args] of removalCalls(c)) {
        const res: any = await client.callTool({ name, arguments: args });
        assert.equal(res.isError, true, name);
        assert.equal(textOf(res), removalUnavailableText(beatOf(false)), `${state}/${name}`);
        assert.ok(!textOf(res).includes("omitly.app"));
      }
    });
  }
});

// ================================================================================================
// The field cannot unlock anything
// ================================================================================================

test("the field claiming 'licensed' with no engine: removal still does not happen (no engine run, no output, nothing queued while the switch is off)", async () => {
  await run({ accept: false, licence: { state: "licensed", tier: "pro", licensed_to: "X", enabled: true, engine: "/bin/sh" } }, false, async (client, c) => {
    for (const [name, args] of removalCalls(c)) {
      const res: any = await client.callTool({ name, arguments: args });
      assert.equal(res.isError, true, name);
      assert.match(textOf(res), /^Nothing was removed\./, name);
    }
    assert.equal(existsSync(c.out), false, "no output written");
    assert.deepEqual(c.engineCalls(), []);
    assert.deepEqual(c.proposals(), []);
  });
  // And with the switch on it can only queue for a person, exactly as with no field: nothing is written.
  await run({ accept: true, licence: { state: "licensed" } }, false, async (client, c) => {
    for (const [name, args] of removalCalls(c).slice(0, 2)) {
      const res: any = await client.callTool({ name, arguments: args });
      assert.equal(res.structuredContent.status, "queued", name);
    }
    assert.equal(existsSync(c.out), false, "a queued proposal writes no PDF");
    assert.deepEqual(c.engineCalls(), []);
  });
});

test("the field claiming 'licensed' with an engine configured and the switch on: still queued for a person, the engine is not run", async () => {
  for (const state of ["licensed", "updates_lapsed"]) {
    await run({ accept: true, licence: { state } }, true, async (client, c) => {
      for (const [name, args] of removalCalls(c).slice(0, 2)) {
        const res: any = await client.callTool({ name, arguments: args });
        assert.equal(res.structuredContent.status, "queued", `${state}/${name}`);
      }
      assert.deepEqual(c.engineCalls(), [], `${state}: the field is not a way round the person's accept-in-app`);
      assert.equal(existsSync(c.out), false);
    });
  }
});

test("the field cannot make an engine-less server verify, write or enable anything: the seal tools and check_license stay engine-only", async () => {
  await run({ accept: true, licence: { state: "licensed" } }, false, async (client, c) => {
    for (const name of ["verify_seal", "verify_document", "check_license"]) {
      const res: any = await client.callTool({ name, arguments: name === "check_license" ? {} : { pdfPath: c.pdf } });
      assert.equal(res.isError, true, name);
      assert.match(textOf(res), /needs the pipeline engine/, name);
      assert.doesNotMatch(textOf(res), /licensed|valid|verified/i, `${name}: no licence verdict from the field`);
    }
  });
});

test("the link and the trial wording appear only in answers to a removal request: scan, verify, status and engine-only answers carry neither", async () => {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const sample = [path.join(here, "..", "tests", "fixtures", "sample.pdf"), path.join(here, "..", "..", "tests", "fixtures", "sample.pdf")].find((p) => existsSync(p));
  assert.ok(sample);
  for (const licence of [{ state: "trial_over" }, { state: "trial", days_left: 3 }, { state: "licensed" }, { state: "updates_lapsed" }]) {
    await run({ accept: true, licence }, false, async (client, c) => {
      const doc = path.join(c.root, "sample.pdf");
      writeFileSync(doc, readFileSync(sample));
      const calls: [string, Record<string, unknown>][] = [
        ["check_redaction", { pdfPath: doc }],
        ["find_sensitive_regions", { pdfPath: doc }],
        ["verify_redaction", { pdfPath: doc }],
        ["verify_seal", { pdfPath: doc }],
        ["verify_document", { pdfPath: doc }],
        ["check_license", {}],
        ["get_proposal_status", { proposalId: "0".repeat(24) }],
      ];
      for (const [name, args] of calls) {
        const res: any = await client.callTool({ name, arguments: args });
        const t = textOf(res) + JSON.stringify(res.structuredContent ?? {});
        assert.ok(!t.includes("omitly.app") && !t.includes("via=mcp"), `${licence.state}/${name}: no link: ${t.slice(0, 200)}`);
        assert.doesNotMatch(t, /trial has ended|trial, \d+ days? left|needs an Omitly licence/, `${licence.state}/${name}: no licence-state wording`);
      }
    });
  }
});

test("the skill text (and its plugin copy) says nothing about licence state or the new field", () => {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  for (const rel of ["skill/SKILL.md", "plugin/skills/omitly-redaction/SKILL.md"]) {
    const text = readFileSync(path.join(root, ...rel.split("/")), "utf8");
    assert.doesNotMatch(text, /trial has ended|trial_over|days left|updates_lapsed|licence field|heartbeat/i, rel);
  }
});
