/**
 * omitly#87 — the `check_license` tool.
 *
 * Two things are worth testing here and nothing else is:
 *
 *  1. The tool relays what the engine reported — state, tier, days left,
 *     licensee, and which of LICENSE-RESOLUTION.md §1's three steps supplied
 *     the licence — rather than inventing or flattening it. Licence
 *     RESOLUTION correctness itself is the licensing crate's job and is
 *     covered by its own Rust tests; this file only holds the MCP layer.
 *
 *  2. The device fingerprint never reaches a tool response. That is the
 *     issue's hard requirement, and the reason is specific: `check_license`
 *     is called by an AI agent, so everything it returns lands in a model
 *     transcript, and the fingerprint is a stable machine identifier. Three
 *     independent layers hold that, and the tests below cover each:
 *       - the engine refuses to emit one (`license_report` in
 *         crates/omitly-cli/src/main.rs, with its own Rust tests);
 *       - the handler here builds `structuredContent` field by field, so an
 *         extra key from a chattier engine is DROPPED, not relayed;
 *       - `checkLicenseOutputSchema` is `.strict()`, so if a future edit to
 *         the handler itself added the field, the call fails loudly.
 *
 * Like routing.test.ts, this drives a fresh module instance per scenario —
 * index.ts resolves ENGINE_BIN once at load — and points the "engine" at a
 * scripted stub, so no Rust toolchain is needed.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtempSync, realpathSync, writeFileSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { checked, checkLicenseOutputSchema } from "./index.js";

/** A real-shaped fingerprint: 64 hex chars, exactly what the licensing
 *  crate's `fingerprint()` produces. Must never appear in a tool response. */
const FINGERPRINT = "9f2b7c1d4e6a8b0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4b6c8d0e2f4a6b8c";

const ENV_KEYS = [
  "OMITLY_ALLOWED_DIR",
  "OMITLY_REDACT_BIN",
  "OMITLY_PDF_BIN",
  "OMITLY_ENGINE_DIR",
  "OMITLY_STATE_DIR",
  "OMITLY_FREE_CAP",
] as const;

let counter = 0;

function freshRoot(): string {
  // realpath: macOS $TMPDIR lives under /var, itself a symlink to /private/var.
  return realpathSync(mkdtempSync(path.join(tmpdir(), "omitly-check-license-")));
}

/** Write a stub engine that answers `check_license` with `reply` verbatim. */
function stubEngine(root: string, reply: unknown): string {
  const bin = path.join(root, "stub-engine.mjs");
  writeFileSync(
    bin,
    `#!/usr/bin/env node
import { readFileSync } from "node:fs";
const req = JSON.parse(readFileSync(0, "utf8"));
if (req.command !== "check_license") {
  process.stdout.write(JSON.stringify({ ok: false, error: "unexpected command " + req.command }));
} else {
  process.stdout.write(${JSON.stringify(JSON.stringify(reply))});
}
`,
    { mode: 0o755 },
  );
  chmodSync(bin, 0o755);
  return bin;
}

async function callCheckLicense(reply: unknown): Promise<any> {
  const root = freshRoot();
  const bin = stubEngine(root, reply);
  for (const k of ENV_KEYS) delete process.env[k];
  process.env.OMITLY_ALLOWED_DIR = root;
  process.env.OMITLY_REDACT_BIN = bin;
  counter += 1;
  const mod = (await import(`./index.js?check-license-variant=${counter}`)) as typeof import("./index.js");

  const server = mod.createServer();
  const [serverTransport, clientTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "check-license-test", version: "0.0.0" });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  try {
    return await client.callTool({ name: "check_license", arguments: {} });
  } finally {
    await client.close();
    await server.close();
  }
}

function textOf(res: any): string {
  return (res.content ?? []).filter((c: any) => c.type === "text").map((c: any) => c.text).join("\n");
}

const LICENSED = {
  ok: true,
  state: "licensed",
  tier: "pro",
  daysLeft: null,
  licensedTo: "A Firm <ops@example.com>",
  expiresAt: null,
  resolutionStep: "the activated licence",
  deviceBound: true,
  provenanceAvailable: true,
  renewalNotice: null,
  reason: null,
};

test("relays tier, licensee and which resolution step supplied the licence", async () => {
  const res = await callCheckLicense(LICENSED);
  assert.equal(res.isError, undefined, textOf(res));
  assert.equal(res.structuredContent.state, "licensed");
  assert.equal(res.structuredContent.tier, "pro");
  assert.equal(res.structuredContent.licensedTo, "A Firm <ops@example.com>");
  assert.equal(res.structuredContent.resolutionStep, "the activated licence");
  assert.equal(res.structuredContent.deviceBound, true);
  assert.match(textOf(res), /Licensed/);
  assert.match(textOf(res), /bound to this machine/);
});

test("reports trial days left without inventing a tier", async () => {
  const res = await callCheckLicense({
    ...LICENSED,
    state: "trial",
    tier: null,
    daysLeft: 9,
    licensedTo: null,
    resolutionStep: null,
    deviceBound: false,
  });
  assert.equal(res.structuredContent.state, "trial");
  assert.equal(res.structuredContent.daysLeft, 9);
  assert.equal(res.structuredContent.tier, null);
  assert.match(textOf(res), /9 days left/);
});

test("a dev-key build says its licensed status is not a provenance claim", async () => {
  const res = await callCheckLicense({ ...LICENSED, provenanceAvailable: false });
  assert.equal(res.structuredContent.provenanceAvailable, false);
  assert.match(textOf(res), /cannot make licensed-provenance claims/);
});

test("surfaces the §1 renewal notice rather than silently adopting it", async () => {
  const notice = "newer licence found at the import inbox (~/.omitly/omitly.license) — it is not active";
  const res = await callCheckLicense({ ...LICENSED, renewalNotice: notice });
  assert.equal(res.structuredContent.renewalNotice, notice);
  assert.match(textOf(res), /newer licence found/);
});

test("an engine error is reported, not rendered as an unlicensed state", async () => {
  const res = await callCheckLicense({ ok: false, error: "licence store unreadable" });
  assert.equal(res.isError, true);
  assert.match(textOf(res), /licence store unreadable/);
});

test("NEVER passes a device fingerprint through, even if the engine sends one", async () => {
  // The engine does not do this — its own Rust tests forbid it. This proves
  // the MCP layer does not RELAY it either, which is a separate guarantee:
  // the handler builds `structuredContent` by naming each field explicitly
  // (an allowlist), so an extra key from the engine is dropped rather than
  // copied through. The call therefore SUCCEEDS and is simply fingerprint-free
  // — dropping is the design, not an error path.
  const res = await callCheckLicense({ ...LICENSED, deviceFingerprint: FINGERPRINT });
  const body = JSON.stringify(res);
  assert.ok(
    !body.includes(FINGERPRINT),
    `the fingerprint must not appear anywhere in the tool response: ${body}`,
  );
  assert.equal(res.isError, undefined, "an unexpected engine field is dropped, not fatal");
  assert.equal(res.structuredContent.deviceBound, true, "binding is still reported as a boolean");
  assert.ok(
    !("deviceFingerprint" in res.structuredContent),
    `the key must not survive at all: ${JSON.stringify(res.structuredContent)}`,
  );
});

test("checked() rejects an undeclared field — the guard if a HANDLER ever regresses", () => {
  // The allowlist above protects against a chatty ENGINE. This is the other
  // half: if a future edit to the handler added the fingerprint to the object
  // it builds, `.strict()` must make that a hard failure rather than an extra
  // key in a model transcript.
  assert.throws(
    () =>
      checked(checkLicenseOutputSchema, {
        ...(LICENSED as any),
        ok: undefined,
        deviceFingerprint: FINGERPRINT,
      } as any),
    /unrecognized|unknown|strict/i,
  );
});

test("a licensed response carries no 64-hex-character token at all", async () => {
  const res = await callCheckLicense(LICENSED);
  const body = JSON.stringify(res);
  const hasLongHex = body
    .split(/[^0-9a-fA-F]/)
    .some((tok) => tok.length >= 64);
  assert.ok(!hasLongHex, `no machine-identifier-shaped token may appear: ${body}`);
});
