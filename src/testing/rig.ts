/**
 * The conformance rig shared by pass-contract-v02.test.ts and pass-contract-v021.test.ts: a server over an in-memory client, the doc holding a
 * fixture's REAL bytes (contract C3), and, in `stub` mode, a scripted native engine that binds a scripted check to the doc's digest.
 */
import { createHash } from "node:crypto";
import { chmodSync, copyFileSync, existsSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

const HERE = path.dirname(fileURLToPath(import.meta.url)); // dist/testing
export const PKG = path.join(HERE, "..", "..");
export const WORKSPACE = path.join(PKG, "..");
export const native: any = JSON.parse(readFileSync(path.join(PKG, "src", "testing", "goldens", "native.json"), "utf8"));
export const wasmGold: any = JSON.parse(readFileSync(path.join(PKG, "src", "testing", "goldens", "wasm.json"), "utf8"));
export const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v));
export const sha256Hex = (b: Buffer) => createHash("sha256").update(b).digest("hex");

const EXE = process.platform === "win32" ? ".exe" : "";
export const ENGINE =
  process.env.OMITLY_TEST_REDACT_BIN ??
  [path.join(WORKSPACE, "target", "debug", `omitly-redact${EXE}`), path.join(WORKSPACE, "target", "release", `omitly-redact${EXE}`)].find((p) => existsSync(p));
export const IN_WORKSPACE = existsSync(path.join(WORKSPACE, "Cargo.toml"));
// Outside the Cargo workspace (the public mirror) there is no engine to build; inside it, under CI, a missing binary FAILS.
export const skipReal = !ENGINE && !(IN_WORKSPACE && process.env.CI) ? "no omitly-redact build (run `cargo build -p omitly-cli`)" : false;
export const skipFixtures = existsSync(path.join(WORKSPACE, "tests", "fixtures")) ? false : "no tests/fixtures next to this package";

export const ENV_KEYS = ["OMITLY_ALLOWED_DIR", "OMITLY_REDACT_BIN", "OMITLY_PDF_BIN", "OMITLY_ENGINE_DIR", "OMITLY_STATE_DIR", "OMITLY_DATA_DIR"] as const;
let counter = 0;
export const textOf = (res: any) => (res.content ?? []).filter((c: any) => c.type === "text").map((c: any) => c.text).join("\n");

export type Mode = "stub" | "wasm" | "real";

/** A rig: a server over an in-memory client, the doc holding the fixture's REAL bytes, and (stub mode) a scripted native engine. */
export async function rig(mode: Mode, fixtureRel: string | null, opts: { bytes?: Buffer; docName?: string } = {}) {
  const root = realpathSync(mkdtempSync(path.join(tmpdir(), "omitly-v02-")));
  for (const k of ENV_KEYS) delete process.env[k];
  process.env.OMITLY_ALLOWED_DIR = root;
  process.env.OMITLY_STATE_DIR = path.join(root, "state");
  process.env.OMITLY_DATA_DIR = path.join(root, "data");
  const cfgPath = path.join(root, "config.json");
  if (mode === "stub") {
    const bin = path.join(root, "stub-engine.mjs");
    writeFileSync(
      bin,
      `#!/usr/bin/env node
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
const req = JSON.parse(readFileSync(0, "utf8"));
const cfg = JSON.parse(readFileSync(${JSON.stringify(cfgPath)}, "utf8"));
const sent = cfg[req.command] ?? { ok: false, error: "no scripted reply for " + req.command };
if (req.command === "check" && !cfg.noBind && typeof sent?.check?.result?.sha256 === "string" && sent.check.result.sha256.length === 64) {
  sent.check.result.sha256 = createHash("sha256").update(readFileSync(req.pdfPath)).digest("hex");
}
process.stdout.write(JSON.stringify(sent));
`,
      { mode: 0o755 },
    );
    chmodSync(bin, 0o755);
    process.env.OMITLY_REDACT_BIN = bin;
  } else if (mode === "real") {
    process.env.OMITLY_REDACT_BIN = ENGINE!;
  }
  const doc = path.join(root, opts.docName ?? "doc.pdf");
  if (opts.bytes) writeFileSync(doc, opts.bytes);
  else if (fixtureRel) copyFileSync(path.join(WORKSPACE, fixtureRel), doc);
  else writeFileSync(doc, "%PDF-1.4\n% not parsed: the engine is scripted\n");
  counter += 1;
  const mod = (await import(`../index.js?rig=${counter}`)) as typeof import("../index.js");
  const server = mod.createServer();
  const client = new Client({ name: "t", version: "0" });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(a), client.connect(b)]);
  return {
    root,
    doc,
    script: (cfg: Record<string, unknown>) => writeFileSync(cfgPath, JSON.stringify(cfg)),
    sidecar: () => writeFileSync(`${doc}.audit.json`, "[]"),
    call: (name: string, args: Record<string, unknown> = {}): Promise<any> => client.callTool({ name, arguments: { pdfPath: doc, ...args } }),
    close: async () => {
      await client.close();
      await server.close();
    },
  };
}

// ---- the §6.3 matcher and the §6.1 structured walk ------------------------------------------------------------------------------------------
