/**
 * omitly#1864, docs/pass-contract.md §8.1 T1, T11, T15, T17 over the MCPB bundle AND the public mirror's overlay copy of its server
 * (mirror-overlay/mcpb/server/index.js, assembled the way scripts/release/mcp-public-mirror.sh does: the bundle's other files with the
 * overlay in place of index.js). Each server is started for real over stdio with the real bundled wasm, and every fixture is copied
 * byte for byte into the file it is asked about (C3: the check's digest is bound to the bytes the server read). The §6.3 text matcher
 * and the §6.1 structured walk run over every text and every structuredContent.
 */
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { cpSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readdirSync, realpathSync, symlinkSync } = require("node:fs");
const { tmpdir } = require("node:os");
const path = require("node:path");

const OMITLY_MCP = path.join(__dirname, "..", "..");
const NODE_MODULES = path.join(OMITLY_MCP, "node_modules");
const WASM = path.join(OMITLY_MCP, "wasm");
const OVERLAY_INDEX = path.join(OMITLY_MCP, "mirror-overlay", "mcpb", "server", "index.js");
const FIXTURES = path.join(OMITLY_MCP, "..", "tests", "fixtures");
const skip = !existsSync(NODE_MODULES) ? "no node_modules (run npm ci)" : !existsSync(path.join(WASM, "leakcheck_wasm.js")) ? "no wasm (run `npm run build:wasm`)" : !existsSync(FIXTURES) ? "no tests/fixtures next to this package" : false;

// ---- the §6.3 matcher and the §6.1 walk: the one shared with the TypeScript tests (../../src/testing/matcher.ts, built to dist/testing) ----------

let matcher;
const loadMatcher = async () => {
  if (matcher) return matcher;
  const built = path.join(OMITLY_MCP, "dist", "testing", "matcher.js");
  assert.ok(existsSync(built), "no dist/testing/matcher.js: run `npx tsc` (npm test builds it first)");
  matcher = await import(require("node:url").pathToFileURL(built).href);
  return matcher;
};

// ---- starting a server ---------------------------------------------------------------------------------------------------------------

/** The bundle server (`variant: "bundle"`) or the mirror's (`"overlay"`: the same files with the overlay's index.js), over stdio. */
async function start(variant, fixtureRel) {
  const { Client } = require("@modelcontextprotocol/sdk/client/index.js");
  const { StdioClientTransport } = require("@modelcontextprotocol/sdk/client/stdio.js");
  const root = realpathSync(mkdtempSync(path.join(tmpdir(), `omitly-mcpb-v02-${variant}-`)));
  const app = path.join(root, "app");
  mkdirSync(path.join(app, "server"), { recursive: true });
  for (const f of readdirSync(__dirname)) if (f.endsWith(".js") && !f.endsWith(".test.js")) copyFileSync(path.join(__dirname, f), path.join(app, "server", f));
  if (variant === "overlay") copyFileSync(OVERLAY_INDEX, path.join(app, "server", "index.js"));
  copyFileSync(path.join(__dirname, "..", "manifest.json"), path.join(app, "manifest.json"));
  cpSync(WASM, path.join(app, "wasm"), { recursive: true });
  symlinkSync(NODE_MODULES, path.join(app, "node_modules"));
  const doc = path.join(root, "doc.pdf");
  copyFileSync(path.join(FIXTURES, "..", "..", fixtureRel), doc);
  const client = new Client({ name: "mcpb-v02", version: "0.0.0" });
  await client.connect(new StdioClientTransport({ command: process.execPath, args: [path.join(app, "server", "index.js")], env: { ...process.env, OMITLY_ALLOWED_DIR: root }, stderr: "ignore" }));
  return {
    call: async (name, args = {}) => {
      const res = await client.callTool({ name, arguments: { pdfPath: doc, ...args } });
      return { res, text: res.content.map((c) => c.text).join("\n") };
    },
    close: () => client.close(),
  };
}

/** The outcome the contract gives each fixture through the bundle's wasm check (T1, T14, T17). */
const FIXTURE_OUTCOMES = [
  ["tests/fixtures/sample.pdf", "needs_review"],
  ["tests/fixtures/covered-text.pdf", "not_a_pass"],
  ["tests/fixtures/invisible-text.pdf", "needs_review"], // T1
  ["tests/fixtures/encrypted-aes256-survivor.pdf", "incomplete"],
  ["tests/fixtures/au-corpus/05-scanned-raster.pdf", "needs_review"],
  ["tests/fixtures/au-corpus/07-incremental-update-prior-revision.pdf", "needs_review"],
  ["tests/fixtures/au-corpus/08-acroform-fields.pdf", "needs_review"],
  ["tests/fixtures/clean-text.pdf", "safe_to_send"], // T17
];

for (const variant of ["bundle", "overlay"]) {
  test(`T1/T11/T15/T17 [${variant}]: every fixture's check_redaction, re-scan and find give the contract's outcome; the matcher and the walk hold`, { skip }, async () => {
    const { matcherHits, passShapedPaths } = await loadMatcher();
    for (const [rel, want] of FIXTURE_OUTCOMES) {
      const s = await start(variant, rel);
      try {
        for (const tool of ["check_redaction", "verify_redaction"]) {
          const { res, text } = await s.call(tool);
          const name = `${variant} ${rel} ${tool}`;
          assert.equal(res.isError, false, `${name}: a completed check\n${text}`);
          assert.equal(res.structuredContent.outcome, want, `${name}\n${text}`);
          assert.deepEqual(matcherHits(text, want), [], `${name}: matcher\n${text}`);
          assert.deepEqual(passShapedPaths(res.structuredContent, want), [], `${name}: a pass-shaped structured value beside ${want}`);
          if (want === "safe_to_send") assert.ok(text.includes("✅ Safe to Send"), `${name}\n${text}`);
          else assert.ok(text.startsWith("⚠️ NOT A PASS — "), `${name}\n${text}`);
        }
        const found = await s.call("find_sensitive_regions");
        assert.equal(found.res.isError, false, `${rel} find`);
        assert.notEqual(found.res.structuredContent.outcome, "safe_to_send", `${variant} ${rel}: a pattern scan is never a pass`);
        assert.deepEqual(matcherHits(found.text, found.res.structuredContent.outcome), [], `${variant} ${rel} find\n${found.text}`);
        assert.deepEqual(passShapedPaths(found.res.structuredContent, found.res.structuredContent.outcome), [], `${variant} ${rel} find`);
      } finally {
        await s.close();
      }
    }
  });
}
