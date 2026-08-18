/**
 * omitly#193: routing-matrix tests for the native-vs-wasm engine selection
 * introduced by PR #192 — `findViaEngineOrWasm` (find_sensitive_regions,
 * check_redaction), `locate_text`'s own inline `ENGINE_BIN ? ... : ...`
 * branch, `verify_redaction`'s three branches (native+sidecar → native
 * "verify"; native+no sidecar → native "find" fallback; no native → wasm
 * scan), and the three write/generate tools (redact_pdf, redact_by_entity,
 * create_pdf), which always require a configured native engine and have no
 * wasm code path at all. See index.ts's module doc (the "WASM fallback"
 * block near the top) and engine-config.ts.
 *
 * `index.ts` resolves ENGINE_BIN / PDF_BIN / ROOT from `process.env` ONCE at
 * module load (leak-canary.test.ts and free-cap.test.ts each rely on exactly
 * this, and say so in their own top-of-file comments) — so proving BOTH
 * "native configured" and "no native configured" routing in a single file
 * needs a FRESH module instance per configuration, not the one process-wide
 * import those two files use. `importFresh()` below re-imports "./index.js"
 * with a unique query-string suffix per call: Node's ESM loader caches
 * modules by the full specifier including any query string, so a new suffix
 * forces a brand-new top-level evaluation — and therefore a fresh
 * ENGINE_BIN/PDF_BIN/ROOT resolution — against whatever env is set
 * immediately beforehand, all inside one process (no subprocess-per-scenario
 * needed the way bin-entry.test.ts drives the built bin).
 *
 * The "native engine" is `testing/routing-stub.mjs` — a stand-in that
 * ignores the input document entirely and always answers with a fixed,
 * unmistakable marker (kind "native-stub-marker", preview "•NATIVE•"), so a
 * response carrying that marker can only have come from the native path.
 * Every native-configured test below feeds the SAME real-PDF fixture this
 * repo already uses (`tests/fixtures/sample.pdf`, real SSN/email/card PII) so
 * the contrast is direct: the bundled wasm engine's real detector, run
 * against that exact file, reports the actual PII it contains (kinds
 * ssn/email/card, count 3 — verified directly against the built wasm module
 * while writing this test, see the `find`/`locate` probes below) and never
 * emits the marker; the stub emits only the marker and never the real
 * findings. Every stub invocation is also appended to a JSONL log
 * (OMITLY_ROUTING_STUB_LOG) as independent evidence of exactly which command
 * reached the native engine and how many times — belt and braces alongside
 * the content check.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROUTING_STUB = path.join(HERE, "..", "src", "testing", "routing-stub.mjs");
// Resolved from candidates rather than a single relative path, because this
// package is developed inside a larger workspace (where the fixture sits at the
// workspace root) and also published as a standalone repository (where it sits
// at this package's own root). Trying both keeps ONE source of truth for the
// test across both layouts — the alternative was a path rewritten at mirror
// time, which is exactly the kind of silent divergence that makes a mirror
// untrustworthy.
const FIXTURE_CANDIDATES = [
  path.join(HERE, "..", "tests", "fixtures", "sample.pdf"), // standalone repo
  path.join(HERE, "..", "..", "tests", "fixtures", "sample.pdf"), // workspace root
];
const FIXTURE_PDF =
  FIXTURE_CANDIDATES.find((p) => existsSync(p)) ??
  // Fail loudly rather than falling back to a path that does not exist: a
  // missing fixture must surface as "the fixture is missing", not as a
  // confusing ENOENT from deep inside a helper.
  (() => {
    throw new Error(
      `sample.pdf fixture not found. Looked in:\n  ${FIXTURE_CANDIDATES.join("\n  ")}`,
    );
  })();

// Real PII this repo's own sample.pdf fixture is known to contain — see the
// module doc. Kept as named constants so every assertion below reads as "the
// real detector found the real thing" rather than a magic string.
const REAL_EMAIL = "jane.doe@example.com";
const REAL_SSN = "123-45-6789";
const REAL_KINDS = ["card", "email", "ssn"];

/** realpath because macOS's $TMPDIR sits under /var, itself a symlink to
 *  /private/var — the server compares realpaths, so an unresolved root would
 *  make every confinement check spuriously fail. */
function freshRoot(prefix: string): string {
  return realpathSync(mkdtempSync(path.join(tmpdir(), prefix)));
}

function copyFixturePdf(root: string, name = "sample.pdf"): string {
  const dest = path.join(root, name);
  writeFileSync(dest, readFileSync(FIXTURE_PDF));
  return dest;
}

function readStubLog(logPath: string): { command: string }[] {
  if (!existsSync(logPath)) return [];
  return readFileSync(logPath, "utf8")
    .split("\n")
    .filter(Boolean)
    .map((l) => JSON.parse(l));
}

const ENGINE_ENV_KEYS = [
  "OMITLY_ALLOWED_DIR",
  "OMITLY_REDACT_BIN",
  "OMITLY_PDF_BIN",
  "OMITLY_ENGINE_DIR",
  "OMITLY_STATE_DIR",
  "OMITLY_FREE_CAP",
  "OMITLY_ROUTING_STUB_LOG",
] as const;

let importCounter = 0;
/**
 * Re-import index.ts as a brand-new module instance (see file doc) after
 * resetting every env var it reads at load time and applying `env` on top.
 * Anything in ENGINE_ENV_KEYS not present in `env` is deliberately cleared,
 * so ambient state from an earlier test in this same file (or the shell)
 * can never leak into the next scenario.
 */
async function importFresh(env: Partial<Record<(typeof ENGINE_ENV_KEYS)[number], string>>) {
  for (const key of ENGINE_ENV_KEYS) delete process.env[key];
  for (const [k, v] of Object.entries(env)) process.env[k] = v;
  importCounter += 1;
  const specifier = "./index.js?routing-test-variant=" + importCounter;
  return (await import(specifier)) as typeof import("./index.js");
}

function nativeEnv(root: string, logPath: string) {
  return {
    OMITLY_ALLOWED_DIR: root,
    OMITLY_REDACT_BIN: ROUTING_STUB,
    OMITLY_PDF_BIN: ROUTING_STUB,
    OMITLY_ROUTING_STUB_LOG: logPath,
  } as const;
}

function wasmOnlyEnv(root: string) {
  return {
    OMITLY_ALLOWED_DIR: root,
    OMITLY_STATE_DIR: path.join(root, "state"),
    // Generous cap: these tests are about routing/results, not the meter.
    OMITLY_FREE_CAP: "1000",
  } as const;
}

async function withClient<T>(
  createServer: () => import("@modelcontextprotocol/sdk/server/mcp.js").McpServer,
  fn: (client: InstanceType<typeof Client>) => Promise<T>,
): Promise<T> {
  const server = createServer();
  const [serverTransport, clientTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "routing-test", version: "0.0.0" });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  try {
    return await fn(client);
  } finally {
    await client.close();
    await server.close();
  }
}

function textOf(res: any): string {
  return (res.content ?? [])
    .filter((c: any) => c.type === "text")
    .map((c: any) => c.text)
    .join("\n");
}

// ---------------------------------------------------------------------------
// 1. Native engine configured — each of the 4 read tools routes to native.
// ---------------------------------------------------------------------------

test("[native] find_sensitive_regions routes to the native engine, not wasm", async () => {
  const root = freshRoot("omitly-routing-native-find-");
  const logPath = path.join(root, "stub.log");
  const doc = copyFixturePdf(root);
  const { createServer } = await importFresh(nativeEnv(root, logPath));
  await withClient(createServer, async (client) => {
    const res: any = await client.callTool({ name: "find_sensitive_regions", arguments: { pdfPath: doc } });
    assert.equal(res.isError, undefined);
    assert.equal(res.structuredContent.count, 1, "must be the stub's marker count, not wasm's real 3");
    assert.equal(res.structuredContent.regions[0].kind, "native-stub-marker");
    assert.equal(res.structuredContent.evaluation, undefined, "a native-engine result is never EVALUATION-marked");
  });
  const log = readStubLog(logPath);
  assert.equal(log.length, 1);
  assert.equal(log[0].command, "find");
});

test("[native] locate_text routes to the native engine, not wasm", async () => {
  const root = freshRoot("omitly-routing-native-locate-");
  const logPath = path.join(root, "stub.log");
  const doc = copyFixturePdf(root);
  const { createServer } = await importFresh(nativeEnv(root, logPath));
  await withClient(createServer, async (client) => {
    const res: any = await client.callTool({
      name: "locate_text",
      arguments: { pdfPath: doc, texts: [REAL_EMAIL, REAL_SSN] },
    });
    assert.equal(res.isError, undefined);
    // The real wasm `locate` on this fixture would return count 2, kind
    // "text" for both (proved below in the wasm-fallback test) — getting the
    // stub's single marker instead proves native, not wasm, answered.
    assert.equal(res.structuredContent.count, 1);
    assert.equal(res.structuredContent.regions[0].kind, "native-stub-marker");
  });
  const log = readStubLog(logPath);
  assert.equal(log.length, 1);
  assert.equal(log[0].command, "locate_text");
});

test("[native] check_redaction routes to the native engine, not wasm", async () => {
  const root = freshRoot("omitly-routing-native-check-");
  const logPath = path.join(root, "stub.log");
  const doc = copyFixturePdf(root);
  const { createServer } = await importFresh(nativeEnv(root, logPath));
  await withClient(createServer, async (client) => {
    const res: any = await client.callTool({ name: "check_redaction", arguments: { pdfPath: doc } });
    assert.equal(res.isError, true, "the stub's marker counts as a (fake) finding, so this is the 'dirty' branch");
    assert.equal(res.structuredContent.clean, false);
    assert.equal(res.structuredContent.totalFindings, 1, "must be the stub's marker count, not wasm's real 3");
    assert.deepEqual(Object.keys(res.structuredContent.byKind), ["native-stub-marker"]);
    assert.equal(res.structuredContent.evaluation, undefined, "a native-engine result is never EVALUATION-marked");
  });
  const log = readStubLog(logPath);
  assert.equal(log.length, 1);
  assert.equal(log[0].command, "find", "check_redaction drives the same native 'find' command as find_sensitive_regions");
});

test("[native] verify_redaction with a sidecar routes to native 'verify' (not 'find', not wasm)", async () => {
  const root = freshRoot("omitly-routing-native-verify-sidecar-");
  const logPath = path.join(root, "stub.log");
  const doc = copyFixturePdf(root, "verified.pdf");
  // The sidecar's own content doesn't matter to the stub (it returns a fixed
  // verdict) — only its PRESENCE decides which branch verify_redaction takes.
  writeFileSync(`${doc}.audit.json`, JSON.stringify([{ page: 0, reason_code: "X", verification: { result: "pass" } }]));
  const { createServer } = await importFresh(nativeEnv(root, logPath));
  await withClient(createServer, async (client) => {
    const res: any = await client.callTool({ name: "verify_redaction", arguments: { pdfPath: doc } });
    assert.equal(res.isError, false);
    assert.equal(res.structuredContent.mode, "sidecar");
    assert.equal(res.structuredContent.clean, true);
  });
  const log = readStubLog(logPath);
  assert.equal(log.length, 1);
  assert.equal(log[0].command, "verify", "sidecar present + native engine must call 'verify', never 'find' or wasm");
});

// ---------------------------------------------------------------------------
// 2. No native engine configured — the 4 read tools use wasm and return the
//    real detection results for the real PII in the shared fixture.
// ---------------------------------------------------------------------------

test("[wasm] find_sensitive_regions uses wasm and returns the real findings", async () => {
  const root = freshRoot("omitly-routing-wasm-find-");
  const doc = copyFixturePdf(root);
  const { createServer } = await importFresh(wasmOnlyEnv(root));
  await withClient(createServer, async (client) => {
    const res: any = await client.callTool({ name: "find_sensitive_regions", arguments: { pdfPath: doc } });
    assert.equal(res.isError, undefined);
    assert.equal(res.structuredContent.count, 3);
    assert.deepEqual(res.structuredContent.regions.map((r: any) => r.kind).sort(), REAL_KINDS);
    assert.equal(res.structuredContent.evaluation, true, "the free/wasm path is EVALUATION-marked");
  });
});

test("[wasm] locate_text uses wasm and returns the real findings", async () => {
  const root = freshRoot("omitly-routing-wasm-locate-");
  const doc = copyFixturePdf(root);
  const { createServer } = await importFresh(wasmOnlyEnv(root));
  await withClient(createServer, async (client) => {
    const res: any = await client.callTool({
      name: "locate_text",
      arguments: { pdfPath: doc, texts: [REAL_EMAIL, REAL_SSN] },
    });
    assert.equal(res.isError, undefined);
    assert.equal(res.structuredContent.count, 2);
    assert.ok(res.structuredContent.regions.every((r: any) => r.kind === "text"));
  });
});

test("[wasm] check_redaction uses wasm and returns the real findings", async () => {
  const root = freshRoot("omitly-routing-wasm-check-");
  const doc = copyFixturePdf(root);
  const { createServer } = await importFresh(wasmOnlyEnv(root));
  await withClient(createServer, async (client) => {
    const res: any = await client.callTool({ name: "check_redaction", arguments: { pdfPath: doc } });
    assert.equal(res.isError, true);
    assert.equal(res.structuredContent.clean, false);
    assert.equal(res.structuredContent.totalFindings, 3);
    assert.deepEqual(Object.keys(res.structuredContent.byKind).sort(), REAL_KINDS);
    assert.equal(res.structuredContent.evaluation, true);
  });
});

test("[wasm] verify_redaction (no native engine at all) uses wasm and returns the real findings", async () => {
  const root = freshRoot("omitly-routing-wasm-verify-");
  const doc = copyFixturePdf(root);
  const { createServer } = await importFresh(wasmOnlyEnv(root));
  await withClient(createServer, async (client) => {
    const res: any = await client.callTool({ name: "verify_redaction", arguments: { pdfPath: doc } });
    assert.equal(res.isError, true);
    assert.equal(res.structuredContent.mode, "rescan", "no native engine at all — only 'rescan' is reachable");
    assert.equal(res.structuredContent.clean, false);
    assert.equal(res.structuredContent.totalFindings, 3);
    assert.deepEqual(
      res.structuredContent.findings.map((f: any) => f.kind).sort(),
      REAL_KINDS,
    );
  });
});

// ---------------------------------------------------------------------------
// 3. verify_redaction's three branches, explicitly, in one place.
// ---------------------------------------------------------------------------

test("[branches] verify_redaction: native+sidecar -> native verify; native+no-sidecar -> native find (never wasm); no native -> wasm scan", async () => {
  // Branch A: native + sidecar present -> native "verify".
  {
    const root = freshRoot("omitly-routing-branch-a-");
    const logPath = path.join(root, "stub.log");
    const doc = copyFixturePdf(root);
    writeFileSync(`${doc}.audit.json`, JSON.stringify([{ page: 0, reason_code: "X", verification: { result: "pass" } }]));
    const { createServer } = await importFresh(nativeEnv(root, logPath));
    await withClient(createServer, async (client) => {
      const res: any = await client.callTool({ name: "verify_redaction", arguments: { pdfPath: doc } });
      assert.equal(res.structuredContent.mode, "sidecar");
      assert.equal(res.structuredContent.clean, true);
    });
    assert.deepEqual(
      readStubLog(logPath).map((e) => e.command),
      ["verify"],
    );
  }

  // Branch B: native + sidecar MISSING -> native "find" fallback (NOT wasm,
  // NOT a silent pass — the marker counts as an unclean finding).
  {
    const root = freshRoot("omitly-routing-branch-b-");
    const logPath = path.join(root, "stub.log");
    const doc = copyFixturePdf(root); // deliberately no .audit.json sidecar
    const { createServer } = await importFresh(nativeEnv(root, logPath));
    await withClient(createServer, async (client) => {
      const res: any = await client.callTool({ name: "verify_redaction", arguments: { pdfPath: doc } });
      assert.equal(res.structuredContent.mode, "rescan");
      assert.equal(res.structuredContent.clean, false, "the fallback must not silently report clean");
      assert.equal(res.structuredContent.totalFindings, 1);
      assert.equal(res.structuredContent.findings[0].kind, "native-stub-marker");
    });
    assert.deepEqual(
      readStubLog(logPath).map((e) => e.command),
      ["find"],
      "no-sidecar fallback must call native 'find', never 'verify' and never touch wasm",
    );
  }

  // Branch C: no native engine at all -> wasm scan (real findings).
  {
    const root = freshRoot("omitly-routing-branch-c-");
    const doc = copyFixturePdf(root);
    const { createServer } = await importFresh(wasmOnlyEnv(root));
    await withClient(createServer, async (client) => {
      const res: any = await client.callTool({ name: "verify_redaction", arguments: { pdfPath: doc } });
      assert.equal(res.structuredContent.mode, "rescan");
      assert.equal(res.structuredContent.clean, false);
      assert.equal(res.structuredContent.totalFindings, 3);
    });
  }
});

// ---------------------------------------------------------------------------
// 4. The 3 write/generate tools never call into wasm, under any config.
//    - No native at all: must hard-refuse (explicit "no engine configured"),
//      never silently produce a wasm-derived "success".
//    - Native configured: must route to native (proven via the stub's log +
//      its distinctive output content).
// ---------------------------------------------------------------------------

test("[no-engine] redact_pdf refuses outright — never falls back to wasm", async () => {
  const root = freshRoot("omitly-routing-noengine-redactpdf-");
  const doc = copyFixturePdf(root);
  const outputPath = path.join(root, "out.pdf");
  const { createServer } = await importFresh({ OMITLY_ALLOWED_DIR: root });
  await withClient(createServer, async (client) => {
    const res: any = await client.callTool({
      name: "redact_pdf",
      arguments: { pdfPath: doc, outputPath, regions: [{ page: 0, x: 1, y: 2, width: 3, height: 4 }] },
    });
    assert.equal(res.isError, true);
    assert.equal(res.structuredContent, undefined);
    assert.match(textOf(res), /No redaction engine configured/);
    assert.equal(existsSync(outputPath), false, "nothing should have been written");
  });
});

test("[no-engine] redact_by_entity refuses outright — never falls back to wasm", async () => {
  const root = freshRoot("omitly-routing-noengine-redactentity-");
  const doc = copyFixturePdf(root);
  const outputPath = path.join(root, "out.pdf");
  const { createServer } = await importFresh({ OMITLY_ALLOWED_DIR: root });
  await withClient(createServer, async (client) => {
    const res: any = await client.callTool({
      name: "redact_by_entity",
      arguments: { pdfPath: doc, outputPath },
    });
    assert.equal(res.isError, true);
    assert.equal(res.structuredContent, undefined);
    assert.match(textOf(res), /No redaction engine configured/);
    assert.equal(existsSync(outputPath), false);
  });
});

test("[no-engine] create_pdf refuses outright — never falls back to wasm", async () => {
  const root = freshRoot("omitly-routing-noengine-createpdf-");
  const outputPath = path.join(root, "out.pdf");
  const { createServer } = await importFresh({ OMITLY_ALLOWED_DIR: root });
  await withClient(createServer, async (client) => {
    const res: any = await client.callTool({
      name: "create_pdf",
      arguments: { outputPath, source: "# Hello" },
    });
    assert.equal(res.isError, true);
    assert.equal(res.structuredContent, undefined);
    assert.match(textOf(res), /No PDF generator configured/);
    assert.equal(existsSync(outputPath), false);
  });
});

test("[native] redact_pdf routes to the native engine (never wasm)", async () => {
  const root = freshRoot("omitly-routing-native-redactpdf-");
  const logPath = path.join(root, "stub.log");
  const doc = copyFixturePdf(root);
  const outputPath = path.join(root, "out.pdf");
  const { createServer } = await importFresh(nativeEnv(root, logPath));
  await withClient(createServer, async (client) => {
    const res: any = await client.callTool({
      name: "redact_pdf",
      arguments: { pdfPath: doc, outputPath, regions: [{ page: 0, x: 1, y: 2, width: 3, height: 4 }] },
    });
    assert.equal(res.isError, undefined);
    assert.equal(res.structuredContent.output, outputPath);
    assert.equal(readFileSync(outputPath, "utf8"), "NATIVE-STUB-REDACTED-OUTPUT");
  });
  assert.deepEqual(
    readStubLog(logPath).map((e) => e.command),
    ["redact"],
  );
});

test("[native] redact_by_entity routes to the native engine (never wasm)", async () => {
  const root = freshRoot("omitly-routing-native-redactentity-");
  const logPath = path.join(root, "stub.log");
  const doc = copyFixturePdf(root);
  const outputPath = path.join(root, "out.pdf");
  const { createServer } = await importFresh(nativeEnv(root, logPath));
  await withClient(createServer, async (client) => {
    const res: any = await client.callTool({
      name: "redact_by_entity",
      arguments: { pdfPath: doc, outputPath },
    });
    assert.equal(res.isError, undefined);
    assert.equal(res.structuredContent.output, outputPath);
    assert.equal(res.structuredContent.redactedCount, 1);
    assert.equal(res.structuredContent.redacted[0].kind, "native-stub-marker");
    assert.equal(readFileSync(outputPath, "utf8"), "NATIVE-STUB-REDACTED-OUTPUT");
  });
  assert.deepEqual(
    readStubLog(logPath).map((e) => e.command),
    ["redact_entities"],
  );
});

test("[native] create_pdf routes to the native engine (never wasm)", async () => {
  const root = freshRoot("omitly-routing-native-createpdf-");
  const logPath = path.join(root, "stub.log");
  const outputPath = path.join(root, "out.pdf");
  const { createServer } = await importFresh(nativeEnv(root, logPath));
  await withClient(createServer, async (client) => {
    const res: any = await client.callTool({
      name: "create_pdf",
      arguments: { outputPath, source: "# Hello" },
    });
    assert.equal(res.isError, undefined);
    assert.equal(res.structuredContent.output, outputPath);
    assert.equal(readFileSync(outputPath, "utf8"), "NATIVE-STUB-CREATED-PDF");
  });
  assert.deepEqual(
    readStubLog(logPath).map((e) => e.command),
    ["create"],
  );
});

// omitly#1169: extract_pdf_text now has a wasm fallback like its four
// siblings (verify_seal and verify_document — omitly#113 — are the two free
// tools that still have none, since signature verification genuinely needs
// the native crypto path; see the #113 issue thread for the tracked follow-up
// to compile omitly-seal into the wasm bundle).

test("[wasm] extract_pdf_text (no native engine) uses wasm and returns the real findings", async () => {
  const root = freshRoot("omitly-routing-wasm-extracttext-");
  const doc = copyFixturePdf(root);
  const { createServer } = await importFresh(wasmOnlyEnv(root));
  await withClient(createServer, async (client) => {
    const res: any = await client.callTool({
      name: "extract_pdf_text",
      arguments: { pdfPath: doc },
    });
    assert.equal(res.isError, undefined);
    assert.equal(res.structuredContent.masked, true);
    const spans = res.structuredContent.pages.flatMap((p: any) => p.spans);
    assert.deepEqual(spans.map((s: any) => s.kind).sort(), REAL_KINDS);
    // masked by default — the raw PII values must not appear in page text.
    for (const p of res.structuredContent.pages) {
      assert.ok(!p.text.includes(REAL_EMAIL) && !p.text.includes(REAL_SSN));
    }
  });
});

test("[wasm] extract_pdf_text masked:false returns raw text, and a regions filter is ignored with a note", async () => {
  const root = freshRoot("omitly-routing-wasm-extracttext-raw-");
  const doc = copyFixturePdf(root);
  const { createServer } = await importFresh(wasmOnlyEnv(root));
  await withClient(createServer, async (client) => {
    const res: any = await client.callTool({
      name: "extract_pdf_text",
      arguments: { pdfPath: doc, masked: false, regions: ["us"] },
    });
    assert.equal(res.isError, undefined);
    assert.equal(res.structuredContent.masked, false);
    assert.match(res.structuredContent.note ?? "", /needs a native engine/);
    const allText = res.structuredContent.pages.map((p: any) => p.text).join("\n");
    assert.ok(allText.includes(REAL_EMAIL) || allText.includes(REAL_SSN));
  });
});

test("[native] extract_pdf_text routes to the native engine", async () => {
  const root = freshRoot("omitly-routing-native-extracttext-");
  const logPath = path.join(root, "stub.log");
  const doc = copyFixturePdf(root);
  const { createServer } = await importFresh(nativeEnv(root, logPath));
  await withClient(createServer, async (client) => {
    const res: any = await client.callTool({
      name: "extract_pdf_text",
      arguments: { pdfPath: doc },
    });
    assert.equal(res.isError, undefined);
    assert.equal(res.structuredContent.pages[0].text, "NATIVE-STUB-EXTRACTED-TEXT");
    assert.equal(res.structuredContent.pages[0].spans[0].kind, "native-stub-marker");
  });
  assert.deepEqual(
    readStubLog(logPath).map((e) => e.command),
    ["extract_text"],
  );
});
