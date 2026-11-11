/**
 * omitly#1841 phase B: decisions 2C and 3B (design 4.5), the check-to-edit round trip, the
 * network claim, and the README tool table.
 *
 * 2C/3B are proved BY BEHAVIOUR, not by spying on internals (the queue function is a closure):
 * with a live desktop heartbeat that has accept-in-app ON, OMITLY_FREE_CAP=1 and this month's
 * one check already used, each writer still produces its file, no proposal appears, and
 * `check_calls` is unchanged. A positive control first shows the same setup DOES queue a
 * proposal for a redaction and DOES refuse a second check, so a vacuous setup cannot pass.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { PDFDocument, StandardFonts } from "pdf-lib";
import { makeDoc, pageMarkers, put, tempRoot, textOf } from "./edit-fixtures.test.js";
import { monthKey } from "./usage.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ENV = ["OMITLY_ALLOWED_DIR", "OMITLY_REDACT_BIN", "OMITLY_PDF_BIN", "OMITLY_ENGINE_DIR", "OMITLY_STATE_DIR", "OMITLY_FREE_CAP"] as const;
let n = 0;

async function withFullServer<T>(env: Record<string, string>, fn: (call: (name: string, args: Record<string, unknown>) => Promise<any>, client: Client) => Promise<T>): Promise<T> {
  for (const k of ENV) delete process.env[k];
  Object.assign(process.env, env);
  n += 1;
  const mod = (await import(`./index.js?edit-invariants=${n}`)) as typeof import("./index.js");
  const server = mod.createServer();
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "Claude Desktop", version: "9.9.9" });
  await Promise.all([server.connect(a), client.connect(b)]);
  try {
    return await fn(async (name, args) => client.callTool({ name, arguments: args }), client);
  } finally {
    await client.close();
    await server.close();
  }
}

const proposals = (state: string) => (existsSync(path.join(state, "proposals")) ? readdirSync(path.join(state, "proposals")) : []);

test("2C/3B: with the desktop live (accept-in-app on) and the free cap used up, every page tool still writes its file, queues nothing and counts nothing", async () => {
  const root = tempRoot();
  const state = path.join(root, "state");
  mkdirSync(state);
  const seeded = { check_calls: { [monthKey()]: 1 }, install_id: "11111111-1111-4111-8111-111111111111", licensed: false };
  const usageFile = path.join(state, "usage.json");
  writeFileSync(usageFile, JSON.stringify(seeded));
  writeFileSync(path.join(state, "desktop.json"), JSON.stringify({ pid: 4242, version: "5.4.0", accept_in_app: true, updated_at: new Date().toISOString() }));
  put(root, "a.pdf", await makeDoc("A", 4));
  put(root, "b.pdf", await makeDoc("B", 2));
  const usageBefore = readFileSync(usageFile, "utf8");

  await withFullServer({ OMITLY_ALLOWED_DIR: root, OMITLY_STATE_DIR: state, OMITLY_FREE_CAP: "1" }, async (call) => {
    // CONTROL 1: this setup refuses a second free check ...
    const capped = await call("check_redaction", { pdfPath: "a.pdf" });
    assert.equal(capped.isError, true);
    assert.equal(JSON.parse(textOf(capped)).reason, "free-cap", "the cap is exhausted, so the control is live");
    // CONTROL 2: ... and a redaction proposal IS queued for the person in the desktop app.
    assert.deepEqual(proposals(state), []);
    const prop = await call("propose_redactions", {
      pdfPath: "a.pdf",
      outputPath: "a-redacted.pdf",
      regions: [{ page: 0, x: 1, y: 1, width: 5, height: 5 }],
    });
    assert.ok(!prop.isError, textOf(prop));
    assert.equal(proposals(state).length, 1, "the desktop channel is live: a redaction proposal was queued");
    const usageAfterControls = readFileSync(usageFile, "utf8");
    assert.equal(JSON.parse(usageAfterControls).check_calls[monthKey()] >= 1, true);

    // THE TEST: the five tools.
    const results = [
      await call("pdf_info", { pdfPath: "a.pdf" }),
      await call("extract_pages", { pdfPath: "a.pdf", pages: [2, 1], outputPath: "x.pdf" }),
      await call("split_pdf", { pdfPath: "a.pdf", ranges: [[1, 2], [3, 4]], outputDir: ".", prefix: "sp" }),
      await call("edit_pages", { pdfPath: "a.pdf", pages: [{ source: 4 }, { blank: true }], outputPath: "ed.pdf" }),
      await call("merge_pdfs", { inputs: ["a.pdf", "b.pdf"], outputPath: "mg.pdf" }),
    ];
    for (const r of results) assert.ok(!r.isError, textOf(r));
    for (const f of ["x.pdf", "ed.pdf", "mg.pdf", "sp-p1-2.pdf", "sp-p3-4.pdf"]) assert.ok(existsSync(path.join(root, f)), `${f} was written directly`);
    assert.equal(proposals(state).length, 1, "no new proposal: new-file edits run automatically (2C)");
    assert.equal(readFileSync(usageFile, "utf8"), usageAfterControls, "check_calls (usage.json) is byte-for-byte unchanged (3B)");
    for (const r of results) {
      const all = JSON.stringify(r);
      assert.ok(!/EVALUATION|free-cap|licen[cs]e/i.test(all), "no EVALUATION banner, cap or licence text");
    }
  });
  assert.notEqual(usageBefore, "", "seeded");
});

// ---------------------------------------------------------------------------
// Structural: nothing the page tools run imports desktop.ts, usage.ts or a network module
// ---------------------------------------------------------------------------

const NETWORK = /^(node:)?(http|https|http2|net|tls|dgram|dns|dns\/promises|inspector|cluster|undici|ws|node-fetch|axios|got)$/;

function importsOf(source: string): string[] {
  const specs: string[] = [];
  for (const m of source.matchAll(/(?:from\s+|import\s*\(\s*|require\s*\(\s*|import\s+)["']([^"']+)["']/g)) specs.push(m[1]);
  return specs;
}

/** All relative files reachable from `entry` (dist .js), plus every bare specifier seen. */
function reach(entry: string): { files: Set<string>; bare: Set<string> } {
  const files = new Set<string>();
  const bare = new Set<string>();
  const stack = [entry];
  while (stack.length) {
    const f = stack.pop()!;
    if (files.has(f)) continue;
    files.add(f);
    for (const spec of importsOf(readFileSync(f, "utf8"))) {
      if (spec.startsWith(".")) stack.push(path.resolve(path.dirname(f), spec));
      else bare.add(spec);
    }
  }
  return { files, bare };
}

test("structural: the page tools import nothing from desktop.ts or usage.ts, and no network module; the scan itself works (control)", () => {
  const entries = [path.join(HERE, "edit-tools.js"), path.join(HERE, "pdf-edit", "worker.js")];
  for (const f of readdirSync(path.join(HERE, "pdf-edit"))) {
    if (f.endsWith(".js") && !f.endsWith(".test.js")) entries.push(path.join(HERE, "pdf-edit", f));
  }
  for (const entry of entries) {
    const { files, bare } = reach(entry);
    for (const f of files) {
      const base = path.basename(f);
      assert.ok(!["desktop.js", "usage.js", "index.js"].includes(base), `${path.basename(entry)} reaches ${base}`);
    }
    for (const spec of bare) {
      assert.ok(!NETWORK.test(spec), `${path.basename(entry)} imports ${spec}`);
      assert.ok(!/desktop|usage/.test(spec));
    }
    for (const f of files) {
      const src = readFileSync(f, "utf8");
      assert.ok(!/\bfetch\s*\(|new\s+WebSocket|XMLHttpRequest/.test(src), `${f} uses a network global`);
    }
  }
  // CONTROL: the same scan on index.ts's build finds the desktop and usage imports.
  const idx = reach(path.join(HERE, "index.js"));
  assert.ok([...idx.files].some((f) => path.basename(f) === "desktop.js"), "control: the scan sees desktop.js from index.js");
  assert.ok([...idx.files].some((f) => path.basename(f) === "usage.js"), "control: the scan sees usage.js from index.js");
  assert.ok(idx.bare.has("node:child_process"), "control: the scan sees a bare node: import");
  // The third-party code they run (pdf-lib and its own dependencies) imports no network module either.
  const pkgRoot = path.resolve(HERE, "..", "node_modules");
  const walk = (dir: string): string[] =>
    readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(path.join(dir, e.name)) : e.name.endsWith(".js") ? [path.join(dir, e.name)] : []));
  for (const dep of ["pdf-lib/cjs", "pako/lib", "@pdf-lib/standard-fonts/lib", "@pdf-lib/upng/UPNG.js"]) {
    const p = path.join(pkgRoot, dep);
    if (!existsSync(p)) continue;
    const js = p.endsWith(".js") ? [p] : walk(p);
    for (const f of js) for (const spec of importsOf(readFileSync(f, "utf8"))) assert.ok(!NETWORK.test(spec), `${f} imports ${spec}`);
  }
});

// ---------------------------------------------------------------------------
// check -> edit round trip: a 0-based `page` from the check tools, plus 1, is the same page
// ---------------------------------------------------------------------------

test("check-to-edit: a 0-based page from find_sensitive_regions, plus 1, extracts the same page", async () => {
  const root = tempRoot();
  const state = path.join(root, "state");
  mkdirSync(state);
  const doc = await PDFDocument.create();
  const font = await doc.embedFont(StandardFonts.Helvetica);
  for (let i = 0; i < 3; i++) {
    const p = doc.addPage([400, 300]);
    p.drawText(i === 1 ? "Social security number 123-45-6789 for John" : `Nothing sensitive on page ${i + 1}`, { x: 20, y: 150, size: 12, font });
  }
  put(root, "doc.pdf", await doc.save());
  await withFullServer({ OMITLY_ALLOWED_DIR: root, OMITLY_STATE_DIR: state, OMITLY_FREE_CAP: "1000" }, async (call) => {
    const found = await call("find_sensitive_regions", { pdfPath: "doc.pdf" });
    assert.ok(!found.isError, textOf(found));
    const regions = found.structuredContent.regions as { page: number; kind: string }[];
    assert.ok(regions.length >= 1, "the wasm detector found the planted SSN");
    const page0 = regions[0].page;
    assert.equal(page0, 1, "0-based: the SSN is on the second page");
    const ex = await call("extract_pages", { pdfPath: "doc.pdf", pages: [page0 + 1], outputPath: "only-that-page.pdf" });
    assert.ok(!ex.isError, textOf(ex));
    assert.deepEqual(ex.structuredContent.sourcePages, [2]);
    const again = await call("find_sensitive_regions", { pdfPath: "only-that-page.pdf" });
    assert.ok(again.structuredContent.regions.length >= 1, "the extracted page is the one holding the finding");
    assert.equal(again.structuredContent.regions[0].page, 0);
    // And the neighbours are not it.
    const wrong = await call("extract_pages", { pdfPath: "doc.pdf", pages: [page0], outputPath: "wrong-page.pdf" });
    const wrongScan = await call("find_sensitive_regions", { pdfPath: "wrong-page.pdf" });
    assert.equal(wrongScan.structuredContent.regions.length, 0, "using the 0-based number as 1-based picks the wrong page");
    assert.ok(!wrong.isError);
  });
  assert.deepEqual(await pageMarkers(readFileSync(path.join(root, "only-that-page.pdf"))), [""]);
});

// ---------------------------------------------------------------------------
// README tool table
// ---------------------------------------------------------------------------

test("README: the tool table and the registered tools agree", async () => {
  const readme = readFileSync(path.resolve(HERE, "..", "README.md"), "utf8");
  const rows = readme
    .split("\n")
    .map((l) => /^\| `([a-z_]+)` \|/.exec(l)?.[1])
    .filter((x): x is string => x !== undefined);
  const root = tempRoot();
  const state = path.join(root, "state");
  mkdirSync(state);
  const registered = await withFullServer({ OMITLY_ALLOWED_DIR: root, OMITLY_STATE_DIR: state }, async (_call, client) => (await client.listTools()).tools.map((t) => t.name));
  for (const t of ["pdf_info", "merge_pdfs", "extract_pages", "split_pdf", "edit_pages"]) {
    assert.ok(rows.includes(t), `README lists ${t}`);
    assert.ok(registered.includes(t), `${t} is registered on the full server`);
  }
  assert.deepEqual([...rows].sort(), [...registered].sort(), "every row names a registered tool and every tool has a row");
});
