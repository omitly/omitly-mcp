#!/usr/bin/env node
/**
 * omitly#1841 phase B: seeded fuzz harness for the five page tools (design 4.6).
 *
 * Mutates generated PDFs (byte flips, truncation, splices of structure keywords, inflated
 * counts, cyclic references) and feeds each through ALL FIVE tools via a real MCP server and
 * the real child-process worker. It passes when:
 *   - no case outlives its timeout,
 *   - the server answers `pdf_info` on a known-good file after EVERY case,
 *   - no file appears outside the root, and no temp (.omitly-tmp-*) is left behind.
 *
 *   npm run build && npm run fuzz                 # 200 cases, 10 s timeout, seed 1841
 *   node fuzz/edit-tools.fuzz.mjs --cases 10000 --timeout 10000 --seed 7
 *
 * Lives outside src/, so it is never compiled, never in `npm test`, never in the tarball.
 * Run from omitly-mcp/ after `npm run build` (it imports dist/).
 */
import { mkdirSync, mkdtempSync, readdirSync, realpathSync, writeFileSync, rmSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { PDFDocument, PDFName, PDFString, StandardFonts } from "pdf-lib";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const { registerEditTools } = await import(path.join(HERE, "..", "dist", "edit-tools.js"));

const args = process.argv.slice(2);
const opt = (name, dflt) => {
  const i = args.indexOf(`--${name}`);
  return i === -1 ? dflt : Number(args[i + 1]);
};
const CASES = opt("cases", 200);
const TIMEOUT = opt("timeout", 10_000);
let seed = opt("seed", 1841) >>> 0;

// mulberry32: small, seeded, reproducible.
function rnd() {
  seed = (seed + 0x6d2b79f5) >>> 0;
  let t = seed;
  t = Math.imul(t ^ (t >>> 15), t | 1);
  t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
}
const int = (n) => Math.floor(rnd() * n);
const pick = (xs) => xs[int(xs.length)];

async function seedDoc(pages, extras) {
  const doc = await PDFDocument.create();
  const font = await doc.embedFont(StandardFonts.Helvetica);
  for (let i = 0; i < pages; i++) {
    const p = doc.addPage([300 + i, 400]);
    p.drawText(`FUZZ-${i + 1}`, { x: 20, y: 200, size: 14, font });
    p.node.set(PDFName.of("OmitlyMarker"), PDFString.of(`FUZZ-${i + 1}`));
  }
  if (extras) {
    const form = doc.getForm();
    const f = form.createTextField("f1");
    f.addToPage(doc.getPages()[0], { x: 20, y: 300, width: 100, height: 20 });
  }
  return Buffer.from(await doc.save({ useObjectStreams: rnd() < 0.5 }));
}

const KEYWORDS = ["/Kids", "/Parent", "/Count 99999999", "/Type /Pages", "/Annots", "/AcroForm", "/Fields", "/Encrypt", "/Rotate 45", "/MediaBox [0 0 -1 1e9]", "/Length 99999999", "endobj", "xref", "startxref 0", "/Prev 9", "/Root"];
function mutate(buf) {
  const b = Buffer.from(buf);
  const kind = int(7);
  if (kind === 0) for (let i = 0, n = 1 + int(20); i < n; i++) b[int(b.length)] = int(256);
  else if (kind === 1) return b.subarray(0, int(b.length));
  else if (kind === 2) {
    const at = int(b.length);
    return Buffer.concat([b.subarray(0, at), Buffer.from(pick(KEYWORDS)), b.subarray(at)]);
  } else if (kind === 3) {
    // replace a keyword occurrence with another
    const s = b.toString("latin1");
    const from = pick(["/Kids", "/Parent", "/Type /Page", "/Contents", "/Resources", "/Count"]);
    const i = s.indexOf(from);
    if (i !== -1) return Buffer.from(s.slice(0, i) + pick(KEYWORDS) + s.slice(i + from.length), "latin1");
  } else if (kind === 4) {
    // duplicate a chunk
    const at = int(b.length), len = int(Math.min(2000, b.length - at));
    return Buffer.concat([b, b.subarray(at, at + len)]);
  } else if (kind === 5) return Buffer.concat([Buffer.from("%PDF-1.7\n"), Buffer.from(Array.from({ length: int(4000) }, () => int(256)))]);
  else for (let i = 0, n = 1 + int(200); i < n; i++) b[int(b.length)] ^= 1 << int(8);
  return b;
}

const root = realpathSync(mkdtempSync(path.join(os.tmpdir(), "omitly-fuzz-")));
const outside = realpathSync(mkdtempSync(path.join(os.tmpdir(), "omitly-fuzz-outside-")));
const good = path.join(root, "good.pdf");
writeFileSync(good, await seedDoc(3, false));

const server = new McpServer({ name: "fuzz", version: "0" });
registerEditTools(server, { root, rootExplicit: true, timeoutMs: TIMEOUT });
const [a, b] = InMemoryTransport.createLinkedPair();
const client = new Client({ name: "fuzz-client", version: "0" });
await Promise.all([server.connect(a), client.connect(b)]);
const call = async (name, a) => client.callTool({ name, arguments: a }, undefined, { timeout: TIMEOUT + 15_000 });

const snapshot = () => readdirSync(root).filter((n) => n !== "good.pdf" && !n.startsWith("case"));
let failures = 0;
const stats = { ok: 0, refused: 0 };
const started = Date.now();
for (let n = 0; n < CASES; n++) {
  const dir = path.join(root, `case${n}`);
  mkdirSync(dir);
  const base = await seedDoc(1 + int(5), rnd() < 0.4);
  const f1 = path.join(dir, "m.pdf");
  const f2 = path.join(dir, "n.pdf");
  writeFileSync(f1, mutate(base));
  writeFileSync(f2, rnd() < 0.5 ? mutate(base) : base);
  const t0 = Date.now();
  const calls = [
    ["pdf_info", { pdfPath: f1 }],
    ["extract_pages", { pdfPath: f1, pages: [1, "2-3"].slice(0, 1 + int(2)), outputPath: path.join(dir, "e.pdf") }],
    ["split_pdf", { pdfPath: f1, ranges: [[1], ["2-3"]], outputDir: dir, prefix: "s" }],
    ["edit_pages", { pdfPath: f1, pages: [{ source: 1, rotate: 90 }, { blank: true }, { source: 2 }], outputPath: path.join(dir, "ed.pdf") }],
    ["merge_pdfs", { inputs: [f1, f2], outputPath: path.join(dir, "mg.pdf") }],
  ];
  for (const [name, a] of calls) {
    const s = Date.now();
    let r;
    try {
      r = await call(name, a);
    } catch (e) {
      failures++;
      console.error(`case ${n} ${name}: the call itself failed: ${e.message}`);
      continue;
    }
    if (Date.now() - s > TIMEOUT + 5_000) {
      failures++;
      console.error(`case ${n} ${name}: outlived its timeout (${Date.now() - s} ms)`);
    }
    if (r.isError) stats.refused++;
    else stats.ok++;
    // The server must answer on a known-good file after EVERY call.
    const probe = await call("pdf_info", { pdfPath: good });
    if (probe.isError || probe.structuredContent?.pageCount !== 3) {
      failures++;
      console.error(`case ${n} ${name}: pdf_info did not answer after the call`);
    }
  }
  const stray = readdirSync(dir).filter((x) => x.startsWith(".omitly-tmp-"));
  if (stray.length) {
    failures++;
    console.error(`case ${n}: temp files left behind: ${stray.join(", ")}`);
  }
  if (snapshot().length) {
    failures++;
    console.error(`case ${n}: unexpected files in the root: ${snapshot().join(", ")}`);
  }
  if (readdirSync(outside).length) {
    failures++;
    console.error(`case ${n}: a file appeared outside the root`);
  }
  void t0;
}
await client.close();
await server.close();
const secs = ((Date.now() - started) / 1000).toFixed(1);
console.log(`fuzz: ${CASES} cases x 5 tools, seed ${opt("seed", 1841)}, timeout ${TIMEOUT} ms: ${stats.ok} succeeded, ${stats.refused} refused, ${failures} FAILURES, ${secs} s`);
rmSync(root, { recursive: true, force: true });
rmSync(outside, { recursive: true, force: true });
process.exit(failures === 0 ? 0 : 1);
