// omitly#1841: a stdio smoke test of the INSTALLED omitly-mcp bin, for the Windows CI leg
// (`omitly-mcp-windows` in .gitlab-ci.yml). It is not part of the npm package: package.json "files"
// does not list scripts/, and scripts/npm-pack-manifest-check.sh would flag a leak.
//
// Run it from a directory that has the production install of omitly-mcp (`npm ci --omit=dev`) and its
// built dist/, with this file copied there:   node windows-smoke.mjs
// It needs only the package's own runtime dependencies (the MCP SDK and pdf-lib), and does NOT need the
// wasm bundle: the page tools run in a child process and never touch it.
//
// What it proves on Windows, through the real bin over stdio: the five page tools register, pdf_info and
// merge_pdfs work on two generated PDFs (so the child process starts with its stripped environment and
// the output is placed), an existing output is never overwritten, and Windows device and stream names
// are refused.
import assert from "node:assert/strict";
import { mkdtempSync, existsSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { PDFDocument } from "pdf-lib";

const here = path.dirname(fileURLToPath(import.meta.url));
const bin = path.join(here, "dist", "index.js");
const work = realpathSync(mkdtempSync(path.join(tmpdir(), "omitly-win-smoke-")));

async function makePdf(name, pages) {
  const doc = await PDFDocument.create();
  for (let i = 0; i < pages; i++) doc.addPage([200 + i, 300]);
  writeFileSync(path.join(work, name), await doc.save());
}
const text = (r) => (r.content ?? []).filter((c) => c.type === "text").map((c) => c.text).join("\n");

const transport = new StdioClientTransport({
  command: process.execPath,
  args: [bin],
  env: { ...(process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {}), OMITLY_ALLOWED_DIR: work },
  stderr: "inherit",
});
const client = new Client({ name: "windows-smoke", version: "0.0.0" });
let failed = false;
try {
  await makePdf("a.pdf", 2);
  await makePdf("b.pdf", 3);
  await client.connect(transport);

  const names = (await client.listTools()).tools.map((t) => t.name);
  for (const t of ["pdf_info", "merge_pdfs", "extract_pages", "split_pdf", "edit_pages"]) assert.ok(names.includes(t), `tools/list has ${t}`);

  const info = await client.callTool({ name: "pdf_info", arguments: { pdfPath: "a.pdf" } });
  assert.ok(!info.isError, text(info));
  assert.equal(info.structuredContent.pageCount, 2);

  const merged = await client.callTool({ name: "merge_pdfs", arguments: { inputs: ["a.pdf", "b.pdf"], outputPath: "m.pdf" } });
  assert.ok(!merged.isError, text(merged));
  assert.equal(merged.structuredContent.pageCount, 5);
  assert.ok(existsSync(path.join(work, "m.pdf")), "the merged file was placed");

  const again = await client.callTool({ name: "merge_pdfs", arguments: { inputs: ["a.pdf", "b.pdf"], outputPath: "m.pdf" } });
  assert.equal(again.isError, true, "an existing output is refused");
  assert.match(text(again), /refusing to overwrite/);

  for (const bad of ["CON.pdf", "nul.pdf", "x.pdf:stream", "trailing.pdf."]) {
    const r = await client.callTool({ name: "extract_pages", arguments: { pdfPath: "a.pdf", pages: [1], outputPath: bad } });
    assert.equal(r.isError, true, `${bad} is refused`);
    assert.equal(text(r), "Output files must end in .pdf.", bad);
  }

  const fresh = await client.callTool({ name: "extract_pages", arguments: { pdfPath: "b.pdf", pages: [3, 1], outputPath: "e.pdf" } });
  assert.ok(!fresh.isError, text(fresh));
  assert.deepEqual(fresh.structuredContent.sourcePages, [3, 1]);
  console.log("windows smoke: ok");
} catch (e) {
  failed = true;
  console.error("windows smoke: FAILED:", e && e.stack ? e.stack : e);
} finally {
  await client.close().catch(() => {});
  rmSync(work, { recursive: true, force: true });
}
process.exit(failed ? 1 : 0);
