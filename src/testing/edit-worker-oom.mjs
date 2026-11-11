#!/usr/bin/env node
// omitly#1841 test stub: a page-tool worker that RUNS OUT OF MEMORY. `info` is answered by
// the real worker code (see edit-worker-hang.mjs); every other op fills the V8 heap with
// live objects until the process is killed by the heap limit the server passed
// (`--max-old-space-size`, small in tests). The server must map that to `failed`, clean up,
// and keep answering.
import { openSync, closeSync, writeSync } from "node:fs";
import * as path from "node:path";
import { runRequest } from "../../dist/pdf-edit/worker.js";

let buf = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", async (chunk) => {
  buf += chunk;
  const nl = buf.indexOf("\n");
  if (nl === -1) return;
  const req = JSON.parse(buf.slice(0, nl));
  if (req.op === "info") {
    process.stdout.write(JSON.stringify(await runRequest(req)) + "\n", () => process.exit(0));
    return;
  }
  for (const t of req.temps) {
    const fd = openSync(path.join(req.outDir, t), "wx");
    writeSync(fd, "%PDF-1.4\npartial");
    closeSync(fd);
  }
  const keep = [];
  for (;;) keep.push({ a: new Array(100_000).fill({ b: keep.length }) });
});
