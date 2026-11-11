#!/usr/bin/env node
// omitly#1841 test stub: a page-tool worker that HANGS. Used to prove the server kills a
// stuck child at its timeout, maps it to `timeout`, removes the temp file the child had
// already created, and keeps answering afterwards.
//
// `info` (the first-use ping, and pdf_info) is answered by the REAL worker code so the
// server's start-up check passes and a later pdf_info is a real answer. Every other op
// creates its issued temp file, then spins in a synchronous loop forever (so only a
// SIGKILL stops it; the stdin-end exit cannot run on a busy main thread, by design of
// this stub). The behaviour is chosen by the server's `workerArgs` (node options), not
// the environment, which the server strips.
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
  for (;;) {
    /* hang */
  }
});
