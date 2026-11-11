#!/usr/bin/env node
// omitly#1841 test stub: a configurable fake page-tool worker. The server strips the
// environment, so the mode comes from `workerArgs`, which are node options placed before
// the script: `--disable-warning=OMITLY_STUB_<mode>` (valid for any code, and it shows up
// in process.execArgv). `info` (the first-use ping and pdf_info) is answered by the REAL
// worker code in every mode except `deadping`.
//
// Modes:
//   ok            every op writes a tiny %PDF- temp file and reports success
//   env           like ok, but the temp file's body is JSON of this process's env KEYS
//   stderr        non-info ops write secret-looking text to stderr and exit 1
//   badmagic      the temp file does not start with %PDF-
//   badsize       the reported byteSize is wrong
//   foreign       the part names a temp this call did not issue
//   bigout        more than 1 MiB on stdout
//   twolines      two JSON lines on stdout
//   unknowncode   ok:false with a code the server does not know
//   err-<code>    ok:false with that code (item/pageCount/inputIndex from the request params)
//   deadping      exit at once without answering anything (even the ping)
//   holdfile      write the temp, then wait until <outDir>/RELEASE exists, then succeed
import { closeSync, existsSync, openSync, writeSync } from "node:fs";
import * as path from "node:path";
import { runRequest } from "../../dist/pdf-edit/worker.js";

const mode = (process.execArgv.find((a) => a.startsWith("--disable-warning=OMITLY_STUB_")) ?? "").slice(
  "--disable-warning=OMITLY_STUB_".length,
);

if (mode === "deadping") process.exit(3);

const line = (o) => JSON.stringify(o) + "\n";
const done = (s, code = 0) => process.stdout.write(s, () => process.exit(code));

function writeTemp(req, i, body) {
  const fd = openSync(path.join(req.outDir, req.temps[i]), "wx");
  writeSync(fd, body);
  closeSync(fd);
  return Buffer.byteLength(body);
}

let buf = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", async (chunk) => {
  buf += chunk;
  const nl = buf.indexOf("\n");
  if (nl === -1) return;
  const req = JSON.parse(buf.slice(0, nl));
  buf = "";
  if (req.op === "info") return done(line(await runRequest(req)));

  const meta = (n) =>
    req.op === "split"
      ? { pageCounts: req.temps.map(() => 1) }
      : req.op === "merge"
        ? { pageCount: 1, pageCounts: req.inputs.map(() => 1) }
        : req.op === "compose"
          ? { pageCount: 1, layout: [{ pageNumber: 1, from: 1, rotation: 0 }] }
          : { pageCount: n };
  const parts = (body) => req.temps.map((t, i) => ({ temp: t, byteSize: writeTemp(req, i, body) }));

  switch (mode) {
    case "stderr":
      process.stderr.write("SECRET-STDERR-TEXT /Users/someone/private.pdf\n");
      return process.exit(1);
    case "bigout":
      return done("x".repeat(1024 * 1024 + 10));
    case "twolines":
      return done(line({ v: 1, ok: true }) + line({ v: 1, ok: true }));
    case "unknowncode":
      return done(line({ v: 1, ok: false, code: "definitely_not_a_code" }));
    case "badmagic":
      return done(line({ v: 1, ok: true, meta: meta(1), parts: parts("NOT-A-PDF"), warnings: [], lost: [] }));
    case "badsize": {
      const p = parts("%PDF-1.4\nstub\n");
      p[0].byteSize += 1;
      return done(line({ v: 1, ok: true, meta: meta(1), parts: p, warnings: [], lost: [] }));
    }
    case "foreign": {
      const p = parts("%PDF-1.4\nstub\n");
      p[0].temp = ".omitly-tmp-0000000000000000-0.pdf";
      return done(line({ v: 1, ok: true, meta: meta(1), parts: p, warnings: [], lost: [] }));
    }
    case "env":
      return done(line({ v: 1, ok: true, meta: meta(1), parts: parts("%PDF-1.4\n" + JSON.stringify(Object.keys(process.env))), warnings: [], lost: [] }));
    case "holdfile": {
      const p = parts("%PDF-1.4\nstub\n");
      const release = path.join(req.outDir, "RELEASE");
      while (!existsSync(release)) await new Promise((r) => setTimeout(r, 25));
      return done(line({ v: 1, ok: true, meta: meta(1), parts: p, warnings: [], lost: [] }));
    }
    default:
      if (mode.startsWith("err-")) {
        return done(line({ v: 1, ok: false, code: mode.slice(4), item: 7, pageCount: 3, inputIndex: req.op === "merge" ? 2 : undefined }));
      }
      return done(line({ v: 1, ok: true, meta: meta(1), parts: parts("%PDF-1.4\nstub\n"), warnings: [], lost: [] }));
  }
});
