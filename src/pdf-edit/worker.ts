/**
 * omitly#1841 phase B: the child process that does ALL the pdf-lib work of the
 * five page tools (design 4.2), so a hostile PDF can hang or crash this process
 * and nothing else.
 *
 * Protocol: one JSON line on stdin (the request), one JSON line on stdout (the
 * response, at most 1 MiB, never PDF bytes). The child takes ALL its settings from
 * the request (the server starts it with an empty environment). It writes only
 * the temp names the server issued, create-exclusive, under the output folder the
 * server confined. It never places a final file; the server does.
 *
 * Lifetime: the pdf-lib work runs in a `worker_thread`; this process's main thread
 * stays free so that it can (a) exit when stdin ends, which is how a child dies
 * with the server even while pdf-lib is stuck in a synchronous loop, and (b) exit
 * on its own at `timeoutMs` + 5 s.
 *
 * One file serves both roles: the entry point in the child process, and the
 * script of the worker thread. Importing it (tests) runs neither.
 */
import { closeSync, fstatSync, openSync, readFileSync, realpathSync, unlinkSync, writeSync } from "node:fs";
import * as path from "node:path";
import { Worker, isMainThread, parentPort, workerData } from "node:worker_threads";
import { fileURLToPath, pathToFileURL } from "node:url";
import { composePages, extractPagesTo, openRangeExtractor, type ComposeEntry } from "./compose.js";
import { isEncryptedError, type LostCode } from "./docFacts.js";
import { pdfInfo } from "./info.js";
import { mergePdfs } from "./merge.js";
import { EditRefusal, type EditCode } from "./refusals.js";

export const TEMP_NAME = /^\.omitly-tmp-[0-9a-f]{16}-[0-9]{1,3}\.pdf$/;
export const MAX_REQUEST_BYTES = 1024 * 1024;
export const MAX_RESPONSE_BYTES = 1024 * 1024;
const MAX_PAGES = 10_000;

export type Op = "info" | "merge" | "extract" | "split" | "compose";

export interface WorkerRequest {
  v: 1;
  op: Op;
  inputs: string[];
  outDir: string;
  temps: string[];
  caps: { perFileBytes: number; totalBytes: number };
  /** Added to the design's request: the child's own backstop, timeoutMs + 5 s. */
  timeoutMs: number;
  params: unknown;
}

export type WorkerResponse =
  | {
      v: 1;
      ok: true;
      meta: Record<string, unknown>;
      parts: { temp: string; byteSize: number }[];
      warnings: string[];
      lost: LostCode[];
    }
  | { v: 1; ok: false; code: EditCode; item?: number; pageCount?: number; inputIndex?: number };

const fail = (code: EditCode, extra: { item?: number; pageCount?: number; inputIndex?: number } = {}): WorkerResponse => ({
  v: 1,
  ok: false,
  code,
  ...extra,
});

function isIntArray(v: unknown, min: number, max: number): v is number[] {
  return Array.isArray(v) && v.length <= MAX_PAGES && v.every((n) => Number.isInteger(n) && n >= min && n <= max);
}

function parseRequest(raw: unknown): WorkerRequest | null {
  const r = raw as Record<string, any> | null;
  if (!r || typeof r !== "object" || r.v !== 1) return null;
  if (!["info", "merge", "extract", "split", "compose"].includes(r.op)) return null;
  if (!Array.isArray(r.inputs) || r.inputs.length < 1 || r.inputs.length > 50) return null;
  if (!r.inputs.every((p: unknown) => typeof p === "string" && path.isAbsolute(p))) return null;
  if (r.op !== "merge" && r.inputs.length !== 1) return null;
  if (typeof r.outDir !== "string" || !path.isAbsolute(r.outDir)) return null;
  if (!Array.isArray(r.temps) || r.temps.length > 100 || !r.temps.every((t: unknown) => typeof t === "string" && TEMP_NAME.test(t))) return null;
  const caps = r.caps;
  if (!caps || !Number.isSafeInteger(caps.perFileBytes) || !Number.isSafeInteger(caps.totalBytes) || caps.perFileBytes < 1 || caps.totalBytes < 1) return null;
  if (!Number.isSafeInteger(r.timeoutMs) || r.timeoutMs < 1) return null;
  return r as WorkerRequest;
}

/** Writes one temp file the server issued: create-exclusive, size-capped while writing. */
function writeTemp(req: WorkerRequest, index: number, bytes: Uint8Array, written: { total: number }): { temp: string; byteSize: number } {
  const temp = req.temps[index];
  if (temp === undefined) throw new EditRefusal("failed");
  if (bytes.length > req.caps.totalBytes || written.total + bytes.length > req.caps.totalBytes) {
    throw new EditRefusal("output_too_large");
  }
  const file = path.join(req.outDir, temp);
  // The server passes the folder as a confined REAL path. If it is not one any more (swapped
  // for a symlink since), write nothing. A swap between this check and the open below remains
  // possible and is a stated residual (see edit-tools.ts); hostile local users are out of scope.
  try {
    if (realpathSync(req.outDir) !== req.outDir) throw new EditRefusal("failed");
  } catch {
    throw new EditRefusal("failed");
  }
  let fd: number;
  try {
    fd = openSync(file, "wx", 0o600);
  } catch {
    throw new EditRefusal("write_failed");
  }
  try {
    const CHUNK = 1024 * 1024;
    let off = 0;
    while (off < bytes.length) {
      const n = Math.min(CHUNK, bytes.length - off);
      if (written.total + n > req.caps.totalBytes) throw new EditRefusal("output_too_large");
      writeSync(fd, bytes, off, n);
      off += n;
      written.total += n;
    }
    closeSync(fd);
  } catch (e) {
    try {
      closeSync(fd);
    } catch {
      /* already closed */
    }
    try {
      unlinkSync(file);
    } catch {
      /* the server removes issued names too */
    }
    throw e instanceof EditRefusal ? e : new EditRefusal("write_failed");
  }
  return { temp, byteSize: bytes.length };
}

/** Open an input for reading, but only if it is still the confined REAL path the server passed:
 *  a path that has since become (or sits behind) a symlink is refused, as for the output folder.
 *  A swap between this check and the open remains possible (stated residual, edit-tools.ts). */
function openInput(p: string): number {
  let same = false;
  try {
    same = realpathSync(p) === p;
  } catch {
    same = false;
  }
  if (!same) throw new EditRefusal("failed");
  return openSync(p, "r");
}

/** Open, check and read one input. The server confined the path; this re-reads it. */
function readInput(req: WorkerRequest, index: number): Uint8Array {
  const inputIndex = req.op === "merge" ? index + 1 : undefined;
  const fd = openInput(req.inputs[index]);
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) throw new EditRefusal("not_a_file", { inputIndex });
    if (st.size > req.caps.perFileBytes) throw new EditRefusal("too_large", { inputIndex });
    const bytes = readFileSync(fd);
    if (!bytes.subarray(0, 1024).includes("%PDF-")) throw new EditRefusal("not_pdf", { inputIndex });
    return bytes;
  } finally {
    closeSync(fd);
  }
}

/** Size and type checks for every input BEFORE any is read (merge: the total). */
function checkInputs(req: WorkerRequest): void {
  let total = 0;
  req.inputs.forEach((p, i) => {
    const inputIndex = req.op === "merge" ? i + 1 : undefined;
    let fd: number;
    try {
      fd = openInput(p);
    } catch (e) {
      if (e instanceof EditRefusal) throw e; // not a confined real path any more: `failed`
      throw new EditRefusal("not_a_file", { inputIndex });
    }
    try {
      const st = fstatSync(fd);
      if (!st.isFile()) throw new EditRefusal("not_a_file", { inputIndex });
      if (st.size > req.caps.perFileBytes) throw new EditRefusal("too_large", { inputIndex });
      total += st.size;
      if (req.op === "merge" && total > req.caps.totalBytes) throw new EditRefusal("too_large", { inputIndex });
    } finally {
      closeSync(fd);
    }
  });
}

const FIXED_ROTATIONS = new Set([0, 90, 180, 270]);

function parseCompose(params: any): ComposeEntry[] | null {
  const layout = params?.layout;
  if (!Array.isArray(layout) || layout.length < 1 || layout.length > MAX_PAGES) return null;
  const out: ComposeEntry[] = [];
  for (const e of layout) {
    if (e && typeof e === "object" && "blank" in e) {
      if (e.blank !== true || !["previous", "A4", "Letter"].includes(e.size)) return null;
      out.push({ blank: true, size: e.size });
    } else if (e && Number.isInteger(e.source) && e.source >= 1 && e.source <= 1e9 && FIXED_ROTATIONS.has(e.rotate)) {
      out.push({ source: e.source, rotate: e.rotate });
    } else return null;
  }
  return out;
}

/** Runs one request. Never throws a message out: every failure is a code. */
export async function runRequest(req: WorkerRequest): Promise<WorkerResponse> {
  try {
    checkInputs(req);
    const written = { total: 0 };
    const params = req.params as any;
    switch (req.op) {
      case "info": {
        const info = await pdfInfo(readInput(req, 0));
        return { v: 1, ok: true, meta: { info }, parts: [], warnings: [], lost: [] };
      }
      case "merge": {
        if (req.temps.length !== 1) return fail("failed");
        const r = await mergePdfs(req.inputs.length, (i) => readInput(req, i));
        const part = writeTemp(req, 0, r.bytes, written);
        return { v: 1, ok: true, meta: { pageCount: r.pageCount, pageCounts: r.pageCounts }, parts: [part], warnings: r.warnings, lost: r.lost };
      }
      case "extract": {
        if (req.temps.length !== 1 || !isIntArray(params?.pages, 0, 1e9) || params.pages.length < 1) return fail("failed");
        const r = await extractPagesTo(readInput(req, 0), params.pages);
        const part = writeTemp(req, 0, r.bytes, written);
        return { v: 1, ok: true, meta: { pageCount: r.pageCount }, parts: [part], warnings: r.warnings, lost: r.lost };
      }
      case "split": {
        const ranges = params?.ranges;
        if (!Array.isArray(ranges) || ranges.length < 1 || ranges.length !== req.temps.length) return fail("failed");
        let total = 0;
        for (const r of ranges) {
          if (!isIntArray(r, 0, 1e9) || r.length < 1) return fail("failed");
          total += r.length;
        }
        if (total > MAX_PAGES) return fail("too_many_pages");
        const bytes = readInput(req, 0);
        const parts: { temp: string; byteSize: number }[] = [];
        const pageCounts: number[] = [];
        const lost = new Set<LostCode>();
        const warnings = new Set<string>();
        // Parsed once; each range is a full default-deny extraction from that parse.
        const extractor = await openRangeExtractor(bytes);
        for (let i = 0; i < ranges.length; i++) {
          const r = await extractor.extract(ranges[i]);
          parts.push(writeTemp(req, i, r.bytes, written));
          pageCounts.push(r.pageCount);
          r.lost.forEach((l) => lost.add(l));
          r.warnings.forEach((w) => warnings.add(w));
        }
        return { v: 1, ok: true, meta: { pageCounts }, parts, warnings: [...warnings], lost: [...lost] };
      }
      case "compose": {
        const layout = parseCompose(params);
        if (!layout || req.temps.length !== 1) return fail("failed");
        const r = await composePages(readInput(req, 0), layout);
        const part = writeTemp(req, 0, r.bytes, written);
        return { v: 1, ok: true, meta: { pageCount: r.pageCount, layout: r.layout }, parts: [part], warnings: r.warnings, lost: r.lost };
      }
    }
  } catch (e) {
    if (e instanceof EditRefusal) {
      const d = e.detail;
      return fail(e.code, {
        ...(typeof d.item === "number" ? { item: d.item } : {}),
        ...(d.pageCount !== undefined ? { pageCount: d.pageCount } : {}),
        ...(d.inputIndex !== undefined ? { inputIndex: d.inputIndex } : {}),
      });
    }
    if (isEncryptedError(e)) return fail("encrypted");
    return fail("failed");
  }
}

// ---------------------------------------------------------------------------
// Process roles
// ---------------------------------------------------------------------------

const SELF = fileURLToPath(import.meta.url);

function isEntry(): boolean {
  const entry = process.argv[1];
  if (entry === undefined) return false;
  try {
    return import.meta.url === pathToFileURL(realpathSync(entry)).href;
  } catch {
    return false;
  }
}

function heapLimitMb(): number | undefined {
  for (const a of process.execArgv) {
    const m = /^--max-old-space-size=(\d+)$/.exec(a);
    if (m) return Number(m[1]);
  }
  return undefined;
}

function respondAndExit(resp: WorkerResponse, code: number): void {
  let line = JSON.stringify(resp) + "\n";
  if (Buffer.byteLength(line) > MAX_RESPONSE_BYTES) line = JSON.stringify(fail("failed")) + "\n";
  process.stdout.write(line, () => process.exit(code));
}

function childMain(): void {
  let buf = "";
  let started = false;
  // Tied to the server: when its end of stdin closes, so do we.
  process.stdin.on("end", () => process.exit(0));
  process.stdin.on("close", () => process.exit(0));
  process.stdin.on("error", () => process.exit(0));
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk: string) => {
    if (started) return;
    buf += chunk;
    if (buf.length > MAX_REQUEST_BYTES) return respondAndExit(fail("failed"), 3);
    const nl = buf.indexOf("\n");
    if (nl === -1) return;
    started = true;
    let req: WorkerRequest | null = null;
    try {
      req = parseRequest(JSON.parse(buf.slice(0, nl)));
    } catch {
      req = null;
    }
    if (!req) return respondAndExit(fail("failed"), 3);
    // The child's own backstop, in case the server is gone and stdin never ends.
    setTimeout(() => process.exit(2), req.timeoutMs + 5000);
    const mb = heapLimitMb();
    let answered = false;
    const worker = new Worker(SELF, {
      workerData: req,
      ...(mb ? { resourceLimits: { maxOldGenerationSizeMb: mb } } : {}),
    });
    worker.on("message", (resp: WorkerResponse) => {
      answered = true;
      respondAndExit(resp, 0);
    });
    worker.on("error", () => process.exit(1));
    worker.on("exit", () => {
      if (!answered) process.exit(1);
    });
  });
}

if (isMainThread) {
  if (isEntry()) childMain();
} else if (parentPort) {
  const port = parentPort;
  runRequest(workerData as WorkerRequest).then(
    (resp) => port.postMessage(resp),
    () => port.postMessage(fail("failed")),
  );
}
