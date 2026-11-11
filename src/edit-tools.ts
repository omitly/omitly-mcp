/**
 * omitly#1841 phase B: five free page tools — `pdf_info`, `merge_pdfs`,
 * `extract_pages`, `split_pdf`, `edit_pages` (design 4.1 to 4.5).
 *
 * What this file is: registration, path confinement, the child-process runner and
 * file placement. The pdf-lib work is in `pdf-edit/` and runs in a CHILD PROCESS
 * (`pdf-edit/worker.js`), so a hostile PDF can hang or crash that process and not
 * this server. The child writes temp files the server names; the server then
 * PLACES them, create-only, never by `rename` (which overwrites).
 *
 * What these tools never do (decisions 2C and 3B, section 4.5): go through the
 * desktop accept-in-app queue, need a licence, carry an EVALUATION banner, count
 * toward the free leak-check cap, or make a network call. This file therefore
 * imports nothing from `desktop.ts` or `usage.ts`; a structural test asserts it.
 *
 * The worst a call can do is write a NEW `.pdf` inside the allowed root, outside
 * hidden folders and `.git`, within the size limits.
 */
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
  closeSync,
  fstatSync,
  linkSync,
  lstatSync,
  mkdtempSync,
  openSync,
  readSync,
  realpathSync,
  rmSync,
  statSync,
  unlinkSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { PDFDocument } from "pdf-lib";
import { z } from "zod";
import { allowedRoot, confineDir, confineInput, confineOutput } from "./paths.js";
import { FONT_RENAME_WARNING, LAYERS_WARNING, RENAME_WARNING, SIGNATURE_WARNING } from "./pdf-edit/docFacts.js";
import {
  expandPageSpec,
  isContiguousAscending,
  splitFileName,
  SPLIT_PREFIX,
  MAX_EXPANDED_PAGES,
} from "./pdf-edit/pageSpec.js";
import { CHILD_CODES, EditRefusal, messageFor, type EditCode } from "./pdf-edit/refusals.js";
import type { WorkerRequest } from "./pdf-edit/worker.js";
import { annotations } from "./annotations.js";

// ---------------------------------------------------------------------------
// Limits (design 4.1, 4.2). The 2048 MB heap and the 120 s budget are set from
// the timed probes before B merges; tests override them through the seam.
// ---------------------------------------------------------------------------

const MiB = 1024 * 1024;
export const DEFAULT_CAPS = {
  /** Largest input PDF (and, for single-input ops, the largest output). */
  perFileBytes: 200 * MiB,
  /** merge: all inputs together, and the merged output. */
  totalBytes: 500 * MiB,
  /** split: everything written by one call. */
  splitTotalBytes: 1024 * MiB,
};
export const DEFAULT_MAX_OLD_SPACE_MB = 2048;
export const DEFAULT_TIMEOUT_MS = 120_000;
const PING_TIMEOUT_MS = 5_000;
const MAX_CONCURRENT = 2;
const MAX_WAITING = 8;
const MAX_STDOUT = 1024 * 1024;
const MAX_STDERR = 64 * 1024;
const MAX_SPLIT_RANGES = 100;
const COPY_CHUNK = 1024 * 1024;

export interface EditToolsOptions {
  /** The allowed root. Default: `allowedRoot()` at registration. */
  root?: string;
  /** Whether the root came from OMITLY_ALLOWED_DIR (default: it is set and non-empty). */
  rootExplicit?: boolean;
  workerPath?: string;
  /** Node options placed before the worker script; stub workers read their behaviour here. */
  workerArgs?: string[];
  maxOldSpaceMb?: number;
  timeoutMs?: number;
  /** Replace `fs.linkSync` (tests force the copy fallback with it). */
  link?: (existing: string, newPath: string) => void;
  /** Called with the final path just before it is placed (tests create it first). */
  beforePlace?: (finalPath: string) => void;
  caps?: Partial<typeof DEFAULT_CAPS>;
}

// ---------------------------------------------------------------------------
// Pure rules (unit-tested)
// ---------------------------------------------------------------------------

/**
 * The default-root rule (design 4.4). When OMITLY_ALLOWED_DIR is unset (or empty
 * after trimming) the root is the working directory; if that is the filesystem
 * root or the user's home, the five tools refuse rather than be handed everything.
 * `home` must already be a real path. `platform` is an argument so the comparison is unit-tested for
 * win32, darwin and linux.
 */
export function rootNeedsExplicitDir(
  root: string,
  explicit: boolean,
  home: string | undefined,
  platform: string = process.platform,
  sameDir: (a: string, b: string) => boolean = statSameDir,
): boolean {
  if (explicit) return false;
  // `home` is undefined when it cannot be determined (no HOME and no passwd entry): then only the
  // filesystem-root check applies.
  const pathLib = platform === "win32" ? path.win32 : path.posix;
  return sameDir(root, pathLib.parse(root).root) || (home !== undefined && sameDir(root, home));
}

/**
 * Are `a` and `b` the same FOLDER? By file identity (device and inode, as bigints, which also works on
 * Windows), not by name: a name comparison is wrong in both directions (`A` and `a` are two folders on a
 * case-sensitive APFS volume, one folder on the default). Only if either path cannot be stat'ed does it fall
 * back to comparing names, folded where the platform's default filesystem ignores case.
 */
export function statSameDir(a: string, b: string, platform: string = process.platform): boolean {
  try {
    const x = statSync(a, { bigint: true });
    const y = statSync(b, { bigint: true });
    if (x.ino !== 0n || y.ino !== 0n) return x.dev === y.dev && x.ino === y.ino;
  } catch {
    /* fall through to names */
  }
  return foldedSameDir(platform)(a, b);
}

/** Name comparison: resolved, no trailing separator, case-folded on Windows and macOS (the default filesystems), exact on Linux. */
export function foldedSameDir(platform: string): (a: string, b: string) => boolean {
  const fold = (p: string) => {
    const resolved = platform === "win32" ? path.win32.resolve(p) : path.posix.resolve(p);
    return platform === "win32" || platform === "darwin" ? resolved.toLowerCase() : resolved;
  };
  return (a, b) => fold(a) === fold(b);
}

/**
 * The child's environment. We pass an EMPTY one on every platform (filtering by name misses Windows'
 * `Path` casing): NODE_OPTIONS and OMITLY_* never reach the child, which takes all its settings from
 * the request. (On Windows the child still ends up with a few system variables, HOMEDRIVE, HOMEPATH,
 * LOGONSERVER, PATH, SYSTEMDRIVE, SYSTEMROOT, TEMP, USERDOMAIN, USERNAME, USERPROFILE and WINDIR:
 * libuv's make_program_env copies them from the parent into any child environment that lacks them.
 * They are not ours to prevent, and none of them reaches the agent.) Two exceptions, each for a reason:
 *  - inside an Electron-hosted client `process.execPath` is the app, so it must run as Node;
 *  - on Windows a process started with no `SystemRoot`/`WINDIR` can fail to start at all (and the
 *    first-use ping would then disable the tools for the session), so exactly those two are
 *    copied, found case-insensitively. Nothing else is.
 */
export function childEnvironment(opts: { platform: string; env: NodeJS.ProcessEnv; electron: boolean }): Record<string, string> {
  const out: Record<string, string> = {};
  if (opts.platform === "win32") {
    for (const want of ["SystemRoot", "WINDIR"]) {
      const key = Object.keys(opts.env).find((k) => k.toLowerCase() === want.toLowerCase());
      const v = key === undefined ? undefined : opts.env[key];
      if (v !== undefined) out[want] = v;
    }
  }
  if (opts.electron) out.ELECTRON_RUN_AS_NODE = "1";
  return out;
}

const DEVICE_NAME = /^(CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[0-9¹²³]|LPT[0-9¹²³])$/i;

/**
 * Output name rules, on every platform: `.pdf` (case-insensitive); no `:` (a
 * Windows alternate data stream, `x.pdf:hidden`); no Windows device name (`CON`,
 * `PRN`, `AUX`, `NUL`, `CONIN$`, `CONOUT$`, `COM0`-`COM9`, `LPT0`-`LPT9`, with or without an
 * extension); no trailing dot or space. Returns the refusal code, or null.
 */
export function outputNameRefusal(name: string): EditCode | null {
  if (!name.toLowerCase().endsWith(".pdf")) return "not_pdf_name";
  if (name.includes(":")) return "not_pdf_name";
  if (/[. ]$/.test(name)) return "not_pdf_name";
  // Windows treats `CON.anything` as the device: the part before the first dot.
  const stem = name.split(".")[0].replace(/ +$/, "");
  if (DEVICE_NAME.test(stem)) return "not_pdf_name";
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f<>"|?*\\/]/.test(name)) return "not_pdf_name";
  return null;
}

/** Hidden-path rule, measured on the path RELATIVE to the root so a root that
 *  itself sits under a dot-folder still works. Any segment starting with a dot. */
export function isHiddenRelative(root: string, realOutput: string): boolean {
  const rel = path.relative(root, realOutput);
  return rel.split(path.sep).some((seg) => seg.startsWith("."));
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/** A message from confineInput / confineOutput / confineDir, passed through verbatim. */
class PassThrough extends Error {}

function pass<T>(fn: () => T): T {
  try {
    return fn();
  } catch (e) {
    throw new PassThrough((e as Error).message);
  }
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------
// Worker response (validated: the child is untrusted too)
// ---------------------------------------------------------------------------

const LOST_CODES = ["outlines", "info", "page_labels", "xfa", "layers"] as const;
const KNOWN_WARNINGS = new Set([SIGNATURE_WARNING, LAYERS_WARNING, RENAME_WARNING, FONT_RENAME_WARNING]);

const workerOk = z.object({
  v: z.literal(1),
  ok: z.literal(true),
  meta: z.record(z.string(), z.unknown()),
  parts: z.array(z.object({ temp: z.string(), byteSize: z.number().int().nonnegative() }).strict()).max(MAX_SPLIT_RANGES),
  warnings: z.array(z.string()).max(20),
  lost: z.array(z.enum(LOST_CODES)).max(10),
});
const workerErr = z.object({
  v: z.literal(1),
  ok: z.literal(false),
  code: z.string().max(64),
  item: z.number().int().optional(),
  pageCount: z.number().int().nonnegative().optional(),
  inputIndex: z.number().int().positive().optional(),
});

interface JobResult {
  meta: Record<string, unknown>;
  finals: string[];
  byteSizes: number[];
  warnings: string[];
  lost: (typeof LOST_CODES)[number][];
}

interface Job {
  op: WorkerRequest["op"];
  /** Confined real paths. */
  inputs: string[];
  /** Confined real folder the temp files are written into. */
  outDir: string;
  /** Confined real final paths, one per output part (empty for `info`). */
  finals: string[];
  params: unknown;
  caps: { perFileBytes: number; totalBytes: number };
}

interface ChildOutcome {
  code: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  oversize: boolean;
  timedOut: boolean;
  aborted: boolean;
  spawnError: boolean;
}

// ---------------------------------------------------------------------------
// The runner: slots, ping, spawn, kill, place, clean up
// ---------------------------------------------------------------------------

/** Exported for tests only (the slot queue is exercised directly). */
export class EditRunner {
  private running = 0;
  private waiting: { grant: () => void; reject: (e: unknown) => void }[] = [];
  private ping: Promise<boolean> | undefined;

  constructor(private readonly o: Required<Pick<EditToolsOptions, "workerPath" | "workerArgs" | "maxOldSpaceMb" | "timeoutMs">> & Pick<EditToolsOptions, "link" | "beforePlace">) {}

  async run(job: Job, signal?: AbortSignal): Promise<JobResult> {
    const release = await this.acquire(signal);
    try {
      if (!(await this.ensurePing())) throw new EditRefusal("failed");
      return await this.execute(job, signal);
    } finally {
      release();
    }
  }

  // --- concurrency: two workers at once, eight calls waiting, a ninth refused ---

  private acquire(signal?: AbortSignal): Promise<() => void> {
    // A call already cancelled takes neither a slot nor a place in the queue.
    if (signal?.aborted) return Promise.reject(new EditRefusal("failed"));
    const make = () => {
      let released = false;
      return () => {
        if (released) return;
        released = true;
        const next = this.waiting.shift();
        if (next) next.grant();
        else this.running--;
      };
    };
    if (this.running < MAX_CONCURRENT) {
      this.running++;
      return Promise.resolve(make());
    }
    if (this.waiting.length >= MAX_WAITING) return Promise.reject(new EditRefusal("busy"));
    return new Promise((resolve, reject) => {
      const entry = { grant: () => resolve(make()), reject };
      this.waiting.push(entry);
      signal?.addEventListener(
        "abort",
        () => {
          const i = this.waiting.indexOf(entry);
          if (i !== -1) {
            this.waiting.splice(i, 1);
            reject(new EditRefusal("failed"));
          }
        },
        { once: true },
      );
    });
  }

  // --- first use: a 5-second ping, so a child that cannot start fails fast ---

  private ensurePing(): Promise<boolean> {
    this.ping ??= this.doPing();
    return this.ping;
  }

  private async doPing(): Promise<boolean> {
    let dir: string | undefined;
    try {
      const doc = await PDFDocument.create({ updateMetadata: false });
      doc.addPage([200, 200]);
      dir = mkdtempSync(path.join(realpathSync(os.tmpdir()), "omitly-edit-ping-"));
      const file = path.join(dir, "ping.pdf");
      writeFileSync(file, await doc.save());
      const req: WorkerRequest = {
        v: 1,
        op: "info",
        inputs: [file],
        outDir: dir,
        temps: [],
        caps: { perFileBytes: MiB, totalBytes: MiB },
        timeoutMs: PING_TIMEOUT_MS,
        params: {},
      };
      const out = await this.spawnChild(req, PING_TIMEOUT_MS, undefined);
      const parsed = this.parseOutcome(out);
      const info = parsed.ok ? (parsed.value.meta.info as { pageCount?: unknown } | undefined) : undefined;
      if (parsed.ok && info?.pageCount === 1) return true;
      // Logged locally for the person running the server; never returned to the agent.
      console.error(
        `[omitly-mcp] the PDF edit worker did not answer its start-up check (exit ${out.code}, signal ${out.signal}); ` +
          `the page tools are disabled for this session. ${out.stderr.slice(0, 2000)}`,
      );
      return false;
    } catch (e) {
      console.error(`[omitly-mcp] the PDF edit worker start-up check failed: ${(e as Error).message}`);
      return false;
    } finally {
      if (dir) rmSync(dir, { recursive: true, force: true });
    }
  }

  // --- the child ---

  private spawnChild(req: WorkerRequest, timeoutMs: number, signal: AbortSignal | undefined): Promise<ChildOutcome> {
    return new Promise((resolve) => {
      const env = childEnvironment({ platform: process.platform, env: process.env, electron: Boolean(process.versions.electron) });
      const child = spawn(
        process.execPath,
        [...this.o.workerArgs, `--max-old-space-size=${this.o.maxOldSpaceMb}`, this.o.workerPath],
        { env, stdio: ["pipe", "pipe", "pipe"], windowsHide: true },
      );
      const out: ChildOutcome = {
        code: null,
        signal: null,
        stdout: "",
        stderr: "",
        oversize: false,
        timedOut: false,
        aborted: false,
        spawnError: false,
      };
      const kill = () => {
        try {
          child.kill("SIGKILL");
        } catch {
          /* already gone */
        }
      };
      const timer = setTimeout(() => {
        out.timedOut = true;
        kill();
      }, timeoutMs);
      const onAbort = () => {
        out.aborted = true;
        kill();
      };
      if (signal?.aborted) onAbort();
      else signal?.addEventListener("abort", onAbort, { once: true });

      child.stdout.setEncoding("utf8");
      child.stdout.on("data", (d: string) => {
        if (out.oversize) return;
        out.stdout += d;
        if (out.stdout.length > MAX_STDOUT) {
          out.oversize = true;
          out.stdout = "";
          kill();
        }
      });
      child.stderr.setEncoding("utf8");
      child.stderr.on("data", (d: string) => {
        if (out.stderr.length < MAX_STDERR) out.stderr += d.slice(0, MAX_STDERR - out.stderr.length);
      });
      child.stdin.on("error", () => {
        /* the child may already be dead; its exit is handled below */
      });
      child.on("error", () => {
        out.spawnError = true;
        clearTimeout(timer);
        signal?.removeEventListener("abort", onAbort);
        resolve(out);
      });
      // `close`, not `exit`: stdout is drained, and a killed child has stopped writing.
      child.on("close", (code, sig) => {
        clearTimeout(timer);
        signal?.removeEventListener("abort", onAbort);
        out.code = code;
        out.signal = sig;
        // The pipe is left open until now: ending stdin is how the child learns the
        // server is gone, so the server must not end it while it is still working.
        resolve(out);
      });
      // One JSON line. stdin stays open until the child exits.
      child.stdin.write(JSON.stringify(req) + "\n");
    });
  }

  private parseOutcome(
    out: ChildOutcome,
  ): { ok: true; value: z.infer<typeof workerOk> } | { ok: false; error: z.infer<typeof workerErr> | null } {
    if (out.spawnError || out.oversize || out.code !== 0 || out.signal) return { ok: false, error: null };
    const text = out.stdout.trim();
    if (text === "" || text.includes("\n")) return { ok: false, error: null };
    let json: unknown;
    try {
      json = JSON.parse(text);
    } catch {
      return { ok: false, error: null };
    }
    const good = workerOk.safeParse(json);
    if (good.success) return { ok: true, value: good.data };
    const bad = workerErr.safeParse(json);
    return { ok: false, error: bad.success ? bad.data : null };
  }

  // --- one call ---

  private async execute(job: Job, signal: AbortSignal | undefined): Promise<JobResult> {
    const callId = randomBytes(8).toString("hex");
    const temps = job.finals.map((_, i) => `.omitly-tmp-${callId}-${i}.pdf`);
    const issued = temps.map((t) => path.join(job.outDir, t));
    /** Files this call created, by the inode it created: only these are ever removed on failure. */
    const ours = new Map<string, { dev: number; ino: number }>();
    let ok = false;
    try {
      const req: WorkerRequest = {
        v: 1,
        op: job.op,
        inputs: job.inputs,
        outDir: job.outDir,
        temps,
        caps: job.caps,
        timeoutMs: this.o.timeoutMs,
        params: job.params,
      };
      const out = await this.spawnChild(req, this.o.timeoutMs, signal);
      if (out.timedOut) throw new EditRefusal("timeout");
      if (out.aborted) throw new EditRefusal("failed");
      const parsed = this.parseOutcome(out);
      if (!parsed.ok) {
        const e = parsed.error;
        if (e && CHILD_CODES.has(e.code)) {
          throw new EditRefusal(e.code as EditCode, { item: e.item, pageCount: e.pageCount, inputIndex: e.inputIndex });
        }
        throw new EditRefusal("failed");
      }
      const res = parsed.value;

      // Parts: exactly the names this call issued, in order.
      if (res.parts.length !== temps.length) throw new EditRefusal("failed");
      res.parts.forEach((p, i) => {
        if (p.temp !== temps[i]) throw new EditRefusal("failed");
      });
      const byteSizes: number[] = [];
      for (let i = 0; i < res.parts.length; i++) {
        const temp = issued[i];
        const st = lstatSync(temp, { throwIfNoEntry: false });
        if (!st || !st.isFile() || st.size !== res.parts[i].byteSize) throw new EditRefusal("failed");
        const head = Buffer.alloc(5);
        const fd = openSync(temp, "r");
        try {
          readSync(fd, head, 0, 5, 0);
        } finally {
          closeSync(fd);
        }
        if (head.toString("latin1") !== "%PDF-") throw new EditRefusal("failed");
        byteSizes.push(st.size);
      }

      // Place: create-only. A link fails with EEXIST if the name is taken (a dangling
      // symlink included) and never overwrites; where hard links are impossible
      // (FAT32, exFAT, many network shares) the fallback opens the final name with `wx`
      // (O_EXCL) and copies the bytes into THAT descriptor, so it is create-only too and
      // the server knows it created the file it may later have to remove.
      //
      // RESIDUAL WINDOW (stated, not closed): the output folder was confined to a real path
      // at the start of the call. A hostile LOCAL user who swaps that folder (or a parent)
      // for a symlink between our check and the link/open system call can still redirect one
      // write. Hostile local users are outside this server's threat model (paths.ts). What is
      // done about it: the child checks the folder's real path before it writes each temp, and
      // the server checks it immediately before AND after each placement; a mismatch after
      // placement removes what this call placed (by inode) and refuses `write_failed`.
      // Also accepted: if another process RENAMES the folder mid-call, the call returns `write_failed`
      // but files already placed, and a temp, can remain under the renamed folder, because cleanup goes
      // by the original path (Node has no directory handles; same root cause as the window above).
      const link = this.o.link ?? linkSync;
      const dirIsConfined = (final: string): boolean => {
        try {
          return realpathSync(path.dirname(final)) === job.outDir;
        } catch {
          return false;
        }
      };
      for (let i = 0; i < job.finals.length; i++) {
        const final = job.finals[i];
        if (!dirIsConfined(final)) throw new EditRefusal("write_failed");
        this.o.beforePlace?.(final);
        const before = lstatSync(issued[i], { throwIfNoEntry: false });
        let created: { dev: number; ino: number } | undefined;
        try {
          link(issued[i], final);
          const st = lstatSync(final, { throwIfNoEntry: false });
          // The inode we linked in; if the name now holds something else, it is not ours.
          if (st && before && st.ino === before.ino && st.dev === before.dev) created = { dev: st.dev, ino: st.ino };
          if (created) ours.set(final, created);
        } catch (e) {
          if ((e as NodeJS.ErrnoException).code === "EEXIST") throw new EditRefusal("output_exists");
          let fd: number;
          try {
            fd = openSync(final, "wx", 0o600);
          } catch (e2) {
            if ((e2 as NodeJS.ErrnoException).code === "EEXIST") throw new EditRefusal("output_exists");
            throw new EditRefusal("write_failed");
          }
          // From here on the file at `final` is ours: any failure removes it.
          const mine = fstatSync(fd);
          ours.set(final, { dev: mine.dev, ino: mine.ino });
          try {
            // In fixed chunks: the child exists to keep big buffers out of THIS process, and a
            // split can write up to 1 GB.
            const from = openSync(issued[i], "r");
            try {
              const chunk = Buffer.allocUnsafe(COPY_CHUNK);
              for (;;) {
                const n = readSync(from, chunk, 0, COPY_CHUNK, null);
                if (n === 0) break;
                let off = 0;
                while (off < n) off += writeSync(fd, chunk, off, n - off);
              }
            } finally {
              closeSync(from);
            }
          } catch {
            throw new EditRefusal("write_failed");
          } finally {
            closeSync(fd);
          }
        }
        if (!dirIsConfined(final)) throw new EditRefusal("write_failed");
        const st = lstatSync(final, { throwIfNoEntry: false });
        if (!st || !st.isFile() || st.size !== byteSizes[i]) throw new EditRefusal("write_failed");
        await removeQuiet(issued[i]);
      }
      ok = true;
      return {
        meta: res.meta,
        finals: [...job.finals],
        byteSizes,
        warnings: res.warnings.filter((w) => KNOWN_WARNINGS.has(w)),
        lost: res.lost,
      };
    } catch (e) {
      if (e instanceof EditRefusal) throw e;
      throw new EditRefusal("failed");
    } finally {
      // The child has already closed (spawnChild resolves on `close`), so nothing
      // is still writing. Only names THIS call issued and finals THIS call created (by inode);
      // never a directory sweep, so another call's files are never touched.
      for (const t of issued) await removeQuiet(t);
      if (!ok) for (const [f, id] of ours) await removeQuiet(f, id);
    }
  }
}

/** lstat then unlink; retries EBUSY/EPERM briefly (Windows holds a just-killed child's files). */
async function removeQuiet(file: string, only?: { dev: number; ino: number }): Promise<void> {
  for (let attempt = 0; attempt < 6; attempt++) {
    try {
      const st = lstatSync(file, { throwIfNoEntry: false });
      if (st === undefined) return;
      // `only`: remove it only if it is still the very file this call created.
      if (only && (st.ino !== only.ino || st.dev !== only.dev)) return;
      unlinkSync(file);
      return;
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code;
      if (code === "ENOENT") return;
      if (code !== "EBUSY" && code !== "EPERM" && code !== "EACCES") return;
      await sleep(50);
    }
  }
}

// ---------------------------------------------------------------------------
// Output schemas (strict; `warnings` and `lost` on every writer)
// ---------------------------------------------------------------------------

const lostSchema = z.array(z.enum(LOST_CODES));
const warningsSchema = z.array(z.string());

const pageInfoSchema = z
  .object({
    pageNumber: z.number().int(),
    widthPt: z.number().nullable(),
    heightPt: z.number().nullable(),
    rotation: z.number().nullable(),
  })
  .strict();

export const pdfInfoOutputSchema = z
  .object({
    pageCount: z.number().int(),
    pages: z.array(pageInfoSchema),
    pagesTruncated: z.boolean(),
    encrypted: z.boolean().nullable(),
    hasForm: z.boolean().nullable(),
    formFieldCount: z.number().int().nullable(),
    hasSignatures: z.boolean().nullable(),
    hasComments: z.boolean().nullable(),
    hasXfa: z.enum(["none", "static", "dynamic"]).nullable(),
    hasLayers: z.boolean().nullable(),
    byteSize: z.number().int(),
  })
  .strict();

export const mergeOutputSchema = z
  .object({
    outputPath: z.string(),
    pageCount: z.number().int(),
    byteSize: z.number().int(),
    sources: z.array(z.object({ input: z.string(), pages: z.number().int() }).strict()),
    lost: lostSchema,
    warnings: warningsSchema,
  })
  .strict();

export const extractOutputSchema = z
  .object({
    outputPath: z.string(),
    pageCount: z.number().int(),
    byteSize: z.number().int(),
    sourcePages: z.array(z.number().int()),
    lost: lostSchema,
    warnings: warningsSchema,
  })
  .strict();

export const splitOutputSchema = z
  .object({
    files: z.array(
      z
        .object({
          outputPath: z.string(),
          sourcePages: z.array(z.number().int()),
          pageCount: z.number().int(),
          byteSize: z.number().int(),
        })
        .strict(),
    ),
    lost: lostSchema,
    warnings: warningsSchema,
  })
  .strict();

export const editPagesOutputSchema = z
  .object({
    outputPath: z.string(),
    pageCount: z.number().int(),
    byteSize: z.number().int(),
    layout: z.array(
      z
        .object({
          pageNumber: z.number().int(),
          from: z.union([z.number().int(), z.literal("blank")]),
          rotation: z.number(),
        })
        .strict(),
    ),
    lost: lostSchema,
    warnings: warningsSchema,
  })
  .strict();

/** Same job as `checked()` in index.ts (kept local: index.ts imports this file). */
function checkedOut<T extends z.ZodTypeAny>(schema: T, value: unknown): z.infer<T> {
  const parsed = schema.safeParse(value);
  if (!parsed.success) throw new EditRefusal("failed");
  return parsed.data;
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

const PAGE_RULE =
  "Page numbers start at 1 (the check tools return 0-based `page` values: add 1). ";
const PAGES_ITEM_DESC =
  'A page number like 3 or a range like "2-5". A bare-number string ("5"), a leading zero, a reversed range and a repeated page are refused.';
const NEW_FILE_RULE =
  "Writes a NEW .pdf inside the allowed folder and never changes or overwrites an existing file. ";
const NOT_REDACTION =
  "This is not redaction and does not sanitise: pages you leave out are not copied, but document metadata, " +
  "bookmark titles and anything a kept page shares with an omitted page can remain. Use redact_pdf to remove sensitive content. " +
  "Nothing is uploaded.";
const NOT_REDACTION_MERGE =
  "This is not redaction and does not sanitise. Use redact_pdf to remove sensitive content. Nothing is uploaded.";

const pageItem = z.union([z.number(), z.string()]).describe(PAGES_ITEM_DESC);

function text(t: string, isError = false) {
  return { content: [{ type: "text" as const, text: t }], ...(isError ? { isError: true } : {}) };
}

function refusalResult(e: unknown) {
  if (e instanceof EditRefusal || e instanceof PassThrough) return text(e.message, true);
  // Never an exception message: it could carry a path or document content.
  return text(messageFor("failed"), true);
}

export function registerEditTools(server: McpServer, options: EditToolsOptions = {}): void {
  const root = options.root ?? allowedRoot();
  const rootExplicit = options.rootExplicit ?? Boolean(process.env.OMITLY_ALLOWED_DIR?.trim());
  const caps = { ...DEFAULT_CAPS, ...options.caps };
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const runner = new EditRunner({
    workerPath: options.workerPath ?? fileURLToPath(new URL("./pdf-edit/worker.js", import.meta.url)),
    workerArgs: options.workerArgs ?? [],
    maxOldSpaceMb: options.maxOldSpaceMb ?? DEFAULT_MAX_OLD_SPACE_MB,
    timeoutMs,
    link: options.link,
    beforePlace: options.beforePlace,
  });

  function guardRoot(): void {
    // An explicit root never needs the home folder, so do not even ask for it.
    let home: string | undefined;
    if (!rootExplicit) {
      try {
        home = os.homedir();
        home = realpathSync(home);
      } catch {
        /* homedir() throws with no HOME and no passwd entry; an unresolvable path is kept as is */
      }
    }
    if (rootNeedsExplicitDir(root, rootExplicit, home)) throw new EditRefusal("allowed_dir_needed");
  }

  /** confineInput, then stat on the CONFINED path only. */
  function confineInputFile(p: string, inputIndex?: number): { real: string; size: number } {
    const real = pass(() => confineInput(p, root));
    let st;
    try {
      st = statSync(real);
    } catch {
      throw new EditRefusal("not_a_file", { inputIndex });
    }
    if (!st.isFile()) throw new EditRefusal("not_a_file", { inputIndex });
    if (st.size > caps.perFileBytes) throw new EditRefusal("too_large", { inputIndex });
    return { real, size: st.size };
  }

  /** Output name rules, then confineOutput, then the hidden-path rule. */
  function confineNewPdf(p: string): string {
    const nameRefusal = outputNameRefusal(path.basename(path.resolve(root, p)));
    if (nameRefusal) throw new EditRefusal(nameRefusal);
    const real = pass(() => confineOutput(p, root));
    if (isHiddenRelative(root, real)) throw new EditRefusal("hidden_path");
    return real;
  }

  // --- pdf_info ---
  server.registerTool(
    "pdf_info",
    {
      title: "PDF info",
      description:
        "Read basic facts about a PDF without opening it in a viewer: page count, each page's size and rotation " +
        "(first 500 pages), and flags for encryption, forms, signatures, comments, XFA and layers. Returns counts and " +
        "flags only, never text or field values. Works on encrypted files (reports encrypted: true). " +
        PAGE_RULE +
        'Example: {"pdfPath":"invoice.pdf"}. Nothing is uploaded.',
      inputSchema: { pdfPath: z.string().describe("path to the PDF, inside the allowed folder") },
      outputSchema: pdfInfoOutputSchema,
      annotations: annotations("PDF info", true, true),
    },
    async ({ pdfPath }, extra) => {
      try {
        guardRoot();
        const input = confineInputFile(pdfPath);
        const r = await runner.run(
          { op: "info", inputs: [input.real], outDir: path.dirname(input.real), finals: [], params: {}, caps: { perFileBytes: caps.perFileBytes, totalBytes: caps.perFileBytes } },
          extra?.signal,
        );
        const info = checkedOut(pdfInfoOutputSchema, r.meta.info);
        return {
          content: [{ type: "text" as const, text: `${info.pageCount} page(s), ${info.byteSize} bytes.` }],
          structuredContent: info,
        };
      } catch (e) {
        return refusalResult(e);
      }
    },
  );

  // --- merge_pdfs ---
  server.registerTool(
    "merge_pdfs",
    {
      title: "Merge PDFs",
      description:
        "Join 2 to 50 PDFs, in the order given, into one new PDF. All pages of every input are kept. " +
        NEW_FILE_RULE +
        "Form fields are kept (a clashing field name is renamed, with a warning). The result starts from an empty " +
        "document, so bookmarks, document metadata, page labels and layers are not carried over; they are listed in `lost`. " +
        "Digital signatures are removed (the output is a new, unsigned document). " +
        'Example: {"inputs":["a.pdf","b.pdf"],"outputPath":"merged.pdf"}. ' +
        NOT_REDACTION_MERGE,
      inputSchema: {
        inputs: z.array(z.string()).min(2).max(50).describe("PDFs to join, in order"),
        outputPath: z.string().describe("new .pdf to create; must not exist"),
      },
      outputSchema: mergeOutputSchema,
      annotations: annotations("Merge PDFs", false),
    },
    async ({ inputs, outputPath }, extra) => {
      try {
        guardRoot();
        let total = 0;
        const reals = inputs.map((p, i) => {
          const f = confineInputFile(p, i + 1);
          total += f.size;
          if (total > caps.totalBytes) throw new EditRefusal("too_large", { inputIndex: i + 1 });
          return f.real;
        });
        const final = confineNewPdf(outputPath);
        const r = await runner.run(
          { op: "merge", inputs: reals, outDir: path.dirname(final), finals: [final], params: {}, caps: { perFileBytes: caps.perFileBytes, totalBytes: caps.totalBytes } },
          extra?.signal,
        );
        const meta = checkedOut(z.object({ pageCount: z.number().int(), pageCounts: z.array(z.number().int()).length(inputs.length) }), r.meta);
        const structuredContent = checkedOut(mergeOutputSchema, {
          outputPath: r.finals[0],
          pageCount: meta.pageCount,
          byteSize: r.byteSizes[0],
          sources: inputs.map((input, i) => ({ input, pages: meta.pageCounts[i] })),
          lost: r.lost,
          warnings: r.warnings,
        });
        return {
          content: [{ type: "text" as const, text: `Merged ${inputs.length} PDFs into ${r.finals[0]} (${meta.pageCount} pages).` }],
          structuredContent,
        };
      } catch (e) {
        return refusalResult(e);
      }
    },
  );

  // --- extract_pages ---
  server.registerTool(
    "extract_pages",
    {
      title: "Extract pages",
      description:
        "Copy chosen pages of a PDF into one new PDF, in the order listed. " +
        PAGE_RULE +
        NEW_FILE_RULE +
        "Pages are an array of numbers and ranges; a page may not be listed twice. Bookmarks to kept pages, metadata " +
        "and form fields on kept pages are kept; layers and static XFA are dropped (listed in `lost`). Digital signatures " +
        "are removed. A dynamic XFA form or an encrypted PDF is refused. " +
        'Example: {"pdfPath":"report.pdf","pages":[1,"3-5"],"outputPath":"report-part.pdf"}. ' +
        NOT_REDACTION,
      inputSchema: {
        pdfPath: z.string().describe("path to the PDF, inside the allowed folder"),
        pages: z.array(pageItem).min(1).max(1000).describe("pages to keep, 1-based, in output order"),
        outputPath: z.string().describe("new .pdf to create; must not exist"),
      },
      outputSchema: extractOutputSchema,
      annotations: annotations("Extract pages", false),
    },
    async ({ pdfPath, pages, outputPath }, extra) => {
      try {
        guardRoot();
        const spec = expandPageSpec(pages);
        const input = confineInputFile(pdfPath);
        const final = confineNewPdf(outputPath);
        const r = await runner
          .run(
            { op: "extract", inputs: [input.real], outDir: path.dirname(final), finals: [final], params: { pages: spec.pages.map((p) => p - 1) }, caps: { perFileBytes: caps.perFileBytes, totalBytes: caps.perFileBytes } },
            extra?.signal,
          )
          .catch((e) => {
            throw withItem(e, spec.pages, spec.itemOf.map((i) => pages[i]));
          });
        const meta = checkedOut(z.object({ pageCount: z.number().int() }), r.meta);
        const structuredContent = checkedOut(extractOutputSchema, {
          outputPath: r.finals[0],
          pageCount: meta.pageCount,
          byteSize: r.byteSizes[0],
          sourcePages: spec.pages,
          lost: r.lost,
          warnings: r.warnings,
        });
        return {
          content: [{ type: "text" as const, text: `Extracted ${meta.pageCount} page(s) to ${r.finals[0]}.` }],
          structuredContent,
        };
      } catch (e) {
        return refusalResult(e);
      }
    },
  );

  // --- split_pdf ---
  server.registerTool(
    "split_pdf",
    {
      title: "Split PDF",
      description:
        "Split a PDF into several new PDFs, one per range. " +
        PAGE_RULE +
        "Each range is a page spec (numbers and ranges) of consecutive pages in order, such as [\"1-3\"] or [4,5]; each " +
        "file is named `<prefix>-p<first>-<last>.pdf` (or `<prefix>-p<first>.pdf` for one page) inside `outputDir`. " +
        "All files are created or none are. " +
        NEW_FILE_RULE +
        "Layers and static XFA are dropped (listed in `lost`); digital signatures are removed. " +
        'Example: {"pdfPath":"book.pdf","ranges":[["1-10"],["11-20"]],"outputDir":"parts","prefix":"book"}. ' +
        NOT_REDACTION,
      inputSchema: {
        pdfPath: z.string().describe("path to the PDF, inside the allowed folder"),
        ranges: z.array(z.array(pageItem).min(1).max(1000)).min(1).max(MAX_SPLIT_RANGES).describe("one page spec per output file"),
        outputDir: z.string().describe("existing folder inside the allowed folder (the allowed folder itself is fine)"),
        prefix: z.string().regex(SPLIT_PREFIX).describe("file name prefix: letters, digits, . _ -, up to 64"),
      },
      outputSchema: splitOutputSchema,
      annotations: annotations("Split PDF", false),
    },
    async ({ pdfPath, ranges, outputDir, prefix }, extra) => {
      try {
        guardRoot();
        // Syntax, duplicates, the 10,000-page total, contiguity and names: before any I/O on the file.
        let budget = MAX_EXPANDED_PAGES;
        const expanded = ranges.map((spec) => {
          const e = expandPageSpec(spec, { budget });
          budget -= e.pages.length;
          if (!isContiguousAscending(e.pages)) throw new EditRefusal("split_not_contiguous");
          return e;
        });
        const names = expanded.map((e) => splitFileName(prefix, e.pages));
        const seen = new Set<string>();
        for (const n of names) {
          const key = n.toLowerCase(); // a case-insensitive filesystem would collide these
          if (seen.has(key)) throw new EditRefusal("split_name_clash", { item: n });
          seen.add(key);
        }
        const input = confineInputFile(pdfPath);
        const dir = pass(() => confineDir(outputDir, root));
        const finals = names.map((n) => confineNewPdf(path.join(dir, n)));
        const r = await runner
          .run(
            { op: "split", inputs: [input.real], outDir: dir, finals, params: { ranges: expanded.map((e) => e.pages.map((p) => p - 1)) }, caps: { perFileBytes: caps.perFileBytes, totalBytes: caps.splitTotalBytes } },
            extra?.signal,
          )
          .catch((e) => {
            throw withItem(
              e,
              expanded.flatMap((x) => x.pages),
              expanded.flatMap((x, ri) => x.itemOf.map((ii) => ranges[ri][ii])),
            );
          });
        const meta = checkedOut(z.object({ pageCounts: z.array(z.number().int()).length(finals.length) }), r.meta);
        const structuredContent = checkedOut(splitOutputSchema, {
          files: finals.map((f, i) => ({
            outputPath: r.finals[i],
            sourcePages: expanded[i].pages,
            pageCount: meta.pageCounts[i],
            byteSize: r.byteSizes[i],
          })),
          lost: r.lost,
          warnings: r.warnings,
        });
        return {
          content: [{ type: "text" as const, text: `Wrote ${finals.length} file(s) into ${dir}.` }],
          structuredContent,
        };
      } catch (e) {
        return refusalResult(e);
      }
    },
  );

  // --- edit_pages ---
  const sourceEntry = z
    .object({
      source: z.number().int().min(1).describe("page of the ORIGINAL document, 1-based"),
      rotate: z.union([z.literal(0), z.literal(90), z.literal(180), z.literal(270)]).optional().describe("clockwise turn added to the page's rotation"),
    })
    .strict();
  const blankEntry = z
    .object({
      blank: z.literal(true),
      size: z.enum(["previous", "A4", "Letter"]).optional().describe("default previous: the size of the page before it (A4 if first)"),
    })
    .strict();
  server.registerTool(
    "edit_pages",
    {
      title: "Edit pages",
      description:
        "Reorder, delete, rotate and insert blank pages in one step by giving the FINAL page list. Each entry is " +
        '`{"source": n, "rotate": 0|90|180|270}` (n is a page of the ORIGINAL document, 1-based) or ' +
        '`{"blank": true, "size": "previous"|"A4"|"Letter"}`. A page you leave out is deleted; the list order is the new ' +
        "order; a source page may appear only once; at least one entry must be a source page. " +
        PAGE_RULE +
        NEW_FILE_RULE +
        "Page labels are removed when pages are reordered or a blank is inserted; layers and static XFA are dropped " +
        "(listed in `lost`); digital signatures are removed. `layout` in the result says where each output page came from. " +
        'Example: {"pdfPath":"deck.pdf","pages":[{"source":2},{"source":1,"rotate":90},{"blank":true}],"outputPath":"deck-edited.pdf"}. ' +
        NOT_REDACTION,
      inputSchema: {
        pdfPath: z.string().describe("path to the PDF, inside the allowed folder"),
        pages: z.array(z.union([sourceEntry, blankEntry])).min(1).max(MAX_EXPANDED_PAGES).describe("the final page list"),
        outputPath: z.string().describe("new .pdf to create; must not exist"),
      },
      outputSchema: editPagesOutputSchema,
      annotations: annotations("Edit pages", false),
    },
    async ({ pdfPath, pages, outputPath }, extra) => {
      try {
        guardRoot();
        const seen = new Set<number>();
        let sources = 0;
        for (const e of pages) {
          if ("blank" in e) continue;
          if (seen.has(e.source)) throw new EditRefusal("duplicate_page", { item: e.source });
          seen.add(e.source);
          sources++;
        }
        if (sources === 0) throw new EditRefusal("no_source_pages");
        const input = confineInputFile(pdfPath);
        const final = confineNewPdf(outputPath);
        const layout = pages.map((e) =>
          "blank" in e ? { blank: true, size: e.size ?? "previous" } : { source: e.source, rotate: e.rotate ?? 0 },
        );
        const r = await runner.run(
          { op: "compose", inputs: [input.real], outDir: path.dirname(final), finals: [final], params: { layout }, caps: { perFileBytes: caps.perFileBytes, totalBytes: caps.perFileBytes } },
          extra?.signal,
        );
        const meta = checkedOut(z.object({ pageCount: z.number().int(), layout: editPagesOutputSchema.shape.layout }), r.meta);
        const structuredContent = checkedOut(editPagesOutputSchema, {
          outputPath: r.finals[0],
          pageCount: meta.pageCount,
          byteSize: r.byteSizes[0],
          layout: meta.layout,
          lost: r.lost,
          warnings: r.warnings,
        });
        return {
          content: [{ type: "text" as const, text: `Wrote ${meta.pageCount} page(s) to ${r.finals[0]}.` }],
          structuredContent,
        };
      } catch (e) {
        return refusalResult(e);
      }
    },
  );
}

/**
 * Turn a child's `page_out_of_range` (which names the offending 1-based page number) into
 * the agent-facing message that quotes the ORIGINAL spec item, so no child-supplied
 * string ever reaches the message. `itemPerPage[k]` is the spec item `pages[k]` came from.
 */
function withItem(e: unknown, pages: readonly number[], itemPerPage: readonly unknown[]): unknown {
  if (e instanceof EditRefusal && e.code === "page_out_of_range" && typeof e.detail.item === "number") {
    const k = pages.indexOf(e.detail.item);
    return new EditRefusal("page_out_of_range", {
      item: k === -1 ? e.detail.item : itemPerPage[k],
      pageCount: e.detail.pageCount,
    });
  }
  return e;
}
