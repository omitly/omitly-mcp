/**
 * omitly#1841 phase B: the child-process worker protocol, placement and cleanup (design 4.2).
 * Stub workers (src/testing/edit-worker-*.mjs) stand in for a hostile or broken child; the real
 * worker is exercised directly too. Every fixture is generated here.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { spawn } from "node:child_process";
import { chmodSync, copyFileSync, existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, renameSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { canSymlink, ls, makeDoc, put, stub, stubMode, tempRoot, textOf, withEditClient, type ToolResult } from "./edit-fixtures.test.js";
import { EditRunner } from "./edit-tools.js";
import { MAX_RESPONSE_BYTES, runRequest, TEMP_NAME, type WorkerRequest } from "./pdf-edit/worker.js";
import { CHILD_CODES, messageFor, type EditCode } from "./pdf-edit/refusals.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REAL_WORKER = path.join(HERE, "pdf-edit", "worker.js");
const noTemps = (root: string) => ls(root).filter((n) => n.startsWith(".omitly-tmp-"));
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
async function until(cond: () => boolean, ms = 8000, what = "condition"): Promise<void> {
  const t = Date.now();
  while (!cond()) {
    if (Date.now() - t > ms) assert.fail(`timed out waiting for ${what}`);
    await sleep(20);
  }
}

const EXTRACT = (out: string) => ({ pdfPath: "a.pdf", pages: [1], outputPath: out });
const FAILED = messageFor("failed");

async function setup(pages = 3): Promise<string> {
  const root = tempRoot();
  put(root, "a.pdf", await makeDoc("A", pages));
  return root;
}

// ---------------------------------------------------------------------------
// Mapping of what a child says (or does) to what the agent sees
// ---------------------------------------------------------------------------

test("every code a child may report maps to its fixed message; an unknown code is `failed`", async () => {
  const root = await setup();
  for (const code of CHILD_CODES) {
    await withEditClient(root, { workerPath: stub("edit-worker-stub"), workerArgs: stubMode(`err-${code}`) }, async (call) => {
      const r = await call("extract_pages", EXTRACT(`o-${code}.pdf`));
      assert.equal(r.isError, true, code);
      const expected = messageFor(code as EditCode, { item: 7, pageCount: 3 });
      assert.equal(textOf(r), expected, code);
      const m = await call("merge_pdfs", { inputs: ["a.pdf", "a.pdf"], outputPath: `m-${code}.pdf` });
      assert.equal(textOf(m), messageFor(code as EditCode, { item: 7, pageCount: 3, inputIndex: 2 }), `merge ${code}`);
    });
  }
  await withEditClient(root, { workerPath: stub("edit-worker-stub"), workerArgs: stubMode("unknowncode") }, async (call) => {
    assert.equal(textOf(await call("extract_pages", EXTRACT("u.pdf"))), FAILED);
  });
  assert.deepEqual(ls(root), ["a.pdf"]);
});

test("a child that lies is `failed`, leaves nothing behind, and the server keeps answering", async () => {
  const root = await setup();
  for (const mode of ["badmagic", "badsize", "foreign", "bigout", "twolines", "stderr"]) {
    await withEditClient(root, { workerPath: stub("edit-worker-stub"), workerArgs: stubMode(mode) }, async (call) => {
      const r = await call("extract_pages", EXTRACT(`o-${mode}.pdf`));
      assert.equal(r.isError, true, mode);
      assert.equal(textOf(r), FAILED, mode);
      assert.equal(r.structuredContent, undefined);
      assert.deepEqual(ls(root), ["a.pdf"], `${mode}: no final file and no temp file`);
      const info = await call("pdf_info", { pdfPath: "a.pdf" });
      assert.equal(info.structuredContent?.pageCount, 3, `${mode}: pdf_info still answers`);
    });
  }
});

test("a child's stderr never appears in a result (and the result is the fixed message)", async () => {
  const root = await setup();
  await withEditClient(root, { workerPath: stub("edit-worker-stub"), workerArgs: stubMode("stderr") }, async (call) => {
    const r = await call("extract_pages", EXTRACT("o.pdf"));
    const all = JSON.stringify(r);
    assert.ok(!all.includes("SECRET-STDERR-TEXT"), all);
    assert.ok(!all.includes("private.pdf"));
    assert.equal(textOf(r), FAILED);
  });
});

test("the child starts with an EMPTY environment: NODE_OPTIONS and OMITLY_* never reach it", async () => {
  const root = await setup();
  const saved = { NODE_OPTIONS: process.env.NODE_OPTIONS, OMITLY_STATE_DIR: process.env.OMITLY_STATE_DIR, OMITLY_CANARY: process.env.OMITLY_CANARY, PATH: process.env.PATH };
  process.env.NODE_OPTIONS = "--no-warnings";
  process.env.OMITLY_CANARY = "leak-me";
  process.env.OMITLY_STATE_DIR = root;
  try {
    await withEditClient(root, { workerPath: stub("edit-worker-stub"), workerArgs: stubMode("env") }, async (call) => {
      const r = await call("extract_pages", EXTRACT("env.pdf"));
      assert.ok(!r.isError, textOf(r));
      const body = readFileSync(r.structuredContent.outputPath, "latin1");
      const keys: string[] = JSON.parse(body.slice(body.indexOf("\n") + 1));
      assert.ok(!keys.includes("NODE_OPTIONS"), `NODE_OPTIONS leaked: ${keys}`);
      assert.ok(!keys.some((k) => k.startsWith("OMITLY_")), `OMITLY_* leaked: ${keys}`);
      if (process.platform === "win32") {
        // libuv (process.c, make_program_env) copies these system variables from the parent into ANY
        // child environment that lacks them, so a Windows child cannot be empty. None of them reach the agent.
        const libuv = new Set(["HOMEDRIVE", "HOMEPATH", "LOGONSERVER", "PATH", "SYSTEMDRIVE", "SYSTEMROOT", "TEMP", "USERDOMAIN", "USERNAME", "USERPROFILE", "WINDIR", "ELECTRON_RUN_AS_NODE"]);
        const extra = keys.filter((k) => !libuv.has(k.toUpperCase()));
        assert.deepEqual(extra, [], `unexpected child environment keys on Windows: ${keys.join(", ")}`);
      } else {
        assert.ok(!keys.includes("PATH"), "not even PATH");
        // Nothing we set. (macOS itself adds __CF_USER_TEXT_ENCODING to every process it execs.)
        assert.deepEqual(keys.filter((k) => k !== "__CF_USER_TEXT_ENCODING"), [], "an empty environment on this platform");
      }
    });
    // Inside an Electron-hosted client the child must run AS NODE; the empty environment gains exactly that.
    Object.defineProperty(process.versions, "electron", { value: "99.0.0", configurable: true });
    try {
      await withEditClient(root, { workerPath: stub("edit-worker-stub"), workerArgs: stubMode("env") }, async (call) => {
        const r = await call("extract_pages", EXTRACT("env2.pdf"));
        assert.ok(!r.isError, textOf(r));
        const body = readFileSync(r.structuredContent.outputPath, "latin1");
        assert.deepEqual(JSON.parse(body.slice(body.indexOf("\n") + 1)).filter((k: string) => k === "ELECTRON_RUN_AS_NODE"), ["ELECTRON_RUN_AS_NODE"]);
      });
    } finally {
      delete (process.versions as any).electron;
    }
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
});

// ---------------------------------------------------------------------------
// Timeout and memory
// ---------------------------------------------------------------------------

test("a hung child is killed at the timeout, mapped to `timeout`, its temp file removed, and the server answers pdf_info afterwards", async () => {
  const root = await setup();
  await withEditClient(root, { workerPath: stub("edit-worker-hang"), timeoutMs: 1500 }, async (call) => {
    const t = Date.now();
    const r = await call("extract_pages", EXTRACT("o.pdf"));
    const took = Date.now() - t;
    assert.equal(r.isError, true);
    assert.equal(textOf(r), messageFor("timeout"));
    assert.ok(took >= 1400 && took < 10_000, `killed at the timeout, not before or long after (${took} ms)`);
    assert.deepEqual(ls(root), ["a.pdf"], "the temp file the child had created is gone");
    const info = await call("pdf_info", { pdfPath: "a.pdf" });
    assert.ok(!info.isError, textOf(info));
    assert.equal(info.structuredContent.pageCount, 3);
  });
});

test("a child that runs out of memory is killed, mapped to `failed`, cleaned up, and the server answers afterwards", async () => {
  const root = await setup();
  await withEditClient(root, { workerPath: stub("edit-worker-oom"), maxOldSpaceMb: 48, timeoutMs: 30_000 }, async (call) => {
    const r = await call("extract_pages", EXTRACT("o.pdf"));
    assert.equal(r.isError, true);
    assert.equal(textOf(r), FAILED);
    assert.deepEqual(ls(root), ["a.pdf"]);
    const info = await call("pdf_info", { pdfPath: "a.pdf" });
    assert.equal(info.structuredContent?.pageCount, 3);
  });
});

// ---------------------------------------------------------------------------
// First-use ping
// ---------------------------------------------------------------------------

test("first use: a worker that cannot answer its start-up ping disables all five tools with `failed`, at once, logged locally", async () => {
  const root = await setup();
  const logged: string[] = [];
  const orig = console.error;
  console.error = (...a: unknown[]) => void logged.push(a.join(" "));
  try {
    await withEditClient(root, { workerPath: stub("edit-worker-stub"), workerArgs: stubMode("deadping"), timeoutMs: 20_000 }, async (call) => {
      const t = Date.now();
      const calls: [string, Record<string, unknown>][] = [
        ["pdf_info", { pdfPath: "a.pdf" }],
        ["extract_pages", EXTRACT("o1.pdf")],
        ["merge_pdfs", { inputs: ["a.pdf", "a.pdf"], outputPath: "o2.pdf" }],
        ["split_pdf", { pdfPath: "a.pdf", ranges: [[1]], outputDir: ".", prefix: "p" }],
        ["edit_pages", { pdfPath: "a.pdf", pages: [{ source: 1 }], outputPath: "o3.pdf" }],
      ];
      for (const [name, args] of calls) {
        const r = await call(name, args);
        assert.equal(r.isError, true, name);
        assert.equal(textOf(r), FAILED, name);
      }
      assert.ok(Date.now() - t < 10_000, "no call waited out the 20 s call timeout");
    });
  } finally {
    console.error = orig;
  }
  assert.ok(logged.some((l) => /start-up check/.test(l)), "logged for the person running the server");
  assert.deepEqual(ls(root), ["a.pdf"]);
});

// ---------------------------------------------------------------------------
// Placement
// ---------------------------------------------------------------------------

test("placement race: an output created between the check and the placement is never overwritten", async () => {
  const root = await setup();
  const target = path.join(root, "out.pdf");
  await withEditClient(root, { beforePlace: (final) => writeFileSync(final, "SOMEONE-ELSES-FILE") }, async (call) => {
    const r = await call("extract_pages", EXTRACT("out.pdf"));
    assert.equal(r.isError, true);
    assert.equal(textOf(r), messageFor("output_exists"));
    assert.equal(readFileSync(target, "utf8"), "SOMEONE-ELSES-FILE", "the other file is untouched");
  });
  assert.deepEqual(ls(root), ["a.pdf", "out.pdf"], "no temp file left");
});

test("placement race through a DANGLING symlink created in the window: refused, and the link's target is never created", { skip: !canSymlink }, async () => {
  for (const forceCopy of [false, true]) {
    const root = await setup();
    const outside = tempRoot();
    const victim = path.join(outside, "victim.pdf");
    await withEditClient(
      root,
      {
        beforePlace: (final) => symlinkSync(victim, final),
        ...(forceCopy ? { link: () => { throw Object.assign(new Error("no hard links here"), { code: "EPERM" }); } } : {}),
      },
      async (call) => {
        const r = await call("extract_pages", EXTRACT("out.pdf"));
        assert.equal(textOf(r), messageFor("output_exists"), `forceCopy=${forceCopy}`);
      },
    );
    assert.ok(!existsSync(victim), `forceCopy=${forceCopy}: nothing was written through the link`);
    assert.deepEqual(noTemps(root), []);
  }
});

test("copy fallback: where hard links fail the result is identical, still create-only, and the race still refuses", async () => {
  const root = await setup();
  let linkCalls = 0;
  const noLink = (): void => {
    linkCalls++;
    throw Object.assign(new Error("EPERM: operation not permitted, link"), { code: "EPERM" });
  };
  const normal = await withEditClient(root, {}, async (call) => call("extract_pages", EXTRACT("linked.pdf")));
  const copied = await withEditClient(root, { link: noLink }, async (call) => call("extract_pages", EXTRACT("copied.pdf")));
  assert.ok(!normal.isError && !copied.isError, `${textOf(normal)} ${textOf(copied)}`);
  assert.equal(linkCalls, 1, "the fallback really ran");
  assert.deepEqual(readFileSync(path.join(root, "copied.pdf")), readFileSync(path.join(root, "linked.pdf")), "byte-identical result");
  assert.deepEqual({ ...copied.structuredContent, outputPath: "" }, { ...normal.structuredContent, outputPath: "" });
  // Create-only on the copy path too.
  await withEditClient(root, { link: noLink, beforePlace: (f) => writeFileSync(f, "OTHER") }, async (call) => {
    const r = await call("extract_pages", EXTRACT("race.pdf"));
    assert.equal(textOf(r), messageFor("output_exists"));
    assert.equal(readFileSync(path.join(root, "race.pdf"), "utf8"), "OTHER");
  });
  assert.deepEqual(noTemps(root), []);
});

test("copy fallback: a copy that fails for another reason is `write_failed` and leaves no final file", { skip: process.platform === "win32" || process.getuid?.() === 0 }, async () => {
  const root = await setup();
  const dir = path.join(root, "locked");
  mkdirSync(dir);
  const noLink = (): void => {
    throw Object.assign(new Error("EXDEV"), { code: "EXDEV" });
  };
  await withEditClient(
    root,
    {
      link: noLink,
      // The child has already written its temp file; now take away the right to create the final,
      // and give it back shortly after, so the cleanup's retry loop (EACCES) can remove the temp.
      beforePlace: () => {
        chmodSync(dir, 0o500);
        setTimeout(() => chmodSync(dir, 0o700), 120);
      },
    },
    async (call) => {
      try {
        const r = await call("split_pdf", { pdfPath: "a.pdf", ranges: [[1]], outputDir: "locked", prefix: "p" });
        assert.equal(textOf(r), messageFor("write_failed"));
      } finally {
        chmodSync(dir, 0o700);
      }
    },
  );
  assert.deepEqual(ls(dir), [], "no final and no temp left");
});

test("split_pdf is all-or-nothing: a failure on the third file removes the first two and leaves no temp file", async () => {
  const root = await setup(6);
  const sub = path.join(root, "parts");
  mkdirSync(sub);
  let placed = 0;
  await withEditClient(
    root,
    {
      beforePlace: (final) => {
        placed++;
        if (placed === 3) writeFileSync(final, "ALREADY-HERE");
      },
    },
    async (call) => {
      const r = await call("split_pdf", { pdfPath: "a.pdf", ranges: [[1, 2], [3, 4], [5, 6]], outputDir: "parts", prefix: "s" });
      assert.equal(textOf(r), messageFor("output_exists"));
    },
  );
  assert.deepEqual(ls(sub), ["s-p5-6.pdf"], "only the file that was not ours remains");
  assert.equal(readFileSync(path.join(sub, "s-p5-6.pdf"), "utf8"), "ALREADY-HERE");
});

// ---------------------------------------------------------------------------
// Cleanup never touches another call's files
// ---------------------------------------------------------------------------

test("cancelling one call removes only ITS temp file; a concurrent call's temp file is untouched and that call completes", async () => {
  const root = await setup();
  await withEditClient(root, { workerPath: stub("edit-worker-stub"), workerArgs: stubMode("holdfile"), timeoutMs: 60_000 }, async (call) => {
    const ac = new AbortController();
    const a = call("extract_pages", EXTRACT("a-out.pdf"), ac.signal).catch((e) => e);
    const b = call("extract_pages", EXTRACT("b-out.pdf"));
    await until(() => noTemps(root).length === 2, 10_000, "both calls to have created their temp files");
    ac.abort();
    await a;
    await until(() => noTemps(root).length === 1, 8000, "the cancelled call's temp file to be removed");
    await sleep(300);
    assert.equal(noTemps(root).length, 1, "the other call's temp file is still there");
    writeFileSync(path.join(root, "RELEASE"), "");
    const rb = await b;
    assert.ok(!rb.isError, textOf(rb));
    assert.ok(existsSync(path.join(root, "b-out.pdf")));
    assert.ok(!existsSync(path.join(root, "a-out.pdf")), "the cancelled call placed nothing");
  });
  assert.deepEqual(noTemps(root), []);
});

// ---------------------------------------------------------------------------
// Concurrency: two at once, eight waiting, the next refused
// ---------------------------------------------------------------------------

test("at most two workers at once, eight calls waiting, then `busy`", async () => {
  const root = await setup();
  await withEditClient(root, { workerPath: stub("edit-worker-stub"), workerArgs: stubMode("holdfile"), timeoutMs: 60_000 }, async (call) => {
    const results: Promise<ToolResult>[] = [];
    for (let i = 0; i < 11; i++) results.push(call("extract_pages", EXTRACT(`o${i}.pdf`)));
    const busy = await Promise.race(results.map((p) => p.then((r) => (textOf(r) === messageFor("busy") ? r : new Promise<never>(() => {})))));
    assert.equal(busy.isError, true);
    await until(() => noTemps(root).length === 2, 10_000, "two workers running");
    await sleep(500);
    assert.equal(noTemps(root).length, 2, "never more than two workers at once");
    writeFileSync(path.join(root, "RELEASE"), "");
    const all = await Promise.all(results);
    assert.equal(all.filter((r) => textOf(r) === messageFor("busy")).length, 1, "exactly the 11th is refused (2 running + 8 waiting)");
    assert.equal(all.filter((r) => !r.isError).length, 10);
  });
  assert.deepEqual(noTemps(root), []);
  assert.equal(ls(root).filter((n) => /^o\d+\.pdf$/.test(n)).length, 10);
});

// ---------------------------------------------------------------------------
// The real worker, directly
// ---------------------------------------------------------------------------

function req(root: string, over: Partial<WorkerRequest> = {}): WorkerRequest {
  return {
    v: 1,
    op: "extract",
    inputs: [path.join(root, "a.pdf")],
    outDir: root,
    temps: [".omitly-tmp-0123456789abcdef-0.pdf"],
    caps: { perFileBytes: 1 << 20, totalBytes: 1 << 20 },
    timeoutMs: 10_000,
    params: { pages: [0] },
    ...over,
  };
}

test("worker: writes only the temp name it was issued, create-exclusive, and refuses one that exists", async () => {
  const root = await setup();
  const r = await runRequest(req(root));
  assert.equal(r.ok, true);
  assert.deepEqual(ls(root), [".omitly-tmp-0123456789abcdef-0.pdf", "a.pdf"]);
  // Same name again: `wx` fails, the existing file is not touched.
  const before = readFileSync(path.join(root, ".omitly-tmp-0123456789abcdef-0.pdf"));
  const again = await runRequest(req(root));
  assert.deepEqual(again, { v: 1, ok: false, code: "write_failed" });
  assert.deepEqual(readFileSync(path.join(root, ".omitly-tmp-0123456789abcdef-0.pdf")), before);
});

test("worker: enforces the output cap while writing and leaves no partial file", async () => {
  const root = await setup();
  const r = await runRequest(req(root, { caps: { perFileBytes: 1 << 20, totalBytes: 100 } }));
  assert.deepEqual(r, { v: 1, ok: false, code: "output_too_large" });
  assert.deepEqual(ls(root), ["a.pdf"]);
});

test("worker: temp names must match the issued pattern, paths must be absolute (checked by spawning the real child)", async () => {
  assert.ok(TEMP_NAME.test(".omitly-tmp-0123456789abcdef-0.pdf"));
  for (const bad of ["../x.pdf", "x.pdf", ".omitly-tmp-xyz-0.pdf", "/abs/.omitly-tmp-0123456789abcdef-0.pdf", ".omitly-tmp-0123456789abcdef-0.pdf/../a", ".omitly-tmp-0123456789ABCDEF-0.pdf"]) {
    assert.ok(!TEMP_NAME.test(bad), bad);
  }
  const root = await setup();
  for (const bad of [
    req(root, { temps: ["../escape.pdf"] }),
    req(root, { inputs: ["a.pdf"] }),
    req(root, { outDir: "relative" }),
    { ...req(root), v: 2 } as unknown as WorkerRequest,
    { ...req(root), op: "rm-rf" } as unknown as WorkerRequest,
  ]) {
    const out = await runChild(JSON.stringify(bad) + "\n");
    assert.equal(out.code, 3);
    assert.deepEqual(JSON.parse(out.stdout), { v: 1, ok: false, code: "failed" });
  }
  assert.ok(!existsSync(path.join(path.dirname(root), "escape.pdf")));
  assert.deepEqual(ls(root), ["a.pdf"]);
});

function runChild(stdinText: string | null, args: string[] = []): Promise<{ code: number | null; stdout: string; ms: number }> {
  return new Promise((resolve) => {
    const t = Date.now();
    const c = spawn(process.execPath, [...args, REAL_WORKER], { env: {}, stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    c.stdout.on("data", (d) => (stdout += d));
    c.on("close", (code) => resolve({ code, stdout, ms: Date.now() - t }));
    if (stdinText !== null) c.stdin.write(stdinText);
    // stdin is deliberately left open when text was sent: ending it would end the child.
    if (stdinText === null) c.stdin.end();
  });
}

test("worker: it exits when its stdin ends, so it cannot outlive the server", async () => {
  const out = await runChild(null);
  assert.equal(out.code, 0);
  assert.ok(out.ms < 5000, `${out.ms} ms`);
});

test("worker: a real request over the real protocol returns one short JSON line and exits 0", async () => {
  const root = await setup();
  const out = await runChild(JSON.stringify(req(root)) + "\n");
  assert.equal(out.code, 0);
  assert.ok(out.stdout.endsWith("\n") && out.stdout.trim().split("\n").length === 1);
  assert.ok(Buffer.byteLength(out.stdout) < MAX_RESPONSE_BYTES);
  const parsed = JSON.parse(out.stdout);
  assert.equal(parsed.ok, true);
  assert.deepEqual(parsed.parts.map((p: any) => p.temp), [".omitly-tmp-0123456789abcdef-0.pdf"]);
  assert.ok(lstatSync(path.join(root, ".omitly-tmp-0123456789abcdef-0.pdf")).size === parsed.parts[0].byteSize);
});

// ---------------------------------------------------------------------------
// Codex 3: the output folder swapped for a symlink after confinement
// ---------------------------------------------------------------------------

test("TOCTOU: a folder swapped for a symlink between the check and the placement is detected AFTER placing, what this call placed is removed, and the call is `write_failed`", { skip: process.platform === "win32" || !canSymlink }, async () => {
  const root = await setup(3);
  const outside = tempRoot();
  const parts = path.join(root, "parts");
  mkdirSync(parts);
  let swapped = false;
  await withEditClient(
    root,
    {
      beforePlace: () => {
        if (swapped) return;
        swapped = true;
        const temp = readdirSync(parts).find((n) => n.startsWith(".omitly-tmp-"))!;
        copyFileSync(path.join(parts, temp), path.join(outside, temp)); // so the link can succeed through the swapped folder
        renameSync(parts, path.join(root, "parts-real"));
        symlinkSync(outside, parts);
      },
    },
    async (call) => {
      const r = await call("split_pdf", { pdfPath: "a.pdf", ranges: [[1]], outputDir: "parts", prefix: "s" });
      assert.equal(r.isError, true);
      assert.equal(textOf(r), messageFor("write_failed"));
    },
  );
  assert.deepEqual(readdirSync(outside), [], "nothing this call placed is left outside the root");
});

test("TOCTOU: the child refuses to write when its output folder is not a real path any more", { skip: process.platform === "win32" || !canSymlink }, async () => {
  const root = await setup();
  const outside = tempRoot();
  const link = path.join(root, "link");
  symlinkSync(outside, link);
  const r = await runRequest(req(root, { outDir: link }));
  assert.deepEqual(r, { v: 1, ok: false, code: "failed" });
  assert.deepEqual(readdirSync(outside), [], "nothing was written through the link");
});

// ---------------------------------------------------------------------------
// Codex 4: the copy fallback only removes what it created
// ---------------------------------------------------------------------------

const noLinks = (): void => {
  throw Object.assign(new Error("EPERM: link"), { code: "EPERM" });
};
const tempIn = (dir: string) => path.join(dir, readdirSync(dir).find((n) => n.startsWith(".omitly-tmp-"))!);

test("copy fallback: with the temp gone and ANOTHER writer's file at the final name, the call is refused and the other file survives untouched", async () => {
  const root = await setup();
  await withEditClient(
    root,
    {
      link: noLinks,
      beforePlace: (final) => {
        unlinkSync(tempIn(root));
        writeFileSync(final, "OTHER-WRITERS-FILE");
      },
    },
    async (call) => {
      const r = await call("extract_pages", EXTRACT("out.pdf"));
      assert.equal(textOf(r), messageFor("output_exists"));
    },
  );
  assert.equal(readFileSync(path.join(root, "out.pdf"), "utf8"), "OTHER-WRITERS-FILE");
});

test("copy fallback: with the temp gone and the final name free, the file this call created is removed and the call is `write_failed`", async () => {
  const root = await setup();
  await withEditClient(root, { link: noLinks, beforePlace: () => unlinkSync(tempIn(root)) }, async (call) => {
    const r = await call("extract_pages", EXTRACT("out.pdf"));
    assert.equal(textOf(r), messageFor("write_failed"));
  });
  assert.deepEqual(ls(root), ["a.pdf"]);
});

test("a hard link that fails because the temp vanished does not delete a file another writer created at the final name", async () => {
  const root = await setup();
  await withEditClient(
    root,
    {
      beforePlace: (final) => {
        unlinkSync(tempIn(root)); // the real linkSync now fails with ENOENT, not EEXIST
        writeFileSync(final, "OTHER-WRITERS-FILE");
      },
    },
    async (call) => {
      const r = await call("extract_pages", EXTRACT("out.pdf"));
      assert.equal(r.isError, true);
    },
  );
  assert.equal(readFileSync(path.join(root, "out.pdf"), "utf8"), "OTHER-WRITERS-FILE");
});

// ---------------------------------------------------------------------------
// The copy fallback streams; the slot queue handles cancellation
// ---------------------------------------------------------------------------

test("copy fallback streams a multi-MiB output in chunks: bytes identical to the hard-link result", async () => {
  const root = tempRoot();
  const { randomBytes } = await import("node:crypto");
  const { PDFName } = await import("pdf-lib");
  // ~3.2 MiB of incompressible content, so the output is more than three copy chunks.
  put(
    root,
    "big.pdf",
    await makeDoc("B", 2, (doc) => {
      const c = doc.context;
      const xo = c.register(c.stream(randomBytes(3_400_000), { Type: "XObject", Subtype: "Form", BBox: [0, 0, 1, 1] }));
      doc.getPages()[0].node.set(PDFName.of("Resources"), c.obj({ XObject: { Big: xo } }));
    }),
  );
  let linkCalls = 0;
  const noLink = (): void => {
    linkCalls++;
    throw Object.assign(new Error("EPERM"), { code: "EPERM" });
  };
  const args = (out: string) => ({ pdfPath: "big.pdf", pages: [1, 2], outputPath: out });
  const linked = await withEditClient(root, {}, async (call) => call("extract_pages", args("linked.pdf")));
  const copied = await withEditClient(root, { link: noLink }, async (call) => call("extract_pages", args("copied.pdf")));
  assert.ok(!linked.isError && !copied.isError, `${textOf(linked)} ${textOf(copied)}`);
  assert.equal(linkCalls, 1);
  const a = readFileSync(path.join(root, "linked.pdf"));
  assert.ok(a.length > 3 * 1024 * 1024, `output is ${a.length} bytes`);
  assert.deepEqual(readFileSync(path.join(root, "copied.pdf")), a);
  assert.deepEqual(noTemps(root), []);
});

test("slot queue: an already-cancelled call takes no slot and no queue place; cancelling a queued call frees its place", async () => {
  const runner = new EditRunner({ workerPath: "unused", workerArgs: [], maxOldSpaceMb: 64, timeoutMs: 1000 }) as any;
  const hold1 = await runner.acquire();
  const hold2 = await runner.acquire();
  assert.equal(runner.running, 2);
  // Already cancelled: refused at once, nothing queued, nothing running.
  const dead = new AbortController();
  dead.abort();
  await assert.rejects(() => runner.acquire(dead.signal), (e: any) => e.code === "failed");
  assert.equal(runner.waiting.length, 0);
  assert.equal(runner.running, 2);
  // Fill the queue (8), the next is busy.
  const controllers = Array.from({ length: 8 }, () => new AbortController());
  const queued = controllers.map((c) => runner.acquire(c.signal).catch((e: any) => e));
  assert.equal(runner.waiting.length, 8);
  await assert.rejects(() => runner.acquire(), (e: any) => e.code === "busy");
  // Cancel one queued call: its place is freed and a new call is accepted rather than busy.
  controllers[3].abort();
  const aborted = await queued[3];
  assert.equal(aborted.code, "failed");
  assert.equal(runner.waiting.length, 7);
  const late = runner.acquire().catch((e: any) => e);
  assert.equal(runner.waiting.length, 8, "the freed place was reusable");
  // Drain: release everything; queued calls are granted in order and release in turn.
  hold1();
  hold2();
  for (const p of [...queued.filter((_, i) => i !== 3), late]) {
    const release = await p;
    assert.equal(typeof release, "function");
    release();
  }
  assert.equal(runner.running, 0);
  assert.equal(runner.waiting.length, 0);
});

test("worker: an INPUT that is a symlink (or sits behind one) is refused as `failed`; a normal confined file is accepted", { skip: process.platform === "win32" || !canSymlink }, async () => {
  const root = await setup();
  const outside = tempRoot();
  put(outside, "secret.pdf", await makeDoc("S", 1));
  symlinkSync(path.join(outside, "secret.pdf"), path.join(root, "link.pdf"));
  symlinkSync(outside, path.join(root, "linkdir"));
  const out = path.join(root, "out");
  mkdirSync(out);
  const ok = await runRequest(req(root, { outDir: out, temps: [".omitly-tmp-0123456789abcdef-0.pdf"] }));
  assert.equal(ok.ok, true, "a normal file is accepted");
  for (const input of [path.join(root, "link.pdf"), path.join(root, "linkdir", "secret.pdf")]) {
    for (const op of ["info", "extract", "merge"] as const) {
      const r = await runRequest(req(root, { op, inputs: [input], outDir: out, temps: op === "info" ? [] : [".omitly-tmp-fedcba9876543210-0.pdf"], params: { pages: [0] } }));
      assert.deepEqual(r, { v: 1, ok: false, code: "failed" }, `${op} ${path.basename(input)}`);
    }
  }
  assert.ok(!readdirSync(out).some((n) => n.includes("fedcba")), "nothing written for a refused input");
});
