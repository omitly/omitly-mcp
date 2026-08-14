/**
 * Filesystem confinement for the free/diagnosis-only MCPB server.
 *
 * Ported from ../../src/paths.ts (the full omitly-mcp server) — this bundle
 * only ever needs the READ-side check, since every tool it exposes
 * (check_redaction, find_sensitive_regions, locate_text, verify_redaction) is
 * diagnosis-only and never writes a file. Kept as a plain CommonJS module
 * (no build step) so the bundle can `require()` it directly at runtime.
 *
 * Every path in a tool call comes from the MODEL, so an unconfined server is
 * an arbitrary-read primitive for whatever the model was talked into. Reads
 * are confined to one allowed root, set via the manifest's
 * `user_config.allowed_dir` (a directory the end user explicitly picks at
 * install time — see manifest.json). There is deliberately NO fallback to
 * $HOME or the server's cwd: an unset root fails closed rather than
 * defaulting to the broadest-available directory.
 *
 * Checks resolve symlinks (realpath) before comparing, so a link inside the
 * root that points outside it is rejected.
 */
"use strict";

const { existsSync, readFileSync, realpathSync, statSync } = require("node:fs");
const path = require("node:path");

/**
 * Cap on input file size (omitly#390). Every tool reads the WHOLE file into
 * memory and hands the bytes to the wasm scanner, which copies them again into
 * a Uint8Array — so an unbounded read of a multi-GB path under the allowed root
 * would OOM or hang the user's machine. A few hundred MB is already far past any
 * real PDF, so cap well below anything legitimate.
 */
const MAX_INPUT_BYTES = 512 * 1024 * 1024; // 512 MiB

/** The confinement root, resolved once at startup. */
function allowedRoot() {
  const configured = process.env.OMITLY_ALLOWED_DIR ? process.env.OMITLY_ALLOWED_DIR.trim() : "";
  if (!configured) {
    throw new Error(
      "OMITLY_ALLOWED_DIR is not set. This server refuses to default to $HOME or its " +
        "working directory — configure the allowed folder in the extension's settings.",
    );
  }
  try {
    return realpathSync(configured);
  } catch {
    throw new Error(
      `OMITLY_ALLOWED_DIR does not exist or is unreadable: ${configured}. ` +
        `Point it at the directory the agent may read PDFs in.`,
    );
  }
}

function within(root, target) {
  const rel = path.relative(root, target);
  if (rel === "" || path.isAbsolute(rel)) return false;
  // Must check the whole leading segment (".." or "../..."), not just a
  // startsWith("..") prefix — that also matches a legitimate in-root
  // descendant whose name happens to start with two dots.
  return rel !== ".." && !rel.startsWith(".." + path.sep);
}

function refusal(what, p, root) {
  return new Error(
    `${what} "${p}" is outside the allowed directory (${root}). ` +
      `This server only reads files under that directory; ` +
      `set OMITLY_ALLOWED_DIR in the MCP config to change it.`,
  );
}

/** Validate a model-supplied INPUT path: must exist inside the root (after
 *  symlink resolution). Returns the resolved real path. */
function confineInput(p, root) {
  // Check containment on the RAW resolved path first, before ever touching
  // the filesystem — otherwise an existing out-of-root path (e.g.
  // /etc/shadow) reaches realpathSync successfully and gets a distinct
  // "outside the allowed directory" refusal, while a non-existent out-of-root
  // path gets "not found": that difference is a filesystem-existence oracle
  // for arbitrary paths outside the root. Refusing here means both cases
  // short-circuit identically for anything outside root.
  const resolved = path.resolve(root, p);
  if (!within(root, resolved)) throw refusal("input path", p, root);
  let real;
  try {
    real = realpathSync(resolved);
  } catch {
    throw new Error(`input file not found: ${p}`);
  }
  // The raw path was in-root, but it may be a symlink that escapes root —
  // re-check after resolution.
  if (!within(root, real)) throw refusal("input path", p, root);
  return real;
}

/**
 * Confine a model-supplied INPUT path AND enforce the size cap, then read it.
 * The single choke point every tool goes through so no read site can drift into
 * an unbounded `readFileSync` (omitly#390). `statSync` is on the already-
 * realpath-resolved, in-root path, so it can't be redirected out of the root.
 * Throws (caught by each tool's try/catch and surfaced as an error) on an
 * over-limit file, rather than reading it.
 */
function readConfinedInput(p, root, maxBytes = MAX_INPUT_BYTES) {
  const real = confineInput(p, root);
  const { size } = statSync(real);
  if (size > maxBytes) {
    const mib = (n) => (n / (1024 * 1024)).toFixed(0);
    throw new Error(
      `file is ${mib(size)} MiB, over the ${mib(maxBytes)} MiB limit for on-device scanning`,
    );
  }
  const bytes = readFileSync(real);
  // omitly#393: this is the one choke point every tool reads through, so it's
  // also the one place to catch "the model pointed this at something that
  // isn't a PDF" before the bytes reach the wasm scanner — a clear "not a
  // PDF" error beats an opaque wasm-side failure or a silently-empty scan.
  if (!isPdfMagic(bytes)) {
    throw new Error(`file does not look like a PDF (missing %PDF- header): ${p}`);
  }
  return bytes;
}

/** True iff `bytes` starts with the PDF magic `%PDF-`. */
function isPdfMagic(bytes) {
  const magic = Buffer.from("%PDF-", "ascii");
  return bytes.length >= magic.length && bytes.subarray(0, magic.length).equals(magic);
}

module.exports = {
  allowedRoot,
  confineInput,
  readConfinedInput,
  within,
  existsSync,
  isPdfMagic,
  MAX_INPUT_BYTES,
};
