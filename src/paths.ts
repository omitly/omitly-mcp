/**
 * Filesystem confinement for the MCP surface (threat-model prerequisite).
 *
 * Every path in a tool call comes from the MODEL, so an uncontained server is
 * an arbitrary-read/-write primitive for whatever the model was talked into.
 * All reads and writes are confined to one allowed root:
 *
 *   OMITLY_ALLOWED_DIR  — explicit root (recommended in the MCP config)
 *   otherwise           — the directory the server was started in
 *
 * Checks resolve symlinks (realpath) before comparing, so a link inside the
 * root that points outside it is rejected; an output path that IS a symlink is
 * refused outright (only its parent can be realpath'd, so following it would
 * escape — #661); and outputs must not clobber existing names, dangling
 * symlinks included — the model is told to pick a fresh name instead. These are
 * guardrails against confused-deputy mistakes, not a sandbox for a hostile
 * local user (they own the machine; see docs/THREAT-MODEL.md).
 */
import { lstatSync, realpathSync } from "node:fs";
import * as path from "node:path";

/** Is there a directory ENTRY at `p`? Deliberately `lstat`, not `existsSync`:
 *  `existsSync` follows symlinks, so a DANGLING link (a name that is very much
 *  taken, pointing at a target that does not exist yet) reports as absent.
 *  `lstat` describes the link itself, so an occupied name is seen as occupied
 *  whether or not its target resolves (#661). */
function entryExists(p: string): boolean {
  return lstatSync(p, { throwIfNoEntry: false }) !== undefined;
}

/** Is `p` itself a symlink? `lstat`, so the link is described rather than
 *  followed — true for a dangling link too. */
function isSymlink(p: string): boolean {
  return lstatSync(p, { throwIfNoEntry: false })?.isSymbolicLink() === true;
}

/** The confinement root, resolved once at startup. */
export function allowedRoot(): string {
  const configured = process.env.OMITLY_ALLOWED_DIR?.trim();
  const root = configured || process.cwd();
  try {
    return realpathSync(root);
  } catch {
    throw new Error(
      `OMITLY_ALLOWED_DIR does not exist or is unreadable: ${root}. ` +
        `Point it at the directory the agent may read/write PDFs in.`,
    );
  }
}

function within(root: string, target: string): boolean {
  const rel = path.relative(root, target);
  if (rel === "" || path.isAbsolute(rel)) return false;
  // Must check the whole leading segment (".." or "../..."), not just a
  // `startsWith("..")` prefix — that also matches a perfectly legitimate
  // in-root descendant whose name happens to start with two dots, e.g.
  // `<root>/..draft.pdf` (relative "..draft.pdf" starts with ".." but is a
  // single in-root path segment, not an escape).
  return rel !== ".." && !rel.startsWith(".." + path.sep);
}

function refusal(what: string, p: string, root: string): Error {
  return new Error(
    `${what} "${p}" is outside the allowed directory (${root}). ` +
      `This server only touches files under that directory; ` +
      `set OMITLY_ALLOWED_DIR in the MCP config to change it.`,
  );
}

/** Validate a model-supplied INPUT path: must exist inside the root (after
 *  symlink resolution). Returns the resolved real path to hand to the engine. */
export function confineInput(p: string, root: string): string {
  // Check containment on the RAW resolved path first, before ever touching
  // the filesystem via realpathSync — otherwise an existing out-of-root path
  // (e.g. /etc/shadow) reaches realpathSync successfully and gets a distinct
  // "outside the allowed directory" refusal, while a non-existent out-of-root
  // path gets "not found": the difference is a filesystem-existence oracle
  // for arbitrary paths outside the root. Refusing here, before any lookup,
  // means both cases short-circuit identically for anything outside root.
  const resolved = path.resolve(root, p);
  if (!within(root, resolved)) throw refusal("input path", p, root);
  let real: string;
  try {
    real = realpathSync(resolved);
  } catch {
    throw new Error(`input file not found: ${p}`);
  }
  // The raw path was in-root, but it may be a symlink that escapes root —
  // re-check after resolution (this is the confused-deputy case the module
  // doc describes: "a link inside the root that points outside it").
  if (!within(root, real)) throw refusal("input path", p, root);
  return real;
}

/** Validate a model-supplied OUTPUT path: its parent must exist inside the
 *  root, and neither the file nor its `.audit.json` sidecar may already exist
 *  (never silently overwrite — ask the model to pick a fresh name). Returns
 *  the resolved path to hand to the engine. */
export function confineOutput(p: string, root: string): string {
  const resolved = path.resolve(root, p);
  let parent: string;
  try {
    parent = realpathSync(path.dirname(resolved));
  } catch {
    throw new Error(`output directory not found: ${path.dirname(p)}`);
  }
  const real = path.join(parent, path.basename(resolved));
  if (!within(root, real)) throw refusal("output path", p, root);
  // The parent is confirmed in-root, but the FINAL COMPONENT may itself be a
  // symlink that escapes it — and only the parent went through realpathSync.
  // A write through the returned path follows that link, so the escape has to
  // be refused here rather than left to the no-clobber check below: that check
  // used to be `existsSync`, which follows links and therefore reports a
  // DANGLING one as absent, seeing neither the escape nor the taken name. The
  // result was an in-root path that wrote outside the root (#661).
  //
  // Any symlink is refused, not just an escaping one: an output target is
  // supposed to be a fresh name the model picked, resolving a link to decide
  // re-opens the same follow-the-link question one level down, and the model
  // can always pick another name.
  if (isSymlink(real)) {
    throw new Error(
      `refusing to write through a symlink: ${real}. Choose a new output name.`,
    );
  }
  for (const candidate of [real, `${real}.audit.json`]) {
    if (entryExists(candidate)) {
      throw new Error(
        `refusing to overwrite existing file: ${candidate}. Choose a new output name.`,
      );
    }
  }
  return real;
}
