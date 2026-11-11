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
import { lstatSync, realpathSync, statSync, type Stats } from "node:fs";
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

/** Validate a model-supplied output FOLDER (omitly#1841 `split_pdf`): an existing
 *  directory that is the allowed root itself or inside it, after symlink
 *  resolution. `confineInput` cannot be used: `within()` treats the root as
 *  outside, so it refuses the root, and its "input file not found" is the wrong
 *  words for a folder. Containment of the RAW path is checked first, before the
 *  filesystem is touched, so a path outside the root gets the same answer whether
 *  or not it exists (no existence oracle). Returns the resolved real path. */
export function confineDir(p: string, root: string): string {
  const resolved = path.resolve(root, p);
  if (resolved !== root && !within(root, resolved)) throw refusal("output folder", p, root);
  let real: string;
  try {
    real = realpathSync(resolved);
  } catch {
    throw new Error("That output folder does not exist.");
  }
  // A link inside the root can point outside it.
  if (real !== root && !within(root, real)) throw refusal("output folder", p, root);
  let isDir = false;
  try {
    isDir = statSync(real).isDirectory();
  } catch {
    isDir = false;
  }
  if (!isDir) throw new Error("That output folder does not exist.");
  return real;
}

/** Validate a model-supplied OUTPUT path: its parent must exist inside the
 *  root, and neither the file nor its `.audit.json` sidecar may already exist
 *  (never silently overwrite — ask the model to pick a fresh name). Returns
 *  the resolved path to hand to the engine. */
export function confineOutput(p: string, root: string): string {
  const resolved = path.resolve(root, p);
  // Containment of the RAW resolved path first, before the filesystem is touched
  // (as confineInput / confineDir do): otherwise "outside the allowed directory"
  // vs "output directory not found" tells the caller which folders exist anywhere
  // on the machine (#1851). The realpath checks below still catch a link inside
  // the root that points out of it.
  if (!within(root, resolved)) throw refusal("output path", p, root);
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

/** The `<pdf>.audit.json` sidecar the engine will read for `verify`, as seen
 *  at the moment it was confined (#1563). */
export interface SidecarClaim {
  /** The sidecar path, exactly as the engine will derive and open it. */
  path: string;
  dev: number;
  ino: number;
  size: number;
  mtimeMs: number;
}

function sidecarRefusal(sidecar: string, why: string): Error {
  // Deliberately says nothing about where a link points or whether its target
  // exists: that would turn the refusal into a probe of paths outside the root.
  return new Error(
    `refusing to verify against ${sidecar}: ${why}. The audit sidecar must be the ` +
      `regular file the redaction wrote next to this PDF; remove the link or copy the ` +
      `real sidecar into place.`,
  );
}

function claimOf(sidecar: string, st: Stats): SidecarClaim {
  return { path: sidecar, dev: st.dev, ino: st.ino, size: st.size, mtimeMs: st.mtimeMs };
}

/** Validate the DERIVED `<pdf>.audit.json` sidecar before the engine reads it.
 *
 *  `confineInput` vets the PDF, but the engine builds the sidecar path itself
 *  (`format!("{pdf}.audit.json")`) and reads it with `fs::read`, which follows
 *  symlinks — so a link planted at that name read a file outside the root and
 *  echoed its reason codes (#1563). `confinedPdf` MUST be `confineInput`'s
 *  return value, so the sidecar sits in the same realpath'd in-root directory
 *  and only its final component can differ.
 *
 *  Returns null when there is no entry at all (the caller falls back to the
 *  general re-scan, as before). Returns a claim for a regular file. Refuses
 *  EVERY other entry, not just a link that leaves the root:
 *   - A symlink — outside the root, inside it, or dangling. The engine writes a
 *     sidecar with an atomic rename, so a genuine one is never a link; and
 *     `confineOutput` already refuses a link at this exact name. An in-root link
 *     would point verification at some OTHER document's record while claiming
 *     to check this one. `confineInput` accepts an in-root PDF link because
 *     the PDF is the thing the caller named; the sidecar is a derived record
 *     whose whole meaning is its name. We also cannot hand the engine a
 *     resolved sidecar path (it takes only the PDF), so "resolve it and allow
 *     it" would vet one path and read another.
 *   - A directory, FIFO or device, which can only hang or confuse the read. */
export function confineSidecar(confinedPdf: string, root: string): SidecarClaim | null {
  const sidecar = `${confinedPdf}.audit.json`;
  if (!within(root, sidecar)) throw refusal("audit sidecar", sidecar, root);
  const st = lstatSync(sidecar, { throwIfNoEntry: false });
  if (st === undefined) return null;
  if (st.isSymbolicLink()) throw sidecarRefusal(sidecar, "it is a symbolic link");
  if (!st.isFile()) throw sidecarRefusal(sidecar, "it is not a regular file");
  return claimOf(sidecar, st);
}

/** Re-check the sidecar AFTER the engine has run, before anything it returned
 *  is used. The engine opens the path itself, so between `confineSidecar` and
 *  its read the entry could be swapped for a link. If it was (or is still) not
 *  the same regular file we vetted, the result is discarded unread. This does
 *  not close the window — a swap that is put back before this runs is not seen;
 *  only an `O_NOFOLLOW` open inside the engine does (#1563). */
export function assertSidecarUnchanged(claim: SidecarClaim): void {
  const st = lstatSync(claim.path, { throwIfNoEntry: false });
  if (
    st === undefined ||
    !st.isFile() ||
    st.dev !== claim.dev ||
    st.ino !== claim.ino ||
    st.size !== claim.size ||
    st.mtimeMs !== claim.mtimeMs
  ) {
    throw sidecarRefusal(claim.path, "it changed while the engine was reading it");
  }
}
