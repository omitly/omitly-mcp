/**
 * Confinement tests: every path here is what a model could plausibly supply.
 * Hermetic — everything happens under a mkdtemp root.
 */
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { test } from "node:test";
import { allowedRoot, assertSidecarUnchanged, confineDir, confineInput, confineOutput, confineSidecar } from "./paths.js";

/** Windows without the symlink privilege (or Developer Mode) cannot create links at all: the tests that
 *  need one are skipped there, not failed. Always true on macOS and Linux. */
const canSymlink = ((): boolean => {
  const d = mkdtempSync(path.join(tmpdir(), "omitly-symlink-probe-"));
  try {
    symlinkSync(d, path.join(d, "l"));
    return true;
  } catch {
    return false;
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
})();

function makeRoot(): string {
  // realpath because /tmp is a symlink on macOS — the module compares realpaths.
  return realpathSync(mkdtempSync(path.join(tmpdir(), "omitly-mcp-paths-")));
}

test("input inside the root resolves; missing input is a clear error", () => {
  const root = makeRoot();
  writeFileSync(path.join(root, "doc.pdf"), "%PDF-");
  assert.equal(confineInput(path.join(root, "doc.pdf"), root), path.join(root, "doc.pdf"));
  // Relative paths resolve against the root, not the process cwd.
  assert.equal(confineInput("doc.pdf", root), path.join(root, "doc.pdf"));
  assert.throws(() => confineInput(path.join(root, "absent.pdf"), root), /not found/);
});

test("input outside the root is refused", () => {
  const root = makeRoot();
  const outside = makeRoot();
  writeFileSync(path.join(outside, "secret.pdf"), "%PDF-");
  assert.throws(() => confineInput(path.join(outside, "secret.pdf"), root), /outside the allowed/);
  assert.throws(() => confineInput("../" + path.basename(outside) + "/secret.pdf", root), /outside the allowed|not found/);
});

test("a symlink inside the root pointing outside it is refused", { skip: !canSymlink }, () => {
  const root = makeRoot();
  const outside = makeRoot();
  writeFileSync(path.join(outside, "secret.pdf"), "%PDF-");
  symlinkSync(path.join(outside, "secret.pdf"), path.join(root, "innocent.pdf"));
  assert.throws(() => confineInput(path.join(root, "innocent.pdf"), root), /outside the allowed/);
});

test("output confinement: outside refused, existing file and sidecar refused", () => {
  const root = makeRoot();
  const outside = makeRoot();
  assert.throws(() => confineOutput(path.join(outside, "out.pdf"), root), /outside the allowed/);

  // Fresh name inside the root is fine.
  assert.equal(confineOutput(path.join(root, "out.pdf"), root), path.join(root, "out.pdf"));

  // Never silently overwrite an existing output…
  writeFileSync(path.join(root, "taken.pdf"), "x");
  assert.throws(() => confineOutput(path.join(root, "taken.pdf"), root), /refusing to overwrite/);

  // …or an existing audit sidecar.
  writeFileSync(path.join(root, "sneaky.pdf.audit.json"), "{}");
  assert.throws(() => confineOutput(path.join(root, "sneaky.pdf"), root), /refusing to overwrite/);

  // A missing parent directory is a clear error, not a crash.
  assert.throws(() => confineOutput(path.join(root, "no-such-dir", "out.pdf"), root), /directory not found/);
});

test("output via a symlinked parent directory that escapes the root is refused", { skip: !canSymlink }, () => {
  const root = makeRoot();
  const outside = makeRoot();
  symlinkSync(outside, path.join(root, "linked"));
  assert.throws(
    () => confineOutput(path.join(root, "linked", "out.pdf"), root),
    /outside the allowed/,
  );
});

test("output through a DANGLING final-component symlink that escapes the root is refused (#661)", { skip: !canSymlink }, () => {
  const root = makeRoot();
  const outside = makeRoot();
  const target = path.join(outside, "escaped.pdf");
  // Dangling on purpose: the target does NOT exist. This is the case the
  // symlinked-PARENT test above does not reach — here the parent is genuinely
  // in-root and only the final component is the link, so realpath'ing the
  // parent proves nothing. `existsSync` follows the link and reports a
  // dangling one as absent, so the old no-clobber guard never fired and
  // confineOutput handed back an in-root path that wrote to `outside`.
  symlinkSync(target, path.join(root, "innocent.pdf"));
  assert.throws(() => confineOutput(path.join(root, "innocent.pdf"), root), /symlink/);
  // The escape must be refused, not merely reported: nothing may appear at the
  // link target as a side effect of the check.
  assert.equal(existsSync(target), false);
});

test("output through a final-component symlink is refused even when it stays inside the root (#661)", { skip: !canSymlink }, () => {
  const root = makeRoot();
  // Same follow-the-link ambiguity one level down, so it is refused too —
  // an output name is meant to be fresh, and the model can pick another.
  symlinkSync(path.join(root, "real.pdf"), path.join(root, "alias.pdf"));
  assert.throws(() => confineOutput(path.join(root, "alias.pdf"), root), /symlink/);
});

test("a dangling symlink occupying the .audit.json sidecar name is refused (#661)", { skip: !canSymlink }, () => {
  const root = makeRoot();
  const outside = makeRoot();
  // The PDF name is free, but the sidecar name is a dangling link out of root:
  // writing the audit sidecar would escape. `existsSync` could not see this.
  symlinkSync(path.join(outside, "leak.json"), path.join(root, "out.pdf.audit.json"));
  assert.throws(() => confineOutput(path.join(root, "out.pdf"), root), /refusing to overwrite/);
});

test("an in-root file whose name starts with two dots is not mistaken for an escape", () => {
  const root = makeRoot();
  writeFileSync(path.join(root, "..draft.pdf"), "%PDF-");
  // path.relative(root, "<root>/..draft.pdf") is the single segment
  // "..draft.pdf", which `startsWith("..")` wrongly flagged as an escape.
  assert.equal(confineInput(path.join(root, "..draft.pdf"), root), path.join(root, "..draft.pdf"));
  assert.equal(confineOutput("..draft2.pdf", root), path.join(root, "..draft2.pdf"));
});

test("an existing out-of-root path and a non-existent one refuse identically (no existence oracle)", () => {
  const root = makeRoot();
  const outside = makeRoot();
  const existing = path.join(outside, "secret.pdf");
  writeFileSync(existing, "%PDF-");
  const missing = path.join(outside, "does-not-exist.pdf");

  let existingMsg = "";
  try {
    confineInput(existing, root);
  } catch (e) {
    existingMsg = (e as Error).message;
  }
  let missingMsg = "";
  try {
    confineInput(missing, root);
  } catch (e) {
    missingMsg = (e as Error).message;
  }
  // Both paths are outside root, so both must refuse with the SAME reason
  // ("outside the allowed directory") — never one "not found" and the other
  // "outside the allowed directory", which would let a caller learn whether
  // an arbitrary out-of-root path exists on disk just by diffing the refusal
  // kind. (The path text itself naturally differs between the two calls.)
  assert.match(existingMsg, /outside the allowed/);
  assert.match(missingMsg, /outside the allowed/);
  assert.doesNotMatch(existingMsg, /not found/);
  assert.doesNotMatch(missingMsg, /not found/);
});

// omitly#1851: confineOutput must check containment of the RAW path before touching the filesystem.

/** The refusal text with the caller's own path text blanked, so two refusals for different paths can be compared byte for byte. */
function refusalWithout(fn: () => unknown, p: string): string {
  try {
    fn();
  } catch (e) {
    return (e as Error).message.split(`"${p}"`).join('"<P>"');
  }
  assert.fail(`expected a refusal for ${p}`);
}

test("confineOutput: an outside path refuses identically whether or not its folder exists (#1851)", () => {
  const root = makeRoot();
  const outside = makeRoot();
  mkdirSync(path.join(outside, "exists"));
  const base = path.basename(outside);
  const pairs: Array<[string, string]> = [
    [path.join(outside, "exists", "x.pdf"), path.join(outside, "nodir", "x.pdf")], // absolute
    [`../${base}/exists/x.pdf`, `../${base}/nodir/x.pdf`], // relative into an existing sibling tree
    ["../x.pdf", "../no-such-dir-1851/x.pdf"], // relative, the two shapes from the report
  ];
  for (const [present, absent] of pairs) {
    const a = refusalWithout(() => confineOutput(present, root), present);
    const b = refusalWithout(() => confineOutput(absent, root), absent);
    assert.match(a, /output path "<P>" is outside the allowed directory/);
    assert.equal(a, b, `${present} vs ${absent}`);
    assert.doesNotMatch(b, /not found/);
  }
});

test("confineOutput: an outside path is refused before any filesystem lookup (#1851)", () => {
  const root = makeRoot();
  // A NUL byte makes every fs call on the path throw. If the filesystem were consulted first the
  // answer would be "output directory not found"; refusing on the raw path gives the outside refusal.
  assert.throws(() => confineOutput("../a\0b/x.pdf", root), /outside the allowed directory/);
  assert.throws(() => confineOutput(path.join(path.dirname(root), "a\0b", "x.pdf"), root), /outside the allowed directory/);
});

test("confineOutput: the root itself, and a symlinked parent that escapes, are still refused after the reorder (#1851)", { skip: !canSymlink }, () => {
  const root = makeRoot();
  const outside = makeRoot();
  assert.throws(() => confineOutput(root, root), /outside the allowed directory/);
  assert.throws(() => confineOutput(".", root), /outside the allowed directory/);
  symlinkSync(outside, path.join(root, "linked"));
  assert.throws(() => confineOutput(path.join("linked", "x.pdf"), root), /outside the allowed directory/);
  assert.throws(() => confineOutput("linked/sub/x.pdf", root), /outside the allowed directory|directory not found/);
  // A final-component link out of the root is still refused.
  symlinkSync(path.join(outside, "target.pdf"), path.join(root, "out.pdf"));
  assert.throws(() => confineOutput("out.pdf", root), /refusing to write through a symlink/);
});

test("confineOutput: an output written through a symlink alias of the allowed directory is refused, as an input is (#1851)", { skip: !canSymlink }, () => {
  const root = makeRoot();
  const aliasHome = makeRoot();
  // The macOS shape: the root is reached through a link (/tmp or /var for /private/...).
  const alias = path.join(aliasHome, "alias");
  symlinkSync(root, alias);
  writeFileSync(path.join(root, "doc.pdf"), "%PDF-");
  // Inputs have always refused the alias spelling; outputs now match.
  assert.throws(() => confineInput(path.join(alias, "doc.pdf"), root), /outside the allowed directory/);
  assert.throws(() => confineOutput(path.join(alias, "out.pdf"), root), /outside the allowed directory/);
  assert.throws(() => confineOutput(path.join(alias, "no-such-dir", "out.pdf"), root), /outside the allowed directory/);
  // The same file under its real spelling is accepted.
  assert.equal(confineOutput(path.join(root, "out.pdf"), root), path.join(root, "out.pdf"));
});

test("confineOutput: an in-root path keeps its own messages and still works (#1851)", () => {
  const root = makeRoot();
  mkdirSync(path.join(root, "sub"));
  // Missing parent INSIDE the root keeps the existing wording.
  assert.throws(() => confineOutput("no-such-dir/x.pdf", root), { message: "output directory not found: no-such-dir" });
  assert.throws(() => confineOutput(path.join(root, "nope", "x.pdf"), root), /output directory not found/);
  // Normal inside paths resolve, absolute and relative, nested and with .. that stays inside.
  assert.equal(confineOutput("sub/x.pdf", root), path.join(root, "sub", "x.pdf"));
  assert.equal(confineOutput(path.join(root, "sub", "x.pdf"), root), path.join(root, "sub", "x.pdf"));
  assert.equal(confineOutput("sub/../y.pdf", root), path.join(root, "y.pdf"));
  // The overwrite refusal still holds.
  writeFileSync(path.join(root, "sub", "taken.pdf"), "x");
  assert.throws(() => confineOutput("sub/taken.pdf", root), /refusing to overwrite existing file/);
});

test("allowedRoot honours OMITLY_ALLOWED_DIR and rejects a missing dir", () => {
  const root = makeRoot();
  const prev = process.env.OMITLY_ALLOWED_DIR;
  try {
    process.env.OMITLY_ALLOWED_DIR = root;
    assert.equal(allowedRoot(), root);
    process.env.OMITLY_ALLOWED_DIR = path.join(root, "definitely-absent");
    assert.throws(() => allowedRoot(), /does not exist/);
  } finally {
    if (prev === undefined) delete process.env.OMITLY_ALLOWED_DIR;
    else process.env.OMITLY_ALLOWED_DIR = prev;
  }
});

// --- #1563: the DERIVED `<pdf>.audit.json` sidecar the engine reads for verify ---

test("confineSidecar: no entry is null, a regular file is claimed", () => {
  const root = makeRoot();
  const pdf = path.join(root, "doc.pdf");
  writeFileSync(pdf, "%PDF-");
  assert.equal(confineSidecar(pdf, root), null);
  writeFileSync(`${pdf}.audit.json`, "[]");
  const claim = confineSidecar(pdf, root);
  assert.equal(claim?.path, `${pdf}.audit.json`);
  assert.doesNotThrow(() => assertSidecarUnchanged(claim!));
});

test("confineSidecar: a symlink to a file outside the root is refused", { skip: !canSymlink }, () => {
  const root = makeRoot();
  const outside = makeRoot();
  const pdf = path.join(root, "doc.pdf");
  writeFileSync(pdf, "%PDF-");
  writeFileSync(path.join(outside, "other.audit.json"), "[]");
  symlinkSync(path.join(outside, "other.audit.json"), `${pdf}.audit.json`);
  assert.throws(() => confineSidecar(pdf, root), /refusing to verify against .*symbolic link/);
});

test("confineSidecar: a symlink to another file INSIDE the root is refused too", { skip: !canSymlink }, () => {
  const root = makeRoot();
  const pdf = path.join(root, "doc.pdf");
  writeFileSync(pdf, "%PDF-");
  mkdirSync(path.join(root, "matter-b"));
  writeFileSync(path.join(root, "matter-b", "b.pdf.audit.json"), "[]");
  symlinkSync(path.join(root, "matter-b", "b.pdf.audit.json"), `${pdf}.audit.json`);
  assert.throws(() => confineSidecar(pdf, root), /symbolic link/);
});

test("confineSidecar: a DANGLING symlink is refused, not read as 'no sidecar'", { skip: !canSymlink }, () => {
  const root = makeRoot();
  const outside = makeRoot();
  const pdf = path.join(root, "doc.pdf");
  writeFileSync(pdf, "%PDF-");
  symlinkSync(path.join(outside, "not-yet-created.json"), `${pdf}.audit.json`);
  assert.throws(() => confineSidecar(pdf, root), /symbolic link/);
});

test("confineSidecar: a directory at the sidecar name is refused", () => {
  const root = makeRoot();
  const pdf = path.join(root, "doc.pdf");
  writeFileSync(pdf, "%PDF-");
  mkdirSync(`${pdf}.audit.json`);
  assert.throws(() => confineSidecar(pdf, root), /not a regular file/);
});

test("confineSidecar: the refusal does not reveal where the link points", { skip: !canSymlink }, () => {
  const root = makeRoot();
  const outside = makeRoot();
  const pdf = path.join(root, "doc.pdf");
  writeFileSync(pdf, "%PDF-");
  const target = path.join(outside, "private-matter-name.json");
  symlinkSync(target, `${pdf}.audit.json`);
  assert.throws(
    () => confineSidecar(pdf, root),
    (e: Error) => !e.message.includes("private-matter-name") && !e.message.includes(outside),
  );
});

test("assertSidecarUnchanged: a sidecar swapped for a link after the claim is refused", { skip: !canSymlink }, () => {
  const root = makeRoot();
  const outside = makeRoot();
  const pdf = path.join(root, "doc.pdf");
  writeFileSync(pdf, "%PDF-");
  writeFileSync(`${pdf}.audit.json`, "[]");
  const claim = confineSidecar(pdf, root)!;
  writeFileSync(path.join(outside, "x.json"), "[]");
  rmSync(`${pdf}.audit.json`);
  symlinkSync(path.join(outside, "x.json"), `${pdf}.audit.json`);
  assert.throws(() => assertSidecarUnchanged(claim), /changed while the engine was reading/);
});

test("confineOutput: a symlink or dangling link at the output's .audit.json name is refused (existing guard, #661)", { skip: !canSymlink }, () => {
  const root = makeRoot();
  const outside = makeRoot();
  writeFileSync(path.join(outside, "victim.json"), "x");
  symlinkSync(path.join(outside, "victim.json"), path.join(root, "a.pdf.audit.json"));
  assert.throws(() => confineOutput(path.join(root, "a.pdf"), root), /refusing to overwrite/);
  symlinkSync(path.join(outside, "absent.json"), path.join(root, "b.pdf.audit.json"));
  assert.throws(() => confineOutput(path.join(root, "b.pdf"), root), /refusing to overwrite/);
});

// omitly#1841: confineDir (split_pdf's output folder).

test("confineDir accepts the root itself and a folder inside it (confineInput refuses the root)", () => {
  const root = makeRoot();
  mkdirSync(path.join(root, "parts"));
  assert.equal(confineDir(root, root), root);
  assert.equal(confineDir(".", root), root);
  assert.equal(confineDir("", root), root);
  assert.equal(confineDir("parts", root), path.join(root, "parts"));
  assert.equal(confineDir(path.join(root, "parts"), root), path.join(root, "parts"));
  assert.throws(() => confineInput(root, root), /outside the allowed/, "the contrast: confineInput refuses the root");
});

test("confineDir refuses a folder outside the root, by raw path, before touching the filesystem", () => {
  const root = makeRoot();
  const outside = makeRoot();
  // Same answer whether or not the outside folder exists: no existence oracle.
  assert.throws(() => confineDir(outside, root), /outside the allowed/);
  assert.throws(() => confineDir(path.join(outside, "nope"), root), /outside the allowed/);
  assert.throws(() => confineDir("..", root), /outside the allowed/);
  assert.throws(() => confineDir("../" + path.basename(outside), root), /outside the allowed/);
});

test("confineDir: a symlink inside the root that points outside is refused; one that stays inside is fine", { skip: !canSymlink }, () => {
  const root = makeRoot();
  const outside = makeRoot();
  mkdirSync(path.join(root, "real"));
  symlinkSync(outside, path.join(root, "escape"));
  symlinkSync(path.join(root, "real"), path.join(root, "inside"));
  assert.throws(() => confineDir("escape", root), /outside the allowed/);
  assert.equal(confineDir("inside", root), path.join(root, "real"));
});

test("confineDir: a missing folder and a file are 'That output folder does not exist.'", () => {
  const root = makeRoot();
  writeFileSync(path.join(root, "file.pdf"), "%PDF-");
  assert.throws(() => confineDir("absent", root), { message: "That output folder does not exist." });
  assert.throws(() => confineDir("file.pdf", root), { message: "That output folder does not exist." });
});
