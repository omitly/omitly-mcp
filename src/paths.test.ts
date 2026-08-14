/**
 * Confinement tests: every path here is what a model could plausibly supply.
 * Hermetic — everything happens under a mkdtemp root.
 */
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, mkdirSync, symlinkSync, writeFileSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { test } from "node:test";
import { allowedRoot, confineInput, confineOutput } from "./paths.js";

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

test("a symlink inside the root pointing outside it is refused", () => {
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

test("output via a symlinked parent directory that escapes the root is refused", () => {
  const root = makeRoot();
  const outside = makeRoot();
  symlinkSync(outside, path.join(root, "linked"));
  assert.throws(
    () => confineOutput(path.join(root, "linked", "out.pdf"), root),
    /outside the allowed/,
  );
});

test("output through a DANGLING final-component symlink that escapes the root is refused (#661)", () => {
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

test("output through a final-component symlink is refused even when it stays inside the root (#661)", () => {
  const root = makeRoot();
  // Same follow-the-link ambiguity one level down, so it is refused too —
  // an output name is meant to be fresh, and the model can pick another.
  symlinkSync(path.join(root, "real.pdf"), path.join(root, "alias.pdf"));
  assert.throws(() => confineOutput(path.join(root, "alias.pdf"), root), /symlink/);
});

test("a dangling symlink occupying the .audit.json sidecar name is refused (#661)", () => {
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
