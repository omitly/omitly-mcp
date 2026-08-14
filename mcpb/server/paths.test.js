/**
 * Confinement + magic-byte tests for the MCPB bundle's server/paths.js
 * (omitly#393 — this file previously had no test coverage at all, unlike its
 * sibling ../../src/paths.test.ts). Hermetic — everything happens under a
 * mkdtemp root. Plain CommonJS + node:test, matching paths.js itself (no
 * build step for this bundle).
 */
"use strict";

const assert = require("node:assert/strict");
const { mkdtempSync, realpathSync, symlinkSync, writeFileSync } = require("node:fs");
const { tmpdir } = require("node:os");
const path = require("node:path");
const { test } = require("node:test");
const { confineInput, isPdfMagic, readConfinedInput } = require("./paths.js");

function makeRoot() {
  // realpath because /tmp is a symlink on macOS — the module compares realpaths.
  return realpathSync(mkdtempSync(path.join(tmpdir(), "omitly-mcpb-paths-")));
}

test("input inside the root resolves; missing input is a clear error", () => {
  const root = makeRoot();
  writeFileSync(path.join(root, "doc.pdf"), "%PDF-1.7\n");
  assert.equal(confineInput(path.join(root, "doc.pdf"), root), path.join(root, "doc.pdf"));
  assert.equal(confineInput("doc.pdf", root), path.join(root, "doc.pdf"));
  assert.throws(() => confineInput(path.join(root, "absent.pdf"), root), /not found/);
});

test("input outside the root is refused", () => {
  const root = makeRoot();
  const outside = makeRoot();
  writeFileSync(path.join(outside, "secret.pdf"), "%PDF-1.7\n");
  assert.throws(() => confineInput(path.join(outside, "secret.pdf"), root), /outside the allowed/);
});

test("a symlink inside the root pointing outside it is refused", () => {
  const root = makeRoot();
  const outside = makeRoot();
  writeFileSync(path.join(outside, "secret.pdf"), "%PDF-1.7\n");
  symlinkSync(path.join(outside, "secret.pdf"), path.join(root, "innocent.pdf"));
  assert.throws(() => confineInput(path.join(root, "innocent.pdf"), root), /outside the allowed/);
});

test("isPdfMagic accepts a real PDF header and rejects non-PDF content", () => {
  assert.equal(isPdfMagic(Buffer.from("%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")), true);
  assert.equal(isPdfMagic(Buffer.from("<html><body>not a pdf</body></html>")), false);
  assert.equal(isPdfMagic(Buffer.from("%PD")), false); // shorter than the magic itself
  assert.equal(isPdfMagic(Buffer.alloc(0)), false);
});

test("readConfinedInput refuses a non-PDF file even though it's in-root and under the size cap", () => {
  const root = makeRoot();
  writeFileSync(path.join(root, "not-a-pdf.txt"), "just some text, not a PDF at all");
  assert.throws(
    () => readConfinedInput(path.join(root, "not-a-pdf.txt"), root),
    /does not look like a PDF/,
  );
});

test("readConfinedInput accepts a real PDF header", () => {
  const root = makeRoot();
  writeFileSync(path.join(root, "real.pdf"), "%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj");
  const bytes = readConfinedInput(path.join(root, "real.pdf"), root);
  assert.equal(bytes.subarray(0, 5).toString("ascii"), "%PDF-");
});
