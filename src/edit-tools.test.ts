/**
 * omitly#1841 phase B: the five page tools through a real MCP client, a real child
 * process and the real pdf-lib. Pure rules first, then each tool's happy path and
 * echoes, then every refusal code with its exact message.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdirSync, readFileSync, readdirSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { PDFBool, PDFDocument, PDFName, PDFNumber, PDFString } from "pdf-lib";
import { childEnvironment, foldedSameDir, isHiddenRelative, outputNameRefusal, rootNeedsExplicitDir, statSameDir } from "./edit-tools.js";
import {
  addCatalogExtras,
  canSymlink,
  ls,
  makeDoc,
  makeEncrypted,
  makeForm,
  makeSigned,
  pageMarkers,
  put,
  stub,
  stubMode,
  tempRoot,
  textOf,
  widths,
  withEditClient,
} from "./edit-fixtures.test.js";
import { messageFor } from "./pdf-edit/refusals.js";

const noTemps = (root: string) => ls(root).filter((n) => n.startsWith(".omitly-tmp-"));

// ---------------------------------------------------------------------------
// Pure rules
// ---------------------------------------------------------------------------

test("default-root rule: refuses only an UNSET root that is the filesystem root or the home folder", () => {
  const home = realpathSync(os.homedir());
  assert.equal(rootNeedsExplicitDir("/", false, home), true, "filesystem root, unset");
  assert.equal(rootNeedsExplicitDir(path.parse(process.cwd()).root, false, home), true);
  assert.equal(rootNeedsExplicitDir(home, false, home), true, "home, unset");
  assert.equal(rootNeedsExplicitDir(path.join(home, "Documents"), false, home), false, "a folder under home is fine");
  assert.equal(rootNeedsExplicitDir("/tmp/work", false, home), false);
  assert.equal(rootNeedsExplicitDir("/", true, home), false, "explicitly set to /, the owner chose it");
  assert.equal(rootNeedsExplicitDir(home, true, home), false, "explicitly set to home");
});

test("default-root rule, name fallback: case and trailing separators are folded on Windows and macOS, never on Linux", () => {
  // Windows: the same folder under another spelling is still the home folder.
  assert.equal(rootNeedsExplicitDir("c:\\users\\alice", false, "C:\\Users\\Alice", "win32", foldedSameDir("win32")), true);
  assert.equal(rootNeedsExplicitDir("C:\\Users\\Alice\\", false, "C:\\Users\\Alice", "win32", foldedSameDir("win32")), true, "trailing separator");
  assert.equal(rootNeedsExplicitDir("C:/Users/alice", false, "C:\\Users\\Alice", "win32", foldedSameDir("win32")), true, "forward slashes");
  assert.equal(rootNeedsExplicitDir("c:\\", false, "C:\\Users\\Alice", "win32", foldedSameDir("win32")), true, "the drive root, lower case");
  assert.equal(rootNeedsExplicitDir("C:\\", false, undefined, "win32", foldedSameDir("win32")), true);
  assert.equal(rootNeedsExplicitDir("c:\\users\\alice\\documents", false, "C:\\Users\\Alice", "win32", foldedSameDir("win32")), false, "a folder under home is fine");
  assert.equal(rootNeedsExplicitDir("c:\\users\\alice", true, "C:\\Users\\Alice", "win32", foldedSameDir("win32")), false, "explicit is never refused");
  // macOS: a case-only difference is the same folder on the default APFS.
  assert.equal(rootNeedsExplicitDir("/users/alice", false, "/Users/Alice", "darwin", foldedSameDir("darwin")), true);
  assert.equal(rootNeedsExplicitDir("/Users/Alice/", false, "/Users/Alice", "darwin", foldedSameDir("darwin")), true);
  assert.equal(rootNeedsExplicitDir("/Users/Alice/Documents", false, "/Users/Alice", "darwin", foldedSameDir("darwin")), false);
  // Linux stays exact.
  assert.equal(rootNeedsExplicitDir("/home/alice", false, "/home/alice", "linux", foldedSameDir("linux")), true);
  assert.equal(rootNeedsExplicitDir("/home/Alice", false, "/home/alice", "linux", foldedSameDir("linux")), false, "different folders on a case-sensitive filesystem");
  assert.equal(rootNeedsExplicitDir("/home/alice/", false, "/home/alice", "linux", foldedSameDir("linux")), true, "trailing slash");
  assert.equal(rootNeedsExplicitDir("/", false, "/home/alice", "linux", foldedSameDir("linux")), true);
});

test("default-root rule: folders are compared by FILE IDENTITY, not by name", () => {
  const root = tempRoot();
  mkdirSync(path.join(root, "sub"));
  // The same folder under two spellings.
  assert.equal(statSameDir(path.join(root, "sub"), path.join(root, "sub", "..", "sub")), true);
  assert.equal(statSameDir(path.join(root, "sub") + path.sep, path.join(root, "sub")), true);
  assert.equal(statSameDir(path.join(root, "sub"), root), false);
  if (canSymlink) {
    symlinkSync(path.join(root, "sub"), path.join(root, "alias"));
    assert.equal(statSameDir(path.join(root, "alias"), path.join(root, "sub")), true, "identity sees through a link; a name comparison cannot");
    assert.equal(rootNeedsExplicitDir(path.join(root, "alias"), false, path.join(root, "sub")), true, "the home folder reached through a link");
  }
  // Two folders that differ only in case, where the filesystem has two of them (APFS case-sensitive, ext4).
  mkdirSync(path.join(root, "a"));
  let two = true;
  try {
    mkdirSync(path.join(root, "A"));
  } catch {
    two = false; // a case-insensitive volume: `A` is `a`
  }
  if (two) assert.equal(statSameDir(path.join(root, "a"), path.join(root, "A")), false, "two distinct folders");
  else assert.equal(statSameDir(path.join(root, "a"), path.join(root, "A")), true, "one folder, two spellings");
  // The guard itself, on real folders.
  assert.equal(rootNeedsExplicitDir(path.join(root, "sub", "..", "sub"), false, path.join(root, "sub")), true, "the home folder under another spelling");
  assert.equal(rootNeedsExplicitDir(path.join(root, "sub"), false, root), false);
  // A name that cannot be stat'ed falls back to names.
  assert.equal(statSameDir("/no/such/Folder-1841", "/no/such/Folder-1841/", "linux"), true);
  assert.equal(statSameDir("/no/such/Folder-1841", "/no/such/folder-1841", "linux"), false);
});

test("default-root rule: an unknown home folder (os.homedir() threw) leaves only the filesystem-root check", () => {
  assert.equal(rootNeedsExplicitDir("/", false, undefined), true);
  assert.equal(rootNeedsExplicitDir("/tmp/work", false, undefined), false);
  assert.equal(rootNeedsExplicitDir("/", true, undefined), false);
});

test("child environment: empty everywhere; Windows gets exactly SystemRoot and WINDIR (found case-insensitively); Electron adds ELECTRON_RUN_AS_NODE", () => {
  const env = { SYSTEMROOT: "C:\\Windows", windir: "C:\\Windows", Path: "C:\\x", NODE_OPTIONS: "--x", OMITLY_STATE_DIR: "/s", HOME: "/h" };
  assert.deepEqual(childEnvironment({ platform: "linux", env, electron: false }), {});
  assert.deepEqual(childEnvironment({ platform: "darwin", env, electron: true }), { ELECTRON_RUN_AS_NODE: "1" });
  assert.deepEqual(childEnvironment({ platform: "win32", env, electron: false }), { SystemRoot: "C:\\Windows", WINDIR: "C:\\Windows" });
  assert.deepEqual(childEnvironment({ platform: "win32", env, electron: true }), { SystemRoot: "C:\\Windows", WINDIR: "C:\\Windows", ELECTRON_RUN_AS_NODE: "1" });
  assert.deepEqual(childEnvironment({ platform: "win32", env: { Path: "x" }, electron: false }), {}, "absent is absent");
});

test("output name rules: .pdf case-insensitive, ADS colon, Windows device names, trailing dot or space", () => {
  for (const ok of ["a.pdf", "A.PDF", "report.final.Pdf", "x y.pdf", "COM10.pdf", "CONSOLE.pdf", "aux-1.pdf", "com.pdf"]) {
    assert.equal(outputNameRefusal(ok), null, ok);
  }
  for (const bad of [
    "a.txt", "a", "a.pdf.exe", ".pdf.", "a.pdf.", "a.pdf ", "a.pdf  ",
    "x.pdf:hidden", "x:y.pdf", "C:x.pdf",
    "CON.pdf", "con.pdf", "PRN.pdf", "AUX.pdf", "NUL.pdf", "nul.PDF", "COM1.pdf", "com9.pdf", "LPT1.pdf", "lpt9.pdf",
    "CON.txt.pdf", "NUL .pdf", "COM¹.pdf", "a<b.pdf", "a|b.pdf", "a\u0000b.pdf",
  ]) {
    assert.equal(outputNameRefusal(bad), "not_pdf_name", JSON.stringify(bad));
  }
});

test("hidden-path rule is measured relative to the root", () => {
  assert.equal(isHiddenRelative("/r", "/r/a/b.pdf"), false);
  assert.equal(isHiddenRelative("/r", "/r/.hidden/b.pdf"), true);
  assert.equal(isHiddenRelative("/r", "/r/a/.git/b.pdf"), true);
  assert.equal(isHiddenRelative("/r", "/r/.b.pdf"), true, "a hidden file name too");
  assert.equal(isHiddenRelative("/r", "/r/..draft.pdf"), true);
  // A root that itself sits under a dot-folder still works.
  assert.equal(isHiddenRelative("/home/u/.work/pdfs", "/home/u/.work/pdfs/out.pdf"), false);
  assert.equal(isHiddenRelative("/home/u/.work/pdfs", "/home/u/.work/pdfs/sub/out.pdf"), false);
});

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

test("the SDK accepts annotations: tools/list carries title and the four hints", async () => {
  const root = tempRoot();
  await withEditClient(root, {}, async (_call, client) => {
    const { tools } = await client.listTools();
    assert.deepEqual(tools.map((t) => t.name).sort(), ["edit_pages", "extract_pages", "merge_pdfs", "pdf_info", "split_pdf"]);
    for (const t of tools) {
      assert.ok(t.annotations?.title, `${t.name} has a title`);
      assert.equal(t.annotations?.readOnlyHint, t.name === "pdf_info", `${t.name} readOnlyHint`);
      assert.equal(t.annotations?.destructiveHint, false);
      assert.equal(t.annotations?.idempotentHint, t.name === "pdf_info", `${t.name} idempotentHint`);
      assert.equal(t.annotations?.openWorldHint, false);
      assert.ok(t.outputSchema, `${t.name} has an output schema`);
    }
    for (const n of ["extract_pages", "split_pdf", "edit_pages"]) {
      assert.match(tools.find((t) => t.name === n)!.description!, /start at 1/, `${n} states the 1-based rule`);
    }
  });
});

// ---------------------------------------------------------------------------
// Happy paths and echoes
// ---------------------------------------------------------------------------

test("pdf_info: normal document", async () => {
  const root = tempRoot();
  put(root, "a.pdf", await makeDoc("A", 3));
  await withEditClient(root, {}, async (call) => {
    const r = await call("pdf_info", { pdfPath: "a.pdf" });
    assert.ok(!r.isError, textOf(r));
    const s = r.structuredContent;
    assert.equal(s.pageCount, 3);
    assert.deepEqual(s.pages.map((p: any) => [p.pageNumber, p.widthPt, p.heightPt, p.rotation]), [[1, 300, 400, 0], [2, 310, 400, 0], [3, 320, 400, 0]]);
    assert.equal(s.pagesTruncated, false);
    assert.equal(s.encrypted, false);
    assert.equal(s.hasForm, false);
    assert.equal(s.formFieldCount, 0);
    assert.equal(s.hasSignatures, false);
    assert.equal(s.hasComments, false);
    assert.equal(s.hasXfa, "none");
    assert.equal(s.hasLayers, false);
    assert.equal(s.byteSize, readFileSync(path.join(root, "a.pdf")).length);
    assert.ok(!JSON.stringify(s).includes("A-1"), "no text or markers in the answer");
  });
});

test("pdf_info: encrypted, signed, form, comments, layers, XFA, rotation values, truncation", async () => {
  const root = tempRoot();
  put(root, "enc.pdf", await makeEncrypted(2));
  put(root, "signed.pdf", await makeSigned());
  put(root, "form.pdf", await makeForm(3));
  put(
    root,
    "misc.pdf",
    await makeDoc("M", 4, (doc) => {
      const pages = doc.getPages();
      pages[1].node.set(PDFName.of("Rotate"), PDFNumber.of(450));
      pages[2].node.set(PDFName.of("Rotate"), PDFNumber.of(45));
      pages[3].node.set(PDFName.of("Rotate"), PDFNumber.of(-90));
      pages[0].node.set(PDFName.of("Annots"), doc.context.obj([doc.context.obj({ Type: "Annot", Subtype: "Text", Rect: [0, 0, 10, 10] })]));
      addCatalogExtras(doc, { layers: true, xfa: "static" });
    }),
  );
  put(root, "dyn.pdf", await makeDoc("D", 1, (doc) => addCatalogExtras(doc, { xfa: "dynamic" })));
  put(root, "big.pdf", await makeDoc("B", 501));
  await withEditClient(root, {}, async (call) => {
    const enc = (await call("pdf_info", { pdfPath: "enc.pdf" })).structuredContent;
    assert.equal(enc.encrypted, true);
    assert.equal(enc.pageCount, 2);
    const signed = (await call("pdf_info", { pdfPath: "signed.pdf" })).structuredContent;
    assert.equal(signed.hasSignatures, true);
    assert.equal(signed.hasForm, true);
    const form = (await call("pdf_info", { pdfPath: "form.pdf" })).structuredContent;
    assert.equal(form.hasForm, true);
    assert.equal(form.formFieldCount, 3);
    assert.equal(form.hasSignatures, false);
    const misc = (await call("pdf_info", { pdfPath: "misc.pdf" })).structuredContent;
    assert.equal(misc.hasComments, true);
    assert.equal(misc.hasLayers, true);
    assert.equal(misc.hasXfa, "static");
    assert.deepEqual(misc.pages.map((p: any) => p.rotation), [0, 90, 45, 270], "normalised to 0/90/180/270; raw if not a multiple of 90");
    const dyn = (await call("pdf_info", { pdfPath: "dyn.pdf" })).structuredContent;
    assert.equal(dyn.hasXfa, "dynamic");
    const big = (await call("pdf_info", { pdfPath: "big.pdf" })).structuredContent;
    assert.equal(big.pageCount, 501);
    assert.equal(big.pages.length, 500);
    assert.equal(big.pagesTruncated, true);
  });
});

test("extract_pages: order, sourcePages echo, markers follow their pages", async () => {
  const root = tempRoot();
  put(root, "a.pdf", await makeDoc("A", 5));
  await withEditClient(root, {}, async (call) => {
    const r = await call("extract_pages", { pdfPath: "a.pdf", pages: [4, "1-2"], outputPath: "out.pdf" });
    assert.ok(!r.isError, textOf(r));
    const s = r.structuredContent;
    assert.equal(s.outputPath, path.join(root, "out.pdf"));
    assert.equal(s.pageCount, 3);
    assert.deepEqual(s.sourcePages, [4, 1, 2]);
    assert.deepEqual(s.warnings, []);
    assert.deepEqual(s.lost, []);
    const out = readFileSync(s.outputPath);
    assert.equal(s.byteSize, out.length);
    assert.deepEqual(await pageMarkers(out), ["A-4", "A-1", "A-2"]);
    assert.deepEqual(await widths(out), [330, 300, 310]);
  });
  assert.deepEqual(noTemps(root), []);
});

test("split_pdf: names, sourcePages, pageCount, byteSize, outputDir may be the root itself", async () => {
  const root = tempRoot();
  mkdirSync(path.join(root, "parts"));
  put(root, "a.pdf", await makeDoc("A", 6));
  await withEditClient(root, {}, async (call) => {
    const r = await call("split_pdf", { pdfPath: "a.pdf", ranges: [["1-2"], [3], [4, 5, 6]], outputDir: "parts", prefix: "book" });
    assert.ok(!r.isError, textOf(r));
    const files = r.structuredContent.files;
    assert.deepEqual(files.map((f: any) => path.basename(f.outputPath)), ["book-p1-2.pdf", "book-p3.pdf", "book-p4-6.pdf"]);
    assert.deepEqual(files.map((f: any) => f.sourcePages), [[1, 2], [3], [4, 5, 6]]);
    assert.deepEqual(files.map((f: any) => f.pageCount), [2, 1, 3]);
    for (const f of files) {
      assert.equal(f.byteSize, readFileSync(f.outputPath).length);
      assert.ok(f.outputPath.startsWith(path.join(root, "parts") + path.sep));
    }
    assert.deepEqual(await pageMarkers(readFileSync(files[2].outputPath)), ["A-4", "A-5", "A-6"]);
    const r2 = await call("split_pdf", { pdfPath: "a.pdf", ranges: [[1]], outputDir: ".", prefix: "root" });
    assert.ok(!r2.isError, textOf(r2));
    assert.equal(r2.structuredContent.files[0].outputPath, path.join(root, "root-p1.pdf"));
  });
  assert.deepEqual(noTemps(path.join(root, "parts")), []);
  assert.deepEqual(noTemps(root), []);
});

test("merge_pdfs: order, per-source page counts, forms kept, a clashing field name renamed with a warning", async () => {
  const root = tempRoot();
  put(root, "a.pdf", await makeDoc("A", 2));
  put(root, "b.pdf", await makeDoc("B", 3));
  put(root, "f1.pdf", await makeForm(2));
  put(root, "f2.pdf", await makeForm(2));
  await withEditClient(root, {}, async (call) => {
    const r = await call("merge_pdfs", { inputs: ["a.pdf", "b.pdf", "a.pdf"], outputPath: "m.pdf" });
    assert.ok(!r.isError, textOf(r));
    const s = r.structuredContent;
    assert.equal(s.pageCount, 7);
    assert.deepEqual(s.sources, [{ input: "a.pdf", pages: 2 }, { input: "b.pdf", pages: 3 }, { input: "a.pdf", pages: 2 }]);
    assert.deepEqual(await pageMarkers(readFileSync(s.outputPath)), ["A-1", "A-2", "B-1", "B-2", "B-3", "A-1", "A-2"]);

    const f = await call("merge_pdfs", { inputs: ["f1.pdf", "f2.pdf"], outputPath: "forms.pdf" });
    assert.ok(!f.isError, textOf(f));
    assert.equal(f.structuredContent.warnings.length, 1);
    assert.match(f.structuredContent.warnings[0], /renamed/);
    const info = (await call("pdf_info", { pdfPath: "forms.pdf" })).structuredContent;
    assert.equal(info.formFieldCount, 4, "both forms' fields are kept");
    assert.equal(info.pageCount, 2);
  });
});

test("edit_pages: reorder, delete, rotate (added to the existing turn), blanks, layout echo", async () => {
  const root = tempRoot();
  put(
    root,
    "a.pdf",
    await makeDoc("A", 4, (doc) => {
      doc.getPages()[0].node.set(PDFName.of("Rotate"), PDFNumber.of(90));
      doc.getPages()[2].node.set(PDFName.of("Rotate"), PDFNumber.of(45)); // a real file may carry one
    }),
  );
  await withEditClient(root, {}, async (call) => {
    const r = await call("edit_pages", {
      pdfPath: "a.pdf",
      pages: [{ source: 3, rotate: 90 }, { blank: true }, { source: 1, rotate: 270 }, { blank: true, size: "Letter" }, { blank: true, size: "A4" }, { source: 4 }],
      outputPath: "out.pdf",
    });
    assert.ok(!r.isError, textOf(r));
    const s = r.structuredContent;
    assert.deepEqual(s.layout, [
      { pageNumber: 1, from: 3, rotation: 135 },
      { pageNumber: 2, from: "blank", rotation: 0 },
      { pageNumber: 3, from: 1, rotation: 0 },
      { pageNumber: 4, from: "blank", rotation: 0 },
      { pageNumber: 5, from: "blank", rotation: 0 },
      { pageNumber: 6, from: 4, rotation: 0 },
    ]);
    assert.equal(s.pageCount, 6);
    const out = await PDFDocument.load(readFileSync(s.outputPath));
    const pages = out.getPages();
    assert.deepEqual(pages.map((p) => p.getRotation().angle), [135, 0, 0, 0, 0, 0].map((x, i) => (i === 0 ? 135 : x)));
    // Blank sizes: "previous" is the page before it (page 3 is 300 wide; page 1 is source 3 = 320 wide), Letter, A4.
    assert.deepEqual(pages[1].getSize(), { width: 320, height: 400 }, "previous = the size of the previous OUTPUT page");
    assert.deepEqual(pages[3].getSize(), { width: 612, height: 792 }, "Letter");
    assert.deepEqual([Math.round(pages[4].getWidth() * 100) / 100, Math.round(pages[4].getHeight() * 100) / 100], [595.28, 841.89], "A4");
    assert.deepEqual(await pageMarkers(readFileSync(s.outputPath)), ["A-3", "", "A-1", "", "", "A-4"]);

    const first = await call("edit_pages", { pdfPath: "a.pdf", pages: [{ blank: true }, { source: 2 }], outputPath: "first.pdf" });
    const fo = await PDFDocument.load(readFileSync(first.structuredContent.outputPath));
    assert.deepEqual([Math.round(fo.getPages()[0].getWidth()), Math.round(fo.getPages()[0].getHeight())], [595, 842], "a blank first with 'previous' is A4");

    const rot = await call("edit_pages", { pdfPath: "a.pdf", pages: [{ source: 1, rotate: 90 }, { source: 2, rotate: 180 }], outputPath: "rot.pdf" });
    assert.deepEqual(rot.structuredContent.layout.map((l: any) => l.rotation), [180, 180]);
    const rotated = await PDFDocument.load(readFileSync(rot.structuredContent.outputPath));
    assert.deepEqual(rotated.getPages().map((p) => p.getRotation().angle), [180, 180]);
  });
});

// ---------------------------------------------------------------------------
// Refusals: every code, exact message, nothing written
// ---------------------------------------------------------------------------

async function refused(call: (n: string, a: Record<string, unknown>) => Promise<any>, name: string, args: Record<string, unknown>, expected: string): Promise<void> {
  const r = await call(name, args);
  assert.equal(r.isError, true, `${name} should be refused; got ${textOf(r)}`);
  assert.equal(textOf(r), expected);
  assert.equal(r.structuredContent, undefined, "a refusal carries no structured content");
}

test("refusals at the tool boundary use the exact fixed messages and write nothing", async () => {
  const root = tempRoot();
  mkdirSync(path.join(root, "sub"));
  mkdirSync(path.join(root, ".hidden"));
  mkdirSync(path.join(root, ".git"));
  put(root, "a.pdf", await makeDoc("A", 4));
  put(root, "enc.pdf", await makeEncrypted());
  put(root, "dyn.pdf", await makeDoc("D", 2, (doc) => addCatalogExtras(doc, { xfa: "dynamic" })));
  put(root, "text.pdf", "this is just text, not a pdf\n");
  put(root, "exists.pdf", "keep me");
  const before = ls(root);
  await withEditClient(root, {}, async (call) => {
    const out = { outputPath: "out.pdf" };
    // not_a_file / not_pdf
    await refused(call, "pdf_info", { pdfPath: "sub" }, messageFor("not_a_file"));
    await refused(call, "pdf_info", { pdfPath: "text.pdf" }, messageFor("not_pdf"));
    // output names
    for (const bad of ["out.txt", "out.pdf:hidden", "CON.pdf", "nul.pdf", "COM1.pdf", "out.pdf.", "out.pdf "]) {
      await refused(call, "extract_pages", { pdfPath: "a.pdf", pages: [1], outputPath: bad }, messageFor("not_pdf_name"));
    }
    // hidden
    for (const bad of [".hidden/out.pdf", ".git/out.pdf", ".out.pdf"]) {
      await refused(call, "extract_pages", { pdfPath: "a.pdf", pages: [1], outputPath: bad }, messageFor("hidden_path"));
    }
    // pass-through messages from confineInput / confineOutput
    const r1 = await call("extract_pages", { pdfPath: "absent.pdf", pages: [1], ...out });
    assert.equal(r1.isError, true);
    assert.equal(textOf(r1), "input file not found: absent.pdf");
    const r2 = await call("extract_pages", { pdfPath: "../outside.pdf", pages: [1], ...out });
    assert.match(textOf(r2), /outside the allowed directory/);
    const r3 = await call("extract_pages", { pdfPath: "a.pdf", pages: [1], outputPath: "exists.pdf" });
    assert.match(textOf(r3), /^refusing to overwrite existing file: .*exists\.pdf\. Choose a new output name\.$/);
    const r4 = await call("extract_pages", { pdfPath: "a.pdf", pages: [1], outputPath: "nodir/out.pdf" });
    assert.match(textOf(r4), /^output directory not found: nodir$/);
    // page specs, through a tool
    const spec = (item: unknown) => `Page item "${item}" is not valid: use a page number like 3 or a range like "2-5".`;
    await refused(call, "extract_pages", { pdfPath: "a.pdf", pages: ["5"], ...out }, spec("5"));
    await refused(call, "extract_pages", { pdfPath: "a.pdf", pages: ["01-03"], ...out }, spec("01-03"));
    await refused(call, "extract_pages", { pdfPath: "a.pdf", pages: ["4-2"], ...out }, spec("4-2"));
    await refused(call, "extract_pages", { pdfPath: "a.pdf", pages: [0], ...out }, spec("0"));
    await refused(call, "extract_pages", { pdfPath: "a.pdf", pages: [-3], ...out }, spec("-3"));
    await refused(call, "extract_pages", { pdfPath: "a.pdf", pages: [2.5], ...out }, spec("2.5"));
    await refused(call, "extract_pages", { pdfPath: "a.pdf", pages: [1, "1-2"], ...out }, "Page 1 is listed twice.");
    await refused(call, "extract_pages", { pdfPath: "a.pdf", pages: ["1-10001"], ...out }, messageFor("too_many_pages"));
    await refused(call, "extract_pages", { pdfPath: "a.pdf", pages: [2, "3-9"], ...out }, 'Page item "3-9" is past the end: this PDF has 4 pages.');
    await refused(call, "extract_pages", { pdfPath: "a.pdf", pages: [9], ...out }, 'Page item "9" is past the end: this PDF has 4 pages.');
    // edit_pages
    await refused(call, "edit_pages", { pdfPath: "a.pdf", pages: [{ source: 1 }, { source: 1, rotate: 90 }], ...out }, "Page 1 is listed twice.");
    await refused(call, "edit_pages", { pdfPath: "a.pdf", pages: [{ blank: true }], ...out }, messageFor("no_source_pages"));
    await refused(call, "edit_pages", { pdfPath: "a.pdf", pages: [{ source: 1 }, { source: 7 }], ...out }, 'Page item "7" is past the end: this PDF has 4 pages.');
    // split
    const base = { pdfPath: "a.pdf", outputDir: "sub", prefix: "p" };
    await refused(call, "split_pdf", { ...base, ranges: [[1, 3]] }, messageFor("split_not_contiguous"));
    await refused(call, "split_pdf", { ...base, ranges: [[2, 1]] }, messageFor("split_not_contiguous"));
    await refused(call, "split_pdf", { ...base, ranges: [["1-2"], [1, 2]] }, 'Two ranges would both be named "p-p1-2.pdf".');
    await refused(call, "split_pdf", { ...base, ranges: [["2-9"]] }, 'Page item "2-9" is past the end: this PDF has 4 pages.');
    await refused(call, "split_pdf", { ...base, ranges: [["x-y"]] }, spec("x-y"));
    await refused(call, "split_pdf", { ...base, outputDir: "nodir", ranges: [[1]] }, messageFor("not_a_directory"));
    await refused(call, "split_pdf", { ...base, outputDir: "a.pdf", ranges: [[1]] }, messageFor("not_a_directory"));
    await refused(call, "split_pdf", { ...base, outputDir: ".hidden", ranges: [[1]] }, messageFor("hidden_path"));
    const out2 = await call("split_pdf", { ...base, outputDir: "../", ranges: [[1]] });
    assert.match(textOf(out2), /outside the allowed directory/);
    const tooMany = await call("split_pdf", { ...base, ranges: [["1-6000"], ["6001-12000"]] });
    assert.equal(textOf(tooMany), messageFor("too_many_pages"), "a split's total is capped at 10,000 pages across ranges");
    // the child's refusals
    await refused(call, "extract_pages", { pdfPath: "enc.pdf", pages: [1], ...out }, messageFor("encrypted"));
    await refused(call, "edit_pages", { pdfPath: "enc.pdf", pages: [{ source: 1 }], ...out }, messageFor("encrypted"));
    await refused(call, "split_pdf", { ...base, pdfPath: "enc.pdf", ranges: [[1]] }, messageFor("encrypted"));
    await refused(call, "merge_pdfs", { inputs: ["a.pdf", "enc.pdf"], ...out }, `Input 2: ${messageFor("encrypted")}`);
    await refused(call, "merge_pdfs", { inputs: ["text.pdf", "a.pdf"], ...out }, `Input 1: ${messageFor("not_pdf")}`);
    await refused(call, "merge_pdfs", { inputs: ["a.pdf", "dyn.pdf"], ...out }, `Input 2: ${messageFor("xfa")}`);
    await refused(call, "merge_pdfs", { inputs: ["a.pdf", "sub"], ...out }, `Input 2: ${messageFor("not_a_file")}`);
    await refused(call, "extract_pages", { pdfPath: "dyn.pdf", pages: [1], ...out }, messageFor("xfa"));
    await refused(call, "edit_pages", { pdfPath: "dyn.pdf", pages: [{ source: 1 }], ...out }, messageFor("xfa"));
    await refused(call, "split_pdf", { ...base, pdfPath: "dyn.pdf", ranges: [[1]] }, messageFor("xfa"));
    // shape errors come from the schema (zod), still an error result
    for (const [name, args] of [
      ["merge_pdfs", { inputs: ["a.pdf"], ...out }],
      ["extract_pages", { pdfPath: "a.pdf", pages: [], ...out }],
      ["split_pdf", { ...base, prefix: "../x", ranges: [[1]] }],
      ["edit_pages", { pdfPath: "a.pdf", pages: [{ source: 1, rotate: 45 }], ...out }],
    ] as const) {
      const r = await call(name, args as any);
      assert.equal(r.isError, true, `${name} ${JSON.stringify(args)}`);
    }
  });
  assert.deepEqual(ls(root), before, "no refused call wrote or left a file");
  assert.deepEqual(ls(path.join(root, "sub")), []);
});

test("too_large and output_too_large use caps from the seam", async () => {
  const root = tempRoot();
  const a = await makeDoc("A", 6);
  put(root, "a.pdf", a);
  put(root, "b.pdf", a);
  await withEditClient(root, { caps: { perFileBytes: 100 } }, async (call) => {
    await refused(call, "pdf_info", { pdfPath: "a.pdf" }, messageFor("too_large"));
    await refused(call, "merge_pdfs", { inputs: ["a.pdf", "b.pdf"], outputPath: "m.pdf" }, `Input 1: ${messageFor("too_large")}`);
  });
  await withEditClient(root, { caps: { totalBytes: a.length + 10 } }, async (call) => {
    await refused(call, "merge_pdfs", { inputs: ["a.pdf", "b.pdf"], outputPath: "m.pdf" }, `Input 2: ${messageFor("too_large")}`);
  });
  // A split whose files together pass the cap: the second file would cross it.
  await withEditClient(root, { caps: { splitTotalBytes: 900 } }, async (call) => {
    await refused(call, "split_pdf", { pdfPath: "a.pdf", ranges: [["1-3"], ["4-6"]], outputDir: ".", prefix: "s" }, messageFor("output_too_large"));
  });
  assert.deepEqual(ls(root), ["a.pdf", "b.pdf"], "nothing left behind, temp files included");
});

test("allowed_dir_needed: an unset root that is the home folder or the filesystem root is refused before any file is touched", async () => {
  const home = realpathSync(os.homedir());
  for (const root of [home, path.parse(home).root]) {
    await withEditClient(root, { rootExplicit: false }, async (call) => {
      const m = messageFor("allowed_dir_needed");
      await refused(call, "pdf_info", { pdfPath: "x.pdf" }, m);
      await refused(call, "merge_pdfs", { inputs: ["a.pdf", "b.pdf"], outputPath: "m.pdf" }, m);
      await refused(call, "extract_pages", { pdfPath: "x.pdf", pages: [1], outputPath: "o.pdf" }, m);
      await refused(call, "split_pdf", { pdfPath: "x.pdf", ranges: [[1]], outputDir: ".", prefix: "p" }, m);
      await refused(call, "edit_pages", { pdfPath: "x.pdf", pages: [{ source: 1 }], outputPath: "o.pdf" }, m);
    });
  }
  // The same root, explicitly chosen, is not refused for that reason.
  await withEditClient(home, { rootExplicit: true }, async (call) => {
    const r = await call("pdf_info", { pdfPath: "definitely-not-here-1841.pdf" });
    assert.equal(textOf(r), "input file not found: definitely-not-here-1841.pdf");
  });
});

test("a symlink: an input link out of the root is refused; an output that is a link is refused", { skip: !canSymlink }, async () => {
  const root = tempRoot();
  const outside = tempRoot();
  put(outside, "secret.pdf", await makeDoc("S", 1));
  put(root, "a.pdf", await makeDoc("A", 2));
  symlinkSync(path.join(outside, "secret.pdf"), path.join(root, "link.pdf"));
  symlinkSync(path.join(outside, "new.pdf"), path.join(root, "dangling.pdf"));
  await withEditClient(root, {}, async (call) => {
    assert.match(textOf(await call("pdf_info", { pdfPath: "link.pdf" })), /outside the allowed directory/);
    const r = await call("extract_pages", { pdfPath: "a.pdf", pages: [1], outputPath: "dangling.pdf" });
    assert.match(textOf(r), /refusing to write through a symlink/);
  });
  assert.deepEqual(ls(outside), ["secret.pdf"], "nothing was created through the link");
});
