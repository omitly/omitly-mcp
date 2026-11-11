/**
 * omitly#1841 phase A: pageOps moved here from the desktop app (src/edit/).
 * These tests run from compiled dist in plain Node ESM against the real
 * pdf-lib, with every PDF generated in-test. Assertions are on observable
 * output only: page count, page sizes, rotation, and marker text in the
 * content streams.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { PDFArray, PDFDict, PDFDocument, PDFName, PDFRawStream, PDFString, StandardFonts, decodePDFRawStream } from "pdf-lib";
import {
  appendPdf,
  deletePage,
  extractPages,
  getPageRotation,
  insertBlankPage,
  reorderPages,
  rotatePage,
} from "./pageOps.js";

/** Build a PDF whose page i is (300 + 10*i) wide, 400 tall, and carries the
 * visible marker `${tag}${i}`. Width identifies the page; the marker proves the
 * content stream travelled with it. */
async function makeDoc(tag: string, count: number): Promise<Uint8Array> {
  const doc = await PDFDocument.create();
  const font = await doc.embedFont(StandardFonts.Helvetica);
  for (let i = 0; i < count; i++) {
    const page = doc.addPage([300 + 10 * i, 400]);
    page.drawText(`${tag}${i}`, { x: 20, y: 200, size: 18, font });
  }
  return doc.save();
}

/** Markers drawn on page `index`, decoded from its content streams. */
function markersOf(doc: PDFDocument, index: number): string[] {
  const page = doc.getPages()[index];
  const contents = page.node.Contents();
  const streams = contents instanceof PDFArray ? contents.asArray().map((r) => doc.context.lookup(r)) : [contents];
  const out: string[] = [];
  for (const s of streams) {
    if (!(s instanceof PDFRawStream)) continue;
    const text = Buffer.from(decodePDFRawStream(s).decode()).toString("latin1");
    for (const m of text.matchAll(/<([0-9A-Fa-f]+)>\s*Tj/g)) out.push(Buffer.from(m[1], "hex").toString("latin1"));
    for (const m of text.matchAll(/\(([^)]*)\)\s*Tj/g)) out.push(m[1]);
  }
  return out;
}

/** True if the marker text is drawn by ANY stream anywhere in the file, not just
 * on a reachable page: content streams are flate-compressed, so every stream
 * object is decoded. This is what proves a deleted page is not recoverable. */
async function fileContainsMarker(bytes: Uint8Array, marker: string): Promise<boolean> {
  const doc = await PDFDocument.load(bytes);
  const hex = Buffer.from(marker, "latin1").toString("hex").toLowerCase();
  for (const [, obj] of doc.context.enumerateIndirectObjects()) {
    if (!(obj instanceof PDFRawStream)) continue;
    const text = Buffer.from(decodePDFRawStream(obj).decode()).toString("latin1").toLowerCase();
    if (text.includes(`<${hex}>`) || text.includes(`(${marker.toLowerCase()})`)) return true;
  }
  return false;
}

const load = (b: Uint8Array) => PDFDocument.load(b);
const widths = (doc: PDFDocument) => doc.getPages().map((p) => Math.round(p.getWidth()));

test("fixture: pages are identifiable by width and marker", async () => {
  const src = await makeDoc("A", 3);
  const doc = await load(src);
  assert.deepEqual(widths(doc), [300, 310, 320]);
  assert.deepEqual(markersOf(doc, 1), ["A1"]);
  assert.ok(await fileContainsMarker(src, "A1"), "raw-bytes marker probe works on the fixture");
});

test("rotatePage adds the delta to the existing angle, normalised to [0,360)", async () => {
  const src = await makeDoc("A", 2);
  const r90 = await rotatePage(src, 0, 90);
  assert.equal(await getPageRotation(r90, 0), 90);
  assert.equal(await getPageRotation(r90, 1), 0, "other pages untouched");
  assert.equal(await getPageRotation(await rotatePage(r90, 0, 90), 0), 180);
  assert.equal(await getPageRotation(await rotatePage(r90, 0, -90), 0), 0);
  assert.equal(await getPageRotation(await rotatePage(src, 0, -90), 0), 270);
  await assert.rejects(() => rotatePage(src, 5, 90), /no page 5/);
});

test("rotatePage with a non-90 delta: CURRENT behaviour is that pdf-lib rejects it", async () => {
  // Documented, not endorsed: the doc comment says "clamped to 90 degree steps"
  // but nothing clamps; pdf-lib's setRotation asserts a multiple of 90.
  const src = await makeDoc("A", 1);
  await assert.rejects(() => rotatePage(src, 0, 45));
});

test("deletePage removes the page, keeps the others in order, and leaves no recoverable trace", async () => {
  const src = await makeDoc("A", 3);
  assert.ok(await fileContainsMarker(src, "A1"));
  const outBytes = await deletePage(src, 1);
  const out = await load(outBytes);
  assert.equal(out.getPageCount(), 2);
  assert.deepEqual(widths(out), [300, 320]);
  assert.deepEqual(markersOf(out, 1), ["A2"]);
  assert.ok(!(await fileContainsMarker(outBytes, "A1")), "deleted page content is not in the output bytes");
  assert.ok(await fileContainsMarker(outBytes, "A2"));
});

test("deletePage refuses the only page and a bad index", async () => {
  await assert.rejects(async () => deletePage(await makeDoc("A", 1), 0), /only page/);
  await assert.rejects(async () => deletePage(await makeDoc("A", 3), 3), /no page 3/);
});

test("insertBlankPage adds an empty page after the index, matching that page's size and rotation", async () => {
  const rotated = await rotatePage(await makeDoc("A", 2), 0, 90);
  const out = await load(await insertBlankPage(rotated, 0));
  assert.equal(out.getPageCount(), 3);
  assert.deepEqual(widths(out), [300, 300, 310]);
  assert.equal(out.getPages()[1].getRotation().angle, 90);
  assert.deepEqual(markersOf(out, 1), [], "inserted page is blank");
  assert.deepEqual(markersOf(out, 2), ["A1"]);
});

test("reorderPages applies the permutation and rejects non-permutations", async () => {
  const src = await makeDoc("A", 3);
  const out = await load(await reorderPages(src, [2, 0, 1]));
  assert.deepEqual(widths(out), [320, 300, 310]);
  assert.deepEqual([0, 1, 2].map((i) => markersOf(out, i)[0]), ["A2", "A0", "A1"]);
  await assert.rejects(() => reorderPages(src, [0, 0, 1]), /repeats page 0/);
  await assert.rejects(() => reorderPages(src, [0, 1]), /expected 3/);
});

test("appendPdf merges two generated PDFs, page for page", async () => {
  const out = await load(await appendPdf(await makeDoc("A", 2), await makeDoc("B", 3)));
  assert.equal(out.getPageCount(), 5);
  assert.deepEqual(widths(out), [300, 310, 300, 310, 320]);
  assert.deepEqual([0, 1, 2, 3, 4].map((i) => markersOf(out, i)[0]), ["A0", "A1", "B0", "B1", "B2"]);
});

test("extractPages picks pages in the requested order; excluded page content is not carried", async () => {
  const src = await makeDoc("A", 4);
  const outBytes = await extractPages(src, [3, 1]);
  const out = await load(outBytes);
  assert.equal(out.getPageCount(), 2);
  assert.deepEqual(widths(out), [330, 310]);
  assert.deepEqual([0, 1].map((i) => markersOf(out, i)[0]), ["A3", "A1"]);
  assert.ok(!(await fileContainsMarker(outBytes, "A0")) && !(await fileContainsMarker(outBytes, "A2")));
  await assert.rejects(() => extractPages(src, []), /no pages selected/);
  await assert.rejects(() => extractPages(src, [1, 1]), /selected twice/);
});

/** 3 pages with one /Outlines bookmark per page and an /Info Title. */
async function docWithOutline(): Promise<Uint8Array> {
  const doc = await PDFDocument.create({ updateMetadata: false });
  doc.setTitle("Fixture title");
  const pages = [0, 1, 2].map((i) => doc.addPage([300 + 10 * i, 400]));
  const ctx = doc.context;
  const items = pages.map((p, i) =>
    ctx.register(ctx.obj({ Title: PDFString.of(`Chapter ${i}`), Dest: ctx.obj([p.ref, PDFName.of("Fit")]) })),
  );
  const outlines = ctx.register(ctx.obj({ Type: PDFName.of("Outlines"), First: items[0], Last: items[2], Count: 3 }));
  items.forEach((r, i) => {
    const d = ctx.lookup(r) as PDFDict;
    d.set(PDFName.of("Parent"), outlines);
    if (i > 0) d.set(PDFName.of("Prev"), items[i - 1]);
    if (i < 2) d.set(PDFName.of("Next"), items[i + 1]);
  });
  doc.catalog.set(PDFName.of("Outlines"), outlines);
  return doc.save();
}

test("extractPages preserveCatalog keeps outlines and Info; the default drops them", async () => {
  const src = await docWithOutline();
  const kept = await load(await extractPages(src, [0, 2], { preserveCatalog: true }));
  assert.ok(kept.catalog.get(PDFName.of("Outlines")), "outlines preserved");
  assert.equal(kept.getTitle(), "Fixture title");
  const plain = await load(await extractPages(src, [0, 2]));
  assert.equal(plain.catalog.get(PDFName.of("Outlines")), undefined, "default drops outlines");
});

test("deletePage keeps the catalog structures of the surviving pages", async () => {
  const out = await load(await deletePage(await docWithOutline(), 1));
  assert.equal(out.getPageCount(), 2);
  assert.ok(out.catalog.get(PDFName.of("Outlines")), "outlines survive a delete");
  assert.equal(out.getTitle(), "Fixture title");
});
