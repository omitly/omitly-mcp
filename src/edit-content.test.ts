/**
 * omitly#1841 phase B: what the OUTPUT files contain, for all four writers
 * (extract_pages, split_pdf, edit_pages, merge_pdfs), through the real tools.
 *
 * Every marker is shown PRESENT IN THE INPUT first (a positive control, so a probe that
 * cannot see the marker cannot pass the "absent" check), then present when its page is kept,
 * then absent when its page is left out. pdf-lib compresses what it writes, so the probes
 * decode every stream and walk every object (edit-fixtures.test.ts).
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import * as path from "node:path";
import { PDFArray, PDFContentStream, PDFDict, PDFDocument, PDFHexString, PDFName, PDFOperator, PDFRawStream, PDFRef, PDFString, decodePDFRawStream, type PDFObject } from "pdf-lib";
import {
  CERT_MARKER,
  addCatalogExtras,
  fileContainsMarker,
  makeDoc,
  makeSharedParentForm,
  makeSigned,
  put,
  signatureTraces,
  tempRoot,
  textOf,
  withEditClient,
  type ToolResult,
} from "./edit-fixtures.test.js";
import { LAYERS_WARNING, SIGNATURE_WARNING, emptySignatureDictionaries } from "./pdf-edit/docFacts.js";
import { extractPages } from "./pdf-edit/pageOps.js";

type Call = (name: string, args: Record<string, unknown>) => Promise<ToolResult>;
type Writer = "extract_pages" | "split_pdf" | "edit_pages";
const WRITERS: Writer[] = ["extract_pages", "split_pdf", "edit_pages"];

/** Run one of the three single-input writers keeping `keep` (1-based, in this order);
 *  returns every output file's bytes. */
async function runWriter(call: Call, root: string, writer: Writer, file: string, keep: number[], tag: string): Promise<{ files: Uint8Array[]; result: ToolResult }> {
  let result: ToolResult;
  if (writer === "extract_pages") result = await call("extract_pages", { pdfPath: file, pages: keep, outputPath: `${tag}-out.pdf` });
  else if (writer === "edit_pages") result = await call("edit_pages", { pdfPath: file, pages: keep.map((source) => ({ source })), outputPath: `${tag}-out.pdf` });
  else result = await call("split_pdf", { pdfPath: file, ranges: keep.map((k) => [k]), outputDir: ".", prefix: tag });
  assert.ok(!result.isError, `${writer}: ${textOf(result)}`);
  const paths: string[] = writer === "split_pdf" ? result.structuredContent.files.map((f: any) => f.outputPath) : [result.structuredContent.outputPath];
  return { files: paths.map((p) => readFileSync(p)), result };
}

const anyContains = async (files: Uint8Array[], marker: string) => {
  for (const f of files) if (await fileContainsMarker(f, marker)) return true;
  return false;
};

function withOrphan(doc: PDFDocument, marker: string): void {
  doc.context.register(doc.context.obj({ OmitlyMarker: PDFString.of(marker) }));
}

test("content: a left-out page's markers (content stream AND page dictionary) and an orphaned object are absent; kept ones travel; all writers", async () => {
  const root = tempRoot();
  const input = await makeDoc("C", 3, (doc) => withOrphan(doc, "C-orphan"));
  put(root, "c.pdf", input);
  // Positive controls: the probes see every marker in the INPUT.
  for (const m of ["C-1", "C-2", "C-3", "C-orphan"]) assert.ok(await fileContainsMarker(input, m), `input holds ${m}`);
  await withEditClient(root, {}, async (call) => {
    for (const w of WRITERS) {
      const { files } = await runWriter(call, root, w, "c.pdf", [1, 3], `c-${w}`);
      assert.ok(await anyContains(files, "C-1"), `${w}: kept page 1 travels`);
      assert.ok(await anyContains(files, "C-3"), `${w}: kept page 3 travels`);
      assert.ok(!(await anyContains(files, "C-2")), `${w}: left-out page 2 is absent`);
      assert.ok(!(await anyContains(files, "C-orphan")), `${w}: the orphaned object is absent`);
    }
  });
});

test("content: merge keeps every page of its inputs, and nothing from an input or object that is not in the call", async () => {
  const root = tempRoot();
  const x = await makeDoc("X", 3, (doc) => withOrphan(doc, "X-orphan"));
  const y = await makeDoc("Y", 2);
  const z = await makeDoc("Z", 2);
  put(root, "x.pdf", x);
  put(root, "y.pdf", y);
  put(root, "z.pdf", z);
  for (const m of ["X-1", "X-3", "X-orphan", "Y-2", "Z-1"]) assert.ok(await fileContainsMarker(m === "Z-1" ? z : m.startsWith("Y") ? y : x, m), `input holds ${m}`);
  await withEditClient(root, {}, async (call) => {
    const r = await call("merge_pdfs", { inputs: ["x.pdf", "y.pdf"], outputPath: "m.pdf" });
    assert.ok(!r.isError, textOf(r));
    const out = readFileSync(r.structuredContent.outputPath);
    for (const m of ["X-1", "X-2", "X-3", "Y-1", "Y-2"]) assert.ok(await fileContainsMarker(out, m), `merged output holds ${m}`);
    assert.ok(!(await fileContainsMarker(out, "Z-1")), "an input left out of the call is absent");
    assert.ok(!(await fileContainsMarker(out, "X-orphan")), "an orphaned object in an input is not copied");
  });
});

test("content: the #1004 variant: a form widget whose sibling sits on a left-out page does not drag that page in", async () => {
  const root = tempRoot();
  const input = await makeDoc("W", 3, (doc) => {
    const [p1, p2] = doc.getPages();
    const field = doc.getForm().createTextField("shared");
    field.addToPage(p1, { x: 20, y: 300, width: 100, height: 20 });
    field.addToPage(p2, { x: 20, y: 300, width: 100, height: 20 }); // the sibling, on the page we leave out
  });
  put(root, "w.pdf", input);
  assert.ok(await fileContainsMarker(input, "W-2"), "input holds W-2");
  // Positive control for the VECTOR: a naive copy of pages 1 and 3 into a fresh document pulls page 2 back in.
  const src = await PDFDocument.load(input);
  const naive = await PDFDocument.create();
  for (const p of await naive.copyPages(src, [0, 2])) naive.addPage(p);
  const naiveBytes = await naive.save();
  assert.ok(await fileContainsMarker(naiveBytes, "W-2"), "CONTROL: copyPages leaks the left-out page through the widget's /P (the #1004 path)");
  await withEditClient(root, {}, async (call) => {
    for (const w of WRITERS) {
      const { files } = await runWriter(call, root, w, "w.pdf", [1, 3], `w-${w}`);
      assert.ok(await anyContains(files, "W-1"), `${w}: kept page 1 travels`);
      assert.ok(await anyContains(files, "W-3"), `${w}: kept page 3 travels`);
      assert.ok(!(await anyContains(files, "W-2")), `${w}: the sibling's page does NOT travel`);
    }
  });
});

test("content: a resource shared with a left-out page DOES travel (stated limit; resource pruning is a separate issue)", async () => {
  const root = tempRoot();
  const input = await makeDoc("S", 2, (doc) => {
    const ctx = doc.context;
    const xo = ctx.register(ctx.flateStream("BT (S-shared-resource) Tj ET", { Type: "XObject", Subtype: "Form", BBox: [0, 0, 10, 10] }));
    const res = ctx.register(ctx.obj({ XObject: { Fx: xo } }));
    for (const p of doc.getPages()) p.node.set(PDFName.of("Resources"), res);
  });
  put(root, "s.pdf", input);
  assert.ok(await fileContainsMarker(input, "S-shared-resource"));
  await withEditClient(root, {}, async (call) => {
    for (const w of WRITERS) {
      const { files } = await runWriter(call, root, w, "s.pdf", [1], `s-${w}`);
      assert.ok(await anyContains(files, "S-shared-resource"), `${w}: the shared resource travels with the kept page`);
      assert.ok(!(await anyContains(files, "S-2")), `${w}: the left-out page's own markers still do not`);
    }
  });
});

// ---------------------------------------------------------------------------
// Signatures
// ---------------------------------------------------------------------------

test("signatures: removed in the SOURCE before copying: no signature value, appearance or certificate bytes survive, SigFlags cleared, all writers", async () => {
  const root = tempRoot();
  for (const variant of ["merged", "kid"] as const) {
    const signed = await makeSigned(variant, 2);
    const name = `signed-${variant}.pdf`;
    put(root, name, signed);
    const control = (await signatureTraces(signed)).join(" | ");
    for (const t of ["/ByteRange", "/Type /Sig", "certificate bytes", "signature appearance stream", "SigFlags"]) {
      assert.ok(control.includes(t), `CONTROL (${variant}): the input shows ${t}`);
    }
    await withEditClient(root, {}, async (call) => {
      for (const w of WRITERS) {
        // Keep page 1 (where the widget sits) and, separately, only page 2 (the widget's page is left out).
        for (const keep of [[1, 2], [1], [2]]) {
          const { files, result } = await runWriter(call, root, w, name, keep, `sg-${variant}-${w}-${keep.join("")}`);
          for (const f of files) assert.deepEqual(await signatureTraces(f), [], `${variant} ${w} keep ${keep}`);
          assert.ok(await anyContains(files, `SIGNED-${keep[0]}`), "the pages themselves still travel");
          const warnings: string[] = result.structuredContent.warnings;
          assert.ok(warnings.includes(SIGNATURE_WARNING), `${variant} ${w} keep ${keep}: warns`);
        }
      }
      const m = await call("merge_pdfs", { inputs: [name, name], outputPath: `sg-merge-${variant}.pdf` });
      assert.ok(!m.isError, textOf(m));
      assert.deepEqual(await signatureTraces(readFileSync(m.structuredContent.outputPath)), [], `${variant} merge`);
      assert.ok(m.structuredContent.warnings.includes(SIGNATURE_WARNING));
    });
  }
});

test("signatures: an unsigned document produces no signature warning (negative control)", async () => {
  const root = tempRoot();
  put(root, "a.pdf", await makeDoc("A", 2));
  await withEditClient(root, {}, async (call) => {
    const { result } = await runWriter(call, root, "extract_pages", "a.pdf", [1], "plain");
    assert.deepEqual(result.structuredContent.warnings, []);
    const m = await call("merge_pdfs", { inputs: ["a.pdf", "a.pdf"], outputPath: "plain-m.pdf" });
    assert.ok(!m.structuredContent.warnings.includes(SIGNATURE_WARNING));
  });
});

// ---------------------------------------------------------------------------
// lost / warnings
// ---------------------------------------------------------------------------

test("lost: layers and page labels (and the rest) are reported, only when the input had them", async () => {
  const root = tempRoot();
  const rich = await makeDoc("R", 3, (doc) => addCatalogExtras(doc, { layers: true, labels: true, outlines: true, xfa: "static" }));
  put(root, "rich.pdf", rich);
  put(root, "plain.pdf", await makeDoc("P", 3, (doc) => {
    doc.context.trailerInfo.Info = undefined; // pdf-lib adds an Info dictionary; take it away for the negative control
  }));
  const catalogHas = async (bytes: Uint8Array, key: string) => (await PDFDocument.load(bytes)).catalog.get(PDFName.of(key)) !== undefined;
  const sorted = (x: string[]) => [...x].sort();
  await withEditClient(root, {}, async (call) => {
    // extract ascending: labels kept; layers and static XFA dropped
    let r = await call("extract_pages", { pdfPath: "rich.pdf", pages: [1, 2], outputPath: "e-asc.pdf" });
    assert.deepEqual(sorted(r.structuredContent.lost), ["layers", "xfa"]);
    assert.ok(r.structuredContent.warnings.includes(LAYERS_WARNING));
    assert.ok(await catalogHas(readFileSync(r.structuredContent.outputPath), "PageLabels"), "labels kept on an ascending extract");
    assert.ok(!(await catalogHas(readFileSync(r.structuredContent.outputPath), "OCProperties")), "layers dropped");
    // extract out of order: labels removed
    r = await call("extract_pages", { pdfPath: "rich.pdf", pages: [2, 1], outputPath: "e-desc.pdf" });
    assert.deepEqual(sorted(r.structuredContent.lost), ["layers", "page_labels", "xfa"]);
    assert.ok(!(await catalogHas(readFileSync(r.structuredContent.outputPath), "PageLabels")), "labels removed when pages are out of order");
    // split ranges are ascending: labels kept
    r = await call("split_pdf", { pdfPath: "rich.pdf", ranges: [["1-2"], [3]], outputDir: ".", prefix: "sp" });
    assert.deepEqual(sorted(r.structuredContent.lost), ["layers", "xfa"]);
    // edit_pages: reorder / blank remove labels; plain deletion keeps them
    r = await call("edit_pages", { pdfPath: "rich.pdf", pages: [{ source: 2 }, { source: 1 }], outputPath: "ed-reorder.pdf" });
    assert.ok(r.structuredContent.lost.includes("page_labels"));
    assert.ok(!(await catalogHas(readFileSync(r.structuredContent.outputPath), "PageLabels")));
    r = await call("edit_pages", { pdfPath: "rich.pdf", pages: [{ source: 1 }, { blank: true }, { source: 2 }], outputPath: "ed-blank.pdf" });
    assert.ok(r.structuredContent.lost.includes("page_labels"));
    r = await call("edit_pages", { pdfPath: "rich.pdf", pages: [{ source: 1 }, { source: 3, rotate: 90 }], outputPath: "ed-keep.pdf" });
    assert.ok(!r.structuredContent.lost.includes("page_labels"), "deleting a page keeps labels");
    assert.ok(r.structuredContent.lost.includes("layers"));
    // merge starts from an empty catalog: all five
    r = await call("merge_pdfs", { inputs: ["rich.pdf", "plain.pdf"], outputPath: "m-rich.pdf" });
    assert.deepEqual(sorted(r.structuredContent.lost), ["info", "layers", "outlines", "page_labels", "xfa"]);
    // negative control: nothing to lose, nothing reported
    r = await call("extract_pages", { pdfPath: "plain.pdf", pages: [3, 1], outputPath: "p-e.pdf" });
    assert.deepEqual(r.structuredContent.lost, []);
    assert.deepEqual(r.structuredContent.warnings, []);
    r = await call("edit_pages", { pdfPath: "plain.pdf", pages: [{ source: 2 }, { blank: true }], outputPath: "p-ed.pdf" });
    assert.deepEqual(r.structuredContent.lost, []);
    r = await call("merge_pdfs", { inputs: ["plain.pdf", "plain.pdf"], outputPath: "p-m.pdf" });
    assert.deepEqual(r.structuredContent.lost, []);
  });
});

// ---------------------------------------------------------------------------
// Signature dictionaries reached by routes other than the field's /V
// ---------------------------------------------------------------------------

type SigRoute = "outline" | "page-key" | "text-annotation" | "doc-timestamp" | "direct-nested" | "deep-nested" | "trailer-info";

/** A signed 3-page document where the signature dictionary (or a /DocTimeStamp) is ALSO
 *  referenced from something that gets copied: an outline item, a page-dictionary key, or a
 *  non-widget annotation on page 2. */
async function makeSignedWithRoute(route: SigRoute): Promise<Uint8Array> {
  const doc = await PDFDocument.load(await makeSigned("merged", 3), { updateMetadata: false });
  const ctx = doc.context;
  const acro = doc.catalog.lookup(PDFName.of("AcroForm"), PDFDict);
  const field = ctx.lookup(acro.lookup(PDFName.of("Fields"), PDFArray).get(0), PDFDict);
  const sigRef = field.get(PDFName.of("V"))!;
  let target = sigRef;
  if (route === "doc-timestamp") {
    // An ORPHANED timestamp dictionary: reachable from nothing but the outline item below.
    target = ctx.register(
      ctx.obj({
        Type: "DocTimeStamp",
        Filter: "Adobe.PPKLite",
        SubFilter: "ETSI.RFC3161",
        ByteRange: [0, 10, 20, 10],
        Contents: PDFHexString.fromText(`${CERT_MARKER}-timestamp-${"0".repeat(20)}`),
      }),
    );
  }
  const page2 = doc.getPage(1);
  const directSig = () =>
    ctx.obj({
      Type: "Sig",
      Filter: "Adobe.PPKLite",
      SubFilter: "adbe.pkcs7.detached",
      ByteRange: [0, 1, 2, 3],
      Contents: PDFHexString.fromText(`${CERT_MARKER}-direct-${"0".repeat(10)}`),
    });
  if (route === "direct-nested") target = ctx.obj({ Holder: directSig() });
  if (route === "deep-nested") {
    // ~20 levels of alternating arrays and dictionaries around a DIRECT signature dictionary.
    let v: any = directSig();
    for (let i = 0; i < 20; i++) v = i % 2 === 0 ? ctx.obj([v]) : ctx.obj({ Level: v });
    target = v;
  }
  if (route === "trailer-info") {
    doc.context.trailerInfo.Info = ctx.obj({ Title: PDFString.of("direct info"), Holder: directSig() });
  } else if (route === "outline" || route === "doc-timestamp" || route === "direct-nested" || route === "deep-nested") {
    const item = ctx.register(ctx.obj({ Title: PDFString.of("Sig ref outline"), Dest: [page2.ref, PDFName.of("Fit")], Extra: target }));
    const outlines = ctx.register(ctx.obj({ Type: "Outlines", First: item, Last: item, Count: 1 }));
    ctx.lookup(item, PDFDict).set(PDFName.of("Parent"), outlines);
    doc.catalog.set(PDFName.of("Outlines"), outlines);
  } else if (route === "page-key") {
    page2.node.set(PDFName.of("OmitlyPieceInfo"), ctx.obj({ Data: target }));
  } else {
    const annot = ctx.register(ctx.obj({ Type: "Annot", Subtype: "Text", Rect: [10, 10, 30, 30], Contents: PDFString.of("note"), OmitlyExtra: target }));
    page2.node.set(PDFName.of("Annots"), ctx.obj([annot]));
  }
  return doc.save();
}

for (const route of ["outline", "page-key", "text-annotation", "doc-timestamp", "direct-nested", "deep-nested", "trailer-info"] as const) {
  test(`signatures: a dictionary also reached through ${route} is emptied in the source; all four writers`, async () => {
    const root = tempRoot();
    const input = await makeSignedWithRoute(route);
    put(root, "s.pdf", input);
    const control = (await signatureTraces(input)).join(" | ");
    assert.ok(control.includes("certificate bytes"), `CONTROL (${route}): the input holds certificate bytes: ${control}`);
    await withEditClient(root, {}, async (call) => {
      for (const keep of [[1, 2], [3, 2]]) {
        for (const w of WRITERS) {
          const { files, result } = await runWriter(call, root, w, "s.pdf", keep, `r-${route}-${w}-${keep.join("")}`);
          for (const f of files) assert.deepEqual(await signatureTraces(f), [], `${route} ${w} keep ${keep}`);
          assert.ok(await anyContains(files, `SIGNED-${keep[0]}`) && (await anyContains(files, "SIGNED-2")), `${route} ${w}: the pages still travel`);
          assert.ok(result.structuredContent.warnings.includes(SIGNATURE_WARNING), `${route} ${w}: warns`);
        }
      }
      const m = await call("merge_pdfs", { inputs: ["s.pdf", "s.pdf"], outputPath: `r-${route}-merge.pdf` });
      assert.ok(!m.isError, textOf(m));
      const out = readFileSync(m.structuredContent.outputPath);
      assert.deepEqual(await signatureTraces(out), [], `${route} merge`);
      assert.ok((await anyContains([out], "SIGNED-3")), "merge: the pages still travel");
      assert.ok(m.structuredContent.warnings.includes(SIGNATURE_WARNING));
    });
  });
}

test("default-deny beyond #1004: a left-out page reachable from a kept page by a /Link annotation does not bring its content", async () => {
  const root = tempRoot();
  const input = await makeDoc("L", 3, (doc) => {
    const ctx = doc.context;
    const [p1, p2] = doc.getPages();
    const link = ctx.register(ctx.obj({ Type: "Annot", Subtype: "Link", Rect: [10, 10, 60, 30], Dest: [p2.ref, PDFName.of("Fit")] }));
    p1.node.set(PDFName.of("Annots"), ctx.obj([link]));
  });
  put(root, "l.pdf", input);
  assert.ok(await fileContainsMarker(input, "L-2"), "CONTROL: the input holds the left-out page's marker");
  await withEditClient(root, {}, async (call) => {
    for (const w of WRITERS) {
      const { files } = await runWriter(call, root, w, "l.pdf", [1, 3], `link-${w}`);
      assert.ok(await anyContains(files, "L-1") || (await anyContains(files, "L-3")), `${w}: kept pages travel`);
      assert.ok(!(await anyContains(files, "L-2")), `${w}: the linked, left-out page's content (stream and page dictionary) is absent`);
    }
  });
});

test("signatures: a structure nested deeper than the scan depth (64) is REFUSED as `failed`, never passed through unscanned", async () => {
  const root = tempRoot();
  const input = await makeDoc("D", 2, (doc) => {
    let v: any = doc.context.obj({ Type: "Sig", ByteRange: [0, 1, 2, 3], Contents: PDFHexString.fromText(`${CERT_MARKER}-too-deep`) });
    for (let i = 0; i < 100; i++) v = doc.context.obj([v]);
    doc.getPages()[0].node.set(PDFName.of("OmitlyDeep"), v);
  });
  put(root, "deep.pdf", input);
  assert.ok(await fileContainsMarker(input, `${CERT_MARKER}-too-deep`), "CONTROL: the input holds the certificate bytes 100 levels down");
  await withEditClient(root, {}, async (call) => {
    for (const w of WRITERS) {
      const r = await call(w === "extract_pages" ? "extract_pages" : w, w === "extract_pages" ? { pdfPath: "deep.pdf", pages: [1], outputPath: "x1.pdf" } : w === "edit_pages" ? { pdfPath: "deep.pdf", pages: [{ source: 1 }], outputPath: "x2.pdf" } : { pdfPath: "deep.pdf", ranges: [[1]], outputDir: ".", prefix: "dd" });
      assert.equal(r.isError, true, w);
      assert.equal(textOf(r), "This PDF could not be processed.", w);
    }
    const m = await call("merge_pdfs", { inputs: ["deep.pdf", "deep.pdf"], outputPath: "x3.pdf" });
    assert.equal(textOf(m), "Input 1: This PDF could not be processed.");
  });
});

// ---------------------------------------------------------------------------
// Codex 1: fields that share a /Parent with a kept field
// ---------------------------------------------------------------------------

test("fields: an excluded sibling field sharing a /Parent does not travel (/V, /DV); a valid filled form does not fail; all writers", async () => {
  const root = tempRoot();
  const input = await makeSharedParentForm();
  put(root, "g.pdf", input);
  for (const m of ["KEPT-VALUE", "SECRET-V-DROP", "SECRET-DV-DROP", "G-1", "G-2"]) assert.ok(await fileContainsMarker(input, m), `CONTROL: input holds ${m}`);
  await withEditClient(root, {}, async (call) => {
    for (const w of WRITERS) {
      const one = await runWriter(call, root, w, "g.pdf", [1], `g1-${w}`);
      assert.ok(await anyContains(one.files, "KEPT-VALUE"), `${w} keep 1: the kept field and its value travel`);
      for (const secret of ["SECRET-V-DROP", "SECRET-DV-DROP", "G-2"]) assert.ok(!(await anyContains(one.files, secret)), `${w} keep 1: ${secret} absent`);
      const two = await runWriter(call, root, w, "g.pdf", [2], `g2-${w}`);
      assert.ok(await anyContains(two.files, "SECRET-V-DROP"), `${w} keep 2: the other field travels with ITS page`);
      assert.ok(!(await anyContains(two.files, "KEPT-VALUE")), `${w} keep 2: KEPT-VALUE (now excluded) absent`);
      const both = await runWriter(call, root, w, "g.pdf", [1, 2], `gb-${w}`);
      for (const m of ["KEPT-VALUE", "SECRET-V-DROP", "SECRET-DV-DROP"]) assert.ok(await anyContains(both.files, m), `${w} keep both: ${m} travels`);
    }
    const m = await call("merge_pdfs", { inputs: ["g.pdf", "g.pdf"], outputPath: "g-merge.pdf" });
    assert.ok(!m.isError, textOf(m));
    const out = readFileSync(m.structuredContent.outputPath);
    for (const marker of ["KEPT-VALUE", "SECRET-V-DROP", "SECRET-DV-DROP"]) assert.ok(await fileContainsMarker(out, marker), `merge keeps everything: ${marker}`);
    const info = (await call("pdf_info", { pdfPath: "g-merge.pdf" })).structuredContent;
    assert.equal(info.formFieldCount, 4, "both fields of both copies");
  });
});

test("fields: the desktop's extractPages (same code) also drops the excluded sibling", async () => {
  const { extractPages } = await import("./pdf-edit/pageOps.js");
  const out = await extractPages(await makeSharedParentForm(), [0], { preserveCatalog: true });
  assert.ok(await fileContainsMarker(out, "KEPT-VALUE"));
  for (const m of ["SECRET-V-DROP", "SECRET-DV-DROP"]) assert.ok(!(await fileContainsMarker(out, m)), m);
});

// ---------------------------------------------------------------------------
// Codex 2: /SV (seed value) and /Lock on signature fields
// ---------------------------------------------------------------------------

test("signatures: a /SV seed value (certificate bytes) and /Lock are removed, signed or not, even under a non-signature field; all writers", async () => {
  const root = tempRoot();
  const seed = (ctx: any) => ctx.obj({ Type: "SV", Ff: 1, Cert: { Subject: [PDFHexString.fromText(CERT_MARKER + "-seed")] }, SubFilter: ["adbe.pkcs7.detached"] });
  const variants: Record<string, (doc: PDFDocument, field: PDFDict) => void> = {
    "signed field": (_doc, field) => field.set(PDFName.of("SV"), seed(field.context)),
    "unsigned field": (_doc, field) => {
      field.delete(PDFName.of("V"));
      field.set(PDFName.of("SV"), seed(field.context));
      field.set(PDFName.of("Lock"), field.context.obj({ Type: "SigFieldLock", Action: "All" }));
    },
    "text field": (doc, field) => {
      field.set(PDFName.of("FT"), PDFName.of("Tx"));
      field.delete(PDFName.of("V"));
      field.delete(PDFName.of("AP")); // an ordinary text field's appearance is not a signature trace
      field.set(PDFName.of("SV"), seed(doc.context));
    },
  };
  for (const [label, edit] of Object.entries(variants)) {
    const doc = await PDFDocument.load(await makeSigned("merged", 2), { updateMetadata: false });
    const acro = doc.catalog.lookup(PDFName.of("AcroForm"), PDFDict);
    const field = doc.context.lookup(acro.lookup(PDFName.of("Fields"), PDFArray).get(0), PDFDict);
    edit(doc, field);
    const input = await doc.save();
    const name = `sv-${label.replace(" ", "-")}.pdf`;
    put(root, name, input);
    assert.ok(await fileContainsMarker(input, CERT_MARKER + "-seed"), `CONTROL (${label}): the input holds the seed certificate`);
    await withEditClient(root, {}, async (call) => {
      for (const w of WRITERS) {
        const { files } = await runWriter(call, root, w, name, [1, 2], `sv-${label.replace(" ", "")}-${w}`);
        for (const f of files) {
          assert.ok(!(await fileContainsMarker(f, CERT_MARKER + "-seed")), `${label} ${w}: seed certificate absent`);
          assert.deepEqual(await signatureTraces(f), [], `${label} ${w}`);
        }
        assert.ok(await anyContains(files, "SIGNED-1"), `${label} ${w}: pages travel`);
      }
      const m = await call("merge_pdfs", { inputs: [name, name], outputPath: `sv-${label.replace(" ", "")}-m.pdf` });
      assert.ok(!m.isError, textOf(m));
      assert.ok(!(await fileContainsMarker(readFileSync(m.structuredContent.outputPath), CERT_MARKER + "-seed")), `${label} merge`);
    });
  }
});

// ---------------------------------------------------------------------------
// Indirect /Type and /FT values
// ---------------------------------------------------------------------------

test("signatures: an INDIRECT /Type (and /FT) value is resolved, so the dictionary is still recognised; all writers", async () => {
  const root = tempRoot();
  for (const variant of ["field", "outline-only"] as const) {
    const doc = await PDFDocument.load(await makeSigned("merged", 2), { updateMetadata: false });
    const ctx = doc.context;
    const acro = doc.catalog.lookup(PDFName.of("AcroForm"), PDFDict);
    const field = ctx.lookup(acro.lookup(PDFName.of("Fields"), PDFArray).get(0), PDFDict);
    const sig = ctx.lookup(field.get(PDFName.of("V"))!, PDFDict);
    // Only /Type identifies it: no ByteRange, Filter or SubFilter, and the name is an indirect object.
    for (const k of ["ByteRange", "Filter", "SubFilter"]) sig.delete(PDFName.of(k));
    sig.set(PDFName.of("Type"), ctx.register(PDFName.of("Sig")));
    field.set(PDFName.of("FT"), ctx.register(PDFName.of("Sig")));
    if (variant === "outline-only") {
      // Cut the field's own route; the only way to the dictionary is an outline item.
      const sigRef = field.get(PDFName.of("V"))!;
      field.delete(PDFName.of("V"));
      const item = ctx.register(ctx.obj({ Title: PDFString.of("o"), Dest: [doc.getPage(1).ref, PDFName.of("Fit")], Extra: sigRef }));
      const outlines = ctx.register(ctx.obj({ Type: "Outlines", First: item, Last: item, Count: 1 }));
      ctx.lookup(item, PDFDict).set(PDFName.of("Parent"), outlines);
      doc.catalog.set(PDFName.of("Outlines"), outlines);
    }
    const input = await doc.save();
    const name = `ind-${variant}.pdf`;
    put(root, name, input);
    assert.ok(await fileContainsMarker(input, CERT_MARKER + "-" + "0".repeat(40)), `CONTROL (${variant}): the input holds the certificate`);
    await withEditClient(root, {}, async (call) => {
      for (const w of WRITERS) {
        const { files } = await runWriter(call, root, w, name, [1, 2], `ind-${variant}-${w}`);
        for (const f of files) {
          assert.ok(!(await fileContainsMarker(f, CERT_MARKER + "-" + "0".repeat(40))), `${variant} ${w}: certificate absent`);
          assert.deepEqual(await signatureTraces(f), [], `${variant} ${w}`);
        }
        assert.ok(await anyContains(files, "SIGNED-1"));
      }
      const m = await call("merge_pdfs", { inputs: [name, name], outputPath: `ind-${variant}-m.pdf` });
      assert.ok(!m.isError, textOf(m));
      assert.ok(!(await fileContainsMarker(readFileSync(m.structuredContent.outputPath), CERT_MARKER + "-" + "0".repeat(40))));
    });
  }
});

test("signatures: /Contents with /Filter, /SubFilter or /Cert (and no ByteRange or Type) is signature material", async () => {
  const root = tempRoot();
  for (const k of ["Filter", "SubFilter", "Cert"]) {
    const input = await makeDoc("K", 2, (doc) => {
      doc.getPages()[0].node.set(PDFName.of("OmitlyBlob"), doc.context.obj({ Contents: PDFHexString.fromText(`${CERT_MARKER}-blob-${k}`), [k]: k === "Cert" ? { Subject: [] } : "X" }));
    });
    put(root, `k-${k}.pdf`, input);
    assert.ok(await fileContainsMarker(input, `${CERT_MARKER}-blob-${k}`), `CONTROL ${k}`);
    await withEditClient(root, {}, async (call) => {
      for (const w of WRITERS) {
        const { files } = await runWriter(call, root, w, `k-${k}.pdf`, [1, 2], `k-${k}-${w}`);
        assert.ok(!(await anyContains(files, `${CERT_MARKER}-blob-${k}`)), `${k} ${w}`);
      }
    });
  }
});

// ---------------------------------------------------------------------------
// split_pdf parses once: every range must equal a fresh, one-shot extraction
// ---------------------------------------------------------------------------

test("split session: ranges from ONE parse are byte-identical to fresh one-shot extractions, in any order, repeated and overlapping", async () => {
  const { extractPagesTo, openRangeExtractor } = await import("./pdf-edit/compose.js");
  const widgetDoc = await makeDoc("W", 4, (doc) => {
    const [p1, p2] = doc.getPages();
    const field = doc.getForm().createTextField("shared");
    field.addToPage(p1, { x: 20, y: 300, width: 100, height: 20 });
    field.addToPage(p2, { x: 20, y: 300, width: 100, height: 20 });
  });
  const linkDoc = await makeDoc("L", 4, (doc) => {
    const ctx = doc.context;
    const [p1, p2] = doc.getPages();
    p1.node.set(PDFName.of("Annots"), ctx.obj([ctx.register(ctx.obj({ Type: "Annot", Subtype: "Link", Rect: [1, 1, 5, 5], Dest: [p2.ref, PDFName.of("Fit")] }))]));
  });
  const fixtures: [string, Uint8Array][] = [
    ["plain", await makeDoc("P", 4, (d) => withOrphan(d, "P-orphan"))],
    ["widget sibling (#1004)", widgetDoc],
    ["link to a left-out page", linkDoc],
    ["shared /Parent form", await makeSharedParentForm()],
    ["merged field via ResetForm", await makeFieldRoute("reset-form")],
    ["orphan field via outline", await makeFieldRoute("outline-only")],
    ["kept actions", await makeActionsDoc()],
    ["attachment and beads", await makeAttachmentAndBeads()],
    ["untitled field", await makeFieldShape("untitled")],
    ["direct field in ResetForm", await makeFieldShape("direct")],
    ["untitled two-level", await makeFieldShape("untitled-two-level")],
    ["direct field nested in outline", await makeFieldShape("outline-nested-direct")],
    ["signed", await makeSigned("kid", 4)],
    ["signature via outline", await makeSignedWithRoute("outline")],
    ["rich catalog", await makeDoc("R", 4, (doc) => addCatalogExtras(doc, { layers: true, labels: true, outlines: true, xfa: "static" }))],
  ];
  const sequences = [[[0], [1], [0, 1], [1, 0], [0], [1]], [[1], [0], [1], [0, 1]]];
  for (const [label, bytes] of fixtures) {
    const count = (await PDFDocument.load(bytes)).getPageCount();
    for (const seq of sequences) {
      const extractor = await openRangeExtractor(bytes);
      for (const range of seq.map((r) => r.filter((p) => p < count))) {
        if (range.length === 0) continue;
        const viaSession = await extractor.extract(range);
        const fresh = await extractPagesTo(bytes, range);
        assert.deepEqual(Buffer.from(viaSession.bytes), Buffer.from(fresh.bytes), `${label}: range ${JSON.stringify(range)} after ${JSON.stringify(seq)}`);
        assert.deepEqual(viaSession.lost, fresh.lost, label);
        assert.deepEqual(viaSession.warnings, fresh.warnings, label);
      }
    }
  }
});

// ---------------------------------------------------------------------------
// Codex final: a field reached by a route other than /Kids (found by enumeration, not by route)
// ---------------------------------------------------------------------------

type FieldRoute = "reset-form" | "submit-form" | "aa-reference" | "outline-only";

/** Merged field/widgets `keep` (page 1) and `drop` (page 2, /V SECRET-MV, /DV SECRET-MDV) under parent `g`, plus
 *  something that REFERENCES `drop` by a route that is not /Kids. Page 1 also carries a Text annotation with a /T
 *  (the author) that must survive, since it is not a field. */
async function makeFieldRoute(route: FieldRoute): Promise<Uint8Array> {
  return makeDoc("M", 2, (doc) => {
    const c = doc.context;
    const [p1, p2] = doc.getPages();
    const g = c.register(c.obj({ T: PDFString.of("g"), FT: "Tx" }));
    const mk = (name: string, page: typeof p1, extra: Record<string, unknown>) =>
      c.register(c.obj({ Type: "Annot", Subtype: "Widget", Rect: [10, 10, 100, 30], T: PDFString.of(name), Parent: g, P: page.ref, ...extra }));
    const keep = mk("keep", p1, { V: PDFString.of("KEPT-MV") });
    const drop = mk("drop", p2, { V: PDFString.of("SECRET-MV"), DV: PDFString.of("SECRET-MDV") });
    c.lookup(g, PDFDict).set(PDFName.of("Kids"), c.obj([keep, drop]));
    const note = c.register(c.obj({ Type: "Annot", Subtype: "Text", Rect: [0, 0, 5, 5], T: PDFString.of("AUTHOR-NAME"), Contents: PDFString.of("NOTE-BODY") }));
    const annots = [keep, note];
    if (route === "reset-form") annots.push(c.register(c.obj({ Type: "Annot", Subtype: "Link", Rect: [0, 0, 10, 10], A: { S: "ResetForm", Fields: [drop] } })));
    if (route === "submit-form") annots.push(c.register(c.obj({ Type: "Annot", Subtype: "Link", Rect: [0, 0, 10, 10], A: { S: "SubmitForm", F: { FS: "URL", F: PDFString.of("x") }, Fields: [drop] } })));
    if (route === "aa-reference") c.lookup(keep, PDFDict).set(PDFName.of("AA"), c.obj({ Fo: { S: "ResetForm", Fields: [drop] } }));
    if (route === "outline-only") {
      // A field-like dictionary nobody lists anywhere: only an outline item points at it.
      const orphan = c.register(c.obj({ T: PDFString.of("orphan"), FT: "Tx", V: PDFString.of("SECRET-MV"), DV: PDFString.of("SECRET-MDV") }));
      const item = c.register(c.obj({ Title: PDFString.of("o"), Dest: [p1.ref, PDFName.of("Fit")], Extra: orphan }));
      const ol = c.register(c.obj({ Type: "Outlines", First: item, Last: item, Count: 1 }));
      c.lookup(item, PDFDict).set(PDFName.of("Parent"), ol);
      doc.catalog.set(PDFName.of("Outlines"), ol);
    }
    p1.node.set(PDFName.of("Annots"), c.obj(annots));
    p2.node.set(PDFName.of("Annots"), c.obj([drop]));
    doc.catalog.set(PDFName.of("AcroForm"), c.obj({ Fields: [g] }));
  });
}

for (const route of ["reset-form", "submit-form", "aa-reference", "outline-only"] as const) {
  test(`fields: an excluded field reached through ${route} (not /Kids) is emptied; kept fields and a kept comment survive; all writers`, async () => {
    const root = tempRoot();
    const input = await makeFieldRoute(route);
    put(root, "m.pdf", input);
    for (const m of ["SECRET-MV", "SECRET-MDV", "KEPT-MV", "AUTHOR-NAME"]) assert.ok(await fileContainsMarker(input, m), `CONTROL (${route}): input holds ${m}`);
    await withEditClient(root, {}, async (call) => {
      for (const w of WRITERS) {
        const { files } = await runWriter(call, root, w, "m.pdf", [1], `fr-${route}-${w}`);
        for (const secret of ["SECRET-MV", "SECRET-MDV", "M-2"]) assert.ok(!(await anyContains(files, secret)), `${route} ${w}: ${secret} absent`);
        if (route !== "outline-only") assert.ok(await anyContains(files, "KEPT-MV"), `${route} ${w}: the kept field's value travels`);
        assert.ok(await anyContains(files, "AUTHOR-NAME"), `${route} ${w}: a kept comment's /T is not mistaken for a field`);
        assert.ok(await anyContains(files, "NOTE-BODY"));
      }
      // Merge keeps everything, fields included.
      const m = await call("merge_pdfs", { inputs: ["m.pdf", "m.pdf"], outputPath: `fr-${route}-m.pdf` });
      assert.ok(!m.isError, textOf(m));
      assert.ok(await fileContainsMarker(readFileSync(m.structuredContent.outputPath), "SECRET-MV"), "merge keeps every field");
    });
  });
}

// ---------------------------------------------------------------------------
// Codex final 2: untitled / inherited / DIRECT fields (value-centric, recursive)
// ---------------------------------------------------------------------------

type FieldShape = "untitled" | "direct" | "untitled-two-level" | "outline-nested-direct";

/** Page 1 keeps a titled field under `g`; the EXCLUDED field (page 2) is built per shape. */
async function makeFieldShape(shape: FieldShape): Promise<Uint8Array> {
  return makeDoc("S", 2, (doc) => {
    const c = doc.context;
    const [p1, p2] = doc.getPages();
    const root = c.register(c.obj({ T: PDFString.of("g"), FT: "Tx" }));
    const keepF = c.register(c.obj({ T: PDFString.of("keep"), Parent: root, V: PDFString.of("KEPT-V") }));
    const wk = c.register(c.obj({ Type: "Annot", Subtype: "Widget", Rect: [10, 10, 100, 30], Parent: keepF, P: p1.ref }));
    c.lookup(keepF, PDFDict).set(PDFName.of("Kids"), c.obj([wk]));
    p1.node.set(PDFName.of("Annots"), c.obj([wk]));
    let rootKids: unknown[] = [keepF];
    if (shape === "untitled") {
      // no /T, /FT inherited; only /Parent, /V, /DV, /Kids
      const drop = c.register(c.obj({ Parent: root, V: PDFString.of("SECRET-V"), DV: PDFString.of("SECRET-DV") }));
      const wd = c.register(c.obj({ Type: "Annot", Subtype: "Widget", Rect: [10, 10, 100, 30], Parent: drop, P: p2.ref }));
      c.lookup(drop, PDFDict).set(PDFName.of("Kids"), c.obj([wd]));
      rootKids = [keepF, drop];
      p2.node.set(PDFName.of("Annots"), c.obj([wd]));
    } else if (shape === "untitled-two-level") {
      // root {FT} -> mid {nothing but /Parent} -> drop {only /Parent, /DA}: no field key of its own
      const mid = c.register(c.obj({ Parent: root }));
      const drop = c.register(c.obj({ Parent: mid, DA: PDFString.of("SECRET-DA") }));
      const wd = c.register(c.obj({ Type: "Annot", Subtype: "Widget", Rect: [10, 10, 100, 30], Parent: drop, P: p2.ref }));
      c.lookup(drop, PDFDict).set(PDFName.of("Kids"), c.obj([wd]));
      c.lookup(mid, PDFDict).set(PDFName.of("Kids"), c.obj([drop]));
      rootKids = [keepF, mid];
      p2.node.set(PDFName.of("Annots"), c.obj([wd]));
    } else if (shape === "direct") {
      // a DIRECT merged field/widget: in page 2's /Annots and in a kept page's ResetForm /Fields
      const drop = c.obj({ Type: "Annot", Subtype: "Widget", Rect: [10, 10, 100, 30], T: PDFString.of("drop"), Parent: root, V: PDFString.of("SECRET-V"), DV: PDFString.of("SECRET-DV") });
      const reset = c.register(c.obj({ Type: "Annot", Subtype: "Link", Rect: [0, 0, 10, 10], A: { S: "ResetForm", Fields: [drop] } }));
      p1.node.set(PDFName.of("Annots"), c.obj([wk, reset]));
      p2.node.set(PDFName.of("Annots"), c.obj([drop]));
    } else {
      // outline-nested-direct: three levels down in an outline item's custom key, a direct untitled-parent field
      const field = c.obj({ T: PDFString.of("deep"), FT: "Tx", V: PDFString.of("SECRET-V"), DV: PDFString.of("SECRET-DV") });
      const item = c.register(c.obj({ Title: PDFString.of("o"), Dest: [p1.ref, PDFName.of("Fit")], Extra: { L1: { L2: [field] } } }));
      const ol = c.register(c.obj({ Type: "Outlines", First: item, Last: item, Count: 1 }));
      c.lookup(item, PDFDict).set(PDFName.of("Parent"), ol);
      doc.catalog.set(PDFName.of("Outlines"), ol);
    }
    c.lookup(root, PDFDict).set(PDFName.of("Kids"), c.obj(rootKids as any));
    doc.catalog.set(PDFName.of("AcroForm"), c.obj({ Fields: [root] }));
  });
}

for (const shape of ["untitled", "direct", "untitled-two-level", "outline-nested-direct"] as const) {
  test(`fields: an excluded field that is ${shape} is emptied (value-centric, recursive); the kept field survives; all writers`, async () => {
    const root = tempRoot();
    const input = await makeFieldShape(shape);
    put(root, "s.pdf", input);
    const secrets = shape === "untitled-two-level" ? ["SECRET-DA"] : ["SECRET-V", "SECRET-DV"];
    for (const m of [...secrets, "KEPT-V"]) assert.ok(await fileContainsMarker(input, m), `CONTROL (${shape}): input holds ${m}`);
    await withEditClient(root, {}, async (call) => {
      for (const w of WRITERS) {
        const { files } = await runWriter(call, root, w, "s.pdf", [1], `fs-${shape}-${w}`);
        for (const m of [...secrets, "S-2"]) assert.ok(!(await anyContains(files, m)), `${shape} ${w}: ${m} absent`);
        assert.ok(await anyContains(files, "KEPT-V"), `${shape} ${w}: the kept field's value travels`);
      }
      if (shape !== "outline-nested-direct") {
        const m = await call("merge_pdfs", { inputs: ["s.pdf", "s.pdf"], outputPath: `fs-${shape}-m.pdf` });
        assert.ok(!m.isError, textOf(m));
        assert.ok(await fileContainsMarker(readFileSync(m.structuredContent.outputPath), secrets[0]), `${shape}: merge keeps every field`);
      }
    });
  });
}

test("field scrub: the answer does not depend on traversal order (an emptied ancestor must not hide its untitled descendants)", async () => {
  const { scrubFieldsOutsideKept } = await import("./pdf-edit/docFacts.js");
  for (const ancestorFirst of [true, false]) {
    const doc = await PDFDocument.create();
    doc.addPage([100, 100]);
    const c = doc.context;
    // Register in either order by creating the objects first and wiring Parent afterwards.
    const order = ancestorFirst ? ["root", "mid", "leaf"] : ["leaf", "mid", "root"];
    const refs: Record<string, any> = {};
    for (const n of order) refs[n] = c.register(c.obj(n === "root" ? { FT: "Tx" } : n === "leaf" ? { DA: PDFString.of("SECRET-DA") } : {}));
    c.lookup(refs.mid, PDFDict).set(PDFName.of("Parent"), refs.root);
    c.lookup(refs.leaf, PDFDict).set(PDFName.of("Parent"), refs.mid);
    const emptied = scrubFieldsOutsideKept(doc, doc.getPages());
    assert.ok(emptied >= 2, `ancestorFirst=${ancestorFirst}: emptied ${emptied}`);
    assert.ok(!(await fileContainsMarker(await doc.save(), "SECRET-DA")), `ancestorFirst=${ancestorFirst}`);
  }
});

async function makeActionsDoc(): Promise<Uint8Array> {
  return makeDoc("A", 2, (doc) => {
    const c = doc.context;
    const [p1] = doc.getPages();
    const btn = c.register(
      c.obj({ Type: "Annot", Subtype: "Widget", FT: "Btn", Ff: 65536, T: PDFString.of("toggle"), Rect: [10, 10, 60, 30], P: p1.ref, A: { S: "Hide", T: PDFString.of("panel"), H: false } }),
    );
    const panel = c.register(c.obj({ Type: "Annot", Subtype: "Widget", FT: "Tx", T: PDFString.of("panel"), Rect: [10, 50, 100, 70], P: p1.ref, V: PDFString.of("panel-value") }));
    const movie = c.register(c.obj({ Type: "Annot", Subtype: "Link", Rect: [0, 0, 10, 10], A: { S: "Movie", T: PDFString.of("movie-title"), Operation: "Play" } }));
    p1.node.set(PDFName.of("Annots"), c.obj([btn, panel, movie]));
    doc.catalog.set(PDFName.of("AcroForm"), c.obj({ Fields: [btn, panel] }));
  });
}

test("fields: a kept widget's Hide action and a kept link's Movie action keep their /T (actions are never field material); all writers", async () => {
  const root = tempRoot();
  put(root, "act.pdf", await makeActionsDoc());
  const actions = async (bytes: Uint8Array) => {
    const out = await PDFDocument.load(bytes);
    const annots = out.getPage(0).node.lookup(PDFName.of("Annots"), PDFArray).asArray().map((x) => out.context.lookup(x, PDFDict));
    return annots.map((a) => a.lookupMaybe(PDFName.of("A"), PDFDict));
  };
  const txt = (d: PDFDict | undefined, k: string) => (d?.lookupMaybe(PDFName.of(k), PDFString)?.decodeText());
  await withEditClient(root, {}, async (call) => {
    for (const w of WRITERS) {
      const { files } = await runWriter(call, root, w, "act.pdf", [1], `act-${w}`);
      const [hide, , movie] = await actions(files[0]);
      assert.equal(hide?.get(PDFName.of("S")), PDFName.of("Hide"), `${w}: Hide /S`);
      assert.equal(txt(hide, "T"), "panel", `${w}: Hide /T kept`);
      assert.ok(hide?.get(PDFName.of("H")) !== undefined, `${w}: Hide /H kept`);
      assert.equal(movie?.get(PDFName.of("S")), PDFName.of("Movie"), `${w}: Movie /S`);
      assert.equal(txt(movie, "T"), "movie-title", `${w}: Movie /T kept`);
      assert.ok(await fileContainsMarker(files[0], "panel-value"), `${w}: the kept field's value travels`);
    }
  });
});

test("fields: a kept Link whose /Parent is a page-2 field does not keep that field; a Popup still travels with its kept markup annotation; all writers", async () => {
  const root = tempRoot();
  const input = await makeDoc("P", 2, (doc) => {
    const c = doc.context;
    const [p1, p2] = doc.getPages();
    const field = c.register(c.obj({ Type: "Annot", Subtype: "Widget", FT: "Tx", T: PDFString.of("far"), Rect: [1, 1, 50, 20], P: p2.ref, V: PDFString.of("SECRET-PARENT") }));
    const link = c.register(c.obj({ Type: "Annot", Subtype: "Link", Rect: [0, 0, 10, 10], Parent: field }));
    const note = c.register(c.obj({ Type: "Annot", Subtype: "Text", Rect: [20, 20, 40, 40], T: PDFString.of("AUTHOR"), Contents: PDFString.of("NOTE-BODY") }));
    const popup = c.register(c.obj({ Type: "Annot", Subtype: "Popup", Rect: [50, 50, 150, 100], Parent: note, Open: true }));
    c.lookup(note, PDFDict).set(PDFName.of("Popup"), popup);
    p1.node.set(PDFName.of("Annots"), c.obj([link, note, popup]));
    p2.node.set(PDFName.of("Annots"), c.obj([field]));
    doc.catalog.set(PDFName.of("AcroForm"), c.obj({ Fields: [field] }));
  });
  put(root, "lp.pdf", input);
  assert.ok(await fileContainsMarker(input, "SECRET-PARENT"), "CONTROL: input holds the secret");
  await withEditClient(root, {}, async (call) => {
    for (const w of WRITERS) {
      const { files } = await runWriter(call, root, w, "lp.pdf", [1], `lp-${w}`);
      assert.ok(!(await anyContains(files, "SECRET-PARENT")), `${w}: the page-2 field kept by a Link's /Parent is gone`);
      const out = await PDFDocument.load(files[0]);
      const annots = out.getPage(0).node.lookup(PDFName.of("Annots"), PDFArray).asArray().map((r) => out.context.lookup(r, PDFDict));
      const popup = annots.find((a) => a.get(PDFName.of("Subtype")) === PDFName.of("Popup"));
      assert.ok(popup, `${w}: the popup travels`);
      const parent = out.context.lookup(popup!.get(PDFName.of("Parent")), PDFDict);
      assert.equal(parent.get(PDFName.of("Subtype")), PDFName.of("Text"), `${w}: its parent is the markup annotation`);
      assert.ok(await fileContainsMarker(files[0], "NOTE-BODY") && (await fileContainsMarker(files[0], "AUTHOR")), `${w}: the markup annotation is intact`);
    }
  });
});

test("signatures: a /Contents (or /Cert) held as an INDIRECT object, also referenced from a kept page, carries no certificate; all writers", async () => {
  const root = tempRoot();
  for (const key of ["Contents", "Cert"] as const) {
    const doc = await PDFDocument.load(await makeSigned("merged", 2), { updateMetadata: false });
    const c = doc.context;
    const acro = doc.catalog.lookup(PDFName.of("AcroForm"), PDFDict);
    const field = c.lookup(acro.lookup(PDFName.of("Fields"), PDFArray).get(0), PDFDict);
    const sig = c.lookup(field.get(PDFName.of("V"))!, PDFDict);
    const blobRef = c.register(PDFHexString.fromText(`${CERT_MARKER}-indirect-${key}`));
    sig.set(PDFName.of(key), key === "Cert" ? c.obj([blobRef]) : blobRef);
    for (const p of doc.getPages()) p.node.set(PDFName.of("PieceInfo"), c.obj({ Data: blobRef }));
    const input = await doc.save();
    const name = `ind-${key}.pdf`;
    put(root, name, input);
    assert.ok(await fileContainsMarker(input, `${CERT_MARKER}-indirect-${key}`), `CONTROL (${key}): the input holds the certificate`);
    await withEditClient(root, {}, async (call) => {
      for (const w of WRITERS) {
        const { files } = await runWriter(call, root, w, name, [1, 2], `ic-${key}-${w}`);
        for (const f of files) assert.ok(!(await fileContainsMarker(f, `${CERT_MARKER}-indirect-${key}`)), `${key} ${w}: certificate absent`);
        assert.ok(await anyContains(files, "SIGNED-1"));
      }
      const m = await call("merge_pdfs", { inputs: [name, name], outputPath: `ic-${key}-m.pdf` });
      assert.ok(!m.isError, textOf(m));
      assert.ok(!(await fileContainsMarker(readFileSync(m.structuredContent.outputPath), `${CERT_MARKER}-indirect-${key}`)), `${key} merge`);
    });
  }
});

test("fields: StructElem and StructTreeRoot dictionaries (their /T is a title) are never field material", async () => {
  const { scrubFieldsOutsideKept } = await import("./pdf-edit/docFacts.js");
  const doc = await PDFDocument.create();
  doc.addPage([100, 100]);
  const c = doc.context;
  const elem = c.register(c.obj({ Type: "StructElem", S: "P", T: PDFString.of("Heading title") }));
  const root = c.register(c.obj({ Type: "StructTreeRoot", T: PDFString.of("root title"), K: elem }));
  doc.catalog.set(PDFName.of("StructTreeRoot"), root);
  scrubFieldsOutsideKept(doc, doc.getPages());
  assert.equal(c.lookup(elem, PDFDict).lookup(PDFName.of("T"), PDFString).decodeText(), "Heading title");
  assert.equal(c.lookup(root, PDFDict).lookup(PDFName.of("T"), PDFString).decodeText(), "root title");
  // CONTROL: a plain dictionary with a /T and an /FT IS field material; a /T alone is not.
  const field = c.register(c.obj({ T: PDFString.of("x"), FT: "Tx" }));
  const titleOnly = c.register(c.obj({ T: PDFString.of("just a title") }));
  scrubFieldsOutsideKept(doc, doc.getPages());
  assert.equal(c.lookup(field, PDFDict).entries().length, 0);
  assert.equal(c.lookup(titleOnly, PDFDict).entries().length, 1);
});

// ---------------------------------------------------------------------------
// Codex round 4: real-world dictionaries that merely use /T, /TM; and the three crafted bypasses
// ---------------------------------------------------------------------------

test("fields: a rectilinear /Measure (with a /T angle-format array) under a kept /VP and a 3D /AN (with /TM) travel unchanged; all writers", async () => {
  const root = tempRoot();
  const input = await makeDoc("R", 2, (doc) => {
    const c = doc.context;
    const [p1] = doc.getPages();
    const nf = (u: string) => ({ Type: "NumberFormat", U: PDFString.of(u), C: 1 });
    p1.node.set(
      PDFName.of("VP"),
      c.obj([{ Type: "Viewport", BBox: [0, 0, 100, 100], Measure: { Type: "Measure", Subtype: "RL", R: PDFString.of("1in = 1mi"), X: [nf("mi")], D: [nf("mi")], A: [nf("sq mi")], T: [nf("deg")], S: [nf("deg")] } }]),
    );
    const threeD = c.register(c.stream("u3d-data", { Type: "3D", Subtype: "U3D", AN: { Type: "3DAnimationStyle", Subtype: "Linear", PC: -1, TM: 2 } }));
    p1.node.set(PDFName.of("OmitlyThreeD"), threeD);
  });
  put(root, "m3.pdf", input);
  const facts = async (bytes: Uint8Array) => {
    const doc = await PDFDocument.load(bytes);
    const vp = doc.getPage(0).node.lookup(PDFName.of("VP"), PDFArray).lookup(0, PDFDict);
    const measure = vp.lookup(PDFName.of("Measure"), PDFDict);
    const t = measure.lookup(PDFName.of("T"), PDFArray);
    const three = doc.context.lookup(doc.getPage(0).node.get(PDFName.of("OmitlyThreeD"))!);
    const an = (three as PDFRawStream).dict.lookup(PDFName.of("AN"), PDFDict);
    return { tSize: t.size(), measureKeys: measure.entries().length, anTM: an.get(PDFName.of("TM"))?.toString(), anPC: an.get(PDFName.of("PC"))?.toString() };
  };
  const control = await facts(input);
  assert.deepEqual(control, { tSize: 1, measureKeys: 8, anTM: "2", anPC: "-1" }, "CONTROL: the input has them");
  await withEditClient(root, {}, async (call) => {
    for (const w of WRITERS) {
      const { files } = await runWriter(call, root, w, "m3.pdf", [1], `m3-${w}`);
      assert.deepEqual(await facts(files[0]), control, `${w}: unchanged`);
    }
  });
});

test("fields: an outline-looking dictionary (/Title and /Parent) that is also a widget with values is still emptied; all writers", async () => {
  const root = tempRoot();
  const input = await makeDoc("O", 2, (doc) => {
    const c = doc.context;
    const [p1, p2] = doc.getPages();
    const g = c.register(c.obj({ T: PDFString.of("g"), FT: "Tx" }));
    const drop = c.register(
      c.obj({ Type: "Annot", Subtype: "Widget", Title: PDFString.of("looks like a bookmark"), Parent: g, P: p2.ref, Rect: [1, 1, 5, 5], V: PDFString.of("SECRET-OL"), DV: PDFString.of("SECRET-OLD") }),
    );
    const reset = c.register(c.obj({ Type: "Annot", Subtype: "Link", Rect: [0, 0, 10, 10], A: { S: "ResetForm", Fields: [drop] } }));
    p1.node.set(PDFName.of("Annots"), c.obj([reset]));
    p2.node.set(PDFName.of("Annots"), c.obj([drop]));
    c.lookup(g, PDFDict).set(PDFName.of("Kids"), c.obj([drop]));
    doc.catalog.set(PDFName.of("AcroForm"), c.obj({ Fields: [g] }));
  });
  put(root, "ol.pdf", input);
  assert.ok(await fileContainsMarker(input, "SECRET-OL") && (await fileContainsMarker(input, "SECRET-OLD")), "CONTROL");
  await withEditClient(root, {}, async (call) => {
    for (const w of WRITERS) {
      const { files } = await runWriter(call, root, w, "ol.pdf", [1], `ol-${w}`);
      assert.ok(!(await anyContains(files, "SECRET-OL")) && !(await anyContains(files, "SECRET-OLD")), `${w}`);
    }
  });
});

test("signatures: an INDIRECT /Cert array whose elements are indirect objects, also referenced from a preserved /Info, carries no certificate; all writers", async () => {
  const root = tempRoot();
  const doc = await PDFDocument.load(await makeSigned("merged", 2), { updateMetadata: false });
  const c = doc.context;
  const acro = doc.catalog.lookup(PDFName.of("AcroForm"), PDFDict);
  const field = c.lookup(acro.lookup(PDFName.of("Fields"), PDFArray).get(0), PDFDict);
  const sig = c.lookup(field.get(PDFName.of("V"))!, PDFDict);
  const certObj = c.register(PDFHexString.fromText(`${CERT_MARKER}-nested-cert`));
  const certArray = c.register(c.obj([certObj]));
  sig.set(PDFName.of("Cert"), certArray);
  c.trailerInfo.Info = c.register(c.obj({ Title: PDFString.of("t"), Custom: certObj }));
  const input = await doc.save();
  put(root, "nc.pdf", input);
  assert.ok(await fileContainsMarker(input, `${CERT_MARKER}-nested-cert`), "CONTROL");
  await withEditClient(root, {}, async (call) => {
    for (const w of WRITERS) {
      const { files } = await runWriter(call, root, w, "nc.pdf", [1, 2], `nc-${w}`);
      assert.ok(!(await anyContains(files, `${CERT_MARKER}-nested-cert`)), `${w}`);
    }
    const m = await call("merge_pdfs", { inputs: ["nc.pdf", "nc.pdf"], outputPath: "nc-m.pdf" });
    assert.ok(!(await fileContainsMarker(readFileSync(m.structuredContent.outputPath), `${CERT_MARKER}-nested-cert`)));
  });
});

test("fields: field material inside a DIRECT trailer /Info is emptied (source scrub and backstop); all writers", async () => {
  const root = tempRoot();
  const input = await makeDoc("I", 2, (doc) => {
    const c = doc.context;
    c.trailerInfo.Info = c.obj({ Title: PDFString.of("direct info"), Nested: { FT: "Tx", V: PDFString.of("SECRET-INFO"), DV: PDFString.of("DEFAULT-INFO") } });
  });
  put(root, "di.pdf", input);
  const loaded = await PDFDocument.load(input);
  assert.ok(loaded.context.trailerInfo.Info instanceof PDFDict, "CONTROL: the Info really is a direct dictionary");
  assert.ok(await fileContainsMarker(input, "SECRET-INFO") || String(loaded.context.trailerInfo.Info).includes("SECRET-INFO"), "CONTROL: it holds the value");
  await withEditClient(root, {}, async (call) => {
    for (const w of WRITERS) {
      const { files } = await runWriter(call, root, w, "di.pdf", [1], `di-${w}`);
      for (const f of files) {
        const out = await PDFDocument.load(f);
        const text = String(out.context.trailerInfo.Info);
        assert.ok(!text.includes("SECRET-INFO") && !text.includes("DEFAULT-INFO"), `${w}: the Info no longer carries the field values`);
        assert.ok(!(await fileContainsMarker(f, "SECRET-INFO")), `${w}`);
      }
    }
  });
});

test("fields: a field mislabelled /Type /Page (with /FT and values) is still emptied; a real page is not; all writers", async () => {
  const root = tempRoot();
  const input = await makeDoc("Q", 2, (doc) => {
    const c = doc.context;
    const [p1] = doc.getPages();
    const fake = c.register(c.obj({ Type: "Page", FT: "Tx", T: PDFString.of("fake"), V: PDFString.of("SECRET-PAGE"), DV: PDFString.of("SECRET-PAGE-DV") }));
    const reset = c.register(c.obj({ Type: "Annot", Subtype: "Link", Rect: [0, 0, 10, 10], A: { S: "ResetForm", Fields: [fake] } }));
    p1.node.set(PDFName.of("Annots"), c.obj([reset]));
  });
  put(root, "fp.pdf", input);
  assert.ok(await fileContainsMarker(input, "SECRET-PAGE") && (await fileContainsMarker(input, "SECRET-PAGE-DV")), "CONTROL");
  await withEditClient(root, {}, async (call) => {
    for (const w of WRITERS) {
      const { files } = await runWriter(call, root, w, "fp.pdf", [1], `fp-${w}`);
      assert.ok(!(await anyContains(files, "SECRET-PAGE")) && !(await anyContains(files, "SECRET-PAGE-DV")), `${w}`);
      assert.ok(await anyContains(files, "Q-1"), `${w}: the real page is untouched`);
    }
  });
});

test("signatures: a STREAM whose own dictionary says /Type /Sig or /DocTimeStamp loses /Contents, /Cert and /ByteRange (and their indirect values); other streams stay; all writers", async () => {
  const root = tempRoot();
  for (const type of ["Sig", "DocTimeStamp"] as const) {
    const blobRef: { ref?: unknown } = {};
    const input = await makeDoc("Z", 2, (doc) => {
      const c = doc.context;
      const blob = c.register(PDFHexString.fromText(`${CERT_MARKER}-stream-${type}`));
      blobRef.ref = blob;
      const sigStream = c.register(
        c.stream("body", { Type: type, ByteRange: [0, 1, 2, 3], Contents: blob, Cert: PDFHexString.fromText(`${CERT_MARKER}-cert-${type}`) }),
      );
      for (const p of doc.getPages()) p.node.set(PDFName.of("OmitlyBlob"), sigStream);
    });
    const name = `ss-${type}.pdf`;
    put(root, name, input);
    for (const m of [`${CERT_MARKER}-stream-${type}`, `${CERT_MARKER}-cert-${type}`]) assert.ok(await fileContainsMarker(input, m), `CONTROL (${type}): ${m}`);
    await withEditClient(root, {}, async (call) => {
      for (const w of WRITERS) {
        const { files, result } = await runWriter(call, root, w, name, [1, 2], `ss-${type}-${w}`);
        for (const m of [`${CERT_MARKER}-stream-${type}`, `${CERT_MARKER}-cert-${type}`]) assert.ok(!(await anyContains(files, m)), `${type} ${w}: ${m} absent`);
        const out = await PDFDocument.load(files[0]);
        const st = out.context.lookup(out.getPage(0).node.get(PDFName.of("OmitlyBlob"))!) as PDFRawStream;
        assert.ok(st instanceof PDFRawStream, `${type} ${w}: the stream itself travels`);
        for (const k of ["Contents", "Cert", "ByteRange"]) assert.equal(st.dict.get(PDFName.of(k)), undefined, `${type} ${w}: /${k} removed`);
        assert.ok(result.structuredContent.warnings.includes(SIGNATURE_WARNING), `${type} ${w}: warns`);
      }
    });
  }
});

async function makeAttachmentAndBeads(): Promise<Uint8Array> {
  return makeDoc("N", 2, (doc) => {
    const c = doc.context;
    const [p1, p2] = doc.getPages();
    // A FileAttachment annotation: /FS is a Filespec whose /V is the volatile flag.
    const ef = c.register(c.stream("attached-file-bytes-OMITLY", { Type: "EmbeddedFile" }));
    const fs = c.register(c.obj({ Type: "Filespec", F: PDFString.of("a.txt"), UF: PDFString.of("a.txt"), V: true, EF: { F: ef } }));
    const att = c.register(c.obj({ Type: "Annot", Subtype: "FileAttachment", Rect: [10, 10, 30, 30], FS: fs, Contents: PDFString.of("attachment") }));
    p1.node.set(PDFName.of("Annots"), c.obj([att]));
    // A two-bead article thread: /V is the PREVIOUS bead, /N the next.
    const thread = c.register(c.obj({ Type: "Thread" }));
    const b1 = c.register(c.obj({ Type: "Bead", T: thread, P: p1.ref, R: [0, 0, 50, 50] }));
    const b2 = c.register(c.obj({ Type: "Bead", T: thread, P: p2.ref, R: [0, 0, 60, 60] }));
    c.lookup(b1, PDFDict).set(PDFName.of("N"), b2);
    c.lookup(b1, PDFDict).set(PDFName.of("V"), b2);
    c.lookup(b2, PDFDict).set(PDFName.of("N"), b1);
    c.lookup(b2, PDFDict).set(PDFName.of("V"), b1);
    c.lookup(thread, PDFDict).set(PDFName.of("F"), b1);
    p1.node.set(PDFName.of("B"), c.obj([b1]));
    p2.node.set(PDFName.of("B"), c.obj([b2]));
  });
}

test("fields: a kept FileAttachment keeps its /FS (/V true, /EF bytes) and a kept article thread keeps its beads' /V /N /T /P; all writers", async () => {
  const root = tempRoot();
  put(root, "nb.pdf", await makeAttachmentAndBeads());
  const facts = async (bytes: Uint8Array) => {
    const out = await PDFDocument.load(bytes);
    const att = out.context.lookup(out.getPage(0).node.lookup(PDFName.of("Annots"), PDFArray).get(0), PDFDict);
    const fs = out.context.lookup(att.get(PDFName.of("FS")), PDFDict);
    const ef = out.context.lookup(fs.lookup(PDFName.of("EF"), PDFDict).get(PDFName.of("F"))!) as PDFRawStream;
    const bead = (i: number) => {
      const b = out.context.lookup(out.getPage(i).node.lookup(PDFName.of("B"), PDFArray).get(0), PDFDict);
      return ["V", "N", "T", "P", "R"].map((k) => b.get(PDFName.of(k)) !== undefined);
    };
    return {
      fsKeys: fs.entries().map(([k]) => k.toString()).sort(),
      volatile: fs.get(PDFName.of("V"))?.toString(),
      efBytes: Buffer.from(decodePDFRawStream(ef).decode()).toString(),
      beads: Array.from({ length: out.getPageCount() }, (_, i) => bead(i)),
    };
  };
  await withEditClient(root, {}, async (call) => {
    for (const w of WRITERS) {
      const { files } = await runWriter(call, root, w, "nb.pdf", [1, 2], `nb-${w}`);
      const f = await facts(files[0]);
      assert.deepEqual(f.fsKeys, ["/EF", "/F", "/Type", "/UF", "/V"], `${w}: the Filespec is intact`);
      assert.equal(f.volatile, "true");
      assert.equal(f.efBytes, "attached-file-bytes-OMITLY", `${w}: attachment bytes`);
      assert.ok(f.beads.length >= 1 && f.beads.every((b) => b.every(Boolean)), `${w}: beads keep V N T P R`);
      if (w !== "split_pdf") assert.equal(f.beads.length, 2);
    }
  });
});

// ---------------------------------------------------------------------------
// Codex final round: merging two forms whose /DR names collide (/F1 = Helvetica vs /F1 = Courier)
// ---------------------------------------------------------------------------

async function makeFontForm(fieldName: string, baseFont: string, opts: { fieldDA: boolean }): Promise<Uint8Array> {
  const doc = await PDFDocument.create();
  const page = doc.addPage([300, 400]);
  const c = doc.context;
  const font = c.register(c.obj({ Type: "Font", Subtype: "Type1", BaseFont: baseFont }));
  const widget = c.register(
    c.obj({
      Type: "Annot", Subtype: "Widget", FT: "Tx", T: PDFString.of(fieldName), Rect: [10, 10, 150, 30], P: page.ref, V: PDFString.of(`value-${fieldName}`),
      ...(opts.fieldDA ? { DA: PDFString.of("/F1 12 Tf 0 g") } : {}),
    }),
  );
  page.node.set(PDFName.of("Annots"), c.obj([widget]));
  doc.catalog.set(PDFName.of("AcroForm"), c.obj({ Fields: [widget], DR: { Font: { F1: font } }, DA: PDFString.of("/F1 12 Tf 0 g"), NeedAppearances: true }));
  return doc.save();
}

/** For each top-level field of the merged form: its font as its /DA names it, resolved through the form's /DR. */
async function fieldFonts(bytes: Uint8Array): Promise<Record<string, string>> {
  const doc = await PDFDocument.load(bytes);
  const acro = doc.catalog.lookup(PDFName.of("AcroForm"), PDFDict);
  const fonts = acro.lookup(PDFName.of("DR"), PDFDict).lookup(PDFName.of("Font"), PDFDict);
  const formDA = acro.lookupMaybe(PDFName.of("DA"), PDFString)?.decodeText();
  const out: Record<string, string> = {};
  for (const ref of acro.lookup(PDFName.of("Fields"), PDFArray).asArray()) {
    const f = doc.context.lookup(ref, PDFDict);
    const raw = f.get(PDFName.of("DA"));
    const daObj = raw === undefined ? undefined : (doc.context.lookup(raw) as PDFString | PDFHexString);
    const da = (daObj ? Buffer.from(daObj.asBytes()).toString("latin1") : undefined) ?? formDA ?? "";
    const name = /\/(\S+)\s+[\d.]+\s+Tf/.exec(da)?.[1] ?? "";
    const font = fonts.get(PDFName.of(name));
    out[f.lookup(PDFName.of("T"), PDFString).decodeText()] = font ? doc.context.lookup(font, PDFDict).lookup(PDFName.of("BaseFont"), PDFName).decodeText() : `MISSING(${name})`;
  }
  return out;
}

test("merge: two forms using the same font NAME for different fonts each keep their own font (the incoming /F1 is renamed and its /DA rewritten)", async () => {
  const root = tempRoot();
  for (const fieldDA of [true, false]) {
    const a = await makeFontForm("fa", "Helvetica", { fieldDA });
    const b = await makeFontForm("fb", "Courier", { fieldDA });
    put(root, `a${fieldDA}.pdf`, a);
    put(root, `b${fieldDA}.pdf`, b);
    assert.deepEqual(await fieldFonts(b), { fb: "Courier" }, "CONTROL: alone, the second form uses Courier");
    await withEditClient(root, {}, async (call) => {
      const m = await call("merge_pdfs", { inputs: [`a${fieldDA}.pdf`, `b${fieldDA}.pdf`], outputPath: `m${fieldDA}.pdf` });
      assert.ok(!m.isError, textOf(m));
      assert.deepEqual(await fieldFonts(readFileSync(m.structuredContent.outputPath)), { fa: "Helvetica", fb: "Courier" }, `fieldDA=${fieldDA}`);
      assert.ok(!m.structuredContent.warnings.some((w: string) => /font/i.test(w)), "no font warning when every rename applied");
    });
    // The desktop's appendPdf shares the helper.
    const { appendPdf } = await import("./pdf-edit/pageOps.js");
    assert.deepEqual(await fieldFonts(await appendPdf(a, b)), { fa: "Helvetica", fb: "Courier" }, `appendPdf fieldDA=${fieldDA}`);
  }
});

test("merge: the same font in both forms is not renamed", async () => {
  const root = tempRoot();
  put(root, "h1.pdf", await makeFontForm("f1", "Helvetica", { fieldDA: true }));
  put(root, "h2.pdf", await makeFontForm("f2", "Helvetica", { fieldDA: true }));
  await withEditClient(root, {}, async (call) => {
    const m = await call("merge_pdfs", { inputs: ["h1.pdf", "h2.pdf"], outputPath: "hm.pdf" });
    assert.ok(!m.isError, textOf(m));
    const out = await PDFDocument.load(readFileSync(m.structuredContent.outputPath));
    const fonts = out.catalog.lookup(PDFName.of("AcroForm"), PDFDict).lookup(PDFName.of("DR"), PDFDict).lookup(PDFName.of("Font"), PDFDict);
    assert.deepEqual(fonts.entries().map(([k]) => k.decodeText()), ["F1"], "one /F1, no /F1_2");
  });
});

type DAForm = "literal" | "hex";

async function makeDAForm(fieldName: string, baseFont: string, fieldDA: string, formDA: string, kind: DAForm): Promise<Uint8Array> {
  const doc = await PDFDocument.create();
  const page = doc.addPage([300, 400]);
  const c = doc.context;
  const font = c.register(c.obj({ Type: "Font", Subtype: "Type1", BaseFont: baseFont }));
  const mk = (t: string) => (kind === "hex" ? PDFHexString.of(Buffer.from(t, "latin1").toString("hex")) : PDFString.of(t));
  const widget = c.register(
    c.obj({ Type: "Annot", Subtype: "Widget", FT: "Tx", T: PDFString.of(fieldName), Rect: [10, 10, 150, 30], P: page.ref, V: PDFString.of(`v-${fieldName}`), DA: mk(fieldDA) }),
  );
  page.node.set(PDFName.of("Annots"), c.obj([widget]));
  doc.catalog.set(PDFName.of("AcroForm"), c.obj({ Fields: [widget], DR: { Font: { F1: font } }, DA: mk(formDA), NeedAppearances: true }));
  return doc.save();
}

/** Each top-level field's /DA bytes (Latin-1) and whether it is written as a hex string. */
async function fieldDAs(bytes: Uint8Array): Promise<Record<string, { text: string; hex: boolean }>> {
  const doc = await PDFDocument.load(bytes, { throwOnInvalidObject: true });
  const acro = doc.catalog.lookup(PDFName.of("AcroForm"), PDFDict);
  const out: Record<string, { text: string; hex: boolean }> = {};
  for (const ref of acro.lookup(PDFName.of("Fields"), PDFArray).asArray()) {
    const f = doc.context.lookup(ref, PDFDict);
    const da = doc.context.lookup(f.get(PDFName.of("DA"))!) as PDFString | PDFHexString;
    out[f.lookup(PDFName.of("T"), PDFString).decodeText()] = { text: Buffer.from(da.asBytes()).toString("latin1"), hex: da instanceof PDFHexString };
  }
  return out;
}

test("merge: a /DA written as a HEX string (form level and field level) does not fail the merge, with or without a font clash", async () => {
  const root = tempRoot();
  const da = "/F1 12 Tf 0 g";
  put(root, "ha.pdf", await makeDAForm("fa", "Helvetica", da, da, "hex"));
  put(root, "hb.pdf", await makeDAForm("fb", "Courier", da, da, "hex"));
  put(root, "plain.pdf", await makeDoc("P", 1));
  await withEditClient(root, {}, async (call) => {
    const one = await call("merge_pdfs", { inputs: ["ha.pdf", "plain.pdf"], outputPath: "m1.pdf" }); // a single form
    assert.ok(!one.isError, textOf(one));
    const two = await call("merge_pdfs", { inputs: ["ha.pdf", "hb.pdf"], outputPath: "m2.pdf" }); // clash
    assert.ok(!two.isError, textOf(two));
    const das = await fieldDAs(readFileSync(two.structuredContent.outputPath));
    assert.deepEqual({ fa: das.fa.text, fb: das.fb.text }, { fa: da, fb: "/F1_2 12 Tf 0 g" }, "the rename applied to the hex /DA");
    assert.equal(das.fa.hex, true, "the unchanged /DA is untouched");
  });
});

test("merge: only the font operand of Tf is renamed (a colour space called /F1 is not), and a /DA with a comment and a ) round-trips", async () => {
  const root = tempRoot();
  const weird = "/F1 12 Tf /F1 cs 1 0 0 sc";
  // As it is WRITTEN in the file: `\)` and `\n` are string escapes (pdf-lib's PDFString.of takes the escaped form).
  const tricky = "/F1 12 Tf % comment \\)\\n0 g";
  put(root, "wa.pdf", await makeDAForm("fa", "Helvetica", "/F1 10 Tf 0 g", "/F1 10 Tf 0 g", "literal"));
  put(root, "wb.pdf", await makeDAForm("fb", "Courier", weird, weird, "literal"));
  put(root, "wc.pdf", await makeDAForm("fc", "Courier", tricky, tricky, "literal"));
  await withEditClient(root, {}, async (call) => {
    const m = await call("merge_pdfs", { inputs: ["wa.pdf", "wb.pdf"], outputPath: "w1.pdf" });
    assert.ok(!m.isError, textOf(m));
    const das = await fieldDAs(readFileSync(m.structuredContent.outputPath));
    assert.equal(das.fb.text, "/F1_2 12 Tf /F1 cs 1 0 0 sc", "only the Tf operand");
    assert.deepEqual(das.fa, { text: "/F1 10 Tf 0 g", hex: false }, "the first form's /DA is untouched, byte for byte, still a literal string");
    const t = await call("merge_pdfs", { inputs: ["wa.pdf", "wc.pdf"], outputPath: "w2.pdf" });
    assert.ok(!t.isError, textOf(t));
    const bytes = readFileSync(t.structuredContent.outputPath);
    const das2 = await fieldDAs(bytes); // loads with throwOnInvalidObject: true
    assert.equal(das2.fc.text, "/F1_2 12 Tf % comment )\n0 g", "comment, paren and newline intact");
    assert.equal(das2.fc.hex, true, "a rewritten /DA is a hex string");
  });
});

test("merge: a #-escaped font name (/Times#20Roman) that collides is renamed and re-escaped, and resolves to its own font", async () => {
  const root = tempRoot();
  const mk = async (name: string, baseFont: string) => {
    const doc = await PDFDocument.create();
    const page = doc.addPage([300, 400]);
    const c = doc.context;
    const font = c.register(c.obj({ Type: "Font", Subtype: "Type1", BaseFont: baseFont }));
    const w = c.register(c.obj({ Type: "Annot", Subtype: "Widget", FT: "Tx", T: PDFString.of(name), Rect: [1, 1, 100, 20], P: page.ref, DA: PDFString.of("/Times#20Roman 12 Tf 0 g") }));
    page.node.set(PDFName.of("Annots"), c.obj([w]));
    doc.catalog.set(PDFName.of("AcroForm"), c.obj({ Fields: [w], DR: { Font: { [PDFName.of("Times Roman").decodeText()]: font } } }));
    return doc.save();
  };
  put(root, "ta.pdf", await mk("fa", "Times-Roman"));
  put(root, "tb.pdf", await mk("fb", "Courier"));
  await withEditClient(root, {}, async (call) => {
    const m = await call("merge_pdfs", { inputs: ["ta.pdf", "tb.pdf"], outputPath: "tm.pdf" });
    assert.ok(!m.isError, textOf(m));
    assert.ok(!m.structuredContent.warnings.some((w: string) => /font/i.test(w)), "every rename applied");
    const doc = await PDFDocument.load(readFileSync(m.structuredContent.outputPath), { throwOnInvalidObject: true });
    const acro = doc.catalog.lookup(PDFName.of("AcroForm"), PDFDict);
    const fonts = acro.lookup(PDFName.of("DR"), PDFDict).lookup(PDFName.of("Font"), PDFDict);
    const resolved: Record<string, string> = {};
    for (const ref of acro.lookup(PDFName.of("Fields"), PDFArray).asArray()) {
      const f = doc.context.lookup(ref, PDFDict);
      const da = f.get(PDFName.of("DA"));
      const text = Buffer.from((doc.context.lookup(da!) as PDFString | PDFHexString).asBytes()).toString("latin1");
      const raw = /^(\/\S+)\s+12\s+Tf/.exec(text)![1];
      const name = raw.slice(1).replace(/#([0-9A-Fa-f]{2})/g, (_, h: string) => String.fromCharCode(parseInt(h, 16)));
      resolved[f.lookup(PDFName.of("T"), PDFString).decodeText()] = `${raw} -> ${doc.context.lookup(fonts.get(PDFName.of(name))!, PDFDict).lookup(PDFName.of("BaseFont"), PDFName).decodeText()}`;
    }
    assert.deepEqual(resolved, { fa: "/Times#20Roman -> Times-Roman", fb: "/Times#20Roman_2 -> Courier" });
  });
});

test("merge: fonts identical down to depth 13 and different below are NOT treated as the same font (the incoming one is renamed)", async () => {
  const root = tempRoot();
  const deepFont = async (name: string, leaf: string) => {
    const doc = await PDFDocument.create();
    const page = doc.addPage([300, 400]);
    const c = doc.context;
    let nested: any = { Leaf: PDFString.of(leaf) };
    for (let i = 0; i < 14; i++) nested = { Down: nested };
    const font = c.register(c.obj({ Type: "Font", Subtype: "Type1", BaseFont: "Helvetica", Deep: nested }));
    const w = c.register(c.obj({ Type: "Annot", Subtype: "Widget", FT: "Tx", T: PDFString.of(name), Rect: [1, 1, 100, 20], P: page.ref, DA: PDFString.of("/F1 12 Tf 0 g") }));
    page.node.set(PDFName.of("Annots"), c.obj([w]));
    doc.catalog.set(PDFName.of("AcroForm"), c.obj({ Fields: [w], DR: { Font: { F1: font } } }));
    return doc.save();
  };
  put(root, "da.pdf", await deepFont("fa", "one"));
  put(root, "db.pdf", await deepFont("fb", "two"));
  await withEditClient(root, {}, async (call) => {
    const m = await call("merge_pdfs", { inputs: ["da.pdf", "db.pdf"], outputPath: "dm.pdf" });
    assert.ok(!m.isError, textOf(m));
    const doc = await PDFDocument.load(readFileSync(m.structuredContent.outputPath));
    const fonts = doc.catalog.lookup(PDFName.of("AcroForm"), PDFDict).lookup(PDFName.of("DR"), PDFDict).lookup(PDFName.of("Font"), PDFDict);
    assert.deepEqual(fonts.entries().map(([k]) => k.decodeText()).sort(), ["F1", "F1_2"], "both fonts are kept under different names");
  });
});

/** A hex string decoded per the PDF spec (white space between digits ignored, an odd last digit padded with 0). */
function specHex(h: PDFHexString): string {
  let d = h.asString().replace(/[\0\t\n\f\r ]/g, "");
  if (d.length % 2) d += "0";
  return d.match(/../g)!.map((x) => String.fromCharCode(parseInt(x, 16))).join("");
}

test("merge: a /DA hex string with white space (and an odd last digit) is decoded per the spec: renamed on a clash, byte-identical when unchanged, not garbled when inherited", async () => {
  const root = tempRoot();
  const spaced = "2F 46 31 20 31 32\n20\t54 66 20 30 20 67"; // /F1 12 Tf 0 g
  const odd = "2F4631203132205466 20 3"; // /F1 12 Tf 0   (the last digit 3 is padded to 30)
  const build = async (name: string, baseFont: string, fieldDA: string | undefined, formDA: string) => {
    const doc = await PDFDocument.create();
    const page = doc.addPage([300, 400]);
    const c = doc.context;
    const font = c.register(c.obj({ Type: "Font", Subtype: "Type1", BaseFont: baseFont }));
    const w = c.register(
      c.obj({ Type: "Annot", Subtype: "Widget", FT: "Tx", T: PDFString.of(name), Rect: [1, 1, 100, 20], P: page.ref, ...(fieldDA ? { DA: PDFHexString.of(fieldDA) } : {}) }),
    );
    page.node.set(PDFName.of("Annots"), c.obj([w]));
    doc.catalog.set(PDFName.of("AcroForm"), c.obj({ Fields: [w], DR: { Font: { F1: font } }, DA: PDFHexString.of(formDA) }));
    return doc.save();
  };
  const dasOf = async (file: string) => {
    const doc = await PDFDocument.load(readFileSync(path.join(root, file)), { throwOnInvalidObject: true });
    const acro = doc.catalog.lookup(PDFName.of("AcroForm"), PDFDict);
    const out: Record<string, { text: string; raw: string }> = {};
    for (const ref of acro.lookup(PDFName.of("Fields"), PDFArray).asArray()) {
      const f = doc.context.lookup(ref, PDFDict);
      const da = doc.context.lookup(f.get(PDFName.of("DA"))!) as PDFHexString;
      out[f.lookup(PDFName.of("T"), PDFString).decodeText()] = { text: specHex(da), raw: da.asString() };
    }
    return out;
  };
  put(root, "sa.pdf", await build("fa", "Helvetica", spaced, spaced));
  put(root, "sb.pdf", await build("fb", "Courier", spaced, spaced)); // clash, own /DA with white space
  put(root, "sc.pdf", await build("fc", "Courier", undefined, spaced)); // clash, /DA inherited from the form
  put(root, "so.pdf", await build("fo", "Courier", odd, odd)); // clash, odd-length hex
  put(root, "sd.pdf", await build("fd", "Helvetica", undefined, "2F 46 31 20 31 30 20 54 66 20 30 20 67")); // same font, a DIFFERENT form /DA (10 pt), inherited
  await withEditClient(root, {}, async (call) => {
    const merge = async (a: string, b: string, out: string) => {
      const m = await call("merge_pdfs", { inputs: [a, b], outputPath: out });
      assert.ok(!m.isError, textOf(m));
      assert.ok(!m.structuredContent.warnings.some((w: string) => /font/i.test(w)), `${out}: no font warning`);
    };
    await merge("sa.pdf", "sb.pdf", "m1.pdf");
    let das = await dasOf("m1.pdf");
    assert.equal(das.fa.raw, spaced, "the unchanged /DA is byte-identical, white space and all");
    assert.equal(das.fb.text, "/F1_2 12 Tf 0 g", "own /DA with white space renamed");
    await merge("sa.pdf", "sc.pdf", "m2.pdf");
    das = await dasOf("m2.pdf");
    assert.equal(das.fc.text, "/F1_2 12 Tf 0 g", "an inherited /DA is pushed down renamed, not garbled");
    await merge("sa.pdf", "so.pdf", "m3.pdf");
    das = await dasOf("m3.pdf");
    assert.equal(das.fo.text, "/F1_2 12 Tf 0", "odd-length hex: the last digit is padded with 0");
    await merge("sa.pdf", "sd.pdf", "m4.pdf");
    das = await dasOf("m4.pdf");
    assert.equal(das.fd.text, "/F1 10 Tf 0 g", "no clash, different form /DA: pushed down byte-for-byte, not garbled");
  });
});

test("merge: a hex string inside a /DA is one token (a % or a /F2 inside it is not syntax); an unterminated one raises the font warning", async () => {
  const root = tempRoot();
  const mk = async (name: string, baseFont: string, da: string) => {
    const doc = await PDFDocument.create();
    const page = doc.addPage([300, 400]);
    const c = doc.context;
    const font = c.register(c.obj({ Type: "Font", Subtype: "Type1", BaseFont: baseFont }));
    const w = c.register(c.obj({ Type: "Annot", Subtype: "Widget", FT: "Tx", T: PDFString.of(name), Rect: [1, 1, 100, 20], P: page.ref, DA: PDFHexString.of(Buffer.from(da, "latin1").toString("hex")) }));
    page.node.set(PDFName.of("Annots"), c.obj([w]));
    doc.catalog.set(PDFName.of("AcroForm"), c.obj({ Fields: [w], DR: { Font: { F1: font } } }));
    return doc.save();
  };
  const textOf2 = async (file: string) => {
    const doc = await PDFDocument.load(readFileSync(path.join(root, file)));
    const acro = doc.catalog.lookup(PDFName.of("AcroForm"), PDFDict);
    const out: Record<string, string> = {};
    for (const ref of acro.lookup(PDFName.of("Fields"), PDFArray).asArray()) {
      const f = doc.context.lookup(ref, PDFDict);
      out[f.lookup(PDFName.of("T"), PDFString).decodeText()] = specHex(doc.context.lookup(f.get(PDFName.of("DA"))!) as PDFHexString);
    }
    return out;
  };
  put(root, "xa.pdf", await mk("fa", "Helvetica", "/F1 10 Tf 0 g"));
  const cases: [string, string, string][] = [
    ["pct", "<41%42> /F1 12 Tf 0 g", "<41%42> /F1_2 12 Tf 0 g"], // the % is inside a hex string, not a comment
    ["slash", "/F1 12 Tf <4142/F2 12 Tf> 0 g", "/F1_2 12 Tf <4142/F2 12 Tf> 0 g"], // a font name inside a hex string is not renamed
  ];
  await withEditClient(root, {}, async (call) => {
    for (const [tag, da, want] of cases) {
      put(root, `x-${tag}.pdf`, await mk("fb", "Courier", da));
      const m = await call("merge_pdfs", { inputs: ["xa.pdf", `x-${tag}.pdf`], outputPath: `xm-${tag}.pdf` });
      assert.ok(!m.isError, textOf(m));
      assert.equal((await textOf2(`xm-${tag}.pdf`)).fb, want, tag);
      assert.ok(!m.structuredContent.warnings.some((w: string) => /font/i.test(w)), `${tag}: no warning`);
    }
    // An unterminated hex string cannot be tokenised reliably: the rename is applied where it can be, and the font warning is raised.
    put(root, "x-open.pdf", await mk("fb", "Courier", "/F1 12 Tf <4142 0 g"));
    const open = await call("merge_pdfs", { inputs: ["xa.pdf", "x-open.pdf"], outputPath: "xm-open.pdf" });
    assert.ok(!open.isError, textOf(open));
    assert.ok(open.structuredContent.warnings.some((w: string) => /font/i.test(w)), "unterminated: warns");
  });
});

// ---------------------------------------------------------------------------
// Codex final P2: a bounded /Parent walk that runs out must THROW, never answer "not found"
// ---------------------------------------------------------------------------

/** A signature widget on page 1 whose /FT lives on the TOP of a chain of `ancestors` parent dictionaries. */
async function makeDeepSigField(ancestors: number): Promise<Uint8Array> {
  const doc = await PDFDocument.load(await makeSigned("merged", 2), { updateMetadata: false });
  const c = doc.context;
  const widget = c.lookup(doc.getPage(0).node.Annots()!.get(0), PDFDict);
  const sigRef = widget.get(PDFName.of("V"))!;
  widget.delete(PDFName.of("FT"));
  widget.delete(PDFName.of("V"));
  let child = widget;
  for (let i = 0; i < ancestors; i++) {
    const top = i === ancestors - 1;
    const parent = c.register(c.obj({ T: PDFString.of(`p${i}`), ...(top ? { FT: "Sig", V: sigRef } : {}) }));
    child.set(PDFName.of("Parent"), parent);
    child = c.lookup(parent, PDFDict);
  }
  doc.catalog.delete(PDFName.of("AcroForm"));
  return doc.save();
}

test("signature field 62 levels deep is processed and its appearance removed; 65 levels is refused by every writer", async () => {
  const root = tempRoot();
  put(root, "d62.pdf", await makeDeepSigField(62));
  put(root, "d65.pdf", await makeDeepSigField(65));
  assert.ok((await signatureTraces(readFileSync(path.join(root, "d62.pdf")))).some((t) => t.includes("signature appearance stream")), "CONTROL: the appearance is in the input");
  await withEditClient(root, {}, async (call) => {
    for (const w of WRITERS) {
      const ok = await runWriter(call, root, w, "d62.pdf", [1, 2], `deep62-${w}`);
      for (const f of ok.files) assert.deepEqual(await signatureTraces(f), [], `62 levels ${w}: appearance and certificate removed`);
      const args = w === "extract_pages" ? { pdfPath: "d65.pdf", pages: [1], outputPath: "r1.pdf" } : w === "edit_pages" ? { pdfPath: "d65.pdf", pages: [{ source: 1 }], outputPath: "r2.pdf" } : { pdfPath: "d65.pdf", ranges: [[1]], outputDir: ".", prefix: "r3" };
      const r = await call(w, args);
      assert.equal(r.isError, true, `65 levels ${w}`);
      assert.equal(textOf(r), "This PDF could not be processed.", w);
    }
    const m = await call("merge_pdfs", { inputs: ["d65.pdf", "d62.pdf"], outputPath: "r4.pdf" });
    assert.equal(textOf(m), "Input 1: This PDF could not be processed.");
  });
});

// ---------------------------------------------------------------------------
// A stream's own dictionary is never signature material; pdf_info agrees with the writers
// ---------------------------------------------------------------------------

test("a legitimate stream whose own dictionary carries /Contents and /Filter travels intact and raises no signature warning; all writers", async () => {
  const root = tempRoot();
  const pixel = Buffer.from([0x7f]);
  const input = await makeDoc("X", 2, (doc) => {
    const c = doc.context;
    const img = c.register(
      c.flateStream(pixel, { Type: "XObject", Subtype: "Image", Width: 1, Height: 1, ColorSpace: "DeviceGray", BitsPerComponent: 8, Contents: PDFString.of("OMITLY-KEPT-KEY") }),
    );
    doc.getPages()[0].node.set(PDFName.of("Resources"), c.obj({ XObject: { Im1: img } }));
  });
  put(root, "img.pdf", input);
  const imageOf = async (bytes: Uint8Array): Promise<PDFRawStream | undefined> => {
    const doc = await PDFDocument.load(bytes);
    for (const [, o] of doc.context.enumerateIndirectObjects()) {
      if (o instanceof PDFRawStream && o.dict.get(PDFName.of("Subtype")) === PDFName.of("Image")) return o;
    }
    return undefined;
  };
  const control = await imageOf(input);
  assert.ok(control && control.dict.get(PDFName.of("Contents")) && control.dict.get(PDFName.of("Filter")), "CONTROL: the input image has both keys");
  await withEditClient(root, {}, async (call) => {
    for (const w of WRITERS) {
      const { files, result } = await runWriter(call, root, w, "img.pdf", [1], `img-${w}`);
      const img = await imageOf(files[0]);
      assert.ok(img, `${w}: the image travels`);
      assert.deepEqual([...decodePDFRawStream(img!).decode()], [...pixel], `${w}: stream bytes intact`);
      assert.equal((img!.dict.get(PDFName.of("Contents")) as PDFString).decodeText(), "OMITLY-KEPT-KEY", `${w}: its dictionary is intact`);
      assert.ok(img!.dict.get(PDFName.of("Filter")) && img!.dict.get(PDFName.of("Width")), `${w}: Filter and Width kept`);
      assert.ok(!result.structuredContent.warnings.includes(SIGNATURE_WARNING), `${w}: no signature warning`);
    }
    const m = await call("merge_pdfs", { inputs: ["img.pdf", "img.pdf"], outputPath: "img-m.pdf" });
    assert.ok(!m.isError, textOf(m));
    const img = await imageOf(readFileSync(m.structuredContent.outputPath));
    assert.ok(img && img.dict.get(PDFName.of("Contents")), "merge: intact");
    assert.ok(!m.structuredContent.warnings.includes(SIGNATURE_WARNING));
  });
});

test("pdf_info hasSignatures agrees with the writers: a DocTimeStamp-only PDF is reported signed, and extract warns", async () => {
  const root = tempRoot();
  const input = await makeDoc("T", 2, (doc) => {
    const c = doc.context;
    c.register(c.obj({ Type: "DocTimeStamp", Filter: "Adobe.PPKLite", SubFilter: "ETSI.RFC3161", ByteRange: [0, 1, 2, 3], Contents: PDFHexString.fromText("ts-token") }));
  });
  put(root, "ts.pdf", input);
  put(root, "plain.pdf", await makeDoc("P", 2));
  await withEditClient(root, {}, async (call) => {
    assert.equal((await call("pdf_info", { pdfPath: "ts.pdf" })).structuredContent.hasSignatures, true);
    assert.equal((await call("pdf_info", { pdfPath: "plain.pdf" })).structuredContent.hasSignatures, false, "negative control");
    const r = await call("extract_pages", { pdfPath: "ts.pdf", pages: [1], outputPath: "ts-out.pdf" });
    assert.ok(!r.isError, textOf(r));
    assert.ok(r.structuredContent.warnings.includes(SIGNATURE_WARNING));
  });
});

// ---------------------------------------------------------------------------
// omitly#1852: signature-typed STREAMS (body and every key) and field dictionaries dressed as outline
// items or pages. Probed first (print-only) on the unfixed tree; both leaks were real there.
// ---------------------------------------------------------------------------

/** Everything visible in a file as one string: raw bytes, every DECODED stream body, every string and hex string
 *  (fileContainsMarker only matches a stream body as `(marker)` or `<hex>`, so it cannot see a bare body). */
async function everythingIn(bytes: Uint8Array): Promise<string> {
  const parts: string[] = [Buffer.from(bytes).toString("latin1")];
  const doc = await PDFDocument.load(bytes, { ignoreEncryption: true });
  const seen = new Set<PDFObject>();
  const walk = (v: PDFObject | undefined): void => {
    if (v === undefined || seen.has(v)) return;
    seen.add(v);
    if (v instanceof PDFString || v instanceof PDFHexString) parts.push(Buffer.from(v.asBytes()).toString("latin1"), v.decodeText());
    else if (v instanceof PDFArray) v.asArray().forEach(walk);
    else if (v instanceof PDFDict) for (const [, x] of v.entries()) walk(x);
  };
  for (const [, obj] of doc.context.enumerateIndirectObjects()) {
    if (obj instanceof PDFRawStream) {
      parts.push(Buffer.from(decodePDFRawStream(obj).decode()).toString("latin1"));
      walk(obj.dict);
    } else walk(obj);
  }
  return parts.join("\n");
}

test("everythingIn sees a bare stream body (positive control for the #1852 probes)", async () => {
  const input = await makeDoc("Z", 1, (doc) => {
    const c = doc.context;
    doc.getPages()[0].node.set(PDFName.of("OmitlyBlob"), c.register(c.flateStream("BARE-BODY-CTRL-1852", { Type: "XObject", Subtype: "Form", BBox: [0, 0, 1, 1] })));
  });
  assert.ok((await everythingIn(input)).includes("BARE-BODY-CTRL-1852"), "the compressed body is decoded and seen");
  assert.ok(!(await fileContainsMarker(input, "BARE-BODY-CTRL-1852")), "CONTRAST: fileContainsMarker alone cannot see a bare body");
  assert.ok(!(await everythingIn(input)).includes("NOT-IN-THE-FILE-1852"));
});

test("signatures: the BODY and every key of a signature-typed stream (/Sig, /DocTimeStamp, /SV, or /Cert-bearing) are gone; plain streams keep theirs; all writers (#1852)", async () => {
  const root = tempRoot();
  const variants: Record<string, { mk: (c: any) => any; needles: string[]; signature: boolean }> = {
    "Sig stream": { mk: (c) => c.flateStream("BODY-CERTBYTES-MARKER-1852-Sig", { Type: "Sig", Reason: PDFString.of("REASON-1852-Sig"), Contents: PDFHexString.fromText("CONTENTS-1852-Sig") }), needles: ["BODY-CERTBYTES-MARKER-1852-Sig", "REASON-1852-Sig", "CONTENTS-1852-Sig"], signature: true },
    "DocTimeStamp stream": { mk: (c) => c.flateStream("BODY-CERTBYTES-MARKER-1852-DTS", { Type: "DocTimeStamp", Reason: PDFString.of("REASON-1852-DTS") }), needles: ["BODY-CERTBYTES-MARKER-1852-DTS", "REASON-1852-DTS"], signature: true },
    "SV stream": { mk: (c) => c.flateStream("BODY-CERTBYTES-MARKER-1852-SV", { Type: "SV", Reason: PDFString.of("REASON-1852-SV"), Cert: PDFHexString.fromText("CERT-1852-SV") }), needles: ["BODY-CERTBYTES-MARKER-1852-SV", "REASON-1852-SV", "CERT-1852-SV"], signature: true },
    "Cert-only stream": { mk: (c) => c.flateStream("BODY-CERTBYTES-MARKER-1852-Cert", { Cert: PDFHexString.fromText("CERT-1852-CertOnly"), Reason: PDFString.of("REASON-1852-Cert") }), needles: ["BODY-CERTBYTES-MARKER-1852-Cert", "CERT-1852-CertOnly", "REASON-1852-Cert"], signature: true },
    // CONTROLS: streams that are NOT signature material keep their body and keys, including one that merely
    // carries /Contents and /Filter (an image or form XObject may).
    "plain form XObject": { mk: (c) => c.flateStream("PLAIN-BODY-1852-form", { Type: "XObject", Subtype: "Form", BBox: [0, 0, 1, 1] }), needles: ["PLAIN-BODY-1852-form"], signature: false },
    "stream with /Contents and /Filter keys": { mk: (c) => c.stream("PLAIN-BODY-1852-cf", { Contents: PDFString.of("PLAIN-CONTENTS-1852"), SubFilter: "X" }), needles: ["PLAIN-BODY-1852-cf", "PLAIN-CONTENTS-1852"], signature: false },
  };
  for (const [label, v] of Object.entries(variants)) {
    const input = await makeDoc("Z", 2, (doc) => {
      const ref = doc.context.register(v.mk(doc.context));
      for (const p of doc.getPages()) p.node.set(PDFName.of("OmitlyBlob"), ref);
    });
    const name = `h1-${label.replace(/\W/g, "")}.pdf`;
    put(root, name, input);
    const inText = await everythingIn(input);
    for (const n of v.needles) assert.ok(inText.includes(n), `CONTROL (${label}): the input holds ${n}`);
    await withEditClient(root, {}, async (call) => {
      for (const w of WRITERS) {
        const { files, result } = await runWriter(call, root, w, name, [1, 2], `${name}-${w}`);
        const out = (await Promise.all(files.map(everythingIn))).join("\n");
        for (const n of v.needles) assert.equal(out.includes(n), !v.signature, `${label} ${w}: ${n} ${v.signature ? "absent" : "kept"}`);
        assert.ok(out.includes("Z-1"), `${label} ${w}: the page travels`);
        assert.equal(result.structuredContent.warnings.includes(SIGNATURE_WARNING), v.signature, `${label} ${w}: signature warning`);
        const doc = await PDFDocument.load(files[0]);
        const st = doc.context.lookup(doc.getPage(0).node.get(PDFName.of("OmitlyBlob"))!);
        assert.ok(st instanceof PDFRawStream, `${label} ${w}: the stream object itself travels`);
        if (v.signature) {
          assert.equal(decodePDFRawStream(st).decode().length, 0, `${label} ${w}: body emptied`);
          assert.deepEqual([...st.dict.keys()].map((k) => k.asString()), ["/Length"], `${label} ${w}: only /Length remains`);
        }
      }
    });
  }
});

test("fields: a dictionary dressed as an outline item or a page, whose /Parent chain reaches a left-out field, is emptied; genuine ones are not; all writers (#1852)", async () => {
  const root = tempRoot();
  const variants: Record<string, { mk: (c: any, field: PDFRef) => any; needles: string[] }> = {
    "Title+Parent, DA only": { mk: (c, f) => c.obj({ Title: PDFString.of("t"), Parent: f, DA: PDFString.of("/Helv 0 Tf (DA-MARKER-1852) Tj") }), needles: ["DA-MARKER-1852"] },
    "Title+Parent, DA and V": { mk: (c, f) => c.obj({ Title: PDFString.of("t"), Parent: f, DA: PDFString.of("DA-MARKER-1852"), V: PDFString.of("V-MARKER-1852") }), needles: ["DA-MARKER-1852", "V-MARKER-1852"] },
    "Title+Parent, TU, Opt and AP text": {
      mk: (c, f) => c.obj({ Title: PDFString.of("t"), Parent: f, TU: PDFString.of("TU-MARKER-1852"), Opt: [PDFString.of("OPT-MARKER-1852")], AP: { N: c.register(c.flateStream("(AP-MARKER-1852) Tj", { Type: "XObject", Subtype: "Form", BBox: [0, 0, 1, 1] })) } }),
      needles: ["TU-MARKER-1852", "OPT-MARKER-1852", "AP-MARKER-1852"],
    },
    "Type Page+Parent, V": { mk: (c, f) => c.obj({ Type: "Page", Parent: f, V: PDFString.of("V-PAGE-MARKER-1852") }), needles: ["V-PAGE-MARKER-1852"] },
    "Type Page+Parent, DA only": { mk: (c, f) => c.obj({ Type: "Page", Parent: f, DA: PDFString.of("DA-PAGE-MARKER-1852") }), needles: ["DA-PAGE-MARKER-1852"] },
  };
  const FIELD_NEEDLES = ["FIELDVAL-1852", "FIELDDV-1852"];
  for (const [label, v] of Object.entries(variants)) {
    const input = await makeDoc("Y", 2, (doc) => {
      const c = doc.context;
      const [p1, p2] = doc.getPages();
      const field = c.register(c.obj({ FT: "Tx", T: PDFString.of("secret"), V: PDFString.of("FIELDVAL-1852"), DV: PDFString.of("FIELDDV-1852") }));
      const w = c.register(c.obj({ Type: "Annot", Subtype: "Widget", Rect: [1, 1, 50, 20], Parent: field, P: p2.ref }));
      c.lookup(field, PDFDict).set(PDFName.of("Kids"), c.obj([w]));
      p2.node.set(PDFName.of("Annots"), c.obj([w]));
      doc.catalog.set(PDFName.of("AcroForm"), c.obj({ Fields: [field] }));
      p1.node.set(PDFName.of("OmitlyBlob"), c.register(v.mk(c, field)));
    });
    const name = `h2-${label.replace(/\W/g, "")}.pdf`;
    put(root, name, input);
    const inText = await everythingIn(input);
    for (const n of [...FIELD_NEEDLES, ...v.needles]) assert.ok(inText.includes(n), `CONTROL (${label}): the input holds ${n}`);
    await withEditClient(root, {}, async (call) => {
      for (const w of WRITERS) {
        const { files } = await runWriter(call, root, w, name, [1], `${name}-${w}`);
        const out = (await Promise.all(files.map(everythingIn))).join("\n");
        for (const n of [...FIELD_NEEDLES, ...v.needles]) assert.ok(!out.includes(n), `${label} ${w}: ${n} absent`);
        assert.ok(out.includes("Y-1") && !out.includes("Y-2"), `${label} ${w}: page 1 travels, page 2 does not`);
      }
    });
  }
  // CONTROL, same document shape (a form is present): an outline-like dictionary with NO field ancestor keeps
  // its keys, including a /DA, so the exemption itself still works.
  const input = await makeDoc("Y", 2, (doc) => {
    const c = doc.context;
    const [p1, p2] = doc.getPages();
    const field = c.register(c.obj({ FT: "Tx", T: PDFString.of("secret"), V: PDFString.of("FIELDVAL-1852") }));
    const w = c.register(c.obj({ Type: "Annot", Subtype: "Widget", Rect: [1, 1, 50, 20], Parent: field, P: p2.ref }));
    c.lookup(field, PDFDict).set(PDFName.of("Kids"), c.obj([w]));
    p2.node.set(PDFName.of("Annots"), c.obj([w]));
    doc.catalog.set(PDFName.of("AcroForm"), c.obj({ Fields: [field] }));
    const root1 = c.register(c.obj({ Type: "Outlines" }));
    p1.node.set(PDFName.of("OmitlyBlob"), c.register(c.obj({ Title: PDFString.of("GENUINE-TITLE-1852"), Parent: root1, DA: PDFString.of("GENUINE-DA-1852") })));
  });
  put(root, "h2-genuine.pdf", input);
  await withEditClient(root, {}, async (call) => {
    for (const w of WRITERS) {
      const { files } = await runWriter(call, root, w, "h2-genuine.pdf", [1], `h2g-${w}`);
      const out = (await Promise.all(files.map(everythingIn))).join("\n");
      assert.ok(out.includes("GENUINE-TITLE-1852") && out.includes("GENUINE-DA-1852"), `${w}: a title-and-parent dictionary with no field ancestor is untouched`);
      assert.ok(!out.includes("FIELDVAL-1852"), `${w}: the left-out field's value is still gone`);
    }
  });
});

test("a real outline (nested items) and the page tree survive a form-bearing extract unchanged (#1852 regression)", async () => {
  const doc = await PDFDocument.create({ updateMetadata: false });
  const pages = [0, 1, 2].map((i) => {
    const p = doc.addPage([300 + 10 * i, 400]);
    p.node.set(PDFName.of("OmitlyMarker"), PDFString.of(`O-${i + 1}`));
    return p;
  });
  const c = doc.context;
  // A form on page 2 (left out) so the field scrub has real work and a real ancestor chain to walk.
  const field = c.register(c.obj({ FT: "Tx", T: PDFString.of("f"), V: PDFString.of("FIELDVAL-OUTLINE-1852") }));
  const w = c.register(c.obj({ Type: "Annot", Subtype: "Widget", Rect: [1, 1, 50, 20], Parent: field, P: pages[1].ref }));
  c.lookup(field, PDFDict).set(PDFName.of("Kids"), c.obj([w]));
  pages[1].node.set(PDFName.of("Annots"), c.obj([w]));
  doc.catalog.set(PDFName.of("AcroForm"), c.obj({ Fields: [field] }));
  // Outline: root > "Part" (page 1) > "Chapter" (page 3): item-under-item Parent chains, with Title, Dest, Count.
  const outlines = c.register(c.obj({ Type: "Outlines", Count: 2 }));
  const part = c.register(c.obj({ Title: PDFString.of("Part One"), Parent: outlines, Dest: [pages[0].ref, PDFName.of("Fit")], Count: 1 }));
  const chapter = c.register(c.obj({ Title: PDFString.of("Chapter Three"), Parent: part, Dest: [pages[2].ref, PDFName.of("Fit")] }));
  const set = (r: PDFRef, k: string, v: PDFObject) => (c.lookup(r, PDFDict) as PDFDict).set(PDFName.of(k), v);
  set(outlines, "First", part);
  set(outlines, "Last", part);
  set(part, "First", chapter);
  set(part, "Last", chapter);
  doc.catalog.set(PDFName.of("Outlines"), outlines);
  const bytes = await doc.save();

  const out = await PDFDocument.load(await extractPages(bytes, [0, 2], { preserveCatalog: true }));
  assert.equal(out.getPageCount(), 2);
  assert.deepEqual(out.getPages().map((p) => p.node.lookupMaybe(PDFName.of("OmitlyMarker"), PDFString)?.decodeText()), ["O-1", "O-3"]);
  assert.deepEqual(out.getPages().map((p) => Math.round(p.getWidth())), [300, 320]);
  const titles: string[] = [];
  const outRoot = out.catalog.lookup(PDFName.of("Outlines"), PDFDict);
  assert.equal(outRoot.get(PDFName.of("Type")), PDFName.of("Outlines"), "the outline root keeps its /Type");
  const walkItems = (parent: PDFDict): void => {
    for (let ref = parent.get(PDFName.of("First")); ref; ) {
      const item = out.context.lookup(ref, PDFDict);
      titles.push((item.lookup(PDFName.of("Title"), PDFString)).decodeText());
      assert.ok(item.get(PDFName.of("Parent")) !== undefined, "an outline item keeps its /Parent");
      assert.ok(item.get(PDFName.of("Dest")) !== undefined, "an outline item keeps its /Dest");
      walkItems(item);
      ref = item.get(PDFName.of("Next"));
    }
  };
  walkItems(outRoot);
  assert.deepEqual(titles, ["Part One", "Chapter Three"], "both nested outline titles survive");
  const t = await everythingIn(await out.save());
  assert.ok(!t.includes("FIELDVAL-OUTLINE-1852"), "the left-out page's field value is gone");
  // The page tree itself: every page still hangs off a /Pages node that lists it.
  const tree = out.catalog.lookup(PDFName.of("Pages"), PDFDict);
  assert.equal(tree.get(PDFName.of("Type")), PDFName.of("Pages"));
});

// ---------------------------------------------------------------------------
// omitly#1852 follow-up: the exempt-dictionary ancestor walk must reach the whole /Parent chain. A genuine
// outline or page tree deeper than the field walk's 64-level bound must still go through extract/split/edit
// (it did on main), and a dressed-up dictionary 100 levels below a left-out field must still be emptied
// (answering "no field ancestor" at the bound would reopen the leak).
// ---------------------------------------------------------------------------

/** A left-out form field on page 2 (page 1 is kept), the shape every test below needs. */
function addLeftOutField(doc: PDFDocument, valueMarker: string): PDFRef {
  const c = doc.context;
  const [, p2] = doc.getPages();
  const field = c.register(c.obj({ FT: "Tx", T: PDFString.of("secret"), V: PDFString.of(valueMarker) }));
  const w = c.register(c.obj({ Type: "Annot", Subtype: "Widget", Rect: [1, 1, 50, 20], Parent: field, P: p2.ref }));
  c.lookup(field, PDFDict).set(PDFName.of("Kids"), c.obj([w]));
  p2.node.set(PDFName.of("Annots"), c.obj([w]));
  doc.catalog.set(PDFName.of("AcroForm"), c.obj({ Fields: [field] }));
  return field;
}

test("a genuine outline 150 levels deep and a /Pages tree with 120 intermediate nodes still go through all writers (#1852 regression)", async () => {
  const root = tempRoot();
  const OUTLINE_DEPTH = 150;
  const TREE_DEPTH = 120;
  const outlineInput = await makeDoc("D", 2, (doc) => {
    const c = doc.context;
    const [p1] = doc.getPages();
    addLeftOutField(doc, "FIELDVAL-DEEPOUTLINE-1852");
    const outlines = c.register(c.obj({ Type: "Outlines", Count: 1 }));
    let parent: PDFRef = outlines;
    for (let i = 0; i < OUTLINE_DEPTH; i++) {
      parent = c.register(c.obj({ Title: PDFString.of(`DEEP-TITLE-${i}-X`), Parent: parent, Dest: [p1.ref, PDFName.of("Fit")], DA: PDFString.of(`DEEP-DA-${i}-X`) }));
    }
    doc.catalog.set(PDFName.of("Outlines"), outlines);
    p1.node.set(PDFName.of("OmitlyBlob"), parent);
  });
  const treeInput = await makeDoc("T", 2, (doc) => {
    const c = doc.context;
    const [p1, p2] = doc.getPages();
    addLeftOutField(doc, "FIELDVAL-DEEPTREE-1852");
    const top = doc.catalog.get(PDFName.of("Pages")) as PDFRef;
    let parent: PDFRef = top;
    for (let i = 0; i < TREE_DEPTH; i++) {
      const node = c.register(c.obj({ Type: "Pages", Parent: parent, Kids: [], Count: 2 }));
      c.lookup(parent, PDFDict).set(PDFName.of("Kids"), c.obj([node]));
      parent = node;
    }
    c.lookup(parent, PDFDict).set(PDFName.of("Kids"), c.obj([p1.ref, p2.ref]));
    p1.node.set(PDFName.of("Parent"), parent);
    p2.node.set(PDFName.of("Parent"), parent);
  });
  put(root, "deep-outline.pdf", outlineInput);
  put(root, "deep-tree.pdf", treeInput);
  const inA = await everythingIn(outlineInput);
  assert.ok(inA.includes(`DEEP-DA-${OUTLINE_DEPTH - 1}-X`) && inA.includes("FIELDVAL-DEEPOUTLINE-1852"), "CONTROL: the outline input holds the markers");
  assert.ok((await everythingIn(treeInput)).includes("FIELDVAL-DEEPTREE-1852"), "CONTROL: the tree input holds the field value");
  await withEditClient(root, {}, async (call) => {
    for (const w of WRITERS) {
      const a = await runWriter(call, root, w, "deep-outline.pdf", [1], `deepo-${w}`);
      const aOut = (await Promise.all(a.files.map(everythingIn))).join("\n");
      assert.ok(aOut.includes(`DEEP-TITLE-${OUTLINE_DEPTH - 1}-X`) && aOut.includes(`DEEP-DA-${OUTLINE_DEPTH - 1}-X`), `${w}: the deepest genuine outline item is untouched`);
      assert.ok(aOut.includes("DEEP-DA-0-X"), `${w}: the top outline item is untouched`);
      assert.ok(!aOut.includes("FIELDVAL-DEEPOUTLINE-1852"), `${w}: the left-out field's value is gone`);
      const b = await runWriter(call, root, w, "deep-tree.pdf", [1], `deept-${w}`);
      const bOut = (await Promise.all(b.files.map(everythingIn))).join("\n");
      assert.ok(bOut.includes("T-1") && !bOut.includes("T-2"), `${w}: page 1 travels, page 2 does not`);
      assert.ok(!bOut.includes("FIELDVAL-DEEPTREE-1852"), `${w}: the left-out field's value is gone`);
    }
  });
});

test("a dictionary dressed as an outline item 100 levels BELOW a left-out field is still emptied, and a cycle through the field is too (#1852 item 2, past the walk bound)", async () => {
  const root = tempRoot();
  const DEPTH = 100;
  const input = await makeDoc("A", 2, (doc) => {
    const c = doc.context;
    const [p1] = doc.getPages();
    const field = addLeftOutField(doc, "FIELDVAL-ADV-1852");
    // field <- d0 <- d1 <- ... <- d99 (each an "outline item" by Title + Parent, each with a /DA).
    // The DEEPEST item gets the lowest object number, so it is the first one the scrub examines: no shallower
    // item has been answered yet, and a bounded walk could not borrow an earlier answer.
    const refs: PDFRef[] = new Array<PDFRef>(DEPTH);
    for (let i = DEPTH - 1; i >= 0; i--) refs[i] = c.nextRef();
    for (let i = DEPTH - 1; i >= 0; i--) c.assign(refs[i], c.obj({ Title: PDFString.of("t"), Parent: i === 0 ? field : refs[i - 1], DA: PDFString.of(`ADV-DA-${i}-X`) }));
    p1.node.set(PDFName.of("OmitlyBlob"), refs[DEPTH - 1]);
    // A cycle: a dressed dictionary whose parent is the field, and the field's own /Parent points back at it.
    const looped = c.register(c.obj({ Title: PDFString.of("t"), DA: PDFString.of("ADV-LOOP-DA-X") }));
    c.lookup(looped, PDFDict).set(PDFName.of("Parent"), field);
    c.lookup(field, PDFDict).set(PDFName.of("Parent"), looped);
    p1.node.set(PDFName.of("OmitlyLoop"), looped);
    // CONTROL: a dressed chain of the same depth with NO field at the top keeps everything.
    let top: PDFRef = c.register(c.obj({ Type: "Outlines" }));
    for (let i = 0; i < DEPTH; i++) top = c.register(c.obj({ Title: PDFString.of("t"), Parent: top, DA: PDFString.of(`CTRL-DA-${i}-X`) }));
    p1.node.set(PDFName.of("OmitlyControl"), top);
  });
  put(root, "adv.pdf", input);
  const inText = await everythingIn(input);
  for (const n of ["FIELDVAL-ADV-1852", "ADV-DA-0-X", `ADV-DA-${DEPTH - 1}-X`, "ADV-LOOP-DA-X", "CTRL-DA-0-X", `CTRL-DA-${DEPTH - 1}-X`]) assert.ok(inText.includes(n), `CONTROL: the input holds ${n}`);
  await withEditClient(root, {}, async (call) => {
    for (const w of WRITERS) {
      const { files } = await runWriter(call, root, w, "adv.pdf", [1], `adv-${w}`);
      const out = (await Promise.all(files.map(everythingIn))).join("\n");
      for (let i = 0; i < DEPTH; i++) assert.ok(!out.includes(`ADV-DA-${i}-X`), `${w}: ADV-DA-${i} (under the field) is gone`);
      assert.ok(!out.includes("ADV-LOOP-DA-X"), `${w}: the dressed dictionary in a cycle with the field is emptied`);
      assert.ok(!out.includes("FIELDVAL-ADV-1852"), `${w}: the field's value is gone`);
      assert.ok(out.includes("CTRL-DA-0-X") && out.includes(`CTRL-DA-${DEPTH - 1}-X`), `${w}: the control chain with no field ancestor is untouched`);
    }
  });
});

test("an emptied signature PDFContentStream does not keep a primed encoded body (#1852)", async () => {
  const doc = await PDFDocument.create();
  const c = doc.context;
  const stream = PDFContentStream.of(c.obj({ Type: "Sig", Reason: PDFString.of("REASON-CS-1852") }), [PDFOperator.of("Tj" as never, [PDFString.of("BODY-CS-1852")])]);
  c.register(stream);
  // Prime the cache the way a serialiser or a size query does BEFORE the scrub.
  const before = stream.getContents();
  assert.ok(before.length > 0 && stream.getContentsSize() === before.length, "CONTROL: the primed body is non-empty");
  assert.ok(stream.getContentsString().includes("BODY-CS-1852"), "CONTROL: the operators hold the marker");
  assert.equal(emptySignatureDictionaries(doc), true);
  assert.equal(stream.getContents().length, 0, "the cached body is gone");
  assert.equal(stream.getContentsSize(), 0);
  assert.equal(stream.getContentsString(), "");
  assert.deepEqual([...stream.dict.keys()].map((k) => k.asString()), ["/Length"]);
});
