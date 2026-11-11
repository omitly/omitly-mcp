/**
 * omitly#1841 phase B: the writers built on `extractPagesDoc` (design 4.3).
 *
 * `extractPagesTo` serves `extract_pages` and `split_pdf`; `composePages` serves
 * `edit_pages`. Both start from `extractPages`' default-deny preparation (pages
 * not kept are neutered in the private source copy first), never from a fresh
 * document with pages copied in, because that route pulls excluded pages back in
 * through form widgets (the #1004 leak). Signatures are removed in the SOURCE
 * before anything is copied.
 */
import { PDFDocument, PDFName, PDFNumber } from "pdf-lib";
import {
  LAYERS_WARNING,
  SIGNATURE_WARNING,
  clearSigFlags,
  scrubDestinationFields,
  scrubDestinationSignatures,
  sourceFacts,
  stripSignaturesFromSource,
  type LostCode,
  type SourceFacts,
} from "./docFacts.js";
import { extractPagesDoc, openExtractionSession } from "./pageOps.js";
import { EditRefusal } from "./refusals.js";

export type Rotation = 0 | 90 | 180 | 270;
export type BlankSize = "previous" | "A4" | "Letter";

/** `source` is 1-based, numbered against the ORIGINAL document. */
export type ComposeEntry = { source: number; rotate: Rotation } | { blank: true; size: BlankSize };

export interface WriterResult {
  bytes: Uint8Array;
  pageCount: number;
  lost: LostCode[];
  warnings: string[];
}

export interface ComposeResult extends WriterResult {
  layout: { pageNumber: number; from: number | "blank"; rotation: number }[];
}

const A4: [number, number] = [595.28, 841.89];
const LETTER: [number, number] = [612, 792];

function isAscending(xs: readonly number[]): boolean {
  for (let i = 1; i < xs.length; i++) if (xs[i] <= xs[i - 1]) return false;
  return true;
}

/** Shared source inspection: range check, dynamic-XFA refusal, signature removal. */
function makeInspector(zeroBasedPages: readonly number[], onItem: (facts: SourceFacts, signed: boolean) => void) {
  return (src: PDFDocument) => {
    const pageCount = src.getPageCount();
    for (const p of zeroBasedPages) {
      if (p >= pageCount) throw new EditRefusal("page_out_of_range", { item: p + 1, pageCount });
    }
    const facts = sourceFacts(src);
    if (facts.xfa === "dynamic") throw new EditRefusal("xfa");
    // Before anything is copied; see docFacts.stripSignaturesFromSource.
    const signed = stripSignaturesFromSource(src);
    onItem(facts, signed);
  };
}

/** Turn a prepared extraction into the writer's result: lost codes, warnings, the destination
 *  backstop, and the save. Shared by the one-shot and the session path. */
async function finishExtraction(
  doc: PDFDocument,
  zeroBasedPages: readonly number[],
  facts: SourceFacts | undefined,
  signedInSource: boolean,
): Promise<WriterResult> {
  clearSigFlags(doc);
  const lost: LostCode[] = [];
  const warnings: string[] = [];
  let signed = signedInSource;
  if (facts?.pageLabels && !isAscending(zeroBasedPages)) {
    // copyPageLabelsForExtractedPages assumes ascending order.
    doc.catalog.delete(PDFName.of("PageLabels"));
    lost.push("page_labels");
  }
  if (facts?.layers) {
    lost.push("layers");
    warnings.push(LAYERS_WARNING);
  }
  if (facts?.xfa === "static") lost.push("xfa");
  // Backstops: anything the source scrubs missed, just before the bytes are written.
  scrubDestinationFields(doc);
  if (scrubDestinationSignatures(doc)) signed = true;
  if (signed) warnings.push(SIGNATURE_WARNING);
  const out = await doc.save();
  return { bytes: out, pageCount: doc.getPageCount(), lost, warnings };
}

/** `extract_pages`: keep these pages (0-based), in this order. */
export async function extractPagesTo(bytes: Uint8Array, zeroBasedPages: number[]): Promise<WriterResult> {
  let facts: SourceFacts | undefined;
  let signed = false;
  const doc = await extractPagesDoc(bytes, zeroBasedPages, {
    preserveCatalog: true,
    inspectSource: makeInspector(zeroBasedPages, (f, s) => {
      facts = f;
      signed = s;
    }),
  });
  return finishExtraction(doc, zeroBasedPages, facts, signed);
}

/** `split_pdf`: parse the input ONCE, then one default-deny extraction per range (the same code as
 *  `extractPagesTo`, with its source mutations undone between ranges; see openExtractionSession). */
export async function openRangeExtractor(
  bytes: Uint8Array,
): Promise<{ extract(zeroBasedPages: number[]): Promise<WriterResult> }> {
  let facts: SourceFacts | undefined;
  let signed = false;
  // Facts and the signature scrub of the SOURCE are properties of the document, not of a range:
  // done once, here, before any copy. The page-range check is per range, below.
  const session = await openExtractionSession(bytes, {
    inspectSource: makeInspector([], (f, s) => {
      facts = f;
      signed = s;
    }),
  });
  return {
    async extract(zeroBasedPages) {
      for (const p of zeroBasedPages) {
        if (p >= session.pageCount) throw new EditRefusal("page_out_of_range", { item: p + 1, pageCount: session.pageCount });
      }
      const doc = await session.extract(zeroBasedPages, { preserveCatalog: true });
      return finishExtraction(doc, zeroBasedPages, facts, signed);
    },
  };
}

/** `edit_pages`: the final page list. */
export async function composePages(bytes: Uint8Array, layout: readonly ComposeEntry[]): Promise<ComposeResult> {
  const sources: number[] = [];
  const seen = new Set<number>();
  let hasBlank = false;
  for (const e of layout) {
    if ("blank" in e) {
      hasBlank = true;
      continue;
    }
    if (seen.has(e.source)) throw new EditRefusal("duplicate_page", { item: e.source });
    seen.add(e.source);
    sources.push(e.source - 1);
  }
  if (sources.length === 0) throw new EditRefusal("no_source_pages");

  let facts: SourceFacts | undefined;
  let signed = false;
  const doc = await extractPagesDoc(bytes, sources, {
    preserveCatalog: true,
    inspectSource: makeInspector(sources, (f, s) => {
      facts = f;
      signed = s;
    }),
  });
  clearSigFlags(doc);

  const extracted = doc.getPages(); // in `sources` order, which is list order
  const echo: ComposeResult["layout"] = [];
  let next = 0;
  let out = 0;
  for (const e of layout) {
    if ("blank" in e) {
      const prev = out > 0 ? doc.getPage(out - 1).getSize() : undefined;
      const [w, h] =
        e.size === "Letter" ? LETTER : e.size === "A4" ? A4 : prev ? [prev.width, prev.height] : A4;
      doc.insertPage(out, [w, h]);
      echo.push({ pageNumber: out + 1, from: "blank", rotation: 0 });
    } else {
      const page = extracted[next++];
      const existing = page.node.Rotate()?.asNumber() ?? 0;
      // Written directly: pdf-lib's setRotation throws on any non-multiple of 90,
      // and some real files carry one.
      const angle = (((existing + e.rotate) % 360) + 360) % 360;
      if (e.rotate !== 0) page.node.set(PDFName.of("Rotate"), PDFNumber.of(angle));
      echo.push({ pageNumber: out + 1, from: e.source, rotation: angle });
    }
    out++;
  }

  const lost: LostCode[] = [];
  const warnings: string[] = [];
  const reordered = !isAscending(sources);
  if (facts?.pageLabels && (reordered || hasBlank)) {
    // Their numbering would now be wrong.
    doc.catalog.delete(PDFName.of("PageLabels"));
    lost.push("page_labels");
  }
  if (facts?.layers) {
    lost.push("layers");
    warnings.push(LAYERS_WARNING);
  }
  if (facts?.xfa === "static") lost.push("xfa");
  scrubDestinationFields(doc);
  if (scrubDestinationSignatures(doc)) signed = true;
  if (signed) warnings.push(SIGNATURE_WARNING);
  const saved = await doc.save();
  return { bytes: saved, pageCount: doc.getPageCount(), lost, warnings, layout: echo };
}
