/**
 * omitly#1841 phase B: `merge_pdfs` (design 4.3).
 *
 * Starts from a fresh document; for each input: load it once, copy ALL its pages
 * with one copier, merge its form with `mergeAcroFormOnAppend`, drop it, and move
 * on; save once. Every page of every input is kept, so nothing is excluded and the
 * #1004 path does not arise, and the cost is linear in the inputs (unlike calling
 * `appendPdf` repeatedly, which reloads the growing result each time). Signatures
 * are removed in each SOURCE before its pages are copied.
 */
import { PDFDocument, PDFObjectCopier, PDFPage, PDFPageLeaf } from "pdf-lib";
import {
  LAYERS_WARNING,
  RENAME_WARNING,
  FONT_RENAME_WARNING,
  SIGNATURE_WARNING,
  clearSigFlags,
  isEncryptedError,
  scrubDestinationSignatures,
  sourceFacts,
  stripSignaturesFromSource,
  type LostCode,
} from "./docFacts.js";
import { mergeAcroFormOnAppend } from "./pageOps.js";
import { EditRefusal } from "./refusals.js";

export interface MergeResult {
  bytes: Uint8Array;
  pageCount: number;
  /** Page count of each input, in order. */
  pageCounts: number[];
  lost: LostCode[];
  warnings: string[];
}

export async function mergePdfs(count: number, getBytes: (index: number) => Uint8Array): Promise<MergeResult> {
  const dst = await PDFDocument.create({ updateMetadata: false });
  const lost = new Set<LostCode>();
  const warnings = new Set<string>();
  const pageCounts: number[] = [];
  let renamed = 0;

  for (let i = 0; i < count; i++) {
    const inputIndex = i + 1;
    try {
      const src = await PDFDocument.load(getBytes(i).slice(), { updateMetadata: false });
      const facts = sourceFacts(src);
      if (facts.xfa === "dynamic") throw new EditRefusal("xfa");
      if (stripSignaturesFromSource(src)) warnings.add(SIGNATURE_WARNING);
      await src.flush();
      const copier = PDFObjectCopier.for(src.context, dst.context);
      const copied: PDFPage[] = [];
      for (const srcPage of src.getPages()) {
        // By ref, so a widget's /P back-reference lands on this same copy (#884).
        const ref = copier.copy(srcPage.ref);
        const node = dst.context.lookup(ref);
        if (!(node instanceof PDFPageLeaf)) throw new Error("page did not copy");
        copied.push(PDFPage.of(node, ref, dst));
      }
      copied.forEach((p) => dst.addPage(p));
      const merged = mergeAcroFormOnAppend(src, dst, copier);
      renamed += merged.renamed;
      if (merged.fontRenameFailed > 0) warnings.add(FONT_RENAME_WARNING);
      pageCounts.push(copied.length);
      // The result starts from an empty catalog, so each of these is dropped.
      if (facts.outlines) lost.add("outlines");
      if (facts.info) lost.add("info");
      if (facts.pageLabels) lost.add("page_labels");
      if (facts.xfa === "static") lost.add("xfa");
      if (facts.layers) {
        lost.add("layers");
        warnings.add(LAYERS_WARNING);
      }
    } catch (e) {
      if (e instanceof EditRefusal) throw new EditRefusal(e.code, { ...e.detail, inputIndex });
      if (isEncryptedError(e)) throw new EditRefusal("encrypted", { inputIndex });
      throw new EditRefusal("failed", { inputIndex });
    }
  }
  clearSigFlags(dst);
  // Backstop: anything the source scrub missed, just before the bytes are written.
  if (scrubDestinationSignatures(dst)) warnings.add(SIGNATURE_WARNING);
  if (renamed > 0) warnings.add(RENAME_WARNING);
  const bytes = await dst.save();
  return { bytes, pageCount: dst.getPageCount(), pageCounts, lost: [...lost], warnings: [...warnings] };
}
