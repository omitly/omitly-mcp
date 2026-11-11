/**
 * omitly#1841 phase B: `pdf_info` (design 4.1). Counts and flags only; never
 * text, field values or metadata. Loads with `ignoreEncryption: true`, so it
 * answers for an encrypted file (reporting `encrypted: true`); any fact it
 * cannot read is `null`.
 */
import { PDFDocument } from "pdf-lib";
import {
  formFieldCount,
  hasComments,
  hasLayers,
  hasSignatureField,
  xfaKind,
  type XfaKind,
} from "./docFacts.js";

export const INFO_PAGE_LIMIT = 500;

export interface PageInfo {
  pageNumber: number;
  widthPt: number | null;
  heightPt: number | null;
  rotation: number | null;
}

export interface PdfInfo {
  pageCount: number;
  pages: PageInfo[];
  pagesTruncated: boolean;
  encrypted: boolean | null;
  hasForm: boolean | null;
  formFieldCount: number | null;
  hasSignatures: boolean | null;
  hasComments: boolean | null;
  hasXfa: XfaKind | null;
  hasLayers: boolean | null;
  byteSize: number;
}

function attempt<T>(fn: () => T): T | null {
  try {
    return fn();
  } catch {
    return null;
  }
}

const finite = (n: number): number | null => (Number.isFinite(n) ? Math.round(n * 100) / 100 : null);

export async function pdfInfo(bytes: Uint8Array): Promise<PdfInfo> {
  const doc = await PDFDocument.load(bytes.slice(), { ignoreEncryption: true, updateMetadata: false });
  const pages = doc.getPages();
  const shown: PageInfo[] = [];
  for (let i = 0; i < Math.min(pages.length, INFO_PAGE_LIMIT); i++) {
    const page = pages[i];
    const mb = attempt(() => page.node.MediaBox()?.asRectangle());
    const rot = attempt(() => page.node.Rotate()?.asNumber() ?? 0);
    shown.push({
      pageNumber: i + 1,
      widthPt: mb ? finite(Math.abs(mb.width)) : null,
      heightPt: mb ? finite(Math.abs(mb.height)) : null,
      // Normalised to 0/90/180/270; the raw value if it is not a multiple of 90.
      rotation: rot === null || !Number.isFinite(rot) ? null : rot % 90 === 0 ? ((rot % 360) + 360) % 360 : rot,
    });
  }
  const fields = attempt(() => formFieldCount(doc));
  return {
    pageCount: pages.length,
    pages: shown,
    pagesTruncated: pages.length > INFO_PAGE_LIMIT,
    encrypted: attempt(() => doc.isEncrypted),
    hasForm: fields === null ? null : fields > 0,
    formFieldCount: fields,
    hasSignatures: attempt(() => hasSignatureField(doc)),
    hasComments: attempt(() => hasComments(doc)),
    hasXfa: attempt(() => xfaKind(doc)),
    hasLayers: attempt(() => hasLayers(doc)),
    byteSize: bytes.length,
  };
}
