/**
 * omitly#1841 phase B: facts about a loaded document and the signature removal
 * the four writers share. pdf-lib only; no I/O, no network.
 *
 * Every function tolerates hostile structure: loops are guarded by visited sets
 * and depth caps, and a value of the wrong type is skipped rather than thrown.
 */
import { EncryptedPDFError, PDFArray, PDFBool, PDFContentStream, PDFDict, PDFDocument, PDFName, PDFNumber, PDFPageLeaf, PDFPageTree, PDFRawStream, PDFRef, PDFStream, PDFString, type PDFObject, type PDFPage } from "pdf-lib";

const MAX_FIELD_NODES = 200_000;
const MAX_PARENT_DEPTH = 64;
/** Deeper than this a document is REFUSED (`failed`), never passed through unscanned. */
const MAX_SIG_WALK_DEPTH = 64;

/** pdf-lib's EncryptedPDFError is compiled to ES5, so `instanceof` is false for the
 *  error it actually throws (measured: constructor.name === "Error"). Match the class
 *  AND the message `PDFDocument.load` gives ("... is encrypted."). */
export function isEncryptedError(e: unknown): boolean {
  return e instanceof EncryptedPDFError || (e instanceof Error && /\bis encrypted\b/i.test(e.message));
}

const N = (s: string) => PDFName.of(s);

export type LostCode = "outlines" | "info" | "page_labels" | "xfa" | "layers";
export type XfaKind = "none" | "static" | "dynamic";

/** `lookupMaybe` THROWS when the value is the wrong type (a field's /V is a string, not a
 *  dictionary), which would fail a perfectly valid document. These return undefined instead. */
function lookupAs<T>(doc: PDFDocument, v: PDFObject | undefined, cls: { prototype: T }): T | undefined {
  if (v === undefined) return undefined;
  const o = doc.context.lookup(v);
  return o instanceof (cls as unknown as new () => T) ? o : undefined;
}

function dictOf(doc: PDFDocument, v: PDFObject | undefined): PDFDict | undefined {
  return lookupAs(doc, v, PDFDict);
}

/** The value of `key` on `dict` with an indirect reference resolved: `/Type 5 0 R` where object 5
 *  is the name `/Sig` is a signature dictionary all the same. Raw `get()` would miss it. */
function val(doc: PDFDocument, dict: PDFDict, key: string): PDFObject | undefined {
  const v = dict.get(N(key));
  return v === undefined ? undefined : doc.context.lookup(v);
}

function acroFormOf(doc: PDFDocument): PDFDict | undefined {
  return dictOf(doc, doc.catalog.get(N("AcroForm")));
}

/** Visit `dict` and then each ancestor reached by `/Parent` (a cycle ends the walk). The walk is
 *  bounded, and going over the bound THROWS (the worker maps it to `failed`): returning "not found"
 *  would let a signature field 65 levels down keep its appearance and certificate. `visit` returns
 *  true to stop early. */
export function walkParents(doc: PDFDocument, dict: PDFDict, visit: (d: PDFDict) => boolean | void): void {
  let cur: PDFDict | undefined = dict;
  const seen = new Set<PDFDict>();
  for (let depth = 0; cur; depth++) {
    if (depth > MAX_PARENT_DEPTH) throw new Error("field hierarchy too deep to inspect");
    if (seen.has(cur)) return;
    seen.add(cur);
    if (visit(cur) === true) return;
    cur = dictOf(doc, cur.get(N("Parent")));
  }
}

/** The first value of `key` found on `dict` or an ancestor reached by `/Parent`. */
function inherited(doc: PDFDocument, dict: PDFDict, key: PDFName): PDFObject | undefined {
  let found: PDFObject | undefined;
  walkParents(doc, dict, (cur) => {
    const v = cur.get(key);
    if (v === undefined) return false;
    found = doc.context.lookup(v);
    return true;
  });
  return found;
}

function isSigField(doc: PDFDocument, dict: PDFDict): boolean {
  if (inherited(doc, dict, N("FT")) === N("Sig")) return true;
  // A signature value filed under a field that does not say it is one.
  const v = dictOf(doc, dict.get(N("V")));
  return v !== undefined && (val(doc, v, "Type") === N("Sig") || v.get(N("ByteRange")) !== undefined);
}

/** Visit every node of the AcroForm field tree once. */
function walkFieldTree(doc: PDFDocument, visit: (dict: PDFDict, terminal: boolean) => void): void {
  const fields = lookupAs(doc, acroFormOf(doc)?.get(N("Fields")), PDFArray);
  if (!fields) return;
  const seen = new Set<PDFObject>();
  let budget = MAX_FIELD_NODES;
  const stack: PDFObject[] = [];
  for (let i = 0; i < fields.size(); i++) stack.push(fields.get(i));
  while (stack.length > 0 && budget > 0) {
    const ref = stack.pop()!;
    const dict = dictOf(doc, ref);
    if (!dict || seen.has(dict)) continue;
    seen.add(dict);
    budget--;
    const kids = lookupAs(doc, dict.get(N("Kids")), PDFArray);
    let hasFieldKid = false;
    if (kids) {
      for (let i = 0; i < kids.size(); i++) {
        const kid = dictOf(doc, kids.get(i));
        // A kid with a partial name is a child FIELD; one without is a widget
        // of this field (visited by the callers that need widgets).
        if (kid?.get(N("T")) !== undefined) {
          hasFieldKid = true;
          stack.push(kids.get(i));
        }
      }
    }
    visit(dict, !hasFieldKid);
  }
}

/** Every widget annotation on every page, once. */
function forEachPageAnnot(doc: PDFDocument, visit: (annot: PDFDict) => void): void {
  const seen = new Set<PDFDict>();
  for (const page of doc.getPages()) {
    const annots = page.node.Annots();
    if (!annots) continue;
    for (let i = 0; i < annots.size(); i++) {
      const a = dictOf(doc, annots.get(i));
      if (!a || seen.has(a)) continue;
      seen.add(a);
      visit(a);
    }
  }
}

/** Terminal fields: field nodes with no child field. */
export function formFieldCount(doc: PDFDocument): number {
  let n = 0;
  walkFieldTree(doc, (_dict, terminal) => {
    if (terminal) n++;
  });
  return n;
}

export function hasSignatureField(doc: PDFDocument): boolean {
  let found = false;
  walkFieldTree(doc, (dict) => {
    if (inherited(doc, dict, N("FT")) === N("Sig")) found = true;
  });
  // The same detection the writers use: a signature dictionary anywhere counts too (a /DocTimeStamp,
  // a value no field points at), so pdf_info and the writers' warning agree.
  return found || findSignatureDictionaries(doc).length > 0;
}

/** Any annotation whose subtype is not Widget, Link or Popup. */
export function hasComments(doc: PDFDocument): boolean {
  let found = false;
  forEachPageAnnot(doc, (a) => {
    const st = val(doc, a, "Subtype");
    if (st !== N("Widget") && st !== N("Link") && st !== N("Popup")) found = true;
  });
  return found;
}

export function xfaKind(doc: PDFDocument): XfaKind {
  const acro = acroFormOf(doc);
  if (!acro || acro.get(N("XFA")) === undefined) return "none";
  const needs = (d: PDFDict | undefined) => lookupAs(doc, d?.get(N("NeedsRendering")), PDFBool)?.asBoolean() === true;
  return needs(doc.catalog) || needs(acro) ? "dynamic" : "static";
}

export function hasLayers(doc: PDFDocument): boolean {
  return doc.catalog.get(N("OCProperties")) !== undefined;
}

export interface SourceFacts {
  outlines: boolean;
  info: boolean;
  pageLabels: boolean;
  layers: boolean;
  xfa: XfaKind;
}

export function sourceFacts(doc: PDFDocument): SourceFacts {
  return {
    outlines: doc.catalog.get(N("Outlines")) !== undefined,
    info: doc.context.trailerInfo.Info !== undefined,
    pageLabels: doc.catalog.get(N("PageLabels")) !== undefined,
    layers: hasLayers(doc),
    xfa: xfaKind(doc),
  };
}

function clearOne(doc: PDFDocument, dict: PDFDict): boolean {
  let removed = false;
  // /V lives on the field; with a widget kid the field is an ancestor.
  walkParents(doc, dict, (cur) => {
    if (cur.get(N("V")) !== undefined) {
      cur.delete(N("V"));
      removed = true;
    }
    // Seed value (names a signer certificate) and lock dictionary: not part of the output.
    if (cur.get(N("SV")) !== undefined) cur.delete(N("SV"));
    if (cur.get(N("Lock")) !== undefined) cur.delete(N("Lock"));
  });
  // The appearance draws the visible signature: the field itself when it is a
  // merged field/widget, and every widget kid (a kid without a partial name).
  if (dict.get(N("AP")) !== undefined) dict.delete(N("AP"));
  const kids = lookupAs(doc, dict.get(N("Kids")), PDFArray);
  if (kids) {
    for (let i = 0; i < kids.size(); i++) {
      const kid = dictOf(doc, kids.get(i));
      if (kid && kid.get(N("T")) === undefined && kid.get(N("AP")) !== undefined) kid.delete(N("AP"));
    }
  }
  return removed;
}

/** Signature material by what it IS, wherever it hangs: `/Type /Sig`, `/Type /DocTimeStamp`,
 *  `/Type /SV` (seed value), any dictionary holding a `/Cert`, or `/Contents` together with one of
 *  `/ByteRange`, `/Filter`, `/SubFilter`. `/Type` is resolved if it is an indirect reference. */
function isSignatureDictionary(doc: PDFDocument, d: PDFDict): boolean {
  const type = val(doc, d, "Type");
  if (type === N("Sig") || type === N("DocTimeStamp") || type === N("SV")) return true;
  // A seed value (/SV) names the certificate a signer must use, and a /Cert-bearing
  // dictionary is certificate material whatever it is called.
  if (d.get(N("Cert")) !== undefined) return true;
  if (d.get(N("Contents")) === undefined) return false;
  // /Contents with a signature-shaped sibling. (A page or annotation has /Contents but none of these.)
  return ["ByteRange", "Filter", "SubFilter", "Cert"].some((k) => d.get(N(k)) !== undefined);
}

/**
 * Defence in depth, independent of route: empty EVERY signature dictionary in the source.
 * Deleting a field's `/V` only cuts one route to the dictionary; an outline item, a page
 * key, a non-widget annotation or any other copied object that also references it would
 * carry the dictionary, with its `/Contents` (the signer's certificate), into the output
 * through the copier. So each such dictionary loses every key (`/Contents`, `/Cert`,
 * `/ByteRange`, `/Reference`, `/Changes`, `/Name`, `/Location`, `/Reason`, `/ContactInfo`,
 * `/M`, `/Prop_Build`, `/SubFilter`, `/Filter`, and anything else). Orphans included.
 * Also reaches signature dictionaries held DIRECTLY inside other objects (nested dicts and
 * arrays, to depth 64; deeper is refused as `failed`, not skipped) and in a direct trailer
 * `/Info`. Returns true if any dictionary was emptied.
 */
export function emptySignatureDictionaries(src: PDFDocument): boolean {
  const found = findSignatureMaterial(src);
  for (const { dict, stream } of found) {
    // A value held as an INDIRECT object (`/Contents 10 0 R`) is overwritten too: emptying the
    // dictionary alone would leave that object, and anything else that points at it, carrying
    // the certificate. (Done once per source, so there is nothing to journal.)
    const seen = new Set<PDFRef>();
    const blank = (v: PDFObject | undefined, empty: () => PDFObject, depth: number): void => {
      if (v === undefined) return;
      if (depth > MAX_SIG_WALK_DEPTH) throw new Error("signature value nesting too deep to inspect");
      if (v instanceof PDFRef) {
        if (seen.has(v)) return;
        seen.add(v);
        // What an indirect array or dictionary points at is blanked too (`/Cert 10 0 R` -> `[11 0 R]`).
        blank(src.context.lookup(v), () => PDFString.of(""), depth + 1);
        src.context.assign(v, empty());
      } else if (v instanceof PDFArray) {
        v.asArray().forEach((e) => blank(e, () => PDFString.of(""), depth + 1));
      } else if (v instanceof PDFStream) {
        for (const [, e] of v.dict.entries()) blank(e, () => PDFString.of(""), depth + 1);
      } else if (v instanceof PDFDict) {
        for (const [, e] of v.entries()) blank(e, () => PDFString.of(""), depth + 1);
      }
    };
    blank(dict.get(N("Contents")), () => PDFString.of(""), 0);
    blank(dict.get(N("Cert")), () => PDFString.of(""), 0);
    blank(dict.get(N("ByteRange")), () => PDFArray.withContext(src.context), 0);
    for (const [key] of [...dict.entries()]) dict.delete(key);
    // A signature STREAM's BODY is signature material too (certificate or timestamp bytes): empty it, and
    // leave the stream well-formed with no filter to decode an empty body with (omitly#1852).
    if (stream) {
      if (stream instanceof PDFRawStream) (stream as { contents: Uint8Array }).contents = new Uint8Array(0);
      else if (stream instanceof PDFContentStream) {
        // pdf-lib builds a content stream's bytes from `operators` on first use and CACHES them: emptying the
        // operators alone leaves a body that was read earlier (getContents / getContentsSize) to be written out.
        // The dictionary lost its /Filter above, so the empty body must not be deflated either (omitly#1852).
        const cs = stream as unknown as { operators: unknown[]; encode: boolean; contentsCache: { invalidate(): void } };
        cs.operators = [];
        cs.encode = false;
        cs.contentsCache.invalidate();
      }
      dict.set(N("Length"), PDFNumber.of(0));
    }
  }
  return found.length > 0;
}

/**
 * Every signature dictionary in `doc`, wherever it hangs: in an indirect object or held DIRECTLY
 * inside another (nested dicts and arrays, to depth 64; deeper THROWS), including a direct trailer
 * `/Info`. A stream's OWN dictionary is one only when it says `/Type /Sig`, `/DocTimeStamp` or `/SV`,
 * or carries a `/Cert` (an XObject that merely carries `/Contents` and `/Filter` must not be emptied); direct
 * dictionaries nested inside a stream's dictionary are always searched. Read-only.
 */
export function findSignatureDictionaries(doc: PDFDocument): PDFDict[] {
  return findSignatureMaterial(doc).map((m) => m.dict);
}

/** As above, saying for each hit whether it is a STREAM's own dictionary. */
function findSignatureMaterial(doc: PDFDocument): { dict: PDFDict; stream?: PDFStream }[] {
  const found: { dict: PDFDict; stream?: PDFStream }[] = [];
  // Walk into DIRECT values only (a PDFRef is covered by the enumeration itself).
  const walk = (v: PDFObject | undefined, depth: number): void => {
    if (v === undefined) return;
    if (depth > MAX_SIG_WALK_DEPTH) throw new Error("object nesting too deep to inspect for signatures");
    if (v instanceof PDFStream) {
      // A stream is exempt (an image XObject may carry /Contents and /Filter) UNLESS its own dictionary
      // says it is a signature: /Type /Sig, /DocTimeStamp or /SV (seed value), or a /Cert (certificate
      // material whatever it is called). /Contents with /Filter is NOT enough here, unlike a plain dictionary.
      const type = val(doc, v.dict, "Type");
      if (type === N("Sig") || type === N("DocTimeStamp") || type === N("SV") || v.dict.get(N("Cert")) !== undefined) {
        found.push({ dict: v.dict, stream: v });
      }
      for (const [, child] of v.dict.entries()) walk(child, depth + 1);
    } else if (v instanceof PDFDict) {
      if (isSignatureDictionary(doc, v)) {
        found.push({ dict: v });
        return;
      }
      for (const [, child] of v.entries()) walk(child, depth + 1);
    } else if (v instanceof PDFArray) {
      for (const child of v.asArray()) walk(child, depth + 1);
    }
  };
  for (const [, obj] of doc.context.enumerateIndirectObjects()) walk(obj, 0);
  // The trailer's /Info is copied by preserveCatalog; a direct dictionary there is not an indirect object.
  walk(doc.context.trailerInfo.Info, 0);
  return found;
}

/**
 * Remove every digital signature from the SOURCE document, before anything is
 * copied (design 4.3): for every signature field (`/FT /Sig`, resolved through
 * `/Parent` inheritance) delete its `/V` (the PKCS#7 blob, which contains the
 * signer's certificate) and delete `/AP` from its widgets. Covers the AcroForm
 * field tree and every page's widget annotations, so a widget the tree does not
 * list is still cleaned. Returns true if any signature VALUE was removed.
 */
export function stripSignaturesFromSource(src: PDFDocument): boolean {
  let removedValue = false;
  walkFieldTree(src, (dict) => {
    if (isSigField(src, dict) && clearOne(src, dict)) removedValue = true;
  });
  forEachPageAnnot(src, (a) => {
    if (val(src, a, "Subtype") !== N("Widget") || !isSigField(src, a)) return;
    if (clearOne(src, a)) removedValue = true;
  });
  // Last, so the field passes above can still recognise a field by the dictionary it holds.
  if (emptySignatureDictionaries(src)) removedValue = true;
  return removedValue;
}

/** Clear `/SigFlags` on the destination so a viewer does not announce a signed document. */
export function clearSigFlags(dst: PDFDocument): void {
  const acro = acroFormOf(dst);
  if (acro?.get(N("SigFlags")) !== undefined) acro.delete(N("SigFlags"));
}

// ---------------------------------------------------------------------------
// Fields outside the kept pages: found by ENUMERATION, never by following a route
// ---------------------------------------------------------------------------

/** What the field scrub records before it changes anything (pageOps' `Journal` fits). */
export interface MutationJournal {
  dict(d: PDFDict): void;
  array(a: PDFArray): void;
}

/** Evidence of a field VALUE (as opposed to a name that merely appears in many dictionaries). */
const FIELD_VALUE_KEYS = ["FT", "V", "DV", "RV"].map(N);

/** /Type values of dictionaries that are never fields, however many `/T` or `/Parent` they carry. */
const NON_FIELD_TYPES = ["Action", "Bead", "Thread", "Filespec", "EmbeddedFile", "Font", "FontDescriptor", "ExtGState", "Pattern", "Shading", "XObject", "OCG", "OCMD", "StructElem", "StructTreeRoot"].map(N);

/**
 * Dictionaries whose `/T` (or `/Parent`) names something else: an ACTION (`/S`: Hide, Movie, Rendition,
 * SubmitForm, ResetForm, GoTo, Named, JavaScript...; its `/T` and `/Fields` name targets and hold no
 * field value), a bead or thread, a file specification, a font, a graphics-state, pattern, shading,
 * XObject or optional-content dictionary, and an annotation that is not a widget. These are field
 * material only through `/FT` or `/Subtype /Widget`: never through `/T`, `/Parent` or a value key
 * (`/V` is a file spec's volatile flag and an article bead's previous-bead link).
 * They are still searched INSIDE (a ResetForm `/Fields` array may hold a direct field dictionary).
 */
function isNonFieldKind(doc: PDFDocument, d: PDFDict): boolean {
  if (d.get(N("S")) !== undefined) return true;
  const type = val(doc, d, "Type");
  if (type !== undefined && NON_FIELD_TYPES.includes(type as PDFName)) return true;
  return type === N("Annot") && val(doc, d, "Subtype") !== N("Widget");
}

const VALUE_KEYS = ["V", "DV", "RV"].map(N);
const FIELD_LINK_KEYS = ["Parent", "T", "Kids"].map(N);

/**
 * A dictionary's OWN evidence that it is a form field: (a) `/Subtype /Widget`, or (b) `/FT`, or
 * (c) a value key (`/V`, `/DV`, `/RV`) together with a field link (`/Parent`, `/T`, `/Kids`).
 * `/T`, `/TM`, `/TU`, `/Opt` and `/MaxLen` ALONE are never evidence: they are used outside forms
 * (a rectilinear `/Measure` has a `/T` array of angle formats, a 3D animation style has `/TM`).
 */
function ownFieldEvidence(doc: PDFDocument, d: PDFDict): boolean {
  if (val(doc, d, "Subtype") === N("Widget") || d.get(N("FT")) !== undefined) return true;
  // `/V` means other things outside forms (a file spec's volatile flag, an article bead's previous bead).
  if (isNonFieldKind(doc, d)) return false;
  return VALUE_KEYS.some((k) => d.get(k) !== undefined) && FIELD_LINK_KEYS.some((k) => d.get(k) !== undefined);
}

/**
 * Does any `/Parent` ancestor of the EXEMPT dictionary `d` (a page node or outline item) have field evidence of
 * its own? Unlike `walkParents` this walks the WHOLE chain and never throws on depth: a genuine outline or page
 * tree can be hundreds of levels deep and must not fail a writer, and answering "no field ancestor" at a cap
 * would let a dressed-up dictionary below a deep field keep its /DA, /TU, /Opt and /AP (omitly#1852). It ends at
 * a genuine root (no /Parent), at a cycle (nothing new to find), or at an already-answered ancestor. `memo` holds,
 * per dictionary, "it or an ancestor has field evidence", so every node of a chain is walked once per scrub, however
 * many dictionaries hang below it. An exempt dictionary has no field evidence of its own (no /Widget, /FT or value
 * key), so its answer is exactly its parent's, and it is memoised too.
 */
function hasFieldAncestor(doc: PDFDocument, d: PDFDict, memo: Map<PDFDict, boolean>): boolean {
  const path: PDFDict[] = [d];
  const onPath = new Set<PDFDict>(path);
  let result = false;
  for (let cur = dictOf(doc, d.get(N("Parent"))); cur; cur = dictOf(doc, cur.get(N("Parent")))) {
    const known = memo.get(cur);
    if (known !== undefined) {
      result = known;
      break;
    }
    if (onPath.has(cur)) break; // a cycle: everything on it was already looked at
    onPath.add(cur);
    path.push(cur);
    if (ownFieldEvidence(doc, cur)) {
      result = true;
      break;
    }
  }
  // Every dictionary on the path inherits the answer: none of the ones above the stopping point had evidence
  // (or the walk would have stopped there), and `d` has none by construction.
  for (const node of path) memo.set(node, result);
  return result;
}

/**
 * "Field material": a dictionary that is, or is part of, a form field. It is one if it has field
 * evidence of its own (above), OR any `/Parent` ancestor does: a field with no `/T` and an inherited
 * `/FT` is still a field, and that ancestor link alone is enough. Page-tree nodes, outline items
 * and signature dictionaries are not (signatures have their own scrub); an outline item (`/Title`
 * with a `/Parent`) is exempt only while it has no widget subtype, no `/FT` and no value key. The
 * ancestor walk is bounded and THROWS past the bound; the exempt kinds' walk (hasFieldAncestor) is not bounded.
 */
function isFieldMaterial(doc: PDFDocument, d: PDFDict, ancestorMemo: Map<PDFDict, boolean>): boolean {
  const type = val(doc, d, "Type");
  const hasValue = FIELD_VALUE_KEYS.some((k) => d.get(k) !== undefined);
  // A page-tree node (by class or /Type; pdf-lib's parser turns `/Type /Page` into a page object) or an
  // outline item (/Title with /Parent) is exempt only while it has no widget subtype, no /FT and no
  // value key: a field mislabelled `/Type /Page` is still a field.
  const pageNode = d instanceof PDFPageLeaf || d instanceof PDFPageTree || type === N("Page") || type === N("Pages");
  const exempt =
    (pageNode && !hasValue && val(doc, d, "Subtype") !== N("Widget")) ||
    (d.get(N("Title")) !== undefined && d.get(N("Parent")) !== undefined && !hasValue && val(doc, d, "Subtype") !== N("Widget"));
  // The exemption covers a genuine page or outline item, not a dictionary that merely wears the label: one
  // whose /Parent chain reaches a field is part of that field (its /DA, /TU, /Opt, /AP...), so only an exempt
  // dictionary with NO field ancestor is left alone (omitly#1852). Walked in full (hasFieldAncestor), not capped.
  if (exempt) return hasFieldAncestor(doc, d, ancestorMemo);
  if (isSignatureDictionary(doc, d)) return false;
  // Never through a value key or an ancestor, only through /FT or /Subtype /Widget.
  if (isNonFieldKind(doc, d)) return d.get(N("FT")) !== undefined || val(doc, d, "Subtype") === N("Widget");
  let material = false;
  walkParents(doc, d, (cur) => {
    if (!ownFieldEvidence(doc, cur)) return false;
    material = true;
    return true;
  });
  return material;
}

/**
 * Empty every piece of field material that is not KEPT, where kept means: the very object (an
 * indirect object, or for a direct dictionary the exact instance) listed in a kept page's
 * `/Annots`, or a `/Parent` ancestor of one. VALUE-CENTRIC and RECURSIVE, like the signature
 * detector: every indirect object is searched, and direct dictionaries and arrays inside them at
 * any depth (a stream's own dictionary never; the dictionaries nested in it yes; deeper than 64
 * THROWS). So it does not matter how a field is reached (/Kids, /Fields, a ResetForm or SubmitForm
 * action, /AA, an outline item, a custom key) or whether it is indirect, direct, untitled or has its
 * `/FT` only on an ancestor: whatever is field material and not kept is empty before it can be
 * copied (source) or written (destination). Emptied dictionaries are also removed from the `/Kids`
 * of fields that stay. A kept page's non-widget annotations (which carry a `/T`, the author) are
 * exempt because they are listed there. Returns how many dictionaries were emptied.
 */
export function scrubFieldsOutsideKept(doc: PDFDocument, keptPages: readonly PDFPage[], journal?: MutationJournal): number {
  // KEPT: every annotation listed on a kept page, plus the /Parent chain of each kept WIDGET. A
  // non-widget annotation (a Link, a Popup) does NOT keep its /Parent: that would let a page-1 Link
  // point at a page-2 field and keep it. A Popup's parent markup annotation is kept because it is
  // itself listed on the kept page, not because of the /Parent link.
  const kept = new Set<PDFDict>();
  for (const page of keptPages) {
    const annots = lookupAs(doc, page.node.get(N("Annots")), PDFArray);
    if (!annots) continue;
    for (let i = 0; i < annots.size(); i++) {
      const a = dictOf(doc, annots.get(i));
      if (!a) continue;
      if (val(doc, a, "Subtype") === N("Widget")) {
        walkParents(doc, a, (anc) => {
          kept.add(anc);
          return false;
        });
      } else kept.add(a);
    }
  }
  const emptied = new Set<PDFDict>();
  const seen = new Set<PDFObject>();
  const ancestorMemo = new Map<PDFDict, boolean>();
  const walk = (v: PDFObject | undefined, depth: number): void => {
    if (v === undefined) return;
    if (depth > MAX_SIG_WALK_DEPTH) throw new Error("object nesting too deep to inspect for fields");
    if (v instanceof PDFStream) {
      // Its own dictionary is never a field; the dictionaries nested in it are searched.
      for (const [, child] of v.dict.entries()) walk(child, depth + 1);
    } else if (v instanceof PDFDict) {
      if (seen.has(v)) return;
      seen.add(v);
      // Decide first, empty afterwards: emptying an ancestor would erase the evidence that makes its
      // untitled descendants field material (the answer must not depend on traversal order).
      if (!kept.has(v) && isFieldMaterial(doc, v, ancestorMemo)) emptied.add(v);
      for (const [, child] of v.entries()) walk(child, depth + 1);
    } else if (v instanceof PDFArray) {
      for (const child of v.asArray()) walk(child, depth + 1);
    }
  };
  for (const [, obj] of doc.context.enumerateIndirectObjects()) walk(obj, 0);
  // A direct trailer /Info (copied by preserveCatalog) is not an indirect object either.
  walk(doc.context.trailerInfo.Info, 0);
  if (emptied.size === 0) return 0;
  for (const v of emptied) {
    journal?.dict(v);
    for (const [key] of [...v.entries()]) v.delete(key);
  }
  // Detach: a field that stays must not list a dictionary that is now empty.
  for (const d of kept) {
    const kids = lookupAs(doc, d.get(N("Kids")), PDFArray);
    if (!kids) continue;
    for (let i = kids.size() - 1; i >= 0; i--) {
      const kid = dictOf(doc, kids.get(i));
      if (kid && emptied.has(kid)) {
        journal?.array(kids);
        kids.remove(i);
      }
    }
  }
  return emptied.size;
}

/**
 * BACKSTOP on the DESTINATION, run just before a writer saves: the same detector as the
 * source scrub, over every object of the document about to be written. The source scrub is
 * the primary defence; this catches any route to a signature dictionary nobody thought of.
 * Returns true if it found and emptied one (the writer then adds the signature warning).
 */
export function scrubDestinationSignatures(dst: PDFDocument): boolean {
  return emptySignatureDictionaries(dst);
}

/**
 * BACKSTOP on the DESTINATION for fields (extract, split, edit; NOT merge, which keeps every field,
 * including ones with no widget): any field material (see isFieldMaterial) that is not an annotation
 * on an output page, or an ancestor of one, is emptied just before the save.
 */
export function scrubDestinationFields(dst: PDFDocument): number {
  return scrubFieldsOutsideKept(dst, dst.getPages());
}

export const SIGNATURE_WARNING =
  "The original's digital signature was removed; the output is a new, unsigned document.";
export const LAYERS_WARNING = "The original had optional-content layers; hidden layers may now show.";
export const FONT_RENAME_WARNING =
  "Two forms used the same font name for different fonts; some form fields could not be switched to their own font and may render in the wrong one.";
export const RENAME_WARNING =
  "Some form fields were renamed because two files used the same field name; a calculation that refers to the old name may no longer work.";
