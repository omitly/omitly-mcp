// Page operations via pdf-lib. Each takes the current document bytes and
// returns new bytes — the caller re-renders and pushes onto the undo stack.

import {
  PDFArray,
  PDFBool,
  PDFContext,
  PDFDict,
  PDFDocument,
  PDFHexString,
  PDFName,
  PDFNumber,
  PDFObject,
  PDFObjectCopier,
  PDFPage,
  PDFPageLeaf,
  PDFRef,
  PDFStream,
  PDFString,
  degrees,
} from "pdf-lib";
import { scrubFieldsOutsideKept } from "./docFacts.js";

/** Maps an old zero-based page index to its new index after a structural page
 * op, or null if that page was removed. The caller applies this to every piece
 * of page-indexed UI state (pending redaction regions, panel selection) so a
 * queued redaction can NEVER land on the wrong page after pages shift. */
export type PageRemap = (page: number) => number | null;

export function remapAfterDelete(removed: number): PageRemap {
  return (p) => (p === removed ? null : p > removed ? p - 1 : p);
}

export function remapAfterInsert(after: number): PageRemap {
  return (p) => (p > after ? p + 1 : p);
}

export function remapAfterMove(from: number, to: number): PageRemap {
  return (p) => {
    if (p === from) return to;
    // Removing `from` shifts later pages left; re-inserting at `to` shifts
    // pages at/after `to` right. Net effect on a bystander page:
    if (from < p && p <= to) return p - 1;
    if (to <= p && p < from) return p + 1;
    return p;
  };
}

/** Apply a `PageRemap` to any list of page-indexed items (pending redaction
 * regions, placed signatures, measurements — anything carrying a zero-based
 * `page`). Items whose page was removed are dropped; the rest keep every other
 * field untouched and follow their page to its new index. Pure, and shared so
 * the three call sites in `mutate()` cannot drift apart — measurements were
 * missing from that set until omitly#854. */
export function remapPageIndexed<T extends { page: number }>(items: readonly T[], remap: PageRemap): T[] {
  return items.flatMap((item) => {
    const page = remap(item.page);
    return page === null ? [] : [{ ...item, page }];
  });
}

async function load(bytes: Uint8Array): Promise<PDFDocument> {
  // slice() so pdf-lib can't detach the caller's buffer.
  return PDFDocument.load(bytes.slice(), { updateMetadata: false });
}

/** Rotate one page by a delta (clamped to 90° steps), preserving prior angle. */
export async function rotatePage(
  bytes: Uint8Array,
  index: number,
  deltaDeg: number,
): Promise<Uint8Array> {
  const doc = await load(bytes);
  const page = doc.getPages()[index];
  if (!page) throw new Error(`no page ${index}`);
  const current = page.getRotation().angle;
  const next = (((current + deltaDeg) % 360) + 360) % 360;
  page.setRotation(degrees(next));
  return doc.save();
}

/**
 * A page's current rotation, normalised to [0, 360). `extractPageText`
 * (`src/redact/pageText.ts`) excludes any page whose rotation is non-zero
 * from automatic PII detection, Find, and Replace All — callers use this to
 * warn when a rotate action is about to cross that 0 → non-zero boundary
 * (omitly#825), without having to duplicate rotatePage's own angle math.
 */
export async function getPageRotation(bytes: Uint8Array, index: number): Promise<number> {
  const doc = await load(bytes);
  const page = doc.getPages()[index];
  if (!page) throw new Error(`no page ${index}`);
  return (((page.getRotation().angle % 360) + 360) % 360);
}

/** Delete a page (refuses to remove the last remaining page).
 *
 * Rebuilds via `extractPages` (keeping every OTHER page) rather than
 * `doc.removePage(index)` + `doc.save()`. pdf-lib never garbage-collects: a
 * `removePage`'d leaf is unlinked from `/Kids`, but its content stream,
 * `/Annots`, and — critically — any `/Resources` XObject it names (the scanned
 * image on a scanned page) stay registered as indirect objects, and `save()`
 * re-emits every registered object regardless of reachability. For a
 * redaction tool that means a "deleted" sensitive page is still fully
 * byte-recoverable from the saved output. `extractPages` copies only objects
 * reachable from the KEPT pages into a fresh document, so the deleted page's
 * content, annotations and images are never carried over — the same
 * default-deny extraction path already proven not to leak an excluded page
 * (see `neuterPage` above).
 *
 * Follow-up (omitly#1007): because `extractPages` builds a fresh catalog, a
 * plain extraction drops document-level structures the old `removePage` path
 * preserved — the outline/bookmark tree, `/Info` metadata, page labels, named
 * destinations and viewer preferences. `deletePage` passes
 * `{ preserveCatalog: true }` so `extractPages` copies+prunes those structures
 * back onto the fresh catalog (see its doc comment for exactly what that
 * covers and the two documented gaps: a `/Kids`-split PageLabels/name-tree,
 * and a destination named indirectly by name/string rather than a direct
 * destination array — both left un-restored rather than guessed at, never
 * silently wrong). The security property (a deleted page must not be
 * byte-recoverable) still takes priority: nothing here ever copies a
 * reference to the deleted page's leaf across, so it stays exactly as
 * unreachable as a plain extraction leaves it. */
export async function deletePage(bytes: Uint8Array, index: number): Promise<Uint8Array> {
  const doc = await load(bytes);
  const count = doc.getPageCount();
  if (count <= 1) throw new Error("cannot delete the only page");
  // Require an integer: a fractional/NaN index matches no loop counter below,
  // so `keep` would silently contain every page and the delete would no-op.
  if (!Number.isInteger(index) || index < 0 || index >= count)
    throw new Error(`no page ${index}`);
  const keep: number[] = [];
  for (let i = 0; i < count; i++) if (i !== index) keep.push(i);
  return extractPages(bytes, keep, { preserveCatalog: true });
}

/** Insert a blank page after `index`, matching that page's size (and its
 * rotation, so the new page shows the same way up in a rotated document). */
export async function insertBlankPage(bytes: Uint8Array, index: number): Promise<Uint8Array> {
  const doc = await load(bytes);
  const ref = doc.getPages()[index];
  if (!ref) throw new Error(`no page ${index}`);
  const page = doc.insertPage(index + 1, [ref.getWidth(), ref.getHeight()]);
  page.setRotation(ref.getRotation());
  return doc.save();
}

/** Copy every PDF-spec *inheritable* attribute (`/Resources`, `/MediaBox`,
 * `/CropBox`, `/Rotate`) that a leaf currently inherits from an intermediate
 * `/Pages` node directly ONTO the leaf. Must run before the leaf is reparented:
 * inheritance is resolved by walking `/Parent` upwards, so a leaf moved onto a
 * different parent silently loses everything it used to inherit — its page
 * size, its rotation, and the resource dictionary its fonts and XObjects are
 * named in. pdf-lib does exactly this in `PDFObjectCopier.copyPDFPage` before
 * detaching a page; the in-place reorder below has to do it too. Producers that
 * hang shared attributes off an intermediate node (pdftk, mail-merge and scan
 * pipelines commonly do, to avoid repeating them per page) are the ones this
 * affects — a flat tree inherits nothing and is unchanged. */
function bakeInheritedAttributes(leaf: PDFPageLeaf): void {
  for (const entry of PDFPageLeaf.InheritableEntries) {
    const key = PDFName.of(entry);
    if (leaf.get(key)) continue; // already set directly on the leaf
    const inherited = leaf.getInheritableAttribute(key);
    if (inherited) leaf.set(key, inherited);
  }
}

/** Reorder the document's pages in place (array of source indices, one per
 * final position). Unlike a copyPages()-based rebuild, this only rewrites the
 * page tree's `/Kids` — the catalog (and everything hanging off it, notably
 * `/Outlines` and `/AcroForm`) is untouched, so bookmarks and form fields
 * survive. Outline destinations hold a page *reference*, not an index, so
 * they automatically continue to point at the right (relocated) page with no
 * remapping needed. */
export async function reorderPages(
  bytes: Uint8Array,
  order: number[],
): Promise<Uint8Array> {
  const doc = await load(bytes);
  const pages = doc.getPages();
  const refs = pages.map((p) => p.ref);
  if (order.length !== refs.length) {
    throw new Error(`order has ${order.length} entries, expected ${refs.length}`);
  }
  // `order` must be a genuine permutation of 0..n-1. Length alone is not
  // enough: a repeated index would put the same page ref in `/Kids` twice and
  // drop another page entirely, leaving a structurally inconsistent tree whose
  // `/Count` no longer matches its distinct pages.
  const seen = new Set<number>();
  for (const sourceIndex of order) {
    if (!Number.isInteger(sourceIndex) || sourceIndex < 0 || sourceIndex >= refs.length) {
      throw new Error(`no page ${sourceIndex}`);
    }
    if (seen.has(sourceIndex)) throw new Error(`order repeats page ${sourceIndex}`);
    seen.add(sourceIndex);
  }

  const root = doc.catalog.Pages();
  const rootRef = doc.catalog.get(PDFName.of("Pages"));
  if (!(rootRef instanceof PDFRef)) throw new Error("catalog has no Pages ref");

  // Two passes: bake inherited attributes onto EVERY leaf while the original
  // tree is still intact, and only then rewrite `/Parent`. Resolving
  // inheritance against a half-flattened tree would be order-dependent.
  const leaves = pages.map((p) => p.node);
  leaves.forEach(bakeInheritedAttributes);

  const kids = PDFArray.withContext(doc.context);
  for (const sourceIndex of order) {
    kids.push(refs[sourceIndex]);
    // Flatten: every relocated leaf now hangs directly off the (single) root
    // node, so a source doc with a nested/unbalanced page tree can't leave a
    // leaf pointing at a `/Parent` that's no longer its actual parent.
    leaves[sourceIndex].set(PDFName.of("Parent"), rootRef);
  }
  root.set(PDFName.of("Kids"), kids);
  root.set(PDFName.of("Count"), PDFNumber.of(order.length));

  return doc.save();
}

/** Move a page from one index to another. */
export async function movePage(
  bytes: Uint8Array,
  from: number,
  to: number,
): Promise<Uint8Array> {
  const src = await load(bytes);
  const order = Array.from({ length: src.getPageCount() }, (_, i) => i);
  const [moved] = order.splice(from, 1);
  order.splice(to, 0, moved);
  return reorderPages(bytes, order);
}

/** Append every page of another PDF (given its bytes) to this one. */
export async function appendPdf(
  bytes: Uint8Array,
  otherBytes: Uint8Array,
): Promise<Uint8Array> {
  const doc = await load(bytes);
  const other = await load(otherBytes);
  await other.flush();
  const copier = PDFObjectCopier.for(other.context, doc.context);
  const copied: PDFPage[] = [];
  for (const srcPage of other.getPages()) {
    // Copy by ref so the copier caches src-page-ref -> dst-page-ref. A form
    // widget's /P back-reference then resolves to this same page instead of
    // copying a second, orphaned page object (#884).
    const ref = copier.copy(srcPage.ref);
    const node = doc.context.lookup(ref);
    if (!(node instanceof PDFPageLeaf)) throw new Error("appended page did not copy");
    copied.push(PDFPage.of(node, ref, doc));
  }
  copied.forEach((p) => doc.addPage(p));
  // omitly#1238: the pages above carry their widget annotations and /AP
  // streams across (#884) regardless of this call, so a skipped merge here
  // is invisible at the pixel level — only readFields()/applyFieldValues,
  // which walk /AcroForm /Fields rather than the page tree, would ever have
  // noticed the appended document's fields were gone.
  mergeAcroFormOnAppend(other, doc, copier);
  return doc.save();
}

/** A field dict's partial name (`/T`), or `""` if absent. Mirrors pdf-lib's
 * own `PDFAcroField.getPartialName()` decoding, without pulling in the
 * `doc.getForm()` high-level API this file deliberately avoids (its lazy
 * AcroForm creation is the exact trap `pageOps.test.ts:158` documents). */
function fieldPartialName(dict: PDFDict): string {
  const t = dict.lookupMaybe(PDFName.of("T"), PDFString, PDFHexString);
  return t?.decodeText() ?? "";
}

/** Partial names already used by `acroForm`'s TOP-LEVEL fields. A fully
 * qualified field name is only disambiguated by an ancestor's OWN `/T`, so
 * two top-level fields sharing a `/T` are indistinguishable to
 * `readFields()`/`applyFieldValues`, which key by name — this is the set an
 * appended field's name must not collide with (omitly#1238). */
function topLevelFieldNames(acroForm: PDFDict | undefined): Set<string> {
  const names = new Set<string>();
  const fields = acroForm?.lookupMaybe(PDFName.of("Fields"), PDFArray);
  if (!fields || !acroForm) return names;
  for (let i = 0; i < fields.size(); i++) {
    const ref = fields.get(i);
    if (!(ref instanceof PDFRef)) continue;
    const name = fieldPartialName(acroForm.context.lookup(ref, PDFDict));
    if (name) names.add(name);
  }
  return names;
}

/** `base`, or the first `base (2)`, `base (3)`, ... not already in `taken`. */
function disambiguateFieldName(base: string, taken: ReadonlySet<string>): string {
  if (!taken.has(base)) return base;
  let i = 2;
  while (taken.has(`${base} (${i})`)) i++;
  return `${base} (${i})`;
}

/** Union `src`'s `/DR` (default resources) into `dst`'s, category by category
 * (`/Font`, `/XObject`, ...), preferring `dst`'s own entry on a same-name
 * collision so the base document's existing field appearances can't change —
 * only genuinely new resource names are added. A viewer that regenerates an
 * appearance (`/NeedAppearances`, or an in-place edit) looks a field's font up
 * by name in `/DR`; an appended field whose font isn't there falls back to
 * whatever the viewer substitutes, which is a wrong-but-plausible rendering
 * rather than an honest failure — the class this codebase treats as worse
 * than an outright miss. */
/** A structural fingerprint of an object, refs resolved (bounded, cycle-safe), stream bytes included
 * by length and an FNV-1a hash. Two objects in DIFFERENT documents are "the same" when this matches,
 * which is how a resource both forms share (the same Helvetica) is told from a name that merely collides. */
let deepFingerprints = 0;
function fingerprint(ctx: PDFContext, v: PDFObject | undefined, depth = 0, seen: Set<PDFObject> = new Set()): string {
  if (v === undefined) return "u";
  // Past the bound the answer must be CONSERVATIVE: a token no other fingerprint can equal, so two
  // objects that differ only below the bound are treated as different (renamed), never as identical.
  if (depth > 12) return `deep#${++deepFingerprints}`;
  if (v instanceof PDFRef) {
    if (seen.has(v)) return "cycle";
    seen.add(v);
    const out = fingerprint(ctx, ctx.lookup(v), depth + 1, seen);
    seen.delete(v);
    return out;
  }
  if (v instanceof PDFStream) {
    const bytes = v.getContents();
    let h = 0x811c9dc5;
    for (let i = 0; i < bytes.length; i++) h = Math.imul(h ^ bytes[i], 0x01000193) >>> 0;
    return `S{${fingerprint(ctx, v.dict, depth + 1, seen)}|${bytes.length}|${h}}`;
  }
  if (v instanceof PDFDict) {
    const parts = v
      .entries()
      .map(([k, x]) => `${k.toString()}=${fingerprint(ctx, x, depth + 1, seen)}`)
      .sort();
    return `D{${parts.join(",")}}`;
  }
  if (v instanceof PDFArray) return `A[${v.asArray().map((x) => fingerprint(ctx, x, depth + 1, seen)).join(",")}]`;
  return v.toString();
}

/** `base`, or `base_2`, `base_3`, ... not used in any of `categories`. */
function uniqueResourceName(base: string, categories: PDFDict[], taken: Set<string>): string {
  let i = 2;
  const used = (n: string) => taken.has(n) || categories.some((c) => c.get(PDFName.of(n)) !== undefined);
  while (used(`${base}_${i}`)) i++;
  taken.add(`${base}_${i}`);
  return `${base}_${i}`;
}

/** Union `src`'s `/DR` (default resources) into `dst`'s, category by category
 * (`/Font`, `/XObject`, ...), preferring `dst`'s own entry on a same-name
 * collision so the base document's existing field appearances can't change —
 * only genuinely new resource names are added. A viewer that regenerates an
 * appearance (`/NeedAppearances`, or an in-place edit) looks a field's font up
 * by name in `/DR`; an appended field whose font isn't there falls back to
 * whatever the viewer substitutes, which is a wrong-but-plausible rendering
 * rather than an honest failure — the class this codebase treats as worse
 * than an outright miss.
 *
 * omitly#1841 (Codex): the same applies when the name IS there but means a DIFFERENT object
 * (Helvetica in one form, Courier in the other, both called /F1): dropping the incoming one
 * silently re-fonts the appended form. So an incoming resource whose name clashes with a
 * different object is added under a UNIQUE name (`/F1` -> `/F1_2`), and the returned map
 * (Font category only) lets the caller rewrite the incoming fields' `/DA` strings. An
 * identical object (the same font in both) is not renamed. */
function mergeDefaultResources(
  dstAcroForm: PDFDict,
  srcAcroForm: PDFDict,
  copier: PDFObjectCopier,
  dstContext: PDFContext,
): Map<string, string> {
  const fontRenames = new Map<string, string>();
  const srcDR = srcAcroForm.lookupMaybe(PDFName.of("DR"), PDFDict);
  if (!srcDR) return fontRenames;
  const dstDR = dstAcroForm.lookupMaybe(PDFName.of("DR"), PDFDict) ?? dstContext.obj({});
  for (const [key] of srcDR.entries()) {
    const srcCategory = srcDR.lookupMaybe(key, PDFDict);
    const dstCategory = dstDR.lookupMaybe(key, PDFDict);
    if (!dstCategory) {
      const value = srcDR.get(key);
      if (value !== undefined) dstDR.set(key, copier.copy(value));
      continue;
    }
    if (!srcCategory) continue; // dst already holds a non-dict value here; leave it
    const taken = new Set<string>();
    for (const [subKey, subValue] of srcCategory.entries()) {
      const existing = dstCategory.get(subKey);
      if (existing === undefined) {
        dstCategory.set(subKey, copier.copy(subValue));
        continue;
      }
      if (fingerprint(srcAcroForm.context, subValue) === fingerprint(dstContext, existing)) continue; // the same object: nothing to rename
      const newName = uniqueResourceName(subKey.decodeText(), [dstCategory, srcCategory], taken);
      dstCategory.set(PDFName.of(newName), copier.copy(subValue));
      if (key === PDFName.of("Font")) fontRenames.set(subKey.decodeText(), newName);
    }
  }
  dstAcroForm.set(PDFName.of("DR"), dstDR);
  return fontRenames;
}

/** The bytes of a hex string, decoded per the PDF spec: white space (NUL, tab, LF, FF, CR, space) between digits is
 * ignored and an odd final digit is padded with 0. pdf-lib's `PDFHexString.asBytes()` does neither (it reads a space
 * as a digit), so `<2F 46 31>` came out as garbage. Undefined if a non-hex character is present. */
function hexStringBytes(raw: string): string | undefined {
  let digits = raw.replace(/[\0\t\n\f\r ]/g, "");
  if (!/^[0-9A-Fa-f]*$/.test(digits)) return undefined;
  if (digits.length % 2 === 1) digits += "0";
  let out = "";
  for (let i = 0; i < digits.length; i += 2) out += String.fromCharCode(parseInt(digits.slice(i, i + 2), 16));
  return out;
}

/** A `/DA` value as bytes (as a Latin-1 string), whether it is written `(...)` or `<...>`; undefined if it is
 * neither. Bytes, not `decodeText()`: a DA is operators and names, and decoding as text would reinterpret it. */
function daBytes(ctx: PDFContext, v: PDFObject | undefined): string | undefined {
  if (v === undefined) return undefined;
  const o = ctx.lookup(v);
  if (o instanceof PDFHexString) return hexStringBytes(o.asString());
  if (o instanceof PDFString) return Array.from(o.asBytes(), (b) => String.fromCharCode(b)).join("");
  return undefined;
}

/** Hex-string form of a Latin-1 string: needs no escaping, so a `)` or `\` or comment in a `/DA` survives. */
function daAsHex(text: string): PDFHexString {
  return PDFHexString.of(Array.from(text, (c) => c.charCodeAt(0).toString(16).padStart(2, "0")).join(""));
}

const PDF_WS = new Set([0, 9, 10, 12, 13, 32]);
const PDF_DELIM = new Set(["(", ")", "<", ">", "[", "]", "{", "}", "/", "%"]);

/** Tokenise a content-stream fragment: names, numbers/operators, strings, comments skipped. Start/end offsets
 * are into `text`, so a token can be replaced in place. */
function daTokens(text: string): {
  tokens: { kind: "name" | "word" | "other"; text: string; start: number; end: number }[];
  /** A hex string with no closing `>`: the rest of the text is not tokenised reliably. */
  unterminated: boolean;
} {
  const out: { kind: "name" | "word" | "other"; text: string; start: number; end: number }[] = [];
  let unterminated = false;
  let i = 0;
  while (i < text.length) {
    const c = text[i];
    if (PDF_WS.has(c.charCodeAt(0))) { i++; continue; }
    if (c === "%") { while (i < text.length && text[i] !== "\n" && text[i] !== "\r") i++; continue; }
    const start = i;
    if (c === "(") {
      let depth = 0;
      for (; i < text.length; i++) {
        if (text[i] === "\\") { i++; continue; }
        if (text[i] === "(") depth++;
        else if (text[i] === ")" && --depth === 0) { i++; break; }
      }
      out.push({ kind: "other", text: text.slice(start, i), start, end: i });
    } else if (c === "/") {
      i++;
      while (i < text.length && !PDF_WS.has(text.charCodeAt(i)) && !PDF_DELIM.has(text[i])) i++;
      out.push({ kind: "name", text: text.slice(start, i), start, end: i });
    } else if (c === "<" && text[i + 1] !== "<") {
      // A hex string: ONE token up to and including the next `>` (its contents, a `%` or a `/F2`, are not syntax).
      const close = text.indexOf(">", i + 1);
      if (close === -1) {
        unterminated = true;
        i = text.length;
      } else i = close + 1;
      out.push({ kind: "other", text: text.slice(start, i), start, end: i });
    } else if (c === "<" || c === ">") {
      i += text[i + 1] === c ? 2 : 1; // `<<`, `>>` or a stray `>`
      out.push({ kind: "other", text: text.slice(start, i), start, end: i });
    } else if (PDF_DELIM.has(c)) {
      i++;
      out.push({ kind: "other", text: c, start, end: i });
    } else {
      while (i < text.length && !PDF_WS.has(text.charCodeAt(i)) && !PDF_DELIM.has(text[i])) i++;
      out.push({ kind: "word", text: text.slice(start, i), start, end: i });
    }
  }
  return { tokens: out, unterminated };
}

/** Rewrite ONLY the font operand of `Tf` (`/F1 12 Tf`) through `renames`; a colour space called `/F1` (`/F1 cs`) is
 * left alone. Name tokens carry `#xx` escapes (`/Times#20Roman`): they are decoded before the lookup, and a renamed
 * name is written back with PDF name escaping. `text` is undefined when nothing changed; `fonts` lists the (decoded)
 * font operands the string uses, after renaming. */
function rewriteDA(da: string, renames: Map<string, string>): { text: string | undefined; fonts: string[]; unterminated: boolean } {
  const { tokens: t, unterminated } = daTokens(da);
  let out = "";
  let last = 0;
  const fonts: string[] = [];
  for (let i = 0; i + 2 < t.length; i++) {
    if (t[i].kind !== "name" || t[i + 1].kind !== "word" || t[i + 2].kind !== "word" || t[i + 2].text !== "Tf") continue;
    if (!/^[+-]?(\d+\.?\d*|\.\d+)$/.test(t[i + 1].text)) continue;
    const decoded = t[i].text.slice(1).replace(/#([0-9A-Fa-f]{2})/g, (_, h: string) => String.fromCharCode(parseInt(h, 16)));
    const to = renames.get(decoded);
    fonts.push(to ?? decoded);
    if (to === undefined) continue;
    out += da.slice(last, t[i].start) + PDFName.of(to).toString();
    last = t[i].end;
  }
  return { text: last === 0 ? undefined : out + da.slice(last), fonts, unterminated };
}

/** Rewrite `/DA` on every field and widget under `roots` (the incoming fields, already copied into
 * `dst`), following `/Kids`. A rewritten `/DA` is written as a hex string; an unchanged one is not touched.
 * Returns how many `/DA` values could not be read (neither a string nor a hex string) plus how many name a font that resolves nowhere in `knownFonts`. */
function rewriteIncomingDA(dstContext: PDFContext, roots: PDFRef[], renames: Map<string, string>, knownFonts: Set<string>): number {
  let unreadable = 0;
  const seen = new Set<PDFObject>();
  const visit = (v: PDFObject | undefined, depth: number): void => {
    if (v === undefined || depth > 64) return;
    const dict = dstContext.lookup(v);
    if (!(dict instanceof PDFDict) || seen.has(dict)) return;
    seen.add(dict);
    const da = dict.get(PDFName.of("DA"));
    if (da !== undefined) {
      const text = daBytes(dstContext, da);
      if (text === undefined) unreadable += 1;
      else {
        const next = rewriteDA(text, renames);
        if (next.text !== undefined) dict.set(PDFName.of("DA"), daAsHex(next.text));
        if (next.unterminated) unreadable += 1; // could not be tokenised reliably: warn rather than guess
        // A font the /DA uses that resolves nowhere in the merged /DR: it would render in a substitute.
        for (const f of next.fonts) if (!knownFonts.has(f)) unreadable += 1;
      }
    }
    const kids = dstContext.lookup(dict.get(PDFName.of("Kids")));
    if (kids instanceof PDFArray) for (const k of kids.asArray()) visit(k, depth + 1);
  };
  roots.forEach((r) => visit(r, 0));
  return unreadable;
}

/** Form-level keys merged verbatim from `src` when `dst` doesn't already carry
 * one — `/DR` and `/NeedAppearances` are handled separately (a real merge and
 * an OR respectively, not "dst wins"), and `/CO` is rebuilt below rather than
 * copied, same reasoning as `SAFE_ACROFORM_KEYS` above. */
const APPEND_SIMPLE_MERGE_KEYS = ["DA", "Q", "SigFlags"] as const;

/** Merge the appended document's AcroForm into `dst`'s (omitly#1238).
 *
 * Every source field is added — never pruned, since every page it lives on
 * was just appended alongside it — renamed only where its top-level partial
 * name would otherwise collide with one already in `dst`. Reuses `copier`'s
 * cache, so a field merged with the widget already copied as part of its
 * page's `/Annots` (the common case: `field.addToPage` produces ONE dict
 * serving both roles) resolves to that SAME destination object rather than a
 * duplicate — the same #884 argument the page-copy loop above already relies
 * on, extended to the field tree. */
export function mergeAcroFormOnAppend(
  src: PDFDocument,
  dst: PDFDocument,
  copier: PDFObjectCopier,
): { renamed: number; fontRenameFailed: number } {
  // omitly#1841: exported for `mergePdfs`; the counts let it warn that a field rename
  // can break a calculation that names the old field, and that a font rename could not
  // be applied to some /DA. `appendPdf` ignores both.
  let renamed = 0;
  let fontRenameFailed = 0;
  const srcAcroForm = src.catalog.AcroForm();
  const srcFields = srcAcroForm?.lookupMaybe(PDFName.of("Fields"), PDFArray);
  if (!srcAcroForm || !srcFields || srcFields.size() === 0) return { renamed, fontRenameFailed };

  const dstAcroFormExisting = dst.catalog.AcroForm();
  const takenNames = topLevelFieldNames(dstAcroFormExisting);

  const fieldRefMap = new Map<PDFRef, PDFRef>();
  const copiedRefs: PDFRef[] = [];
  for (let i = 0; i < srcFields.size(); i++) {
    const srcRef = srcFields.get(i);
    if (!(srcRef instanceof PDFRef)) continue;
    const dstRef = copier.copy(srcRef);
    fieldRefMap.set(srcRef, dstRef);
    copiedRefs.push(dstRef);

    const originalName = fieldPartialName(src.context.lookup(srcRef, PDFDict));
    const finalName = disambiguateFieldName(originalName, takenNames);
    takenNames.add(finalName);
    if (finalName !== originalName) {
      dst.context.lookup(dstRef, PDFDict).set(PDFName.of("T"), PDFHexString.fromText(finalName));
      renamed += 1;
    }
  }
  if (copiedRefs.length === 0) return { renamed, fontRenameFailed };

  const dstAcroForm = dstAcroFormExisting ?? dst.context.obj({});
  const dstFields = dstAcroForm.lookupMaybe(PDFName.of("Fields"), PDFArray) ?? PDFArray.withContext(dst.context);
  copiedRefs.forEach((r) => dstFields.push(r));
  dstAcroForm.set(PDFName.of("Fields"), dstFields);

  for (const name of APPEND_SIMPLE_MERGE_KEYS) {
    const key = PDFName.of(name);
    if (dstAcroForm.get(key) !== undefined) continue; // dst's own value wins
    const value = srcAcroForm.get(key);
    if (value !== undefined) dstAcroForm.set(key, copier.copy(value));
  }
  const fontRenames = mergeDefaultResources(dstAcroForm, srcAcroForm, copier, dst.context);
  // The incoming fields keep their own fonts: rewrite their /DA through the renames; and if they relied on the
  // source form's /DA (no /DA of their own) while the destination keeps a DIFFERENT form-level /DA, give them
  // that one, rewritten, explicitly.
  const original = daBytes(src.context, srcAcroForm.get(PDFName.of("DA")));
  if (original !== undefined) {
    const dstFormDA = daBytes(dst.context, dstAcroForm.get(PDFName.of("DA")));
    const rewritten = rewriteDA(original, fontRenames).text;
    if (dstFormDA !== undefined && (dstFormDA !== original || fontRenames.size > 0)) {
      for (const ref of copiedRefs) {
        const f = dst.context.lookup(ref, PDFDict);
        // Rewritten: as hex (no escaping to get wrong). Unchanged: the source's own bytes, as a hex string too.
        if (f.get(PDFName.of("DA")) === undefined) f.set(PDFName.of("DA"), daAsHex(rewritten ?? original));
      }
    }
  }
  if (fontRenames.size > 0) {
    const drFonts = dstAcroForm.lookupMaybe(PDFName.of("DR"), PDFDict)?.lookupMaybe(PDFName.of("Font"), PDFDict);
    const known = new Set((drFonts?.entries() ?? []).map(([k]) => k.decodeText()));
    fontRenameFailed += rewriteIncomingDA(dst.context, copiedRefs, fontRenames, known);
  }

  // OR, not "dst wins": if EITHER document relies on viewer-regenerated
  // appearances, the merged form still needs to.
  const srcNeedApp = srcAcroForm.lookupMaybe(PDFName.of("NeedAppearances"), PDFBool);
  if (srcNeedApp?.asBoolean()) dstAcroForm.set(PDFName.of("NeedAppearances"), PDFBool.True);

  // Rebuilt from the surviving field map, not concatenated: a raw
  // concatenation of two /CO arrays would carry stale-looking src refs if
  // any entry didn't map (defensive; every top-level field is copied above,
  // so in practice every entry maps).
  const srcCalcOrder = srcAcroForm.lookupMaybe(PDFName.of("CO"), PDFArray);
  if (srcCalcOrder && srcCalcOrder.size() > 0) {
    const dstCalcOrder = dstAcroForm.lookupMaybe(PDFName.of("CO"), PDFArray) ?? PDFArray.withContext(dst.context);
    for (let i = 0; i < srcCalcOrder.size(); i++) {
      const entry = srcCalcOrder.get(i);
      const mapped = entry instanceof PDFRef ? fieldRefMap.get(entry) : undefined;
      if (mapped) dstCalcOrder.push(mapped);
    }
    if (dstCalcOrder.size() > 0) dstAcroForm.set(PDFName.of("CO"), dstCalcOrder);
  }

  if (!dstAcroFormExisting) {
    const acroFormRef = dst.context.register(dstAcroForm);
    dst.catalog.set(PDFName.of("AcroForm"), acroFormRef);
  }
  return { renamed, fontRenameFailed };
}

/** Recursively copy the subset of a source AcroForm field tree whose widgets
 * survived onto an extracted page, reusing `copier`'s cache so a merged
 * field/widget dict already copied as part of the page's `/Annots` resolves
 * to the SAME destination object rather than being duplicated. A container
 * field is kept only if at least one descendant survived; a field none of
 * whose widgets made it across is dropped entirely rather than carried as a
 * dangling reference. Returns the destination ref, or undefined if dropped. */
function copyKeptField(
  copier: PDFObjectCopier,
  srcContext: PDFContext,
  dstContext: PDFContext,
  ref: PDFRef,
  keptWidgetRefs: Set<PDFRef>,
  keptFieldMap: Map<PDFRef, PDFRef>,
): PDFRef | undefined {
  const dict = srcContext.lookup(ref, PDFDict);
  const kids = dict.lookupMaybe(PDFName.of("Kids"), PDFArray);

  if (!kids) {
    const subtype = dict.lookup(PDFName.of("Subtype"));
    // Merged field/widget (the common case): keep only if its widget
    // actually landed on an extracted page.
    if (subtype === PDFName.of("Widget") && keptWidgetRefs.has(ref)) {
      const copied = copier.copy(ref);
      keptFieldMap.set(ref, copied);
      return copied;
    }
    return undefined;
  }

  const keptKidRefs: PDFRef[] = [];
  for (let i = 0; i < kids.size(); i++) {
    const kidRef = kids.get(i);
    if (!(kidRef instanceof PDFRef)) continue;
    const copiedKidRef = copyKeptField(
      copier,
      srcContext,
      dstContext,
      kidRef,
      keptWidgetRefs,
      keptFieldMap,
    );
    if (copiedKidRef) keptKidRefs.push(copiedKidRef);
  }
  if (keptKidRefs.length === 0) return undefined;

  const newDict = dstContext.obj({});
  for (const [key, value] of dict.entries()) {
    if (key === PDFName.of("Kids")) continue;
    newDict.set(key, copier.copy(value));
  }
  const newKids = PDFArray.withContext(dstContext);
  keptKidRefs.forEach((r) => newKids.push(r));
  newDict.set(PDFName.of("Kids"), newKids);
  const newRef = dstContext.register(newDict);
  keptFieldMap.set(ref, newRef);
  for (const kidRef of keptKidRefs) {
    dstContext.lookup(kidRef, PDFDict).set(PDFName.of("Parent"), newRef);
  }
  return newRef;
}

/** Form-level `/AcroForm` entries that are safe to carry into an extracted
 * document. Every key here holds either a scalar or a resource dictionary; none
 * can reference a field, a widget or a page, so none can drag a page the user
 * did NOT select into the output. The list is an ALLOWLIST on purpose: an
 * unrecognised entry is dropped, not copied.
 *
 * `/CO` (JS calculation order) is deliberately absent — it names fields by
 * reference, and forms with any calculated field routinely list every
 * participating field in it, including ones whose only widget sits on an
 * excluded page. It is rebuilt below from the surviving fields only.
 * `/XFA` is absent for the same reason and worse: it carries a whole second
 * copy of the form (structure and data) for every page, which a pruned page
 * subset has no way to honour. */
const SAFE_ACROFORM_KEYS = ["DA", "DR", "Q", "NeedAppearances", "SigFlags"] as const;

/** Carry the source document's AcroForm across to `dst`, pruned to only the
 * fields whose widgets landed on `extractedPages` — never the whole form. A
 * document with no surviving fields ends up with no `/AcroForm` at all. */
function copyAcroFormForExtractedPages(
  src: PDFDocument,
  dst: PDFDocument,
  copier: PDFObjectCopier,
  extractedSrcPages: PDFPage[],
): void {
  const srcAcroForm = src.catalog.AcroForm();
  if (!srcAcroForm) return;

  const keptWidgetRefs = new Set<PDFRef>();
  for (const page of extractedSrcPages) {
    const annots = page.node.Annots();
    if (!annots) continue;
    for (let i = 0; i < annots.size(); i++) {
      const annotRef = annots.get(i);
      if (!(annotRef instanceof PDFRef)) continue;
      const annotDict = src.context.lookup(annotRef, PDFDict);
      if (annotDict.lookup(PDFName.of("Subtype")) === PDFName.of("Widget")) {
        keptWidgetRefs.add(annotRef);
      }
    }
  }
  if (keptWidgetRefs.size === 0) return;

  const srcFields = srcAcroForm.lookupMaybe(PDFName.of("Fields"), PDFArray);
  const keptFieldRefs: PDFRef[] = [];
  const keptFieldMap = new Map<PDFRef, PDFRef>();
  if (srcFields) {
    for (let i = 0; i < srcFields.size(); i++) {
      const fieldRef = srcFields.get(i);
      if (!(fieldRef instanceof PDFRef)) continue;
      const copiedRef = copyKeptField(
        copier,
        src.context,
        dst.context,
        fieldRef,
        keptWidgetRefs,
        keptFieldMap,
      );
      if (copiedRef) keptFieldRefs.push(copiedRef);
    }
  }
  if (keptFieldRefs.length === 0) return;

  const dstAcroForm = dst.context.obj({});
  // Allowlist, never a blanket copy of every remaining entry: deep-copying an
  // arbitrary form-level entry that references a field (notably /CO) pulls that
  // field's widget across with `copier`, and the widget's `/P` back-reference
  // then drags in the whole EXCLUDED page it sits on — a page the user chose to
  // leave behind, byte-recoverable in the output despite being unreachable from
  // the page tree.
  for (const name of SAFE_ACROFORM_KEYS) {
    const key = PDFName.of(name);
    const value = srcAcroForm.get(key);
    if (value !== undefined) dstAcroForm.set(key, copier.copy(value));
  }
  // Rebuild /CO from the surviving fields only, preserving their relative
  // order, so calculated fields that DID come across still evaluate in order.
  const srcCalcOrder = srcAcroForm.lookupMaybe(PDFName.of("CO"), PDFArray);
  if (srcCalcOrder) {
    const dstCalcOrder = PDFArray.withContext(dst.context);
    for (let i = 0; i < srcCalcOrder.size(); i++) {
      const entry = srcCalcOrder.get(i);
      const mapped = entry instanceof PDFRef ? keptFieldMap.get(entry) : undefined;
      if (mapped) dstCalcOrder.push(mapped);
    }
    if (dstCalcOrder.size() > 0) dstAcroForm.set(PDFName.of("CO"), dstCalcOrder);
  }
  const fieldsArr = PDFArray.withContext(dst.context);
  keptFieldRefs.forEach((r) => fieldsArr.push(r));
  dstAcroForm.set(PDFName.of("Fields"), fieldsArr);

  const acroFormRef = dst.context.register(dstAcroForm);
  dst.catalog.set(PDFName.of("AcroForm"), acroFormRef);
}

/** A before-image of every dictionary and array an extraction mutates in the SOURCE, so one parsed
 * source can serve many extractions (`openExtractionSession`): parsing is the dominant cost of an
 * extraction (a 2 MB, 10,000-page file takes ~0.36 s of a ~0.41 s extraction), and `split_pdf`
 * does one per range. Only the mutations of default-deny (neuter, detach, field scrub) are
 * journaled; nothing is journaled for a one-shot `extractPages`. */
class Journal {
  private dicts = new Map<PDFDict, [PDFName, PDFObject][]>();
  private arrays = new Map<PDFArray, PDFObject[]>();
  dict(d: PDFDict): void {
    if (!this.dicts.has(d)) this.dicts.set(d, [...d.entries()]);
  }
  array(a: PDFArray): void {
    if (!this.arrays.has(a)) this.arrays.set(a, a.asArray());
  }
  restore(): void {
    for (const [d, saved] of this.dicts) {
      for (const [k] of [...d.entries()]) d.delete(k);
      for (const [k, v] of saved) d.set(k, v);
    }
    for (const [a, saved] of this.arrays) {
      while (a.size() > 0) a.remove(a.size() - 1);
      for (const v of saved) a.push(v);
    }
    this.dicts.clear();
    this.arrays.clear();
  }
}

/** Detach every widget annotation on `page` from the field it belongs to, so a
 * surviving sibling widget's `/Parent` chain can't reach back down into a page
 * the user excluded. Mutates the SOURCE document, which for `extractPages` is a
 * private throwaway copy. */
function detachWidgetsFromFields(context: PDFContext, page: PDFPage, journal?: Journal): void {
  const annots = page.node.Annots();
  if (!annots) return;
  for (let i = 0; i < annots.size(); i++) {
    const annotRef = annots.get(i);
    if (!(annotRef instanceof PDFRef)) continue;
    const annot = context.lookupMaybe(annotRef, PDFDict);
    const parentRef = annot?.get(PDFName.of("Parent"));
    if (!(parentRef instanceof PDFRef)) continue;
    const kids = context.lookupMaybe(parentRef, PDFDict)?.lookupMaybe(PDFName.of("Kids"), PDFArray);
    if (!kids) continue;
    for (let k = kids.size() - 1; k >= 0; k--) {
      if (kids.get(k) === annotRef) {
        journal?.array(kids);
        kids.remove(k);
      }
    }
  }
}

/** Reduce a page to an inert stub — drop every entry but `/Type`, then give it
 * a degenerate `/MediaBox` so it stays a structurally valid (if empty) page.
 *
 * This is the DEFAULT-DENY half of the extraction leak fix. The allowlist above
 * closes the reference paths we know about; this closes the ones we don't. Any
 * object graph that still manages to reach a page the user did not select finds
 * nothing there to leak: no `/Contents`, no `/Annots`, no `/Resources`. Safe to
 * do because `extractPages` loads its own private copy of the source bytes and
 * discards it — the user's document is never touched. */
function neuterPage(context: PDFContext, page: PDFPage, journal?: Journal): void {
  const leaf = page.node;
  journal?.dict(leaf);
  for (const [key] of leaf.entries()) {
    if (key === PDFName.of("Type")) continue;
    leaf.delete(key);
  }
  leaf.set(PDFName.of("MediaBox"), context.obj([0, 0, 1, 1]));
}

// ---------------------------------------------------------------------------
// Document-level (catalog) structures for `extractPages({ preserveCatalog })`
// (omitly#1007). Every helper below only ever ADDS a reference to a page ref
// already present in `keptSrcPageRefs` (or copies something with no page
// dependency at all, like `/Info`/`/ViewerPreferences`) — never to a deleted
// page's (neutered) leaf — so none of this can reopen the #1004 leak. A PDF
// destination names its target page by REFERENCE, not by index, so once a
// kept page's ref has been copied once (in the page-copy loop below),
// `copier`'s src->dst cache remaps every further reference to it for free —
// the same trick `reorderPages` already relies on for outline destinations.
// ---------------------------------------------------------------------------

/** Resolve an explicit destination array's target page ref: `[pageRef, /Fit,
 * ...]`. `undefined` for anything else (an empty/malformed array, or a value
 * that isn't an array at all) — callers treat "can't resolve" as "don't
 * assume this destination is safe to keep," never as "assume it's fine." */
function resolveDestArrayPageRef(value: PDFObject | undefined): PDFRef | undefined {
  if (!(value instanceof PDFArray) || value.size() === 0) return undefined;
  const first = value.get(0);
  return first instanceof PDFRef ? first : undefined;
}

/** Resolve a destination VALUE (as found in an outline item's `/Dest`, a
 * GoTo action's `/D`, or a `/Dests`/name-tree entry) to its target page ref.
 * Handles an indirect reference to the array, and the `{ D: [...] }` wrapper
 * form the name tree sometimes uses. A destination named indirectly by a
 * PDF name/string (rather than holding the array itself) is NOT followed
 * further — that would require cross-referencing the `/Dests` tree from
 * inside its own construction, so it's a documented gap: such a destination
 * degrades to "unresolved," never to a guess. */
function resolveDestTargetPageRef(
  context: PDFContext,
  value: PDFObject | undefined,
): PDFRef | undefined {
  let resolved: PDFObject | undefined = value;
  if (resolved instanceof PDFRef) resolved = context.lookup(resolved);
  if (resolved instanceof PDFArray) return resolveDestArrayPageRef(resolved);
  if (resolved instanceof PDFDict) {
    return resolveDestTargetPageRef(context, resolved.get(PDFName.of("D")));
  }
  return undefined;
}

/** Whether an outline item names a page at all, and if so, which one. An
 * item with neither `/Dest` nor a `/A` GoTo action (a URI link, a JavaScript
 * action, a pure container heading) is `pageDependent: false` — it has no
 * relationship to the page set and is always kept untouched, regardless of
 * what got deleted. */
function outlineItemPageDependency(
  context: PDFContext,
  item: PDFDict,
): { pageDependent: boolean; targetRef?: PDFRef } {
  const dest = item.get(PDFName.of("Dest"));
  if (dest !== undefined) {
    return { pageDependent: true, targetRef: resolveDestTargetPageRef(context, dest) };
  }
  const action = item.lookupMaybe(PDFName.of("A"), PDFDict);
  if (action && action.get(PDFName.of("S")) === PDFName.of("GoTo")) {
    return {
      pageDependent: true,
      targetRef: resolveDestTargetPageRef(context, action.get(PDFName.of("D"))),
    };
  }
  return { pageDependent: false };
}

interface BuiltOutlineItem {
  ref: PDFRef;
  children: BuiltOutlineItem[];
}

/** Fields the tree-linking step (`linkOutlineSiblings`) rebuilds itself —
 * never copied verbatim from the source item, since the source's own
 * Parent/Prev/Next/First/Last/Count describe a tree shape that pruning may
 * have changed. `Dest`/`A` are handled separately too (only copied when the
 * destination survives), so they're excluded from the generic field copy. */
const OUTLINE_STRUCTURAL_KEYS = new Set([
  PDFName.of("Parent"),
  PDFName.of("Prev"),
  PDFName.of("Next"),
  PDFName.of("First"),
  PDFName.of("Last"),
  PDFName.of("Count"),
  PDFName.of("Dest"),
  PDFName.of("A"),
]);

/** Recursively rebuild one sibling level of the outline tree (the items
 * chained via `/Next` starting at `firstRef`), keeping an item if its own
 * destination survives OR at least one descendant's does; an item that
 * survives only via a descendant degrades to a destination-less container
 * rather than carrying a dangling/incorrect `/Dest`. Returns the rebuilt
 * siblings in order, unlinked (the caller wires Parent/Prev/Next/First/Last). */
function rebuildOutlineSiblings(
  copier: PDFObjectCopier,
  srcContext: PDFContext,
  dstContext: PDFContext,
  firstRef: PDFObject | undefined,
  keptSrcPageRefs: Set<PDFRef>,
): BuiltOutlineItem[] {
  const built: BuiltOutlineItem[] = [];
  const seen = new Set<PDFRef>(); // guards against a malformed cyclic /Next chain
  let cursor: PDFObject | undefined = firstRef;
  while (cursor instanceof PDFRef) {
    if (seen.has(cursor)) break;
    seen.add(cursor);
    const item = srcContext.lookupMaybe(cursor, PDFDict);
    if (!item) break;

    const children = rebuildOutlineSiblings(
      copier,
      srcContext,
      dstContext,
      item.get(PDFName.of("First")),
      keptSrcPageRefs,
    );

    const { pageDependent, targetRef } = outlineItemPageDependency(srcContext, item);
    const targetSurvives = !pageDependent || (targetRef !== undefined && keptSrcPageRefs.has(targetRef));

    if (pageDependent && !targetSurvives && children.length === 0) {
      cursor = item.get(PDFName.of("Next"));
      continue; // nothing left of this item; drop it
    }

    const newDict = dstContext.obj({});
    for (const [key, value] of item.entries()) {
      if (OUTLINE_STRUCTURAL_KEYS.has(key)) continue;
      newDict.set(key, copier.copy(value));
    }
    if (targetSurvives) {
      const dest = item.get(PDFName.of("Dest"));
      const action = item.get(PDFName.of("A"));
      if (dest !== undefined) newDict.set(PDFName.of("Dest"), copier.copy(dest));
      else if (action !== undefined) newDict.set(PDFName.of("A"), copier.copy(action));
    }
    // else: pageDependent, but its target page was deleted — the item
    // survives only because a descendant does, so it degrades to a plain
    // (destination-less) container rather than carrying a dangling ref.

    built.push({ ref: dstContext.register(newDict), children });
    cursor = item.get(PDFName.of("Next"));
  }
  return built;
}

/** Total descendant count of a rebuilt subtree, every surviving item counted
 * as OPEN — a deliberate simplification (see `copyOutlineForExtractedPages`)
 * rather than trying to preserve each item's original open/closed `/Count`
 * sign across a pruned tree shape. */
function subtreeDescendantCount(children: BuiltOutlineItem[]): number {
  let total = 0;
  for (const child of children) total += 1 + subtreeDescendantCount(child.children);
  return total;
}

/** Wire Parent/Prev/Next/First/Last/Count across a rebuilt sibling level
 * (and recursively, its children), onto the already-registered dst dicts
 * `rebuildOutlineSiblings` produced. */
function linkOutlineSiblings(
  dstContext: PDFContext,
  siblings: BuiltOutlineItem[],
  parentRef: PDFRef,
): void {
  for (let i = 0; i < siblings.length; i++) {
    const dict = dstContext.lookup(siblings[i].ref, PDFDict);
    dict.set(PDFName.of("Parent"), parentRef);
    if (i > 0) dict.set(PDFName.of("Prev"), siblings[i - 1].ref);
    if (i < siblings.length - 1) dict.set(PDFName.of("Next"), siblings[i + 1].ref);

    const kids = siblings[i].children;
    if (kids.length > 0) {
      linkOutlineSiblings(dstContext, kids, siblings[i].ref);
      dict.set(PDFName.of("First"), kids[0].ref);
      dict.set(PDFName.of("Last"), kids[kids.length - 1].ref);
      dict.set(PDFName.of("Count"), PDFNumber.of(subtreeDescendantCount(kids)));
    }
  }
}

/** Copy the `/Outlines` bookmark tree onto the extracted subset, keeping a
 * bookmark whose destination resolves to a RETAINED page (remapped for free
 * via `copier`'s cache — see the module-doc comment above) and dropping one
 * that targets the DELETED page, unless it has a surviving descendant, in
 * which case it degrades to a plain container. A bookmark with no page
 * destination at all (a URI link, a JavaScript action, a heading with
 * neither) is never touched. Every surviving item is reported OPEN
 * (`/Count` positive) regardless of the source's collapsed state — cosmetic,
 * not a correctness or leak concern. */
function copyOutlineForExtractedPages(
  src: PDFDocument,
  dst: PDFDocument,
  copier: PDFObjectCopier,
  keptSrcPageRefs: Set<PDFRef>,
): void {
  const outlinesRef = src.catalog.get(PDFName.of("Outlines"));
  if (outlinesRef === undefined) return;
  const outlines = src.context.lookupMaybe(outlinesRef, PDFDict);
  if (!outlines) return;

  const topLevel = rebuildOutlineSiblings(
    copier,
    src.context,
    dst.context,
    outlines.get(PDFName.of("First")),
    keptSrcPageRefs,
  );
  if (topLevel.length === 0) return;

  const dstOutlines = dst.context.obj({ Type: PDFName.of("Outlines") });
  const dstOutlinesRef = dst.context.register(dstOutlines);
  linkOutlineSiblings(dst.context, topLevel, dstOutlinesRef);
  dstOutlines.set(PDFName.of("First"), topLevel[0].ref);
  dstOutlines.set(PDFName.of("Last"), topLevel[topLevel.length - 1].ref);
  dstOutlines.set(PDFName.of("Count"), PDFNumber.of(subtreeDescendantCount(topLevel)));

  dst.catalog.set(PDFName.of("Outlines"), dstOutlinesRef);
}

/** Copy `/Info` (Title/Author/Subject/Keywords/Creator/CreationDate/custom
 * fields...) across UNMODIFIED. This matches the existing convention for
 * every OTHER page op in this file: `reorderPages`/`movePage` never touch
 * `/Info` at all, because they mutate the loaded document in place rather
 * than rebuilding the catalog — so its natural "preserved" state is simply
 * "left alone." No preserve-metadata TOGGLE applies here: `preserveMetadata`
 * (`src/ipc/redact.ts`, `src/preserveMetadataPref.ts`) gates whether the Rust
 * redaction ENGINE scrubs `/Info` as part of removing sensitive content; a
 * page delete was never a metadata-scrubbing operation, so its own catalog
 * rebuild has no reason to invent a competing toggle — it just carries
 * whatever was already there, like its siblings do. */
function copyInfoForExtractedPages(src: PDFDocument, dst: PDFDocument, copier: PDFObjectCopier): void {
  const info = src.context.trailerInfo.Info;
  if (info === undefined) return;
  dst.context.trailerInfo.Info = copier.copy(info);
}

/** Copy `/ViewerPreferences` (page layout/mode, print scaling, etc.) across
 * as-is — it never references a page, so there's nothing to prune. */
function copyViewerPreferencesForExtractedPages(
  src: PDFDocument,
  dst: PDFDocument,
  copier: PDFObjectCopier,
): void {
  const key = PDFName.of("ViewerPreferences");
  const value = src.catalog.get(key);
  if (value === undefined) return;
  dst.catalog.set(key, copier.copy(value));
}

/** Remap the `/PageLabels` number tree onto the extracted page subset, using
 * the same old-index -> new-index mapping `extractPages` computes for its
 * own bookkeeping. Only the flat shape (`{ Nums: [...] }` directly on the
 * root, no `/Kids` sub-trees — what any ordinarily-sized document produces)
 * is handled; a split tree is left un-restored rather than guessed at. A
 * `/Nums` entry keyed at the deleted page's index describes a labelling
 * range that started there and has no home after the delete, so it is
 * dropped rather than kept under a fabricated new key. */
function copyPageLabelsForExtractedPages(
  src: PDFDocument,
  dst: PDFDocument,
  copier: PDFObjectCopier,
  oldIndexToNewIndex: Map<number, number>,
): void {
  const ref = src.catalog.get(PDFName.of("PageLabels"));
  if (ref === undefined) return;
  const tree = src.context.lookupMaybe(ref, PDFDict);
  if (!tree) return;
  const nums = tree.lookupMaybe(PDFName.of("Nums"), PDFArray);
  if (!nums) return; // /Kids-split tree: not restored (documented gap)

  const remapped: { newIndex: number; value: PDFObject }[] = [];
  for (let i = 0; i + 1 < nums.size(); i += 2) {
    const key = nums.get(i);
    if (!(key instanceof PDFNumber)) continue;
    const newIndex = oldIndexToNewIndex.get(key.asNumber());
    if (newIndex === undefined) continue; // this range started on the deleted page
    remapped.push({ newIndex, value: nums.get(i + 1) });
  }
  if (remapped.length === 0) return;
  remapped.sort((a, b) => a.newIndex - b.newIndex); // number-tree keys must be ascending

  const dstNums = PDFArray.withContext(dst.context);
  for (const { newIndex, value } of remapped) {
    dstNums.push(PDFNumber.of(newIndex));
    dstNums.push(copier.copy(value));
  }
  const dstTree = dst.context.obj({ Nums: dstNums });
  dst.catalog.set(PDFName.of("PageLabels"), dst.context.register(dstTree));
}

/** Copy named destinations, dropping any entry whose target page was
 * deleted (never remapping-and-keeping a dangling one). Handles both the
 * legacy `/Dests` catalog dictionary (PDF 1.1) and the `/Names /Dests` name
 * tree (PDF 1.2+, flat shape only — a `/Kids`-split tree is left
 * un-restored, same documented gap as `/PageLabels` above). Like outline
 * destinations, a surviving target's ref is remapped for free by `copier`'s
 * cache. */
function copyNamedDestinationsForExtractedPages(
  src: PDFDocument,
  dst: PDFDocument,
  copier: PDFObjectCopier,
  keptSrcPageRefs: Set<PDFRef>,
): void {
  const legacyRef = src.catalog.get(PDFName.of("Dests"));
  const legacyDests = src.context.lookupMaybe(legacyRef, PDFDict);
  if (legacyDests) {
    const dstDests = dst.context.obj({});
    let any = false;
    for (const [name, value] of legacyDests.entries()) {
      const target = resolveDestTargetPageRef(src.context, value);
      if (!target || !keptSrcPageRefs.has(target)) continue;
      dstDests.set(name, copier.copy(value));
      any = true;
    }
    if (any) dst.catalog.set(PDFName.of("Dests"), dst.context.register(dstDests));
  }

  const namesRef = src.catalog.get(PDFName.of("Names"));
  const namesDict = src.context.lookupMaybe(namesRef, PDFDict);
  const destTreeRef = namesDict?.get(PDFName.of("Dests"));
  const destTree = namesDict && src.context.lookupMaybe(destTreeRef, PDFDict);
  const namesArr = destTree?.lookupMaybe(PDFName.of("Names"), PDFArray);
  if (!namesArr) return; // absent, or a /Kids-split tree: not restored

  const dstNames = PDFArray.withContext(dst.context);
  let anyNamed = false;
  for (let i = 0; i + 1 < namesArr.size(); i += 2) {
    const nameObj = namesArr.get(i);
    const value = namesArr.get(i + 1);
    const target = resolveDestTargetPageRef(src.context, value);
    if (!target || !keptSrcPageRefs.has(target)) continue;
    dstNames.push(copier.copy(nameObj));
    dstNames.push(copier.copy(value));
    anyNamed = true;
  }
  if (!anyNamed) return;
  const dstDestTree = dst.context.obj({ Names: dstNames });
  const dstNamesDict = dst.context.obj({ Dests: dst.context.register(dstDestTree) });
  dst.catalog.set(PDFName.of("Names"), dst.context.register(dstNamesDict));
}

export interface ExtractPagesOptions {
  preserveCatalog?: boolean;
  /** omitly#1841: called with the private source copy BEFORE anything in it is
   *  changed or copied. The page tools use it to read facts about the source
   *  (layers, XFA, labels), to refuse a file they cannot edit, and to remove
   *  digital signatures from the SOURCE so a signature value never reaches the
   *  copier (removing it afterwards would leave the signer's certificate in the
   *  output as an unreachable but byte-recoverable object). */
  inspectSource?: (src: PDFDocument) => void;
}

/** Extract the given page indices into a brand-new document. By default,
 * document-level structures are dropped (a bookmark tree naming pages that
 * no longer exist has no home in a subset document) — the `bytesForPrint`
 * range-print path relies on exactly that, disclosed to the user as lossy.
 * `{ preserveCatalog: true }` (used by `deletePage`, omitly#1007) instead
 * copies+prunes them onto the fresh catalog: `/Outlines`, `/Info`,
 * `/PageLabels`, named destinations (`/Dests` and `/Names /Dests`) and
 * `/ViewerPreferences` — see each helper above for exactly what's covered
 * and the two documented gaps (a `/Kids`-split number/name tree; a
 * destination named indirectly by name/string rather than a direct array).
 * The AcroForm is ALWAYS carried across regardless of the option, pruned to
 * only the fields whose widgets are actually present on an extracted page,
 * so a field left entirely behind is dropped rather than becoming a
 * dangling reference. */
export async function extractPagesDoc(
  bytes: Uint8Array,
  indices: number[],
  options: ExtractPagesOptions = {},
): Promise<PDFDocument> {
  if (indices.length === 0) throw new Error("no pages selected");
  const src = await load(bytes);
  options.inspectSource?.(src);
  await src.flush();
  return buildExtraction(src, src.getPages(), indices, options.preserveCatalog === true, undefined);
}

export interface ExtractionSession {
  pageCount: number;
  /** One extraction from the already-parsed source. Sequential use only. The source is left exactly
   *  as it was parsed (plus whatever `inspectSource` did once), so any range, in any order, any
   *  number of times, gives what a fresh `extractPagesDoc` would. */
  extract(indices: number[], options?: { preserveCatalog?: boolean }): Promise<PDFDocument>;
}

/** Parse `bytes` ONCE for many extractions (omitly#1841 `split_pdf`: one per range). The default-deny
 * steps still run in full for every extraction; their mutations of the source are journaled and
 * undone afterwards, so nothing one range blanked out is missing from the next. */
export async function openExtractionSession(
  bytes: Uint8Array,
  options: { inspectSource?: (src: PDFDocument) => void } = {},
): Promise<ExtractionSession> {
  const src = await load(bytes);
  options.inspectSource?.(src);
  await src.flush();
  const srcPages = src.getPages();
  return {
    pageCount: srcPages.length,
    async extract(indices, o = {}) {
      const journal = new Journal();
      try {
        return await buildExtraction(src, srcPages, indices, o.preserveCatalog === true, journal);
      } finally {
        journal.restore();
      }
    },
  };
}

async function buildExtraction(
  src: PDFDocument,
  srcPages: PDFPage[],
  indices: number[],
  preserveCatalog: boolean,
  journal: Journal | undefined,
): Promise<PDFDocument> {
  if (indices.length === 0) throw new Error("no pages selected");
  const dst = await PDFDocument.create({ updateMetadata: false });
  const keptIndices = new Set<number>();
  for (const i of indices) {
    if (!srcPages[i]) throw new Error(`no page ${i}`);
    if (keptIndices.has(i)) throw new Error(`page ${i} selected twice`);
    keptIndices.add(i);
  }
  const extractedSrcPages = indices.map((i) => srcPages[i]);

  // BEFORE anything is copied, blank out every page the user did NOT select in
  // our private copy of the source. See neuterPage: this is what makes the
  // extraction default-deny rather than dependent on having enumerated every
  // possible back-reference into an excluded page.
  srcPages.forEach((page, i) => {
    if (keptIndices.has(i)) return;
    detachWidgetsFromFields(src.context, page, journal);
    neuterPage(src.context, page, journal);
  });
  // By enumeration, not by following routes (omitly#1841, Codex): after the steps above, in any order.
  scrubFieldsOutsideKept(src, extractedSrcPages, journal);

  // Copy pages with our OWN PDFObjectCopier (rather than the doc.copyPages()
  // convenience method, which would spin up its own copier and discard it)
  // so the AcroForm copy below can reuse the SAME src->dst object cache: a
  // merged field/widget dict already copied as part of a page's /Annots must
  // resolve to that identical destination object, not a duplicate.
  const copier = PDFObjectCopier.for(src.context, dst.context);
  const copied: PDFPage[] = [];
  for (const srcPage of extractedSrcPages) {
    // Copy by REF, not by node. Copying the node hands the copier a fresh clone
    // it has never seen, so its cache is keyed on an object nothing else points
    // at — and a widget's `/P` back-reference to this same page then copies the
    // page a SECOND time, as an orphan duplicate. Going through the ref caches
    // src-ref -> dst-ref, so every back-reference lands on the one real copy.
    const ref = copier.copy(srcPage.ref);
    const node = dst.context.lookup(ref);
    if (!(node instanceof PDFPageLeaf)) throw new Error(`page ${indices[copied.length]} did not copy`);
    copied.push(PDFPage.of(node, ref, dst));
  }
  copied.forEach((p) => dst.addPage(p));

  copyAcroFormForExtractedPages(src, dst, copier, extractedSrcPages);

  if (preserveCatalog) {
    const keptSrcPageRefs = new Set(extractedSrcPages.map((p) => p.ref));
    // Position within `indices` IS the new page index — both call sites
    // (deletePage's ascending `keep`, bytesForPrint's pre-sorted range) build
    // `indices` in output order already.
    const oldIndexToNewIndex = new Map<number, number>();
    indices.forEach((oldIndex, newIndex) => oldIndexToNewIndex.set(oldIndex, newIndex));

    copyOutlineForExtractedPages(src, dst, copier, keptSrcPageRefs);
    copyInfoForExtractedPages(src, dst, copier);
    copyPageLabelsForExtractedPages(src, dst, copier, oldIndexToNewIndex);
    copyNamedDestinationsForExtractedPages(src, dst, copier, keptSrcPageRefs);
    copyViewerPreferencesForExtractedPages(src, dst, copier);
  }

  return dst;
}

/** Extract the given page indices into a brand-new document and save it. */
export async function extractPages(
  bytes: Uint8Array,
  indices: number[],
  options: { preserveCatalog?: boolean } = {},
): Promise<Uint8Array> {
  const dst = await extractPagesDoc(bytes, indices, options);
  return dst.save();
}
