/**
 * omitly#1841 phase B: PDF fixtures and probes shared by the page-tool tests.
 *
 * Named `.test.ts` so the package's `!dist/**\/*.test.*` rule keeps it out of the tarball; the
 * only test here proves the fixtures themselves (positive controls for the probes the other
 * files rely on). Every PDF is generated with the real pdf-lib; nothing is read from outside
 * the test's own temp folder.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtempSync, readdirSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerEditTools, type EditToolsOptions } from "./edit-tools.js";
import { tmpdir } from "node:os";
import * as path from "node:path";
import {
  PDFArray,
  PDFBool,
  PDFDict,
  PDFDocument,
  PDFHexString,
  PDFName,
  PDFRawStream,
  PDFRef,
  PDFString,
  StandardFonts,
  decodePDFRawStream,
  type PDFObject,
} from "pdf-lib";

/** Windows without the symlink privilege (or Developer Mode) cannot create links at all: the tests that
 *  need one are skipped there, not failed. Always true on macOS and Linux. */
export const canSymlink = ((): boolean => {
  const d = mkdtempSync(path.join(tmpdir(), "omitly-symlink-probe-"));
  try {
    symlinkSync(d, path.join(d, "l"));
    return true;
  } catch {
    return false;
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
})();

export function tempRoot(prefix = "omitly-edit-"): string {
  // realpath: macOS's $TMPDIR sits under /var, a symlink to /private/var.
  return realpathSync(mkdtempSync(path.join(tmpdir(), prefix)));
}

/** A document with `count` pages; page i is 300+10i wide, 400 tall, draws the text
 *  `${tag}-${i+1}` in its content stream and carries `/OmitlyMarker (${tag}-${i+1})` in its page dictionary. */
export async function makeDoc(tag: string, count: number, build?: (doc: PDFDocument) => void): Promise<Uint8Array> {
  const doc = await PDFDocument.create();
  const font = await doc.embedFont(StandardFonts.Helvetica);
  for (let i = 0; i < count; i++) {
    const page = doc.addPage([300 + 10 * i, 400]);
    page.drawText(`${tag}-${i + 1}`, { x: 20, y: 200, size: 18, font });
    page.node.set(PDFName.of("OmitlyMarker"), PDFString.of(`${tag}-${i + 1}`));
  }
  build?.(doc);
  return doc.save();
}

/** True if `marker` is anywhere in the file: drawn by ANY stream (every stream object is
 *  decoded, because pdf-lib compresses what it writes), or held as a string in ANY object's
 *  dictionary or array (the page-dictionary marker; objects inside object streams included). */
export async function fileContainsMarker(bytes: Uint8Array, marker: string): Promise<boolean> {
  const doc = await PDFDocument.load(bytes, { ignoreEncryption: true });
  const hex = Buffer.from(marker, "latin1").toString("hex").toLowerCase();
  const seen = new Set<PDFObject>();
  const inValue = (v: PDFObject | undefined): boolean => {
    if (v === undefined || seen.has(v)) return false;
    seen.add(v);
    if (v instanceof PDFString) return v.decodeText() === marker;
    if (v instanceof PDFHexString) return v.decodeText() === marker || Buffer.from(v.asBytes()).toString("latin1").includes(marker);
    if (v instanceof PDFArray) return v.asArray().some(inValue);
    if (v instanceof PDFDict) return [...v.entries()].some(([, x]) => inValue(x));
    return false;
  };
  for (const [, obj] of doc.context.enumerateIndirectObjects()) {
    if (obj instanceof PDFRawStream) {
      const text = Buffer.from(decodePDFRawStream(obj).decode()).toString("latin1").toLowerCase();
      if (text.includes(`<${hex}>`) || text.includes(`(${marker.toLowerCase()})`)) return true;
      if (inValue(obj.dict)) return true;
    } else if (inValue(obj)) return true;
  }
  return false;
}

/** The marker of each page's dictionary, in page order. */
export async function pageMarkers(bytes: Uint8Array): Promise<string[]> {
  const doc = await PDFDocument.load(bytes);
  return doc.getPages().map((p) => p.node.lookupMaybe(PDFName.of("OmitlyMarker"), PDFString)?.decodeText() ?? "");
}

export const widths = async (bytes: Uint8Array): Promise<number[]> =>
  (await PDFDocument.load(bytes)).getPages().map((p) => Math.round(p.getWidth()));

/** An /Encrypt entry in the trailer (pdf-lib cannot encrypt; this is what makes it refuse to load). */
export async function makeEncrypted(count = 2): Promise<Uint8Array> {
  const doc = await PDFDocument.create();
  for (let i = 0; i < count; i++) doc.addPage([200, 200]);
  doc.context.trailerInfo.Encrypt = doc.context.register(
    doc.context.obj({ Filter: "Standard", V: 1, R: 2, O: PDFHexString.of("00"), U: PDFHexString.of("00"), P: -4 }),
  );
  return doc.save();
}

export const CERT_MARKER = "CERT-BYTES-UNIQUE-0123456789";
export const SIG_AP_MARKER = "SIG-APPEARANCE-MARKER";

/** A signed document: a signature field whose /V holds a signature dictionary (ByteRange, a
 *  Contents blob that embeds CERT_MARKER) and whose widget has an /AP that draws SIG_AP_MARKER.
 *  `variant` "kid" puts /FT and /V on a parent field and the appearance on a widget kid. */
export async function makeSigned(variant: "merged" | "kid" = "merged", pages = 2): Promise<Uint8Array> {
  const doc = await PDFDocument.create();
  const font = await doc.embedFont(StandardFonts.Helvetica);
  for (let i = 0; i < pages; i++) {
    const p = doc.addPage([300, 400]);
    p.drawText(`SIGNED-${i + 1}`, { x: 20, y: 200, size: 18, font });
    p.node.set(PDFName.of("OmitlyMarker"), PDFString.of(`SIGNED-${i + 1}`));
  }
  const ctx = doc.context;
  const sigDict = ctx.obj({
    Type: "Sig",
    Filter: "Adobe.PPKLite",
    SubFilter: "adbe.pkcs7.detached",
    ByteRange: [0, 10, 20, 10],
    Contents: PDFHexString.fromText(`${CERT_MARKER}-${"0".repeat(40)}`),
    M: PDFString.of("D:20260101000000Z"),
  });
  const sigRef = ctx.register(sigDict);
  const ap = ctx.register(ctx.flateStream(`BT /F1 9 Tf (${SIG_AP_MARKER}) Tj ET`, { Type: "XObject", Subtype: "Form", BBox: [0, 0, 100, 40] }));
  const page0 = doc.getPages()[0];
  let fieldRef: PDFRef;
  if (variant === "merged") {
    const widget = ctx.obj({
      Type: "Annot", Subtype: "Widget", FT: "Sig", T: PDFString.of("Signature1"),
      Rect: [10, 10, 110, 50], F: 4, V: sigRef, P: page0.ref, AP: { N: ap },
    });
    fieldRef = ctx.register(widget);
    page0.node.set(PDFName.of("Annots"), ctx.obj([fieldRef]));
  } else {
    const field = ctx.obj({ FT: "Sig", T: PDFString.of("Signature1"), V: sigRef });
    fieldRef = ctx.register(field);
    const widget = ctx.obj({
      Type: "Annot", Subtype: "Widget", Rect: [10, 10, 110, 50], F: 4, P: page0.ref, Parent: fieldRef, AP: { N: ap },
    });
    const widgetRef = ctx.register(widget);
    field.set(PDFName.of("Kids"), ctx.obj([widgetRef]));
    page0.node.set(PDFName.of("Annots"), ctx.obj([widgetRef]));
  }
  doc.catalog.set(PDFName.of("AcroForm"), ctx.obj({ Fields: [fieldRef], SigFlags: 3 }));
  return doc.save();
}

/** Everything in the file that identifies a signature, as human-readable strings. Empty = clean. */
export async function signatureTraces(bytes: Uint8Array): Promise<string[]> {
  const doc = await PDFDocument.load(bytes);
  const found: string[] = [];
  for (const [ref, obj] of doc.context.enumerateIndirectObjects()) {
    const where = ref.toString();
    const dict = obj instanceof PDFRawStream ? obj.dict : obj;
    if (dict instanceof PDFDict) {
      if (dict.get(PDFName.of("ByteRange")) !== undefined) found.push(`${where}: /ByteRange`);
      if (dict.get(PDFName.of("Type")) === PDFName.of("Sig")) found.push(`${where}: /Type /Sig`);
      if (dict.get(PDFName.of("SubFilter")) !== undefined) found.push(`${where}: /SubFilter`);
    }
    const scan = (v: PDFObject | undefined, depth = 0): void => {
      if (v === undefined || depth > 64) return;
      if (v instanceof PDFHexString || v instanceof PDFString) {
        const s = Buffer.from(v.asBytes()).toString("latin1") + v.decodeText();
        if (s.includes(CERT_MARKER)) found.push(`${where}: certificate bytes`);
      } else if (v instanceof PDFArray) v.asArray().forEach((x) => scan(x, depth + 1));
      else if (v instanceof PDFDict) for (const [, x] of v.entries()) scan(x, depth + 1);
    };
    scan(dict);
    if (obj instanceof PDFRawStream) {
      const text = Buffer.from(decodePDFRawStream(obj).decode()).toString("latin1");
      if (text.includes(SIG_AP_MARKER)) found.push(`${where}: signature appearance stream`);
      if (text.includes(CERT_MARKER)) found.push(`${where}: certificate bytes in a stream`);
    }
  }
  const acro = doc.catalog.AcroForm();
  if (acro?.get(PDFName.of("SigFlags")) !== undefined) found.push("AcroForm /SigFlags");
  return found;
}

/** Catalog extras for the `lost` tests. */
export function addCatalogExtras(doc: PDFDocument, which: { layers?: boolean; labels?: boolean; outlines?: boolean; xfa?: "static" | "dynamic" }): void {
  const ctx = doc.context;
  if (which.layers) doc.catalog.set(PDFName.of("OCProperties"), ctx.obj({ OCGs: [], D: {} }));
  if (which.labels) doc.catalog.set(PDFName.of("PageLabels"), ctx.register(ctx.obj({ Nums: [0, { S: "D" }] })));
  if (which.outlines) {
    const item = ctx.register(ctx.obj({ Title: PDFString.of("Chapter"), Dest: [doc.getPages()[0].ref, "Fit"] }));
    const root = ctx.register(ctx.obj({ Type: "Outlines", First: item, Last: item, Count: 1 }));
    ctx.lookup(item, PDFDict).set(PDFName.of("Parent"), root);
    doc.catalog.set(PDFName.of("Outlines"), root);
  }
  if (which.xfa) {
    const acro = doc.catalog.AcroForm() ?? ctx.obj({ Fields: [] });
    acro.set(PDFName.of("XFA"), ctx.obj([PDFString.of("template"), ctx.register(ctx.stream("<xdp/>"))]));
    if (which.xfa === "dynamic") acro.set(PDFName.of("NeedsRendering"), PDFBool.True);
    doc.catalog.set(PDFName.of("AcroForm"), acro);
  }
}

/** A form with `n` text fields on page 1. */
export async function makeForm(n = 2): Promise<Uint8Array> {
  const doc = await PDFDocument.create();
  const page = doc.addPage([300, 400]);
  const form = doc.getForm();
  for (let i = 0; i < n; i++) {
    const f = form.createTextField(`field${i + 1}`);
    f.addToPage(page, { x: 20, y: 300 - 40 * i, width: 100, height: 20 });
  }
  return doc.save();
}

/** Codex finding 1: AcroForm Fields [group]; group {T group, FT Tx, Kids [keep, drop]}; each of keep/drop
 *  has a filled /V (a STRING, which a field walker must tolerate) and drop also a /DV; their widgets sit
 *  on page 1 and page 2. Pages carry the markers G-1 and G-2. */
export async function makeSharedParentForm(): Promise<Uint8Array> {
  return makeDoc("G", 2, (doc) => {
    const c = doc.context;
    const [p1, p2] = doc.getPages();
    const group = c.register(c.obj({ T: PDFString.of("group"), FT: "Tx" }));
    const keep = c.register(c.obj({ T: PDFString.of("keep"), Parent: group, V: PDFString.of("KEPT-VALUE") }));
    const drop = c.register(c.obj({ T: PDFString.of("drop"), Parent: group, V: PDFString.of("SECRET-V-DROP"), DV: PDFString.of("SECRET-DV-DROP") }));
    const wk = c.register(c.obj({ Type: "Annot", Subtype: "Widget", Rect: [10, 10, 100, 30], Parent: keep, P: p1.ref }));
    const wd = c.register(c.obj({ Type: "Annot", Subtype: "Widget", Rect: [10, 10, 100, 30], Parent: drop, P: p2.ref }));
    c.lookup(keep, PDFDict).set(PDFName.of("Kids"), c.obj([wk]));
    c.lookup(drop, PDFDict).set(PDFName.of("Kids"), c.obj([wd]));
    c.lookup(group, PDFDict).set(PDFName.of("Kids"), c.obj([keep, drop]));
    p1.node.set(PDFName.of("Annots"), c.obj([wk]));
    p2.node.set(PDFName.of("Annots"), c.obj([wd]));
    doc.catalog.set(PDFName.of("AcroForm"), c.obj({ Fields: [group] }));
  });
}

const HERE = path.dirname(fileURLToPath(import.meta.url));
/** The test stubs live in src/testing (not compiled); tests run from dist/. */
export const stub = (name: "edit-worker-hang" | "edit-worker-oom" | "edit-worker-stub"): string =>
  path.join(HERE, "..", "src", "testing", `${name}.mjs`);
/** Node options that select a stub mode (see edit-worker-stub.mjs). */
export const stubMode = (mode: string): string[] => [`--disable-warning=OMITLY_STUB_${mode}`];

export type ToolResult = {
  isError?: boolean;
  content?: { type: string; text: string }[];
  structuredContent?: any;
};

export const textOf = (res: ToolResult): string =>
  (res.content ?? []).filter((c) => c.type === "text").map((c) => c.text).join("\n");

/** Registers ONLY the five page tools on a fresh in-memory server and hands a client to `fn`. */
export async function withEditClient<T>(
  root: string,
  opts: EditToolsOptions,
  fn: (call: (name: string, args: Record<string, unknown>, signal?: AbortSignal) => Promise<ToolResult>, client: Client) => Promise<T>,
): Promise<T> {
  const server = new McpServer({ name: "edit-test", version: "0.0.0" });
  registerEditTools(server, { root, rootExplicit: true, ...opts });
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "edit-test-client", version: "0.0.0" });
  await Promise.all([server.connect(a), client.connect(b)]);
  try {
    return await fn(
      async (name, args, signal) => (await client.callTool({ name, arguments: args }, undefined, signal ? { signal } : undefined)) as ToolResult,
      client,
    );
  } finally {
    await client.close();
    await server.close();
  }
}

export function put(root: string, name: string, bytes: Uint8Array | string): string {
  const p = path.join(root, name);
  writeFileSync(p, bytes);
  return p;
}

/** Files in `root` (names only, sorted). */
export const ls = (root: string): string[] => readdirSync(root).sort();

test("fixtures: the probes see what the fixtures contain (positive controls)", async () => {
  const doc = await makeDoc("FX", 3);
  assert.ok(await fileContainsMarker(doc, "FX-2"), "content-stream and page-dictionary marker");
  assert.ok(!(await fileContainsMarker(doc, "FX-9")));
  assert.deepEqual(await pageMarkers(doc), ["FX-1", "FX-2", "FX-3"]);
  const signed = await makeSigned("merged");
  const traces = (await signatureTraces(signed)).join(" | ");
  for (const t of ["/ByteRange", "/Type /Sig", "certificate bytes", "signature appearance stream", "SigFlags"]) {
    assert.ok(traces.includes(t), `the signed fixture shows ${t}: ${traces}`);
  }
  assert.ok((await signatureTraces(await makeSigned("kid"))).length > 0);
  assert.deepEqual(await signatureTraces(doc), []);
  const enc = await makeEncrypted();
  await assert.rejects(() => PDFDocument.load(enc), /encrypt/i, "the encrypted fixture really is refused by pdf-lib");
});
