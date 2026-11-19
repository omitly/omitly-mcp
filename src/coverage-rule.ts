/**
 * omitly#1864 round 6: the ONE definition of which `not_scanned` disclosures deny completion, shared by every
 * surface that reads a coverage (the engine-reply parser, the card envelope parser; the MCPB bundle's CommonJS
 * port in `mcpb/server/replies.js` holds the same patterns, compared by a test), so the surfaces cannot drift apart.
 * Browser-safe: no imports.
 *
 * Line terminators: an interpolated name (the attachment filename, detect.rs:4024) comes from the PDF and may contain
 * any character, a newline and U+2028/U+2029 included. `.` does not match those, so a wildcard over a name is
 * `[\s\S]`, never `.`; a test sweeps every pattern's source for a bare wildcard.
 */

/**
 * The `not_scanned` lines crates/redaction-core/src/detect.rs writes exactly when it holds `scan_complete`
 * false (detect.rs:4596-4612 for the flag; the lines at :4640-4745): an image-only page, CID text with an
 * unmapped code, a Type0 codespace that could not be verified, embedded streams that failed, Form XObject
 * text in an inherited font, an attachment tree that could not be walked, a page whose survivors could not be
 * checked, a prior revision that could not be scanned, the unread off-page streams
 * (`scan_nonpage_detail`: the AcroForm depth note, the XMP and attachment lines) and a file structure that
 * did not read the same way twice. The native `find` sends none of the matching `*_failed` / `*_unread`
 * fields, so for it these lines are the only evidence. Other disclosures are legitimate limits and do not
 * deny completion: "text drawn as raster images (needs OCR)" and the suspect-font line (omitly#1519).
 */
export const ENGINE_INCOMPLETE_DISCLOSURES: RegExp[] = [
  /^\d+ page\(s\) are effectively image-only/,
  /^CID\/Identity-H text with a code not covered by the ToUnicode map/,
  /^Type0\/CID text using a named encoding whose codespace ranges could not be verified/,
  /^\d+ embedded content stream\(s\) that failed to parse or could not be fully decoded/,
  /^\d+ Form XObject\(s\) showing text in a font set by the page that draws them/,
  /^embedded-file attachment name tree could not be fully scanned/,
  /^\d+ page\(s\) could not be fully checked for text surviving under a redaction mark/,
  /^\d+ prior \(superseded\) revision\(s\) could not be scanned for leftover PII/,
  /^AcroForm field tree deeper than 16 levels was not fully scanned/,
  /^document information, form fields and attachments: /,
  /^XMP metadata stream (was |could not be read as text)/,
  /^attachment '[\s\S]*' was /,
  /^the file's structure \(object streams, cross-reference data or stream lengths\) did not read the same way twice/,
];


/** The first `not_scanned` line that denies completion, or null. Any non-string entry is not a disclosure and is ignored. */
export function engineIncompleteDisclosure(lines: readonly unknown[]): string | null {
  for (const line of lines) if (typeof line === "string" && ENGINE_INCOMPLETE_DISCLOSURES.some((re) => re.test(line))) return line;
  return null;
}

/**
 * Contract §4 / §6.4: the text label of a `not_scanned` line. No file-derived string (a filename, a font name, `{e}`, `{reason}`,
 * `{why}`) is ever written into a text; the raw lines stay in `structuredContent.coverage.notScanned`. Every line gets one label,
 * unknown ones the last. `[\s\S]*` in the attachment row for the same reason as above.
 */
const DISCLOSURE_LABELS: [RegExp, string][] = [
  [/^\d+ page\(s\) are effectively image-only/, "pages that are images only"],
  [/^text drawn as raster images \(needs OCR\)$/, "text drawn as images (not OCR'd)"],
  [/^CID\/Identity-H text with a code not covered by the ToUnicode map/, "text in a font that could not be decoded"],
  [/^text in font\(s\) /, "text whose drawn characters could not be confirmed"],
  [/^Type0\/CID text using a named encoding whose codespace ranges could not be verified/, "text in a font that could not be decoded"],
  [/^\d+ embedded content stream\(s\) that failed to parse or could not be fully decoded/, "content streams that could not be read"],
  [/^\d+ Form XObject\(s\) showing text in a font set by the page that draws them/, "form text that may be misread"],
  [/^embedded-file attachment name tree could not be fully scanned/, "attachments that could not be listed"],
  [/^\d+ page\(s\) could not be fully checked for text surviving under a redaction mark/, "pages where text under a mark could not be checked"],
  [/^\d+ prior \(superseded\) revision\(s\) could not be scanned for leftover PII/, "earlier versions that could not be read"],
  [/^the file's structure \(object streams, cross-reference data or stream lengths\) did not read the same way twice/, "parts of the file structure"],
  [/^AcroForm field tree deeper than 16 levels was not fully scanned/, "form fields nested too deep"],
  [/^document information, form fields and attachments: /, "document information, form fields and attachments"],
  [/^XMP metadata stream (was |could not be read as text)/, "the XMP metadata"],
  [/^attachment '[\s\S]*' was /, "an attachment"],
];
export function disclosureLabel(line: unknown): string {
  if (typeof line !== "string") return "a part of the file this server cannot name";
  for (const [re, label] of DISCLOSURE_LABELS) if (re.test(line)) return label;
  return "a part of the file this server cannot name";
}
