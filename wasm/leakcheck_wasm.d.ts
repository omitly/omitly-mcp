/* tslint:disable */
/* eslint-disable */

/**
 * Engine/version string for the page footer ("scanned locally by Omitly vX").
 */
export function engine_version(): string;

/**
 * Extract a PDF's text page by page, with PII spans, entirely client-side —
 * the wasm twin of `extract_text`, giving `extract_pdf_text` the same
 * zero-install fallback its four detection siblings (`scan`/`locate`, native
 * names `find`/`locate_text`) already have (omitly#1169). It was the one
 * free MCP tool that silently required a native engine while its siblings
 * ran on bundled wasm.
 *
 * Called from JS as `extract_text(new Uint8Array(arrayBuffer), masked)`.
 * Output shape is `{ ok, masked, pages: [{ page, contentDecoded, text,
 * spans: [{ kind, start, end }] }] }` — deliberately identical to
 * `omitly-cli`'s native `extract_text` command (`do_extract_text` in
 * `crates/omitly-cli/src/main.rs`), so the MCP server's
 * `toOutputExtractedPage` mapping works unchanged regardless of which engine
 * produced the result.
 *
 * `spans[].start`/`end` are CHAR (Unicode scalar value) offsets, never byte
 * offsets — see `TextSpan`'s doc comment in `redaction_core::detect` for
 * why (a mask replacement character is 3 UTF-8 bytes but 1 char, so only
 * char offsets stay valid across the masked/raw distinction; this crate has
 * been bitten by byte-vs-char confusion before, omitly#744's `café`
 * fixture). This binding does not recompute them, only serializes what
 * `extract_text` already produced in char space — verified unchanged by
 * this crate's own non-ASCII regression test.
 *
 * Unlike the native path, region narrowing (`extract_text_in`) is not
 * exposed here: wasm always scans every pattern, the same "more results,
 * never fewer" posture `findViaEngineOrWasm` already applies to
 * `find_sensitive_regions`'s wasm fallback.
 */
export function extract_text(bytes: Uint8Array, masked: boolean): string;

/**
 * Locate literal strings (names, addresses — whatever the caller's own entity
 * recognition turns up) and return their masked positions, the wasm twin of the
 * engine's `find_text`. Lets the standalone MCP offer `locate_text` without a
 * native binary. `needles_json` is a JSON array of strings; returns the same
 * `ScanResult` shape as `scan` (kind is "text").
 */
export function locate(bytes: Uint8Array, needles_json: string): string;

/**
 * Scan PDF bytes for residual sensitive text and return a JSON `ScanResult`.
 *
 * Called from JS as `scan(new Uint8Array(arrayBuffer))`. Always returns JSON;
 * parse errors come back as `{ ok: false, error }` rather than throwing, so the
 * UI has one code path. A non-empty `leaks` list on an *already-redacted* file
 * is the whole point: it means the redaction only painted over the data.
 */
export function scan(bytes: Uint8Array): string;
