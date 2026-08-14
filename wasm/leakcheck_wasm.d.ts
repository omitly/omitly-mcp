/* tslint:disable */
/* eslint-disable */

/**
 * Engine/version string for the page footer ("scanned locally by Omitly vX").
 */
export function engine_version(): string;

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
