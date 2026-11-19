/**
 * Shared constants for the free scan tools.
 *
 * History: until 5.5.0 this module metered the two leak-scan tools
 * (`find_sensitive_regions`, `check_redaction`) at 10 a UTC month in
 * `usage.json` and refused past the cap (omitly#226). The owner removed the cap
 * (omitly#1859, 11-12 November 2026): the scan is free and unlimited, matching
 * the free checker on the website. There is no counter, no refusal and no
 * `usage.json` any more, and the MCP server holds no licence check for scans.
 *
 * What stays:
 *   - `stateDir()` — the directory the MCP server and the desktop app share
 *     (OMITLY_STATE_DIR, else ~/.omitly): heartbeat, proposals, clients.
 *   - `OMITLY_SITE_URL` — the tagged link. It is shown only in the result of a
 *     removal request (omitly#1860), never on a scan result.
 *   - `FIND_NOTICE` / `CHECK_NOTICE` — the one-sentence disclaimer on free (wasm-served) scan
 *     results, paired with `evaluation: true` in the structured output (the field keeps its name:
 *     it is in the strict output schemas; only the visible wording changed). The owner reworded
 *     the old "EVALUATION (free tier) ..." line (omitly#1859): no "evaluation", no "free tier".
 *
 * Doctrine: NO phone-home — nothing here touches the network or writes a file.
 */
import * as os from "node:os";
import * as path from "node:path";

/** Marketing-site URL carrying the acquisition tag the website records as source "mcp" (omitly#1854). Every user-facing link from this package to omitly.app uses it. */
export const OMITLY_SITE_URL = "https://omitly.app/?via=mcp";

export function stateDir(): string {
  return process.env.OMITLY_STATE_DIR || path.join(os.homedir(), ".omitly");
}

/** One sentence on a free (wasm-served) `find_sensitive_regions` result. Not shown on results
 *  produced through a configured native engine. */
export const FIND_NOTICE =
  "This scan lists likely sensitive items. It does not remove anything and is not a removal certificate.";

/** One sentence on a free (wasm-served) `check_redaction` result. Same condition as FIND_NOTICE. */
export const CHECK_NOTICE =
  "This check finds likely leaks. It does not remove anything and is not a removal certificate.";
