/**
 * The free scan tools' one-sentence notices — CJS mirror of ../../src/usage.ts for the MCPB bundle
 * server, which is deliberately a separate, smaller CommonJS program (see index.js's module doc).
 *
 * Until 5.5.0 this module metered the two scan tools at 10 a month in `usage.json` (omitly#226).
 * The owner removed the cap (omitly#1859): the scan is free and unlimited. There is no counter,
 * no refusal and no state file any more. The one line that stays is a short disclaimer on scan
 * results, reworded by the owner (no "evaluation", no "free tier"). Keep the texts identical to
 * the TS twin's FIND_NOTICE and CHECK_NOTICE.
 */
"use strict";

const FIND_NOTICE =
  "This scan lists likely sensitive items. It does not remove anything and is not a removal certificate.";

const CHECK_NOTICE =
  "This check finds likely leaks. It does not remove anything and is not a removal certificate.";

module.exports = { FIND_NOTICE, CHECK_NOTICE };
