/**
 * omitly#1864: the strict parsers (replies.ts) accept what the real engine's contract goldens say it
 * sends (contract/cases/*.json, with each `<placeholder>` filled), so a correct reply is never refused.
 * The native-engine tests elsewhere drive the real binary through the same parsers (scan, locate,
 * check, seal no_report). Only in the Cargo workspace: the standalone package has no contract dir.
 */
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import * as path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { parseLocateReply, parseSealReply, parseSidecarVerifyReply } from "./replies.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DIR = path.join(HERE, "..", "..", "contract", "cases");
const skip = existsSync(DIR) ? false : "no contract/cases next to this package";

function fill(v: unknown): unknown {
  if (typeof v === "string") {
    return (
      { "<number>": 1, "<string>": "x", "<bool>": true, "<masked>": "•••", "<array>": [], "<object>": {}, "<any>": { result: "pass" } } as Record<string, unknown>
    )[v] ?? v;
  }
  if (Array.isArray(v)) return v.map(fill);
  if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, fill(x)]));
  return v;
}
/** The contract golden's `"<object>"` for the v2 `result` replayed as a whole CheckResult (the real one is in goldens/native.json). */
const SAFE_RESULT = {
  state: "safe_to_send", blocking: false, summary: "Every check passed.", pagesTotal: 1, pagesRead: 1, checked: [{ text: "Metadata" }], notChecked: [], problems: [], review: [], information: [],
  decisions: [], reasons: [], checkedAt: "2026-11-13T01:00:00Z", omitlyVersion: "5.6.0", sha256: "a".repeat(64), sizeBytes: 40,
};
const golden = (f: string) => fill(JSON.parse(readFileSync(path.join(DIR, f), "utf8")).response);

test("the seal goldens parse", { skip }, () => {
  for (const f of ["verify_seal.json", "verify_seal_v2.json", "verify_seal_unsupported_version.json", "verify_seal_format_v2.json"]) {
    // The v2 goldens do not list `sealValid`, which the engine always sends (null for a v2 report:
    // crates/omitly-cli/src/main.rs, the `unsupported_schema` reply).
    const g: any = golden(f);
    // The contract goldens list only some of a verified reply's fields: the engine also always sends `metadataScrubbed`, `warnings` and
    // `legacyUnboundVerdict` (main.rs verified reply), replayed here as a current-build report.
    // Likewise `carriesAuditReport` on an unsupported version (the engine's `seal_unsupported_version` reply).
    const r = parseSealReply(g.verdict === "unsupported_schema" ? { sealValid: null, ...g, ...(g.result ? { result: SAFE_RESULT } : {}) } : g.verdict === "seal_unsupported_version" ? { carriesAuditReport: false, ...g } : g.verdict === "verified" ? { metadataScrubbed: true, warnings: [], ...g, legacyUnboundVerdict: false } : g);
    assert.equal(r.ok, true, `${f}: ${r.ok ? "" : r.reason}`);
  }
});

test("the locate golden parses", { skip }, () => {
  const g: any = golden("locate_text.json");
  g.count = g.regions.length;
  assert.equal(parseLocateReply(g).ok, true);
});

test("the sidecar verify golden, with the hidden-content list the real engine always sends (main.rs `hiddenContent`), parses", { skip }, () => {
  const g: any = golden("verify.json");
  // The golden lists only `regions`; the engine also sends `hiddenContent` (crates/omitly-cli/src/main.rs).
  g.hiddenContent = ["thumbnails", "document-actions", "embedded-files", "incremental-revisions", "hidden-layers", "comment-annotations", "signature-identity", "semantic-text", "labels", "redacted-text-in-strings"].map((c) => ({ class: c, verification: { result: "pass" } }));
  assert.equal(parseSidecarVerifyReply(g).ok, true);
});
