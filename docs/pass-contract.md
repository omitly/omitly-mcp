# omitly-mcp pass contract (omitly#1864)

**v0.2.4**, 2026-11-17 (v0.2 plus the Errata v0.2.1 to v0.2.4 sections at the end). It supersedes v0.1 and resolves the EGM review
(`scratchpad/egm-pass-contract.md`: B1–B8, M1–M13, Nits) and the owner's decisions of 16 Nov (§9).
It is written against `feat/1864-r4-rebased` at f179b998. Line numbers are pinned to that commit;
expect drift on a rebased branch.

This is security-sensitive code under estate Rule 11 (frontier only; `Innisfallen/CLAUDE.md`).
Rule 4 (worker output is a claim; prove every test non-vacuous) applies to every test below.

Rust paths name their crate the first time they appear:
- `main.rs` is omitly-cli;
- `lib.rs`, `check.rs`, `audit_v2.rs` are omitly-seal;
- `report.rs`, `dispatch.rs`, `v2/mod.rs` are omitly-verify;
- `detect.rs`, `engine.rs` are redaction-core.

TS paths are under `omitly-mcp/`. "Bundle" means `mcpb/server/`. "Overlay" means
`mirror-overlay/mcpb/server/index.js`. It differs from the bundle's `index.js` only in comment
lines 15 and 40, so every bundle edit is made to both.

## 0. What this decides, and what is built tonight

The contract decides when any surface may say Safe to Send, clean or verified, or draw green. The
surfaces are the full server, the bundle, the overlay and the result card. It is an allow-list: a
pass is a fixed set of positive facts the MCP itself obtained from the engine over these bytes, and
anything else is not a pass.

**TONIGHT** means the MCP changes that close every known Safe-to-Send path. All three surfaces must
obey tonight's rules. **FOLLOW-UP** (F1–F10, §9.3) is everything else.

Tonight's build order. Each step leaves the build and tests green:

1. Add `src/outcome.ts` and its tests. Nothing is wired yet.
2. Change the parsers and their tests: replies, coverage-rule, seal (§7.2).
3. Wire `check_redaction` and `find_sensitive_regions`.
4. Wire `verify_redaction` (both paths).
5. Wire `verify_seal` and `verify_document`, including the schema.
6. Wire the redact tools and `get_proposal_status`.
7. Change the result card.
8. Port to the bundle and the overlay, then `BASIS.json`.
9. Add the new goldens and run T16 and T17.

## 1. Threat model

In scope:
- **(a) Hostile files.** Any PDF may be crafted, and so may anything inside or beside it: its
  embedded audit report (fields, warnings, `omitly_version`, a declared OCR layer), its seal and
  seal keys, and a `<pdf>.audit.json` sidecar (entries, warnings).
- **(b) Bad engine replies.** Version skew, engine bugs, truncated replies, and two engine calls
  that disagree. These fail closed. A malformed or self-contradicting reply is an execution
  failure, never a softer verdict.

Out of scope:
- a compromised engine binary, wasm module, host or MCP client;
- **tonight only**, a concurrent local process that rewrites the file between the native engine
  calls.

Condition C3 detects that rewrite for the check leg. The native private copy (F3) closes it for
both legs.

## 2. The pass set, the order of outcomes, and the one issuer

### 2.1 Conditions (PASS holds only if all hold)

- **C1. Read once.** The MCP reads the file once into `B` and computes `sha256(B)` as lowercase hex.
  The wasm `check` and `scan` both receive `B`. Today the server reads twice:
  `checkViaEngineOrWasm` (index.ts:1234) and `findViaEngineOrWasm` (:1373) each call
  `readFileSync`. Both change to take `B`. The bundle already reads once (index.js:295).
  - Native calls still receive the confined path tonight. F3 adds `withSnapshot`: `mkdtempSync`
    under `realpathSync(os.tmpdir())` (Node creates it with mode 0700), the copy written with flag
    `"wx"` and mode `0o600`, the sidecar copied beside it, and `rmSync(dir, {recursive:true})` in
    `finally`.
  - The Rust `PrivateSnapshot` (main.rs:2065-2091) is not a private directory: it is a guessable
    file name in `temp_dir()`. Do not cite it as one.
- **C2. The check passes.** The `check` reply (`free_check`, check.rs:518-587) has all of:
  - `verdict === "safe_to_send"` and `blocking === false`;
  - `reason_code` absent or `null`. Real passes send `null` (native.json:528).
  - a non-null `result` that meets the pass rules of `parseCheckVerdict` (replies.ts:520-534).
- **C2b. The check relied on nothing the file says about itself.** The raw engine
  `result.information` (read before any MCP rewording) has no item whose text starts with
  `This file carries an Omitly report (omitly-audit.json) sealed with key ` (check.rs:753).
  - `check` adds that line (check.rs:362, `sealed_report_item` :1934-1970) exactly when
    `attachment_exemptions` (lib.rs:410-416) found the file's own report `BoundToSeal`.
  - In that same case, and only then, `check` also exempts the report from the attachment checks
    and reads the report's `declared_ocr_layer` and `entries` (`bound_presented_layer`,
    lib.rs:424-458). Binding needs only a seal over a report naming the seal's own key
    (lib.rs:246-250).
  - So this line is the one reply field showing that `check` was steered by an in-file claim. If it
    is present, cap at `needs_review` (W6). The engine's own line already tells the user to confirm
    the key.
  - Residual risk: the seal-v2 envelope exemption (`envelope_status_for`, lib.rs:183-207) leaves no
    field in the reply. Its content is fixed-shape CBOR. `find` scans every attachment, because
    detect.rs has no Omitly-attachment exemption, so pattern PII there is still found. F4 removes
    the residual.
- **C3. The check is bound to `B`.**
  - The check's `sha256` comes from the bytes it read (check.rs:221-225; on its failure path, :550).
  - A non-empty `result.sha256` must equal `sha256(B)`, compared exactly. A mismatch is an
    execution failure (row 0).
  - An empty `sha256`, or `result: null`, is allowed only with `verdict: cannot_verify` and
    `reason_code` in {`input_too_large`, `check_failed`}. Sources: `input_too_large` at
    check.rs:531, :544-546 (native.json:1149); the wasm serialisation fallback at
    leakcheck-wasm lib.rs:322-329. Such a reply never satisfies C2. It maps through rows 1–4.
  - Any other empty or null case is row 0.
  - Every check golden's `sha256` equals the SHA-256 of its fixture file. Rigs therefore copy the
    real fixture bytes into their `doc.pdf` (§8.2).
- **C4. The scan is empty and complete.** The PASS pipeline never passes a `regions` filter.
  - `total_findings === 0`.
  - These lists are present and empty: `regions` (native) or `leaks` (wasm), `survivors`,
    `off_page`. A missing list is a parse failure.
  - Top-level `scan_complete` and `coverage.scan_complete` are both `true`. Either one absent
    means not complete (`incomplete`), never a parse failure (replies.ts:14-16). Present and
    disagreeing is row 0 (replies.ts:178).
- **C5. Disclosures are allow-listed.** Every `coverage.not_scanned` line is a BENIGN line (§4).
- **C6. Typed coverage is clear.** Required keys:
  - **native** (main.rs:1628-1642), 13 keys: `pages_total`, `pages_scanned`, `pages_failed`,
    `prior_revisions_scanned`, `metadata_scanned`, `acroform_scanned`, `attachments_scanned`,
    `form_xobjects_scanned`, `annotation_appearances_scanned`, `raster_pages`, `raster_only_pages`,
    `not_scanned`, `scan_complete`.
  - **wasm**: those 13 plus `survivor_pages_failed`, `prior_revisions_failed`,
    `embedded_streams_failed`, `acroform_tree_incomplete`, `xmp_stream_unread`,
    `attachment_content_unread`, `attachment_tree_unread`. These match the wasm.json reply.

  A missing required key is a parse failure. PASS requires all of:
  - `pages_failed`, `raster_only_pages`, `survivor_pages_failed` and `prior_revisions_failed` are
    empty;
  - `embedded_streams_failed === 0` (a count);
  - every `*_unread` and `*_incomplete` flag is `false`.

  `*_scanned: false` means "not present in this file" and **never** denies. The invisible-text and
  covered-text fixtures have `metadata_scanned: false`.
- **C7. No engine warning** (§5). It applies only to replies that carry `warnings`: the redact
  audit, the sidecar `verify` and the seal replies. The check and scan replies have no `warnings`,
  so C7 is not a `check_redaction` condition.
- **C8. The legs agree.** `legsDisagree` (verdict-rule.ts:229) is unchanged. A disagreement is row 0.

### 2.2 Order and outcome mapping

`worst(...)` is taken over the order **not_a_pass > needs_review > incomplete > safe_to_send**.
"Cap at X", "lower to X" and "at most X" all mean `worst(current, X)`.

| Row | Condition | Outcome |
|---|---|---|
| 0 | Parse failure or contradiction, C3 mismatch, C8 disagreement, or the check could not run (`check_unavailable`, `result_invalid`) | execution failure: `isError: true`, text only, **no `structuredContent`** |
| 1 | A failed redaction: a blocking check verdict, `survivors.length > 0`, or a §3 surface rule that names `not_a_pass` | `not_a_pass` |
| 2 | Items a person must look at: findings, a non-blocking Needs Review, C2b, an engine warning, or a §3 surface rule that names `needs_review` | `needs_review` |
| 3 | PASS (C1–C8) | `safe_to_send` |
| 4 | Anything else: Cannot Verify, an incomplete scan, a denying or unknown disclosure, a typed coverage failure, or a tool that cannot establish safety | `incomplete` |

`passOutcome` computes rows 1–4 for a check+scan pair, then takes `worst` with the caps. Survivors
are always row 1 on every surface, `find_sensitive_regions` included. That resolves M11.

### 2.3 The one issuer

Only `passOutcome` in `src/outcome.ts`, and its hand port `mcpb/server/outcome.js`, can produce
`safe_to_send`. Every other surface supplies caps only (§7.1). T18 enforces this.

**Never evidence:** an embedded report, a sidecar, a seal, a fingerprint, an in-file version string,
a desktop proposal record, or an earlier result. These may only add caps.

## 3. Surfaces

Every completed result is `isError: false` and carries an `outcome`. Every execution failure is
`isError: true` with no `structuredContent`.

| Surface | Engine calls | Tonight's outcome |
|---|---|---|
| `check_redaction` (server, bundle, overlay) | PASS pipeline | `passOutcome` (any of the four) |
| `find_sensitive_regions` (server, bundle, overlay) | `find` / `scan` | `capped` of row 1/2/4 scan facts plus W12 at `incomplete`. Never `safe_to_send` |
| `verify_redaction`, re-scan (server, bundle, overlay) | PASS pipeline | `passOutcome` |
| `verify_redaction`, sidecar (server) | PASS pipeline, plus `verify` | `passOutcome` lowered by the sidecar caps (§3.4) |
| `verify_seal` | `verify_seal` | the §3.5 table, at most `incomplete` |
| `verify_document` | `verify_seal` (Q2 is capped tonight, §9) | same as `verify_seal`, plus a pointer to `check_redaction` |
| `redact_pdf`, `redact_by_entity` (done) | `redact` / `redact_entities` | the §3.6 audit outcome, capped at `needs_review` (W11) |
| redact tools (`status: "queued"`) | none | no `outcome`. Nothing was written and nothing was checked |
| `get_proposal_status` | none | no `outcome`. Treated as non-pass by the text rule (§6) |
| result card | none | its look is a pure function of `outcome` (§3.8) |

### 3.1 `check_redaction`

Changes, all tonight:

- **Pipeline.** `passOutcome` replaces `checkOutcome` (index.ts:2431; bundle :343).
- **Execution failure.** When `executionFailed`, return no `structuredContent`. Today it returns
  the structured result beside `isError: true` (index.ts:2493-2495, :2541-2544; bundle :363
  returns `{outcome}` beside `isError: true`).
- **Verdict.** `structuredContent.verdict` is `reconcileVerdict(applyScanToVerdict(...), issued)`
  (§7.1). So a C2b, C5 or C6 non-pass never leaves `verdict.verdict === "safe_to_send"`, and the
  schema's two-way refine (index.ts:1100-1102) stays as it is.
- **Text.** `issued.lead` replaces `notAPassLine` (index.ts:1194). The other text sites change as
  listed in §6.2.
- **Description.** Remove "safe_to_send (every check that applies to this file passed ...)" from
  the description (index.ts:2377-2386). Replace it with: "`outcome` is the only verdict field.
  `safe_to_send` is given only when the engine's check passed, the scan read the whole file and
  found nothing, and the file's own seal or report played no part."

### 3.2 `find_sensitive_regions`

- **Outcome.** `outcome = capped(null, caps)`. The caps are: W2 at `not_a_pass` for survivors; W1
  at `needs_review` for findings; W3/W5 at `incomplete` for an incomplete scan or a denying
  disclosure; and always W12 at `incomplete`. The result is one of `not_a_pass`, `needs_review`
  or `incomplete`.
- **Schema.** Add `outcome: z.enum(OUTCOMES)` to `findSensitiveRegionsOutputSchema` (index.ts:350).
- **Bundle and overlay.** Today their `find` returns no `structuredContent` (index.js:180). Add
  `{ outcome }`.

### 3.3 `verify_redaction`, re-scan path: runs the check

Tonight, the re-scan path (index.ts:1973-2012; bundle and overlay :230-254) calls the same pipeline
function as `check_redaction`. The real goldens show why it must: `invisible-text.pdf` gives a
clean, complete `find` and a Needs Review `check` on both engines.

- **Pipeline.** Factor the inline pipeline (index.ts:2398-2431) into `runCheckPipeline(B, path):
  Promise<{ issued, verdict, scan } | Failure>`. Both tools call it. In the bundle, do the same
  over index.js:293-363.
- **`isError`.** The re-scan's `isError: !clean` (index.ts:2012; bundle and overlay :254) becomes
  `false` for every completed check.
- **Metadata.** A file with metadata but no pattern match gets what `check` gives it today:
  `metadata_present` is an Information line in Presented mode (check.rs:1433-1437; owner decision
  #1454). This contract does not reopen that.

### 3.4 `verify_redaction`, sidecar path

`verify` re-checks the sidecar's regions, ten hidden-content classes and metadata
(main.rs:1030-1172; `scan_performed: false` at :1159). The sidecar is attacker-writable.
`compute_all_pass` (main.rs:914-921) is vacuous over **regions** when the sidecar lists none: a bare
`[]`, or v1/v2 `entries: []`. `hidden_content` always holds ten checks.
`compute_all_pass` ignores warnings (main.rs:1142-1146). The warnings returned are the sidecar's own
(main.rs:1171). For a v2 sidecar they are engine **codes**, plus a product notice the CLI derives
from `provenance.license` (main.rs:1061, :1080-1084).

Tonight's rule:

- **Pipeline.** `issued = passOutcome(pipeline over B)`, then these caps from the parsed `verify`
  reply:
  - a failing region (`regions[].verification.result === "fail"`) → W9 at `not_a_pass`;
  - a failing hidden-content class → W16 at `needs_review`. `verify` is stricter than `check` here,
    for example on `document-actions`, so this does not mean "failed redaction".
  - `metadataScrubbed === false` → W10 at `needs_review` (M3). The sample.pdf verify golden has it
    (native.json:1890).
  - any `warnings` entry that is not exactly a product notice → W7 at `needs_review`. This does not
    depend on omitly#1904. Routing v2 codes by `route()` (audit_v2_engine_warnings.rs:57-104), so
    that Unsafe codes give `not_a_pass`, is F8.
- **`disclosures`.** Informational. The count goes in structured `sidecar.disclosures`. The text
  holds no strings from it.
- **Binding.** The `verify` leg reads the original path and its sidecar, and its reply has no sha,
  so it is exempt from C3. F3 copies the sidecar beside the snapshot.
- **`isError`.** `false` for every completed check. Today it is `res?.ok === false || verdict ===
  "fail"` (index.ts:1969).
- **Text.** A passing sidecar adds nothing: `clean` comes from the pipeline scan (index.ts:1953
  changes). Replace `SIDECAR_VERIFY_NOTE` (index.ts:651) with: "ℹ️ Region check: the N regions
  recorded in this file's sidecar were re-checked, plus ten hidden-content checks. The sidecar is
  not evidence: the outcome above comes from this server's own check of the file." Delete the dump
  (:1965).

### 3.5 `verify_seal` and `verify_document`: seals are integrity only (owner Q1 = A)

**v1 seals are self-attested.**
- The trailer is made with any key (`seal_pdf`, lib.rs:113-126).
- `seal_valid` checks only that the signature verifies and that the report's recorded key equals
  the seal's key, and both are in the file (lib.rs:985-986).
- `all_passed`, `metadata_scrubbed` and `warnings` are then copied from the report
  (lib.rs:1050-1058).
- The "legacy" test reads the report's own `omitly_version` (report.rs:103-118).

**v2 is self-attested too.**
- The seal-v2 keys sit in the envelope in the file. `key_id` is SHA-384 of the CBOR of
  `[suite, keys]` (v2/mod.rs:549, :563-570), and becomes the seal key (dispatch.rs:114-132).
  `report_binding` is also from the file.
- An audit-v2 report needs only that key to match (`seal_gate`, audit_v2.rs:1421-1469).
- The verifier recomputes **applicability**, not **statuses** (audit_v2.rs:1536-1538).
  `overall = aggregate(report's own statuses)` (audit_v2.rs:323, :2194-2203).
- The CLI seals each output with a fresh one-time key (main.rs:610, :655).
- `countersign_pubkey` (lib.rs:1468) is test-only.
- The goldens agree: v5.3.0 and the redact_entities output give `userVerdict: safe_to_send`.

**Fields** (B8):
- `v1Held` = `sealValid === true` and `verdict` ∈ {`verified`, `incomplete`, `no_report`}.
- `v2Held` = `auditV2Recognized === true` and `auditV2SealValid === true`. When the seal is a v2
  seal, `sealVerdict === "valid"` is also required. The v2 replies carry `sealValid: null`
  (native.json:1278), so never key on `sealValid` for v2.

**Verifier-own lines** are not report warnings. They are lines starting with:
- `CAUTION: this file was sealed by a build predating` (lib.rs:1088-1093);
- `UNVERIFIED: ` (lib.rs:670-671 and the source-comparison line in the invalid branch);
- `unsupported audit report schema ` (lib.rs:895-897).

The v2 `warnings` array holds only that last line (golden v5.3.0). `sealWarnings` comes from the
verifier (main.rs:1273-1275).

**Seal table** (first match wins; only the seal tools evaluate it):

| # | Condition | Outcome, why |
|---|---|---|
| S1 | `sealRemoved === true` | `not_a_pass`, W13 removed |
| S2 | `verdict === "seal_invalid"`, or `report_unparseable` with `sealValid === false` | `not_a_pass`, W13 invalid |
| S3 | `v1Held` and `verdict === "incomplete"` | `not_a_pass`, W14 |
| S4 | `v2Held` and `auditV2Overall === "unsafe"` | `not_a_pass`, W14 |
| S5 | `v2Held` and `auditV2Overall` ∈ {`review_required`, `pass_with_operator_decisions`} | `needs_review`, W15 |
| S6 | `v1Held`, `verified`, `metadataScrubbed !== true` | `needs_review`, W10 |
| S7 | `v1Held`, and a `warnings` entry that is neither a product notice nor a verifier-own line; or any `sealWarnings` entry | `needs_review`, W17 |
| S8 | everything else: a v1 pass of any era, a v2 `pass` or `technical_fail`, v2 with no overall, `no_report`, `seal_unsupported_version`, `unsupported_schema`, `report_unparseable` with a held seal | `incomplete`, W8 |

`outcome = worst(row, incomplete)`. It is never `safe_to_send`.

- **Refine.** The verify_seal schema refine (index.ts:804-816) becomes "`outcome !== "safe_to_send"`".
- **Changed tests.** Expectations at real-engine-goldens.test.ts:111 and :117 change to
  `incomplete`.
- **`verify_document`** is identical tonight. Its text adds: "This does not check the document's
  content. Run check_redaction for that." Its description drops "confirm it's an authentic,
  unaltered Omitly output" (index.ts:2210). Replace that with: "reports whether the file's seal
  still verifies. A seal shows integrity, not origin, and is not a check of the content."

### 3.6 `redact_pdf`, `redact_by_entity` (owner Q5 = A, capped tonight)

**Audit outcome** (B4), first match. Read from the parsed `audit`:

| # | Condition | Outcome |
|---|---|---|
| A1 | `blocking === true` (v2 `unsafe`), or any `regions[].verification.result === "fail"` | `not_a_pass` |
| A2 | v2 overall `review_required` or `pass_with_operator_decisions`; v1 `verdict: "fail"` with no failing region (metadata not scrubbed) | `needs_review` |
| A3 | any `warnings` entry that is not exactly a product notice | `needs_review` (W7) |
| A4 | v2 `technical_fail` | `incomplete` |
| A5 | v2 `pass`, or v1 `pass` | no cap from the audit |

Then `outcome = capped(null, [audit caps..., W11 at needs_review])`. That gives `not_a_pass` or
`needs_review`.

- **Example.** The real `redact` golden (`review_required`, native.json:2111, :2222-2223) gives
  `needs_review`.
- **Disclosures.** `audit.disclosures` is informational.
- **Parser change.** `parseRedactAudit`'s "pass beside an engine warning" failure (replies.ts:449-452)
  is deleted. A3 replaces it.
- **Failure after write.** If the parse fails after the file is written, the result stays an
  execution failure. Its text must say: "The output was written to <path>, but its audit could not
  be read. Do not use it until check_redaction has checked it."

**Text** (§6.2):
- Replace `verificationLine` and `resultLine` (index.ts:476-506) with one line: "The engine's
  record of this redaction: {A-label}. This is not a check of the document: run check_redaction on
  the output."
- A-labels: A1 "a failed redaction"; A2/A3 "items to review"; A4 "could not complete its checks";
  A5 "no failed region".
- Delete the "Audit log:" dumps (index.ts:1773, :1851).

**Why the full check is not tonight** (§9, Q2/Q5): every redact output carries the engine's own
bound report, so C2b would cap it at `needs_review` anyway. The minted-key exception is F2. The
consequence: until F2, no MCP surface gives `safe_to_send` for an Omitly-sealed output. T17b
records this.

### 3.7 `get_proposal_status`

- **Structured.** Rename `verdict` to `recordedByDesktop` in `proposalStatusOutputSchema`
  (index.ts:586).
- **Text** (index.ts:2742): "Applied: a person accepted it in Omitly; the output is at <path>. The
  desktop app recorded: {label}. Run check_redaction on the output for this server's own result."
  - Labels replace `proposalVerdictLabel` (index.ts:485): `safe_to_send` → "nothing to review";
    `needs_review` → "items to review"; `cannot_verify` → "could not check"; `pass` → "no failed
    region (legacy report)"; `fail` → "a failed region (legacy report)"; anything else → "not
    recorded".
  - Replace `p.note` in the text (index.ts:2745) with "(see `note`)".
- **Description.** Change "verified and sealed" (index.ts:2712) to "removed and sealed".

### 3.8 Result card

**Look.** The look is a function of `outcome` alone:

| `outcome` | look |
|---|---|
| `safe_to_send` | `safe` |
| `needs_review` | `visible` when the check envelope lists findings; otherwise `review` |
| `not_a_pass` | `blocking` |
| `incomplete` | `cannot` |
| missing or unknown | `error` |

Delete the look derivation in `buildCheckModel` (result-card.ts:482-501) and in `sealLook`
(:640-709). The latter includes the v2 green branch at :678-687.

**Envelopes.**
- `parseCheckEnvelope` keeps its shape checks. It replaces the recompute (replies.ts:593-600) with
  two rules: `outcome` must be in OUTCOMES, and `outcome === "safe_to_send"` implies
  `verdict.verdict === "safe_to_send"` and `scanComplete && clean`.
- `parseSealEnvelope` replaces its recompute (:615-618) with: `outcome` in OUTCOMES and not
  `safe_to_send`.

**Green.** No green element on a non-pass:
- the ✓ rows and the green SEAL section in `buildSealModel` (:725-737, :755) become blue ℹ rows;
- WHAT WAS CHECKED (`SECTIONS.checked`, :50) is drawn neutral unless the outcome is `safe_to_send`.

**Footer** (:774): "Checked on this {device} by Omitly {version}".

**Seal titles.**
- S1/S2: the existing `invalid` / `removed` titles.
- S3/S4: `intactNotPassed`.
- S5–S7: "Seal unchanged — its report lists items to review".
- S8 with a held seal: "Seal unchanged — a seal is not a check of the content".
- S8 without a held seal: the existing no-report and unsupported titles.

**Rule 13.** These are copy and colour changes on an existing component, so they count as visually
minor: verify with a before/after screenshot.

## 4. Disclosures: two sets

Every `not_scanned` line comes from `scan_document_with_flags` (detect.rs:4524; struct built at
:4614). It is either built at :4647-4755 or passed through from `scan_nonpage_detail` at :4742.
`scan_complete` is computed at detect.rs:4599-4612. Wasm and native share these strings
(leakcheck-wasm lib.rs:111-141).

**Set 1, `ENGINE_INCOMPLETE_DISCLOSURES` (parser).**
- What it holds: today's `COMPLETION_DENYING_DISCLOSURES` (coverage-rule.ts:23-37; bundle
  replies.js:23) **plus** `^document information, form fields and attachments: `.
- Meaning: lines the engine sends only beside `scan_complete: false`. One of them beside
  `scan_complete: true` is a contradiction, which is row 0 (replies.ts:120, :551; bundle
  replies.js:68).
- Changes: rename it, and add the 3869 pattern in all three copies. Its role is unchanged.

**Set 2, `BENIGN_DISCLOSURES` (contract module).** Exact string equality against the raw engine
line. It holds one entry: `text drawn as raster images (needs OCR)` (detect.rs:4669). Every other
line, including unknown ones, fails C5. A line that fails C5 gives `incomplete`, or `needs_review`
when there are findings.

| detect.rs | Line (prefix) | Engine sets `scan_complete: false` | Set 1 | C5 | Text label (§6.3) |
|---|---|---|---|---|---|
| 4660-4666 | `{n} page(s) are effectively image-only` | yes | yes | deny | "pages that are images only" |
| 4669 | `text drawn as raster images (needs OCR)` | no | no | **benign** | "text drawn as images (not OCR'd)" |
| 4671-4675 | `CID/Identity-H text with a code not covered` | yes | yes | deny | "text in a font that could not be decoded" |
| 4684-4693 | `text in font(s) ... not verified as drawn` | **no** | no | **deny** (owner Q4) | "text whose drawn characters could not be confirmed" |
| 4694-4698 | `Type0/CID text using a named encoding` | yes | yes | deny | "text in a font that could not be decoded" |
| 4700-4704 | `{n} embedded content stream(s) that failed` | yes | yes | deny | "content streams that could not be read" |
| 4706-4710 | `{n} Form XObject(s) showing text in a font set by the page` | yes | yes | deny | "form text that may be misread" |
| 4713 | `embedded-file attachment name tree` | yes | yes | deny | "attachments that could not be listed" |
| 4715-4721 | `{n} page(s) could not be fully checked for text surviving` | yes | yes | deny | "pages where text under a mark could not be checked" |
| 4729-4735 | `{n} prior (superseded) revision(s)` | yes | yes | deny | "earlier versions that could not be read" |
| 4745-4752 | `the file's structure (...) did not read the same way twice` | yes | yes | deny | "parts of the file structure" |
| 3823 (via 3797) | `AcroForm field tree deeper than 16 levels` | yes (:4605) | yes | deny | "form fields nested too deep" |
| 3869-3871 | `document information, form fields and attachments: {e}` | yes (:4605) | **added** | deny | "document information, form fields and attachments" |
| 3916-3919 | `XMP metadata stream was {reason}` | yes (:4605) | yes | deny | "the XMP metadata" |
| 3971-3974 | `XMP metadata stream could not be read as text` | yes (:4605) | yes | deny | "the XMP metadata" |
| 4024-4027 | `attachment '{filename}' was {reason}` | yes (:4605) | yes | deny | "an attachment" |
| (unknown) | anything else | — | no | deny | "a part of the file this server cannot name" |

The 4684 row and the unknown row sit beside `scan_complete: true` legitimately. They are not in
Set 1, so they never become execution failures.

**`pages_failed`** has no `not_scanned` line. It is C6, with the label "{n} page(s) that could not
be parsed".

**False rejects (M12).** The 4684 row may reject many ordinary PDFs: subset fonts often hit
`.notdef`. The owner accepted that risk. F7 measures the hit rate.

## 5. Warnings and product notices

**Product notices** are appended by the CLI after the engine decides `all_passed`
(main.rs:440-460):
- `TRIAL_OUTPUT_WARNING` (licensing policy.rs:73-74);
- `PERSONAL_USE_WARNING` (policy.rs:82-84);
- `DEV_KEY_WARNING` (omitly-cli license.rs:56).

**Matching.** A product notice matches by **exact equality** with the full string.
- `PRODUCT_NOTICES` in seal.ts:305-309 becomes the three full strings (today it holds prefixes),
  and `isProductNotice` (:314) becomes `===`.
- Rust `\`-newline continuations drop the newline and the following indentation. The PERSONAL
  string contains an em dash (U+2014).

**Constants test** (tonight). Read policy.rs and license.rs:
- Apply that unescape rule: delete `\\\n[ \t]*`.
- Compare with the TS list.
- Skip, with a logged reason, when `../crates` is absent, as in the public mirror.

A Rust-emitted JSON fixture replaces this test in F9.

**Engine warning** means any other string in a `warnings` list. A notice confers nothing and denies
nothing.

| Reply | Source of `warnings` | Rule |
|---|---|---|
| redact `audit.warnings` | the engine in this call, plus notices (main.rs:441-460, :700) | A3 |
| sidecar `verify.warnings` | the sidecar file, plus a derived notice (main.rs:1080-1084, :1171) | W7 at `needs_review` (§3.4). An empty list proves nothing |
| `verify_seal.warnings`, v1 | the report if the seal holds (lib.rs:1055), plus verifier-own lines | S7 |
| `verify_seal.warnings`, v2 | verifier-own lines only | ignored, since S8 already gives `incomplete` |
| `verify_seal.sealWarnings` | the verifier (main.rs:1273-1275) | S7 |

## 6. Text and structured fields

### 6.1 Structured-field invariant (B5)

A field a client could read as a pass may hold a pass-shaped value only when
`outcome === "safe_to_send"`. That covers: `verdict` / `verdict.verdict` / `result.state` /
`summary`, `userVerdict`, `allPassed`, and `verdict: "pass" | "verified"`. Raw engine or file
claims move under an attributed key.

| Surface | Change |
|---|---|
| `check_redaction` | `verdict` is reconciled (`reconcileVerdict`, §7.1). `clean`, `scanComplete` and `totalFindings` stay as **scan facts**: Q7 keeps the names, and the schema text says "`clean`: the pattern scan listed nothing; not a verdict". |
| `verify_redaction` | Schema (index.ts:676-686) becomes `{ outcome, mode, scanComplete, clean, totalFindings, findings, verdict: checkVerdictOutputSchema (reconciled), sidecar?: { regions: int, regionsFailed: int, hiddenContentFailed: int, metadataScrubbed: boolean, engineWarnings: int, disclosures: int } }`. The old `verdict: "pass" \| "fail"` is removed. |
| `find_sensitive_regions` | adds `outcome` |
| redact tools (done) | Top-level `verdict` is removed. `audit` is renamed `engineAudit`, with the same fields (described as "the engine's record of this redaction, not a check of the document"). Adds `outcome`. Queued results are unchanged and carry no `outcome`. |
| `verify_seal`, `verify_document` | The schema (index.ts:768) becomes `{ outcome, seal: { state: "held"\|"invalid"\|"removed"\|"none"\|"unsupported", version, eraLabel, fingerprint, keyKind }, embeddedReport: {every other field of `toOutputSeal` (index.ts:821), including the old `verdict` as `verifierVerdict`} \| null }` |
| `get_proposal_status` | `verdict` becomes `recordedByDesktop` |

`seal.state` is the first match of:
- `removed` when S1 applies;
- `invalid` when S2 applies;
- `unsupported` when the verdict is `seal_unsupported_version`;
- `held` when `v1Held || v2Held`;
- `none` otherwise.

**Fingerprint.** `seal.fingerprint` is `sealFingerprint`, which is null on every v2 golden. When it
is null, the text says "a key this engine does not report". F6 adds the v2 `key_id` fingerprint.

T11 walks `structuredContent` as well as text.

### 6.2 Server-authored text sites to change (B6)

| Site | Today | Tonight |
|---|---|---|
| `scanStatusLine` (index.ts:658-660) | "✅ Scan complete: ..." | "ℹ️ The pattern scan read every page and stream it found. Images are not OCR'd." |
| check_redaction (index.ts:2482-2485) | "✅ No recoverable PII found ..." | Only when `outcome === "safe_to_send"`: "✅ Safe to Send: ...". Otherwise "The pattern scan listed nothing in the part of the file it read." |
| bundle and overlay check_redaction (:333-337) | the same ✅ lines | the same change |
| re-scan (index.ts:1998-2000; bundle and overlay :251-253) | "✅ No recoverable PII ...", "not clean" + dump | the check_redaction lines; the dump is deleted |
| `v1NotCleanSummary`, `v2SealSummary`, and the summaries at index.ts:2184, :2279 | ✅ "Seal valid ..." / "... intact ..." | the §3.5 text: "ℹ️ The seal checks out: these bytes are unchanged since they were sealed by the holder of {fingerprint \| a key this engine does not report}. Anyone can seal a file with their own key, so this is not a check of the content: run check_redaction." Then "The file's own report records: {label}" (the §3.6 A-labels, or the S-row label) |
| seal tools: dumps (index.ts:2167, :2190, :2266, :2290) | `JSON.stringify(res)` | deleted |
| redact `verificationLine` / `resultLine` and the dumps (:476-506, :1773, :1851) | "Verification: pass", "Result: Safe to Send", the audit JSON | §3.6 |
| sidecar dump (:1965) | the raw reply | deleted |
| `get_proposal_status` (:2742, :2745) | "Result: Safe to Send", the raw note | §3.7 |
| `embeddedReportLine` (verdict-rule.ts:83-95) | quotes "all redactions verified" verbatim (:88) | `said` comes from a closed map: "Safe to Send" → "nothing to review"; "all redactions verified" → "no failed region". No file-derived field sits inside the quote. The key is hex-and-colons only (check.rs:1958-1962). |

`check_license` (index.ts:2076, :2100) is out of scope: it reads no document.

### 6.3 The text matcher (T11)

The matcher runs on every document tool's text for every golden and stub case, on the server, the
bundle and the overlay. It treats `get_proposal_status` as non-pass. Steps:

1. Apply NFKC, then lowercase.
2. Delete the exact lead prefix `⚠️ not a pass — `, then each exact allowed negation:
   - "this is not a clean result"
   - "not a clean result"
   - "not a check of the content"
3. When `outcome !== "safe_to_send"`, fail on any of:
   - the phrases `safe to send`, `safe_to_send`, `safe-to-send`, `no recoverable pii`,
     `verification: pass`, `intact`;
   - `\bclean\b`, `\bverified\b`, `\bpassed\b`;
   - the glyphs ✅ ✓ ✔ ☑ 🟢.

Engine `not_scanned` lines never appear in text (§6.4), so no engine line needs an exemption.

The matcher is NFKC-normalised, but homoglyph and bidi tricks are prevented at the source: no
file-derived text is ever shown (§6.4). The text is English only; there are no localised surfaces
today.

### 6.4 File-derived strings (M6)

No file-derived value is written into text. It appears only as a fixed placeholder, and the raw
value stays in `structuredContent`. The values:

- **`not_scanned` lines.** The text shows the §4 label for each row. The raw lines stay in
  `coverage.notScanned`. This covers filenames, font names, `{e}`, `{reason}`, `{why}` and
  `objstm_problems`.
- **`off_page[].source`** (for example `attachment:{filename}`). The text shows its category, the
  part before the first `:`, from the closed set {`metadata`, `form`, `attachment`, `revision`},
  else `other`. Structured keeps the raw value.
- **Seal and report fields** (`sourceFilename`, `outputFilename`, `licensedTo`, report `warnings`):
  structured only. The dumps are gone.
- **The proposal `note`**: structured only.

Today the masked previews are `•` plus up to four digits from the engine (native.json:335). They
are engine-made, not raw file strings, and stay as they are.

## 7. Implementation for tonight

### 7.1 `src/outcome.ts`: exact API (browser-safe, no imports outside `src/`)

```ts
export const OUTCOMES = ["safe_to_send", "needs_review", "not_a_pass", "incomplete"] as const; // moved from verdict-rule.ts, re-exported there
export type Outcome = (typeof OUTCOMES)[number];
export function worst(first: Outcome, ...rest: Outcome[]): Outcome; // order: not_a_pass > needs_review > incomplete > safe_to_send

declare const ISSUED: unique symbol;
/** Only this module constructs one. `why` is empty iff outcome === "safe_to_send"; lead === notAPassLead(why). */
export interface Issued { readonly outcome: Outcome; readonly why: readonly string[]; readonly lead: string; readonly [ISSUED]: true }
export interface Cap { readonly at: Exclude<Outcome, "safe_to_send">; readonly why: string }
export interface Failure { readonly failure: string } // row 0: the caller returns isError true, text only

export interface CheckLeg { verdict: "safe_to_send" | "needs_review" | "cannot_verify"; blocking: boolean; reasonCode: string | null; result: ResultLike | null } // after parseCheckVerdict; result.information RAW
export interface ScanLeg { engine: "native" | "wasm"; total: number; survivors: number; topComplete: boolean | null; covComplete: boolean | null;
  notScanned: readonly string[]; pagesFailed: number; listsNonEmpty: boolean; embeddedStreamsFailed: number; flagsSet: boolean } // after parseScanReply
export function passOutcome(i: { check: CheckLeg; scan: ScanLeg; snapshotSha256: string; caps?: readonly Cap[] }): Issued | Failure; // C2–C8, rows 0–4, then caps
export function capped(base: Issued | null, caps: readonly Cap[]): Issued; // worst(base?.outcome ?? "incomplete", ...caps.map(c => c.at)); never upgrades
export function sealCaps(res: NormalizedSealResult): Cap[];   // the §3.5 table S1–S8 (always includes W8)
export function auditCaps(audit: ParsedAudit): Cap[];          // the §3.6 table A1–A5 plus W11
export function sidecarCaps(v: ParsedVerify): Cap[];           // §3.4 (W9, W16, W10, W7)
export const BENIGN_DISCLOSURES: readonly string[];            // ["text drawn as raster images (needs OCR)"]
export const SEALED_REPORT_PREFIX = "This file carries an Omitly report (omitly-audit.json) sealed with key ";
```

`capped(null, [])` returns `incomplete` with the default why W0, "this tool cannot confirm the
document is ready to send". W0 contains no matcher token, so no exemption is needed.

In `verdict-rule.ts`, add `reconcileVerdict(v, issued)`. When `issued.outcome !== "safe_to_send"`
and `v.verdict === "safe_to_send"`, it sets the state:
- `needs_review`: state `needs_review`, `blocking: false`, the why lines appended to `review`;
- `incomplete`: state `cannot_verify`, the why lines appended to `reasons`;
- `not_a_pass`: `needs_review` with `blocking: true`, the why lines appended to `problems`.

It also sets `summary` to the fixed `SUMMARY[outcome]`:

| outcome | `SUMMARY` |
|---|---|
| `needs_review` | "This file needs review before it is sent." |
| `incomplete` | "Omitly could not confirm every part of this file." |
| `not_a_pass` | `UNDER_MARK_SUMMARY` |

`reason_code` stays null.

**Why strings** (exact; `{n}` is a count):

| Id | String |
|---|---|
| W1 | `{n} sensitive item(s) found` |
| W2 | `text is still present under a redaction mark ({n} item(s))` |
| W3 | `INCOMPLETE SCAN` |
| W4 | `Check verdict: {Needs Review — problems found \| Needs Review \| Cannot Verify}` |
| W5 | `part of the file was not read` |
| W5b | `the engine could not complete its checks` (v0.2.1) |
| W6 | `the file carries its own sealed report, which this check relied on: confirm the key is the sender's` |
| W7 | `the engine raised a warning` |
| W8 | `a seal shows integrity only and is not a check of the content` |
| W9 | `{n} recorded redaction region(s) failed` |
| W10 | `the document's metadata was not scrubbed` |
| W11 | `a redaction record is not a check of the document: run check_redaction on the output` |
| W12 | `a pattern scan is not a check of the document: run check_redaction` |
| W13 | `the seal does not verify` / `the seal was removed` |
| W14 | `the file's own report records a failed redaction` |
| W15 | `the file's own report records items to review` |
| W16 | `{n} hidden-content check(s) failed` |
| W17 | `the verifier raised a warning` |

### 7.2 Parser and module boundary

| Check today | Tonight |
|---|---|
| replies.ts:83-109 `coverageProblem` shapes | stays in the parser. It adds C6's required key sets per engine; a missing key is a parse failure |
| replies.ts:110-121 and :551 "complete beside an unread surface" | stays, using Set 1 (§4) |
| `parseScanReply` count/total/clean consistency (:152-198) | stays |
| `parseSidecarVerifyReply` (:237-267), including :263-265 | stays: the engine's own `compute_all_pass` contradiction. Warnings move to `sidecarCaps` |
| `parseSealReply` :343-345, :347 | stays |
| `parseSealReply` :346 "verified beside an engine warning" | **deleted**, replaced by S7 |
| `parseRedactAudit` :445, :453-466 | stays |
| `parseRedactAudit` :449-452 "pass beside an engine warning" | **deleted**, replaced by A3 |
| `parseCheckVerdict` (:504-536) | stays. Sha and C2b live in `passOutcome` |
| `parseCheckEnvelope` :593-600 | replaced by the §3.8 rule |
| `parseSealEnvelope` :615-618 | replaced by the §3.8 rule |
| `checkOutcome` (verdict-rule.ts:212) | **deleted**. `passOutcome` replaces it; update the imports in replies.ts:20, index.ts, result-card.ts |
| `sealOutcome` (seal.ts:321) | **deleted**. `sealCaps` replaces it |
| `isSealError` / `isSealErrorVerdict` | unused by outcomes. Leave them for `isError` until verify_seal stops using them (it already returns `false`) |
| `applyScanToVerdict`, `legsDisagree`, `embeddedReportLine` | stay. `embeddedReportLine` changes per §6.2 |
| `denyingDisclosure` (coverage-rule.ts:40) | renamed `engineIncompleteDisclosure`, over Set 1 |

### 7.3 Files for tonight

**Create:**
- `src/outcome.ts`
- `src/outcome.test.ts` (unit: `worst`, `capped`, `passOutcome` C1–C8, `sealCaps`, `auditCaps`,
  `sidecarCaps`)
- `src/pass-contract-v02.test.ts` (T1–T18, the rig-based ones)
- `mcpb/server/outcome.js` (a hand port of `worst`, `capped`, `passOutcome`, `BENIGN_DISCLOSURES`,
  `SEALED_REPORT_PREFIX` and the why strings the bundle uses)
- `mcpb/server/outcome.test.js` (a parity table against `dist/outcome.js` when it is built, the
  pattern verdict.test.js uses)
- `tests/fixtures/clean-text.pdf`, generated by the new `src/testing/make-clean-text-fixture.mjs`
  (pdf-lib 1.17.1, already a dependency): one page of non-sensitive prose, no forms, attachments
  or images

**Modify:**
- `src/index.ts`: §3, §6
- `src/replies.ts`, `src/verdict-rule.ts`, `src/coverage-rule.ts`, `src/seal.ts`: §5, §7.2
- `src/result-card.ts`: §3.8
- `mcpb/server/{index,replies,verdict}.js`, `mirror-overlay/mcpb/server/index.js`
- `mirror-overlay/BASIS.json`: the new sha of `mcpb/server/index.js`, enforced by the repo-root
  `scripts/mirror-overlay.test.mjs`
- `src/testing/capture-goldens.mjs`: add `clean-text.pdf` to the check and find/scan lists, and
  capture `check` and `find`/`scan` on the redact_entities output
- `src/testing/goldens/{native,wasm}.json`: re-captured
- the tests in §8.2

**Delete:** nothing. `mcpb/server/verdict.js` stays, because `scripts/mirror-overlay.test.mjs:86`
asserts it is reached.

## 8. Tests

### 8.1 Conformance tests

**Tonight.** Every test is shown to fail with its rule removed.

| # | Case | Expected |
|---|---|---|
| T1 (R6-3) | invisible-text, both engines, real fixture bytes | `check_redaction` and the re-scan (server, bundle, overlay): `needs_review`; no matcher hit |
| T3 (R6-1) | v2 goldens v5.3.0 and the redact_entities output | seal tools: `incomplete`; card look `cannot`; no matcher hit |
| T5 (R6-2) | the real `verify` golden on the redact_entities output, with a stub pipeline that passes: (a) with an engine-warning string added (the engine.rs:1048-1061 wording), (b) with only notices | (a) `needs_review`, W7; (b) `safe_to_send` (the sidecar adds nothing) |
| T6 | `[]` sidecar beside real sample.pdf bytes; stub `verify` = the sample verify golden | `needs_review` (W1, W10); never `safe_to_send` |
| T7 | every §4 row and `"zzz unknown"`, each beside both `scan_complete` values | A Set 1 line (3869 included) beside `true`: row 0. The benign line beside `true`: may pass. The 4684 and unknown rows beside `true`, and every deny row beside `false`: `incomplete`, or `needs_review` with findings |
| T8 | a notice plus extra text; the exact notices; the constants test | denied; allowed; equal |
| T9 | `result.sha256` changed by one character; empty sha with `cannot_verify` + `input_too_large`; empty sha with `needs_review` | row 0; allowed (`incomplete`, or `not_a_pass` with survivors); row 0 |
| T11 | the matcher (§6.3) plus a structured walk (§6.1) over every tool × every golden, on the server, bundle and overlay; the card look over all outcomes plus missing and unknown | holds |
| T12 | the `redact` golden; the `redact_entities` golden | `needs_review`; `needs_review` (W11); no "Result:" line |
| T13 | proposal status `safe_to_send`, `pass`, and an unknown value | the §3.7 labels; no matcher hit |
| T14 | goldens through the pipeline: encrypted; scanned raster; prior revision; AcroForm; sample; covered-text; form-xobject; input_too_large. Seal: legacy clean-sealed | `incomplete`; `needs_review`; `needs_review`; `needs_review`; `needs_review`; `not_a_pass`; `not_a_pass`; `not_a_pass`. Seal: `incomplete` |
| T15 | bundle parity table (`outcome.test.js`) plus T1/T11 over the bundle and the overlay | identical |
| T16 (B1) | **print-only probe first:** real check, both engines, on the redact_entities output. Print whether `result.information` holds `SEALED_REPORT_PREFIX`. Then assert it, and assert `check_redaction` gives `needs_review` with W6 | as stated |
| T17 (M7) | positive controls: `clean-text.pdf`, both engines | `check_redaction` and the re-scan: `safe_to_send`; card `safe`; text "✅ Safe to Send". (b) The redact_entities output gives `needs_review` (W6): the documented consequence. Also print whether `find` lists anything in its `omitly-audit.json` (the M7 hypothesis) |
| T18 | single issuer | (a) The TS brand: `Issued` cannot be built outside outcome.ts (a `@ts-expect-error` file). (b) A source scan of `src/*.ts` other than outcome.ts, plus `mcpb/server/*.js` other than outcome.js, plus the overlay: no `outcome: "` or `outcome = "` literal, and every `structuredContent` `outcome` property is `<x>.outcome` |

**Follow-up:**
- **T2.** A self-sealed dirty v1. Needs a `seal_pdf` Rust helper.
- **T4.** A crafted v2 with status `pass`. Needs ML-DSA and P-384 keys.
- **T6n.** Real-engine vacuity of the empty sidecar.
- **T10.** Assert the native engine received the snapshot path.
- **T16b.** A crafted self-sealed report that declares an OCR layer over hidden non-pattern text.

### 8.2 Existing tests that change (M10)

Rigs copy the real fixture into `doc` and set synthetic replies' `result.sha256` to
`sha256(doc)`. That covers pass-contract-r6.test.ts:43 and the matching rig in r5 and
pass-contract.test.ts.

| Test | New expectation |
|---|---|
| pass-contract.test.ts:199-205 (v1/v2 seal "positive controls") | `outcome: "incomplete"`. `structuredContent.embeddedReport.userVerdict` is `"safe_to_send"` (attributed) |
| pass-contract.test.ts:372-376 (sidecar `verify("pass")` gives no NOT A PASS; the clean stub passes) | The sidecar result follows the pipeline stub: NOT A PASS unless the pipeline passes. The positive control needs sha-bound replies |
| pass-contract-r5.test.ts:82-86 (v2 positive control) | `incomplete` |
| pass-contract-r5.test.ts:185 (`LEGITIMATE_LIMITS` includes the suspect-font line) | the suspect-font line: never a parse failure, but outcome `incomplete` |
| pass-contract-r5.test.ts:315-319 (card `safe` for a verified seal, or with no outcome) | `cannot` for `incomplete`; `error` with no outcome |
| pass-contract-r6.test.ts:61 `POSITIVE` | drop `these bytes are unchanged`; use the §6.3 matcher |
| pass-contract-r6.test.ts:94-109 (v1 positive control `safe`; "engine warning" gives `isError`) | `incomplete`, look `cannot`; an engine warning gives `needs_review` (S7), not `isError` |
| pass-contract-r6.test.ts:122 (legacy) | unchanged (`incomplete`) |
| pass-contract-r6.test.ts:152-169 (raster-limit envelope `safe`; denying lines give `error`) | raster limit: still `safe` when `outcome` says so; denying lines beside `scanComplete: true` still `error` (Set 1) |
| pass-contract-r6.test.ts:236-262 (input_too_large) | unchanged, and allowed under C3 |
| real-engine-goldens.test.ts:111, :117 (v5.3.0 and the redact output give `safe_to_send`) | `incomplete` |
| result-card.test.ts:459 (`sealLook` v2 `safe`) | the test moves to look = f(outcome); `sealLook` no longer decides the look |
| mcpb/server/pass-contract.test.js:17, :92, :139 (outcome from `verdict.js`; safe on stub replies) | import from `outcome.js`; the stubs carry sha-bound results |
| mcpb/server/pass-contract.test.js:160-164 (source string check against verdict-rule.ts) | point it at outcome.ts `notAPassLead` |
| mcpb/server/pass-contract.test.js:195-197 (re-scan `isError: true` on findings) | `isError: false`, `outcome` `needs_review` |
| mcpb/server/pass-contract.test.js:218, :224-244 (denying disclosures beside `true` give `isError`; benign line read) | unchanged for Set 1 lines; add the 3869 pattern; benign stays read |
| mcpb/server/pass-contract.test.js:267 | the K1 survivor case on the re-scan: now `not_a_pass` |
| mcpb/server/verdict.test.js | its `checkOutcome` cases move to `outcome.test.js` |

## 9. Decisions

### 9.1 Owner (16 Nov)

- **Q1 = A.** No seal tool ever gives `safe_to_send`, for v1 or v2 of any era (§3.5).
- **Q2 = B.** `verify_document` runs the full check. Tonight it is capped instead (below).
- **Q3 = yes.** Read-once and sha binding are conditions on every surface (C1, C3).
- **Q4.** The suspect-font line denies a pass. Raster "needs OCR" stays benign (§4).
- **Q5 = A.** The redact tools run the full check. Tonight they are capped instead (below).
- **Q6 = A.** `find_sensitive_regions` carries an `outcome`, never `safe_to_send`.
- **Q7 = keep.** `clean` keeps its name and is documented as a scan fact (§6.1).

### 9.2 Decisions for tonight (orchestrator)

- **Scope split.** As in §0: one issuer, `worst()`, the seal cap, the re-scan check, the sidecar
  warning cap, the card from outcome, B5, B6, M6 placeholders, M7 goldens and the M10 table.
- **Q2/Q5: capped tonight.** `verify_document` is capped at `incomplete` with a pointer. The redact
  tools are capped at `needs_review` (W11) with a pointer. The full check is the first follow-up,
  F1. From the code, the existing path cannot be reused unchanged:
  - The pipeline is inline in the `check_redaction` handler (index.ts:2398-2431). It has to be
    factored for the re-scan anyway, but the two other callers need more than a call:
    - `verify_document` shares the strict `verifySealOutputSchema` (index.ts:768) and the seal
      card model. A check leg needs a new schema branch and a new card model.
    - The redact done schemas (index.ts:508-529) have no check fields, and a pipeline failure
      after the file is written has no defined result.
  - Both would hit the C2b cap on every Omitly-sealed file. A genuine output carries its own
    bound report, so the full check could not give `safe_to_send` without the minted-key
    exception, which is new logic (F2).
  - Whether `find` flags the digits in an output's own `omitly-audit.json` is unprobed (T17).
    If it does, every redact output reads `needs_review` regardless.
- **B1:** C2b, keyed on the `sealed_report_attached` information line. Probe T16 first.
- **B2:** C3 as stated. Rigs copy fixture bytes.
- **B3:** two sets (§4).
- **M3:** unscrubbed metadata gives `needs_review` (sidecar W10, seal S6).
- **M4:** `withSnapshot` is specified (C1) and built in F3.
- **B7:** §7.

### 9.3 Follow-up (in order)

- **F1.** Q2 = B and Q5 = A: `verify_document` and the redact tools call `runCheckPipeline`.
  verify_document gets the check outcome, lowered by S1–S4 only; S5–S8 become neutral there, so a
  held seal does not cap it (M2). The redact tools snapshot the output after the write, and require
  `sha256(B_out) === audit.result.sha256 === check.result.sha256` (row 0 otherwise). This needs
  schema and card work.
- **F2.** The minted-key exception: the redact tools may drop the C2b cap when the line's key equals
  the `audit.sealFingerprint` they received in the same call.
- **F3.** `withSnapshot` (C1), with a native private copy for every native call, the sidecar
  included. Then T10.
- **F4.** An engine option for `free_check` to disable `attachment_exemptions` and the declared
  layer (check.rs:257-261). Then drop C2b, or keep it for desktop parity. Closes the
  envelope residual.
- **F5.** Generate `mcpb/server/outcome.js` with esbuild (pinned 0.28.2, `scripts/build-view.mjs`).
  Build only in `build` and `mcpb:prep`; under `test`, a `--check` mode that builds to a temporary
  directory and diffs. Use `banner` (the GENERATED header), `absWorkingDir`, `target` and
  `legalComments`. Update the mirror test that asserts `verdict.js` (scripts/mirror-overlay.test.mjs:86)
  in the same MR. Then consolidate `verdict-rule.ts`, `coverage-rule.ts`, and the outcome halves
  of `seal.ts` and `replies.ts` into one module.
- **F6.** An engine field for the v2 seal key fingerprint (`key_id`). Today it is null on every v2
  reply.
- **F7.** Measure the suspect-font hit rate on a real corpus (M12). Report it to the owner.
- **F8.** Route v2 sidecar engine codes by `route()`: Unsafe codes give `not_a_pass`.
- **F9.** A Rust test that emits the product-notice constants as a JSON fixture. It replaces the
  source-reading test.
- **F10.** Tests T2, T4, T6n and T16b, and the T10 snapshot assertion after F3.

## Errata v0.2.1

From the Codex and Kimi review of the v0.2 build. Each item states the rule; the tests are in
`src/pass-contract-v021.test.ts` and `mcpb/server/pass-contract-v021.test.js`. These supersede the
text of §3.4, §6.3, §6.4, §7.1, §8 and the W-table where they differ.

1. **Sidecar `warnings` is required (§3.4).** `parseSidecarVerifyReply` fails (row 0) unless `warnings`
   is an array of strings (main.rs:1171). A missing, null, string, object or mixed list can no longer
   reach `sidecarCaps` and be read as "no warning".
2. **No engine error text from `verify` (§6.4).** When the sidecar `verify` answers `ok: false`, the text
   is fixed ("Could not verify: the engine could not check this file's sidecar, so no result could be
   given. Do not treat this file as checked.") and the engine's `error` is not printed: the native
   unknown-variant error (main.rs:1091) quotes the sidecar.
3. **The seal version token is structured only (§6.4).** `seal.version` keeps the raw token; the text
   ("a seal version this verifier does not implement") and the card ("Seal version not recognised",
   "Sealed with a version this app can't check") name no version. The two card titles therefore differ
   from the desktop App.tsx wording on purpose.
4. **One sanitiser for file-derived previews (§6.3, §6.4).** Every region, survivor, off-page,
   located-text and removed-entity preview that reaches a text goes through `safeText`
   (src/verdict-rule.ts, mcpb/server/verdict.js): NFKC, then each green glyph (✅ ✓ ✔ ☑ 🟢) and each
   phrase of the matcher (`safe to send` and its `_`/`-` forms, `no recoverable pii`,
   `verification: pass`, `intact`, `clean`, `verified`, `passed`) becomes "•". `mask_preview`
   (detect.rs:2338) keeps non-alphanumerics, so a file can carry them. `structuredContent` keeps the raw
   preview. All three copies (server, bundle, overlay) apply it.
5. **The matcher's closed list of engine negation sentences (§6.3).** After the lead and the three
   allowed negations, the matcher also deletes, whole and after NFKC + lowercase, exactly these two
   sentences, and nothing else:
   - "not every redaction verified": the `{verdict}` of the sealed-report line for a v1 report that
     records a failure (crates/omitly-seal/src/check.rs:1957);
   - "A font's character encoding could not be verified, so some text may not have been read
     correctly." (check.rs:1763-1764, `unverified_type0_codespace`).
   A longer, shorter or altered sentence is still a hit. The list is `ENGINE_NEGATIONS` in
   `src/testing/matcher.ts`, shared by the bundle tests.
6. **Page lists are bounded by the reply (§7.1 `parseCheckVerdict`, `checkItemSchema`).** The fixed
   10,000-page cap is removed (the engine lists every distinct page it counted, check.rs
   `visible_text_item`). An item's `pages` must each be a whole number from 1 to the result's
   `pagesTotal`, with no repeat; a page list on a result that has no `pagesTotal` cannot be bounded and
   is refused. Either failure is `result_invalid` (row 0).
7. **Two vacuous tests made real (§8).** Every non-`safe_to_send` document-tool text starts with the issued lead
   (`⚠️ NOT A PASS — ` + why strings joined by "; " + ".") and every why is one of W0–W17 and W5b (T11
   `assertLead`); T7's "needs_review with findings" rows call the tool and assert the outcome.
8. **W5b (§3.6 A4, W-table).** A v2 audit whose overall is `technical_fail` is capped `incomplete` with
   W5b, "the engine could not complete its checks", not W5 ("part of the file was not read"), in both
   issuers.

## Errata v0.2.2

From the re-review (Grok G1–G5, Codex C1–C5, Kimi K2). Tests: `src/pass-contract-v022.test.ts` and
`mcpb/server/pass-contract-v022.test.js`.

**The class rule (§6.4).** Every non-constant string that reaches a tool's text is passed through
`safeText` or removed from the text: engine `error` strings, exception messages, output paths, file
names, seal fingerprints, notes. Raw values stay in `structuredContent`. Test E9 enforces it: every
document tool, on the server, the bundle and the overlay, with a hostile file name, hostile engine
string fields and non-pass outcomes, must pass the §6.3 matcher; and every non-pass text starts with
its issued lead. (`extract_text` returns document content by design and `check_license` reads no
document: both are out of this rule.)

- **G1.** `check_redaction` and the re-scan name no path in their text: "…found nothing in this file."
  and "…in the part of this file that it read."
- **G2.** `sealText` prints the seal fingerprint only if it is colon-hex (`^[0-9A-Fa-f:]{1,200}$`),
  else "a key this engine does not report".
- **G3.** `verify_redaction`'s structured `findings` list everything `totalFindings` counts, on both
  paths: regions, survivors and off-page items, each with `where` (`regions` | `survivors` |
  `offPage`); an off-page item also carries its raw `source`.
- **G4.** `parseRedactAudit` requires `warnings` (an array of text) on EVERY audit: the engine always
  emits it, pass or fail (omitly-cli main.rs:547). Both redact tools remember that the engine wrote the
  output; any later failure, including a throw, says "The output was written to <path>, but its audit
  could not be read. Do not use it until check_redaction has checked it." (§3.6).
- **G5.** `sourceCategory` maps the engine's real off-page sources by their prefix before ":"
  (redaction-core detect.rs): `prior-revision` (:3688) to `revision`, `form-field` (:3803) to `form`,
  `metadata:{key}` / `metadata:XMP` (:3893, :3944) to `metadata`, `attachment:{name}` (:4031) to
  `attachment`, `annotation:page{N}` (:4198) to `annotation`, `form-xobject:page{N}/{name}` (:4249) to
  `form-xobject`; anything else is `other`. The text shows the category only (§6.4).
- **C1.** Only the verifier's own legacy CAUTION is tied to `legacyUnboundVerdict`: it is inserted at
  index 0 exactly when the flag is true (omitly-seal lib.rs:1087). The flag true without that line at
  index 0 is row 0. With the flag false, a CAUTION-looking line is the report's own warning (copied
  unchanged, lib.rs:1055): the reply parses and S7 caps it at `needs_review`. `NormalizedSealResult`
  carries `legacyUnboundVerdict`; S7 exempts only that index-0 line.
- **C3.** The "scan completeness not reported" banner reads "…so the result below is not a pass.", with
  no matcher token (server and bundle).
- **C4.** An engine negation sentence (errata v0.2.1 item 5) is exempt only as a whole sentence: it
  starts the text, a line or a bullet, or follows `:` `.` `;` `!` `?`; and it ends the text or a line,
  or is followed by `.` `;` `:` `,` `!` `?` `)`. "not every redaction verified and approved" is a hit.
- **C5.** `get_proposal_status` has no outcome of its own, so its text is always a non-pass text and
  starts with the lead of `capped(null, [])` (W0): "⚠️ NOT A PASS — this tool cannot confirm the
  document is ready to send." T13 and E9 call `assertLead` on it.
- **K2.** The result card's comment now says every `isError` result renders the error state.
- **K1 (not a defect).** On the native path `find` reads the file once into B for the check pipeline's
  digest even though the engine reads it itself. Left as is for tonight.

## Errata v0.2.3

From the Grok 4.7 re-review (three more in the v0.2.2 class). The rule: **an engine string reaches a
text or a card by construction through fixed wording or `safeText`; never through "rewrite if it
matches a pattern, else print raw".** Tests: `src/pass-contract-v023.test.ts`,
`mcpb/server/pass-contract-v023.test.js`.

1. **A sealed-report line is replaced, whatever it says (§6.2, C2b).** Any information line that starts
   with `SEALED_REPORT_PREFIX` (not just one that matches the engine's exact pattern) is replaced by
   "A report embedded in this file (sealed with key K) is not evidence for this check. This check's own
   result is {Needs Review | Needs Review — problems found | Cannot Verify}. A seal shows the file is
   unchanged since it was sealed, not that the report is right." `K` is the key only if it is colon-hex
   (check.rs:1958-1962), else "sealed with a key this engine does not report". What the report records
   is never quoted; the old "says nothing to review / no failed region" map is gone.
   Every other engine copy line (a check item or summary) is passed through `safeText`, except a line
   that is exactly one of the closed list `ENGINE_COPY_NEGATIONS` (src/verdict-rule.ts; mcpb
   verdict.js): today only "A font's character encoding could not be verified, so some text may not have
   been read correctly." (check.rs:1763). The matcher's closed list of errata v0.2.1 item 5 IS that
   list; "not every redaction verified" left it because the line that carried it is replaced.
2. **Engine items reach text through an allow-list (§6.4).** A region, survivor, located occurrence or
   removed entity is rebuilt from `page`, `x`, `y`, `width`, `height`, `under_redaction` (only when of
   the right type) and `kind` and `preview` through `safeText`; every other field is dropped. An
   off-page finding is `{category, kind, preview}` (category per errata v0.2.2 G5). The tally's kinds go
   through `safeText`. No engine object is stringified into a text (`textRegion`, `textOffPage`).
3. **The card (§3.8).** The same rule on the card: the seal fingerprint only if colon-hex; the file
   name through `safeText`; every item line and the summary through `engineLine`; the footer's version,
   time and digest only in the shape the engine writes them. Card copy that held a matcher word is
   reworded: "Seal intact — …" is "Seal unchanged — …" (S5–S8 held-seal titles), and the unsupported
   seal line ends "…do not rely on this document." These MCP titles differ from the desktop's App.tsx
   on purpose.
4. **`get_proposal_status` over the desktop's decision record (§3.7; omitly#1890 steps 3–5).** The
   outcome-file branch obeys the same rules as the proposal-file branch: the structured field is
   `recordedByDesktop` (never `verdict`); the text starts with the lead of `capped(null, [])` (W0);
   the output path, the person's note and a legacy record's claims go through `safeText`; an applied
   outcome reads "…The desktop app recorded: {label}. Run check_redaction on the output for this
   server's own result." (no "Result:" line); a legacy outcome never says sealed, a verdict, or that a
   person accepted it. E9c fuzzes every string field of the proposal and outcome goldens.

**E9 widened.** (a) Every hostile E9 case that has a card renders it and the matcher must find nothing
in any rendered string (title, line, meta, section, row, footer). (b) Field fuzz: every string field
(recursively; an array contributes its first and last element) of a real golden of each reply type is
set, one at a time, to a hostile string, and the tool must either fail as row 0, or leave no matcher
hit in the text or on the card for any outcome other than `safe_to_send`, and the raw hostile string
must never be in the text. Reply types: native find, check, sidecar verify, verify_seal, redact,
redact_entities, locate_text and create; and, for the bundle and overlay, the wasm scan, check and
locate.

## Errata v0.2.4

From the Grok 4.7 re-review. Tests: `src/pass-contract-v024.test.ts`, `mcpb/server/pass-contract-v024.test.js`;
the E9 field fuzz (v023 tests) now rotates the variants below over every string field.

1. **Format characters (§6.3, §6.4).** Matching reads text as a person does. `foldText` (src/verdict-rule.ts,
   mcpb/server/verdict.js) is NFKC, then every Unicode format character (`\p{Cf}`: U+200B–U+200F,
   U+202A–U+202E, U+2060–U+2064, the soft hyphen, U+FEFF, ...) removed, then every whitespace run folded to
   one space. `safeText` folds BEFORE it replaces glyphs and pass phrases and returns the folded text, so no
   format character survives in a sanitised string and none can split a phrase. `engineLine` compares its
   closed negation lines after the same fold. The test matcher (src/testing/matcher.ts) does the same
   (its own implementation, as an independent oracle), keeps newlines only for the whole-sentence rule of
   errata v0.2.2 C4, and also reports a multi-word phrase whose separators were the only thing removed
   (`safe<ZWSP>to send` folds to `safeto send`, a hit). Characters that are not format characters (for
   example combining marks, U+2800, U+3164) are not folded: a known remaining gap.
2. **The proposal id in `get_proposal_status` text (§3.7).** The id cannot be hostile: the request's id must
   match `^[0-9a-f]{24}$` before any file is read (`readProposal`, desktop.ts; `readOutcome`,
   decisions.ts), the record's own `id` must equal it, and the desktop mints ids as 12 random bytes in hex
   (`newProposalId`, desktop.ts). It is now also printed only through `idText`: the validated shape, else
   "(unrecognised id)". E9c fuzzes `id` too (a record whose id differs is an error with fixed wording).
