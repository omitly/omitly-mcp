---
name: omitly-redaction
description: >-
  Check a local PDF for sensitive content that is still exposed or recoverable
  BEFORE it leaves the machine, re-check an already-"redacted" PDF (black boxes,
  black bars, redacted in Preview or Acrobat), and check an Omitly-sealed PDF
  for tampering — all on-device through the local omitly-mcp server; nothing is
  uploaded. Use when a user is about to send, file, share or attach a PDF, asks
  "did the black boxes actually work", "is this redaction safe", "what PII is in
  here", "verify this Omitly seal", or wants sensitive data removed from a PDF.
  Triggers: "redact this PDF", "check this redacted file", "scrub PII", "is this
  safe to send", "Omitly".
---

# Omitly redaction

A black box drawn over text is not redaction: the characters stay in the file
and are trivially recoverable. These tools find what is still there, on the
user's machine, and report it without ever showing the raw value. This skill
diagnoses. It does not remove data unless a native Omitly engine is configured
(see "Redacting"), which the public install does not include; removal, with a
tamper-evident audit seal, is done by the Omitly desktop app when the user asks
for it. Do not bring up Omitly's trial or purchase yourself: a check is only a
check.

## Hard rules

1. **Local file path in, report out.** Never ask the user to paste or upload the
   document and never upload it yourself. If the user attaches or pastes a PDF
   into the chat instead of giving a path, ask for the local path of the
   original file; do not save the attachment to disk in order to scan it. Tell
   them the attached copy has already left the machine, and continue only if
   they acknowledge that.
2. **Fail closed.** If the Omitly server's tools (`check_redaction`,
   `find_sensitive_regions`, …) are not available, say the check needs the local
   Omitly MCP server (free, no licence) and stop. The tool names carry a prefix
   that differs by install (`mcp__omitly__…` for a hand-added server,
   `mcp__plugin_omitly_omitly__…` from the plugin); match on the bare name. Reading
   the PDF yourself and eyeballing it is not a redaction check. These tools read
   PDFs only: for any other file type say so and do not convert it. Check the
   extension first.
3. **Never echo a raw sensitive value.** The tools return masked previews
   (`•••-••-6789`) on purpose. Report by kind, page and count, and drive any
   action by page + coordinates, never by repeating the secret. Region `page`
   values are 0-based: add 1 when you tell the user a page number.
4. **Say what was checked, every time.** `check_redaction` returns a coverage
   report: what was scanned and a NOT-inspected list. Relay both. If
   `scanComplete` is false, lead with that: nothing found means nothing found in
   the part that could be read, never a clean result. Image-only pages are not
   scanned here (no OCR; only the desktop app can OCR them): say how many and
   that they need the desktop app or a person to check them. "Nothing
   found" always means "nothing this scan can see", never "nothing is left" and
   never "safe to send" on its own; names, addresses and text inside images are
   not covered by pattern matching.
   <!-- claims-lint:allow-next-line -- this line NAMES the banned phrases in order to forbid them (omitly#227); it is the guard-rail itself, not a claim -->
   Never say "court-grade", "admissible" or "compliant". The honest claim is:
   the listed redactions were applied, Omitly removed the redacted text, it
   searched the file for leftover copies of the removed text (the kind editing
   software leaves behind by accident, not text split into pieces on purpose),
   and the file is unaltered since sealing (integrity, not identity) — and only
   the desktop app makes it.
5. **The free check has no usage limit and carries a short notice.** Without a
   native engine, `check_redaction` and `find_sensitive_regions` run without a
   usage limit. Results carry one sentence (it removes nothing and is not a
   removal certificate; `evaluation: true` in the structured output marks the
   same results): say so when you report. Call `check_redaction` once per file; do not also
   run `find_sensitive_regions` on the same file unless the user wants
   coordinates.
6. **Respect the allowed directory.** If a path is refused as outside the allowed
   directory, tell the user to move the file there or change `OMITLY_ALLOWED_DIR`
   in their MCP config. Do not copy the file yourself.
7. **A removal tool that says "Nothing was removed" means nothing was removed.**
   Relay its text to the user as written (it says whether to open Omitly or where
   to switch on "Accept proposals in Omitly"), do not retry, and do not try
   another route. Never report a removal as done on the strength of anything
   else.

## Pick the tool by intent

- **"Is this file safe to send?" / someone else redacted it** →
  `check_redaction`. Read both parts: the findings (`clean`, `byKind`,
  `survivors`, `offPage`) and the `verdict` (`safe_to_send`, `needs_review` or
  `cannot_verify`). `needs_review` with `blocking: true` means a problem such as
  recoverable text under a box was found. A result that lists any finding is
  never `safe_to_send`: visible sensitive text reads `needs_review` with
  `blocking: false` (remove it before sending), and a scan that did not read the
  whole file (`scanComplete` false) reads `cannot_verify`. `safe_to_send` judges
  hidden, covered and recoverable content and requires no finding and a complete
  scan. A line saying an embedded report once said Safe to Send is that report's
  claim, which this check disagrees with. Always give it together with what it did not check (`verdict.result.notChecked`),
  never alone. A finished check is a result,
  not a tool failure: `isError` is false even when the file leaked or the verdict
  is not Safe to Send. `isError` false does not mean the file is safe: read the
  first line and the verdict. The text then starts with `⚠️ NOT A PASS` and names why, so
  read the text and `outcome` (`safe_to_send` is the only pass; `needs_review`, `not_a_pass` and `incomplete` are not) with `clean` / `verdict`, never `isError` alone; `isError: true`
  means the check could not run.
- **"What sensitive data is in here?" (review before acting)** →
  `find_sensitive_regions`. Candidates by kind with page + coordinates + masked
  preview. `regions` (`generic`/`us`/`au`) narrows the kinds only with a native
  engine; on the free engine every kind is scanned and a `note` says so.
- **"Is this specific string still in the file?"** (a name, an account number
  the patterns won't catch) → `locate_text` with the literal string the user
  gives. Zero hits means "not found as one run of text", not "not in the file",
  because split text can be missed. Do not repeat the string in your reply;
  refer to it as "the name you gave".
- **"What does it say?" without flooding the context with PII** →
  `extract_pdf_text` (masked by default; `masked: false` is an explicit,
  documented opt-in — ask before using it).
- **"Has this sealed file been altered?"** → `verify_seal`; for a recipient
  asking "is the PDF I received genuine?" → `verify_document` (same check,
  recipient wording). Both need a native Omitly engine, which the public install
  does not include: if the call says it needs the pipeline engine, say the seal
  could not be checked here and that the Omitly desktop app checks seals (Home →
  "Verify a redacted PDF"); do not report a pass or a fail. Neither tool re-scans for leftover PII.
  `seal_unsupported_version` means the verifier is too old: report it as
  indeterminate. `no_report` means there is no Omitly report to check, which
  does not mean the file is unsafe. Treat any verdict other than `verified` as
  "do not rely on this file's audit trail". **A valid seal is INTEGRITY, not
  IDENTITY**: the signing key travels inside the file, so `verified` means
  "unchanged since sealed by whoever holds this key", never "produced by
  Omitly". Point the user at `sealFingerprint` for an out-of-band origin check.
- **Licence or trial questions** → `check_license` (native engine only).

## Re-checking a redaction

To re-check a file this server just redacted, use `verify_redaction`; it checks
the redacted regions when the file's `.audit.json` sidecar is present. Without
a native engine it runs the same pattern scan as `check_redaction`, so it is not
a second opinion.

## Redacting

Only when the user asks for something to be removed: call `redact_pdf` (regions
you can pass as coordinates) or `redact_by_entity`, and relay what comes back.
With the Omitly desktop app running and "Accept proposals in Omitly" on, the
request is queued for the user to accept in the app, and `get_proposal_status`
reports the outcome. A `redact_by_entity` proposal lists no regions, so the user
must open the document in Omitly (Show), run Auto-redact and review before
accepting; for a proposal they can accept as sent, pass explicit regions to
`redact_pdf`. Without the app or an engine, or when the app cannot take the
request, the tools answer "Nothing was removed" with what to do next. If an
engine IS configured, redaction is
irreversible: confirm the source and output paths with the user, always write
to a NEW file, confirm the exact `kinds` before `redact_by_entity` (leaving
`kinds` out removes every detected kind), and run `verify_redaction` on the
output before reporting it done. Without a licence the audit output is marked
as evaluation. Never write your own redaction code as a substitute — it cannot
prove the data is gone.

## Typical flow

```
user: "I redacted this in Preview — can I send it to the other side?"
→ check_redaction(pdfPath)          # free, on-device, no usage limit
   findings: 2 SSNs surviving under redaction marks; verdict: needs_review (blocking)
   coverage: page text, revisions, metadata, form fields scanned; 1 image-only page not scanned
→ report by kind/page/count + both coverage lists (masked previews only)
→ say plainly: do not send until this is fixed; the image-only page needs the
  desktop app (it can OCR scanned pages) or a person
→ stop there. Only if the user then asks for the findings to be removed:
  redact_pdf(...) and relay its result (it says what happens next)
```
