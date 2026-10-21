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
(see "Redacting"), which the public install does not include; removal for real,
with a tamper-evident audit seal, is the Omitly desktop app (https://omitly.app).

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
   extension first, because a failed call still uses a free check.
3. **Never echo a raw sensitive value.** The tools return masked previews
   (`•••-••-6789`) on purpose. Report by kind, page and count, and drive any
   action by page + coordinates, never by repeating the secret. Region `page`
   values are 0-based: add 1 when you tell the user a page number.
4. **Say what was checked, every time.** `check_redaction` returns a coverage
   report: what was scanned and a NOT-inspected list. Relay both. If
   `scanComplete` is false, lead with that: nothing found means nothing found in
   the part that could be read, never a clean result. Image-only pages are not
   scanned (no OCR): say how many and that a person must check them. "Nothing
   found" always means "nothing this scan can see", never "nothing is left" and
   never "safe to send" on its own; names, addresses and text inside images are
   not covered by pattern matching.
   <!-- claims-lint:allow-next-line -- this line NAMES the banned phrases in order to forbid them (omitly#227); it is the guard-rail itself, not a claim -->
   Never say "court-grade", "admissible" or "compliant". The honest claim is:
   the listed redactions were applied and that data removed, and the file is
   tamper-evident (integrity, not identity) — and only the desktop app makes it.
5. **The free check is capped and EVALUATION-marked.** Without a native engine,
   `check_redaction` and `find_sensitive_regions` share a monthly allowance
   counted on this machine (10 by default). Every call uses one, including calls
   that fail. Results carry `evaluation: true` and an EVALUATION banner: say so,
   and say it is not a removal certificate. If a call returns
   `reason: "free-cap"`, relay its `message` and stop the check. Never delete or
   edit `~/.omitly/usage.json`, change `OMITLY_FREE_CAP` or `OMITLY_STATE_DIR`,
   or use another tool to get the same scan. Call `check_redaction` once per
   file; do not also run `find_sensitive_regions` on the same file unless the
   user wants coordinates.
6. **Respect the allowed directory.** If a path is refused as outside the allowed
   directory, tell the user to move the file there or change `OMITLY_ALLOWED_DIR`
   in their MCP config. Do not copy the file yourself.
7. **No engine means no retry.** If a call returns "No redaction engine
   configured", do not retry and do not try another route. Report what you have
   and hand off to the desktop app.

## Pick the tool by intent

- **"Is this file safe to send?" / someone else redacted it** →
  `check_redaction`. Read both parts: the findings (`clean`, `byKind`,
  `survivors`, `offPage`) and the `verdict` (`safe_to_send`, `needs_review` or
  `cannot_verify`). `needs_review` with `blocking: true` means a problem such as
  recoverable text under a box was found. `safe_to_send` judges only hidden,
  covered and recoverable content, so pattern findings can still exist alongside
  it: report them, and always give `safe_to_send` together with what it did not
  check (`verdict.result.notChecked`), never alone. `isError: true` with findings
  means the file leaked; it is a result, not a tool failure.
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
  does not include: if the call returns "No redaction engine configured", say the
  seal could not be checked here and that the Omitly desktop app checks seals;
  do not report a pass or a fail. Neither tool re-scans for leftover PII.
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

`redact_pdf` and `redact_by_entity` need a native Omitly engine. If they return
"No redaction engine configured", do not try to redact: report the findings and
hand off to the desktop app. If an engine IS configured, redaction is
irreversible: confirm the source and output paths with the user, always write
to a NEW file, confirm the exact `kinds` before `redact_by_entity` (leaving
`kinds` out removes every detected kind), and run `verify_redaction` on the
output before reporting it done. Without a licence the audit output is marked
as evaluation. Never write your own redaction code as a substitute — it cannot
prove the data is gone.

## Typical flow

```
user: "I redacted this in Preview — can I send it to the other side?"
→ check_redaction(pdfPath)          # free, on-device, uses one check
   findings: 2 SSNs surviving under redaction marks; verdict: needs_review (blocking)
   coverage: page text, revisions, metadata, form fields scanned; 1 image-only page not scanned
→ report by kind/page/count + both coverage lists (masked previews only)
→ say plainly: do not send until this is fixed; the image-only page needs a person
→ hand off: removal for real, with a tamper-evident audit seal, is the Omitly
  desktop app — https://omitly.app
```
