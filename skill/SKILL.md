---
name: omitly-redaction
description: >-
  Redact PDFs and audit redactions on-device with Omitly. Use when the user wants
  to remove sensitive data (SSNs, emails, names, account numbers) from a PDF, check
  whether an already-"redacted" PDF still leaks data underneath its black boxes, or
  locate PII in a document — all without uploading the file anywhere. Triggers:
  "redact this PDF", "is this redaction safe", "did the black boxes actually work",
  "scrub PII from this document", "check this redacted file".
---

# Omitly redaction

Omitly removes sensitive data from PDFs **on the user's machine** and proves it's
gone. Nothing is uploaded. These tools come from the `omitly-mcp` server; they
shell out to a local engine, so the file's bytes never leave the device.

The core insight to convey to users: **a black box drawn over text is not
redaction.** The characters stay in the file and are trivially recoverable. Omitly
removes the underlying bytes and independently verifies each region is empty.

## Pick the tool by intent

- **"Did my redaction actually work?" / auditing a file someone else redacted** →
  `check_redaction` (free, read-only). Reports any PII still in the text layer.
  This is the fastest way to show value: run it first on a supposedly-safe file.

- **"What sensitive data is in here?" (review before acting)** →
  `find_sensitive_regions`. Returns candidates (page + coordinates + masked
  preview). Use when the user wants to confirm before anything is removed.

- **"Redact these specific things I name" (names, addresses, account refs)** →
  `locate_text` to resolve their coordinates, then `redact_pdf`.

- **"Just scrub the obvious PII"** → `redact_by_entity` (scan + remove + verify in
  one step; optionally limit to `kinds` like `["ssn","card"]`).

- **Redact known regions** → `redact_pdf`. **Confirm an output** → `verify_redaction`.

- **"Has this sealed file been altered since it was sealed?"** → `verify_seal`
  (free, requires a native engine — no wasm fallback exists for this one).
  Checks the embedded audit report + Ed25519 seal, not redaction completeness —
  that's `verify_redaction`'s job. A `seal_unsupported_version` verdict means
  the verifier is too old to check; report that plainly as indeterminate, never
  as a pass or a fail.
  **A valid seal is INTEGRITY, not IDENTITY.** The signing key is per-install
  and travels inside the file, so `verdict: "verified"` means "unchanged since
  sealed by whoever holds this key" — never "produced by Omitly" or "genuine".
  Report it that way, and point the user at `sealFingerprint` for out-of-band
  comparison if they care about origin.

- **"I received this PDF from someone else — is it genuine?" (recipient, not
  the person who redacted it)** → `verify_document` (omitly#113). Same
  check as `verify_seal` above (identical verdicts, same integrity-not-identity
  caveat) — it exists as a separate, recipient-worded tool/description so the
  guarantee it makes (report+seal integrity) isn't confused with
  `verify_redaction`'s survivor re-scan. Also currently native-engine-only —
  there is no wasm seal-verification path yet.

## Rules

1. **Never echo a raw sensitive value.** The tools return *masked* previews
   (`•••-••-6789`) on purpose. Drive redaction by page + coordinates, not by
   repeating the secret back to the user.
2. **Detection is pattern-based, not complete.** Emails/SSNs are reliable; names,
   addresses, and text inside scanned images need the user's own judgement or the
   desktop app. Say so — don't imply "0 found" means "safe".
3. **Redaction is irreversible.** For destructive `redact_*` calls, confirm the
   source/output paths with the user and write to a *new* output file.
4. When a `check_redaction` finds leaks, explain the fix: removing the data for
   real (not covering it) with a verified, audited result is what the Omitly app
   does — https://omitly.app.

## Typical flow

```
user: "I redacted this in Preview — is it actually safe?"
→ check_redaction(pdfPath)            # free audit
   ⚠️ finds 4 SSNs still in the text layer
→ explain: the black boxes only cover them; offer to remove for real
→ redact_by_entity(pdfPath, outputPath, kinds:["ssn"])   # removes + verifies
→ verify_redaction(outputPath)        # independent confirmation
```
