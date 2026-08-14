# Omitly in Claude Code — a 5-minute walkthrough

This shows the real problem Omitly's MCP server solves: you're working over a
confidential PDF in Claude Code, you need to share a redacted copy, and you do
**not** want to upload the file anywhere or trust a black box drawn on top of
still-selectable text.

Everything below runs **on your machine**. The PDF never leaves disk; Claude
orchestrates, the local engine does the cutting and proves it.

## 0. One-time setup

```bash
# Build the local engine binary (from the repo root)
# omitly-redact ships with the Omitly desktop application (source not in this repository)

# Register the MCP server with Claude Code
claude mcp add omitly -- \
  env OMITLY_REDACT_BIN=$PWD/target/release/omitly-redact \
  node $PWD/omitly-mcp/dist/index.js
```

You now have eight tools available to Claude: `find_sensitive_regions`,
`locate_text`, `check_redaction`, `redact_by_entity`, `redact_pdf`,
`verify_redaction`, `verify_seal`, and `create_pdf`. The walkthrough below
covers the redaction flow; the rest — including `verify_seal`, which checks
tamper-evidence rather than redaction completeness — are documented in
[README.md](./README.md).

## 1. The easy case — "just scrub the obvious PII"

> **You:** Redact the emails and SSNs from `~/contracts/offer.pdf` and save it as
> `offer.redacted.pdf`.

Claude calls **`redact_by_entity`** once:

```jsonc
{ "pdfPath": "/Users/you/contracts/offer.pdf",
  "outputPath": "/Users/you/contracts/offer.redacted.pdf",
  "kinds": ["email", "ssn"] }
```

and reports back:

```
Redacted 2 entities → /Users/you/contracts/offer.redacted.pdf
Verification: pass

Removed:
  - ssn   "•••-••-6789"        (page 1)
  - email "••••.•••@••••••e.com" (page 1)
```

The underlying bytes are gone (not hidden), metadata is scrubbed, and a signed
`offer.redacted.pdf.audit.json` sits next to the file as proof.

## 2. The careful case — review before you cut

For anything sensitive, look before removing.

> **You:** Find any PII in `report.pdf` first — I want to see it before redacting.

Claude calls **`find_sensitive_regions`**, which returns candidates *with exact
coordinates* and a **masked** preview (the raw value never leaves your machine):

```jsonc
[ { "page": 0, "x": 250.4, "y": 610.4, "width": 79.2, "height": 14.4,
    "kind": "ssn", "preview": "•••-••-6789" },
  { "page": 1, "x": 171.2, "y": 654.4, "width": 136.8, "height": 14.4,
    "kind": "card", "preview": "•••• •••• •••• 1111" } ]
```

You see *which* secret and *where* (and you have the file open locally for the
full value); the model only ever sees the mask and the coordinates.

> **You:** Keep the SSN (the auditor needs it) but redact the card number.

Claude passes only the card region straight to **`redact_pdf`** — no guessed
geometry, the coordinates came from the engine:

```jsonc
{ "pdfPath": "...report.pdf", "outputPath": "...report.redacted.pdf",
  "regions": [ { "page": 1, "x": 171.2, "y": 654.4, "width": 136.8,
                 "height": 14.4, "reason": "PII.CARD" } ] }
```

## 3. Names and addresses — let Claude do the recognition

Pattern-matching can't reliably find names. But Claude can — so it identifies
them and uses **`locate_text`** to get their coordinates:

> **You:** Redact every mention of the claimant's name and home address.

Claude reads the document, decides the strings, then:

```jsonc
// locate_text
{ "pdfPath": "...claim.pdf",
  "texts": ["John Q. Smith", "42 Birchwood Lane"] }
// → returns a box per occurrence, which Claude feeds to redact_pdf
```

This is the division of labour that makes it trustworthy: **the model decides
*what* is sensitive; the engine decides *where* it is and proves it's gone.**

## 4. Always verify

After any redaction Claude can independently re-confirm:

```jsonc
// verify_redaction
{ "pdfPath": "...report.redacted.pdf" }
// → { "verdict": "pass", "regions": [...], "metadataScrubbed": true }
```

`verify_redaction` re-reads the output and checks that nothing renders into each
redacted region — a second, independent pass, not a restatement of step 1.

## Honest limits

- `find_sensitive_regions` is a pattern detector (email/SSN/phone/card, ASCII):
  treat its hits as **candidates for review**, not a completeness guarantee.
- `find_sensitive_regions` / `locate_text` match per text-operator; a string the
  PDF splits across operators may not match as one run. When in doubt, verify
  visually and add regions explicitly.
- `redact`/`verify` need `qpdf` installed; `find`/`locate` are read-only and
  don't.
