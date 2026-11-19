# Omitly plugin for Claude Code

Free on-device PDF tools for Claude: find sensitive content in a PDF, check whether a
redacted PDF still exposes sensitive text, and merge, split, extract and edit pages. The
PDF is not uploaded; the findings (masked previews, never raw values) go to your Claude
conversation.

Licence: the Omitly End User Licence Agreement, https://omitly.app/eula. Installing or using this package accepts it.

## What you get

- One skill, `omitly-redaction`: how Claude checks a PDF for sensitive content that is
  still exposed or recoverable, and how it reports the result.
- One command, `/omitly:check <path/to/file.pdf>`.
- The local MCP server (`omitly-mcp`, run via `npx`), registered as `omitly`. Besides the
  check tools it has the page tools: `pdf_info`, `merge_pdfs`, `split_pdf`, `extract_pages`
  and `edit_pages`. They write a new file and leave the original as it is.

## Install

```
claude plugin marketplace add omitly/omitly-mcp
claude plugin install omitly@omitly
```

Or inside a session: `/plugin marketplace add omitly/omitly-mcp`.

## What loads where

The skill loads everywhere the plugin is installed. The local MCP server runs in
Claude Code and Cowork, not in claude.ai chat.

## Limits

The free check has no usage limit; its results carry a sentence saying it removes nothing and is not a removal certificate. Scanned (image-only)
pages are desktop-only: these tools have no OCR path, do not read
them, and never report one as fully scanned (`scanComplete` is false and the
text leads with INCOMPLETE SCAN; `redact` returns `needs_review`/`review_required`) — the
desktop app can OCR them. The check tools check files; they do not remove anything.

Made by Omitly: https://omitly.app

The skill file in this plugin mirrors `skill/SKILL.md` in the `omitly-mcp` package.
