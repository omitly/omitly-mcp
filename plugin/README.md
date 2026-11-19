# Omitly plugin for Claude Code

On-device PDF redaction leak check. The PDF is not uploaded; the findings (masked
previews, never raw values) go to your Claude conversation.

Licence: the Omitly End User Licence Agreement, https://omitly.app/eula. Installing or using this package accepts it.

## What you get

- One skill, `omitly-redaction`: how Claude checks a PDF for sensitive content that is
  still exposed or recoverable, and how it reports the result.
- One command, `/omitly:check <path/to/file.pdf>`.
- The local MCP server (`omitly-mcp`, run via `npx`), registered as `omitly`.

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
pages are desktop-only in Omitly 5.3: these tools have no OCR path, do not read
them, and never report one as fully scanned (`scanComplete` is false and the
text leads with INCOMPLETE SCAN; `redact` returns `needs_review`/`review_required`) — the
desktop app can OCR them. These tools check files; they do not remove anything.

Made by Omitly: https://omitly.app

The skill file in this plugin mirrors `skill/SKILL.md` in the `omitly-mcp` package.
