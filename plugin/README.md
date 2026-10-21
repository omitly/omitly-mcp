# Omitly plugin for Claude Code

On-device PDF redaction leak check. The PDF is not uploaded; the findings (masked
previews, never raw values) go to your Claude conversation.

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

The free check is capped and its output is evaluation-marked. Removing the sensitive
content is done in the Omitly desktop app: https://omitly.app

The skill file in this plugin mirrors `skill/SKILL.md` in the `omitly-mcp` package.
