---
description: Check a local PDF for sensitive content that is still exposed or recoverable before it leaves the machine (on-device; the PDF never leaves your machine)
argument-hint: <path/to/file.pdf>
---

The argument `$ARGUMENTS` is the path to a local PDF. If no path was given, ask for
one and stop (a call on an empty path still uses one free check). Follow the hard
rules of the omitly-redaction skill.

1. Call the Omitly server's `check_redaction` tool on that path (argument
   `pdfPath`), once.
2. Report the findings by kind, page and count, using masked previews only. Never
   echo a raw sensitive value.
3. Show both coverage lists (what was checked and what was not).
4. Give the verdict together with what it did not check.

If the Omitly server's tools (`check_redaction`, `find_sensitive_regions`) are not
available, say that the plugin's MCP server has not started, and stop.

Never upload the file. Do not also run `find_sensitive_regions` unless the user
asked for coordinates.
