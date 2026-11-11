---
name: omitly-pdf-pages
description: >-
  Merge, split, extract, reorder, rotate, delete and insert blank pages in local
  PDFs, on-device through the local omitly-mcp server; nothing is uploaded. Use
  when a user wants to combine PDFs, split one into parts, pull out some pages,
  reorder or rotate pages, remove pages, add a blank page, or asks what is in a
  PDF (page count, sizes, forms, signatures). Triggers: "merge these PDFs",
  "split this PDF", "extract pages 3 to 5", "rotate page 2", "delete the last
  page", "put page 4 first", "how many pages is this".
---

<!-- DRAFT (omitly#1841 phase B). Not shipped: it lives under docs/skill-drafts/, not skill/,
     until D2 wires it into skill-prompt.ts. Wording is reviewed like code. -->

# Omitly PDF pages

Five free tools for working with the pages of a PDF on the user's own computer. They
never upload anything, never change or overwrite an existing file, and need no licence.

## Hard rules

1. **Local file paths only.** Never ask the user to paste or upload a document. If they
   attached a PDF to the chat, ask for the local path of the original.
2. **Every result is a NEW file.** Choose a clear new name next to the original (for
   example `invoice-merged.pdf`). If a name is taken the tool says so: pick another.
3. **Page numbers start at 1.** The Omitly check tools (`find_sensitive_regions` and
   friends) report 0-based `page` values: add 1 before using one here.
4. **Say what was lost.** Every result lists `lost` (things the new file does not carry,
   such as bookmarks, page labels or layers) and `warnings`. Tell the user in plain words,
   in one sentence, when either is not empty.
5. **This is not redaction.** Leaving a page out does not sanitise a document: metadata,
   bookmark titles and anything a kept page shares with a left-out page can remain. If the
   user wants sensitive content removed, use the Omitly redaction tools instead.
6. **Digital signatures are removed.** The new file is unsigned. Say so if `warnings`
   mentions it, and never describe the output as signed or as the original.

## Which tool

| The user wants | Tool |
|---|---|
| Facts about a PDF (pages, sizes, encrypted, form, signed) | `pdf_info` |
| Several PDFs joined into one | `merge_pdfs` (2 to 50 inputs, in order) |
| Some pages as one new PDF | `extract_pages` (numbers and ranges, in the order wanted) |
| A PDF cut into parts | `split_pdf` (one range per file, consecutive pages) |
| Reorder, delete, rotate, add a blank page | `edit_pages` (the FINAL page list) |

Start with `pdf_info` when you do not know how many pages there are.

## Examples

- Merge: `merge_pdfs {"inputs":["a.pdf","b.pdf"],"outputPath":"a-b.pdf"}`
- Extract pages 2 and 4 to 6: `extract_pages {"pdfPath":"report.pdf","pages":[2,"4-6"],"outputPath":"report-part.pdf"}`
- Split into two files: `split_pdf {"pdfPath":"book.pdf","ranges":[["1-10"],["11-20"]],"outputDir":".","prefix":"book"}`
- Move page 3 first, rotate page 1 a quarter turn, drop page 2, add a blank at the end:
  `edit_pages {"pdfPath":"deck.pdf","pages":[{"source":3},{"source":1,"rotate":90},{"blank":true}],"outputPath":"deck-edited.pdf"}`

In `edit_pages`, `source` always means a page of the ORIGINAL file; a page you leave out is
deleted; a page may be listed once.

## When a tool refuses

Read the message to the user and act on it; the text is written for this:
- "Set OMITLY_ALLOWED_DIR..." means the user should set the folder their PDFs are in in the
  MCP config (the tools will not work from the home folder or the filesystem root otherwise).
- "A file with that name already exists" means choose a new output name.
- "This PDF is encrypted..." means the user should open it in Omitly and remove the
  encryption first. Do not try to bypass it.
- A page-number message means fix the item it quotes: numbers like 3 and ranges like "2-5".

## What stays on the computer

Everything. Results are paths, counts and flags.
