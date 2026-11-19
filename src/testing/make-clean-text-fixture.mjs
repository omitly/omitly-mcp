#!/usr/bin/env node
/**
 * omitly#1864 contract §7.3 / T17: generates `tests/fixtures/clean-text.pdf`, the positive-control fixture that reaches Safe to Send:
 * one page of non-sensitive prose, no form, no attachment, no image, fixed dates. Deterministic for a given pdf-lib.
 *
 *   node omitly-mcp/src/testing/make-clean-text-fixture.mjs
 */
import { writeFileSync } from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { PDFDocument, StandardFonts } from "pdf-lib";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(HERE, "..", "..", "..", "tests", "fixtures", "clean-text.pdf");
const doc = await PDFDocument.create();
doc.setTitle("Quarterly summary");
doc.setCreationDate(new Date(Date.UTC(2026, 0, 1)));
doc.setModificationDate(new Date(Date.UTC(2026, 0, 1)));
const font = await doc.embedFont(StandardFonts.Helvetica);
const page = doc.addPage([400, 300]);
["The committee met on Tuesday to review the quarterly summary.", "Attendance was good and the agenda was completed on time.", "The next meeting is planned for the end of the month."].forEach((l, i) =>
  page.drawText(l, { x: 20, y: 250 - i * 24, size: 9, font }),
);
writeFileSync(OUT, await doc.save({ useObjectStreams: false }));
console.log(`wrote ${path.relative(process.cwd(), OUT)}`);
