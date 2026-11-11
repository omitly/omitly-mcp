/** omitly#1841 phase B: the page-spec grammar and the refusal messages (pure functions). */
import assert from "node:assert/strict";
import { test } from "node:test";
import { expandPageSpec, isAscending, isContiguousAscending, splitFileName, SPLIT_PREFIX } from "./pageSpec.js";
import { EDIT_CODES, EditRefusal, messageFor, showItem } from "./refusals.js";

function refusal(fn: () => unknown): EditRefusal {
  try {
    fn();
  } catch (e) {
    assert.ok(e instanceof EditRefusal, `expected an EditRefusal, got ${String(e)}`);
    return e;
  }
  assert.fail("expected a refusal");
}

test("a valid spec expands in order: numbers and ranges", () => {
  const r = expandPageSpec([3, "5-7", 1]);
  assert.deepEqual(r.pages, [3, 5, 6, 7, 1]);
  assert.deepEqual(r.itemOf, [0, 1, 1, 1, 2]);
});

test("every invalid item is page_spec with the fixed message", () => {
  const bad: unknown[] = ["5", "01-03", "1-02", " 1-3", "1 -3", "1-3 ", "5-2", 0, -1, 1.5, "0-3", "a-b", "", "1-", "-3", "1--3", "1-3-5", null, {}, [], true, Number.MAX_SAFE_INTEGER + 2, "99999999999999999999-99999999999999999999"];
  for (const item of bad) {
    const r = refusal(() => expandPageSpec([item]));
    assert.equal(r.code, "page_spec", `item ${JSON.stringify(item)}`);
  }
  assert.equal(
    refusal(() => expandPageSpec(["5"])).message,
    'Page item "5" is not valid: use a page number like 3 or a range like "2-5".',
  );
  assert.equal(
    refusal(() => expandPageSpec(["5-2"])).message,
    'Page item "5-2" is not valid: use a page number like 3 or a range like "2-5".',
  );
  assert.equal(
    refusal(() => expandPageSpec([0])).message,
    'Page item "0" is not valid: use a page number like 3 or a range like "2-5".',
  );
});

test("a repeated page is duplicate_page, across items and inside ranges", () => {
  assert.equal(refusal(() => expandPageSpec([2, 2])).message, "Page 2 is listed twice.");
  assert.equal(refusal(() => expandPageSpec(["1-4", 3])).message, "Page 3 is listed twice.");
  assert.equal(refusal(() => expandPageSpec(["1-3", "3-5"])).code, "duplicate_page");
});

test("expansion past 10,000 pages is too_many_pages, and is counted before a range is expanded", () => {
  assert.equal(expandPageSpec(["1-10000"]).pages.length, 10_000, "10,000 exactly is fine");
  const r = refusal(() => expandPageSpec(["1-10001"]));
  assert.equal(r.code, "too_many_pages");
  assert.equal(r.message, "That would be more than 10,000 pages.");
  // Would take minutes and gigabytes if it were expanded first.
  const t = Date.now();
  assert.equal(refusal(() => expandPageSpec(["1-999999999"])).code, "too_many_pages");
  assert.ok(Date.now() - t < 1000, "refused without expanding");
  assert.equal(refusal(() => expandPageSpec([1, "100-10100"])).code, "too_many_pages");
  // The budget a split passes in is honoured.
  assert.equal(refusal(() => expandPageSpec(["1-5"], { budget: 4 })).code, "too_many_pages");
});

test("the item shown back is shortened and cleaned", () => {
  assert.equal(showItem("a\nb\"c\\d"), "a?b?c?d");
  assert.equal(showItem("x".repeat(100)).length, 43);
  assert.equal(showItem(undefined), "undefined");
});

test("contiguity, ascending and split names", () => {
  assert.ok(isContiguousAscending([3, 4, 5]));
  assert.ok(isContiguousAscending([7]));
  assert.ok(!isContiguousAscending([3, 5]));
  assert.ok(!isContiguousAscending([4, 3]));
  assert.ok(isAscending([1, 3, 9]));
  assert.ok(!isAscending([3, 1]));
  assert.equal(splitFileName("doc", [3, 4, 5]), "doc-p3-5.pdf");
  assert.equal(splitFileName("doc", [3]), "doc-p3.pdf");
});

test("split prefix pattern", () => {
  for (const ok of ["a", "A1", "my-file_1.v2", "x".repeat(64)]) assert.ok(SPLIT_PREFIX.test(ok), ok);
  for (const bad of ["", ".hidden", "-x", "a b", "a/b", "a:b", "x".repeat(65), "é"]) assert.ok(!SPLIT_PREFIX.test(bad), bad);
});

test("the refusal table: every code has its exact fixed message", () => {
  const expected: Record<string, string> = {
    allowed_dir_needed: "Set OMITLY_ALLOWED_DIR to the folder your PDFs are in.",
    not_a_file: "That path is not a file.",
    not_a_directory: "That output folder does not exist.",
    not_pdf_name: "Output files must end in .pdf.",
    hidden_path: "Omitly won't write inside a hidden folder or a .git folder.",
    too_large: "That PDF is over the 200 MB limit. (Merge: the inputs are over 500 MB in total.)",
    output_too_large: "The result would be over the size limit.",
    encrypted: "This PDF is encrypted (it may only restrict permissions). Open it in Omitly to remove the encryption, then try again.",
    page_spec: 'Page item "X" is not valid: use a page number like 3 or a range like "2-5".',
    page_out_of_range: 'Page item "X" is past the end: this PDF has 4 pages.',
    duplicate_page: "Page X is listed twice.",
    split_name_clash: 'Two ranges would both be named "X".',
    split_not_contiguous: "Each split range must be consecutive pages in order.",
    output_exists: "A file with that name already exists. Choose a new output name.",
    write_failed: "Omitly could not write the output file.",
    not_pdf: "That file is not a PDF.",
    too_many_pages: "That would be more than 10,000 pages.",
    no_source_pages: "The page list has no pages from the original.",
    xfa: "This is a dynamic XFA form, which these tools can't edit. Open it in Omitly.",
    busy: "Omitly is busy with other PDFs. Try again in a moment.",
    timeout: "This PDF took too long to process.",
    failed: "This PDF could not be processed.",
  };
  assert.deepEqual([...EDIT_CODES].sort(), Object.keys(expected).sort(), "the code list is the design's table");
  for (const code of EDIT_CODES) {
    assert.equal(messageFor(code, { item: "X", pageCount: 4 }), expected[code], code);
  }
  assert.equal(messageFor("encrypted", { inputIndex: 2 }), `Input 2: ${expected.encrypted}`);
});
