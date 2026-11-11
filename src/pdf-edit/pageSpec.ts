/**
 * omitly#1841 phase B: the page-spec grammar (design 4.1). Pure; no I/O.
 *
 * A page spec is an array of items. Each item is a JSON integer n >= 1, or a
 * string "a-b" matching ^[1-9][0-9]*-[1-9][0-9]*$ with a <= b. Items expand in
 * order. A bare-number string ("5"), a leading zero ("01-03"), spaces, a reversed
 * range, zero, a negative number or a non-integer is refused with `page_spec`.
 * A page that appears twice is refused with `duplicate_page` (extractPages
 * refuses it, and a repeated page would share one page object in the output).
 * Expansion is refused with `too_many_pages` once it passes 10,000 pages, and
 * the count is checked BEFORE a range is expanded, so "1-999999999" costs nothing.
 *
 * Page numbers are 1-based here and everywhere in the new tools. The caller
 * converts to 0-based when it builds the worker request.
 */
import { EditRefusal } from "./refusals.js";

export const MAX_SPEC_ITEMS = 1000;
export const MAX_EXPANDED_PAGES = 10_000;

const RANGE = /^[1-9][0-9]*-[1-9][0-9]*$/;

export interface ExpandedSpec {
  /** 1-based pages in expansion order. */
  pages: number[];
  /** For each page in `pages`, the index of the spec item it came from. */
  itemOf: number[];
}

/** Parse one item into [first, last] (1-based, inclusive), or throw `page_spec`. */
function parseItem(item: unknown): [number, number] {
  if (typeof item === "number") {
    if (!Number.isSafeInteger(item) || item < 1) throw new EditRefusal("page_spec", { item });
    return [item, item];
  }
  if (typeof item === "string" && RANGE.test(item)) {
    const [a, b] = item.split("-").map(Number);
    if (!Number.isSafeInteger(a) || !Number.isSafeInteger(b) || a > b) throw new EditRefusal("page_spec", { item });
    return [a, b];
  }
  throw new EditRefusal("page_spec", { item });
}

/**
 * Expand a page spec. `budget` is the number of pages the caller can still
 * accept (the 10,000 cap, minus pages already taken by earlier ranges in a
 * split); `seen` (optional) is shared across calls when duplicates must be
 * refused across them. Throws `EditRefusal`.
 */
export function expandPageSpec(
  items: readonly unknown[],
  opts: { budget?: number } = {},
): ExpandedSpec {
  if (items.length < 1 || items.length > MAX_SPEC_ITEMS) throw new EditRefusal("page_spec", { item: `${items.length} items` });
  let budget = opts.budget ?? MAX_EXPANDED_PAGES;
  const pages: number[] = [];
  const itemOf: number[] = [];
  const seen = new Set<number>();
  items.forEach((item, idx) => {
    const [first, last] = parseItem(item);
    const count = last - first + 1;
    if (count > budget) throw new EditRefusal("too_many_pages");
    budget -= count;
    for (let p = first; p <= last; p++) {
      if (seen.has(p)) throw new EditRefusal("duplicate_page", { item: p });
      seen.add(p);
      pages.push(p);
      itemOf.push(idx);
    }
  });
  return { pages, itemOf };
}

/** True if `pages` is consecutive ascending (a, a+1, a+2, ...). */
export function isContiguousAscending(pages: readonly number[]): boolean {
  for (let i = 1; i < pages.length; i++) if (pages[i] !== pages[i - 1] + 1) return false;
  return true;
}

/** True if `pages` is strictly ascending (gaps allowed). */
export function isAscending(pages: readonly number[]): boolean {
  for (let i = 1; i < pages.length; i++) if (pages[i] <= pages[i - 1]) return false;
  return true;
}

/** The split file name for a contiguous range: `prefix-p3-5.pdf` or `prefix-p3.pdf`. */
export function splitFileName(prefix: string, pages: readonly number[]): string {
  const first = pages[0];
  const last = pages[pages.length - 1];
  return first === last ? `${prefix}-p${first}.pdf` : `${prefix}-p${first}-${last}.pdf`;
}

export const SPLIT_PREFIX = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
