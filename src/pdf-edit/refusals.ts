/**
 * omitly#1841 phase B: the refusal codes of the five page tools and their FIXED
 * messages (design 4.4). Every refusal is an MCP tool result with `isError: true`
 * whose text is exactly one of these (plus, where noted, the offending item or
 * page count). Messages from `confineInput` / `confineOutput` / `confineDir`
 * pass through unchanged because they are already written for the agent.
 *
 * Shared by the server (edit-tools.ts), the child (worker.ts) and pageSpec.ts.
 * Imports nothing, so nothing here can reach a network module.
 */

export const EDIT_CODES = [
  "allowed_dir_needed",
  "not_a_file",
  "not_a_directory",
  "not_pdf_name",
  "hidden_path",
  "too_large",
  "output_too_large",
  "encrypted",
  "page_spec",
  "page_out_of_range",
  "duplicate_page",
  "split_name_clash",
  "split_not_contiguous",
  "output_exists",
  "write_failed",
  "not_pdf",
  "too_many_pages",
  "no_source_pages",
  "xfa",
  "busy",
  "timeout",
  "failed",
] as const;

export type EditCode = (typeof EDIT_CODES)[number];

/** The codes a child may report. The server maps anything else to `failed`. */
export const CHILD_CODES: ReadonlySet<string> = new Set<EditCode>([
  "not_a_file",
  "too_large",
  "output_too_large",
  "encrypted",
  "page_out_of_range",
  "not_pdf",
  "too_many_pages",
  "no_source_pages",
  "xfa",
  "write_failed",
  "failed",
]);

const FIXED: Record<Exclude<EditCode, "page_spec" | "page_out_of_range" | "duplicate_page" | "split_name_clash">, string> = {
  allowed_dir_needed: "Set OMITLY_ALLOWED_DIR to the folder your PDFs are in.",
  not_a_file: "That path is not a file.",
  not_a_directory: "That output folder does not exist.",
  not_pdf_name: "Output files must end in .pdf.",
  hidden_path: "Omitly won't write inside a hidden folder or a .git folder.",
  too_large: "That PDF is over the 200 MB limit. (Merge: the inputs are over 500 MB in total.)",
  output_too_large: "The result would be over the size limit.",
  encrypted:
    "This PDF is encrypted (it may only restrict permissions). Open it in Omitly to remove the encryption, then try again.",
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

/** An item echoed back to the agent: shortened, control characters removed. The
 *  item came from the model, so it is never trusted to be tidy. */
export function showItem(item: unknown): string {
  const raw = typeof item === "string" ? item : typeof item === "number" ? String(item) : typeof item;
  // eslint-disable-next-line no-control-regex
  const clean = raw.replace(/[\u0000-\u001f\u007f-\u009f"\\]/g, "?");
  return clean.length > 40 ? `${clean.slice(0, 40)}...` : clean;
}

export interface MessageDetail {
  /** page_spec / page_out_of_range / duplicate_page / split_name_clash: the offending item, page or name. */
  item?: unknown;
  /** page_out_of_range: the real page count. */
  pageCount?: number;
  /** merge: 1-based index of the input the refusal is about. */
  inputIndex?: number;
}

export function messageFor(code: EditCode, d: MessageDetail = {}): string {
  let text: string;
  switch (code) {
    case "page_spec":
      text = `Page item "${showItem(d.item)}" is not valid: use a page number like 3 or a range like "2-5".`;
      break;
    case "page_out_of_range":
      text = `Page item "${showItem(d.item)}" is past the end: this PDF has ${Number.isSafeInteger(d.pageCount) ? d.pageCount : "fewer"} pages.`;
      break;
    case "duplicate_page":
      text = `Page ${showItem(d.item)} is listed twice.`;
      break;
    case "split_name_clash":
      text = `Two ranges would both be named "${showItem(d.item)}".`;
      break;
    default:
      text = FIXED[code];
  }
  return d.inputIndex !== undefined ? `Input ${d.inputIndex}: ${text}` : text;
}

/** Thrown inside the server's own steps (page-spec parsing, naming) to carry a refusal out. */
export class EditRefusal extends Error {
  constructor(
    readonly code: EditCode,
    readonly detail: MessageDetail = {},
  ) {
    super(messageFor(code, detail));
    this.name = "EditRefusal";
  }
}
