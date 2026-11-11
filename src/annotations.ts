/**
 * MCP tool annotations (omitly#1853), shared by every tool registration so the
 * hints cannot drift between `index.ts` and `edit-tools.ts`.
 *
 * Every Omitly tool is non-destructive (an output path that already exists is
 * refused before anything is written, see `confineOutput`) and closed-world
 * (nothing is uploaded; `create_pdf` blocks all network in its browser), so
 * those two hints are fixed. A tool states only whether it is read-only and,
 * if so, whether repeating it is a no-op.
 */
export interface ToolAnnotations {
  title: string;
  readOnlyHint: boolean;
  destructiveHint: false;
  idempotentHint: boolean;
  openWorldHint: false;
}

export const annotations = (title: string, readOnly: boolean, idempotent = false): ToolAnnotations => ({
  title,
  readOnlyHint: readOnly,
  destructiveHint: false,
  idempotentHint: idempotent,
  openWorldHint: false,
});
