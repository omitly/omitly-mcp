/**
 * omitly#1890 (step 4) — the desktop's decision record, as the MCP server reads it back.
 *
 * The desktop app keeps a native, append-only decision log in `<state dir>/decisions/` and, in the
 * same transaction that records a decision, writes one small permanent file per decided proposal:
 * `decisions/outcomes/<id>.json`. The proposal file in `proposals/` is AI-writable (this very
 * server writes it, and so can any process), so after a decision it is not evidence of anything:
 * a rewritten copy can say `pending` again. `get_proposal_status` therefore answers from the
 * outcome file whenever one exists, takes `tool`, `createdAt`, `output`, `verdict` and the decision
 * time from it and never from the proposal file, and never infers `pending` for an id that has an
 * outcome. With no outcome file it falls back to the proposal file, as before.
 *
 * This module only READS. It writes nothing, in either directory.
 */

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import * as path from "node:path";

import { proposalsDir, type ProposalStatus, type ProposalTool } from "./desktop.js";
import { USER_VERDICTS } from "./seal.js";
import { stateDir } from "./usage.js";

const ID_RE = /^[0-9a-f]{24}$/;

/** The native ledger's terminal decisions (`src-tauri/src/proposals/decisions.rs`). */
export type OutcomeDecision = "rejected" | "applied" | "unknown" | "failed_after_publish" | "legacy";

const DECISIONS: ReadonlySet<string> = new Set([
  "rejected",
  "applied",
  "unknown",
  "failed_after_publish",
  "legacy",
]);

const TOOLS: ReadonlySet<string> = new Set(["redact_pdf", "redact_by_entity"]);

/** What the desktop recorded about one decided proposal. `tool` and `createdAt` are the DECIDED
 *  proposal's own and are null only for a decision made before the ledger existed (`legacy`). */
export interface Outcome {
  id: string;
  decision: OutcomeDecision;
  /** The revision (SHA-256 of the record file's bytes) the decision applied to; null for `legacy`. */
  decidedRevision: string | null;
  output: string | null;
  verdict: string | null;
  decidedAt: string;
  tool: ProposalTool | null;
  createdAt: string | null;
  /** `legacy` only: the status the record file had when the ledger was first created. */
  legacyStatus: string | null;
  /** The person's note on a reject, stored by the desktop in the ledger. */
  note: string | null;
  /** SHA-256 of the exact bytes of the status file the desktop wrote (or planned to write) into
   *  the proposal file, computed before the decision was appended; null when it had none. */
  mailboxRevision: string | null;
}

/** The decisions directory, beside `proposalsDir()` (same `OMITLY_STATE_DIR` rule). */
export function decisionsDir(): string {
  return path.join(stateDir(), "decisions");
}

function outcomePath(id: string): string {
  return path.join(decisionsDir(), "outcomes", `${id}.json`);
}

function nullableString(v: unknown, what: string): string | null {
  if (v === null || v === undefined) return null;
  if (typeof v === "string") return v;
  throw new Error(`the decision record has a malformed ${what}`);
}

/**
 * The outcome of a decided proposal, or `null` when there is none (no file). A file that exists
 * but cannot be read or does not have the shape the desktop writes THROWS: the caller must not
 * fall back to the proposal file for it, because that file may say `pending`.
 */
export function readOutcome(id: string): Outcome | null {
  if (!ID_RE.test(id)) return null;
  let text: string;
  try {
    text = readFileSync(outcomePath(id), "utf8");
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw new Error("the decision record for this proposal could not be read");
  }
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    throw new Error("the decision record for this proposal is not valid JSON");
  }
  if (!raw || typeof raw !== "object") throw new Error("the decision record for this proposal is malformed");
  const o = raw as Record<string, unknown>;
  if (o.v !== 1 || o.id !== id || typeof o.decision !== "string" || !DECISIONS.has(o.decision)) {
    throw new Error("the decision record for this proposal is malformed");
  }
  if (typeof o.decidedAt !== "string") throw new Error("the decision record has no decision time");
  const tool = nullableString(o.tool, "tool");
  if (tool !== null && !TOOLS.has(tool)) throw new Error("the decision record names an unknown tool");
  return {
    id,
    decision: o.decision as OutcomeDecision,
    decidedRevision: nullableString(o.decidedRevision, "revision"),
    output: nullableString(o.output, "output"),
    verdict: nullableString(o.verdict, "verdict"),
    decidedAt: o.decidedAt,
    tool: tool as ProposalTool | null,
    createdAt: nullableString(o.createdAt, "createdAt"),
    legacyStatus: nullableString(o.legacyStatus, "legacyStatus"),
    note: nullableString(o.note, "note"),
    mailboxRevision: nullableString(o.mailboxRevision, "mailboxRevision"),
  };
}

/** The status word `get_proposal_status` reports for an outcome. `unknown` (the app stopped before
 *  it could record whether the proposal was applied) and `failed_after_publish` (an output was
 *  placed but not confirmed) both read as `failed`: the safe thing for the AI to do is to look at
 *  the output folder and propose again. A `legacy` decision reports the status its record had. */
export function outcomeStatus(o: Outcome): ProposalStatus {
  switch (o.decision) {
    case "rejected":
      return "rejected";
    case "applied":
      return "applied";
    case "unknown":
    case "failed_after_publish":
      return "failed";
    case "legacy": {
      const s = o.legacyStatus;
      return s === "accepted" || s === "rejected" || s === "applied" || s === "failed" || s === "expired" ? s : "failed";
    }
  }
}

/** Facts about the proposal file as it is now, read raw. Only its HASH is ever used to judge a
 *  decided proposal; `decidedRevision` is the file's own claim and is used only when there is NO
 *  outcome (the fallback path), never to vouch for one. */
export interface MailboxFacts {
  /** SHA-256 of the file's exact bytes, the same value the desktop calls its revision. */
  revision: string;
  decidedRevision: string | null;
}

export function readMailboxFacts(id: string): MailboxFacts | null {
  if (!ID_RE.test(id)) return null;
  let bytes: Buffer;
  try {
    bytes = readFileSync(path.join(proposalsDir(), `${id}.json`));
  } catch {
    return null;
  }
  let parsed: unknown = null;
  try {
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch {
    // an unreadable file still has a revision
  }
  const o = parsed && typeof parsed === "object" ? (parsed as Record<string, unknown>) : {};
  return {
    revision: createHash("sha256").update(bytes).digest("hex"),
    decidedRevision: typeof o.decided_revision === "string" ? o.decided_revision : null,
  };
}

const EARLIER_VERSION = "This decision was for an earlier version of the proposal.";

const DECISION_NOTE: Partial<Record<OutcomeDecision, string>> = {
  unknown: "Omitly stopped before it could record whether this was applied; check the output folder",
  failed_after_publish:
    "Omitly placed an output but could not confirm it; check the output folder. Ask your AI to propose again.",
};

/** Everything `get_proposal_status` reports about a decided proposal, from the outcome. */
export interface OutcomeView {
  status: ProposalStatus;
  tool: ProposalTool | null;
  createdAt: string | null;
  resolvedAt: string;
  output: string | null;
  verdict: string | null;
  note: string | null;
  decidedRevision: string | null;
  /** True only for a `legacy` outcome: recorded before the desktop kept its own decision record,
   *  so what it says (including any verdict) cannot be confirmed and is never presented as fact. */
  unverified?: true;
}

/** The verdict values Omitly itself writes into a proposal record: the v2 user verdicts and the v1
 *  `pass` / `fail` (see `proposalVerdictLabel`). Anything else in a legacy record is not repeated. */
const LEGACY_VERDICTS: ReadonlySet<string> = new Set([...USER_VERDICTS, "pass", "fail"]);

/** Said instead of a legacy record's note, which is never repeated (R3-1). Exact wording. */
export const LEGACY_NOTE_NOT_REPEATED = "The old record also had a note, which Omitly does not repeat.";

/** Leads the note of every legacy outcome (R2-1). Exact wording. */
export const LEGACY_UNVERIFIED =
  "This was recorded before this version of Omitly kept its own decision record, and Omitly cannot confirm it.";

/**
 * The view of an outcome. Everything reported comes from the outcome file. `mailbox` is the
 * proposal file as it is NOW (or null when it is gone) and contributes exactly one thing: whether
 * it is a different version than the one decided, judged by HASH ONLY. It is "the same" when its
 * bytes hash to the decided revision (the untouched original) or to `mailboxRevision` (the exact
 * status file the desktop itself wrote). Any other bytes, whatever fields they carry (a rewriter
 * can keep `decided_revision` and write its own `note`), add the earlier-version sentence. The
 * file's own `note` is never read, and native's wording for `unknown` and `failed_after_publish`
 * can never be replaced.
 */
export function outcomeView(o: Outcome, mailbox: MailboxFacts | null): OutcomeView {
  if (o.decision === "legacy") {
    // A pre-ledger record is unverifiable (anyone who could write the mailbox could have written
    // it): its status, output and time are reported as the old record's claim, its verdict is NOT
    // reported as a verdict, and the note leads with the unverified statement.
    // R3-1: shrink what is rendered. A legacy note is NEVER repeated (it could be instructions);
    // a verdict is repeated only if it is exactly a verdict Omitly itself writes.
    const claims: string[] = [];
    if (o.verdict !== null && LEGACY_VERDICTS.has(o.verdict)) claims.push(`The old record said: verdict ${o.verdict}.`);
    if (o.note !== null) claims.push(LEGACY_NOTE_NOT_REPEATED);
    return {
      status: outcomeStatus(o),
      tool: o.tool,
      createdAt: o.createdAt,
      resolvedAt: o.decidedAt,
      output: o.output,
      verdict: null,
      note: [LEGACY_UNVERIFIED, ...claims].join(" "),
      decidedRevision: null,
      unverified: true,
    };
  }
  let note: string | null = DECISION_NOTE[o.decision] ?? o.note;
  if (mailbox && o.decidedRevision !== null) {
    const same =
      mailbox.revision === o.decidedRevision || (o.mailboxRevision !== null && mailbox.revision === o.mailboxRevision);
    if (!same) note = note ? `${note} ${EARLIER_VERSION}` : EARLIER_VERSION;
  }
  return {
    status: outcomeStatus(o),
    tool: o.tool,
    createdAt: o.createdAt,
    resolvedAt: o.decidedAt,
    output: o.output,
    verdict: o.verdict,
    note,
    decidedRevision: o.decidedRevision,
  };
}
