/**
 * omitly#1864: the ONE rule that decides what a check_redaction verdict may say beside what the
 * pattern scan found, shared by the server (text, structured result) and the result card, so the
 * card cannot disagree with the text. Browser-safe: no Node imports (the view bundle includes it).
 *
 * The engine's presented check (`omitly_seal::check`) judges hidden, covered and recoverable
 * content. The pattern scan is a second pass that lists findings and says whether it read the whole
 * file. A Safe to Send verdict is only kept when the scan listed nothing AND the scan is known to
 * have read everything:
 *  - the scan listed something -> Needs Review (not blocking: blocking is for a failed redaction,
 *    which the engine reports itself);
 *  - the scan did not read everything, or did not say -> Cannot Verify;
 *  - any other verdict is returned as the engine sent it.
 * Whatever the verdict, a line that quotes an embedded report's own "Safe to Send" is reworded so it
 * cannot be read as this check's verdict, and what could not be read is listed.
 */

export interface ItemLike {
  text: string;
  pages?: number[];
}
export interface ResultLike {
  state: string;
  blocking: boolean;
  summary: string;
  checked: ItemLike[];
  notChecked: ItemLike[];
  problems: ItemLike[];
  review: ItemLike[];
  information: ItemLike[];
  decisions: ItemLike[];
  reasons: ItemLike[];
  [k: string]: unknown;
}
export interface VerdictLike {
  verdict: "safe_to_send" | "needs_review" | "cannot_verify";
  blocking: boolean;
  result: ResultLike | null;
  reason_code: unknown;
}

/** What the scan said: how many items it listed, and whether it read everything. */
export interface ScanFacts {
  found: number;
  /** Only `true` is complete: a scan that did not say is treated as incomplete. */
  complete: boolean;
  /** Items of `found` that are text confirmed UNDER a redaction mark (the scan's `survivors`): a failed redaction,
   *  never "visible text". Absent: none. */
  survivors?: number;
}

export const VISIBLE_SENSITIVE_SUMMARY = "Sensitive-looking text is visible in this file. Review it before sending.";
export const INCOMPLETE_SUMMARY = "Part of this file could not be read, so Omitly cannot say whether it is ready to send.";
export const NOT_READ_LINE = "The pattern scan could not read all of this file, so nothing here covers the part it could not read.";
/** The engine's INFORMATION line about visible sensitive-looking text starts with this
 *  (`INFO_SENSITIVE_TEXT_VISIBLE` in crates/omitly-seal/src/check.rs). */
export const VISIBLE_TEXT_INFO_PREFIX = "Sensitive-looking text is visible";

export const UNDER_MARK_SUMMARY = "This file should not be sent. Text is still present under a redaction mark.";
export const underMarkLine = (n: number) => `Text is still present under a redaction mark (${n} ${n === 1 ? "item" : "items"}).`;

export const visibleReviewLine = (found: number) =>
  `Sensitive-looking text is visible (${found} ${found === 1 ? "item" : "items"}).`;

/** The check's information line showing it relied on the file's own bound report (check.rs:753, :1934-1970). Lives here so both this module and
 *  outcome.ts (which re-exports it) can read it without a cycle. */
export const SEALED_REPORT_PREFIX = "This file carries an Omitly report (omitly-audit.json) sealed with key ";

const LABEL: Record<string, string> = {
  safe_to_send: "Safe to Send",
  needs_review: "Needs Review",
  cannot_verify: "Cannot Verify",
};

/**
 * v0.2.3 (errata 1): ANY line that starts with the sealed-report prefix is REPLACED by this fixed wording; the line itself, and what the
 * report records, is never quoted (the engine's own line, check.rs:1934-1970, carries the file's report verdict in free text). The key is
 * shown only if it is colon-hex (check.rs:1958-1962), else "a key this engine does not report".
 */
export function embeddedReportLine(text: string, verdict: VerdictLike["verdict"], blocking: boolean): string {
  const own = verdict === "needs_review" && blocking ? "Needs Review — problems found" : LABEL[verdict];
  const m = /^[0-9A-Fa-f:]{1,200}(?=[.\s]|$)/.exec(text.slice(SEALED_REPORT_PREFIX.length));
  const key = m ? `sealed with key ${m[0]}` : "sealed with a key this engine does not report";
  return (
    `A report embedded in this file (${key}) is not evidence for this check. This check's own result is ${own}. ` +
    `A seal shows the file is unchanged since it was sealed, not that the report is right.`
  );
}

const SECTIONS = ["checked", "notChecked", "problems", "review", "information", "decisions", "reasons"] as const;

/** `v` as it may be shown beside `facts`. Pure; adds only fixed text and a count; idempotent. */
export function applyScanToVerdict<V extends VerdictLike>(v: V, facts: ScanFacts): V {
  let out: VerdictLike = v;
  const incomplete = !facts.complete;
  const survivors = facts.survivors ?? 0;
  if (survivors > 0 && v.result !== null && !(v.verdict === "needs_review" && v.blocking)) {
    // omitly#1864 round 5 (review K1): text confirmed under a redaction mark is a failed redaction whatever the engine's
    // verdict says: a blocking Needs Review, never the amber "visible text" state, so the text, the structure, the
    // card and `outcome` (not_a_pass) say one thing.
    const r = v.result;
    out = {
      ...v,
      verdict: "needs_review",
      blocking: true,
      // A reason code (`input_too_large`, `check_failed`) is legal only with Cannot Verify (check.rs `FreeCheck`), so a
      // promoted verdict carries none: the refusal's own line, which is in `reasons`, is kept in `notChecked` too, where a
      // result that is not Cannot Verify lists what could not be checked.
      reason_code: null,
      result: r && {
        ...r,
        state: "needs_review",
        blocking: true,
        summary: UNDER_MARK_SUMMARY,
        problems: [...r.problems, { text: underMarkLine(survivors) }],
        notChecked: [...r.notChecked, ...r.reasons.filter((x) => !r.notChecked.some((n) => n.text === x.text))],
        information: r.information.filter((i) => !i.text.startsWith(VISIBLE_TEXT_INFO_PREFIX)),
      },
    };
  } else if (v.verdict === "safe_to_send" && (facts.found > 0 || incomplete)) {
    const r = v.result;
    if (facts.found > 0) {
      out = {
        ...v,
        verdict: "needs_review",
        blocking: false,
        result: r && {
          ...r,
          state: "needs_review",
          blocking: false,
          summary: VISIBLE_SENSITIVE_SUMMARY,
          review: [...r.review, { text: visibleReviewLine(facts.found) }],
          information: r.information.filter((i) => !i.text.startsWith(VISIBLE_TEXT_INFO_PREFIX)),
        },
      };
    } else {
      out = {
        ...v,
        verdict: "cannot_verify",
        blocking: false,
        result: r && {
          ...r,
          state: "cannot_verify",
          blocking: false,
          summary: INCOMPLETE_SUMMARY,
          reasons: [...r.reasons, { text: NOT_READ_LINE }],
        },
      };
    }
  }
  const r = out.result;
  if (!r) return out as V;
  let result: ResultLike = r;
  // What could not be read is listed in every state that has the limit.
  if (incomplete && !r.notChecked.some((i) => i.text === NOT_READ_LINE)) {
    result = { ...result, notChecked: [...result.notChecked, { text: NOT_READ_LINE }] };
  }
  // A quoted embedded verdict is never left to read as this check's.
  if (out.verdict !== "safe_to_send") result = rewordEmbedded(result, out.verdict, out.blocking);
  return (result === r ? out : { ...out, result }) as V;
}

/** Every line that starts with the sealed-report prefix is replaced by `embeddedReportLine` (no pattern to miss: the default is fixed wording). */
export function rewordEmbedded(result: ResultLike, verdict: VerdictLike["verdict"], blocking: boolean): ResultLike {
  let out = result;
  for (const key of SECTIONS) {
    let changed = false;
    const items = out[key].map((i) => {
      if (typeof i.text !== "string" || !i.text.startsWith(SEALED_REPORT_PREFIX)) return i;
      changed = true;
      return { ...i, text: embeddedReportLine(i.text, verdict, blocking) };
    });
    if (changed) out = { ...out, [key]: items };
  }
  return out;
}

/**
 * The scan facts of a `check_redaction` structuredContent, for the card: the items its arrays list
 * (or its counts claim) and whether it says the scan was complete. Anything that is not exactly
 * `scanComplete: true` is incomplete.
 */
export function scanFactsOf(sc: Record<string, unknown>): ScanFacts {
  const len = (v: unknown) => (Array.isArray(v) ? v.length : 0);
  const listed = len(sc.regions) + len(sc.survivors) + len(sc.offPage);
  const claimed = typeof sc.totalFindings === "number" && Number.isFinite(sc.totalFindings) ? sc.totalFindings : 0;
  return {
    found: Math.max(listed, claimed, sc.clean === false ? 1 : 0),
    complete: sc.scanComplete === true,
    survivors: len(sc.survivors),
  };
}

/** The four outcomes and `worst` live in outcome.ts (contract §7.1); re-exported here for the modules that import them from this one. */
export { OUTCOMES, type Outcome } from "./outcome.js";

const SAYS_SAFE = /safe[\s_-]*to[\s_-]*send/i;

/** The fixed summary of a reconciled verdict (contract §7.1). */
export const SUMMARY = {
  needs_review: "This file needs review before it is sent.",
  incomplete: "Omitly could not confirm every part of this file.",
  not_a_pass: UNDER_MARK_SUMMARY,
} as const;

/**
 * Contract §7.1: when the issued outcome is not `safe_to_send` and the verdict still says so (a C2b, C5 or C6 non-pass leaves the
 * engine's own verdict at Safe to Send), set the state the outcome names: `needs_review` (non-blocking, the why lines appended to
 * `review`), `incomplete` -> `cannot_verify` (appended to `reasons`), `not_a_pass` -> a blocking `needs_review` (appended to
 * `problems`); the summary becomes the fixed SUMMARY of the outcome. `reason_code` stays null. Any other verdict is returned as it is.
 */
export function reconcileVerdict<V extends VerdictLike>(v: V, issued: { outcome: string; why: readonly string[] }): V {
  if (issued.outcome === "safe_to_send") return v;
  if (v.verdict !== "safe_to_send") {
    // CONTRACT-QUESTION: §6.3 forbids the phrase "safe to send" in any non-pass text, but the engine's own `cannot_verify` summary reads "...so it
    // cannot say whether this file is safe to send." (check.rs) and §6.3 allows no such negation. Fail-safe reading: a summary that says the phrase
    // is replaced by the fixed SUMMARY of the verdict's state; nothing else about the verdict changes.
    if (v.result && SAYS_SAFE.test(v.result.summary)) {
      const summary = v.verdict === "cannot_verify" ? SUMMARY.incomplete : v.blocking ? SUMMARY.not_a_pass : SUMMARY.needs_review;
      return { ...v, result: { ...v.result, summary } };
    }
    return v;
  }
  const r = v.result;
  const lines = issued.why.map((text) => ({ text }));
  const done = (verdict: VerdictLike["verdict"], blocking: boolean, result: ResultLike | null): V => ({ ...v, verdict, blocking, result: result && rewordEmbedded(result, verdict, blocking) });
  if (issued.outcome === "needs_review") return done("needs_review", false, r && { ...r, state: "needs_review", blocking: false, summary: SUMMARY.needs_review, review: [...r.review, ...lines] });
  if (issued.outcome === "not_a_pass") return done("needs_review", true, r && { ...r, state: "needs_review", blocking: true, summary: SUMMARY.not_a_pass, problems: [...r.problems, ...lines] });
  return done("cannot_verify", false, r && { ...r, state: "cannot_verify", blocking: false, summary: SUMMARY.incomplete, reasons: [...r.reasons, ...lines] });
}

/**
 * omitly#1864 round 5: the two legs of a check (the engine's presented `check` and the separate pattern scan) look at
 * the same file, so one cannot list visible sensitive-looking values the other did not find. The check's own scan
 * writes the line "Sensitive-looking text is visible on pages 1 and 2 (3 values)." into `result.information`
 * (crates/omitly-seal/src/check.rs `visible_text_item`, only when it counted at least one value); a separate scan
 * that listed nothing beside it is a file that changed between the two calls or a reply that is wrong, and no
 * verdict may be given. A check on its own (no scan beside it) is valid: this is only for the pair. Returns the
 * reason, or null when the legs agree. Run on the engine's verdict BEFORE `applyScanToVerdict` reconciles it.
 */
export function legsDisagree(result: ResultLike | null, facts: ScanFacts): string | null {
  if (!result || facts.found > 0) return null;
  const lists = (result.information ?? []).some((i) => typeof i.text === "string" && i.text.startsWith(VISIBLE_TEXT_INFO_PREFIX));
  return lists ? "the scan and the check disagree: the check lists visible sensitive-looking text and the scan found none" : null;
}

/** The first line of a text that is not a pass: names why. `why` empty means a pass and no line. */
export function notAPassLead(why: string[]): string {
  return why.length ? `⚠️ NOT A PASS — ${why.join("; ")}.\n\n` : "";
}

// ---------------------------------------------------------------------------------------------------
// v0.2.1 (errata 4): file-derived previews in the text
// ---------------------------------------------------------------------------------------------------

const PASS_GLYPHS = /[\u2705\u2713\u2714\u2611\u{1F7E2}]/gu;
const PASS_PHRASES = /safe[\s_-]*to[\s_-]*send|no recoverable pii|verification:\s*pass|intact|\bclean\b|\bverified\b|\bpassed\b/giu;

/**
 * A text a FILE controls (a preview: the engine's mask keeps non-alphanumerics, so a file can carry a glyph or a phrase through it) shown in
 * a tool's text: NFKC-normalised, then every green glyph and pass phrase of the §6.3 matcher replaced with "•". `structuredContent` keeps the
 * raw value. Applied by every text site that prints a region, survivor, off-page or removed-entity preview.
 */
export function safeText(s: unknown): string {
  return foldText(s).replace(PASS_GLYPHS, "•").replace(PASS_PHRASES, "•");
}

/** v0.2.4 (errata 1): the text as a person reads it: NFKC, every Unicode format character (`\p{Cf}`: zero-width and joiner characters, bidi
 *  marks and isolates, the soft hyphen, the BOM, ...) removed, and every whitespace run folded to one space. Run BEFORE any matching, and
 *  its output (not the original) is what is shown, so no format character can split a phrase or hide a glyph. */
export function foldText(s: unknown): string {
  return String(s).normalize("NFKC").replace(/\p{Cf}/gu, "").replace(/\s+/g, " ");
}

/**
 * v0.2.3 (errata 2): an engine item (region, survivor, off-page finding, removed entity) shown in text is rebuilt from an ALLOW-LIST of
 * fields: `page`, the box (`x` `y` `width` `height`) and `under_redaction` only when they are the right type, and `kind` and `preview`
 * through `safeText`. Any other field the engine sent is dropped. The text never holds a stringified engine object.
 */
export function textRegion(r: unknown): Record<string, unknown> {
  const o = (r && typeof r === "object" ? r : {}) as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  if (typeof o.page === "number" && Number.isFinite(o.page)) out.page = o.page;
  if (o.kind !== undefined) out.kind = safeText(o.kind);
  if (o.preview !== undefined) out.preview = safeText(o.preview);
  for (const k of ["x", "y", "width", "height"]) if (typeof o[k] === "number" && Number.isFinite(o[k] as number)) out[k] = o[k];
  if (typeof o.under_redaction === "boolean") out.under_redaction = o.under_redaction;
  return out;
}
export const textRegions = (list: readonly unknown[]): Record<string, unknown>[] => list.map(textRegion);

/** An off-page finding in text: its source as a category (`sourceCategory`), never the raw value; `kind` and `preview` sanitised. */
export function textOffPage(f: unknown, sourceCategory: (s: unknown) => string): Record<string, unknown> {
  const o = (f && typeof f === "object" ? f : {}) as Record<string, unknown>;
  return { category: sourceCategory(o.source), kind: safeText(o.kind), preview: safeText(o.preview) };
}

/**
 * v0.2.3 (errata 1): the closed list of engine COPY lines that are shown as the engine wrote them although they hold a matcher word (a
 * negation the engine itself writes). Matched as a whole line (exact, after NFKC + lowercase). Every other engine line is passed through
 * `safeText`. The matcher (src/testing/matcher.ts) reads this list.
 */
export const ENGINE_COPY_NEGATIONS: readonly { sentence: string; source: string }[] = [
  // The `unverified_type0_codespace` Not-checked line (check.rs:1763-1764).
  { sentence: "a font's character encoding could not be verified, so some text may not have been read correctly.", source: "crates/omitly-seal/src/check.rs:1763" },
];

/** An engine copy line (a check item or summary) as it may appear in text: sanitised unless it is exactly one of the closed negation lines. */
export function engineLine(s: unknown): string {
  const t = foldText(s);
  return ENGINE_COPY_NEGATIONS.some((e) => t.toLowerCase() === e.sentence) ? t : safeText(t);
}
