/**
 * omitly#1864: the one rule that keeps findings, an unread file and a Safe to Send verdict apart, for
 * the MCPB bundle's `check_redaction`. A CommonJS port of `applyScanToVerdict` in
 * ../../src/verdict-rule.ts (the full server and the result card use that one); `verdict.test.js`
 * compares the two over every combination when the build is present, and the fixed lines with the
 * TypeScript source.
 *
 * A Safe to Send verdict is kept only when the scan listed nothing AND is known to have read the
 * whole file. Findings -> Needs Review (not blocking); unread or unknown coverage -> Cannot Verify;
 * any other verdict is returned as the engine sent it. An embedded report's own positive verdict
 * ("Safe to Send", "all redactions verified") is reworded beside a verdict that is not Safe to Send.
 */
"use strict";

const { parseScanReply, unusableReplyMessage } = require("./replies.js");

const VISIBLE_TEXT_INFO_PREFIX = "Sensitive-looking text is visible";
const VISIBLE_SENSITIVE_SUMMARY = "Sensitive-looking text is visible in this file. Review it before sending.";
const INCOMPLETE_SUMMARY = "Part of this file could not be read, so Omitly cannot say whether it is ready to send.";
const NOT_READ_LINE = "The pattern scan could not read all of this file, so nothing here covers the part it could not read.";
const UNDER_MARK_SUMMARY = "This file should not be sent. Text is still present under a redaction mark.";
const underMarkLine = (n) => `Text is still present under a redaction mark (${n} ${n === 1 ? "item" : "items"}).`;
const visibleReviewLine = (found) => `Sensitive-looking text is visible (${found} ${found === 1 ? "item" : "items"}).`;

const SEALED_REPORT_PREFIX = "This file carries an Omitly report (omitly-audit.json) sealed with key ";
const LABEL = { safe_to_send: "Safe to Send", needs_review: "Needs Review", cannot_verify: "Cannot Verify" };
const SECTIONS = ["checked", "notChecked", "problems", "review", "information", "decisions", "reasons"];

function embeddedReportLine(text, verdict, blocking) {
  const own = verdict === "needs_review" && blocking ? "Needs Review — problems found" : LABEL[verdict];
  const m = /^[0-9A-Fa-f:]{1,200}(?=[.\s]|$)/.exec(text.slice(SEALED_REPORT_PREFIX.length));
  const key = m ? `sealed with key ${m[0]}` : "sealed with a key this engine does not report";
  return (
    `A report embedded in this file (${key}) is not evidence for this check. This check's own result is ${own}. ` +
    `A seal shows the file is unchanged since it was sealed, not that the report is right.`
  );
}

const list = (a) => (Array.isArray(a) ? a : []);

function applyScanToVerdict(v, facts) {
  if (!v) return v;
  const incomplete = facts.complete !== true;
  let out = v;
  const survivors = facts.survivors || 0;
  if (survivors > 0 && v.result && !(v.verdict === "needs_review" && v.blocking)) {
    // Text confirmed under a redaction mark is a failed redaction whatever the engine said (see applyScanToVerdict in ../../src/verdict-rule.ts).
    const r = v.result || null;
    out = {
      ...v,
      verdict: "needs_review",
      blocking: true,
      reason_code: null, // legal only with Cannot Verify; the refusal's line moves to notChecked (src/verdict-rule.ts)
      result: r && {
        ...r,
        state: "needs_review",
        blocking: true,
        summary: UNDER_MARK_SUMMARY,
        problems: [...list(r.problems), { text: underMarkLine(survivors) }],
        notChecked: [...list(r.notChecked), ...list(r.reasons).filter((x) => !list(r.notChecked).some((n) => n && x && n.text === x.text))],
        information: list(r.information).filter((i) => !(i && typeof i.text === "string" && i.text.startsWith(VISIBLE_TEXT_INFO_PREFIX))),
      },
    };
  } else if (v.verdict === "safe_to_send" && (facts.found > 0 || incomplete)) {
    const r = v.result || null;
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
          review: [...list(r.review), { text: visibleReviewLine(facts.found) }],
          information: list(r.information).filter((i) => !(i && typeof i.text === "string" && i.text.startsWith(VISIBLE_TEXT_INFO_PREFIX))),
        },
      };
    } else {
      out = {
        ...v,
        verdict: "cannot_verify",
        blocking: false,
        result: r && { ...r, state: "cannot_verify", blocking: false, summary: INCOMPLETE_SUMMARY, reasons: [...list(r.reasons), { text: NOT_READ_LINE }] },
      };
    }
  }
  let result = out.result;
  if (!result) return out;
  if (incomplete && !list(result.notChecked).some((i) => i && i.text === NOT_READ_LINE)) {
    result = { ...result, notChecked: [...list(result.notChecked), { text: NOT_READ_LINE }] };
  }
  if (out.verdict !== "safe_to_send") result = rewordEmbedded(result, out.verdict, out.blocking);
  return result === out.result ? out : { ...out, result };
}

/** Every line that starts with the sealed-report prefix is replaced by `embeddedReportLine` (rewordEmbedded in ../../src/verdict-rule.ts). */
function rewordEmbedded(result, verdict, blocking) {
  let out = result;
  for (const key of SECTIONS) {
    let changed = false;
    const items = list(out[key]).map((i) => {
      if (!i || typeof i.text !== "string" || !i.text.startsWith(SEALED_REPORT_PREFIX)) return i;
      changed = true;
      return { ...i, text: embeddedReportLine(i.text, verdict, blocking) };
    });
    if (changed) out = { ...out, [key]: items };
  }
  return out;
}

/** The fixed summary of a reconciled verdict (SUMMARY in ../../src/verdict-rule.ts). */
const SUMMARY = { needs_review: "This file needs review before it is sent.", incomplete: "Omitly could not confirm every part of this file.", not_a_pass: UNDER_MARK_SUMMARY };

/** Contract §7.1 (`reconcileVerdict` in ../../src/verdict-rule.ts): a verdict still saying Safe to Send beside a non-pass outcome takes the state the outcome names. */
const SAYS_SAFE = /safe[\s_-]*to[\s_-]*send/i;
function reconcileVerdict(v, issued) {
  if (!v || issued.outcome === "safe_to_send") return v;
  if (v.verdict !== "safe_to_send") {
    // CONTRACT-QUESTION: see reconcileVerdict in ../../src/verdict-rule.ts (the engine's cannot_verify summary says "safe to send").
    if (v.result && SAYS_SAFE.test(v.result.summary)) {
      const summary = v.verdict === "cannot_verify" ? SUMMARY.incomplete : v.blocking ? SUMMARY.not_a_pass : SUMMARY.needs_review;
      return { ...v, result: { ...v.result, summary } };
    }
    return v;
  }
  const r = v.result || null;
  const lines = issued.why.map((text) => ({ text }));
  const done = (verdict, blocking, result) => ({ ...v, verdict, blocking, result: result && rewordEmbedded(result, verdict, blocking) });
  if (issued.outcome === "needs_review") return done("needs_review", false, r && { ...r, state: "needs_review", blocking: false, summary: SUMMARY.needs_review, review: [...list(r.review), ...lines] });
  if (issued.outcome === "not_a_pass") return done("needs_review", true, r && { ...r, state: "needs_review", blocking: true, summary: SUMMARY.not_a_pass, problems: [...list(r.problems), ...lines] });
  return done("cannot_verify", false, r && { ...r, state: "cannot_verify", blocking: false, summary: SUMMARY.incomplete, reasons: [...list(r.reasons), ...lines] });
}

/** The two legs of a check agree (`legsDisagree` in ../../src/verdict-rule.ts): a check that lists visible values beside
 *  a scan that found none is no verdict. Returns the reason, or null. Run on the engine's verdict before it is reconciled. */
function legsDisagree(result, facts) {
  if (!result || facts.found > 0) return null;
  const lists = list(result.information).some((i) => i && typeof i.text === "string" && i.text.startsWith(VISIBLE_TEXT_INFO_PREFIX));
  return lists ? "the scan and the check disagree: the check lists visible sensitive-looking text and the scan found none" : null;
}

/** The first line of a text that is not a pass (`notAPassLead` in ../../src/verdict-rule.ts). */
const notAPassLead = (why) => (why.length ? `⚠️ NOT A PASS — ${why.join("; ")}.\n\n` : "");

/** What the scan found and whether it read everything, from the scan's own reply, read only through the
 *  strict parser (replies.js); `error` text when the reply is malformed or contradicts itself. */
function scanFactsOfReply(res) {
  const parsed = parseScanReply(res, { engine: "wasm" });
  if (!parsed.ok) return { error: `Audit failed: ${unusableReplyMessage("scan", parsed.reason)}` };
  // Contract C4: complete only when BOTH flags are present and true; either absent is "not reported" (null), either false is false.
  const { topComplete, covComplete } = parsed.value;
  const complete = topComplete === true && covComplete === true;
  return { found: parsed.value.total, complete, scanComplete: complete ? true : topComplete === false || covComplete === false ? false : null, survivors: parsed.value.survivors.length };
}

// v0.2.1 (errata 4): see safeText / textRegions in ../../src/verdict-rule.ts.
const PASS_GLYPHS = /[\u2705\u2713\u2714\u2611\u{1F7E2}]/gu;
const PASS_PHRASES = /safe[\s_-]*to[\s_-]*send|no recoverable pii|verification:\s*pass|intact|\bclean\b|\bverified\b|\bpassed\b/giu;
// v0.2.4 (errata 1): see foldText in ../../src/verdict-rule.ts.
function foldText(s) {
  return String(s).normalize("NFKC").replace(/\p{Cf}/gu, "").replace(/\s+/g, " ");
}
function safeText(s) {
  return foldText(s).replace(PASS_GLYPHS, "•").replace(PASS_PHRASES, "•");
}
function textRegion(r) {
  const o = r && typeof r === "object" ? r : {};
  const out = {};
  if (typeof o.page === "number" && Number.isFinite(o.page)) out.page = o.page;
  if (o.kind !== undefined) out.kind = safeText(o.kind);
  if (o.preview !== undefined) out.preview = safeText(o.preview);
  for (const k of ["x", "y", "width", "height"]) if (typeof o[k] === "number" && Number.isFinite(o[k])) out[k] = o[k];
  if (typeof o.under_redaction === "boolean") out.under_redaction = o.under_redaction;
  return out;
}
const textRegions = (list) => list.map(textRegion);
function textOffPage(f, sourceCategory) {
  const o = f && typeof f === "object" ? f : {};
  return { category: sourceCategory(o.source), kind: safeText(o.kind), preview: safeText(o.preview) };
}
// The closed list of engine copy lines shown as written (ENGINE_COPY_NEGATIONS in ../../src/verdict-rule.ts); everything else is sanitised.
const ENGINE_COPY_NEGATIONS = [{ sentence: "a font's character encoding could not be verified, so some text may not have been read correctly." }];
function engineLine(s) {
  const t = foldText(s);
  return ENGINE_COPY_NEGATIONS.some((e) => t.toLowerCase() === e.sentence) ? t : safeText(t);
}

module.exports = {
  safeText,
  foldText,
  textRegion,
  textRegions,
  textOffPage,
  engineLine,
  ENGINE_COPY_NEGATIONS,
  applyScanToVerdict,
  legsDisagree,
  reconcileVerdict,
  rewordEmbedded,
  SUMMARY,
  notAPassLead,
  scanFactsOfReply,
  UNDER_MARK_SUMMARY,
  underMarkLine,
  VISIBLE_SENSITIVE_SUMMARY,
  VISIBLE_TEXT_INFO_PREFIX,
  INCOMPLETE_SUMMARY,
  NOT_READ_LINE,
};
