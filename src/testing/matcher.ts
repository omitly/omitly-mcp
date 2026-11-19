import assert from "node:assert/strict";
import { WHY } from "../outcome.js";
import { ENGINE_COPY_NEGATIONS } from "../verdict-rule.js";

/**
 * docs/pass-contract.md §6.3 (v0.2.1): the text matcher and the §6.1 structured walk, shared by the conformance tests. The bundle's
 * copy (mcpb/server/pass-contract-v02.test.js) holds the same lists and `matcher-parity` in pass-contract-v021.test.ts compares them.
 */

/** The exact negations the matcher deletes before it looks for pass wording (v0.2). */
export const NEGATIONS = ["this is not a clean result", "not a clean result", "not a check of the content"];

/**
 * v0.2.1 (errata 5), v0.2.3: the CLOSED list of exact engine sentences a non-pass text may hold although they contain a matcher word. It is
 * the production list (`ENGINE_COPY_NEGATIONS`, src/verdict-rule.ts): the server prints an engine line as written only if it is exactly one
 * of these; every other engine line goes through `safeText`. (The sealed-report line's "not every redaction verified" is no longer in the
 * list: that line is replaced by fixed wording and never printed.)
 */
export const ENGINE_NEGATIONS = ENGINE_COPY_NEGATIONS;

/** v0.2.2 (errata C4): an engine sentence is exempt only as a WHOLE sentence: it starts the text, a line, a bullet or follows sentence
 *  punctuation (`:` `.` `;` `!` `?`), and it ends the text, a line, or is followed by sentence punctuation. "not every redaction verified
 *  and approved" is not exempt, nor is a sentence glued to a word before it. */
const wholeSentence = (sentence: string): RegExp => {
  const esc = sentence.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  // A sentence that carries its own final punctuation is closed by it, so whitespace may follow; one that does not must be followed by punctuation.
  const after = /[.!?]$/.test(sentence) ? "(?=$|\\s)" : "(?=$|[\\n.;:,!?)])";
  return new RegExp(`(?<=(?:^|[\\n:.;!?])[ \\t]*(?:-[ \\t]+)?)${esc}${after}`, "g");
};

const TOKENS = ["safe to send", "safe_to_send", "safe-to-send", "no recoverable pii", "verification: pass", "intact"];
const GLYPHS = ["✅", "✓", "✔", "☑", "🟢"];

/** The §6.3 matcher: NFKC + lowercase; the exact lead prefix, each exact allowed negation and each closed engine sentence deleted; for a
 *  non-pass any pass phrase, any of `\bclean\b` `\bverified\b` `\bpassed\b`, or a green glyph is a hit. */
export function matcherHits(text: string, outcome: string | undefined, engineNegations: readonly { sentence: string }[] = ENGINE_NEGATIONS): string[] {
  // v0.2.4 (errata 1): the text is read as a person reads it: NFKC, every Unicode format character (\p{Cf}: zero-width, bidi marks and
  // isolates, soft hyphen, BOM, ...) removed, whitespace runs folded, lower-cased. `safe<ZWSP>to send` and a bidi-wrapped phrase are hits.
  const norm = (s: string) => s.normalize("NFKC").replace(/\p{Cf}/gu, "").replace(/[^\S\n]+/g, " ").toLowerCase(); // horizontal runs folded; newlines kept for the whole-sentence rule
  let t = norm(text);
  t = t.split(norm("⚠️ NOT A PASS — ")).join("");
  for (const n of NEGATIONS) t = t.split(n).join("");
  for (const e of engineNegations) t = t.replace(wholeSentence(norm(e.sentence)), "");
  if (outcome === "safe_to_send") return [];
  const u = t.replace(/\s+/g, " "); // then every whitespace run (a newline too) is one space for the phrase checks
  const hits: string[] = [];
  // a phrase is also a hit with its separators removed ("safe<ZWSP>to send" folds to "safeto send": the break was the only space)
  const d = u.replace(/[\s_-]+/g, "");
  for (const k of TOKENS) if (u.includes(k) || (/[\s_-]/.test(k) && d.includes(k.replace(/[\s_-]+/g, "")))) hits.push(k);
  for (const re of [/\bclean\b/, /\bverified\b/, /\bpassed\b/]) if (re.test(u)) hits.push(String(re));
  for (const g of GLYPHS) if (u.includes(g)) hits.push(g);
  return hits;
}

/** §6.1: a pass-shaped value (a `verdict`, `userVerdict`, `state` of safe_to_send / pass / verified, `allPassed: true`) may appear in a
 *  structured result only when the outcome is safe_to_send, or under an attributed key. */
export function passShapedPaths(sc: unknown, outcome: string | undefined): string[] {
  if (outcome === "safe_to_send") return [];
  const out: string[] = [];
  const ATTRIBUTED = new Set(["embeddedReport", "engineAudit", "recordedByDesktop"]);
  const walk = (v: unknown, p: string[]) => {
    if (Array.isArray(v)) return v.forEach((x, i) => walk(x, [...p, String(i)]));
    if (v && typeof v === "object") {
      for (const [k, x] of Object.entries(v as Record<string, unknown>)) {
        if (p.some((q) => ATTRIBUTED.has(q))) continue;
        if (["verdict", "userVerdict", "state"].includes(k) && typeof x === "string" && ["safe_to_send", "pass", "verified"].includes(x)) out.push([...p, k].join("."));
        if (k === "allPassed" && x === true) out.push([...p, k].join("."));
        walk(x, [...p, k]);
      }
    }
  };
  walk(sc, []);
  return out;
}

const esc = (x: string) => x.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const WHY_PATTERNS: RegExp[] = Object.values(WHY).flatMap((w: any) => {
  const forms: string[] = typeof w === "function" ? [w(7777), w("LABELX"), w(true), w(false)] : [w];
  return forms.map((f) => new RegExp(`^${esc(f).replace("7777", "\\d+").replace("LABELX", "[^;]+")}$`));
});

/** Contract §2.3 / §6.2 (v0.2.1 errata 7a): a document tool's text that is not a pass STARTS with the issued lead, `notAPassLead(why)`:
 *  "⚠️ NOT A PASS — " + the why strings joined by "; " + ".\n\n", and every why is one of the contract's. */
export function assertLead(name: string, text: string, outcome: string) {
  if (outcome === "safe_to_send") return;
  assert.ok(text.startsWith("⚠️ NOT A PASS — "), `${name}: the text starts with the issued lead\n${text.slice(0, 200)}`);
  const first = text.split("\n\n")[0]!;
  assert.ok(first.endsWith("."), `${name}: the lead is one paragraph ending in a full stop\n${first}`);
  for (const seg of first.slice("⚠️ NOT A PASS — ".length, -1).split("; ")) {
    assert.ok(WHY_PATTERNS.some((re) => re.test(seg)), `${name}: "${seg}" is not one of the contract's why strings`);
  }
}

