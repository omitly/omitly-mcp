/**
 * omitly#1857: the MCP Apps result card — a read-only view of a Check or Seal result.
 *
 * Browser-safe on purpose: no Node imports, so the SAME functions run in the view
 * bundle (esbuild, see scripts/build-view.mjs) and in the tests, which render the card
 * against fixtures as plain strings. The view (view-entry.ts) only wires events.
 *
 * What the card may read: the tool result's EXISTING `structuredContent` and the tool's
 * input arguments (`pdfPath`). Nothing is added to any output schema. The card never reads
 * `findings` or any `preview`: model-facing structuredContent is uploaded to Anthropic and
 * stored with the conversation, so this view must never encourage putting more there. The one
 * exception is the amber / red "sensitive text still visible" section (omitly#1864), which reads
 * the `kind` and `page` of each entry of `regions`, `survivors` and `offPage`, and the position
 * boxes of `regions` and `survivors` (see `sensitiveRows`), and nothing else of them: no `preview`. The detected values are never
 * copied into the card model, the HTML or a data attribute. A field the card needs but the result
 * lacks is omitted.
 *
 * Copy is the desktop app's approved copy, verbatim (`src/check/model.ts` and
 * `src/App.tsx`). `result-card-parity.test.ts` fails when it drifts. Never paraphrase.
 */

import { type Outcome } from "./outcome.js";
import { parseCheckEnvelope, parseSealEnvelope } from "./replies.js";
import { engineLine, safeText, VISIBLE_TEXT_INFO_PREFIX as VISIBLE_TEXT_LINE_PREFIX } from "./verdict-rule.js";

/** Wording from the desktop Check screen (omitly#1266), the subset the card uses. */
export const COPY = {
  safe: "Safe to Send",
  needsReviewBlocking: "Needs Review — problems found",
  needsReview: "Needs Review",
  cannotVerify: "Cannot Verify",
  running: "Checking…",
  couldNotRun: "Check could not run",
} as const;

export type Look = "running" | "safe" | "blocking" | "review" | "cannot" | "error" | "visible";
type VerdictLook = Exclude<Look, "running" | "error" | "visible">;

export const LOOK_TITLES: Record<VerdictLook, string> = {
  safe: COPY.safe,
  blocking: COPY.needsReviewBlocking,
  review: COPY.needsReview,
  cannot: COPY.cannotVerify,
};

export type SectionKey = "checked" | "notChecked" | "problems" | "review" | "information" | "decisions" | "reasons";

/** Marker glyph + colour family per section, as in `SECTIONS` of src/check/model.ts. */
export const SECTIONS: Record<SectionKey, { heading: string; marker: string; family: Family | "neutral" }> = {
  checked: { heading: "WHAT WAS CHECKED", marker: "✓", family: "green" },
  notChecked: { heading: "COULD NOT BE CHECKED", marker: "–", family: "neutral" },
  problems: { heading: "PROBLEMS FOUND", marker: "✗", family: "red" },
  review: { heading: "REVIEW", marker: "⚠", family: "amber" },
  information: { heading: "INFORMATION (does not affect the result)", marker: "ℹ", family: "blue" },
  decisions: { heading: "DECISIONS RECORDED", marker: "✓", family: "green" },
  reasons: { heading: "WHY", marker: "?", family: "blue" },
};

/** Section order per look (`SECTION_ORDER` of src/check/model.ts). */
/** Contract §3.8: the look of each outcome. A missing or unknown outcome is the error state (the envelope parser refuses it). */
const OUTCOME_LOOK: Record<Outcome, VerdictLook> = { safe_to_send: "safe", needs_review: "review", not_a_pass: "blocking", incomplete: "cannot" };

export const SECTION_ORDER: Record<VerdictLook, SectionKey[]> = {
  safe: ["checked", "notChecked", "information", "decisions"],
  blocking: ["problems", "review", "information", "decisions"],
  review: ["review", "checked", "notChecked", "information", "decisions"],
  cannot: ["reasons", "checked", "notChecked", "information", "decisions"],
};

/** Seal copy, from `src/App.tsx` (the Verify modal) and the owner-approved card brief. */
export const SEAL_COPY = {
  heldReview: "Seal unchanged — its report lists items to review",
  heldNotACheck: "Seal unchanged — a seal is not a check of the content",
  intactNotPassed: "Seal unchanged — but redaction did NOT fully pass",
  invalid: "Seal INVALID — report altered or unsigned",
  removed: "Seal REMOVED — file re-saved or changed after sealing",
  noReport: "No Omitly audit report found in this PDF",
  unsupportedWithReport: () => "Cannot verify — sealed with a version this app can't check",
  unsupportedNoReport: () => "Sealed with a version this app can't check",
  removedLine:
    "This file carries a sealed Omitly report, but its seal is gone — usually because the file was re-saved in another app. It cannot be confirmed unaltered. Ask the sender for the original file.",
  unsupportedWithReportLine:
    "This file carries an Omitly audit report, but its seal is in a format this app cannot verify, so the document CANNOT be confirmed unaltered. It may be output from a newer Omitly, or an altered file relabelled to look like one — this app cannot tell them apart. Update Omitly, and until then do not rely on this document.",
  unsupportedNoReportLine:
    "Update Omitly to verify this document. Nothing was verified here — this is not a pass or a fail. The version tag itself is unauthenticated.",
  // Owner-approved card lines (omitly#1857 brief).
  unchangedLine:
    "Unchanged since it was sealed. A seal shows integrity, not who made the file: compare the key fingerprint with the sender.",
  invalidLine:
    "This file was changed after sealing, or its report was never signed. Do not rely on the embedded report.",
  signatureMismatchRow: "Signature does not match the file bytes",
  reportPresentRow: "Embedded report present: its verdict cannot be trusted",
} as const;

// ---------------------------------------------------------------------------
// Colours. The Tailwind palette the desktop uses, so the card cannot drift from it.
// ---------------------------------------------------------------------------

export type Family = "green" | "red" | "amber" | "blue";

const TW: Record<Family | "neutral", Record<number, string>> = {
  green: { 50: "#f0fdf4", 200: "#bbf7d0", 400: "#4ade80", 600: "#16a34a", 800: "#166534", 900: "#14532d", 950: "#052e16" },
  red: { 50: "#fef2f2", 200: "#fecaca", 400: "#f87171", 600: "#dc2626", 800: "#991b1b", 900: "#7f1d1d", 950: "#450a0a" },
  amber: { 50: "#fffbeb", 200: "#fde68a", 400: "#fbbf24", 600: "#d97706", 800: "#92400e", 900: "#78350f", 950: "#451a03" },
  blue: { 50: "#eff6ff", 200: "#bfdbfe", 400: "#60a5fa", 600: "#2563eb", 800: "#1e40af", 900: "#1e3a8a", 950: "#172554" },
  neutral: { 100: "#f5f5f5", 200: "#e5e5e5", 300: "#d4d4d4", 400: "#a3a3a3", 500: "#737373", 700: "#404040", 800: "#262626", 900: "#171717" },
};

export const LOOK_FAMILY: Record<VerdictLook, Family> = { safe: "green", blocking: "red", review: "amber", cannot: "blue" };

/** The Tailwind class string for a verdict look — compared with `LOOK_CLASSES` in
 *  src/check/model.ts by the parity test. */
export function lookClasses(look: VerdictLook): string {
  const f = LOOK_FAMILY[look];
  return `bg-${f}-50 dark:bg-${f}-950/40 text-${f}-800 dark:text-${f}-200 border-${f}-200 dark:border-${f}-900`;
}

/** `Tailwind bg-X-950/40` over the dark card background (#171717), as an opaque hex. */
export function blend(hex: string, over: string, alpha: number): string {
  const c = (h: string, i: number) => parseInt(h.slice(1 + i * 2, 3 + i * 2), 16);
  const out = [0, 1, 2].map((i) => Math.round(alpha * c(hex, i) + (1 - alpha) * c(over, i)));
  return "#" + out.map((n) => n.toString(16).padStart(2, "0")).join("");
}

const DARK_CARD = "#171717";

function lookVars(): string {
  const fams = ["green", "red", "amber", "blue"] as const;
  const light: string[] = [];
  const dark: string[] = [];
  (Object.keys(LOOK_FAMILY) as VerdictLook[]).forEach((look) => {
    const p = TW[LOOK_FAMILY[look]];
    light.push(`--${look}-bg:${p[50]};--${look}-bd:${p[200]};--${look}-tx:${p[800]};`);
    dark.push(`--${look}-bg:${blend(p[950]!, DARK_CARD, 0.4)};--${look}-bd:${p[900]};--${look}-tx:${p[200]};`);
  });
  const lightM = fams.map((f) => `--m-${f}:${TW[f][600]};`).join("") + `--m-neutral:${TW.neutral[500]};`;
  const darkM = fams.map((f) => `--m-${f}:${TW[f][400]};`).join("") + `--m-neutral:${TW.neutral[400]};`;
  const darkAll =
    `--card-bg:${DARK_CARD};--card-bd:${TW.neutral[800]};--tx:${TW.neutral[200]};--tx-mute:${TW.neutral[400]};` +
    `--btn-bd:${TW.neutral[700]};--run-bg:${DARK_CARD};--run-bd:${TW.neutral[800]};--run-tx:${TW.neutral[200]};` +
    dark.join("") +
    darkM;
  return (
    `:root{color-scheme:light dark;--card-bg:#ffffff;--card-bd:${TW.neutral[200]};--tx:${TW.neutral[800]};--tx-mute:${TW.neutral[500]};` +
    `--btn-bd:${TW.neutral[300]};--run-bg:${TW.neutral[100]};--run-bd:${TW.neutral[200]};--run-tx:${TW.neutral[800]};` +
    light.join("") +
    lightM +
    `}` +
    // Host theme wins when it is sent (data-theme); otherwise the page follows the OS.
    `@media (prefers-color-scheme:dark){:root:not([data-theme=light]){${darkAll}}}` +
    `:root[data-theme=dark]{${darkAll}}` +
    `:root[data-theme=light]{color-scheme:light}`
  );
}

/** The card's stylesheet. Inline; no web fonts, no external URL. */
export const CARD_CSS =
  lookVars() +
  `*{box-sizing:border-box}` +
  `html,body{margin:0;padding:0;background:transparent}` +
  `body{font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;color:var(--tx);font-size:13px;line-height:1.4}` +
  `.card{width:100%;max-width:560px;border-radius:12px;padding:14px 16px;display:flex;flex-direction:column;gap:12px;background:var(--card-bg);border:1px solid var(--card-bd)}` +
  `.hdr{display:flex;flex-direction:column;gap:2px}` +
  `.hd-t{font-size:13px}.brand{font-weight:600}.kind{font-weight:400;color:var(--tx-mute)}` +
  `.meta{font-size:12px;font-weight:400;color:var(--tx-mute);overflow-wrap:anywhere}` +
  `.banner{border-radius:8px;padding:10px 12px;display:flex;flex-direction:column;gap:4px;border:1px solid}` +
  `.banner h3{margin:0;font-size:16px;font-weight:600}.banner p{margin:0;font-size:13px;font-weight:400}` +
  (["safe", "blocking", "review", "cannot"] as VerdictLook[])
    .map((l) => `.look-${l}{background:var(--${l}-bg);border-color:var(--${l}-bd);color:var(--${l}-tx)}`)
    .join("") +
  // omitly#1864: the amber "sensitive text is visible" state is the review look's colours.
  `.look-visible{background:var(--review-bg);border-color:var(--review-bd);color:var(--review-tx)}` +
  `.look-running,.look-error{background:var(--run-bg);border-color:var(--run-bd);color:var(--run-tx)}` +
  `.sec{display:flex;flex-direction:column;gap:6px}.sec h4{margin:0;font-size:12px}` +
  `.sh{all:unset;box-sizing:border-box;cursor:pointer;display:inline-flex;gap:6px;align-items:baseline;font:inherit;font-size:12px;font-weight:600;color:var(--tx-mute);text-transform:uppercase;border-radius:4px}` +
  `.sh:focus-visible{outline:2px solid var(--m-blue);outline-offset:2px}` +
  `.cnt{font-weight:500}` +
  `.rows{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:6px}.rows[hidden]{display:none}` +
  `.rows li{display:flex;gap:8px;align-items:baseline}` +
  `.mk{font-size:13px;font-weight:500;flex:none;min-width:1ch;text-align:center}.tx{font-size:13px;font-weight:400;color:var(--tx);overflow-wrap:anywhere}` +
  (["green", "red", "amber", "blue", "neutral"] as const).map((f) => `.c-${f}{color:var(--m-${f})}`).join("") +
  `.acts{display:flex;align-items:center;gap:8px;flex-wrap:wrap}` +
  `.open{font:inherit;font-size:13px;font-weight:500;padding:6px 10px;border-radius:6px;border:1px solid var(--btn-bd);background:var(--card-bg);color:var(--tx);cursor:pointer}` +
  `.open:focus-visible{outline:2px solid var(--m-blue);outline-offset:2px}` +
  `.note{font-size:12px;color:var(--tx-mute)}` +
  `.foot{font-size:11px;font-weight:400;color:var(--tx-mute);overflow-wrap:anywhere}`;

// ---------------------------------------------------------------------------
// Input shapes. Everything read here is untrusted until checked: the host hands the view
// whatever the tool returned.
// ---------------------------------------------------------------------------

export interface ToolInputLike {
  arguments?: { pdfPath?: unknown } | null;
}
export interface ToolResultLike {
  structuredContent?: unknown;
  isError?: boolean;
}

export interface CardContext {
  /** The server's own version, injected into the page at resources/read. */
  version: string;
  /** "Mac" or "PC" — the same device noun the desktop's status bar uses. */
  deviceNoun: "Mac" | "PC";
  /** The current time, for a footer that the result has no time for. */
  now: Date;
  /** The view can offer "Open in Omitly" on this host (macOS only in v1). */
  canOpen: boolean;
  /** Sections the user opened or closed, by key; overrides the default. */
  openOverrides?: Record<string, boolean>;
}

export interface CardItem {
  marker: string;
  family: Family | "neutral";
  label: string;
  text: string;
}
export interface CardSection {
  key: string;
  heading: string;
  family: Family | "neutral";
  count: number;
  /** What the count chip prints when it is not the bare number ("4 ⚠"). */
  countText?: string;
  open: boolean;
  items: CardItem[];
}
export interface CardModel {
  kind: "check" | "seal" | "pending" | "unknown";
  look: Look;
  title: string;
  line: string;
  /** "Check" / "Seal" / "" */
  suffix: string;
  meta: string;
  sections: CardSection[];
  footer: string;
  /** The "Open in Omitly" button, or null. */
  button: { label: string } | null;
  pdfPath: string | null;
}

const MARKER_LABEL: Record<string, string> = {
  "✓": "passed",
  "✗": "problem",
  "⚠": "review",
  "?": "unknown",
  "ℹ": "information",
  "–": "not checked",
};

// ---------------------------------------------------------------------------
// Formatting (the desktop's own helpers, src/check/model.ts)
// ---------------------------------------------------------------------------

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/** "11 Nov 2026 14:02" in local time; the raw string if it does not parse. */
export function formatLocalTime(d: Date | string): string {
  const date = typeof d === "string" ? new Date(d) : d;
  if (Number.isNaN(date.getTime())) return typeof d === "string" ? d : "";
  const hh = String(date.getHours()).padStart(2, "0");
  const mm = String(date.getMinutes()).padStart(2, "0");
  return `${date.getDate()} ${MONTHS[date.getMonth()]} ${date.getFullYear()} ${hh}:${mm}`;
}

/** "812 KB" / "3.4 MB". */
export function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/** First four and last four characters: "ab12…cd34". */
export function shortEnds(h: string): string {
  return h.length > 8 ? `${h.slice(0, 4)}…${h.slice(-4)}` : h;
}

export function baseName(p: string): string {
  const parts = p.split(/[\\/]/).filter((s) => s.length > 0);
  return parts.length ? parts[parts.length - 1]! : "";
}

function pageCountText(n: number): string {
  return `${n} page${n === 1 ? "" : "s"}`;
}

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

/** Items of a check section: only `{text: string}` entries, text only (a line names its
 *  own pages, as on the desktop). Anything else is dropped. */
function itemTexts(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  const out: string[] = [];
  for (const x of v) if (isRecord(x) && typeof x.text === "string") out.push(engineLine(x.text)); // v0.2.3: engine copy is sanitised unless it is a closed negation line
  return out;
}

function pdfPathOf(input: ToolInputLike | undefined | null): string | null {
  const p = input?.arguments?.pdfPath;
  return typeof p === "string" && p.length > 0 ? p : null;
}

function headerMeta(pdfPath: string | null, extra: string[]): string {
  const parts: string[] = [];
  if (pdfPath) {
    const b = safeText(baseName(pdfPath)); // v0.2.3: a file name is the file's own string
    if (b) parts.push(b);
  }
  parts.push(...extra);
  return parts.join(" · ");
}

// ---------------------------------------------------------------------------
// Check card
// ---------------------------------------------------------------------------

type Json = Record<string, unknown>;

function checkVerdictOf(sc: Json): { state: "safe_to_send" | "needs_review" | "cannot_verify"; blocking: boolean; result: Json | null } | null {
  const v = sc.verdict;
  if (!isRecord(v)) return null;
  const state = v.verdict;
  if (state !== "safe_to_send" && state !== "needs_review" && state !== "cannot_verify") return null;
  if (typeof v.blocking !== "boolean") return null;
  const result = isRecord(v.result) ? v.result : null;
  return { state, blocking: v.blocking, result };
}

export function checkLook(state: string, blocking: boolean): VerdictLook {
  if (state === "safe_to_send") return "safe";
  if (state === "needs_review") return blocking ? "blocking" : "review";
  return "cannot";
}

/** Which sections open by default: Problems and Review when blocking; Why for Cannot
 *  Verify; What was checked for Safe to Send. Everything else starts collapsed. */
function checkOpenByDefault(look: VerdictLook, key: SectionKey): boolean {
  if (look === "blocking") return key === "problems" || key === "review";
  if (look === "cannot") return key === "reasons";
  if (look === "safe") return key === "checked";
  return false;
}

// ---------------------------------------------------------------------------
// omitly#1864: sensitive text still visible (kinds, counts and pages only)
// ---------------------------------------------------------------------------

/** The owner-approved copy of the amber state and of its section (13 November 2026). */
export const VISIBLE_COPY = {
  heading: "SENSITIVE TEXT STILL VISIBLE",
  marker: "⚠",
  button: "Open in Omitly to redact",
  title: (n: number) => `${COPY.needsReview} — sensitive text is visible (${n})`,
  line: (n: number) =>
    n === 1
      ? "This file still shows 1 item that looks sensitive. Do not send it until it is removed."
      : `This file still shows ${n} items that look sensitive. Do not send it until they are removed.`,
} as const;

/** Kind code (`kind` of a finding) -> [singular, plural]. A kind not listed is "sensitive item(s)":
 *  the code itself is never printed. */
const KIND_NOUN: Record<string, [string, string]> = {
  email: ["email address", "email addresses"],
  phone: ["phone number", "phone numbers"],
  ssn: ["social security number", "social security numbers"],
  card: ["card number", "card numbers"],
  tfn: ["tax file number", "tax file numbers"],
  abn: ["Australian business number", "Australian business numbers"],
  acn: ["Australian company number", "Australian company numbers"],
  medicare: ["Medicare number", "Medicare numbers"],
  crn: ["Centrelink reference number", "Centrelink reference numbers"],
  ihi: ["healthcare identifier", "healthcare identifiers"],
  bsb: ["BSB number", "BSB numbers"],
};
const OTHER_NOUN: [string, string] = ["other sensitive item", "other sensitive items"];

/** "page 1", "pages 1 and 2", "pages 1, 2 and 5", "12 pages" (more than ten are counted). */
export function pagesPhrase(pages: number[]): string {
  const p = [...new Set(pages)].sort((a, b) => a - b);
  if (p.length === 0) return "";
  if (p.length === 1) return `page ${p[0]}`;
  if (p.length > 10) return `${p.length} pages`;
  return `pages ${p.slice(0, -1).join(", ")} and ${p[p.length - 1]}`;
}

function listPhrase(parts: string[]): string {
  return parts.length <= 1 ? (parts[0] ?? "") : `${parts.slice(0, -1).join(", ")} and ${parts[parts.length - 1]}`;
}

export interface SensitiveRows {
  /** Every finding counted, whatever its row. */
  total: number;
  /** One row per group of kinds that share the same pages. */
  rows: string[];
}

/**
 * The kinds, counts and pages of the findings in a `check_redaction` result.
 *
 * Reads ONLY `kind` (checked against a fixed list of nouns) and `page` (a whole number) of each
 * entry of `regions` and `offPage`, plus `survivors` when `withSurvivors`, and the position boxes
 * (`x`, `y`, `width`, `height`) of `regions` and `survivors` to drop a text-layer entry that lies
 * inside a survivor of the same kind on the same page: the scan lists a value under a box twice,
 * and that value is the failed redaction, not visible text. It never reads `preview` or any other
 * field, so no detected value can reach the card.
 */
export function sensitiveRows(sc: Json, withSurvivors: boolean): SensitiveRows {
  const perKind = new Map<string, { n: number; pages: Set<number> }>();
  let total = 0;
  const add = (list: unknown, hasPage: boolean) => {
    if (!Array.isArray(list)) return;
    for (const f of list) {
      if (!isRecord(f)) continue;
      const kind = typeof f.kind === "string" && f.kind in KIND_NOUN ? f.kind : "other";
      // An item with no page (metadata, a form field, an attachment) never joins a kind's page row.
      const key = `${hasPage ? "p" : "o"}:${kind}`;
      const e = perKind.get(key) ?? { n: 0, pages: new Set<number>() };
      e.n += 1;
      if (hasPage && typeof f.page === "number" && Number.isInteger(f.page) && f.page >= 0 && f.page < 1_000_000) {
        e.pages.add(f.page + 1);
      }
      perKind.set(key, e);
      total += 1;
    }
  };
  const box = (f: Record<string, unknown>) =>
    ["x", "y", "width", "height"].every((k) => typeof f[k] === "number" && Number.isFinite(f[k] as number))
      ? { x: f.x as number, y: f.y as number, w: f.width as number, h: f.height as number }
      : null;
  const under = (Array.isArray(sc.survivors) ? sc.survivors : []).filter(isRecord);
  // 0.5 pt of slack: the two boxes come from the same glyph positions but are measured separately.
  const coveredByASurvivor = (f: Record<string, unknown>): boolean => {
    const r = box(f);
    return (
      r !== null &&
      under.some((u) => {
        const b = box(u);
        return (
          b !== null &&
          u.kind === f.kind &&
          u.page === f.page &&
          r.x >= b.x - 0.5 &&
          r.y >= b.y - 0.5 &&
          r.x + r.w <= b.x + b.w + 0.5 &&
          r.y + r.h <= b.y + b.h + 0.5
        );
      })
    );
  };
  add(Array.isArray(sc.regions) ? sc.regions.filter((f) => !(isRecord(f) && coveredByASurvivor(f))) : sc.regions, true);
  if (withSurvivors) add(sc.survivors, true);
  add(sc.offPage, false);

  // Kinds with the same pages share a row.
  const byPages = new Map<string, { pages: number[]; parts: { kind: string; n: number }[] }>();
  for (const [pk, e] of perKind) {
    const kind = pk.slice(2);
    const pages = [...e.pages].sort((a, b) => a - b);
    const key = pages.join(",");
    const g = byPages.get(key) ?? { pages, parts: [] };
    g.parts.push({ kind, n: e.n });
    byPages.set(key, g);
  }
  const groups = [...byPages.values()].sort((a, b) => (a.pages[0] ?? Infinity) - (b.pages[0] ?? Infinity));
  const rows = groups.map((g) => {
    const what = listPhrase(
      g.parts.map(({ kind, n }) => {
        const noun = KIND_NOUN[kind] ?? OTHER_NOUN;
        return `${n} ${n === 1 ? noun[0] : noun[1]}`;
      }),
    );
    return g.pages.length ? `${what} on ${pagesPhrase(g.pages)}` : `${what} outside the page text`;
  });
  return { total, rows };
}

export function buildCheckModel(sc: Json, pdfPath: string | null, ctx: CardContext): CardModel | null {
  const raw = checkVerdictOf(sc);
  if (!raw) return null;
  // Contract §3.8: the look is a function of `outcome` ALONE (the envelope parser has already required a known one, and a pass to agree
  // with its verdict and scan). The verdict's reconciled result only supplies the sections.
  const outcome = sc.outcome as Outcome;
  const v = { state: raw.state as string, blocking: raw.blocking, result: raw.result };
  const r = v.result;
  const verdictLook: VerdictLook = OUTCOME_LOOK[outcome];
  const blocking = outcome === "not_a_pass";
  // A needs_review outcome whose envelope lists findings is the approved amber "sensitive text visible" state.
  const amber = outcome === "needs_review" ? sensitiveRows(sc, true) : null;
  const visible = amber !== null && amber.total > 0 ? amber : null;
  const underRed = blocking ? sensitiveRows(sc, false) : null;
  const look: Look = visible ? "visible" : verdictLook;

  // The desktop's `sectionsFor`: a blocking result keeps COULD NOT BE CHECKED when the
  // result carries could-not-check findings (`reasons`).
  let order: (SectionKey | "sensitive")[];
  if (visible) {
    // The approved amber state: the visible items, what was checked, information. Anything else the
    // engine asked a person to review stays visible too (never hidden by this state).
    order = ["sensitive", "review", "checked", "notChecked", "information"];
  } else {
    order = [...SECTION_ORDER[verdictLook]];
    // Desktop keeps COULD NOT BE CHECKED on a blocking result only when it has `reasons`; the card
    // also keeps it when the scan could not read the file (omitly#1864: limits are shown in every state).
    if (verdictLook === "blocking" && r && (itemTexts(r.reasons).length > 0 || itemTexts(r.notChecked).length > 0)) {
      const at = order.indexOf("review") + 1;
      order = [...order.slice(0, at), "notChecked", ...order.slice(at)];
    }
    if (underRed && underRed.total > 0) {
      order.splice(order.indexOf("information"), 0, "sensitive");
    }
  }
  const shown = visible ?? (underRed && underRed.total > 0 ? underRed : null);
  const sections: CardSection[] = [];
  for (const key of order) {
    if (key === "sensitive") {
      if (!shown) continue;
      sections.push({
        key: "sensitive",
        heading: VISIBLE_COPY.heading,
        family: "amber",
        count: shown.total,
        countText: `${shown.total} ${VISIBLE_COPY.marker}`,
        open: ctx.openOverrides?.sensitive ?? true,
        items: shown.rows.map((text) => ({ marker: VISIBLE_COPY.marker, family: "amber" as const, label: MARKER_LABEL[VISIBLE_COPY.marker] ?? "", text })),
      });
      continue;
    }
    if (!r) continue;
    let texts = itemTexts(r[key]);
    // The card's own section says it; the engine's line (information, or review once it was
    // reconciled) would repeat it.
    if (shown && (key === "information" || key === "review")) {
      texts = texts.filter((t) => !t.startsWith(VISIBLE_TEXT_LINE_PREFIX));
    }
    if (texts.length === 0) continue;
    const def = SECTIONS[key];
    // Contract §3.8: no green element on a non-pass. What was checked (and decisions recorded) is neutral unless the outcome is a pass.
    const neutral = outcome !== "safe_to_send" && (key === "checked" || key === "decisions");
    const family = neutral ? ("neutral" as const) : def.family;
    const marker = neutral ? "–" : def.marker;
    sections.push({
      key,
      heading: def.heading,
      family,
      count: texts.length,
      open: ctx.openOverrides?.[key] ?? (visible ? false : checkOpenByDefault(verdictLook, key)),
      items: texts.map((text) => ({ marker, family, label: MARKER_LABEL[marker] ?? "", text })),
    });
  }

  const extra: string[] = [];
  if (r) {
    if (typeof r.pagesTotal === "number" && r.pagesTotal > 0) extra.push(pageCountText(r.pagesTotal));
    if (typeof r.sizeBytes === "number" && r.sizeBytes > 0) extra.push(formatSize(r.sizeBytes));
  }

  let footer = "";
  // v0.2.3: each footer field is drawn only in the shape the engine writes it (a version, an RFC 3339 time, a hex digest).
  if (r && typeof r.omitlyVersion === "string" && /^[0-9A-Za-z.+-]{1,64}$/.test(r.omitlyVersion) && typeof r.checkedAt === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$/.test(r.checkedAt)) {
    const parts = [`Checked on this ${ctx.deviceNoun} by Omitly ${r.omitlyVersion}`, formatLocalTime(r.checkedAt)];
    if (typeof r.sha256 === "string" && /^[0-9a-f]{64}$/.test(r.sha256)) parts.push(`sha256 ${shortEnds(r.sha256)}`);
    footer = parts.join(" · ");
  }

  return {
    kind: "check",
    look,
    title: visible ? VISIBLE_COPY.title(visible.total) : LOOK_TITLES[verdictLook],
    line: visible ? VISIBLE_COPY.line(visible.total) : r && typeof r.summary === "string" ? engineLine(r.summary) : COPY.couldNotRun,
    suffix: "Check",
    meta: headerMeta(pdfPath, extra),
    sections,
    footer,
    button:
      ctx.canOpen && pdfPath
        ? { label: visible ? VISIBLE_COPY.button : blocking ? "Open in Omitly to fix" : "Open in Omitly" }
        : null,
    pdfPath,
  };
}

// ---------------------------------------------------------------------------
// Seal card
// ---------------------------------------------------------------------------

export interface SealLook {
  look: VerdictLook;
  title: string;
  line: string;
}

/** What the file's own report records, in the contract's words (the same labels as the server's text, §3.6): never a file string. */
function reportRecordLabel(er: Json | null): string | null {
  if (!er) return null;
  const uv = er.userVerdict;
  if (uv === "safe_to_send") return "nothing to review";
  if (uv === "needs_review") return er.blocking === true ? "a failed redaction" : "items to review";
  if (uv === "cannot_verify") return "that it could not be checked";
  if (er.verifierVerdict === "verified") return "no failed region";
  if (er.verifierVerdict === "incomplete") return "a failed region";
  return null;
}

/**
 * Contract §3.8: the look of a seal result is a function of `outcome` ALONE (`OUTCOME_LOOK`); the seal state only chooses the title
 * (S1/S2 the invalid and removed titles; S3/S4 "intact but not passed"; S5-S7 "its report lists items to review"; S8 with a held seal
 * "a seal is not a check of the content"; S8 without one the no-report and unsupported titles). No seal result is green: the envelope
 * parser refuses `safe_to_send` here.
 */
export function sealLook(sc: Json): SealLook {
  const outcome = sc.outcome as Outcome;
  const look = OUTCOME_LOOK[outcome];
  const seal = isRecord(sc.seal) ? sc.seal : {};
  const er = isRecord(sc.embeddedReport) ? sc.embeddedReport : null;
  const state = seal.state;
  if (state === "removed") return { look, title: SEAL_COPY.removed, line: SEAL_COPY.removedLine };
  if (state === "invalid") return { look, title: SEAL_COPY.invalid, line: SEAL_COPY.invalidLine };
  if (state === "unsupported") {
    return er && er.carriesAuditReport === true
      ? { look, title: SEAL_COPY.unsupportedWithReport(), line: SEAL_COPY.unsupportedWithReportLine }
      : { look, title: SEAL_COPY.unsupportedNoReport(), line: SEAL_COPY.unsupportedNoReportLine };
  }
  if (state === "held") {
    const title = outcome === "not_a_pass" ? SEAL_COPY.intactNotPassed : outcome === "needs_review" ? SEAL_COPY.heldReview : SEAL_COPY.heldNotACheck;
    return { look, title, line: SEAL_COPY.unchangedLine };
  }
  return er === null ? { look, title: SEAL_COPY.noReport, line: "" } : { look, title: COPY.cannotVerify, line: "" };
}

export function buildSealModel(sc: Json, pdfPath: string | null, ctx: CardContext): CardModel | null {
  if (!isRecord(sc.seal)) return null;
  const sl = sealLook(sc);
  const seal = sc.seal;
  const er = isRecord(sc.embeddedReport) ? sc.embeddedReport : null;
  const rows: CardItem[] = [];
  // Contract §3.8: every row is red (a failed seal) or blue information; none is green.
  const row = (marker: string, family: CardItem["family"], text: string) =>
    rows.push({ marker, family, label: MARKER_LABEL[marker] ?? "", text });

  const state = seal.state;
  const eraLabel = typeof seal.eraLabel === "string" && seal.eraLabel.length > 0 ? seal.eraLabel : null;
  const keyKind = seal.keyKind === "one_time" || seal.keyKind === "install" ? seal.keyKind : null;
  const fingerprint = typeof seal.fingerprint === "string" && /^[0-9A-Fa-f:]{1,200}$/.test(seal.fingerprint) ? seal.fingerprint : null; // v0.2.3: the same colon-hex gate as the text

  if (state === "held") {
    // Name an algorithm only with evidence: the v1 era label, or a v2 report whose engine also reports the key kind.
    if (eraLabel !== null) row("ℹ", "blue", "Seal v1 · Ed25519");
    else if (er && er.userVerdict !== null && er.userVerdict !== undefined && keyKind !== null) row("ℹ", "blue", "Seal v2 · ML-DSA-87 with ECDSA P-384");
    row("ℹ", "blue", fingerprint ? `Key fingerprint ${shortEnds(fingerprint)}${keyKind === "one_time" ? " (one-time key)" : keyKind === "install" ? " (per-install key)" : ""}` : "Key: a key this engine does not report");
    const label = reportRecordLabel(er);
    if (label) row("ℹ", "blue", `The file's own report records: ${label}`);
  } else if (state === "unsupported") {
    // v0.2.1 (errata 3): the file's own version token is never drawn.
    row("?", "blue", "Seal version not recognised · this verifier cannot check it");
    if (er && er.carriesAuditReport === true) row("?", "blue", SEAL_COPY.reportPresentRow);
  } else if (state === "invalid" || state === "removed") {
    if (state === "invalid") row("✗", "red", SEAL_COPY.signatureMismatchRow);
    if ((er && er.carriesAuditReport === true) || state === "removed") row("✗", "red", SEAL_COPY.reportPresentRow);
  }
  if (eraLabel !== null) row("ℹ", "blue", `Seal format: ${eraLabel}`);

  const sections: CardSection[] = rows.length
    ? [{ key: "seal", heading: "SEAL", family: sl.look === "blocking" ? "red" : "blue", count: rows.length, open: ctx.openOverrides?.seal ?? true, items: rows }]
    : [];

  const extra: string[] = [];
  if (er && typeof er.pageCount === "number" && er.pageCount > 0) extra.push(pageCountText(er.pageCount));

  return {
    kind: "seal",
    look: sl.look,
    title: sl.title,
    line: sl.line,
    suffix: "Seal",
    meta: headerMeta(pdfPath, extra),
    sections,
    footer: `Checked on this ${ctx.deviceNoun} by Omitly ${ctx.version} · ${formatLocalTime(ctx.now)}`,
    button: null,
    pdfPath,
  };
}

// ---------------------------------------------------------------------------
// Entry
// ---------------------------------------------------------------------------

/** The card for what the view has so far. `toolInput` arrives first (`ontoolinput`), the
 *  result later (`ontoolresult`); each is optional. */
export function buildModel(
  toolInput: ToolInputLike | undefined | null,
  toolResult: ToolResultLike | undefined | null,
  ctx: CardContext,
): CardModel {
  const pdfPath = pdfPathOf(toolInput);
  if (!toolResult) {
    return {
      kind: "pending",
      look: "running",
      title: COPY.running,
      line: "",
      suffix: "",
      meta: headerMeta(pdfPath, []),
      sections: [],
      footer: "",
      button: null,
      pdfPath,
    };
  }
  const sc = isRecord(toolResult.structuredContent) ? toolResult.structuredContent : null;
  // omitly#1864 (contract §3): a completed check is `isError: false` and carries `outcome` and a structured result; a check that could not run
  // is `isError: true` with no structured result. So EVERY `isError` result renders the error state here (a flagged result that also carries a
  // structured result is inconsistent), and an unflagged one is drawn only if the strict parsers (replies.ts) accept its envelope: a missing
  // field, a wrong type, an unknown or missing `outcome`, a verdict that disagrees with its own result or with what the scan found, or a
  // verdict check that did not run is the error state too. The card never re-derives a pass: its look is a function of `outcome` alone.
  if (sc) {
    // An execution failure (the host flags `isError`) carries no structured result of ours; one that does is inconsistent: the error state.
    const flagged = toolResult.isError === true;
    // A check result carries `verdict` as an object; a seal result carries `seal` (contract §6.1).
    const m = flagged
      ? null
      : isRecord(sc.verdict)
        ? parseCheckEnvelope(sc).ok
          ? buildCheckModel(sc, pdfPath, ctx)
          : null
        : parseSealEnvelope(sc).ok
          ? buildSealModel(sc, pdfPath, ctx)
          : null;
    if (m) return m;
  }
  return {
    kind: "unknown",
    look: "error",
    title: COPY.couldNotRun,
    line: "",
    suffix: "",
    meta: headerMeta(pdfPath, []),
    sections: [],
    footer: "",
    button: null,
    pdfPath,
  };
}

// ---------------------------------------------------------------------------
// Render
// ---------------------------------------------------------------------------

export function esc(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

const lookClass = (look: Look) => `look-${look}`;

/** The card as an HTML string. Every dynamic value is escaped. */
export function renderCardHtml(m: CardModel, opts: { buttonNote?: string } = {}): string {
  const out: string[] = [];
  out.push(`<section class="card" data-kind="${m.kind}" data-look="${m.look}" aria-label="Omitly${m.suffix ? " " + m.suffix : ""} result">`);
  out.push(
    `<header class="hdr"><div class="hd-t"><span class="brand">Omitly</span>` +
      (m.suffix ? `<span class="kind"> · ${esc(m.suffix)}</span>` : "") +
      `</div>` +
      (m.meta ? `<div class="meta">${esc(m.meta)}</div>` : "") +
      `</header>`,
  );
  out.push(
    `<div class="banner ${lookClass(m.look)}" data-testid="banner"${m.look === "running" ? ` role="status"` : ""}>` +
      `<h3>${esc(m.title)}</h3>` +
      (m.line ? `<p>${esc(m.line)}</p>` : "") +
      `</div>`,
  );
  for (const s of m.sections) {
    const id = `sec-${s.key}`;
    out.push(
      `<section class="sec" data-section="${esc(s.key)}">` +
        `<h4><button type="button" class="sh" data-toggle="${esc(s.key)}" aria-expanded="${s.open}" aria-controls="${id}">` +
        `<span aria-hidden="true">${s.open ? "▾" : "▸"}</span><span>${esc(s.heading)}</span>` +
        `<span class="cnt c-${s.family}">${esc(s.countText ?? String(s.count))}</span></button></h4>` +
        `<ul class="rows" id="${id}"${s.open ? "" : " hidden"}>` +
        s.items
          .map(
            (it) =>
              `<li><span class="mk c-${it.family}" role="img" aria-label="${esc(it.label)}">${esc(it.marker)}</span>` +
              `<span class="tx">${esc(it.text)}</span></li>`,
          )
          .join("") +
        `</ul></section>`,
    );
  }
  if (m.button) {
    out.push(
      `<div class="acts"><button type="button" class="open" data-action="open">${esc(m.button.label)}</button>` +
        `<span class="note" role="status" aria-live="polite">${esc(opts.buttonNote ?? "")}</span></div>`,
    );
  }
  if (m.footer) out.push(`<footer class="foot">${esc(m.footer)}</footer>`);
  out.push(`</section>`);
  return out.join("");
}

const VERSION_PLACEHOLDER = "__OMITLY_VERSION__";

/** The full page. `bundle` is the view's JS (the ext-apps client plus view-entry.ts);
 *  `version` is replaced at resources/read, see `withVersion`. */
export function pageHtml(bundle: string): string {
  // `</script` inside the bundle would end the element early.
  const safe = bundle.replace(/<\/script/gi, "<\\/script");
  return (
    `<!doctype html><html lang="en"><head><meta charset="utf-8">` +
    `<meta name="viewport" content="width=device-width,initial-scale=1">` +
    `<meta name="color-scheme" content="light dark">` +
    `<meta name="omitly-version" content="${VERSION_PLACEHOLDER}">` +
    `<title>Omitly result</title><style>${CARD_CSS}</style></head>` +
    `<body><div id="root"></div><script>${safe}</script></body></html>`
  );
}

/** Put the server's own version into the page. Only a plain version string is accepted. */
export function withVersion(html: string, version: string): string {
  const v = /^[0-9A-Za-z.+-]{1,64}$/.test(version) ? version : "";
  return html.replace(`content="${VERSION_PLACEHOLDER}"`, () => `content="${v}"`);
}

// ---------------------------------------------------------------------------
// Interaction rules (pure, so the tests can drive them without a DOM)
// ---------------------------------------------------------------------------

/** One "Open in Omitly" call per this many milliseconds. */
export const OPEN_DEBOUNCE_MS = 2000;

/**
 * Whether a click on "Open in Omitly" may call the server. It needs a REAL pointer click
 * (`event.detail > 0`: Space or Enter on a focused button gives 0, and a spike measured 41
 * calls from keystrokes on a focused button) and at most one call per 2 s.
 */
export function mayOpen(detail: number, nowMs: number, lastCallMs: number | null): boolean {
  if (!(detail > 0)) return false;
  return lastCallMs === null || nowMs - lastCallMs >= OPEN_DEBOUNCE_MS;
}

/** The device noun for the footer, from the platform string the view can see. */
export function deviceNounFor(platform: string): "Mac" | "PC" {
  return /mac/i.test(platform) ? "Mac" : "PC";
}

// ---------------------------------------------------------------------------
// View state (a pure reducer, so the tests can drive the transitions without a DOM)
// ---------------------------------------------------------------------------

/** Everything the view keeps for ONE tool call. A host may reuse a single view instance for
 *  several calls, so a new input must start from nothing: the previous call's verdict, section
 *  toggles and "Open" note must never be painted on the new file. */
export interface ViewState {
  toolInput?: ToolInputLike;
  toolResult?: ToolResultLike;
  /** Sections the user opened or closed, by key. */
  overrides: Record<string, boolean>;
  /** The line beside the "Open in Omitly" button. */
  note: string;
  /** Bumped on every new input: an "Open" reply that belongs to an earlier call is ignored. */
  generation: number;
}

export const initialViewState = (): ViewState => ({ overrides: {}, note: "", generation: 0 });

/** A new tool input: drop the previous result and every other per-call field, so the card shows
 *  "Checking…" until the matching result arrives. */
export function onToolInput(s: ViewState, input: ToolInputLike): ViewState {
  return { toolInput: input, toolResult: undefined, overrides: {}, note: "", generation: s.generation + 1 };
}

/** A tool result keeps the input it belongs to, so a result that arrives with no fresh input
 *  still renders. */
export function onToolResult(s: ViewState, result: ToolResultLike): ViewState {
  return { ...s, toolResult: result };
}

export function onToggle(s: ViewState, key: string, open: boolean): ViewState {
  return { ...s, overrides: { ...s.overrides, [key]: open } };
}

/** The reply to an "Open" call: applied only if no newer input has arrived since it was sent. */
export function onOpenReply(s: ViewState, generation: number, note: string): ViewState {
  return generation === s.generation ? { ...s, note } : s;
}

export function modelFor(s: ViewState, ctx: Omit<CardContext, "openOverrides">): CardModel {
  return buildModel(s.toolInput, s.toolResult, { ...ctx, openOverrides: s.overrides });
}
