/**
 * omitly#1857: the MCP Apps result card, rendered against fixtures.
 *
 * jsdom is not a dependency of this package, so the card is built to be tested without a
 * DOM: `buildModel` + `renderCardHtml` are the same pure functions the view bundle runs, and
 * here they are rendered to strings. What the tests pin:
 *   - one fixture per check verdict and one per seal verdict;
 *   - the card never shows `regions`, `survivors`, `offPage` or `findings` (a canary value
 *     placed in each must not reach the HTML);
 *   - a green look needs a held seal, over every verdict a seal result can carry;
 *   - the bundled page is self-contained (no external script, style, font or request URL);
 *   - the "Open in Omitly" click rules (a real pointer click, one call per 2 s).
 */
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import * as path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import {
  CARD_CSS,
  OPEN_DEBOUNCE_MS,
  SEAL_COPY,
  baseName,
  blend,
  buildModel,
  deviceNounFor,
  esc,
  initialViewState,
  modelFor,
  onOpenReply,
  onToggle,
  onToolInput,
  onToolResult,
  formatLocalTime,
  formatSize,
  mayOpen,
  renderCardHtml,
  sealLook,
  shortEnds,
  type CardContext,
} from "./result-card.js";
import { SEAL_ERA_V1_LABEL } from "./seal.js";

const CTX: CardContext = {
  version: "5.5.0",
  deviceNoun: "Mac",
  now: new Date(2026, 10, 11, 14, 2, 0),
  canOpen: true,
};
/** `checkedAt` in the fixtures is 06:02 UTC; the card shows it in LOCAL time, so the expected text is
 *  computed, not hardcoded: these tests must pass in every time zone (CI runs in UTC). The formatter
 *  itself is pinned against local `Date`s in "formatting helpers". */
const CHECKED_AT = formatLocalTime("2026-11-11T06:02:00Z");
const PDF = "/Users/someone/Documents/Statement 2026.pdf";
const CANARY = "CANARY-MASKED-PREVIEW";
const SHA = "a1b2c3d4" + "0".repeat(48) + "e5f6a7b8";

const items = (...texts: string[]) => texts.map((text) => ({ text }));

/** A check_redaction structuredContent, with the v1 scan fields the card must ignore. */
function checkSC(
  verdict: "safe_to_send" | "needs_review" | "cannot_verify",
  blocking: boolean,
  r: Partial<Record<string, unknown>> = {},
  result: Record<string, unknown> | null | "default" = "default",
  /** The v1 scan part of the result. Default: a clean scan (omitly#1864: a card reads the kinds and
   *  pages of what the scan found, so a fixture that is not about findings lists none). */
  scan: Record<string, unknown> = {},
) {
  const base = {
    state: verdict,
    blocking,
    summary: "Fixed summary line from the engine.",
    pagesTotal: 14,
    pagesRead: 14,
    checked: [],
    notChecked: [],
    problems: [],
    review: [],
    information: [],
    decisions: [],
    reasons: [],
    checkedAt: "2026-11-11T06:02:00Z",
    omitlyVersion: "5.5.0",
    sha256: SHA,
    sizeBytes: 831_488,
    decisionChannel: "none",
    ...r,
  };
  return {
    scanComplete: true,
    clean: true,
    totalFindings: 0,
    byKind: {},
    regions: [],
    survivors: [],
    offPage: [],
    coverage: { pagesScanned: 1, pagesTotal: 1, notScanned: [], priorRevisionsScanned: true, metadataScanned: true, acroformScanned: true, attachmentsScanned: true, formXobjectsScanned: 0, annotationAppearancesScanned: 0, pagesFailedCount: 0 },
    verdict: { verdict, blocking, result: result === "default" ? base : result, reason_code: null },
    // Contract §3.8: the look is a function of `outcome`; the server issues it. A fixture's outcome is what its verdict and scan give.
    outcome:
      (scan.survivors as unknown[] | undefined)?.length || blocking
        ? "not_a_pass"
        : scan.clean === false || (scan.totalFindings as number | undefined)
          ? "needs_review"
          : verdict === "safe_to_send"
            ? "safe_to_send"
            : verdict === "needs_review"
              ? "needs_review"
              : "incomplete",
    ...scan,
  };
}

const input = { arguments: { pdfPath: PDF } };
const render = (sc: unknown, ctx: CardContext = CTX, pdf: unknown = input) =>
  renderCardHtml(buildModel(pdf as any, { structuredContent: sc }, ctx));

/** Headings in the order they appear. */
const headings = (html: string) => [...html.matchAll(/<span>([^<]*)<\/span><span class="cnt/g)].map((m) => m[1]);
const expanded = (html: string, key: string) =>
  new RegExp(`data-toggle="${key}" aria-expanded="(true|false)"`).exec(html)?.[1];

// ---------------------------------------------------------------------------
// Check fixtures
// ---------------------------------------------------------------------------

test("check card: Safe to Send is green, opens What was checked, collapses the rest", () => {
  const html = render(
    checkSC("safe_to_send", false, {
      checked: items("Text under boxes", "Metadata"),
      notChecked: items("Scanned pages are not read"),
      information: items("Producer: Acrobat"),
    }),
  );
  assert.match(html, /data-look="safe"/);
  assert.match(html, /<h3>Safe to Send<\/h3><p>Fixed summary line from the engine\.<\/p>/);
  assert.deepEqual(headings(html), ["WHAT WAS CHECKED", "COULD NOT BE CHECKED", "INFORMATION (does not affect the result)"]);
  assert.equal(expanded(html, "checked"), "true");
  assert.equal(expanded(html, "notChecked"), "false");
  assert.equal(expanded(html, "information"), "false");
  // A section with nothing in it is not drawn; counts are shown.
  assert.doesNotMatch(html, /DECISIONS RECORDED/);
  assert.match(html, /WHAT WAS CHECKED<\/span><span class="cnt c-green">2</);
  assert.match(html, /<ul class="rows" id="sec-notChecked" hidden>/);
  // Header, meta and footer.
  assert.match(html, /<span class="brand">Omitly<\/span><span class="kind"> · Check<\/span>/);
  assert.match(html, /Statement 2026\.pdf · 14 pages · 812 KB/);
  assert.ok(html.includes(`Checked on this Mac by Omitly 5.5.0 · ${CHECKED_AT} · sha256 a1b2…a7b8`), CHECKED_AT);
  assert.match(html, />Open in Omitly<\/button>/);
});

test("check card: Needs Review with problems is red, opens Problems and Review, says 'to fix'", () => {
  const html = render(
    checkSC("needs_review", true, {
      problems: items("Text under a box on page 3"),
      review: items("A comment on page 2"),
      information: items("Layers: 2"),
      checked: items("This is hidden by the blocking order"),
    }),
  );
  assert.match(html, /data-look="blocking"/);
  assert.match(html, /<h3>Needs Review — problems found<\/h3>/);
  assert.deepEqual(headings(html), ["PROBLEMS FOUND", "REVIEW", "INFORMATION (does not affect the result)"]);
  assert.equal(expanded(html, "problems"), "true");
  assert.equal(expanded(html, "review"), "true");
  assert.equal(expanded(html, "information"), "false");
  assert.doesNotMatch(html, /WHAT WAS CHECKED/);
  assert.match(html, />Open in Omitly to fix<\/button>/);
  assert.match(html, /role="img" aria-label="problem">✗/);
});

test("check card: a blocking result with could-not-check findings keeps COULD NOT BE CHECKED", () => {
  const html = render(
    checkSC("needs_review", true, { problems: items("p"), review: items("r"), reasons: items("A page could not be read"), notChecked: items("n") }),
  );
  assert.deepEqual(headings(html), ["PROBLEMS FOUND", "REVIEW", "COULD NOT BE CHECKED"]);
});

test("check card: Needs Review without a problem is amber, everything starts collapsed", () => {
  const html = render(checkSC("needs_review", false, { review: items("Alt text present"), checked: items("Metadata") }));
  assert.match(html, /data-look="review"/);
  assert.match(html, /<h3>Needs Review<\/h3>/);
  assert.deepEqual(headings(html), ["REVIEW", "WHAT WAS CHECKED"]);
  assert.equal(expanded(html, "review"), "false");
  assert.equal(expanded(html, "checked"), "false");
  assert.match(html, />Open in Omitly<\/button>/);
});

test("check card: Cannot Verify is blue and opens WHY", () => {
  const html = render(checkSC("cannot_verify", false, { reasons: items("The file is encrypted"), checked: items("x") }));
  assert.match(html, /data-look="cannot"/);
  assert.match(html, /<h3>Cannot Verify<\/h3>/);
  assert.deepEqual(headings(html), ["WHY", "WHAT WAS CHECKED"]);
  assert.equal(expanded(html, "reasons"), "true");
  assert.equal(expanded(html, "checked"), "false");
});

test("check card: a refusal with no result is Cannot Verify with the desktop's 'Check could not run'", () => {
  const html = render(checkSC("cannot_verify", false, {}, null));
  assert.match(html, /data-look="cannot"/);
  assert.match(html, /<h3>Cannot Verify<\/h3><p>Check could not run<\/p>/);
  assert.doesNotMatch(html, /class="foot"/);
  assert.doesNotMatch(html, /sec-/);
});

test("check card: parts whose data is missing are omitted", () => {
  // (A result that is not a pass: a Safe to Send without its digest and page counts is not drawn at all, omitly#1864.)
  const html = render(checkSC("needs_review", false, { review: items("a"), pagesTotal: 0, sizeBytes: 0, sha256: "" }), CTX, {});
  assert.doesNotMatch(html, /class="meta"/);
  assert.ok(html.includes(`Checked on this Mac by Omitly 5.5.0 · ${CHECKED_AT}</footer>`), CHECKED_AT);
  const one = render(checkSC("safe_to_send", false, { checked: items("a"), pagesTotal: 1, pagesRead: 1, sizeBytes: 12 }));
  assert.match(one, /Statement 2026\.pdf · 1 page · 12 B/);
});

test("check card: never shows a preview or the `findings` field, whatever the verdict", () => {
  const f = { page: 0, x: 1, y: 2, width: 3, height: 4, kind: "ssn", preview: CANARY };
  const scan = {
    clean: false,
    totalFindings: 3,
    byKind: { ssn: 2, email: 1 },
    regions: [f],
    survivors: [f],
    offPage: [{ source: "metadata", kind: "email", preview: CANARY }],
    findings: [{ preview: CANARY }],
  };
  for (const sc of [
    checkSC("needs_review", true, { problems: items("Text under a box on page 3") }, "default", scan),
    checkSC("needs_review", false, { review: items("x") }, "default", scan),
    checkSC("safe_to_send", false, { checked: items("a") }, "default", scan),
    checkSC("safe_to_send", false, { checked: items("a") }),
  ]) {
    const html = render(sc);
    assert.ok(!html.includes(CANARY), "a preview from regions/survivors/offPage/findings reached the card");
    assert.ok(!/regions|survivors|offPage|findings/i.test(html), "the card names a field it must not read");
  }
});

test("check card: no Open button off macOS, or without a path", () => {
  const sc = checkSC("safe_to_send", false, { checked: items("a") });
  assert.doesNotMatch(render(sc, { ...CTX, canOpen: false }), /data-action="open"/);
  assert.doesNotMatch(render(sc, CTX, {}), /data-action="open"/);
  // The device noun follows the platform, as on the desktop's status bar.
  assert.match(render(sc, { ...CTX, deviceNoun: "PC" }), /Checked on this PC by/);
  assert.equal(deviceNounFor("MacIntel"), "Mac");
  assert.equal(deviceNounFor("Win32"), "PC");
});

test("card: a file name and every line is escaped", () => {
  const evil = "/x/<img src=x onerror=alert(1)>.pdf";
  const html = render(checkSC("needs_review", true, { problems: items(`<script>alert(1)</script>`) }), CTX, { arguments: { pdfPath: evil } });
  assert.ok(!html.includes("<img"), html);
  assert.ok(!html.includes("<script>alert"), html);
  assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;\.pdf/);
  assert.equal(esc(`a&b<c>"d'`), "a&amp;b&lt;c&gt;&quot;d&#39;");
});

test("card: before a result arrives it shows 'Checking…'; an unknown result shows 'Check could not run'", () => {
  const pending = renderCardHtml(buildModel(input as any, undefined, CTX));
  assert.match(pending, /data-look="running"/);
  assert.match(pending, /<h3>Checking…<\/h3>/);
  assert.match(pending, /Statement 2026\.pdf/);
  assert.doesNotMatch(pending, /data-action="open"/);
  for (const sc of [undefined, null, {}, { verdict: {} }, { foo: 1 }, "x"]) {
    const html = render(sc);
    assert.match(html, /data-look="error"/, JSON.stringify(sc));
    assert.match(html, /<h3>Check could not run<\/h3>/);
  }
});

test("card: a malformed check result never renders a verdict it was not given", () => {
  const sc: any = checkSC("safe_to_send", false, { checked: items("a") });
  sc.verdict.verdict = "mostly_fine";
  assert.match(render(sc), /data-look="error"/);
  const sc2: any = checkSC("safe_to_send", false, {});
  sc2.verdict.blocking = "no";
  assert.match(render(sc2), /data-look="error"/);
});

// ---------------------------------------------------------------------------
// Seal fixtures (contract §6.1, §3.8): `outcome` (never safe_to_send), `seal`, `embeddedReport`
// ---------------------------------------------------------------------------

const FP = "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12";

/** A verify_seal structuredContent. Defaults: a held v1 seal over a legacy report (S8: `incomplete`). */
function sealSC(over: Record<string, unknown> = {}, report: Record<string, unknown> | null | "default" = "default", seal: Record<string, unknown> = {}) {
  return {
    outcome: "incomplete",
    seal: { state: "held", version: null, eraLabel: SEAL_ERA_V1_LABEL, fingerprint: FP, keyKind: null, ...seal },
    embeddedReport:
      report === "default"
        ? {
            verifierVerdict: "verified", sealValid: true, carriesAuditReport: null, allPassed: true, metadataScrubbed: true, decisionChannel: null, regionCount: null, pageCount: 9,
            warnings: [], licenseProvenance: null, inputSha256: null, outputSha256: null, sourceFilename: null, outputFilename: null, auditV2Overall: null, userVerdict: null, blocking: null,
          }
        : report,
    ...over,
  };
}
const look = (sc: unknown) => /data-look="(\w+)"/.exec(render(sc))![1];
const noGreen = (html: string) => assert.doesNotMatch(html, /data-look="safe"|class="[^"]*green|Safe to Send|Seal intact & verified/);

test("seal card: the look is a function of `outcome` alone, and no outcome a seal tool issues is green", () => {
  const cases: [string, Record<string, unknown>, string][] = [
    ["incomplete (S8, a held seal)", sealSC(), "cannot"],
    ["needs_review (S5-S7)", sealSC({ outcome: "needs_review" }), "review"],
    ["not_a_pass (S3/S4, a held seal over a failed report)", sealSC({ outcome: "not_a_pass" }), "blocking"],
    ["not_a_pass (S2 invalid)", sealSC({ outcome: "not_a_pass" }, "default", { state: "invalid" }), "blocking"],
    ["not_a_pass (S1 removed)", sealSC({ outcome: "not_a_pass" }, "default", { state: "removed" }), "blocking"],
    ["incomplete, no report", sealSC({}, null, { state: "none" }), "cannot"],
    ["incomplete, unsupported version", sealSC({}, { ...(sealSC().embeddedReport as object), carriesAuditReport: true }, { state: "unsupported", version: "9" }), "cannot"],
  ];
  for (const [label, sc, want] of cases) {
    assert.equal(look(sc), want, label);
    noGreen(render(sc));
  }
  // `safe_to_send` is refused for a seal (contract §3.5): the error state, never green. Missing or unknown outcome: error.
  for (const outcome of ["safe_to_send", undefined, "fine", null]) assert.equal(look(sealSC({ outcome })), "error", String(outcome));
  assert.equal(look(sealSC({ seal: { state: "fine" } })), "error");
  // The same result handed an error flag is the error state.
  assert.match(renderCardHtml(buildModel(input, { structuredContent: sealSC(), isError: true }, CTX)), /data-look="error"/);
});

test("seal card: titles name the seal state; rows are red (failed) or blue information, never green", () => {
  const titleOf = (sc: unknown) => /<h3>([^<]*)<\/h3>/.exec(render(sc))![1];
  assert.equal(titleOf(sealSC()), SEAL_COPY.heldNotACheck);
  assert.equal(titleOf(sealSC({ outcome: "needs_review" })), SEAL_COPY.heldReview);
  assert.equal(titleOf(sealSC({ outcome: "not_a_pass" })), SEAL_COPY.intactNotPassed);
  assert.equal(titleOf(sealSC({ outcome: "not_a_pass" }, "default", { state: "invalid" })), SEAL_COPY.invalid);
  assert.equal(titleOf(sealSC({ outcome: "not_a_pass" }, "default", { state: "removed" })), SEAL_COPY.removed);
  assert.equal(titleOf(sealSC({}, null, { state: "none" })), SEAL_COPY.noReport);
  const held = render(sealSC());
  assert.match(held, /Seal v1 · Ed25519/);
  assert.match(held, /Key fingerprint ab12…ab12/);
  assert.match(held, /Seal format: classical-era seal \(v1\)/);
  assert.doesNotMatch(held, /✓/, "no check mark");
  const noFp = render(sealSC({}, "default", { fingerprint: null }));
  assert.match(noFp, /a key this engine does not report/);
  const v2 = render(sealSC({}, { ...(sealSC().embeddedReport as object), verifierVerdict: "unsupported_schema", userVerdict: "safe_to_send", auditV2Overall: "pass", blocking: false }, { eraLabel: null, keyKind: "one_time" }));
  assert.match(v2, /Seal v2 · ML-DSA-87 with ECDSA P-384/);
  assert.match(v2, /The file(?:'|&#39;)s own report records: nothing to review/);
  assert.doesNotMatch(v2, /Safe to Send/);
});

test("seal card: never reads or shows the report's own strings", () => {
  const sc = sealSC({}, { ...(sealSC().embeddedReport as object), warnings: [CANARY], sourceFilename: CANARY, outputFilename: CANARY, licenseProvenance: { valid: true, licenseId: CANARY, licensedTo: CANARY, product: CANARY, reason: CANARY } });
  assert.doesNotMatch(render(sc), new RegExp(CANARY));
});

test("formatting helpers", () => {
  assert.equal(formatLocalTime(new Date(2026, 10, 11, 14, 2)), "11 Nov 2026 14:02");
  assert.equal(formatLocalTime(new Date(2026, 0, 3, 9, 5)), "3 Jan 2026 09:05");
  assert.equal(formatLocalTime("not a time"), "not a time");
  assert.equal(formatSize(900), "900 B");
  assert.equal(formatSize(831_488), "812 KB");
  assert.equal(formatSize(3_565_158), "3.4 MB");
  assert.equal(shortEnds("0123456789abcdef"), "0123…cdef");
  assert.equal(shortEnds("abcd"), "abcd");
  assert.equal(baseName("/a/b/c.pdf"), "c.pdf");
  assert.equal(baseName("C:\\Users\\x\\d.pdf"), "d.pdf");
  assert.equal(baseName(""), "");
});

test("colours: the brief's light and dark values", () => {
  // Dark green banner background is Tailwind green-950 at 40% over the dark card, #102017.
  assert.equal(blend("#052e16", "#171717", 0.4), "#102017");
  for (const needle of [
    "--safe-bg:#f0fdf4;--safe-bd:#bbf7d0;--safe-tx:#166534;",
    "--safe-bg:#102017;--safe-bd:#14532d;--safe-tx:#bbf7d0;",
    "--blocking-bg:#fef2f2;--blocking-bd:#fecaca;--blocking-tx:#991b1b;",
    "--cannot-bg:#eff6ff;--cannot-bd:#bfdbfe;--cannot-tx:#1e40af;",
    "--review-bg:#fffbeb;--review-bd:#fde68a;--review-tx:#92400e;",
    "--card-bg:#ffffff;--card-bd:#e5e5e5;",
    "--card-bg:#171717;--card-bd:#262626;",
    "--m-green:#16a34a;--m-red:#dc2626;--m-amber:#d97706;--m-blue:#2563eb;--m-neutral:#737373;",
  ])
    assert.ok(CARD_CSS.includes(needle), `missing ${needle}`);
  assert.match(CARD_CSS, /font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif/);
  // Theme: the host's choice wins, the OS preference is the fallback.
  assert.match(CARD_CSS, /@media \(prefers-color-scheme:dark\)\{:root:not\(\[data-theme=light\]\)/);
  assert.match(CARD_CSS, /:root\[data-theme=dark\]\{/);
});

test("Open in Omitly needs a real pointer click and one call per 2 s", () => {
  assert.equal(OPEN_DEBOUNCE_MS, 2000);
  // Space or Enter on a focused button is a click with detail 0.
  assert.equal(mayOpen(0, 10_000, null), false);
  assert.equal(mayOpen(-1, 10_000, null), false);
  assert.equal(mayOpen(1, 10_000, null), true);
  assert.equal(mayOpen(2, 10_000, 9_000), false, "within 2 s");
  assert.equal(mayOpen(1, 11_999, 10_000), false);
  assert.equal(mayOpen(1, 12_000, 10_000), true);
  // A burst of keystrokes (detail 0) never calls, whatever the clock says.
  let calls = 0;
  let last: number | null = null;
  for (let i = 0; i < 41; i++) if (mayOpen(0, i * 5000, last)) calls += 1;
  assert.equal(calls, 0);
  // A burst of real clicks within a second calls once.
  for (let i = 0; i < 20; i++) {
    const now = 50_000 + i * 40;
    if (mayOpen(1, now, last)) {
      calls += 1;
      last = now;
    }
  }
  assert.equal(calls, 1);
});

// ---------------------------------------------------------------------------
// The built page
// ---------------------------------------------------------------------------

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PAGE = path.join(HERE, "result-card.html");

test("the built page is one self-contained string: no external script, style, font or request", () => {
  assert.ok(existsSync(PAGE), "dist/result-card.html is missing: run `npm run build:view`");
  const html = readFileSync(PAGE, "utf8");
  assert.match(html, /^<!doctype html>/);
  // Exactly one script element, inline.
  const scripts = html.match(/<script\b[^>]*>/g) ?? [];
  assert.deepEqual(scripts, ["<script>"]);
  // Everything outside that script (markup + CSS) names no URL at all.
  const markup = html.replace(/<script>[\s\S]*<\/script>/, "");
  assert.ok(!/https?:\/\//i.test(markup), "a URL in the markup or CSS");
  for (const forbidden of [/<link\b/i, /@import/i, /@font-face/i, /url\(/i, /<img\b/i, /<iframe\b/i, /<object\b/i, /<embed\b/i, /\ssrc=/i, /\shref=/i, /<base\b/i]) {
    assert.ok(!forbidden.test(markup), `forbidden in markup: ${forbidden}`);
  }
  // The script loads nothing: no import of a URL, no remote Worker or importScripts.
  const js = html.slice(html.indexOf("<script>"));
  assert.ok(!/import\(\s*["'`]https?:/i.test(js), "dynamic import of a URL");
  assert.ok(!/importScripts\(/.test(js), "importScripts");
  assert.ok(!/new Worker\(/.test(js), "new Worker");
  assert.ok(!/\bfetch\(\s*["'`]https?:/i.test(js), "fetch of a URL");
  // The server's version placeholder is still there to be filled at resources/read.
  assert.match(html, /<meta name="omitly-version" content="__OMITLY_VERSION__">/);
  // The ext-apps client is bundled in, not imported.
  assert.ok(js.includes("ui/initialize"), "the ext-apps App client is not in the bundle");
  assert.ok(html.length < 4 * 1024 * 1024, `page is ${html.length} bytes`);
});

// ---------------------------------------------------------------------------
// A host may reuse one view instance for several calls
// ---------------------------------------------------------------------------

test("a new tool input drops the previous call's verdict, toggles and note until its own result arrives", () => {
  const A = { arguments: { pdfPath: "/docs/A-statement.pdf" } };
  const B = { arguments: { pdfPath: "/docs/B-invoice.pdf" } };
  const resA = { structuredContent: checkSC("needs_review", true, { problems: items("Problem only in A"), information: items("Info only in A") }) };
  const resB = { structuredContent: checkSC("safe_to_send", false, { checked: items("Checked only in B") }) };
  const draw = (s: ReturnType<typeof initialViewState>) => renderCardHtml(modelFor(s, CTX), { buttonNote: s.note });

  let s = onToolInput(initialViewState(), A);
  s = onToolResult(s, resA);
  s = onToggle(s, "information", true);
  s = { ...s, note: "Could not open Omitly." };
  const a = draw(s);
  assert.match(a, /data-look="blocking"/);
  assert.match(a, /A-statement\.pdf/);
  assert.equal(expanded(a, "information"), "true");
  assert.match(a, /data-action="open"/);
  assert.match(a, /Could not open Omitly\./);

  // Input B arrives; B's result has not yet.
  s = onToolInput(s, B);
  const pending = draw(s);
  assert.match(pending, /data-look="running"/, pending);
  assert.match(pending, /<h3>Checking…<\/h3>/);
  assert.match(pending, /B-invoice\.pdf/);
  assert.ok(!/A-statement|Problem only in A|Info only in A|Could not open|data-look="(blocking|safe|review|cannot)"|data-action="open"|sec-/.test(pending), pending);
  assert.deepEqual(s.overrides, {});
  assert.equal(s.note, "");
  assert.equal(s.toolResult, undefined);

  // Then B's result renders B, with B's default sections (A's toggle is gone).
  s = onToolResult(s, resB);
  const b = draw(s);
  assert.match(b, /data-look="safe"/);
  assert.match(b, /B-invoice\.pdf/);
  assert.ok(b.includes("Checked only in B"));
  assert.ok(!/Problem only in A|A-statement/.test(b));
  assert.match(b, /data-action="open"/);
});

test("a result that arrives with no fresh input keeps the input it belongs to", () => {
  let s = onToolInput(initialViewState(), input);
  s = onToolResult(s, { structuredContent: checkSC("safe_to_send", false, { checked: items("a") }) });
  const before = renderCardHtml(modelFor(s, CTX));
  // A second result for the same call (no new input): still drawn, still for the same file.
  s = onToolResult(s, { structuredContent: checkSC("needs_review", false, { review: items("r") }) });
  const after = renderCardHtml(modelFor(s, CTX));
  assert.match(before, /Statement 2026\.pdf/);
  assert.match(after, /Statement 2026\.pdf/);
  assert.match(after, /data-look="review"/);
  // A result before any input renders without a file name rather than failing.
  assert.match(renderCardHtml(modelFor(onToolResult(initialViewState(), { structuredContent: checkSC("safe_to_send", false, { checked: items("a") }) }), CTX)), /data-look="safe"/);
});

test("an Open reply that belongs to an earlier call is ignored", () => {
  let s = onToolInput(initialViewState(), input);
  const gen = s.generation;
  s = onToolInput(s, { arguments: { pdfPath: "/docs/B.pdf" } });
  assert.equal(onOpenReply(s, gen, "Could not open Omitly.").note, "");
  assert.equal(onOpenReply(s, s.generation, "Could not open Omitly.").note, "Could not open Omitly.");
});
