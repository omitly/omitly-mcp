/**
 * omitly#1857: the result card's copy must not drift from the desktop app's approved copy.
 *
 * `src/check/model.ts` (the Check screen: COPY, SECTIONS, SECTION_ORDER, LOOK_TITLES,
 * LOOK_CLASSES, the time and size formats) is TRANSPILED and executed here, so the comparison
 * is against the real values, not a regex over its text. The seal headlines live in JSX in
 * `src/App.tsx`, which cannot be executed in a test, so each is searched for in its source.
 *
 * Both files exist only in the Cargo workspace. In the standalone omitly-mcp repository there
 * is no desktop source to compare with and the test is skipped; inside the workspace, under CI,
 * a missing file FAILS (the same rule as verdict-parity.test.ts: a parity check that could not
 * run is not a pass).
 */
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import * as path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import {
  COPY,
  LOOK_FAMILY,
  LOOK_TITLES,
  SEAL_COPY,
  SECTIONS,
  SECTION_ORDER,
  formatLocalTime,
  formatSize,
  lookClasses,
} from "./result-card.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const WORKSPACE = path.join(HERE, "..", "..");
const MODEL = path.join(WORKSPACE, "src", "check", "model.ts");
const APP = path.join(WORKSPACE, "src", "App.tsx");
const IN_WORKSPACE = existsSync(path.join(WORKSPACE, "Cargo.toml"));
const skip = !(existsSync(MODEL) && existsSync(APP)) && !(IN_WORKSPACE && process.env.CI)
  ? "no desktop source (src/check/model.ts, src/App.tsx) next to this package"
  : false;

/** Execute the desktop's model.ts. Its one import (`normaliseCheckState`, `../ipc/check`) is
 *  stubbed; nothing in the parts compared here depends on it. */
function loadModel(): any {
  assert.ok(existsSync(MODEL), `${MODEL} is missing: the card cannot be checked against the desktop copy`);
  const out = ts.transpileModule(readFileSync(MODEL, "utf8"), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  const exports: Record<string, unknown> = {};
  const fakeRequire = (id: string) => {
    if (id === "../ipc/check") return { normaliseCheckState: (s: string) => s };
    throw new Error(`unexpected import ${id}`);
  };
  new Function("require", "exports", out)(fakeRequire, exports);
  return exports;
}

test("card copy equals src/check/model.ts: COPY, headlines, sections, order", { skip }, () => {
  const m = loadModel();
  for (const key of ["safe", "needsReviewBlocking", "needsReview", "cannotVerify", "running", "couldNotRun"] as const) {
    assert.equal(COPY[key], m.COPY[key], `COPY.${key}`);
  }
  assert.deepEqual(LOOK_TITLES, m.LOOK_TITLES, "LOOK_TITLES");
  assert.deepEqual(Object.keys(SECTIONS).sort(), Object.keys(m.SECTIONS).sort(), "section keys");
  for (const [key, def] of Object.entries(SECTIONS)) {
    const d = m.SECTIONS[key];
    assert.equal(def.heading, d.heading, `${key} heading`);
    assert.equal(def.marker, d.marker, `${key} marker`);
    // The marker colour family: the desktop's `text-<f>-600 dark:text-<f>-400`.
    const f = def.family === "neutral" ? "neutral" : def.family;
    const light = f === "neutral" ? 500 : 600;
    const dark = f === "neutral" ? 400 : 400;
    assert.equal(d.markerClass, `text-${f}-${light} dark:text-${f}-${dark}`, `${key} marker colour`);
  }
  assert.deepEqual(SECTION_ORDER, m.SECTION_ORDER, "SECTION_ORDER");
});

test("card colours name the same Tailwind families and weights as LOOK_CLASSES", { skip }, () => {
  const m = loadModel();
  for (const look of Object.keys(LOOK_FAMILY) as (keyof typeof LOOK_FAMILY)[]) {
    assert.equal(lookClasses(look), m.LOOK_CLASSES[look], `${look} classes`);
  }
});

test("card time and size formats equal the desktop's", { skip }, () => {
  const m = loadModel();
  for (const d of [new Date(2026, 10, 11, 14, 2), new Date(2026, 0, 3, 9, 5), new Date(2027, 11, 31, 23, 59)]) {
    assert.equal(formatLocalTime(d), m.formatCheckedAt(d.toISOString()));
  }
  for (const n of [0, 1, 1023, 1024, 831_488, 1_048_575, 1_048_576, 3_565_158]) {
    assert.equal(formatSize(n), m.formatSize(n), `size ${n}`);
  }
});

test("the desktop still builds a blocking look's sections the way the card does", { skip }, () => {
  // `sectionsFor` keeps COULD NOT BE CHECKED on a blocking result that has `reasons`, right after
  // REVIEW. The card re-implements it; this fails when the desktop changes the rule.
  const m = loadModel();
  const items = (n: number) => Array.from({ length: n }, () => ({ text: "x" }));
  const base = { problems: items(1), review: items(1), reasons: [], notChecked: items(1), information: [], decisions: [], checked: [] };
  assert.deepEqual(m.sectionsFor(base, "blocking"), SECTION_ORDER.blocking);
  assert.deepEqual(m.sectionsFor({ ...base, reasons: items(1) }, "blocking"), ["problems", "review", "notChecked", "information", "decisions"]);
});

test("seal headlines and lines are the ones App.tsx shows", { skip }, () => {
  assert.ok(existsSync(APP), `${APP} is missing`);
  const app = readFileSync(APP, "utf8");
  const mustContain: string[] = [
    // `SEAL_COPY.intact` ("Seal intact & verified") is gone: no seal result is a pass (contract §3.5). The new held-seal titles are
    // this server's, not the desktop's, so App.tsx does not hold them.
    // v0.2.3: intactNotPassed and unsupportedWithReportLine are worded without the matcher words ("intact", "verified"), so they differ from App.tsx on purpose.
    SEAL_COPY.invalid,
    SEAL_COPY.removed,
    SEAL_COPY.noReport,
    SEAL_COPY.removedLine,
    SEAL_COPY.unsupportedNoReportLine,
    // The two unsupported-version headlines are template literals in the source.
    "Cannot verify — sealed with version ",
    ", which this app can't check",
    "Sealed with version ",
    " — this app can't check it",
  ];
  for (const s of mustContain) assert.ok(app.includes(s), `App.tsx no longer contains: ${s}`);
  // v0.2.1 (errata 3): the desktop app prints the version its own engine read; here the token is the FILE's own string, so the MCP card
  // names no version at all (it stays in structuredContent). The two titles deliberately differ from App.tsx.
  assert.equal(SEAL_COPY.unsupportedWithReport(), "Cannot verify — sealed with a version this app can't check");
  assert.equal(SEAL_COPY.unsupportedNoReport(), "Sealed with a version this app can't check");
});

test("the owner-approved seal lines are exact", () => {
  // Not in the desktop source: written for the card in the omitly#1857 brief.
  assert.equal(
    SEAL_COPY.unchangedLine,
    "Unchanged since it was sealed. A seal shows integrity, not who made the file: compare the key fingerprint with the sender.",
  );
  assert.equal(
    SEAL_COPY.invalidLine,
    "This file was changed after sealing, or its report was never signed. Do not rely on the embedded report.",
  );
  assert.equal(SEAL_COPY.signatureMismatchRow, "Signature does not match the file bytes");
  assert.equal(SEAL_COPY.reportPresentRow, "Embedded report present: its verdict cannot be trusted");
});
