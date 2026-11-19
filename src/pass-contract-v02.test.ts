/**
 * omitly#1864: the conformance tests of docs/pass-contract.md v0.2 (§8.1, T1-T18 that are built tonight). Real goldens are the oracles and the
 * rigs copy REAL fixture bytes into their `doc` (C3: a check's digest is bound to the bytes the server read), through three engines:
 *   - `stub`: a scripted native engine that replies with the captured golden of the fixture (testing/goldens/native.json);
 *   - `wasm`: no native engine at all: the server's bundled wasm answers (the real `check` and `scan`);
 *   - `real`: the built native `omitly-redact` (cargo build -p omitly-cli).
 * Every text a document tool returns goes through the §6.3 matcher, and every structuredContent through the §6.1 walk.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync, copyFileSync, existsSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { assertLead, matcherHits, passShapedPaths } from "./testing/matcher.js";
import { buildModel, renderCardHtml, type CardContext } from "./result-card.js";
import { PRODUCT_NOTICES } from "./seal.js";
import { parseRedactAudit, parseScanReply } from "./replies.js";
import { capped, passOutcome, isFailure, sealCaps, type Issued, WHY } from "./outcome.js";
import { normalizeSealResult } from "./seal.js";
import { checkLegOf, scanLegOf } from "./replies.js";

import { ENGINE, ENV_KEYS, IN_WORKSPACE, WORKSPACE, clone, native, rig, sha256Hex, skipFixtures, skipReal, textOf, type Mode } from "./testing/rig.js";
const HERE = path.dirname(fileURLToPath(import.meta.url));
let counter = 0;
const CTX: CardContext = { version: "5.6.0", deviceNoun: "Mac", now: new Date(2026, 10, 16, 9, 0, 0), canOpen: true };

const cardOf = (res: any, input = "/x/a.pdf") =>
  renderCardHtml(buildModel({ arguments: { pdfPath: input } }, { structuredContent: res.structuredContent, isError: res.isError }, CTX));
const lookOf = (res: any) => /data-look="(\w+)"/.exec(cardOf(res))![1]!;
const OUTCOME_LOOK: Record<string, string> = { safe_to_send: "safe", not_a_pass: "blocking", incomplete: "cannot" };

/** Every `why` string of the contract (§7.1, W0-W17), as a pattern: a count is `\d+`, a label is any text without `;`. */
/** The invariant on every document tool result: the matcher and the structured walk hold, and the card's look follows the outcome. */
function assertConforms(name: string, res: any, opts: { card?: boolean } = { card: true }) {
  const text = textOf(res);
  if (res.isError === true) {
    assert.equal(res.structuredContent, undefined, `${name}: an execution failure has no structured result`);
    assert.deepEqual(matcherHits(text, "failure"), [], `${name}: matcher on a failure text\n${text}`);
    return;
  }
  const outcome = res.structuredContent?.outcome;
  assert.ok(["safe_to_send", "needs_review", "not_a_pass", "incomplete"].includes(outcome), `${name}: outcome ${outcome}\n${text}`);
  assert.deepEqual(matcherHits(text, outcome), [], `${name}: matcher hit in the text\n${text}`);
  assert.deepEqual(passShapedPaths(res.structuredContent, outcome), [], `${name}: a pass-shaped structured value beside ${outcome}`);
  assertLead(name, text, outcome);
  if (opts.card && res.structuredContent?.verdict && typeof res.structuredContent.verdict === "object") {
    const look = lookOf(res);
    const want = outcome === "needs_review" ? (res.structuredContent.totalFindings > 0 ? "visible" : "review") : OUTCOME_LOOK[outcome];
    assert.equal(look, want, `${name}: the card look is a function of the outcome`);
  }
  if (opts.card && res.structuredContent?.seal) assert.equal(lookOf(res), outcome === "needs_review" ? "review" : OUTCOME_LOOK[outcome], `${name}: seal card look`);
}

// ---- the fixtures, with the outcome the contract gives each (T14) --------------------------------------------------------------------------------

interface Fx { rel: string; check: Outcome; }
type Outcome = "safe_to_send" | "needs_review" | "not_a_pass" | "incomplete";
const FIXTURES: Fx[] = [
  { rel: "tests/fixtures/sample.pdf", check: "needs_review" },
  { rel: "tests/fixtures/covered-text.pdf", check: "not_a_pass" },
  { rel: "tests/fixtures/invisible-text.pdf", check: "needs_review" }, // T1
  { rel: "tests/fixtures/encrypted-aes256-survivor.pdf", check: "incomplete" },
  { rel: "tests/fixtures/au-corpus/05-scanned-raster.pdf", check: "needs_review" },
  { rel: "tests/fixtures/au-corpus/07-incremental-update-prior-revision.pdf", check: "needs_review" },
  { rel: "tests/fixtures/au-corpus/08-acroform-fields.pdf", check: "needs_review" },
  { rel: "scripts/fixtures/leakcheck/form-xobject-under-box.pdf", check: "not_a_pass" },
  { rel: "tests/fixtures/clean-text.pdf", check: "safe_to_send" }, // T17
];
const goldenFind = (rel: string) => clone(native.find.find((e: any) => e.pdf === rel && !e.regions).reply);
const goldenCheck = (rel: string) => clone(native.check.find((e: any) => e.pdf === rel).reply);
const expectedFind = (rel: string): Outcome => {
  const f = goldenFind(rel);
  return f.survivors.length > 0 ? "not_a_pass" : f.total_findings > 0 ? "needs_review" : "incomplete";
};

for (const mode of ["stub", "wasm", "real"] as Mode[]) {
  test(`T1/T11/T14/T17 [${mode}]: every fixture through check_redaction, the verify_redaction re-scan and find_sensitive_regions gives the outcome the contract names, and holds the matcher and the walk`, { skip: mode === "real" ? skipReal || skipFixtures : skipFixtures }, async () => {
    for (const fx of FIXTURES) {
      const r = await rig(mode, fx.rel);
      try {
        if (mode === "stub") r.script({ find: goldenFind(fx.rel), check: goldenCheck(fx.rel) });
        const chk = await r.call("check_redaction");
        assertConforms(`${mode} ${fx.rel} check_redaction`, chk);
        assert.equal(chk.structuredContent?.outcome, fx.check, `${mode} ${fx.rel} check_redaction\n${textOf(chk)}`);
        const re = await r.call("verify_redaction");
        assertConforms(`${mode} ${fx.rel} verify_redaction`, re, { card: false });
        assert.equal(re.isError, false, `${fx.rel}: a re-scan is a completed check`);
        assert.equal(re.structuredContent.outcome, fx.check, `${mode} ${fx.rel} re-scan`);
        assert.equal(re.structuredContent.mode, "rescan");
        const fnd = await r.call("find_sensitive_regions");
        assertConforms(`${mode} ${fx.rel} find_sensitive_regions`, fnd, { card: false });
        assert.notEqual(fnd.structuredContent.outcome, "safe_to_send", "a pattern scan is never a pass");
        if (mode === "stub") assert.equal(fnd.structuredContent.outcome, expectedFind(fx.rel), `${fx.rel} find`);
        if (fx.check === "safe_to_send") {
          assert.ok(textOf(chk).includes("✅ Safe to Send"), textOf(chk));
          assert.equal(lookOf(chk), "safe");
          assert.ok(textOf(re).includes("✅ Safe to Send"), "the re-scan runs the same check and reaches the same pass");
        }
      } finally {
        await r.close();
      }
    }
  });
}

test("T14 [stub]: a file over the free check's size limit with a survivor from the scan is not_a_pass (the check refuses it unread: C3's empty digest)", { skip: skipFixtures }, async () => {
  const BIG = "(generated: tests/fixtures/covered-text.pdf plus a 66 MiB unreferenced stream)";
  const r = await rig("stub", null);
  try {
    r.script({ find: clone(native.find.find((e: any) => e.pdf === BIG).reply), check: clone(native.check.find((e: any) => e.pdf === BIG).reply) });
    const res = await r.call("check_redaction");
    assertConforms("big", res);
    assert.equal(res.structuredContent.outcome, "not_a_pass");
    assert.equal(res.structuredContent.verdict.reason_code, null);
  } finally {
    await r.close();
  }
});

// ---- T3: seal tools -------------------------------------------------------------------------------------------------------------------------------

test("T3/T11/T14: every seal golden through verify_seal and verify_document: never a pass; the outcome is the seal table's; the card follows", async () => {
  const EXPECT: Record<string, Outcome> = {
    "positive/clean-sealed.pdf": "incomplete", "positive/seal-at-boundary.pdf": "incomplete", "compat/v3.2.0.pdf": "incomplete", "compat/v5.3.0.pdf": "incomplete",
    "negative/stripped-seal.pdf": "not_a_pass", "negative/tampered-content.pdf": "not_a_pass", "negative/forged-signature.pdf": "not_a_pass", "negative/corrupt-audit-json.pdf": "incomplete",
  };
  const r = await rig("stub", null);
  try {
    for (const e of native.verify_seal) {
      const key = Object.keys(EXPECT).find((k) => e.pdf.endsWith(k)) ?? "(redact output)";
      const want = EXPECT[key] ?? "incomplete";
      r.script({ verify_seal: clone(e.reply) });
      for (const tool of ["verify_seal", "verify_document"]) {
        const res = await r.call(tool);
        assertConforms(`${tool} ${e.pdf}`, res);
        assert.equal(res.isError, false, `${tool} ${e.pdf}`);
        assert.equal(res.structuredContent.outcome, want, `${tool} ${e.pdf}\n${textOf(res)}`);
        assert.equal(res.structuredContent.verdict, undefined, "no top-level verdict field on a seal result");
        if (tool === "verify_document") assert.match(textOf(res), /This does not check the document's content\. Run check_redaction for that\./);
        assert.doesNotMatch(textOf(res), /"verdict"|"sealValid"/, "no JSON dump of the engine's reply");
      }
    }
    // The v2 pass: the file's own report's word is ATTRIBUTED, and the outcome is still not a pass.
    r.script({ verify_seal: clone(native.verify_seal.find((e: any) => e.pdf.endsWith("compat/v5.3.0.pdf")).reply) });
    const v2 = await r.call("verify_seal");
    assert.equal(v2.structuredContent.embeddedReport.userVerdict, "safe_to_send");
    assert.equal(v2.structuredContent.outcome, "incomplete");
    assert.equal(lookOf(v2), "cannot");
    assert.match(textOf(v2), /The file's own report records: nothing to review\./);
    assert.match(textOf(v2), /a key this engine does not report/);
  } finally {
    await r.close();
  }
});

// ---- T5, T6: the sidecar -------------------------------------------------------------------------------------------------------------------------

const verifyGolden = (i: number) => clone(native.verify[i].reply);

test("T5: the real sidecar `verify` over a passing pipeline: (b) only notices -> safe_to_send (the sidecar adds nothing); (a) an engine warning -> needs_review (W7)", { skip: skipFixtures }, async () => {
  const FX = "tests/fixtures/clean-text.pdf";
  const r = await rig("stub", FX);
  try {
    r.sidecar();
    const base = { find: goldenFind(FX), check: goldenCheck(FX) };
    const pass = verifyGolden(0);
    assert.deepEqual(pass.warnings.filter((w: string) => !PRODUCT_NOTICES.includes(w)), [], "the real reply holds only the trial notice");
    r.script({ ...base, verify: pass });
    const b = await r.call("verify_redaction");
    assertConforms("T5b", b, { card: false });
    assert.equal(b.structuredContent.mode, "sidecar");
    assert.equal(b.structuredContent.outcome, "safe_to_send");
    assert.equal(b.structuredContent.sidecar.engineWarnings, 0);
    assert.match(textOf(b), /The sidecar is not evidence/);
    // (a) the engine.rs:1048-1061 wording of an engine warning.
    const warned = verifyGolden(0);
    warned.warnings = [...warned.warnings, "page 1: content that could not be fully analysed; review manually"];
    r.script({ ...base, verify: warned });
    const a = await r.call("verify_redaction");
    assertConforms("T5a", a, { card: false });
    assert.equal(a.structuredContent.outcome, "needs_review");
    assert.match(textOf(a), new RegExp(WHY.W7));
    assert.equal(a.structuredContent.sidecar.engineWarnings, 1);
    assert.equal(a.isError, false);
  } finally {
    await r.close();
  }
});

test("T6: a `[]` sidecar beside real sample.pdf bytes, with the sample verify golden (metadata not scrubbed): needs_review (W1, W10), never safe_to_send", { skip: skipFixtures }, async () => {
  const FX = "tests/fixtures/sample.pdf";
  const r = await rig("stub", FX);
  try {
    r.sidecar();
    const v = verifyGolden(1);
    assert.equal(v.metadataScrubbed, false, "the sample.pdf verify golden has unscrubbed metadata");
    r.script({ find: goldenFind(FX), check: goldenCheck(FX), verify: v });
    const res = await r.call("verify_redaction");
    assertConforms("T6", res, { card: false });
    // CONTRACT-QUESTION: T6 names needs_review (W1, W10), but the sample verify golden also has failing regions, which §3.4 caps at not_a_pass (W9).
    // The fail-safe reading (never more permissive) is not_a_pass; W1 and W10 are both still stated.
    assert.equal(res.structuredContent.outcome, "not_a_pass");
    const t = textOf(res);
    assert.match(t, /sensitive item\(s\) found/);
    assert.match(t, new RegExp(WHY.W10));
    assert.equal(res.structuredContent.sidecar.metadataScrubbed, false);
    // The sidecar's own failing regions never read as a failed redaction of the file; they cap at not_a_pass only through W9.
    assert.equal(res.structuredContent.sidecar.regionsFailed > 0, true);
    assert.doesNotMatch(t, /"verdict"/, "the raw reply is not dumped");
  } finally {
    await r.close();
  }
});

// ---- T7: the disclosure sets ----------------------------------------------------------------------------------------------------------------------

/** The Rust lines (detect.rs 3797, 3869, 3916, 3971, 4024, 4660-4752): `deny` rows beside scan_complete true are row 0 only when the ENGINE sends them
 *  solely beside an incomplete scan (Set 1). */
const SET1 = [
  "1 page(s) are effectively image-only (raster content, fewer than 100 extractable text characters) — this build never OCRs, so any text inside those images was not read",
  "CID/Identity-H text with a code not covered by the ToUnicode map, simple-font text whose declared ToUnicode map could not be read, or simple-font text with a code its encoding does not determine (present in this file)",
  "Type0/CID text using a named encoding whose codespace ranges could not be verified (present in this file)",
  "2 embedded content stream(s) that failed to parse or could not be fully decoded",
  "1 Form XObject(s) showing text in a font set by the page that draws them (that text may be misread)",
  "embedded-file attachment name tree could not be fully scanned",
  "1 page(s) could not be fully checked for text surviving under a redaction mark (the content stream failed to decode) — a redaction on this page is unproven, not confirmed clean",
  "1 prior (superseded) revision(s) could not be scanned for leftover PII (x) — a prior revision left unscanned is unproven, not confirmed clean",
  "the file's structure (object streams, cross-reference data or stream lengths) did not read the same way twice, so some objects may not have been read: object 1 is listed in the cross-reference table but could not be read",
  "AcroForm field tree deeper than 16 levels was not fully scanned",
  "document information, form fields and attachments: the file is encrypted",
  "XMP metadata stream was truncated",
  "XMP metadata stream could not be read as text (invalid UTF-16); only its raw bytes and decoded text were scanned",
  "attachment 'a.txt' was truncated",
];
const NOT_SET1_DENY = [
  "text in font(s) \"F1\" that may be drawn as different characters than the text read (a code's glyph is a digit under a letter, a different digit, or the font's .notdef glyph): not verified as drawn",
  "zzz unknown",
];
const BENIGN = "text drawn as raster images (needs OCR)";

test("T7 [stub]: every §4 row beside both scan_complete values: Set 1 beside true is row 0; the benign line may pass; the 4684 and unknown rows and every deny row beside false are incomplete (needs_review with findings)", { skip: skipFixtures }, async () => {
  const FX = "tests/fixtures/clean-text.pdf";
  const r = await rig("stub", FX);
  try {
    const setup = (line: string, complete: boolean, extra: Record<string, unknown> = {}) => {
      const f = goldenFind(FX);
      f.coverage.not_scanned = [line];
      f.scan_complete = complete;
      f.coverage.scan_complete = complete;
      Object.assign(f, extra);
      r.script({ find: f, check: goldenCheck(FX) });
    };
    for (const line of SET1) {
      setup(line, true);
      const t = await r.call("check_redaction");
      assert.equal(t.isError, true, `Set 1 beside true is row 0: ${line.slice(0, 40)}`);
      assert.equal(t.structuredContent, undefined);
      setup(line, false);
      const f = await r.call("check_redaction");
      assertConforms(`Set 1 beside false ${line.slice(0, 30)}`, f);
      assert.equal(f.structuredContent.outcome, "incomplete", line.slice(0, 40));
      assert.doesNotMatch(textOf(f), /a\.txt|F1|object 1|was truncated|invalid UTF-16/i, "no engine line (it can carry a filename or a font name) reaches the text");
    }
    setup(BENIGN, true);
    const b = await r.call("check_redaction");
    assert.equal(b.structuredContent.outcome, "safe_to_send", "the benign line may sit beside a pass");
    setup(BENIGN, false);
    assert.equal((await r.call("check_redaction")).structuredContent.outcome, "incomplete");
    for (const line of NOT_SET1_DENY) {
      setup(line, true);
      const t = await r.call("check_redaction");
      assertConforms(`beside true ${line.slice(0, 30)}`, t);
      assert.equal(t.isError, false, `${line.slice(0, 30)}: never an execution failure`);
      assert.equal(t.structuredContent.outcome, "incomplete", line.slice(0, 40));
      setup(line, false);
      assert.equal((await r.call("check_redaction")).structuredContent.outcome, "incomplete");
    }
    // A deny line beside findings: needs_review (T7: "or needs_review with findings"). Each is called through the tool and asserted.
    const r2 = await rig("stub", "tests/fixtures/sample.pdf");
    try {
      const cases: [string, boolean][] = [...SET1.map((l) => [l, false] as [string, boolean]), ...NOT_SET1_DENY.flatMap((l) => [[l, true], [l, false]] as [string, boolean][]), [BENIGN, false]];
      for (const [line, complete] of cases) {
        const sample = goldenFind("tests/fixtures/sample.pdf");
        sample.coverage.not_scanned = [line];
        sample.scan_complete = complete;
        sample.coverage.scan_complete = complete;
        r2.script({ find: sample, check: goldenCheck("tests/fixtures/sample.pdf") });
        const w = await r2.call("check_redaction");
        assertConforms(`findings + "${line.slice(0, 30)}" (${complete})`, w);
        assert.equal(w.isError, false, `${line.slice(0, 40)}\n${textOf(w)}`);
        assert.equal(w.structuredContent.outcome, "needs_review", `${line.slice(0, 40)} (${complete})`);
        assert.ok(w.structuredContent.totalFindings > 0, "the findings are listed");
      }
    } finally {
      await r2.close();
    }
  } finally {
    await r.close();
  }
});

// ---- T8: product notices ---------------------------------------------------------------------------------------------------------------------------

test("T8: a notice plus extra text is an engine warning (denied); the exact notices are allowed; the list equals the Rust constants (skipped, logged, without ../crates)", () => {
  const audit = () => clone(native.redact_entities[0].reply.audit);
  for (const notice of PRODUCT_NOTICES) {
    const a = audit();
    a.warnings = [notice];
    const p = parseRedactAudit(a);
    assert.equal(p.ok, true);
    assert.equal(capped(null, (require_auditCaps(p) as any)).outcome, "needs_review");
    assert.ok(!(require_auditCaps(p) as any).some((c: any) => c.why === WHY.W7), `an exact notice is not an engine warning: ${notice.slice(0, 30)}`);
    const extra = audit();
    extra.warnings = [`${notice} extra`];
    assert.ok((require_auditCaps(parseRedactAudit(extra)) as any).some((c: any) => c.why === WHY.W7), "a notice plus extra text is an engine warning");
    const prefix = audit();
    prefix.warnings = [notice.slice(0, 30)];
    assert.ok((require_auditCaps(parseRedactAudit(prefix)) as any).some((c: any) => c.why === WHY.W7), "a prefix of a notice is an engine warning");
  }
  const policy = path.join(WORKSPACE, "crates", "licensing", "src", "policy.rs");
  const license = path.join(WORKSPACE, "crates", "omitly-cli", "src", "license.rs");
  if (!existsSync(policy) || !existsSync(license)) {
    console.log("T8 constants test skipped: ../crates is absent (the public mirror); F9 replaces it with a Rust-emitted fixture");
    return;
  }
  const lit = (file: string, name: string) => {
    const m = new RegExp(`pub const ${name}: &str =\\s*"((?:[^"\\\\]|\\\\.)*)"\\s*;`, "s").exec(readFileSync(file, "utf8"));
    assert.ok(m, `${name} not found in ${file}`);
    // Rust: a backslash-newline continuation drops the newline and the following indentation.
    return m![1]!.replace(/\\\n[ \t]*/g, "");
  };
  assert.deepEqual([...PRODUCT_NOTICES], [lit(policy, "TRIAL_OUTPUT_WARNING"), lit(policy, "PERSONAL_USE_WARNING"), lit(license, "DEV_KEY_WARNING")]);
});

// auditCaps is imported lazily so the table above stays readable.
import { auditCaps } from "./outcome.js";
function require_auditCaps(p: ReturnType<typeof parseRedactAudit>) {
  assert.equal(p.ok, true);
  return auditCaps((p as any).value.audit);
}

// ---- T9: the digest binding ---------------------------------------------------------------------------------------------------------------------

test("T9 [stub]: a check bound to other bytes is row 0; an empty digest with cannot_verify + input_too_large is allowed (incomplete, or not_a_pass with survivors); an empty digest with needs_review is row 0", { skip: skipFixtures }, async () => {
  const FX = "tests/fixtures/clean-text.pdf";
  const r = await rig("stub", FX);
  try {
    const check = goldenCheck(FX);
    const withSha = (sha: string, verdict?: Record<string, unknown>) => {
      const c = clone(check);
      c.check.result.sha256 = sha;
      Object.assign(c.check, verdict ?? {});
      return c;
    };
    const real = sha256Hex(readFileSync(r.doc));
    assert.equal(check.check.result.sha256, real, "the golden's digest is the sha256 of its fixture file");
    r.script({ find: goldenFind(FX), check: withSha(real), noBind: true });
    assert.equal((await r.call("check_redaction")).structuredContent.outcome, "safe_to_send", "positive control");
    r.script({ find: goldenFind(FX), check: withSha(real.slice(0, 63) + (real.endsWith("0") ? "1" : "0")), noBind: true });
    const off = await r.call("check_redaction");
    assert.equal(off.isError, true);
    assert.equal(off.structuredContent, undefined);
    assertConforms("T9 mismatch", off);
    // Empty digest: the refusals.
    const refusal = (code: string) => {
      const c = clone(check);
      c.check = { verdict: "cannot_verify", blocking: false, reason_code: code, result: { ...c.check.result, state: "cannot_verify", summary: "The file is larger than this checker accepts, so it was not read.", sha256: "", checked: [], reasons: [{ text: "The file is larger than this checker accepts, so it was not read." }] } };
      return c;
    };
    for (const code of ["input_too_large", "check_failed"]) {
      r.script({ find: goldenFind(FX), check: refusal(code), noBind: true });
      const x = await r.call("check_redaction");
      assertConforms(`T9 ${code}`, x);
      assert.equal(x.structuredContent.outcome, "incomplete", code);
    }
    const covered = goldenFind("tests/fixtures/covered-text.pdf");
    r.script({ find: covered, check: refusal("input_too_large"), noBind: true });
    assert.equal((await r.call("check_redaction")).structuredContent.outcome, "not_a_pass");
    // Empty digest with a verdict that is not a refusal: row 0.
    const nr = clone(check);
    nr.check = { verdict: "needs_review", blocking: false, reason_code: null, result: { ...nr.check.result, state: "needs_review", sha256: "", review: [{ text: "x" }] } };
    r.script({ find: goldenFind(FX), check: nr, noBind: true });
    const bad = await r.call("check_redaction");
    assert.equal(bad.isError, true);
    assert.equal(bad.structuredContent, undefined);
  } finally {
    await r.close();
  }
});

// ---- T12: the redact tools -------------------------------------------------------------------------------------------------------------------------

test("T12: the redact golden gives needs_review; the redact_entities golden gives needs_review (W11); there is no `Result:` line, no top-level verdict, and no dump of the audit", async () => {
  const request = clone(native.redact[0].regions);
  const r = await rig("stub", null);
  try {
    r.script({ redact: clone(native.redact[0].reply), redact_entities: clone(native.redact_entities[0].reply) });
    const a = await r.call("redact_pdf", { outputPath: r.doc + ".o.pdf", regions: request });
    const b = await r.call("redact_by_entity", { outputPath: r.doc + ".o2.pdf" });
    for (const [tool, res] of [["redact_pdf", a], ["redact_by_entity", b]] as const) {
      assert.equal(res.isError, undefined, `${tool}\n${textOf(res)}`);
      assert.equal(res.structuredContent.outcome, "needs_review", tool);
      assert.equal(res.structuredContent.verdict, undefined, `${tool}: no top-level verdict`);
      assert.ok(res.structuredContent.engineAudit, `${tool}: the engine's record is attributed`);
      assert.equal(res.structuredContent.audit, undefined);
      assert.deepEqual(matcherHits(textOf(res), res.structuredContent.outcome), [], `${tool}\n${textOf(res)}`);
      assertLead(tool, textOf(res), res.structuredContent.outcome);
      assert.deepEqual(passShapedPaths(res.structuredContent, res.structuredContent.outcome), [], tool);
      assert.doesNotMatch(textOf(res), /Result:|Verification:|Audit log:|"auditSchema"/, tool);
      assert.match(textOf(res), /The engine's record of this redaction: /);
      assert.match(textOf(res), /This is not a check of the document: run check_redaction on the output\./);
    }
    assert.match(textOf(a), /items to review/, "the real redact golden is review_required");
    assert.match(textOf(b), /no failed region/, "the redact_entities golden has no failed region");
    // A failure after the write names the written output.
    const bad = clone(native.redact[0].reply);
    bad.audit.regions = [];
    r.script({ redact: bad });
    const f = await r.call("redact_pdf", { outputPath: r.doc + ".o.pdf", regions: request });
    assert.equal(f.isError, true);
    assert.match(textOf(f), /The output was written to .*, but its audit could not be read\. Do not use it until check_redaction has checked it\./);
  } finally {
    await r.close();
  }
});

// ---- T13: proposals ------------------------------------------------------------------------------------------------------------------------------------

test("T13: get_proposal_status labels what the desktop recorded without a verdict reading; the structured field is recordedByDesktop; no matcher hit", async () => {
  const { enqueueProposal } = await import("./desktop.js");
  const root = realpathSync(mkdtempSync(path.join(tmpdir(), "omitly-v02-prop-")));
  const stateDir = realpathSync(mkdtempSync(path.join(tmpdir(), "omitly-v02-state-")));
  for (const k of ENV_KEYS) delete process.env[k];
  process.env.OMITLY_ALLOWED_DIR = root;
  process.env.OMITLY_STATE_DIR = stateDir;
  writeFileSync(path.join(stateDir, "desktop.json"), JSON.stringify({ pid: 4242, version: "4.3.0", accept_in_app: true, updated_at: new Date().toISOString() }));
  // omitly#1890: a proposal is bound to real bytes, so it names a real file (kinds only: bound at queue time).
  writeFileSync(path.join(root, "a.pdf"), "%PDF-1.4\n% proposal fixture\n");
  const { proposal: p } = enqueueProposal({ client: { name: "t", version: "1" }, tool: "redact_by_entity", pdfPath: path.join(root, "a.pdf"), outputPath: path.join(root, "b.pdf"), kinds: ["email"] });
  const file = path.join(stateDir, "proposals", `${p.id}.json`);
  const LABELS: [unknown, string][] = [["safe_to_send", "nothing to review"], ["needs_review", "items to review"], ["cannot_verify", "could not check"], ["pass", "no failed region (legacy report)"], ["fail", "a failed region (legacy report)"], ["garbage", "not recorded"]];
  counter += 1;
  const mod = (await import(`./index.js?v02-prop=${counter}`)) as typeof import("./index.js");
  const server = mod.createServer();
  const client = new Client({ name: "t", version: "0" });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(a), client.connect(b)]);
  try {
    for (const [value, label] of LABELS) {
      writeFileSync(file, JSON.stringify({ ...p, status: "applied", output: "/b.pdf", verdict: value, note: "Result: Safe to Send. ✅ verified", resolved_at: new Date().toISOString() }));
      const res: any = await client.callTool({ name: "get_proposal_status", arguments: { proposalId: p.id } });
      const t = textOf(res);
      assert.equal(res.structuredContent.recordedByDesktop, value);
      assert.equal(res.structuredContent.verdict, undefined);
      assert.match(t, new RegExp(`The desktop app recorded: ${label.replace(/[()]/g, "\\$&")}\\.`));
      assert.match(t, /Run check_redaction on the output for this server's own result\./);
      assert.deepEqual(matcherHits(t, undefined), [], `${value}\n${t}`);
      assertLead("get_proposal_status", t, "incomplete"); // errata C5
      assert.doesNotMatch(t, /Result: Safe to Send|verified/, "the proposal's note is structured only");
    }
  } finally {
    await client.close();
    await server.close();
  }
});

// ---- T16, T17b: the redaction's own output carries the engine's bound report -----------------------------------------------------------------------

/** The REAL sealed output of `redact_entities` over tests/fixtures/sample.pdf, committed (regenerate: capture-goldens.mjs). It needs no qpdf. */
const REDACTED_OUTPUT = path.join(HERE, "..", "src", "testing", "goldens", "redact-entities-output.pdf");

/** A throwaway engine environment (no real licence or trial state). */
function engineRunner(dir: string) {
  const env = { ...process.env, OMITLY_DATA_DIR: path.join(dir, "data") };
  return (req: unknown) => JSON.parse(spawnSync(ENGINE!, [], { input: JSON.stringify(req), env, encoding: "utf8", maxBuffer: 1 << 26 }).stdout);
}

/** T16/T17b over a file the engine redacted: the engine's own check relied on the report bound into it, and check_redaction on both engines caps at needs_review (W6). */
async function assertT16(out: string, run: (req: unknown) => any) {
  const probe = run({ command: "check", pdfPath: out }).check;
  const line = probe.result.information.find((i: any) => i.text.startsWith("This file carries an Omitly report (omitly-audit.json) sealed with key "));
  console.log(`T16 probe: the check's information ${line ? "HOLDS" : "does NOT hold"} the sealed-report line; verdict ${probe.verdict}`);
  const f = run({ command: "find", pdfPath: out });
  console.log(`T17 probe (M7): find over the output lists ${f.total_findings} item(s), off_page ${JSON.stringify(f.off_page.map((x: any) => x.kind))}`);
  assert.ok(line, "the check relied on the file's own bound report (check.rs:753): this is C2b's evidence");
  assert.equal(probe.verdict, "safe_to_send", "the engine itself says Safe to Send over its own output");
  for (const mode of ["real", "wasm"] as Mode[]) {
    const r = await rig(mode, null, { bytes: readFileSync(out) });
    try {
      const res = await r.call("check_redaction");
      assertConforms(`T16 ${mode}`, res);
      assert.equal(res.structuredContent.outcome, "needs_review", `${mode}\n${textOf(res)}`);
      assert.match(textOf(res), new RegExp(WHY.W6.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
      assert.equal(res.structuredContent.verdict.verdict, "needs_review", "the verdict is reconciled with the outcome");
      assert.doesNotMatch(textOf(res), /Safe to Send|says Safe/, "the embedded report's own word is not repeated");
    } finally {
      await r.close();
    }
  }
}

test("T16/T17b [real + wasm]: the check on the committed redact_entities output lists the sealed-report line (printed first, then asserted); check_redaction gives needs_review (W6)", { skip: skipReal || skipFixtures }, async () => {
  const dir = realpathSync(mkdtempSync(path.join(tmpdir(), "omitly-v02-out-")));
  await assertT16(REDACTED_OUTPUT, engineRunner(dir));
});

/** Whether `qpdf` (the redaction engine's sidecar) can run here: a plain Node image does not have it. */
function qpdfRuns(): boolean {
  const r = spawnSync("qpdf", ["--version"], { encoding: "utf8" });
  return r.status === 0;
}

test("T16/T17b live: a fresh redact_entities output gives the same (skips, with its reason, where the qpdf sidecar cannot run)", { skip: skipReal || skipFixtures }, async (t) => {
  if (!qpdfRuns()) return t.skip("qpdf is not on PATH: redact_entities needs its sidecar (the committed output above covers T16/T17b)");
  const dir = realpathSync(mkdtempSync(path.join(tmpdir(), "omitly-v02-live-")));
  const run = engineRunner(dir);
  const out = path.join(dir, "out.pdf");
  const red = run({ command: "redact_entities", pdfPath: path.join(WORKSPACE, "tests/fixtures/sample.pdf"), outputPath: out });
  if (red.ok !== true && /qpdf/i.test(String(red.error))) return t.skip(`the engine reports the qpdf sidecar failure: ${String(red.error).slice(0, 120)}`);
  assert.equal(red.ok, true, String(red.error));
  await assertT16(out, run);
});

// ---- T18: the single issuer -------------------------------------------------------------------------------------------------------------------------

test("T18: only outcome.ts / outcome.js can issue an outcome: no `outcome = \"` / `outcome: \"` literal anywhere else, and every structuredContent outcome is `<x>.outcome`", () => {
  const { readdirSync } = require_fs();
  const scan = (dir: string, ext: string, skip: string[]) =>
    readdirSync(dir)
      .filter((f: string) => f.endsWith(ext) && !f.endsWith(`.test${ext}`) && !skip.includes(f))
      .map((f: string) => path.join(dir, f));
  const files = [
    ...scan(path.join(HERE, "..", "src"), ".ts", ["outcome.ts"]),
    ...scan(path.join(HERE, "..", "mcpb", "server"), ".js", ["outcome.js"]),
    path.join(HERE, "..", "mirror-overlay", "mcpb", "server", "index.js"),
  ];
  assert.ok(files.length > 10);
  const bad: string[] = [];
  for (const f of files) {
    const src = readFileSync(f, "utf8");
    // The literal assignment forms, and the structured property forms that are not `<x>.outcome` / a schema / a type.
    for (const m of src.matchAll(/\boutcome(?:\s*=\s*|\s*:\s*)"(safe_to_send|needs_review|not_a_pass|incomplete)"/g)) bad.push(`${path.basename(f)}: ${m[0]}`);
    for (const m of src.matchAll(/structuredContent\s*(?::|=)\s*\{[^}]*\boutcome\s*:\s*([^,}\s][^,}]*)/g)) if (!/^[A-Za-z_$][\w$.]*\.outcome\b/.test(m[1]!.trim())) bad.push(`${path.basename(f)}: structuredContent outcome ${m[1]}`);
  }
  assert.deepEqual(bad, []);
});
import * as fs from "node:fs";
function require_fs() {
  return fs;
}

// ---- unit: the issuer over the goldens (the same table as the real-engine goldens test, through passOutcome directly) ------------------------------------

test("a seal outcome is never safe_to_send for any golden (belt and braces for T3)", () => {
  for (const e of native.verify_seal) assert.notEqual(capped(null, sealCaps(normalizeSealResult(e.reply))).outcome, "safe_to_send", e.pdf);
  assert.equal(typeof passOutcome, "function");
  const f = goldenFind("tests/fixtures/clean-text.pdf");
  const parsed = parseScanReply(f, { engine: "native" });
  assert.equal(parsed.ok, true);
  const out = passOutcome({ check: checkLegOf(goldenCheck("tests/fixtures/clean-text.pdf").check), scan: scanLegOf((parsed as any).value, "native"), snapshotSha256: goldenCheck("tests/fixtures/clean-text.pdf").check.result.sha256 });
  assert.equal(isFailure(out), false);
  assert.equal((out as Issued).outcome, "safe_to_send");
});
