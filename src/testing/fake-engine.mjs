#!/usr/bin/env node
/**
 * A stand-in for `omitly-redact`/`omitly-pdf` (crates/omitly-cli), used ONLY by
 * `leak-canary.test.ts`. Speaks the exact same stdin-JSON/stdout-JSON contract
 * `spawnEngine` in index.ts drives (see that file's module doc), so it can be
 * pointed at via OMITLY_REDACT_BIN / OMITLY_PDF_BIN to exercise every one of
 * the 9 MCP tools end-to-end WITHOUT a Rust toolchain — this repo's real
 * `redaction-core` engine correctness is covered by its own Rust test suite;
 * this double exists only to prove the MCP layer's schemas + masking hold.
 *
 * "Documents" here are plain UTF-8 text files (confineInput/confineOutput
 * don't care about PDF structure), and "detection" is a literal substring
 * search for a small set of canary values — good enough to prove the MCP
 * server never puts a raw canary string into a tool response, which is the
 * thing this fixture is for.
 */
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

/** Mirrors the shape (not the exact algorithm) of `mask_preview` in
 *  crates/redaction-core: keeps a short prefix/suffix, masks the interior, and
 *  — critically — never reproduces the input verbatim. */
function maskPreview(s) {
  if (s.length <= 4) return "•".repeat(s.length);
  const head = s.slice(0, 2);
  const tail = s.slice(-2);
  return `${head}${"•".repeat(Math.max(1, s.length - 4))}${tail}`;
}

const PII_KINDS = [
  { kind: "email", envVar: "FAKE_ENGINE_CANARY_EMAIL" },
  { kind: "ssn", envVar: "FAKE_ENGINE_CANARY_SSN" },
  { kind: "phone", envVar: "FAKE_ENGINE_CANARY_PHONE" },
];

function findCandidates(content) {
  const out = [];
  for (const { kind, envVar } of PII_KINDS) {
    const needle = process.env[envVar];
    if (!needle) continue;
    const at = content.indexOf(needle);
    if (at === -1) continue;
    out.push({
      page: 0,
      x: 10 + out.length * 5,
      y: 700 - out.length * 20,
      width: Math.max(20, needle.length * 4),
      height: 12,
      kind,
      text: needle,
    });
  }
  return out;
}

function auditEntryFor(c, i) {
  return {
    page: c.page,
    bbox: { x: c.x, y: c.y, width: c.width, height: c.height },
    timestamp: new Date(0).toISOString(),
    reason_code: `PII.${c.kind.toUpperCase()}`,
    verification: { result: "pass" },
  };
}

function stripCanaries(content) {
  let out = content;
  for (const { envVar } of PII_KINDS) {
    const needle = process.env[envVar];
    if (needle) out = out.split(needle).join("[REDACTED]");
  }
  const sentinel = process.env.FAKE_ENGINE_SENTINEL;
  if (sentinel) out = out.split(sentinel).join("[REDACTED]");
  return out;
}

function handle(req) {
  switch (req.command) {
    case "find": {
      const content = readFileSync(req.pdfPath, "utf8");
      const candidates = findCandidates(content);
      // The real engine's full `find` contract (omitly#1864: the server reads it strictly).
      return {
        ok: true,
        scan_complete: true,
        clean: candidates.length === 0,
        count: candidates.length,
        total_findings: candidates.length,
        regions: candidates.map((c) => ({
          page: c.page,
          x: c.x,
          y: c.y,
          width: c.width,
          height: c.height,
          kind: c.kind,
          preview: maskPreview(c.text),
          // On the real native `find`'s page regions (crates/omitly-cli/src/main.rs `do_find`).
          under_redaction: false,
        })),
        survivors: [],
        off_page: [],
        coverage: { pages_total: 1, pages_scanned: 1, pages_failed: [], not_scanned: [], prior_revisions_scanned: false, metadata_scanned: false, acroform_scanned: false, attachments_scanned: false, form_xobjects_scanned: 0, annotation_appearances_scanned: 0, raster_pages: [], raster_only_pages: [], scan_complete: true },
      };
    }
    case "locate_text": {
      const content = readFileSync(req.pdfPath, "utf8");
      const regions = [];
      for (const needle of req.texts ?? []) {
        const at = content.indexOf(needle);
        if (at === -1) continue;
        regions.push({
          page: 0,
          x: 10 + regions.length * 5,
          y: 600 - regions.length * 20,
          width: Math.max(20, needle.length * 4),
          height: 12,
          kind: "text",
          preview: maskPreview(needle),
        });
      }
      return { ok: true, count: regions.length, regions };
    }
    case "redact_entities": {
      const content = readFileSync(req.pdfPath, "utf8");
      const candidates = findCandidates(content).filter(
        (c) => !req.kinds || req.kinds.includes(c.kind),
      );
      if (candidates.length === 0) {
        return { ok: true, output: null, redacted: [], note: "no matching entities found; no output written" };
      }
      writeFileSync(req.outputPath, stripCanaries(content));
      const auditEntries = candidates.map(auditEntryFor);
      writeFileSync(`${req.outputPath}.audit.json`, JSON.stringify(auditEntries));
      return {
        ok: true,
        output: req.outputPath,
        auditLogPath: `${req.outputPath}.audit.json`,
        redacted: candidates.map((c) => ({ page: c.page, kind: c.kind, preview: maskPreview(c.text) })),
        audit: {
          verdict: "pass",
          regions: auditEntries,
          warnings: [],
          metadataScrubbed: true,
          license: "licensed",
          licensedTo: null,
          disclosures: [],
        },
      };
    }
    case "redact": {
      const content = readFileSync(req.pdfPath, "utf8");
      writeFileSync(req.outputPath, stripCanaries(content));
      const auditEntries = (req.regions ?? []).map((r, i) => ({
        page: r.page,
        bbox: { x: r.x, y: r.y, width: r.width, height: r.height },
        timestamp: new Date(0).toISOString(),
        reason_code: r.reason ?? "UNSPECIFIED",
        verification: { result: "pass" },
      }));
      writeFileSync(`${req.outputPath}.audit.json`, JSON.stringify(auditEntries));
      return {
        ok: true,
        output: req.outputPath,
        auditLogPath: `${req.outputPath}.audit.json`,
        audit: {
          verdict: "pass",
          regions: auditEntries,
          warnings: [],
          metadataScrubbed: true,
          license: "licensed",
          licensedTo: null,
          disclosures: [],
          // omitly#1104: the real engine's v2 fields (crates/omitly-cli
          // `publish_v2`), fixed strings only.
          auditSchema: "omitly.audit/v2",
          userVerdict: "safe_to_send",
          blocking: false,
          auditV2Overall: "pass",
          // The Verify screen's rendering (`audit_v2_view`, main.rs `publish_v2`): a whole safe CheckResult.
          result: {
            state: "safe_to_send", blocking: false, summary: "Fake engine: every check passed.", pagesTotal: 1, pagesRead: 1,
            checked: [{ text: "Fake engine check" }], notChecked: [], problems: [], review: [], information: [], decisions: [], reasons: [],
            checkedAt: "2026-11-11T06:02:00Z", omitlyVersion: "0.0.0", sha256: "c".repeat(64), sizeBytes: 10, canWrite: false, producer: null,
          },
          sealFingerprint: "00:11:22:33",
        },
      };
    }
    case "verify": {
      // Reloads the sidecar written by redact/redact_entities above and
      // reports pass — the fixture already stripped the canaries at write
      // time, so this mirrors a genuine clean re-check.
      const sidecar = JSON.parse(readFileSync(`${req.pdfPath}.audit.json`, "utf8"));
      return {
        ok: true,
        verdict: "pass",
        regions: sidecar.map((e) => ({ page: e.page, reason: e.reason_code, verification: { result: "pass" } })),
        metadataScrubbed: true,
        hiddenContent: [
          { class: "thumbnails", verification: { result: "pass" } },
          { class: "document-actions", verification: { result: "pass" } },
          { class: "embedded-files", verification: { result: "pass" } },
          { class: "incremental-revisions", verification: { result: "pass" } },
          { class: "hidden-layers", verification: { result: "pass" } },
          { class: "comment-annotations", verification: { result: "pass" } },
          { class: "signature-identity", verification: { result: "pass" } },
          { class: "semantic-text", verification: { result: "pass" } },
          { class: "labels", verification: { result: "pass" } },
          { class: "redacted-text-in-strings", verification: { result: "pass" } },
        ],
        disclosures: [],
        scan_performed: false,
        license: null,
        warnings: [],
      };
    }
    case "extract_text": {
      // omitly#114. One "page" (page 0) — the fixture documents aren't
      // paginated. `masked` mirrors the real contract's default: omitted (or
      // explicit `true`) means masked; only an explicit `false` returns raw
      // text. Spans are CHAR offsets — for this ASCII-only fixture that's
      // identical to byte offsets, so the char-vs-byte distinction is proven
      // by the Rust suite (crates/redaction-core), not re-derived here; this
      // fixture exists to prove the MCP layer's schema + masking hold.
      const content = readFileSync(req.pdfPath, "utf8");
      const masked = req.masked !== false;
      const candidates = findCandidates(content);
      const spans = [];
      for (const c of candidates) {
        const at = content.indexOf(c.text);
        if (at === -1) continue;
        spans.push({ kind: c.kind, start: at, end: at + c.text.length });
      }
      spans.sort((a, b) => a.start - b.start);
      let text = content;
      if (masked) {
        let out = "";
        let last = 0;
        for (const s of spans) {
          out += content.slice(last, s.start);
          out += maskPreview(content.slice(s.start, s.end));
          last = s.end;
        }
        out += content.slice(last);
        text = out;
      }
      return { ok: true, masked, pages: [{ page: 0, contentDecoded: true, text, spans }] };
    }
    case "verify_seal": {
      // A canned "verified" seal response — verify_seal's fields (fingerprint,
      // hashes, filenames, license provenance) are all engine-computed
      // metadata, never document text, so this fixture doesn't need to read
      // req.pdfPath at all to exercise the MCP layer's schema + masking.
      return {
        ok: true,
        verdict: "verified",
        sealValid: true,
        sealFingerprint: "fake-seal-fingerprint-0123456789abcdef",
        // omitly#1588: the real engine adds this for a v1 seal.
        sealEraLabel: "classical-era seal (v1)",
        allPassed: true,
        metadataScrubbed: true,
        // The verifier's flag for a pre-#506 seal (main.rs verified reply); this fixture is a current-build report.
        legacyUnboundVerdict: false,
        regionCount: 3,
        pageCount: 1,
        warnings: [],
        licenseProvenance: {
          valid: true,
          licenseId: "fake-license-id",
          licensedTo: "Fake Engine Test Fixture",
          product: "omitly",
          reason: null,
        },
        inputSha256: "a".repeat(64),
        outputSha256: "b".repeat(64),
        sourceFilename: "canary.pdf",
        outputFilename: "canary.pdf",
      };
    }
    case "check": {
      // omitly#1857: check_redaction calls `check` after `find`. An engine with no `check` is an
      // execution failure (isError:true), so the fake answers with a COMPLETED verdict: fixed
      // copy only, never document text.
      return {
        ok: true,
        check: {
          verdict: "safe_to_send",
          blocking: false,
          reason_code: null,
          result: {
            state: "safe_to_send",
            blocking: false,
            summary: "Fake engine: nothing hidden was found.",
            pagesTotal: 1,
            pagesRead: 1,
            checked: [{ text: "Fake engine check" }],
            notChecked: [],
            problems: [],
            review: [],
            information: [],
            decisions: [],
            reasons: [],
            checkedAt: "2026-11-11T06:02:00Z",
            omitlyVersion: "0.0.0",
            sha256: createHash("sha256").update(readFileSync(req.pdfPath)).digest("hex"), // contract C3: bound to the file
            sizeBytes: 10,
            canWrite: false,
            producer: null,
          },
        },
      };
    }
    case "create": {
      const body = req.source ?? (req.sourcePath ? readFileSync(req.sourcePath, "utf8") : "");
      writeFileSync(req.outputPath, `%FAKE-PDF%\n${req.title ?? ""}\n${body}`);
      return { ok: true, output: req.outputPath };
    }
    default:
      return { ok: false, error: `fake-engine: unknown command ${req.command}` };
  }
}

let raw = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (d) => (raw += d));
process.stdin.on("end", () => {
  try {
    const req = JSON.parse(raw);
    process.stdout.write(JSON.stringify(handle(req)));
  } catch (e) {
    process.stdout.write(JSON.stringify({ ok: false, error: String(e && e.message ? e.message : e) }));
  }
});
