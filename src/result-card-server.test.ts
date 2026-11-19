/**
 * omitly#1857: the result card's server side, driven through the REAL `createServer()` over
 * an in-memory MCP client.
 *
 *  - the three card-linked tools carry `_meta.ui.resourceUri`; `verify_redaction` does not;
 *  - their output schemas are byte-identical to what `gitlab/main` (v5.5.0, 5dc19dde) served, but for
 *    the one structured `outcome` field (omitly#1864, owner decision): the card adds no field;
 *  - `ui://omitly/result-card.html` is served as `text/html;profile=mcp-app` with the server's
 *    version in it;
 *  - `open_in_omitly` is listed, and callable, ONLY for a client that advertises the MCP Apps
 *    extension `io.modelcontextprotocol/ui`;
 *  - it opens ONLY a pdfPath this connection returned a card-linked result for, newest 64, and
 *    only through the injected opener (never a shell);
 *  - the text a client without MCP Apps sees is unchanged (the existing suites pin it).
 */
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { test } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { CARD_PATH_CAP, CardPathAllowlist, logName, logOpen, systemOpener, type FileOpener } from "./open-in-omitly.js";

/** `tools/list` outputSchema of the three card-linked tools on gitlab/main 5dc19dde, as JSON (v0.2.1: minus the fixed 10,000-page `maxItems` of a result's `pages`, which the reply now bounds, errata 6). */
const BASE_OUTPUT_SCHEMAS: Record<string, string> = {
  check_redaction: "{\"type\":\"object\",\"properties\":{\"scanComplete\":{\"type\":\"boolean\"},\"clean\":{\"type\":\"boolean\"},\"totalFindings\":{\"type\":\"integer\",\"minimum\":0,\"maximum\":9007199254740991},\"byKind\":{\"type\":\"object\",\"propertyNames\":{\"type\":\"string\"},\"additionalProperties\":{\"type\":\"integer\",\"minimum\":-9007199254740991,\"maximum\":9007199254740991}},\"regions\":{\"type\":\"array\",\"items\":{\"type\":\"object\",\"properties\":{\"page\":{\"type\":\"integer\",\"minimum\":-9007199254740991,\"maximum\":9007199254740991},\"x\":{\"type\":\"number\"},\"y\":{\"type\":\"number\"},\"width\":{\"type\":\"number\"},\"height\":{\"type\":\"number\"},\"kind\":{\"type\":\"string\"},\"preview\":{\"type\":\"string\"}},\"required\":[\"page\",\"x\",\"y\",\"width\",\"height\",\"kind\",\"preview\"],\"additionalProperties\":false}},\"survivors\":{\"type\":\"array\",\"items\":{\"type\":\"object\",\"properties\":{\"page\":{\"type\":\"integer\",\"minimum\":-9007199254740991,\"maximum\":9007199254740991},\"x\":{\"type\":\"number\"},\"y\":{\"type\":\"number\"},\"width\":{\"type\":\"number\"},\"height\":{\"type\":\"number\"},\"kind\":{\"type\":\"string\"},\"preview\":{\"type\":\"string\"}},\"required\":[\"page\",\"x\",\"y\",\"width\",\"height\",\"kind\",\"preview\"],\"additionalProperties\":false}},\"offPage\":{\"type\":\"array\",\"items\":{\"type\":\"object\",\"properties\":{\"source\":{\"type\":\"string\"},\"kind\":{\"type\":\"string\"},\"preview\":{\"type\":\"string\"}},\"required\":[\"source\",\"kind\",\"preview\"],\"additionalProperties\":false}},\"coverage\":{\"type\":\"object\",\"properties\":{\"pagesScanned\":{\"anyOf\":[{\"type\":\"integer\",\"minimum\":-9007199254740991,\"maximum\":9007199254740991},{\"type\":\"null\"}]},\"pagesTotal\":{\"anyOf\":[{\"type\":\"integer\",\"minimum\":-9007199254740991,\"maximum\":9007199254740991},{\"type\":\"null\"}]},\"notScanned\":{\"type\":\"array\",\"items\":{\"type\":\"string\"}},\"priorRevisionsScanned\":{\"type\":\"boolean\"},\"metadataScanned\":{\"type\":\"boolean\"},\"acroformScanned\":{\"type\":\"boolean\"},\"attachmentsScanned\":{\"type\":\"boolean\"},\"formXobjectsScanned\":{\"type\":\"integer\",\"minimum\":-9007199254740991,\"maximum\":9007199254740991},\"annotationAppearancesScanned\":{\"type\":\"integer\",\"minimum\":-9007199254740991,\"maximum\":9007199254740991},\"pagesFailedCount\":{\"type\":\"integer\",\"minimum\":-9007199254740991,\"maximum\":9007199254740991}},\"required\":[\"pagesScanned\",\"pagesTotal\",\"notScanned\",\"priorRevisionsScanned\",\"metadataScanned\",\"acroformScanned\",\"attachmentsScanned\",\"formXobjectsScanned\",\"annotationAppearancesScanned\",\"pagesFailedCount\"],\"additionalProperties\":false},\"verdict\":{\"type\":\"object\",\"properties\":{\"verdict\":{\"type\":\"string\",\"enum\":[\"safe_to_send\",\"needs_review\",\"cannot_verify\"]},\"blocking\":{\"type\":\"boolean\"},\"result\":{\"anyOf\":[{\"type\":\"object\",\"properties\":{\"state\":{\"type\":\"string\",\"enum\":[\"safe_to_send\",\"needs_review\",\"cannot_verify\"]},\"blocking\":{\"type\":\"boolean\"},\"summary\":{\"type\":\"string\",\"maxLength\":1024,\"pattern\":\"^[^\\\\u0000-\\\\u001f\\\\u007f-\\\\u009f\\\\u2028\\\\u2029]*$\"},\"pagesTotal\":{\"type\":\"integer\",\"minimum\":0,\"maximum\":1000000},\"pagesRead\":{\"type\":\"integer\",\"minimum\":0,\"maximum\":1000000},\"checked\":{\"maxItems\":1024,\"type\":\"array\",\"items\":{\"type\":\"object\",\"properties\":{\"text\":{\"type\":\"string\",\"maxLength\":1024,\"pattern\":\"^[^\\\\u0000-\\\\u001f\\\\u007f-\\\\u009f\\\\u2028\\\\u2029]*$\"},\"pages\":{\"type\":\"array\",\"items\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":1000000}}},\"required\":[\"text\"],\"additionalProperties\":false}},\"notChecked\":{\"maxItems\":1024,\"type\":\"array\",\"items\":{\"type\":\"object\",\"properties\":{\"text\":{\"type\":\"string\",\"maxLength\":1024,\"pattern\":\"^[^\\\\u0000-\\\\u001f\\\\u007f-\\\\u009f\\\\u2028\\\\u2029]*$\"},\"pages\":{\"type\":\"array\",\"items\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":1000000}}},\"required\":[\"text\"],\"additionalProperties\":false}},\"problems\":{\"maxItems\":1024,\"type\":\"array\",\"items\":{\"type\":\"object\",\"properties\":{\"text\":{\"type\":\"string\",\"maxLength\":1024,\"pattern\":\"^[^\\\\u0000-\\\\u001f\\\\u007f-\\\\u009f\\\\u2028\\\\u2029]*$\"},\"pages\":{\"type\":\"array\",\"items\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":1000000}}},\"required\":[\"text\"],\"additionalProperties\":false}},\"review\":{\"maxItems\":1024,\"type\":\"array\",\"items\":{\"type\":\"object\",\"properties\":{\"text\":{\"type\":\"string\",\"maxLength\":1024,\"pattern\":\"^[^\\\\u0000-\\\\u001f\\\\u007f-\\\\u009f\\\\u2028\\\\u2029]*$\"},\"pages\":{\"type\":\"array\",\"items\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":1000000}}},\"required\":[\"text\"],\"additionalProperties\":false}},\"information\":{\"maxItems\":1024,\"type\":\"array\",\"items\":{\"type\":\"object\",\"properties\":{\"text\":{\"type\":\"string\",\"maxLength\":1024,\"pattern\":\"^[^\\\\u0000-\\\\u001f\\\\u007f-\\\\u009f\\\\u2028\\\\u2029]*$\"},\"pages\":{\"type\":\"array\",\"items\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":1000000}}},\"required\":[\"text\"],\"additionalProperties\":false}},\"decisions\":{\"maxItems\":1024,\"type\":\"array\",\"items\":{\"type\":\"object\",\"properties\":{\"text\":{\"type\":\"string\",\"maxLength\":1024,\"pattern\":\"^[^\\\\u0000-\\\\u001f\\\\u007f-\\\\u009f\\\\u2028\\\\u2029]*$\"},\"pages\":{\"type\":\"array\",\"items\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":1000000}}},\"required\":[\"text\"],\"additionalProperties\":false}},\"reasons\":{\"maxItems\":1024,\"type\":\"array\",\"items\":{\"type\":\"object\",\"properties\":{\"text\":{\"type\":\"string\",\"maxLength\":1024,\"pattern\":\"^[^\\\\u0000-\\\\u001f\\\\u007f-\\\\u009f\\\\u2028\\\\u2029]*$\"},\"pages\":{\"type\":\"array\",\"items\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":1000000}}},\"required\":[\"text\"],\"additionalProperties\":false}},\"checkedAt\":{\"type\":\"string\",\"pattern\":\"^\\\\d{4}-\\\\d{2}-\\\\d{2}T\\\\d{2}:\\\\d{2}:\\\\d{2}(\\\\.\\\\d{1,9})?Z$\"},\"omitlyVersion\":{\"type\":\"string\",\"maxLength\":64,\"pattern\":\"^[0-9A-Za-z.+-]+$\"},\"sha256\":{\"type\":\"string\",\"pattern\":\"^([0-9a-f]{64})?$\"},\"sizeBytes\":{\"type\":\"integer\",\"minimum\":0,\"maximum\":9007199254740991},\"decisionChannel\":{\"anyOf\":[{\"type\":\"string\",\"enum\":[\"human-desktop\",\"mcp-agent\",\"cli\",\"none\"]},{\"type\":\"null\"}]}},\"required\":[\"state\",\"blocking\",\"summary\",\"pagesTotal\",\"pagesRead\",\"checked\",\"notChecked\",\"problems\",\"review\",\"information\",\"decisions\",\"reasons\",\"checkedAt\",\"omitlyVersion\",\"sha256\",\"sizeBytes\",\"decisionChannel\"],\"additionalProperties\":false},{\"type\":\"null\"}]},\"reason_code\":{\"anyOf\":[{\"type\":\"string\",\"enum\":[\"input_too_large\",\"check_failed\",\"check_unavailable\",\"result_invalid\"]},{\"type\":\"null\"}]}},\"required\":[\"verdict\",\"blocking\",\"result\",\"reason_code\"],\"additionalProperties\":false},\"evaluation\":{\"type\":\"boolean\",\"const\":true}},\"required\":[\"scanComplete\",\"clean\",\"totalFindings\",\"byKind\",\"regions\",\"survivors\",\"offPage\",\"coverage\",\"verdict\"],\"$schema\":\"http://json-schema.org/draft-07/schema#\",\"additionalProperties\":false}",
  verify_seal: "{\"type\":\"object\",\"properties\":{\"verdict\":{\"type\":\"string\",\"enum\":[\"no_report\",\"seal_invalid\",\"seal_unsupported_version\",\"report_unparseable\",\"unsupported_schema\",\"incomplete\",\"verified\"]},\"sealValid\":{\"type\":[\"boolean\",\"null\"]},\"sealVersion\":{\"type\":[\"string\",\"null\"]},\"carriesAuditReport\":{\"type\":[\"boolean\",\"null\"]},\"sealFingerprint\":{\"type\":[\"string\",\"null\"]},\"sealEraLabel\":{\"type\":[\"string\",\"null\"]},\"allPassed\":{\"type\":[\"boolean\",\"null\"]},\"metadataScrubbed\":{\"type\":[\"boolean\",\"null\"]},\"decisionChannel\":{\"type\":[\"string\",\"null\"]},\"regionCount\":{\"anyOf\":[{\"type\":\"integer\",\"minimum\":-9007199254740991,\"maximum\":9007199254740991},{\"type\":\"null\"}]},\"pageCount\":{\"anyOf\":[{\"type\":\"integer\",\"minimum\":-9007199254740991,\"maximum\":9007199254740991},{\"type\":\"null\"}]},\"warnings\":{\"anyOf\":[{\"type\":\"array\",\"items\":{\"type\":\"string\"}},{\"type\":\"null\"}]},\"licenseProvenance\":{\"anyOf\":[{\"type\":\"object\",\"properties\":{\"valid\":{\"type\":\"boolean\"},\"licenseId\":{\"type\":\"string\"},\"licensedTo\":{\"type\":\"string\",\"description\":\"The name the buyer entered at checkout. The vendor licence chain signs it, but Omitly does not verify who the buyer is: report it as the name given by the buyer, never as a verified identity.\"},\"product\":{\"type\":\"string\"},\"reason\":{\"type\":[\"string\",\"null\"]}},\"required\":[\"valid\",\"licenseId\",\"licensedTo\",\"product\",\"reason\"],\"additionalProperties\":false},{\"type\":\"null\"}]},\"inputSha256\":{\"type\":[\"string\",\"null\"]},\"outputSha256\":{\"type\":[\"string\",\"null\"]},\"sourceFilename\":{\"type\":[\"string\",\"null\"]},\"outputFilename\":{\"type\":[\"string\",\"null\"]},\"auditV2Overall\":{\"anyOf\":[{\"type\":\"string\",\"enum\":[\"pass\",\"pass_with_operator_decisions\",\"review_required\",\"unsafe\",\"technical_fail\"]},{\"type\":\"null\"}]},\"userVerdict\":{\"anyOf\":[{\"type\":\"string\",\"enum\":[\"safe_to_send\",\"needs_review\",\"cannot_verify\"]},{\"type\":\"null\"}]},\"blocking\":{\"type\":[\"boolean\",\"null\"]},\"sealRemoved\":{\"type\":\"boolean\"},\"sealKeyKind\":{\"anyOf\":[{\"type\":\"string\",\"enum\":[\"one_time\",\"install\"]},{\"type\":\"null\"}]}},\"required\":[\"verdict\",\"sealValid\",\"sealVersion\",\"carriesAuditReport\",\"sealFingerprint\",\"sealEraLabel\",\"allPassed\",\"metadataScrubbed\",\"decisionChannel\",\"regionCount\",\"pageCount\",\"warnings\",\"licenseProvenance\",\"inputSha256\",\"outputSha256\",\"sourceFilename\",\"outputFilename\",\"auditV2Overall\",\"userVerdict\",\"blocking\",\"sealRemoved\",\"sealKeyKind\"],\"$schema\":\"http://json-schema.org/draft-07/schema#\",\"additionalProperties\":false}",
  verify_document: "{\"type\":\"object\",\"properties\":{\"verdict\":{\"type\":\"string\",\"enum\":[\"no_report\",\"seal_invalid\",\"seal_unsupported_version\",\"report_unparseable\",\"unsupported_schema\",\"incomplete\",\"verified\"]},\"sealValid\":{\"type\":[\"boolean\",\"null\"]},\"sealVersion\":{\"type\":[\"string\",\"null\"]},\"carriesAuditReport\":{\"type\":[\"boolean\",\"null\"]},\"sealFingerprint\":{\"type\":[\"string\",\"null\"]},\"sealEraLabel\":{\"type\":[\"string\",\"null\"]},\"allPassed\":{\"type\":[\"boolean\",\"null\"]},\"metadataScrubbed\":{\"type\":[\"boolean\",\"null\"]},\"decisionChannel\":{\"type\":[\"string\",\"null\"]},\"regionCount\":{\"anyOf\":[{\"type\":\"integer\",\"minimum\":-9007199254740991,\"maximum\":9007199254740991},{\"type\":\"null\"}]},\"pageCount\":{\"anyOf\":[{\"type\":\"integer\",\"minimum\":-9007199254740991,\"maximum\":9007199254740991},{\"type\":\"null\"}]},\"warnings\":{\"anyOf\":[{\"type\":\"array\",\"items\":{\"type\":\"string\"}},{\"type\":\"null\"}]},\"licenseProvenance\":{\"anyOf\":[{\"type\":\"object\",\"properties\":{\"valid\":{\"type\":\"boolean\"},\"licenseId\":{\"type\":\"string\"},\"licensedTo\":{\"type\":\"string\",\"description\":\"The name the buyer entered at checkout. The vendor licence chain signs it, but Omitly does not verify who the buyer is: report it as the name given by the buyer, never as a verified identity.\"},\"product\":{\"type\":\"string\"},\"reason\":{\"type\":[\"string\",\"null\"]}},\"required\":[\"valid\",\"licenseId\",\"licensedTo\",\"product\",\"reason\"],\"additionalProperties\":false},{\"type\":\"null\"}]},\"inputSha256\":{\"type\":[\"string\",\"null\"]},\"outputSha256\":{\"type\":[\"string\",\"null\"]},\"sourceFilename\":{\"type\":[\"string\",\"null\"]},\"outputFilename\":{\"type\":[\"string\",\"null\"]},\"auditV2Overall\":{\"anyOf\":[{\"type\":\"string\",\"enum\":[\"pass\",\"pass_with_operator_decisions\",\"review_required\",\"unsafe\",\"technical_fail\"]},{\"type\":\"null\"}]},\"userVerdict\":{\"anyOf\":[{\"type\":\"string\",\"enum\":[\"safe_to_send\",\"needs_review\",\"cannot_verify\"]},{\"type\":\"null\"}]},\"blocking\":{\"type\":[\"boolean\",\"null\"]},\"sealRemoved\":{\"type\":\"boolean\"},\"sealKeyKind\":{\"anyOf\":[{\"type\":\"string\",\"enum\":[\"one_time\",\"install\"]},{\"type\":\"null\"}]}},\"required\":[\"verdict\",\"sealValid\",\"sealVersion\",\"carriesAuditReport\",\"sealFingerprint\",\"sealEraLabel\",\"allPassed\",\"metadataScrubbed\",\"decisionChannel\",\"regionCount\",\"pageCount\",\"warnings\",\"licenseProvenance\",\"inputSha256\",\"outputSha256\",\"sourceFilename\",\"outputFilename\",\"auditV2Overall\",\"userVerdict\",\"blocking\",\"sealRemoved\",\"sealKeyKind\"],\"$schema\":\"http://json-schema.org/draft-07/schema#\",\"additionalProperties\":false}",
};

const UI_CAPS = { extensions: { "io.modelcontextprotocol/ui": { mimeTypes: ["text/html;profile=mcp-app"] } } };
const CARD_TOOLS = ["check_redaction", "verify_seal", "verify_document"];

const ENV_KEYS = ["OMITLY_ALLOWED_DIR", "OMITLY_REDACT_BIN", "OMITLY_PDF_BIN", "OMITLY_ENGINE_DIR", "OMITLY_STATE_DIR", "OMITLY_FREE_CAP"] as const;
let counter = 0;

function freshRoot(): string {
  return realpathSync(mkdtempSync(path.join(tmpdir(), "omitly-result-card-")));
}

/** A one-page PDF with some live text, hand-built so the xref is exact. */
function tinyPdf(): Buffer {
  const content = "BT /F1 12 Tf 100 680 Td (Hello card) Tj ET\n";
  const objects = [
    "<< /Type /Catalog /Pages 2 0 R >>",
    "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
    `<< /Length ${content.length} >>\nstream\n${content}endstream`,
    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
  ];
  let pdf = "%PDF-1.5\n";
  const offsets: number[] = [];
  objects.forEach((body, i) => {
    offsets.push(pdf.length);
    pdf += `${i + 1} 0 obj\n${body}\nendobj\n`;
  });
  const xref = pdf.length;
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const o of offsets) pdf += `${String(o).padStart(10, "0")} 00000 n \n`;
  pdf += `trailer\n<< /Root 1 0 R /Size ${objects.length + 1} >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.from(pdf, "latin1");
}

/** A stub engine that answers `verify_seal` with a v1-verified result, so the seal tools run
 *  without a native build. */
function stubEngine(root: string): string {
  const bin = path.join(root, "stub-engine.mjs");
  writeFileSync(
    bin,
    `#!/usr/bin/env node
import { readFileSync } from "node:fs";
const req = JSON.parse(readFileSync(0, "utf8"));
if (req.command === "verify_seal") {
  process.stdout.write(JSON.stringify({ ok: true, verdict: "verified", sealValid: true, allPassed: true, metadataScrubbed: true, warnings: [], legacyUnboundVerdict: false, pageCount: 2, sealFingerprint: "ab12cd34ef56", sealEraLabel: "classical-era seal (v1)" }));
} else {
  process.stdout.write(JSON.stringify({ ok: false, error: "unexpected command " + req.command }));
}
`,
    { mode: 0o755 },
  );
  chmodSync(bin, 0o755);
  return bin;
}

interface Rig {
  root: string;
  client: Client;
  opened: string[];
  close(): Promise<void>;
}

/** A fresh module instance (index.ts reads its environment once at load) wired to an
 *  in-memory client. `ui` = whether the client advertises MCP Apps. */
async function rig(opts: { ui: boolean; engine?: boolean; opener?: Partial<FileOpener> }): Promise<Rig> {
  const root = freshRoot();
  for (const k of ENV_KEYS) delete process.env[k];
  process.env.OMITLY_ALLOWED_DIR = root;
  process.env.OMITLY_STATE_DIR = path.join(root, "state");
  process.env.OMITLY_FREE_CAP = "1000";
  if (opts.engine) process.env.OMITLY_REDACT_BIN = stubEngine(root);
  writeFileSync(path.join(root, "doc.pdf"), tinyPdf());
  counter += 1;
  const mod = (await import(`./index.js?result-card-variant=${counter}`)) as typeof import("./index.js");
  const opened: string[] = [];
  const opener: FileOpener = {
    supported: true,
    open: async (p) => {
      opened.push(p);
    },
    ...opts.opener,
  };
  const server = mod.createServer({ opener });
  const client = new Client({ name: "result-card-test", version: "0.0.0" }, { capabilities: opts.ui ? (UI_CAPS as any) : {} });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(a), client.connect(b)]);
  return {
    root,
    client,
    opened,
    close: async () => {
      await client.close();
      await server.close();
    },
  };
}

const textOf = (res: any) => (res.content ?? []).filter((c: any) => c.type === "text").map((c: any) => c.text).join("\n");

async function withRig<T>(opts: Parameters<typeof rig>[0], fn: (r: Rig) => Promise<T>): Promise<T> {
  const r = await rig(opts);
  try {
    return await fn(r);
  } finally {
    await r.close();
  }
}

/** Capture what the server writes to stderr (the open_in_omitly log lines) while `fn` runs. */
async function captureStderr(fn: () => Promise<void>): Promise<string[]> {
  const lines: string[] = [];
  const real = process.stderr.write.bind(process.stderr);
  (process.stderr as any).write = (chunk: any, ...rest: any[]) => {
    lines.push(String(chunk));
    return true;
  };
  try {
    await fn();
  } finally {
    process.stderr.write = real as any;
  }
  return lines;
}

// ---------------------------------------------------------------------------

test("the three card-linked tools carry the card's resourceUri; verify_redaction does not", async () => {
  await withRig({ ui: true }, async ({ client }) => {
    const tools = (await client.listTools()).tools;
    for (const name of CARD_TOOLS) {
      const t: any = tools.find((x) => x.name === name);
      assert.ok(t, name);
      assert.equal(t._meta?.ui?.resourceUri, "ui://omitly/result-card.html", name);
      // Model-visible (default visibility): the card is not an app-only tool.
      assert.equal(t._meta?.ui?.visibility, undefined, name);
    }
    for (const t of tools) {
      if (!CARD_TOOLS.includes(t.name)) {
        assert.equal((t as any)._meta?.ui?.resourceUri, undefined, `${t.name} must not link the card`);
      }
    }
    assert.equal((tools.find((x) => x.name === "verify_redaction") as any)._meta, undefined);
  });
});

test("the card adds no field to check_redaction's output schema (byte-identical to gitlab/main but for `outcome`); the seal tools carry the contract §6.1 envelope", async () => {
  for (const ui of [false, true]) {
    await withRig({ ui }, async ({ client }) => {
      const tools = (await client.listTools()).tools;
      for (const name of CARD_TOOLS) {
        const t = tools.find((x) => x.name === name)!;
        const schema: any = JSON.parse(JSON.stringify(t.outputSchema));
        // The structured verdict field the owner asked for: a closed set, required, and nothing else added.
        assert.deepEqual(schema.properties.outcome, { type: "string", enum: ["safe_to_send", "needs_review", "not_a_pass", "incomplete"] }, `${name} outcome`);
        assert.ok(schema.required.includes("outcome"), `${name}: outcome is required`);
        if (name === "check_redaction") {
          delete schema.properties.outcome;
          schema.required = schema.required.filter((k: string) => k !== "outcome");
          assert.equal(JSON.stringify(schema), BASE_OUTPUT_SCHEMAS[name], `${name} outputSchema changed (ui=${ui})`);
        } else {
          // Contract §6.1: the seal tools' schema is the new envelope { outcome, seal, embeddedReport }; there is no top-level verdict.
          assert.deepEqual(Object.keys(schema.properties).sort(), ["embeddedReport", "outcome", "seal"], `${name} (ui=${ui})`);
          assert.deepEqual(schema.properties.seal.properties.state.enum, ["held", "invalid", "removed", "none", "unsupported"], name);
          assert.ok(schema.required.includes("seal"), name);
        }
      }
    });
  }
});

test("the card resource: text/html;profile=mcp-app, the server's version, no widened CSP", async () => {
  await withRig({ ui: true }, async ({ client }) => {
    const listed = (await client.listResources()).resources.find((r) => r.uri === "ui://omitly/result-card.html");
    assert.ok(listed, "resource is not listed");
    assert.equal(listed.mimeType, "text/html;profile=mcp-app");
    const read = await client.readResource({ uri: "ui://omitly/result-card.html" });
    const c: any = read.contents[0];
    assert.equal(c.mimeType, "text/html;profile=mcp-app");
    const pkg = (await import("node:fs")).readFileSync(new URL("../package.json", import.meta.url), "utf8");
    const version = JSON.parse(pkg).version;
    assert.ok(c.text.includes(`<meta name="omitly-version" content="${version}">`), "version not injected");
    assert.ok(!c.text.includes("__OMITLY_VERSION__>"), "placeholder left in the page");
    assert.deepEqual(c._meta?.ui?.csp, { connectDomains: [], resourceDomains: [] });
  });
});

// ---- capability gating ----------------------------------------------------

test("open_in_omitly: listed and callable only when the client advertises MCP Apps", async () => {
  // Without the extension: not in tools/list, and a call is refused (the opener is never reached).
  await withRig({ ui: false, engine: true }, async ({ client, opened, root }) => {
    const names = (await client.listTools()).tools.map((t) => t.name);
    assert.ok(!names.includes("open_in_omitly"), "listed for a plain client");
    await client.callTool({ name: "verify_seal", arguments: { pdfPath: path.join(root, "doc.pdf") } });
    const res: any = await client.callTool({ name: "open_in_omitly", arguments: { pdfPath: path.join(root, "doc.pdf") } });
    assert.equal(res.isError, true);
    assert.match(textOf(res), /disabled|only available to MCP Apps/);
    assert.deepEqual(opened, [], "a client without MCP Apps launched something");
  });
  // With it: listed (app-only, not read-only, idempotent), and callable.
  await withRig({ ui: true, engine: true }, async ({ client, opened, root }) => {
    const tool: any = (await client.listTools()).tools.find((t) => t.name === "open_in_omitly");
    assert.ok(tool, "not listed for an MCP Apps client");
    assert.deepEqual(tool._meta?.ui?.visibility, ["app"]);
    assert.equal(tool.annotations.readOnlyHint, false);
    assert.equal(tool.annotations.idempotentHint, true);
    assert.equal(tool.annotations.destructiveHint, false);
    assert.equal(tool.annotations.openWorldHint, false);
    const pdf = path.join(root, "doc.pdf");
    await client.callTool({ name: "verify_seal", arguments: { pdfPath: pdf } });
    const res: any = await client.callTool({ name: "open_in_omitly", arguments: { pdfPath: pdf } });
    assert.equal(res.isError, undefined, textOf(res));
    assert.deepEqual(res.structuredContent, { status: "opened" });
    assert.deepEqual(opened, [pdf]);
  });
});

test("open_in_omitly: an extension key with another name does not count", async () => {
  const root = freshRoot();
  for (const k of ENV_KEYS) delete process.env[k];
  process.env.OMITLY_ALLOWED_DIR = root;
  process.env.OMITLY_STATE_DIR = path.join(root, "state");
  counter += 1;
  const mod = (await import(`./index.js?result-card-variant=${counter}`)) as typeof import("./index.js");
  const server = mod.createServer();
  const client = new Client({ name: "t", version: "0" }, { capabilities: { extensions: { "io.example/ui": {} } } as any });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(a), client.connect(b)]);
  try {
    assert.ok(!(await client.listTools()).tools.some((t) => t.name === "open_in_omitly"));
  } finally {
    await client.close();
    await server.close();
  }
});

test("open_in_omitly: the extension must advertise the MCP Apps MIME type", async () => {
  const variants: Record<string, unknown> = {
    "empty mimeTypes": { mimeTypes: [] },
    "text/plain only": { mimeTypes: ["text/plain"] },
    "missing mimeTypes": {},
    "mimeTypes not an array": { mimeTypes: "text/html;profile=mcp-app" },
  };
  for (const [label, ext] of Object.entries(variants)) {
    const root = freshRoot();
    for (const k of ENV_KEYS) delete process.env[k];
    process.env.OMITLY_ALLOWED_DIR = root;
    process.env.OMITLY_STATE_DIR = path.join(root, "state");
    process.env.OMITLY_REDACT_BIN = stubEngine(root);
    writeFileSync(path.join(root, "doc.pdf"), tinyPdf());
    counter += 1;
    const mod = (await import(`./index.js?result-card-variant=${counter}`)) as typeof import("./index.js");
    const opened: string[] = [];
    const server = mod.createServer({ opener: { supported: true, open: async (p) => void opened.push(p) } });
    const client = new Client({ name: "t", version: "0" }, { capabilities: { extensions: { "io.modelcontextprotocol/ui": ext } } as any });
    const [a, b] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(a), client.connect(b)]);
    try {
      assert.ok(!(await client.listTools()).tools.some((t) => t.name === "open_in_omitly"), `${label}: listed`);
      const pdf = path.join(root, "doc.pdf");
      await client.callTool({ name: "verify_seal", arguments: { pdfPath: pdf } });
      const res: any = await client.callTool({ name: "open_in_omitly", arguments: { pdfPath: pdf } });
      assert.equal(res.isError, true, `${label}: call not refused`);
      assert.deepEqual(opened, [], `${label}: opened a file`);
    } finally {
      await client.close();
      await server.close();
    }
  }
  // The right MIME type among others still works.
  await withRig({ ui: true, engine: true }, async ({ client }) => {
    assert.ok((await client.listTools()).tools.some((t) => t.name === "open_in_omitly"));
  });
});

// ---- the allowlist --------------------------------------------------------

test("open_in_omitly opens only a pdfPath a card-linked result was returned for", async () => {
  await withRig({ ui: true, engine: true }, async ({ client, opened, root }) => {
    const shown = path.join(root, "doc.pdf");
    const other = path.join(root, "other.pdf");
    writeFileSync(other, tinyPdf());
    const call = (pdfPath: string): Promise<any> => client.callTool({ name: "open_in_omitly", arguments: { pdfPath } });

    // Nothing has been shown yet.
    let res = await call(shown);
    assert.equal(res.isError, true);
    assert.match(textOf(res), /not checked in this session/);
    assert.deepEqual(opened, []);

    // A tool result that carries no card (an error with no structuredContent) allows nothing.
    await client.callTool({ name: "verify_seal", arguments: { pdfPath: path.join(root, "missing.pdf") } });
    res = await call(path.join(root, "missing.pdf"));
    assert.equal(res.isError, true);

    // After a card-linked result for `shown`: that file opens; `other` still does not.
    const sealRes: any = await client.callTool({ name: "verify_seal", arguments: { pdfPath: shown } });
    assert.ok(sealRes.structuredContent, "the seal call returned no card data");
    res = await call(shown);
    assert.equal(res.isError, undefined, textOf(res));
    assert.deepEqual(opened, [shown]);
    res = await call(other);
    assert.equal(res.isError, true);
    assert.deepEqual(opened, [shown], "a path that was never shown was opened");

    // verify_document is card-linked too; repeating a call is harmless.
    await client.callTool({ name: "verify_document", arguments: { pdfPath: other } });
    await call(other);
    await call(other);
    assert.deepEqual(opened, [shown, other, other]);

    // The path is re-confined: an absolute path outside the allowed folder is refused even
    // though the string is on the list (the list is keyed by what the model sent).
    for (const bad of ["/etc/passwd", path.join(root, "..", "outside.pdf"), "-a", "--help"]) {
      res = await call(bad);
      assert.equal(res.isError, true, bad);
    }
    assert.deepEqual(opened, [shown, other, other]);
  });
});

test("open_in_omitly opens only a file inside the allowed folder, even if the model once sent its path", async () => {
  await withRig({ ui: true, engine: true }, async ({ client, opened, root }) => {
    const pdf = path.join(root, "doc.pdf");
    await client.callTool({ name: "verify_seal", arguments: { pdfPath: pdf } });
    // The file disappears after the card was shown: nothing to open.
    (await import("node:fs")).rmSync(pdf);
    const res: any = await client.callTool({ name: "open_in_omitly", arguments: { pdfPath: pdf } });
    assert.equal(res.isError, true);
    assert.deepEqual(opened, []);
  });
});

test("open_in_omitly: a card-linked check_redaction result (wasm, no engine) allows the path", async () => {
  await withRig({ ui: true }, async ({ client, opened, root }) => {
    const pdf = path.join(root, "doc.pdf");
    const check: any = await client.callTool({ name: "check_redaction", arguments: { pdfPath: pdf } });
    assert.ok(check.structuredContent?.verdict, textOf(check));
    const res: any = await client.callTool({ name: "open_in_omitly", arguments: { pdfPath: pdf } });
    assert.equal(res.isError, undefined, textOf(res));
    assert.deepEqual(opened, [pdf]);
  });
});

test("open_in_omitly: unsupported platform is a polite answer, not an error; a failing opener is an error", async () => {
  await withRig({ ui: true, engine: true, opener: { supported: false } }, async ({ client, opened, root }) => {
    const pdf = path.join(root, "doc.pdf");
    await client.callTool({ name: "verify_seal", arguments: { pdfPath: pdf } });
    const res: any = await client.callTool({ name: "open_in_omitly", arguments: { pdfPath: pdf } });
    assert.equal(res.isError, undefined);
    assert.deepEqual(res.structuredContent, { status: "unsupported" });
    assert.match(textOf(res), /not supported on this platform yet/);
    assert.deepEqual(opened, []);
  });
  await withRig(
    { ui: true, engine: true, opener: { open: async () => { throw new Error("boom: /secret/path"); } } },
    async ({ client, root }) => {
      const pdf = path.join(root, "doc.pdf");
      await client.callTool({ name: "verify_seal", arguments: { pdfPath: pdf } });
      const res: any = await client.callTool({ name: "open_in_omitly", arguments: { pdfPath: pdf } });
      assert.equal(res.isError, true);
      assert.ok(!textOf(res).includes("secret"), "the opener's error text reached the client");
    },
  );
});

test("open_in_omitly logs each call to stderr with a time and a basename only", async () => {
  await withRig({ ui: true, engine: true }, async ({ client, root }) => {
    const pdf = path.join(root, "doc.pdf");
    await client.callTool({ name: "verify_seal", arguments: { pdfPath: pdf } });
    const lines = await captureStderr(async () => {
      await client.callTool({ name: "open_in_omitly", arguments: { pdfPath: pdf } });
      await client.callTool({ name: "open_in_omitly", arguments: { pdfPath: "/nope/never.pdf" } });
    });
    const logs = lines.filter((l) => l.includes("open_in_omitly"));
    assert.equal(logs.length, 2, lines.join(""));
    assert.match(logs[0]!, /^\[omitly-mcp\] open_in_omitly \d{4}-\d\d-\d\dT[\d:.]+Z doc\.pdf\n$/);
    assert.match(logs[1]!, / never\.pdf\n$/);
    for (const l of logs) assert.ok(!l.includes(root) && !l.includes("/nope"), "a directory reached the log");
  });
});

// ---- units ----------------------------------------------------------------

test("CardPathAllowlist keeps the newest 64, newest first", () => {
  assert.equal(CARD_PATH_CAP, 64);
  const list = new CardPathAllowlist();
  for (let i = 0; i < 70; i++) list.remember(`/d/${i}.pdf`);
  assert.equal(list.size, 64);
  for (let i = 0; i < 6; i++) assert.equal(list.has(`/d/${i}.pdf`), false, `${i} should be evicted`);
  for (let i = 6; i < 70; i++) assert.equal(list.has(`/d/${i}.pdf`), true, `${i} should remain`);
  // A repeat moves to the front (so it is evicted last); the size does not grow.
  list.remember("/d/6.pdf");
  assert.equal(list.size, 64);
  for (let i = 70; i < 133; i++) list.remember(`/d/${i}.pdf`);
  assert.equal(list.has("/d/6.pdf"), true);
  assert.equal(list.has("/d/7.pdf"), false);
  assert.equal(list.has("/never"), false);
});

test("systemOpener: macOS runs `open -a Omitly -- <path>` with no shell; other platforms are unsupported", async () => {
  const calls: unknown[][] = [];
  const mac = systemOpener("darwin", (file, args, options, cb) => {
    calls.push([file, args, options]);
    cb(null);
  });
  assert.equal(mac.supported, true);
  await mac.open("/Users/x/My Docs/a b;rm -rf.pdf");
  assert.deepEqual(calls, [["open", ["-a", "Omitly", "--", "/Users/x/My Docs/a b;rm -rf.pdf"], { timeout: 10_000 }]]);
  await assert.rejects(
    systemOpener("darwin", (_f, _a, _o, cb) => cb(new Error("no app"))).open("/x.pdf"),
  );
  for (const platform of ["win32", "linux"] as const) {
    const other = systemOpener(platform, () => assert.fail("must not run"));
    assert.equal(other.supported, false);
    await assert.rejects(other.open("/x.pdf"));
  }
});

test("log lines carry a basename only, with control characters removed", () => {
  const out: string[] = [];
  logOpen("/a/b/c d.pdf", new Date("2026-11-11T08:00:00Z"), (s) => out.push(s));
  assert.deepEqual(out, ["[omitly-mcp] open_in_omitly 2026-11-11T08:00:00.000Z c d.pdf\n"]);
  assert.equal(logName("/x/evil\n[omitly-mcp] forged.pdf"), "evil?[omitly-mcp] forged.pdf");
  assert.equal(logName("/x/" + "a".repeat(300)).length, 121);
});
