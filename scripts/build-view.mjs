#!/usr/bin/env node
/**
 * omitly#1857: bundle the MCP Apps result card into ONE self-contained HTML page,
 * `dist/result-card.html`. The host's CSP is `connect-src 'none'` and blocks CDNs, so the
 * ext-apps `App` client, the card's CSS and its code are all inlined: no external script,
 * stylesheet or font. The server reads this file when a client asks for the card
 * (`ui://omitly/result-card.html`). The bundle is generated, never committed (dist/ is
 * gitignored); `npm run build` and `npm test` run it.
 *
 * esbuild is a pinned devDependency; the page template lives in src/result-card.ts
 * (`pageHtml`), compiled by tsc first, so run this AFTER tsc.
 */
import { build } from "esbuild";
import { mkdirSync, writeFileSync } from "node:fs";
import * as path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const result = await build({
  entryPoints: [path.join(root, "src", "view-entry.ts")],
  bundle: true,
  write: false,
  format: "iife",
  platform: "browser",
  target: "es2020",
  minify: true,
  legalComments: "none",
  logLevel: "warning",
});
if (result.outputFiles.length !== 1) throw new Error("expected exactly one bundle");
const js = result.outputFiles[0].text;

const { pageHtml } = await import(pathToFileURL(path.join(root, "dist", "result-card.js")).href);
const html = pageHtml(js);
mkdirSync(path.join(root, "dist"), { recursive: true });
const out = path.join(root, "dist", "result-card.html");
writeFileSync(out, html);
console.log(`[build:view] ${path.relative(root, out)} ${html.length} bytes`);
