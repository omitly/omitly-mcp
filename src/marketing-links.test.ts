/**
 * omitly#1854: every user-facing link from this package to the marketing site
 * carries `?via=mcp`, the tag the website records as acquisition source "mcp".
 *
 * Oracle: the real shipped files (compiled dist/*.js, the MCPB server, the
 * skill, plugin and manifest files), read from disk. Nothing is reimplemented.
 * Exempt, on purpose: /support and /privacy (not marketing), releases.omitly.app
 * (a different host, so never matched), LICENSE and THIRD-PARTY-NOTICES (not
 * scanned), server.json (registry metadata, not scanned) and code comments.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { readdirSync, readFileSync } from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { freeCapRefusal, OMITLY_SITE_URL } from "./usage.js";

// dist/marketing-links.test.js -> package root is one level up.
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const SITE = /https?:\/\/(?:www\.)?omitly\.app(?![\w.-])([^\s"'`)\]>]*)/g;
const EXEMPT_PATH = /^\/(?:support|privacy)(?:[/?#]|$)/;
const TAGGED = /[?&]via=mcp(?:[&#]|$)/;

// On-disk path for a POSIX-style relative path (Windows accepts "/" but join normalises).
const abs = (rel: string) => path.join(root, ...rel.split("/"));

const listJs = (dir: string): string[] =>
  readdirSync(abs(dir), { withFileTypes: true }).flatMap((e) => {
    const rel = path.posix.join(dir, e.name); // POSIX on every platform
    if (e.isDirectory()) return listJs(rel);
    return e.name.endsWith(".js") && !e.name.includes(".test.") ? [rel] : [];
  });

const SCANNED = [
  ...listJs("dist"), // tool-result strings in the built server
  ...listJs("mcpb/server"), // the MCPB bundle's own server
  "skill/SKILL.md",
  "plugin/skills/omitly-redaction/SKILL.md",
  "plugin/README.md",
  "plugin/commands/check.md",
  "plugin/.claude-plugin/plugin.json",
  ".claude-plugin/marketplace.json",
  "mcpb/manifest.json",
  "package.json",
  "README.md",
];

const isComment = (line: string) => /^\s*(?:\/\/|\/\*|\*)/.test(line);

function untaggedLinks(rel: string): string[] {
  const bad: string[] = [];
  readFileSync(abs(rel), "utf8")
    .split("\n")
    .forEach((line, i) => {
      if (rel.endsWith(".js") && isComment(line)) return;
      for (const m of line.matchAll(SITE)) {
        const rest = m[1];
        if (EXEMPT_PATH.test(rest) || TAGGED.test(rest)) continue;
        bad.push(`${rel}:${i + 1}: ${m[0]}`);
      }
    });
  return bad;
}

test("the scan covers the built server, the MCPB server and every shipped skill/manifest file", () => {
  assert.ok(SCANNED.includes("dist/index.js") && SCANNED.includes("dist/usage.js"));
  assert.ok(SCANNED.some((f) => f.startsWith("dist/pdf-edit/")), "dist/pdf-edit must be scanned");
  assert.ok(SCANNED.includes("mcpb/server/index.js") && SCANNED.includes("mcpb/server/usage.js"));
  // Self-check of the oracle: the files really do contain site links to judge.
  const total = SCANNED.reduce(
    (n, f) => n + [...readFileSync(abs(f), "utf8").matchAll(SITE)].length,
    0,
  );
  assert.ok(total >= 10, `expected to find site links to check, found ${total}`);
});

test("no marketing link to omitly.app lacks ?via=mcp", () => {
  const bad = SCANNED.flatMap(untaggedLinks);
  assert.deepEqual(bad, [], `untagged marketing links:\n${bad.join("\n")}`);
});

test("the free-cap refusal message links the tagged URL, cleanly delimited", () => {
  const msg = freeCapRefusal("check_redaction", {
    capped: true, used: 11, cap: 10, month: "2026-11",
  }).message;
  assert.equal(OMITLY_SITE_URL, "https://omitly.app/?via=mcp");
  assert.match(msg, /https:\/\/omitly\.app\/\?via=mcp(?= )/);
});
