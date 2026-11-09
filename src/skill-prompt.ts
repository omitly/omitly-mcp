/**
 * omitly#1641 option (a): serve the shipped Claude skill as an MCP prompt.
 *
 * `skill/SKILL.md` is in every npm tarball (package.json `files`) and is the
 * same file the Claude Code plugin installs, but before this the server never
 * read it, so a Claude Desktop / Cursor / any-MCP-client user had no way to
 * find it. Exposing it as a prompt puts it in the client's own prompt picker.
 *
 * The prompt is READ from the shipped file at runtime, never copied into code,
 * so there is one source of truth: editing SKILL.md changes the prompt, and
 * `skill-prompt.test.ts` asserts the served text equals the file's body.
 *
 * Fail-soft by design: the prompt is a convenience, so a missing or malformed
 * skill file (a dev tree, a repackaged install) skips the prompt with one
 * stderr line and never stops the tools from registering.
 */
import { readFileSync } from "node:fs";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

export const SKILL_PROMPT_NAME = "omitly-redaction";

/** Where the shipped skill lives relative to the built `dist/` module. */
export const SKILL_URL = new URL("../skill/SKILL.md", import.meta.url);

export interface ParsedSkill {
  name: string;
  description: string;
  body: string;
}

/**
 * Split a SKILL.md into its frontmatter `name` / `description` and its body.
 * Only the two keys the prompt needs are read; `description` may be a YAML
 * folded block (`>-`), which is all the shipped file uses. Returns undefined
 * for anything that does not look like a skill, so the caller can skip.
 */
export function parseSkill(text: string): ParsedSkill | undefined {
  const m = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/.exec(text);
  if (!m) return undefined;
  const [, front, rest] = m;
  const lines = front.split(/\r?\n/);
  let name = "";
  let description = "";
  for (let i = 0; i < lines.length; i++) {
    const kv = /^([A-Za-z_-]+):\s*(.*)$/.exec(lines[i]);
    if (!kv) continue;
    const [, key, value] = kv;
    let v = value.trim();
    if (/^[>|][+-]?$/.test(v)) {
      const block: string[] = [];
      while (i + 1 < lines.length && /^\s+\S/.test(lines[i + 1])) block.push(lines[++i].trim());
      v = block.join(" ");
    } else {
      v = v.replace(/^(["'])(.*)\1$/, "$2");
    }
    if (key === "name") name = v;
    if (key === "description") description = v;
  }
  // Drop HTML comments: they are maintainer notes (claims-lint suppressions
  // citing internal issues), invisible in a rendered skill, and must not be
  // sent to a customer's model as prompt text.
  const body = rest
    .replace(/^[ \t]*<!--[\s\S]*?-->[ \t]*\r?\n/gm, "")
    .replace(/<!--[\s\S]*?-->/g, "")
    .trim();
  if (!name || !description || !body) return undefined;
  return { name, description, body };
}

/** Read and parse the shipped skill; undefined if absent or malformed. */
export function loadShippedSkill(url: URL = SKILL_URL): ParsedSkill | undefined {
  let text: string;
  try {
    text = readFileSync(url, "utf8");
  } catch {
    return undefined;
  }
  return parseSkill(text);
}

/**
 * Register the skill as the `omitly-redaction` prompt. Returns whether it was
 * registered. The optional `pdfPath` argument is appended as plain text for
 * the model; it is NOT a tool input, so it is not confined here — any tool the
 * model then calls with it goes through paths.ts as usual.
 */
export function registerSkillPrompt(server: McpServer, url: URL = SKILL_URL): boolean {
  const skill = loadShippedSkill(url);
  if (!skill) {
    console.error(`[omitly-mcp] skill prompt not registered: ${url.pathname} missing or not a SKILL.md`);
    return false;
  }
  server.registerPrompt(
    SKILL_PROMPT_NAME,
    {
      title: "Check a PDF before it leaves the machine",
      description: skill.description,
      argsSchema: {
        pdfPath: z
          .string()
          .optional()
          .describe("Local path of the PDF to check (optional; you will be asked if omitted)"),
      },
    },
    ({ pdfPath }) => {
      const p = pdfPath?.trim();
      const text = p
        ? `${skill.body}\n\n---\n\nThe user wants this local PDF checked: ${p}`
        : skill.body;
      return { messages: [{ role: "user" as const, content: { type: "text" as const, text } }] };
    },
  );
  return true;
}
