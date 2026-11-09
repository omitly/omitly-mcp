/**
 * omitly#1641 option (a): the shipped skill is served as an MCP prompt.
 *
 * Driven through the REAL `createServer()` over an in-memory client, so the
 * test proves the wiring, not just the helper. The oracle is the shipped
 * file itself: the served text must equal SKILL.md's body, so the prompt and
 * the skill cannot drift apart.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { pathToFileURL } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { SKILL_PROMPT_NAME, SKILL_URL, parseSkill, registerSkillPrompt } from "./skill-prompt.js";

const tmp = () => realpathSync(mkdtempSync(path.join(tmpdir(), "omitly-skill-prompt-")));

async function connect(server: McpServer): Promise<Client> {
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "skill-prompt-test", version: "0" });
  await Promise.all([server.connect(a), client.connect(b)]);
  return client;
}

test("the real server lists the skill as a prompt and serves SKILL.md's body verbatim", async () => {
  // Keep the client heartbeat out of the real ~/.omitly.
  process.env.OMITLY_STATE_DIR = tmp();
  process.env.OMITLY_ALLOWED_DIR = tmp();
  const { createServer } = await import("./index.js");
  const client = await connect(createServer());

  const shipped = parseSkill(readFileSync(SKILL_URL, "utf8"));
  assert.ok(shipped, "skill/SKILL.md must parse — it ships in the npm tarball");

  const { prompts } = await client.listPrompts();
  const p = prompts.find((x) => x.name === SKILL_PROMPT_NAME);
  assert.ok(p, `prompt ${SKILL_PROMPT_NAME} not listed: ${JSON.stringify(prompts.map((x) => x.name))}`);
  assert.equal(p.description, shipped.description);
  assert.equal(shipped.name, SKILL_PROMPT_NAME, "prompt name must match the skill's frontmatter name");

  const bare = await client.getPrompt({ name: SKILL_PROMPT_NAME, arguments: {} });
  assert.equal(bare.messages.length, 1);
  const msg = bare.messages[0];
  assert.equal(msg.role, "user");
  assert.equal(msg.content.type, "text");
  assert.equal((msg.content as { text: string }).text, shipped.body);
  // Frontmatter and maintainer comments must not leak into the prompt text.
  const served = (msg.content as { text: string }).text;
  assert.ok(!served.startsWith("---"));
  assert.ok(!served.includes("<!--"), "HTML comments (claims-lint notes) must be stripped");
  assert.ok(!served.includes("claims-lint"), "internal lint notes must not reach a customer's model");
  // ...while the rule those notes sit beside is still served.
  assert.ok(served.includes("Never say"), "the banned-phrases rule itself must survive stripping");
  // Everything else is the file, line for line: the served text plus the
  // stripped comment lines reassembles the shipped body.
  const raw = readFileSync(SKILL_URL, "utf8").split(/\r?\n---\r?\n/).slice(1).join("\n---\n");
  const rawLines = raw.trim().split(/\r?\n/).filter((l) => !/^\s*<!--.*-->\s*$/.test(l));
  assert.deepEqual(served.split("\n"), rawLines);

  const withPath = await client.getPrompt({
    name: SKILL_PROMPT_NAME,
    arguments: { pdfPath: "  ~/Desktop/filing.pdf " },
  });
  const t = (withPath.messages[0].content as { text: string }).text;
  assert.ok(t.startsWith(shipped.body));
  assert.ok(t.endsWith("The user wants this local PDF checked: ~/Desktop/filing.pdf"));

  await client.close();
});

test("a missing skill file skips the prompt and leaves the server usable", async () => {
  const server = new McpServer({ name: "t", version: "0" });
  const missing = pathToFileURL(path.join(tmp(), "nope", "SKILL.md"));
  assert.equal(registerSkillPrompt(server, missing), false);
});

test("a malformed skill file (no frontmatter) is skipped, not served half-parsed", async () => {
  const dir = tmp();
  const f = path.join(dir, "SKILL.md");
  writeFileSync(f, "# Just a heading\nno frontmatter\n");
  const server = new McpServer({ name: "t", version: "0" });
  assert.equal(registerSkillPrompt(server, pathToFileURL(f)), false);
});

test("parseSkill reads a folded description and quoted name", () => {
  const s = parseSkill('---\nname: "x"\ndescription: >-\n  one\n  two\n---\n\nBody here.\n');
  assert.deepEqual(s, { name: "x", description: "one two", body: "Body here." });
  assert.equal(parseSkill("---\nname: x\n---\nbody"), undefined, "no description → skip");
  const c = parseSkill("---\nname: x\ndescription: d\n---\nA\n  <!-- note -->\nB <!-- inline --> C\n");
  assert.equal(c?.body, "A\nB  C");
});
