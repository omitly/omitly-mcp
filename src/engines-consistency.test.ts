/**
 * omitly#633: package.json's declared `engines.node` floor must never claim
 * support for a node version older than what a LOCKED transitive dependency
 * actually requires. This drifted silently once — `@modelcontextprotocol/sdk`
 * pulled in `@hono/node-server` 2.x (node >=20) while `engines.node` still
 * said `>=18` — because nothing compared the two. This test reads both real
 * files (package.json and package-lock.json) and does that comparison, so a
 * future SDK bump that raises a transitive floor again fails loudly here
 * instead of only surfacing as an EBADENGINE warning for a real node-18 user.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const PKG_ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");

function readJson(relPath: string): any {
  return JSON.parse(readFileSync(path.join(PKG_ROOT, relPath), "utf8"));
}

/** Parse a plain `">=N"` engines string into N. Anything else is a shape this
 * check doesn't understand — fail loudly rather than silently pass. */
function minNodeMajor(spec: string): number {
  const m = /^>=\s*(\d+)/.exec(spec.trim());
  if (!m) throw new Error(`engines.node spec "${spec}" is not a plain ">=N" — update this check`);
  return Number(m[1]);
}

test("declared engines.node is not older than the locked @hono/node-server's own floor", () => {
  const pkg = readJson("package.json");
  const lock = readJson("package-lock.json");

  const declared = minNodeMajor(pkg.engines.node);

  const honoEntry = lock.packages?.["node_modules/@hono/node-server"];
  if (!honoEntry) {
    // Not resolved at all in this lockfile (e.g. a stdio-only SDK version
    // that never pulls the HTTP transport) — nothing to compare against.
    return;
  }
  const honoFloor = minNodeMajor(honoEntry.engines.node);

  assert.ok(
    declared >= honoFloor,
    `package.json declares engines.node ">=${declared}" but the locked @hono/node-server@${honoEntry.version} ` +
      `requires node >=${honoFloor} — a node ${declared} user would hit EBADENGINE on install. Bump engines.node.`,
  );
});
