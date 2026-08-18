/**
 * Bin-entry smoke test (#540 follow-up).
 *
 * #540's refactor extracted `registerTools`/`createServer` so tests could drive
 * the tools in-process, and gated the actual `server.connect(transport)` behind
 * an `isMainModule` check. That check is the ONLY thing standing between `npx
 * omitly-mcp` and a server that starts, connects nothing, and exits silently —
 * and it is easy to get subtly wrong, because npm/npx/`npm link` install a
 * `bin` as a SYMLINK. Node resolves `import.meta.url` through the symlink but
 * leaves `process.argv[1]` unresolved, so the naive
 * `import.meta.url === pathToFileURL(process.argv[1]).href` is FALSE on the
 * most common real invocation path. Nothing else in CI ever runs the built bin
 * as a process (the other suites import it as a module), so without this test
 * that regression ships un-caught.
 *
 * So: run the BUILT `dist/index.js` through a `node_modules/.bin`-style
 * relative symlink, speak real MCP stdio JSON-RPC to it, and require both the
 * `initialize` handshake and a `tools/list` naming all 11 tools. Direct (non-
 * symlinked) invocation is covered too, so a "fix" that only works via a
 * symlink also fails.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, realpathSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

/** The built bin — this test file lives next to it in `dist/` after `tsc`. */
const DIST_INDEX = path.join(path.dirname(fileURLToPath(import.meta.url)), "index.js");

const EXPECTED_TOOLS = [
  "find_sensitive_regions",
  "locate_text",
  "extract_pdf_text",
  "redact_by_entity",
  "redact_pdf",
  "verify_redaction",
  "verify_seal",
  "verify_document",
  "create_pdf",
  "check_redaction",
  "check_license",
];

interface Handshake {
  serverName: string;
  tools: string[];
  stderr: string;
}

/**
 * Start `node <entry>` as a real child process, run the MCP initialize
 * handshake plus `tools/list` over stdio, and resolve with what came back.
 * Rejects (rather than hanging) if the child produces no response — which is
 * exactly the shape of the bug this guards: a silent no-op exit.
 */
function handshake(entry: string, cwd: string): Promise<Handshake> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [entry], {
      cwd,
      stdio: ["pipe", "pipe", "pipe"],
      env: { ...process.env, OMITLY_ALLOWED_DIR: cwd },
    });

    let stdout = "";
    let stderr = "";
    let serverName: string | undefined;
    let settled = false;

    const timer = setTimeout(() => finish(new Error("timed out waiting for an MCP response")), 20_000);

    function finish(err: Error | null, value?: Handshake) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      child.kill("SIGKILL");
      if (err) reject(err);
      else resolve(value!);
    }

    child.stderr.on("data", (b) => (stderr += String(b)));
    child.stdout.on("data", (b) => {
      stdout += String(b);
      let nl: number;
      while ((nl = stdout.indexOf("\n")) !== -1) {
        const line = stdout.slice(0, nl).trim();
        stdout = stdout.slice(nl + 1);
        if (!line) continue;
        let msg: any;
        try {
          msg = JSON.parse(line);
        } catch {
          continue; // not JSON-RPC — ignore stray output rather than fail
        }
        if (msg.id === 1) {
          if (msg.error) return finish(new Error(`initialize failed: ${JSON.stringify(msg.error)}`));
          serverName = msg.result?.serverInfo?.name;
          child.stdin.write(
            JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n",
          );
          child.stdin.write(
            JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }) + "\n",
          );
        } else if (msg.id === 2) {
          if (msg.error) return finish(new Error(`tools/list failed: ${JSON.stringify(msg.error)}`));
          const tools = (msg.result?.tools ?? []).map((t: any) => t.name);
          return finish(null, { serverName: serverName ?? "", tools, stderr });
        }
      }
    });

    child.on("error", (e) => finish(e));
    child.on("exit", (code, signal) => {
      if (settled) return;
      finish(
        new Error(
          `bin exited (code=${code}, signal=${signal}) without answering MCP — ` +
            `the isMainModule guard almost certainly evaluated false.\nstderr: ${stderr}`,
        ),
      );
    });

    child.stdin.write(
      JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2024-11-05",
          capabilities: {},
          clientInfo: { name: "omitly-mcp-bin-smoke", version: "0.0.0" },
        },
      }) + "\n",
    );
  });
}

function assertHandshake(result: Handshake, label: string) {
  assert.equal(result.serverName, "omitly-mcp", `${label}: unexpected serverInfo.name`);
  for (const name of EXPECTED_TOOLS) {
    assert.ok(result.tools.includes(name), `${label}: tools/list is missing ${name}`);
  }
  assert.equal(result.tools.length, EXPECTED_TOOLS.length, `${label}: unexpected tool count`);
}

/** `realpathSync` because macOS's `$TMPDIR` sits under `/var`, itself a symlink
 *  to `/private/var` — a RELATIVE link computed against the unresolved path
 *  climbs one `..` too few and dangles. */
function tempDir(prefix: string): string {
  return realpathSync(mkdtempSync(path.join(tmpdir(), prefix)));
}

test("the built bin connects stdio when invoked DIRECTLY", async () => {
  const cwd = tempDir("omitly-mcp-bin-direct-");
  assertHandshake(await handshake(DIST_INDEX, cwd), "direct");
});

test("the built bin connects stdio when invoked through an npm-bin-style SYMLINK", async () => {
  // Mirrors what `npm install`/`npx` actually create: a RELATIVE symlink in a
  // sibling `.bin` directory pointing at the package's dist entry.
  const cwd = tempDir("omitly-mcp-bin-symlink-");
  const link = path.join(cwd, "omitly-mcp");
  symlinkSync(path.relative(cwd, realpathSync(DIST_INDEX)), link);
  assertHandshake(await handshake(link, cwd), "symlink");
});
