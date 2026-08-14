#!/usr/bin/env node
/**
 * Copies the wasm detector (../wasm, shipped prebuilt with this package
 * in the parent omitly-mcp package) into ./wasm here, so the MCPB bundle is
 * fully self-contained before `mcpb pack` zips this directory. Cross-platform
 * (no `cp -R` shell dependency) since the bundle declares darwin/win32/linux
 * compatibility.
 */
import { cpSync, existsSync, rmSync } from "node:fs";
import { fileURLToPath } from "node:url";
import * as path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const src = path.join(here, "..", "..", "wasm");
const dest = path.join(here, "..", "wasm");

if (!existsSync(src)) {
  console.error(
    `[mcpb] ../../wasm not found — the wasm bundle ships in wasm/ at the package root ` +
      `(see package.json).`,
  );
  process.exit(1);
}

rmSync(dest, { recursive: true, force: true });
cpSync(src, dest, { recursive: true });
console.log(`[mcpb] copied ${src} -> ${dest}`);
