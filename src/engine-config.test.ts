import assert from "node:assert/strict";
import { test } from "node:test";
import { resolveEngineTimeoutMs, ENGINE_OUTPUT_CAP_BYTES } from "./engine-config.js";

test("resolveEngineTimeoutMs falls back to the default for non-positive-finite input", () => {
  assert.equal(resolveEngineTimeoutMs(undefined), 120_000);
  assert.equal(resolveEngineTimeoutMs("abc"), 120_000);
  assert.equal(resolveEngineTimeoutMs("0"), 120_000);
  // Negative is truthy as a Number, so a bare `|| DEFAULT` would miss it —
  // this is the regression case: OMITLY_ENGINE_TIMEOUT_MS=-1 must not survive.
  assert.equal(resolveEngineTimeoutMs("-1"), 120_000);
  // Infinity ("1e999" overflows to Infinity) must also be rejected.
  assert.equal(resolveEngineTimeoutMs("1e999"), 120_000);
});

test("resolveEngineTimeoutMs honours a valid positive override", () => {
  assert.equal(resolveEngineTimeoutMs("5000"), 5000);
  assert.equal(resolveEngineTimeoutMs("0.5"), 0.5);
});

test("resolveEngineTimeoutMs respects a custom fallback", () => {
  assert.equal(resolveEngineTimeoutMs("-1", 30_000), 30_000);
});

test("ENGINE_OUTPUT_CAP_BYTES is a sane positive bound", () => {
  assert.ok(ENGINE_OUTPUT_CAP_BYTES > 0);
  assert.ok(ENGINE_OUTPUT_CAP_BYTES < 1024 * 1024 * 1024, "must be well under V8's max string length");
});
