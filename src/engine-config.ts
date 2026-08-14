/**
 * Small pure helpers for engine invocation limits — split out of index.ts so
 * they can be unit tested without importing index.ts itself (which connects
 * an MCP stdio transport as a side effect of module load).
 */

/**
 * Resolve the engine timeout from an env var string, falling back to the
 * default for anything not positive-finite.
 *
 * Must be validated positive-finite, not just truthy: `Number("-1")` is -1,
 * which is truthy (so a bare `|| DEFAULT` never applies the fallback), and
 * Node clamps a negative `setTimeout` delay to ~1ms — SIGKILLing every engine
 * invocation almost immediately. `Number("1e999")` (Infinity) fails the same
 * way. `0` and non-numeric strings are already safe (falsy → default).
 */
export function resolveEngineTimeoutMs(raw: string | undefined, fallback = 120_000): number {
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

/**
 * Cap on accumulated stdout/stderr from a single engine invocation. The
 * elapsed-time timeout alone bounds time, not memory: a runaway/noisy engine
 * streaming fast can grow an unbounded accumulator for the whole timeout
 * window and hit V8's max string length (~512MB) first, throwing an uncaught
 * RangeError inside the stream's `data` handler and crashing the whole MCP
 * server. A legitimate audit/report JSON payload is nowhere near this size.
 */
export const ENGINE_OUTPUT_CAP_BYTES = 8 * 1024 * 1024; // 8 MiB
