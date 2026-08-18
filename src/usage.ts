/**
 * Free-tier usage metering (omitly#226) — the anti-cannibalization mechanic for
 * the free detection tools.
 *
 * Why this exists: an UNLIMITED free `check_redaction` is a QA oracle usable on
 * any tool's output — redact in Acrobat, iterate against the free Omitly check
 * until clean, never buy the engine. So the free (wasm-served, unlicensed) tier
 * of the two detection tools is capped per calendar month and every free leak
 * report is EVALUATION-marked. `verify_redaction`/`verify_seal` are NEVER
 * capped or marked (category-membership tools; recipient-side ubiquity is the
 * point), and calls served by a configured native engine are not metered here —
 * that user is already in the engine funnel, whose own licence gates apply.
 *
 * Doctrine constraints, enforced by construction:
 *   - NO phone-home. Counting is a local file under OMITLY_STATE_DIR
 *     (default ~/.omitly), written 0600. Nothing here touches the network.
 *   - The counter is honesty infrastructure, not a paywall: deleting
 *     usage.json resets the free count and that is ACCEPTED (the no-network
 *     doctrine makes it unavoidable). What the counter must never do is gate
 *     a paid write — the paid line is the native engine + licence, and this
 *     module is deliberately never consulted by any write tool.
 *   - Metering I/O must never fail a tool call: every filesystem error
 *     degrades to an in-memory count for this process (monotonic — the
 *     in-memory floor keeps the cap enforced within a session even on a
 *     read-only filesystem).
 *
 * State file shape (issue omitly#226):
 *   { "check_calls": { "YYYY-MM": n }, "install_id": "<uuid>", "licensed": false }
 *
 * `licensed` is a forward hook for the licence-UX work (omitly#116/#87): the
 * MCP server cannot verify a licence today, so nothing in this repo sets it
 * true automatically — but a true value skips the cap and the EVALUATION mark,
 * so the field's semantics are settled now rather than migrated later.
 */
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import * as os from "node:os";
import * as path from "node:path";

export const DEFAULT_FREE_CAP = 10;

export interface UsageState {
  check_calls: Record<string, number>;
  install_id: string;
  licensed: boolean;
}

export interface FreeCheckOutcome {
  /** true when this call is past the monthly cap and must be refused */
  capped: boolean;
  /** 1-based count of this month's free checks including this one (0 when licensed) */
  used: number;
  cap: number;
  /** UTC month bucket, YYYY-MM */
  month: string;
}

export function stateDir(): string {
  return process.env.OMITLY_STATE_DIR || path.join(os.homedir(), ".omitly");
}

function usagePath(): string {
  return path.join(stateDir(), "usage.json");
}

/** Cap override (OMITLY_FREE_CAP) exists for tests and deliberate tuning — the
 *  counter is client-side honesty, not a security boundary (see module doc), so
 *  an env override gives away nothing that deleting the state file wouldn't. */
export function freeCap(): number {
  const raw = process.env.OMITLY_FREE_CAP;
  if (raw !== undefined) {
    const n = Number.parseInt(raw, 10);
    if (Number.isFinite(n) && n > 0) return n;
  }
  return DEFAULT_FREE_CAP;
}

/** UTC so the bucket doesn't jump backwards across timezone changes. */
export function monthKey(now: Date = new Date()): string {
  return `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, "0")}`;
}

function freshState(): UsageState {
  return { check_calls: {}, install_id: randomUUID(), licensed: false };
}

/** Corrupt/absent/foreign-shaped state degrades to a fresh state, never a
 *  crash — metering must not be able to break the tools it meters. */
export function loadUsage(): UsageState {
  try {
    const raw = JSON.parse(readFileSync(usagePath(), "utf8")) as unknown;
    if (raw && typeof raw === "object") {
      const r = raw as Record<string, unknown>;
      const calls: Record<string, number> = {};
      if (r.check_calls && typeof r.check_calls === "object") {
        for (const [k, v] of Object.entries(r.check_calls as Record<string, unknown>)) {
          if (/^\d{4}-\d{2}$/.test(k) && typeof v === "number" && Number.isFinite(v) && v >= 0) {
            calls[k] = Math.floor(v);
          }
        }
      }
      return {
        check_calls: calls,
        install_id: typeof r.install_id === "string" && r.install_id ? r.install_id : randomUUID(),
        licensed: r.licensed === true,
      };
    }
  } catch {
    // fall through to fresh
  }
  return freshState();
}

export function saveUsage(state: UsageState): void {
  try {
    mkdirSync(stateDir(), { recursive: true, mode: 0o700 });
    writeFileSync(usagePath(), `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
    // `mode` above only applies when the file is CREATED — re-assert on every
    // write so a pre-existing looser file is tightened too. Windows has no
    // POSIX modes; chmod is a no-op there and the containing profile dir is
    // already per-user.
    chmodSync(usagePath(), 0o600);
  } catch {
    // Best-effort persistence — never fail the tool call over metering I/O.
    // The in-memory floor in recordFreeCheck keeps the cap monotonic for this
    // process even when nothing can be written.
  }
}

/** In-memory monotonic floor per month bucket — keeps the cap enforced within
 *  a process even when the state file is unreadable/unwritable. */
const memCounts: Record<string, number> = {};

/** Test hook: clear the in-memory floor (tests re-point OMITLY_STATE_DIR at
 *  fresh temp dirs; without this the floor would bleed across scenarios). */
export function _resetMemCounts(): void {
  for (const k of Object.keys(memCounts)) delete memCounts[k];
}

/**
 * Record one free detection call (check_redaction / find_sensitive_regions on
 * the wasm-served free tier) and say whether it is past the monthly cap.
 * Counting happens BEFORE the scan runs — an attempt is an attempt.
 */
export function recordFreeCheck(now: Date = new Date()): FreeCheckOutcome {
  const cap = freeCap();
  const month = monthKey(now);
  const state = loadUsage();
  if (state.licensed) {
    return { capped: false, used: 0, cap, month };
  }
  const used = Math.max(state.check_calls[month] ?? 0, memCounts[month] ?? 0) + 1;
  memCounts[month] = used;
  // Keep the file tiny and boring: current month plus the immediately previous
  // one (for "did I really hit the cap last month?" debugging), nothing older.
  const kept: Record<string, number> = { [month]: used };
  const prev = monthKey(new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 1, 1)));
  if (state.check_calls[prev] !== undefined) kept[prev] = state.check_calls[prev];
  state.check_calls = kept;
  saveUsage(state);
  return { capped: used > cap, used, cap, month };
}

/** The structured refusal for a capped call (issue omitly#226's shape). */
export function freeCapRefusal(tool: string, o: FreeCheckOutcome): {
  blocked: true;
  reason: "free-cap";
  tool: string;
  month: string;
  used: number;
  cap: number;
  message: string;
} {
  return {
    blocked: true,
    reason: "free-cap",
    tool,
    month: o.month,
    used: o.used,
    cap: o.cap,
    message:
      `Free-tier limit reached: ${o.cap} free redaction checks per month, counted locally on this machine (nothing is uploaded). ` +
      `The count resets next month. For unlimited checking — plus actual removal, independent verification and a tamper-evident certificate — ` +
      `activate the Omitly engine: https://omitly.app. Verification tools (verify_redaction, verify_seal) remain free and uncapped.`,
  };
}

/** One-line banner prepended to every free (unlicensed, wasm-served) leak
 *  report, pairing with `evaluation: true` in the structured output — so a
 *  free report can't quietly be treated as unlimited production QA. */
export function evaluationBanner(o: FreeCheckOutcome): string {
  return (
    `EVALUATION (free tier) — this report is for evaluation, not production reliance; ` +
    `it is not a removal certificate. Free check ${Math.min(o.used, o.cap)}/${o.cap} this month (counted locally).`
  );
}
