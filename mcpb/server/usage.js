/**
 * Free-tier usage metering (omitly#226) — CJS mirror of ../../src/usage.ts for
 * the MCPB bundle server, which is deliberately a separate, smaller CommonJS
 * program (see index.js's module doc). Keep the two in behavioural lockstep:
 * same state file, same shape, same cap semantics — a user who hits the cap in
 * Claude Desktop and switches to `npx omitly-mcp` (or vice versa) shares one
 * local count.
 *
 * Doctrine (same as the TS twin): NO phone-home — counting is a local file
 * under OMITLY_STATE_DIR (default ~/.omitly), written 0600; deleting it resets
 * the free count and that is accepted; metering I/O must never fail a tool
 * call (all errors degrade to an in-memory monotonic floor for this process);
 * and this module is never consulted by any write tool — the paid line is the
 * native engine + licence, not this counter.
 */
"use strict";

const { chmodSync, mkdirSync, readFileSync, writeFileSync } = require("node:fs");
const { randomUUID } = require("node:crypto");
const os = require("node:os");
const path = require("node:path");

const DEFAULT_FREE_CAP = 10;

function stateDir() {
  return process.env.OMITLY_STATE_DIR || path.join(os.homedir(), ".omitly");
}

function usagePath() {
  return path.join(stateDir(), "usage.json");
}

function freeCap() {
  const raw = process.env.OMITLY_FREE_CAP;
  if (raw !== undefined) {
    const n = Number.parseInt(raw, 10);
    if (Number.isFinite(n) && n > 0) return n;
  }
  return DEFAULT_FREE_CAP;
}

function monthKey(now) {
  const d = now || new Date();
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, "0")}`;
}

function freshState() {
  return { check_calls: {}, install_id: randomUUID(), licensed: false };
}

function loadUsage() {
  try {
    const raw = JSON.parse(readFileSync(usagePath(), "utf8"));
    if (raw && typeof raw === "object") {
      const calls = {};
      if (raw.check_calls && typeof raw.check_calls === "object") {
        for (const [k, v] of Object.entries(raw.check_calls)) {
          if (/^\d{4}-\d{2}$/.test(k) && typeof v === "number" && Number.isFinite(v) && v >= 0) {
            calls[k] = Math.floor(v);
          }
        }
      }
      return {
        check_calls: calls,
        install_id: typeof raw.install_id === "string" && raw.install_id ? raw.install_id : randomUUID(),
        licensed: raw.licensed === true,
      };
    }
  } catch {
    // fall through to fresh
  }
  return freshState();
}

function saveUsage(state) {
  try {
    mkdirSync(stateDir(), { recursive: true, mode: 0o700 });
    writeFileSync(usagePath(), `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
    // `mode` only applies at creation — re-assert so a pre-existing looser
    // file is tightened. No-op semantics on Windows (no POSIX modes there).
    chmodSync(usagePath(), 0o600);
  } catch {
    // Best-effort — never fail the tool call over metering I/O.
  }
}

/** In-memory monotonic floor per month — keeps the cap enforced within a
 *  process even when the state file is unreadable/unwritable. */
const memCounts = {};

/** Test hook. */
function _resetMemCounts() {
  for (const k of Object.keys(memCounts)) delete memCounts[k];
}

function recordFreeCheck(now) {
  const cap = freeCap();
  const month = monthKey(now);
  const state = loadUsage();
  if (state.licensed) {
    return { capped: false, used: 0, cap, month };
  }
  const used = Math.max(state.check_calls[month] || 0, memCounts[month] || 0) + 1;
  memCounts[month] = used;
  const kept = { [month]: used };
  const d = now || new Date();
  const prev = monthKey(new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() - 1, 1)));
  if (state.check_calls[prev] !== undefined) kept[prev] = state.check_calls[prev];
  state.check_calls = kept;
  saveUsage(state);
  return { capped: used > cap, used, cap, month };
}

function freeCapRefusal(tool, o) {
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
      `activate the Omitly engine: https://omitly.app. Verification tools (verify_redaction) remain free and uncapped.`,
  };
}

function evaluationBanner(o) {
  return (
    `EVALUATION (free tier) — this report is for evaluation, not production reliance; ` +
    `it is not a removal certificate. Free check ${Math.min(o.used, o.cap)}/${o.cap} this month (counted locally).`
  );
}

module.exports = {
  DEFAULT_FREE_CAP,
  stateDir,
  freeCap,
  monthKey,
  loadUsage,
  saveUsage,
  recordFreeCheck,
  freeCapRefusal,
  evaluationBanner,
  _resetMemCounts,
};
