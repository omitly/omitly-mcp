/**
 * omitly#1642 — the desktop proposal channel.
 *
 * The MCP server and the Omitly desktop app share the state directory
 * (`OMITLY_STATE_DIR`, else `~/.omitly` — the same place as `usage.json` and the
 * licence import inbox). They never open a socket: a legal customer's promise
 * is "no outbound request unless the user asks for one", and a localhost
 * listener would be a new, unauthenticated surface to defend. Files are the
 * whole protocol:
 *
 *   desktop.json          written by the desktop every ~15 s while it runs:
 *                         { pid, version, accept_in_app, updated_at }.
 *                         Fresh = updated within PRESENCE_FRESH_MS.
 *   proposals/<id>.json   written HERE when a redaction write arrives while the
 *                         desktop is present with accept-in-app on. The desktop
 *                         rewrites the same file with its decision.
 *   clients/<slug>.json   written HERE on initialize and every ~20 s so the
 *                         desktop's Connect panel can list connected clients.
 *
 * Doctrine (omitly.md): "human decides, tool proves" — a queued proposal is not
 * a redaction. Nothing is written to any PDF by this module; the desktop runs
 * the verified-removal core after a person accepts, and the sealed record then
 * says `human-desktop`. A stale or absent heartbeat means "no desktop", and the
 * caller falls back to today's direct, `mcp-agent`-labelled behaviour.
 *
 * Client identity (the MCP initialize `clientInfo`) goes into the proposal file
 * and the desktop's LOCAL run log only — never into the sealed report (cert v2
 * threat T7: "which agent flagged what" is work-product the receiving party is
 * not entitled to).
 */

import { randomBytes } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import * as path from "node:path";

import { stateDir } from "./usage.js";

/** A desktop heartbeat older than this is treated as "no desktop running". */
export const PRESENCE_FRESH_MS = 45_000;
/** How often this server refreshes its own client heartbeat. */
export const CLIENT_HEARTBEAT_MS = 20_000;

export interface DesktopPresence {
  pid: number;
  version: string;
  accept_in_app: boolean;
  updated_at: string;
}

export interface ProposalClient {
  name: string;
  version: string;
}

export type ProposalTool = "redact_pdf" | "redact_by_entity";

export type ProposalStatus = "pending" | "accepted" | "rejected" | "applied" | "failed" | "expired";

export interface ProposalRegion {
  page: number;
  x: number;
  y: number;
  width: number;
  height: number;
  reason?: string;
}

export interface Proposal {
  id: string;
  created_at: string;
  client: ProposalClient;
  tool: ProposalTool;
  /** Confined by the caller (paths.ts) before it reaches here. */
  pdfPath: string;
  /** Recorded as the client's suggestion. The desktop chooses the real output
   * path through its own save dialog (its output-name template), so the person
   * confirms every write and ApprovedWritePaths is untouched by this channel. */
  outputPath: string;
  regions?: ProposalRegion[];
  kinds?: string[];
  status: ProposalStatus;
  resolved_at?: string;
  output?: string | null;
  verdict?: string | null;
  note?: string | null;
}

export type ProposalInput = Pick<Proposal, "client" | "tool" | "pdfPath" | "outputPath" | "regions" | "kinds">;

const ID_RE = /^[0-9a-f]{24}$/;
const PROPOSAL_STATUSES: ReadonlySet<string> = new Set(["pending", "accepted", "rejected", "applied", "failed", "expired"]);

export function proposalsDir(): string {
  return path.join(stateDir(), "proposals");
}

export function clientsDir(): string {
  return path.join(stateDir(), "clients");
}

function presencePath(): string {
  return path.join(stateDir(), "desktop.json");
}

/** 0700 directories, so another local user cannot read a proposal's paths. */
function ensureDir(dir: string): void {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
}

/** Write-then-rename so a reader never sees a half-written file. 0600. */
function writeAtomic(file: string, value: unknown): void {
  ensureDir(path.dirname(file));
  const tmp = `${file}.tmp-${process.pid}-${randomBytes(4).toString("hex")}`;
  writeFileSync(tmp, JSON.stringify(value, null, 2) + "\n", { mode: 0o600 });
  renameSync(tmp, file);
}

function readJson(file: string): unknown {
  try {
    return JSON.parse(readFileSync(file, "utf8"));
  } catch {
    return null;
  }
}

function isFresh(updatedAt: unknown, now: number, windowMs: number): boolean {
  if (typeof updatedAt !== "string") return false;
  const t = Date.parse(updatedAt);
  if (!Number.isFinite(t)) return false;
  // A heartbeat from the "future" (clock skew) is still a live heartbeat.
  return now - t <= windowMs;
}

/** The desktop's heartbeat, or null when it is missing, malformed or stale. */
export function readDesktopPresence(now: number = Date.now()): DesktopPresence | null {
  const raw = readJson(presencePath());
  if (!raw || typeof raw !== "object") return null;
  const p = raw as Record<string, unknown>;
  if (typeof p.pid !== "number" || typeof p.version !== "string" || typeof p.accept_in_app !== "boolean") {
    return null;
  }
  if (!isFresh(p.updated_at, now, PRESENCE_FRESH_MS)) return null;
  return {
    pid: p.pid,
    version: p.version,
    accept_in_app: p.accept_in_app,
    updated_at: p.updated_at as string,
  };
}

/** True when a redaction write must become a proposal instead of running. */
export function acceptInApp(now: number = Date.now()): boolean {
  const p = readDesktopPresence(now);
  return p !== null && p.accept_in_app;
}

export function newProposalId(): string {
  return randomBytes(12).toString("hex");
}

/** Queue a proposal for the desktop. Returns the record as written. */
export function enqueueProposal(input: ProposalInput, now: Date = new Date()): Proposal {
  const proposal: Proposal = {
    id: newProposalId(),
    created_at: now.toISOString(),
    client: { name: input.client.name, version: input.client.version },
    tool: input.tool,
    pdfPath: input.pdfPath,
    outputPath: input.outputPath,
    ...(input.regions ? { regions: input.regions } : {}),
    ...(input.kinds ? { kinds: input.kinds } : {}),
    status: "pending",
  };
  writeAtomic(path.join(proposalsDir(), `${proposal.id}.json`), proposal);
  return proposal;
}

/** Read one proposal by id. Unknown or malformed ids read as null — the id is
 *  the only path component a caller controls, so it is validated, never joined. */
export function readProposal(id: string): Proposal | null {
  if (!ID_RE.test(id)) return null;
  const raw = readJson(path.join(proposalsDir(), `${id}.json`));
  if (!raw || typeof raw !== "object") return null;
  const p = raw as Record<string, unknown>;
  if (p.id !== id || typeof p.status !== "string" || !PROPOSAL_STATUSES.has(p.status)) return null;
  return p as unknown as Proposal;
}

/** Every proposal on disk, oldest first (the desktop's queue view). */
export function listProposals(): Proposal[] {
  const dir = proposalsDir();
  if (!existsSync(dir)) return [];
  const out: Proposal[] = [];
  for (const name of readdirSync(dir)) {
    if (!name.endsWith(".json")) continue;
    const p = readProposal(name.slice(0, -".json".length));
    if (p) out.push(p);
  }
  return out.sort((a, b) => a.created_at.localeCompare(b.created_at));
}

function clientSlug(name: string): string {
  const s = name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40);
  return s || "client";
}

/** Record this server's client (the MCP initialize `clientInfo`) so the desktop
 *  can show "connected clients". Harmless if the desktop never reads it. */
/** One file per server PROCESS: two servers for the same client (two windows)
 *  must not clear each other's heartbeat on close. Stale files age out. */
function clientFile(client: ProposalClient): string {
  return path.join(clientsDir(), `${clientSlug(client.name)}-${process.pid}.json`);
}

export function writeClientHeartbeat(client: ProposalClient, now: Date = new Date()): string {
  const file = clientFile(client);
  writeAtomic(file, {
    name: client.name,
    version: client.version,
    pid: process.pid,
    updated_at: now.toISOString(),
  });
  return file;
}

/** Remove this server's client heartbeat on shutdown (best effort). */
export function clearClientHeartbeat(client: ProposalClient): void {
  try {
    rmSync(clientFile(client), { force: true });
  } catch {
    // best effort
  }
}

/** Start the periodic client heartbeat. The timer is unref'd so it never keeps
 *  the process alive. `tick` writes immediately (call it from `oninitialized`,
 *  when `clientInfo` first becomes known); `stop` clears the timer and the file. */
export function startClientHeartbeat(
  getClient: () => ProposalClient | undefined,
  intervalMs: number = CLIENT_HEARTBEAT_MS,
): { tick: () => void; stop: () => void } {
  const tick = () => {
    const c = getClient();
    if (c) {
      try {
        writeClientHeartbeat(c);
      } catch {
        // The state dir may be unwritable (read-only home); the channel is
        // optional, so never let a heartbeat failure break a tool call.
      }
    }
  };
  tick();
  const timer = setInterval(tick, intervalMs);
  timer.unref();
  return {
    tick,
    stop: () => {
      clearInterval(timer);
      const c = getClient();
      if (c) clearClientHeartbeat(c);
    },
  };
}
