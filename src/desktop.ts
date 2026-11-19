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
 *                         { pid, version, accept_in_app, updated_at, licence? }.
 *                         Fresh = updated within PRESENCE_FRESH_MS. `licence` is
 *                         the app's own coarse licence state (omitly#1870): WORDING
 *                         INPUT ONLY, see DesktopLicence.
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

import { createHash, randomBytes } from "node:crypto";
import {
  closeSync,
  existsSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  readSync,
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

/**
 * omitly#1870: what the desktop app says about its OWN licence, coarsely. It is advisory wording
 * input for the answer to a removal request and nothing else. This server never verifies a licence
 * and nothing here unlocks, enables or skips anything: the desktop app is the only enforcer, and a
 * stale, missing, malformed or hand-edited value can only change the words shown (and, for
 * `trial_over`, make the server DECLINE to queue a proposal the app would refuse to accept anyway,
 * i.e. do less, never more). No name, licence id or email is ever in this field.
 *
 * "unknown" in the file, and anything this parser does not recognise, reads as ABSENT: exactly the
 * behaviour of an app that does not write the field.
 */
export type DesktopLicence =
  | { state: "trial"; daysLeft: number }
  | { state: "trial_over" }
  | { state: "licensed" }
  | { state: "updates_lapsed" };

/** A trial is 14 days; anything above this in the file is not a number this app writes. */
const MAX_TRIAL_DAYS_LEFT = 60;

/** Parse the heartbeat's `licence` value defensively. Anything but a known, well-formed state is
 *  `undefined`. Extra keys are ignored; only own properties are read. */
export function parseDesktopLicence(raw: unknown): DesktopLicence | undefined {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return undefined;
  const own = (k: string): unknown => (Object.prototype.hasOwnProperty.call(raw, k) ? (raw as Record<string, unknown>)[k] : undefined);
  switch (own("state")) {
    case "trial": {
      const d = own("days_left");
      if (typeof d !== "number" || !Number.isInteger(d) || d < 1 || d > MAX_TRIAL_DAYS_LEFT) return undefined;
      return { state: "trial", daysLeft: d };
    }
    case "trial_over":
      return { state: "trial_over" };
    case "licensed":
      return { state: "licensed" };
    case "updates_lapsed":
      return { state: "updates_lapsed" };
    default:
      return undefined;
  }
}

export interface DesktopPresence {
  pid: number;
  version: string;
  accept_in_app: boolean;
  updated_at: string;
  /** The app's own licence state, when it states one (omitly#1870). Wording only. */
  licence?: DesktopLicence;
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
  /**
   * omitly#1890 (D3): lowercase hex SHA-256 of the PDF bytes the AI analysed. For a proposal with
   * coordinates it is the digest of the bytes the scan loaded (the scan's `analysisId`), never a
   * hash taken at enqueue. The desktop hashes the file on disk at Accept and refuses on a mismatch.
   */
  pdfSha256?: string;
  /**
   * Present (and `"at-queue"`) only on a kinds-only proposal (`redact_by_entity`): it carries no
   * coordinates, so there is no scan to bind to, and `pdfSha256` was taken when it was queued.
   */
  binding?: "at-queue";
}

type ProposalBase = Pick<Proposal, "client" | "tool" | "pdfPath" | "outputPath">;

/**
 * A proposal with coordinates must name the scan those coordinates came from. `analysisId` is
 * required here but may be `undefined` at runtime (it comes from an optional tool argument):
 * `enqueueProposal` refuses it then, rather than the type system pretending the model supplied one.
 */
export type ProposalInput = ProposalBase &
  (
    | { regions: ProposalRegion[]; kinds?: undefined; analysisId: string | undefined }
    | { regions?: undefined; kinds?: string[]; analysisId?: undefined }
  );

/** What `enqueueProposal` hands back: the record as written, plus `revision`, the SHA-256 of the
 *  exact bytes written to `proposals/<id>.json` (omitly#1890, X9). */
export interface EnqueuedProposal {
  proposal: Proposal;
  revision: string;
}

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

/** Write-then-rename so a reader never sees a half-written file. 0600. Returns the SHA-256 (lowercase
 *  hex) of the exact bytes written, so a caller can echo the file's revision without re-reading it. */
function writeAtomic(file: string, value: unknown): string {
  ensureDir(path.dirname(file));
  const tmp = `${file}.tmp-${process.pid}-${randomBytes(4).toString("hex")}`;
  const bytes = Buffer.from(JSON.stringify(value, null, 2) + "\n", "utf8");
  writeFileSync(tmp, bytes, { mode: 0o600 });
  renameSync(tmp, file);
  return sha256Hex(bytes);
}

/** Lowercase hex SHA-256 of some bytes. */
export function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

/** Lowercase hex SHA-256 of a file, streamed through a 64 KiB buffer (never the whole file in
 *  memory). Synchronous on purpose: `enqueueProposal` is, and a chunked read loop is still a stream. */
export function sha256OfFile(file: string): string {
  const hash = createHash("sha256");
  const buf = Buffer.allocUnsafe(64 * 1024);
  const fd = openSync(file, "r");
  try {
    for (;;) {
      const n = readSync(fd, buf, 0, buf.length, null);
      if (n === 0) break;
      hash.update(buf.subarray(0, n));
    }
  } finally {
    closeSync(fd);
  }
  return hash.digest("hex");
}

/**
 * omitly#1890 (D3, X4): the document identity a proposal's coordinates are bound to.
 *
 * A scan (`find_sensitive_regions`, `locate_text`) returns an opaque `analysisId`. Here it maps to
 * `{ path, sha256, at }`, where `sha256` is the digest of the bytes the scan ACTUALLY LOADED (the
 * wasm buffer it held, or the native CLI's `inputSha256` of the input it read once), never a hash of
 * the path taken before or after. `enqueueProposal` looks the id up (never the path), refuses an id
 * that is not this call's document, hashes the file now and refuses if it differs, and writes the
 * id's digest into the proposal. So scan A, replace the file with B, scan B, then propose A's
 * coordinates with A's id is refused: B's scan is a different id with a different digest.
 *
 * The map is process-local and bounded: past `ANALYSES_MAX` the oldest id is forgotten (an agent
 * then has to scan again, which is the safe direction).
 */
export const ANALYSES_MAX = 256;
interface Analysis {
  path: string;
  sha256: string;
  at: string;
}
const analyses = new Map<string, Analysis>();
const SHA256_RE = /^[0-9a-f]{64}$/;

/** Register a scan of `confinedPath` whose loaded bytes hash to `sha256`; returns its `analysisId`. */
export function recordAnalysis(confinedPath: string, sha256: string, now: Date = new Date()): string {
  if (!SHA256_RE.test(sha256)) throw new Error("analysis digest is not a SHA-256");
  const id = randomBytes(16).toString("hex");
  analyses.set(id, { path: confinedPath, sha256, at: now.toISOString() });
  while (analyses.size > ANALYSES_MAX) {
    const oldest = analyses.keys().next().value;
    if (oldest === undefined) break;
    analyses.delete(oldest);
  }
  return id;
}

/** `recordAnalysis` for an engine response: `undefined` (no id) when the engine reported no valid
 *  digest, e.g. a native engine older than this server. No id means no proposal can be queued for
 *  that scan, which fails closed. */
export function recordAnalysisOf(confinedPath: string, digest: unknown): string | undefined {
  return typeof digest === "string" && SHA256_RE.test(digest) ? recordAnalysis(confinedPath, digest) : undefined;
}

export const ANALYSIS_REQUIRED_MESSAGE =
  "Scan this document with find_sensitive_regions or locate_text and pass its analysisId before proposing boxes for it.";
export const DOCUMENT_CHANGED_MESSAGE = "The document changed since you looked at it; scan it again.";

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
  const licence = parseDesktopLicence(p.licence);
  return {
    pid: p.pid,
    version: p.version,
    accept_in_app: p.accept_in_app,
    updated_at: p.updated_at as string,
    ...(licence ? { licence } : {}),
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

/**
 * Queue a proposal for the desktop. Returns the record as written and its `revision`.
 *
 * With coordinates (`regions`) the proposal must carry the `analysisId` of the scan they came from
 * (omitly#1890, D3). Nothing is queued, and nothing is written, if the id is missing, unknown,
 * evicted or names another path, or if the file on disk no longer hashes to what that scan loaded.
 * The `pdfSha256` written is the id's digest, never a hash taken now.
 *
 * Without coordinates (`redact_by_entity`, kinds only) there is no scan to bind to: `pdfSha256` is
 * taken now and the record says `binding: "at-queue"`.
 */
export function enqueueProposal(input: ProposalInput, now: Date = new Date()): EnqueuedProposal {
  let pdfSha256: string;
  let atQueue = false;
  if (input.regions !== undefined) {
    const analysis = typeof input.analysisId === "string" ? analyses.get(input.analysisId) : undefined;
    if (!analysis || analysis.path !== input.pdfPath) throw new Error(ANALYSIS_REQUIRED_MESSAGE);
    let onDisk: string;
    try {
      onDisk = sha256OfFile(input.pdfPath);
    } catch {
      throw new Error(DOCUMENT_CHANGED_MESSAGE);
    }
    if (onDisk !== analysis.sha256) throw new Error(DOCUMENT_CHANGED_MESSAGE);
    pdfSha256 = analysis.sha256;
  } else {
    try {
      pdfSha256 = sha256OfFile(input.pdfPath);
    } catch {
      throw new Error("The document could not be read, so nothing was queued.");
    }
    atQueue = true;
  }
  const proposal: Proposal = {
    id: newProposalId(),
    created_at: now.toISOString(),
    client: { name: input.client.name, version: input.client.version },
    tool: input.tool,
    pdfPath: input.pdfPath,
    outputPath: input.outputPath,
    ...(input.regions ? { regions: input.regions } : {}),
    ...(input.kinds ? { kinds: input.kinds } : {}),
    pdfSha256,
    ...(atQueue ? { binding: "at-queue" as const } : {}),
    status: "pending",
  };
  const revision = writeAtomic(path.join(proposalsDir(), `${proposal.id}.json`), proposal);
  return { proposal, revision };
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
