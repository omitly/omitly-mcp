/**
 * omitly#1857: the "Open in Omitly" action behind the MCP Apps result card.
 *
 * The desktop app has no URL scheme. It does handle macOS file-open events
 * (`RunEvent::Opened`, omitly#503, with its own approval rule in src-tauri/src/lib.rs), so the
 * server asks the OS to open one PDF in the app: `open -a Omitly -- <path>`.
 *
 * `open_in_omitly` must never become a general launcher, so it is narrow on purpose:
 *  - it is an APP-ONLY tool (`_meta.ui.visibility: ["app"]`), listed and callable only by a
 *    client that advertises the MCP Apps extension (see `uiCapable` in index.ts);
 *  - it opens ONLY a `pdfPath` this process has already returned a card-linked result for
 *    (`CardPathAllowlist`, newest 64), and re-confines it to the allowed folder first;
 *  - it runs `execFile("open", ["-a", "Omitly", "--", path])`: no shell, no string building;
 *  - it only opens a window and writes nothing, so a repeat is harmless; every call is
 *    logged to stderr with a time and a basename only.
 */
import { execFile } from "node:child_process";
import * as path from "node:path";

/** How many card-linked paths the server remembers per connection. */
export const CARD_PATH_CAP = 64;

/** The `pdfPath` values this server has returned a card-linked result for, newest first,
 *  capped. A path leaves the list when 64 newer ones arrive. */
export class CardPathAllowlist {
  private readonly paths: string[] = [];
  constructor(private readonly cap = CARD_PATH_CAP) {}

  /** Remember `p`; a repeat moves it to the front. */
  remember(p: string): void {
    const i = this.paths.indexOf(p);
    if (i !== -1) this.paths.splice(i, 1);
    this.paths.unshift(p);
    if (this.paths.length > this.cap) this.paths.length = this.cap;
  }

  has(p: string): boolean {
    return this.paths.includes(p);
  }

  get size(): number {
    return this.paths.length;
  }
}

/** How the server asks the OS to open a file in Omitly. Injectable for tests. */
export interface FileOpener {
  /** False where v1 cannot open the app (anything but macOS). */
  readonly supported: boolean;
  open(confinedPath: string): Promise<void>;
}

type ExecFileFn = (
  file: string,
  args: readonly string[],
  options: { timeout: number },
  cb: (err: Error | null) => void,
) => unknown;

/** macOS: `open -a Omitly -- <path>`. Elsewhere: unsupported (v1). */
export function systemOpener(
  platform: NodeJS.Platform = process.platform,
  exec: ExecFileFn = execFile as unknown as ExecFileFn,
): FileOpener {
  if (platform !== "darwin") {
    return { supported: false, open: () => Promise.reject(new Error("not supported on this platform")) };
  }
  return {
    supported: true,
    open: (confinedPath) =>
      new Promise<void>((resolve, reject) => {
        // `--` ends option parsing, so a path can never be read as a flag.
        exec("open", ["-a", "Omitly", "--", confinedPath], { timeout: 10_000 }, (err) =>
          err ? reject(err) : resolve(),
        );
      }),
  };
}

/** A log-safe basename: control characters stripped, length capped. */
export function logName(p: string): string {
  const base = path.basename(String(p)).replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, "?");
  return base.length > 120 ? `${base.slice(0, 120)}…` : base;
}

/** One stderr line per call: the time and the file's basename, nothing else. */
export function logOpen(p: string, now: Date = new Date(), write: (s: string) => void = (s) => process.stderr.write(s)): void {
  write(`[omitly-mcp] open_in_omitly ${now.toISOString()} ${logName(p)}\n`);
}
