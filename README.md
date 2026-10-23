# omitly-mcp

A [Model Context Protocol](https://modelcontextprotocol.io) server that exposes
Omitly's **local, verifiable PDF redaction** to AI agents (Claude Code, Claude
Desktop, and any other MCP client).

> **Repository scope and licence — please read before opening a PR.**
>
> This repository is **source-available, not open source**. See [`LICENSE`](LICENSE):
> the code is published so you can read exactly what runs on your machine before
> you let it touch a confidential document. It is not licensed for reuse in other
> projects.
>
> It contains the MCP server and the compiled wasm detection bundle. The Omitly
> redaction engine, the tamper-evidence seal and the licensing implementation are
> **not** in this repository and are developed privately; this code calls the
> engine, it does not contain it.
>
> Development happens in a private repository and is mirrored here on release, so
> **pull requests cannot be merged**. Issues and security reports are very welcome
> — see [`SECURITY.md`](SECURITY.md).

The point of difference: an agent can redact a document **without uploading it
anywhere**. Redaction runs on-device through the Omitly engine and returns a
signed audit log recording what was removed; the seal shows the delivered file
is unchanged since it was sealed. It does not show that nothing else sensitive
remains in the document — the opposite of pasting a confidential file into a
chat model.

**Five of the eleven tools (`find_sensitive_regions`, `locate_text`,
`check_redaction`, `verify_redaction`, `extract_pdf_text`) work out of the
box — `npm install`, no Rust toolchain, no native binary, no desktop app.**
They run on a wasm-bindgen build of the same detector that powers the web
leak-checker at omitly.app, bundled directly in this package. `create_pdf`,
the two write tools (`redact_pdf`, `redact_by_entity`), and the two
seal-verification tools (`verify_seal`, `verify_document`) still need a
configured native engine — see "Native engine" below. Neither seal tool has a
wasm fallback yet: there is no wasm seal-verification path (tracked in
issue #113), so both always require the native engine, even though checking
a seal needs no licence.

## Install

Add the server to your MCP client with `npx` — nothing to clone, build or
compile. Published releases ship the wasm detector bundled, so a registry
install never needs Rust.

Claude Code:

```bash
claude mcp add omitly --env OMITLY_ALLOWED_DIR=/path/agents/may/touch -- npx -y omitly-mcp
```

Claude Desktop (`claude_desktop_config.json`), Cursor (`~/.cursor/mcp.json`) and
Windsurf (`~/.codeium/windsurf/mcp_config.json`) take the same entry:

```jsonc
{
  "mcpServers": {
    "omitly": {
      "command": "npx",
      "args": ["-y", "omitly-mcp"],
      "env": { "OMITLY_ALLOWED_DIR": "/path/agents/may/touch" }
    }
  }
}
```

Set `OMITLY_ALLOWED_DIR` to the folder holding the documents you want checked;
without it the server uses the directory it was launched from (see "Access
control"). Claude Desktop users can instead install the one-click `.mcpb`
bundle (see "One-click install for Claude Desktop" below).

Five tools work out of the box. `find_sensitive_regions` and `check_redaction`
are free but EVALUATION-marked and limited to 10 attempts a month, shared
across the two, without a native engine (`OMITLY_FREE_CAP` changes the number);
`locate_text`, `verify_redaction` and `extract_pdf_text` are free with no cap. Redaction (`redact_pdf`, `redact_by_entity`),
`create_pdf` and seal verification need the native engine, which is not
currently distributed outside the source repo (omitly#1405).

## Skill (Claude Code)

The package ships a Claude skill at [`skill/SKILL.md`](./skill/SKILL.md):
plain instructions that tell Claude when to reach for these tools and how to
report results — masked values only, and what the free check does and does not
prove.

Install it for Claude Code (user scope):

```bash
mkdir -p ~/.claude/skills/omitly-redaction
curl -fsSL https://raw.githubusercontent.com/omitly/omitly-mcp/main/skill/SKILL.md \
  -o ~/.claude/skills/omitly-redaction/SKILL.md
```

A project can instead keep the skill under `.claude/skills/omitly-redaction/`.
The skill is instructions only; limits and the free cap are enforced by the
server, not by the skill.

## Tools

| Tool | What it does |
|------|--------------|
| `find_sensitive_regions` | Scans a PDF on-device and returns PII candidates — email/SSN/phone/card plus Australian identifiers (TFN, ABN, ACN, Medicare, Centrelink CRN, IHI, BSB; check-digit validated where a published algorithm exists) — with page + exact coordinates, so the agent selects by entity and never guesses geometry. Best-effort pattern matching, not a compliance assessment. Optional `regions` (`generic`/`us`/`au`) narrows the listed kinds. Free tier (wasm) is EVALUATION-marked and counts toward the shared 10-attempts-a-month cap (see "Licensing"); a configured native engine is not capped. |
| `locate_text` | Resolves literal strings the model supplies (names, addresses — anything regex can't catch) to their page + coordinates. The model does the recognition; the engine does the geometry. |
| `check_redaction` | Audits an ALREADY-redacted PDF and reports whether sensitive text still survives underneath the redaction marks, in prior incremental-update revisions, metadata, AcroForm fields, or attachments — the "did my black boxes actually remove the data?" check, with a coverage report scoping what was inspected. It also returns `verdict` — `safe_to_send`, `needs_review` (with `blocking` for a problem found) or `cannot_verify` — from the same presented-document check the desktop app's "Check any PDF" runs (native `omitly-redact check` or the bundled wasm `check`, one Rust function), with the fixed-copy result sections (what was checked, problems, review, what could not be checked). The full audit v2 report behind the verdict is not returned by this tool; it is available from the engine's `check` command. A verdict is about the check and what it covered (hidden, covered and recoverable content), never a statement that the document is safe. Free tier (wasm) is EVALUATION-marked and counts toward the shared 10-attempts-a-month cap (see "Licensing"); a configured native engine is not capped. |
| `extract_pdf_text` | Extracts a PDF's full text, page by page, PII-MASKED BY DEFAULT so raw sensitive values never flood the model's context window. Each page's `spans` report the CHAR offset (not byte offset) and kind of every masked value, so an agent can still reason about position without seeing the raw value. `masked: false` is a documented, explicit opt-in to raw text. Free, no licence, works out of the box on the bundled wasm engine — a native engine is preferred when available (also enables the `regions` filter; wasm ignores it and scans every pattern). Never renders pages to images. |
| `redact_by_entity` | One-shot: find + filter by kind (`email`/`ssn`/`phone`/`card`/`tfn`/`abn`/`acn`/`medicare`/`crn`/`ihi`/`bsb`) and/or `regions` + redact + verify. The "just scrub the obvious PII" shortcut. |
| `redact_pdf` | Removes the underlying data from given regions of a PDF, verifies nothing survives, writes the redacted file, and returns the audit log. |
| `verify_redaction` | Re-scans an already-redacted PDF and returns the verification verdict — the redaction-completeness check. |
| `verify_seal` | Cryptographically checks a PDF's embedded Omitly audit report and whole-file tamper-evidence seal (seal v1: Ed25519; seal v2, from Omitly 4.0: ML-DSA-87 with ECDSA P-384) — the tamper-evidence check, distinct from `verify_redaction`. **Integrity, not identity:** the signing key rides inside the file (per-install from the desktop app, or one-time for a single output from the engine), so a valid seal means "unchanged since sealed by the holder of this key", never "produced by Omitly" — compare `sealFingerprint` out-of-band for origin. Requires a native engine; no wasm fallback exists. |
| `verify_document` | Recipient trust-verification (omitly#113): the same seal/report check as `verify_seal` — not a survivor re-scan — aimed at someone who *received* a PDF from someone else and wants to confirm the file is unchanged since it was sealed (integrity, not identity — see `verify_seal`), without paying or licensing anything. Free, no licence. Currently requires a native engine like `verify_seal` (no wasm seal-verification path yet). |
| `create_pdf` | Generates a clean PDF from Markdown/HTML on-device, rendered through a real browser engine so it looks printed — instead of writing a throwaway reportlab/LaTeX script. |
| `check_license` | Reports the current licence or trial state — tier, trial days left, the vendor-signed licensee name, which resolution step supplied the licence, and whether it is bound to this machine. Free, takes no arguments, reads no document, and is re-resolved on every call so buy → save licence → call again works without a restart. **Never returns the device fingerprint or the licence file's contents** — device binding is a yes/no. Requires a native engine: the wasm free tier has no licence concept. |
| `propose_redactions` | omitly#1643, bring your own AI: proposes regions for a PERSON to accept in the Omitly desktop app. Writes nothing. Requires the desktop app to be running on this computer; on acceptance the desktop removes, verifies and seals, and the record shows a person decided (`human-desktop`). |
| `get_proposal_status` | Follows a queued proposal: pending, accepted, rejected, applied (with output path and verdict), failed or expired. Free; reads no document. |

### Accept-in-app (omitly#1643)

While the Omitly desktop app is running on the same computer with **Settings → Connect
your AI → "Accept proposals in Omitly"** on (the default), `redact_pdf` and
`redact_by_entity` do not run: they return `{ status: "queued", proposalId }` and the
redaction becomes a **proposal** a person accepts or rejects in the app. On acceptance the
desktop runs its own verified-removal engine, the survivor scan and the seal, and the
sealed record says a person decided (`human-desktop`); this path needs no native engine
on the agent's side. `propose_redactions` is the explicit form of the same thing;
`get_proposal_status` follows the outcome; the person picks the output path in Omitly's own
save dialog (`outputPath` is kept as the client's suggestion). Needs an omitly-mcp release that
knows the channel — an older server writes directly. With no desktop running (or the toggle off),
the write tools behave exactly as before and the record says `mcp-agent` (not
human-reviewed). The two sides talk through files under the state directory
(`OMITLY_STATE_DIR`, else `~/.omitly`: `desktop.json`, `proposals/`, `clients/`) — no
socket, no network. The PDF and the engine stay on this computer; text a client asks for
(for example `extract_pdf_text`) goes to wherever that client's model runs.

## PDF generation (`create_pdf`)

`create_pdf` is served by a **separate** binary, `omitly-pdf`, kept apart from the redaction engine because generation is
a different trust model from verifiable redaction. It renders Markdown (or raw
HTML) through a headless Chromium-family browser (Chrome/Chromium/Edge/Brave;
override with `OMITLY_BROWSER_BIN`) — the same engine family the Omitly app's
webview uses, so output looks printed rather than script-generated. It needs the
native `omitly-pdf` binary, which is not currently distributed (omitly#1405) and
whose source is not in this repository; point `OMITLY_PDF_BIN` at a copy to
enable this tool.

```jsonc
// stdin
{ "command": "create", "outputPath": "/abs/out.pdf",
  "source": "# Hello\n\nBody **markdown**", "format": "markdown", "title": "Hello" }
// stdout
{ "ok": true, "output": "/abs/out.pdf" }
```

Typical agent flows:
- Quick: **`redact_by_entity`** (find + redact + verify in one call).
- Careful: **`find_sensitive_regions` / `locate_text` → review → `redact_pdf` → `verify_redaction`**.
  Coordinates from `find`/`locate` drop straight into `redact` as its `regions` argument.

See [DEMO.md](./DEMO.md) for a full Claude Code walkthrough.

## Status

The MCP surface (eleven tools, schemas, transport), the native engine binary
(`crates/omitly-cli`, built as `omitly-redact`), and the bundled wasm engine
(`crates/leakcheck-wasm`, covering the five free tools without a native
binary) are all implemented and pass end-to-end tests. `find_sensitive_regions`
is a first-pass detector (ASCII patterns, per-show-operator matching): treat
its hits as *candidates for review*, not a completeness guarantee. An LLM can
always supply additional regions directly.

**Privacy of findings.** This server processes files locally and never uploads
them. Every tool result, though, is returned to your MCP client, so it enters
that client's model context and goes wherever the client sends it: "nothing is
uploaded" describes the file, not the results. The detection tools
(`find_sensitive_regions`, `check_redaction`, `verify_redaction`) return a
**masked** preview of each finding (e.g. `•••-••-6789`) rather than the raw
value, and redaction is driven by page + coordinates. `extract_pdf_text` masks
recognised values by default, but `masked: false` is an explicit opt-in under
which raw text appears verbatim in the result and in the model's context.
Masking covers only the recognised pattern kinds (email, SSN, phone, card and
the Australian identifiers): a name, an address or a clause the detector does
not know is returned as ordinary text. `locate_text` hits also carry a
masked preview, but that mask hides all but the last four letters or digits of
whatever text matched, so short or distinctive strings stay partly legible.

### Engine contract (implemented in `crates/omitly-cli`)

The server spawns `OMITLY_REDACT_BIN`, writes a JSON request to stdin, and reads
a JSON response from stdout. Any failure returns `{ "ok": false, "error": "..." }`
(the process still exits 0, so the caller reads `ok` rather than the exit code).

```jsonc
// stdin
{ "command": "find", "pdfPath": "..." }
// stdout
{ "ok": true, "count": 2, "regions": [
  { "page": 0, "x": 250.4, "y": 610.4, "width": 79.2, "height": 14.4, "kind": "ssn", "preview": "•••-••-6789" } ] }
// `preview` is masked — the raw value never leaves the process; redaction is driven by coordinates.
```

```jsonc
// stdin — "masked" omitted ⇒ true (the default); pass "masked": false for the
// documented raw-text opt-in. "regions" narrows detected kinds (generic
// kinds like email/card always apply).
{ "command": "extract_text", "pdfPath": "..." }
// stdout — "spans" offsets are CHAR (not byte) offsets into "text", valid
// against either the masked or the raw text of the same page (masking never
// changes a page's character count). A page whose text could not be fully
// read reports "contentDecoded": false rather than being silently skipped;
// any text that was read is still returned, so treat that page as incomplete.
{ "ok": true, "masked": true, "pages": [
  { "page": 0, "contentDecoded": true,
    "text": "Sensitive sample line: SSN •••-••-6789",
    "spans": [ { "kind": "ssn", "start": 24, "end": 35 } ] } ] }
```

```jsonc
// stdin
{ "command": "redact", "pdfPath": "...", "outputPath": "...",
  "regions": [{ "page": 0, "x": 72, "y": 700, "width": 200, "height": 14, "reason": "PII.SSN" }] }
// stdout — also writes "<outputPath>.audit.json" beside the file
{ "ok": true, "output": "...", "audit": { "verdict": "pass", "regions": [ ... ], "warnings": [], "metadataScrubbed": true } }
```

```jsonc
// stdin — recovers the redacted regions from "<pdfPath>.audit.json"
{ "command": "verify", "pdfPath": "..." }
// stdout — hiddenContent re-checks thumbnails / document actions / embedded
// files on the delivered bytes (omitly#171); any fail flips the verdict
{ "ok": true, "verdict": "pass", "regions": [ ... ], "metadataScrubbed": true,
  "hiddenContent": [ { "class": "thumbnails", "verification": { "result": "pass" } }, ... ] }
```

```jsonc
// stdin — checks the embedded audit report + whole-file seal (v1 or v2), not
// redaction completeness (that's "verify" above)
{ "command": "verify_seal", "pdfPath": "..." }
// stdout — verdict is one of: no_report | seal_invalid |
// seal_unsupported_version | incomplete | verified. seal_unsupported_version
// means this verifier is too old to check the seal at all — sealValid is
// `null` (checked nothing), never true or false; carriesAuditReport flags
// whether the file also carries an Omitly audit report (escalation signal).
// sealRemoved (omitly#1591) is true when the file carries a sealed report but
// no seal at all (typically re-saved in another app) — a reason beside
// seal_invalid or a v2 cannot_verify, never a verdict of its own.
{ "ok": true, "verdict": "verified", "sealValid": true, "sealFingerprint": "...",
  "allPassed": true, "metadataScrubbed": true, "regionCount": 2, "pageCount": 4,
  "warnings": [], "licenseProvenance": null,
  "inputSha256": "...", "outputSha256": "...",
  "sourceFilename": "...", "outputFilename": "..." }
```

```jsonc
// stdin — omitly#1267: the Safe to Send verdict over the file AS PRESENTED
// (the desktop "Check any PDF" check; the bundled wasm `check` returns the
// same object). Free, read-only, no qpdf.
{ "command": "check", "pdfPath": "..." }
// stdout — verdict is one of: safe_to_send | needs_review | cannot_verify;
// "blocking" marks a problem found (e.g. text recoverable under a box).
// These are verdicts about the CHECK, scoped to what it covered
// (result.checked / result.notChecked) — never "the document is safe".
// "report" is the presented audit v2 report, present only when it verified;
// "reason_code" is set only for input_too_large / check_failed.
{ "ok": true, "check": { "verdict": "needs_review", "blocking": true,
  "result": { "state": "needs_review", "summary": "...", "problems": [ { "text": "...", "pages": [1] } ], ... },
  "report": { "schema": "omitly.audit/v2", "release_check": { "mode": "presented", "overall": "unsafe", ... }, ... },
  "reason_code": null } }
```

The MCP tool `verify_document` (omitly#113) shells out to the exact same
`verify_seal` engine command above — it is the recipient-facing name/wording
for the same seal/report integrity check, not a separate engine command.

## Native engine

`create_pdf`, `verify_seal`, `verify_document` and the two write tools
(`redact_pdf`, `redact_by_entity`) always need a native engine configured; the
five free tools use the bundled wasm engine unless one is. The native binaries
(`omitly-redact`, `omitly-pdf`) are not currently distributed outside the source
repo (omitly#1405). Neither seal tool has a wasm fallback, even though checking a
seal carries no licence requirement (see "Licensing" below).

One env var covers both binaries: `OMITLY_ENGINE_DIR` is the directory holding
`omitly-redact` and `omitly-pdf`. Per-binary overrides (`OMITLY_REDACT_BIN`,
`OMITLY_PDF_BIN`) win over the directory when set. When `OMITLY_ENGINE_DIR`
(or `OMITLY_REDACT_BIN`) isn't set, `find_sensitive_regions`, `locate_text`,
`check_redaction`, and `extract_pdf_text` transparently use the bundled wasm
engine instead — same detector, no native binary (`extract_pdf_text`'s
optional `regions` filter is native-only; wasm scans every pattern and notes
that the filter was ignored). `verify_redaction` does too, but with a
narrower check: without a native engine there's no `<path>.audit.json`
sidecar to verify specific regions against, so it falls back to a general
re-scan of the whole file (still useful — a non-empty result still means the
file isn't clean — just not the same rigor as the sidecar-based check).

`find`/`redact` need `qpdf` for the redaction pipeline (`QPDF_BIN` overrides the
PATH lookup). `find` alone (native or wasm) is read-only and works without it.

## Access control

Every path in a tool call comes from the model, so the server confines all
reads and writes to one allowed directory:

- **`OMITLY_ALLOWED_DIR`** — set it in the MCP config (recommended). Without
  it, the directory the server was started in is used.
- Symlinks are resolved before the check, so a link inside the root pointing
  outside it is refused.
- Outputs **never overwrite an existing file** (or its `.audit.json` sidecar);
  the agent is asked to pick a fresh name instead.
- **`OMITLY_ENGINE_TIMEOUT_MS`** (default 120000) — a wedged engine process is
  killed at the deadline instead of hanging the agent's tool call.

These are guardrails against confused-deputy mistakes, not a sandbox against a
hostile local user — see `docs/THREAT-MODEL.md`.

## Licensing

`redact_pdf`/`redact_by_entity` are the write surface, enforced **inside the
engine binary** (not in this server, and not bypassable by the bundled wasm
fallback — wasm never touches these two tools): a Pro or Personal licence
(`OMITLY_LICENSE_FILE`, or the Omitly desktop app's activated licence on the
same machine) runs unmarked; otherwise the shared 14-day trial applies and
the audit output is permanently marked as evaluation output. The redaction
itself is never degraded, and licence checks never touch the network.
`find_sensitive_regions`, `locate_text`, `check_redaction`, `verify_redaction`,
`verify_seal`, `verify_document`, and `extract_pdf_text` are free — and
`locate_text`/`verify_redaction`/`verify_seal`/`verify_document`/`extract_pdf_text`
are free forever with **no cap and no marking** (recipient-side verification and
on-device extraction are the point, not a metered funnel). The two free
*detection* tools (`find_sensitive_regions`, `check_redaction`) on the wasm
tier — i.e. with no native engine configured — are metered (omitly#226):
results carry an `evaluation: true` flag plus an EVALUATION banner, and after
10 attempts a month across the two tools (one shared counter; `OMITLY_FREE_CAP`
changes the number) the tool returns a structured `{ blocked: true, reason: "free-cap" }` refusal
until the month rolls over. The count lives in `~/.omitly/usage.json`
(override the directory with `OMITLY_STATE_DIR`; written 0600) and is
**local-only — nothing ever phones home**; deleting the file resets the free
count, which is accepted (the no-network doctrine makes it unavoidable), and
the counter is deliberately never consulted by any paid write path. An
attempt is counted before the scan runs, so a failed attempt still counts.
Calls served by a configured native engine (licensed or not) are not metered here — that user is in
the engine funnel, where the licence rules above apply. `verify_seal` and
`verify_document` (both native-only) stay free by the same design in
`crates/omitly-cli` (no Pro/Personal licence check on that command path
either — both tools shell out to the identical `verify_seal` engine command).

## One-click install for Claude Desktop (MCPB, free tier only)

`mcpb/` packages the four free/diagnosis tools (`check_redaction`,
`find_sensitive_regions`, `locate_text`, `verify_redaction`) — never the write
tools — as a self-contained [MCPB](https://github.com/anthropics/mcpb) `.mcpb`
extension: no Node/npm/Rust toolchain on the end user's machine, just
"Install Extension…" in Claude Desktop. This is a deliberately smaller,
separate server (`mcpb/server/index.js`) from `dist/index.js` above, so the
bundle can never expose `redact_pdf`/`redact_by_entity`/`create_pdf` even by
accident.

**Download:** [releases.omitly.app/mcp/omitly-leak-check.mcpb](https://releases.omitly.app/mcp/omitly-leak-check.mcpb)
— always the current version (published by `publish-npm.yml` on every real
`omitly-mcp` release; a versioned copy + checksum also live at
[mcp/latest.json](https://releases.omitly.app/mcp/latest.json)). Drag the
downloaded file into Claude Desktop, or use "Install Extension…".

To build the bundle yourself, see "Building from source".

**Not signed** (`mcpb sign` needs a code-signing cert we don't have yet — same
gate as desktop app signing). `mcpb info` on the packed file confirms
`WARNING: Not signed`. Whether Claude Desktop's "Install Extension…" flow
blocks or just warns on an unsigned `.mcpb` has NOT been confirmed against the
real Desktop app in this change (no Desktop GUI in this environment) — that
check is still open, tracked in omitly#225.

## Building from source

Building this repository. A registry install (see "Install") needs none of this.

**The server and the free tools (no native engine):**

```bash
cd omitly-mcp
npm install
npm run build  # plain tsc; the wasm bundle ships prebuilt in wasm/
node dist/index.js
```

This repository ships the compiled wasm bundle in `wasm/`, alongside
`wasm/leakcheck_wasm_bg.wasm.sha256` so you can verify the byte-for-byte
artifact you received. It is the same bundle published in the npm package.
That means `npm install && npm run build && npm test` works here with no Rust
toolchain: `npm run build` is plain `tsc`. The wasm is compiled from the
Omitly detection engine, whose Rust source is not part of this repository
(see "Repository scope" above).

**The native engine binaries** (for `create_pdf`, the seal tools and the write
tools; see "Native engine"):

```bash
# Build and start the MCP server (no Rust toolchain needed)
npm install
npm run build
node dist/index.js

# To enable the native-engine tools as well, point at a directory containing
# the Omitly engine binaries (omitly-redact, omitly-pdf). They are not currently
# distributed (omitly#1405), and their source is not in this repository.
OMITLY_ENGINE_DIR=/abs/path/to/engine node dist/index.js
```

**Registering a local build** with Claude Code:

```bash
claude mcp add omitly -- env \
  OMITLY_ENGINE_DIR=/path/to/engine-dir \
  OMITLY_ALLOWED_DIR=/path/agents/may/touch \
  node /abs/path/to/omitly-mcp/dist/index.js
```

or in Claude Desktop's `claude_desktop_config.json`:

```jsonc
{
  "mcpServers": {
    "omitly": {
      "command": "node",
      "args": ["/abs/path/to/omitly-mcp/dist/index.js"],
      "env": {
        "OMITLY_ENGINE_DIR": "/path/to/engine-dir",
        "OMITLY_ALLOWED_DIR": "/path/agents/may/touch"
      }
    }
  }
}
```

**The MCPB bundle:**

```bash
npm run mcpb:pack   # copy wasm/ into mcpb/wasm + npm install + mcpb pack
                     # → dist-mcpb/omitly-leak-check.mcpb
```

`mcpb:pack` needs no Rust toolchain — it reuses the prebuilt `wasm/` in this repository
(builds the shared wasm detector once, then copies it into `mcpb/` — see
`mcpb/scripts/copy-wasm.mjs`). The packed `.mcpb` itself needs nothing but
Node, already bundled inside Claude Desktop.
