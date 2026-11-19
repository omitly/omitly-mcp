/**
 * omitly#1857: the result card's browser entry. Bundled by scripts/build-view.mjs into the
 * single self-contained page the server serves as `ui://omitly/result-card.html`; it is NOT
 * part of the tsc build (see tsconfig.json "exclude" and tsconfig.view.json).
 *
 * The host's CSP is `connect-src 'none'`, so nothing here fetches anything: the card reads
 * the tool input and result the host hands it (`ontoolinput`, `ontoolresult`) and renders
 * them with the pure functions in result-card.ts. Its one action, "Open in Omitly", calls
 * the app-only `open_in_omitly` tool through the host.
 */
import { App } from "@modelcontextprotocol/ext-apps/app-with-deps";
import {
  deviceNounFor,
  initialViewState,
  mayOpen,
  modelFor,
  onOpenReply,
  onToggle,
  onToolInput,
  onToolResult,
  renderCardHtml,
  type ToolInputLike,
  type ToolResultLike,
} from "./result-card.js";

const root = document.getElementById("root") as HTMLElement;
const version = document.querySelector('meta[name="omitly-version"]')?.getAttribute("content") ?? "";
const platform = navigator.platform || navigator.userAgent || "";

// Per-call state lives in one reducer-managed value (result-card.ts): a new tool input clears the
// previous result, section toggles and note, so a reused view never shows an old verdict.
let state = initialViewState();
let lastOpenCall: number | null = null;
// v1 opens a file with macOS's `open`: other hosts do not get the button. The server may
// also say "unsupported" on the first click, which hides it too.
let serverUnsupported = false;

function render(focusKey?: string): void {
  const model = modelFor(state, {
    version,
    deviceNoun: deviceNounFor(platform),
    now: new Date(),
    canOpen: /mac/i.test(platform) && !serverUnsupported,
  });
  root.innerHTML = renderCardHtml(model, { buttonNote: state.note });
  if (focusKey) (root.querySelector(`[data-toggle="${focusKey}"]`) as HTMLElement | null)?.focus();
}

function applyTheme(theme: unknown): void {
  const el = document.documentElement;
  if (theme === "dark" || theme === "light") el.setAttribute("data-theme", theme);
  else el.removeAttribute("data-theme"); // no host theme: follow prefers-color-scheme
}

const app = new App({ name: "omitly-result-card", version: version || "0" }, {});

root.addEventListener("click", (e) => {
  const btn = (e.target as Element | null)?.closest("button");
  if (!btn) return;
  const key = btn.getAttribute("data-toggle");
  if (key) {
    state = onToggle(state, key, btn.getAttribute("aria-expanded") !== "true");
    render(key);
    return;
  }
  if (btn.getAttribute("data-action") !== "open") return;
  const now = Date.now();
  if (!mayOpen(e.detail, now, lastOpenCall)) return;
  const pdfPath = state.toolInput?.arguments?.pdfPath;
  if (typeof pdfPath !== "string") return;
  lastOpenCall = now;
  const generation = state.generation;
  void app
    .callServerTool({ name: "open_in_omitly", arguments: { pdfPath } })
    .then((res) => {
      const status = (res.structuredContent as { status?: unknown } | undefined)?.status;
      if (status === "unsupported") serverUnsupported = true;
      state = onOpenReply(state, generation, res.isError ? "Could not open Omitly." : "");
    })
    .catch(() => {
      state = onOpenReply(state, generation, "Could not open Omitly.");
    })
    .finally(() => render());
});

app.ontoolinput = (params) => {
  state = onToolInput(state, params as ToolInputLike);
  render();
};
app.ontoolresult = (result) => {
  state = onToolResult(state, result as ToolResultLike);
  render();
};
app.onhostcontextchanged = (ctx) => {
  applyTheme((ctx as { theme?: unknown }).theme);
};

render();
app
  .connect()
  .then(() => applyTheme(app.getHostContext()?.theme))
  .catch(() => {
    /* Not inside a host (a plain browser tab): the empty card stays. */
  });
