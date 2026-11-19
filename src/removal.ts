/**
 * Result texts for a REMOVAL request over MCP (omitly#1861, #1860, #1866).
 *
 * Pure functions of what this server can observe: whether a native engine is
 * configured (index.ts `ENGINE_BIN`) and the desktop app's heartbeat
 * (`readDesktopPresence()`: running, and whether accept-in-app is on). They
 * hold no state and do no I/O, so the texts are unit-tested directly.
 *
 * Every text is complete on its own: many clients show no card. The tagged
 * link appears ONLY in the answers to a removal request that cannot proceed:
 * `removalNeedsAppText` (no engine, no running app; omitly#1860) and
 * `removalTrialOverText` (the running app says its trial has ended; omitly#1870).
 * No scan result, no verify result and no skill text carries it or any licence
 * state.
 *
 * What this server cannot do: tell "trial over" from "licensed" itself. It never
 * verifies a licence. Since omitly#1870 the desktop app states its own coarse
 * licence state in its heartbeat (`presence.licence`), and these texts use that
 * statement as WORDING INPUT ONLY: a missing, stale, malformed or unknown value
 * reads as absent and gives exactly the texts below that do not mention it. The
 * app stays the only enforcer; nothing read here can unlock or skip anything.
 *
 * Wording rules: plain and factual; never imply a scan proves a file is fully
 * redacted; nothing was removed is stated first, so an agent cannot report a
 * removal that did not happen.
 */
import type { DesktopLicence, DesktopPresence } from "./desktop.js";
import { OMITLY_SITE_URL } from "./usage.js";

/**
 * The trial's terms (owner decision, 12 November 2026): "free to try for 14 days or 5
 * redacted documents, whichever comes first". This package cannot import the Rust
 * constants, so they are written here once and every text below is built from them;
 * `scripts/trial-terms-parity.test.mjs` fails if they stop matching `TRIAL_DAYS` /
 * `TRIAL_DOCUMENTS` in `crates/licensing/src/policy.rs`.
 */
export const TRIAL_DAYS = 14;
export const TRIAL_DOCUMENTS = 5;
export const TRIAL_TERMS = `${TRIAL_DAYS} days or ${TRIAL_DOCUMENTS} redacted documents, whichever comes first`;

/** The one short sentence for pipeline users; kept last, never the lead. */
const PIPELINE_SENTENCE =
  "If this is a pipeline with its own engine, set OMITLY_ENGINE_DIR to the folder that holds omitly-redact.";

/** Where the accept-in-app switch is, as the desktop app labels it. */
export const ACCEPT_SWITCH_PATH = "Settings → Connect your AI → \"Accept proposals in Omitly\"";

/** Where the desktop app checks a seal, as the app labels it. */
export const APP_VERIFY_PATH = "Home → \"Verify a redacted PDF\"";

/** True when the running app has said its trial is over (omitly#1870). Wording input only. */
export function isTrialOver(presence: DesktopPresence | null): boolean {
  return presence?.licence?.state === "trial_over";
}

/** The running desktop app says its trial has ended. Nothing was removed and the request was not
 *  queued: the app would refuse to accept it (its redaction gate is closed), so a queued proposal
 *  would sit pending, unacceptable, until it expired. The one place, besides the no-app text, that
 *  carries the tagged link: this is the answer to a removal request. */
export function removalTrialOverText(): string {
  return (
    "Nothing was removed. The Omitly desktop app is running, but its free trial has ended " +
    `(${TRIAL_TERMS}), and removing data from a PDF needs an Omitly licence.\n` +
    `Get a licence: ${OMITLY_SITE_URL}\n` +
    "Once a licence is activated in Omitly (About Omitly → Licence), ask again."
  );
}

/** One short factual clause for a queued proposal while the app is in its trial. No link. Empty
 *  for every other state, including an absent one. */
export function trialClause(licence: DesktopLicence | undefined): string {
  if (licence?.state !== "trial") return "";
  const n = licence.daysLeft;
  // The heartbeat note carries the days, not the documents, so say only what is always true
  // of the trial about them.
  return ` Omitly is in its free trial, ${n} ${n === 1 ? "day" : "days"} left; the trial also ends after ${TRIAL_DOCUMENTS} redacted documents.`;
}

/** No engine configured and the desktop app is not running. */
export function removalNeedsAppText(): string {
  return (
    "Nothing was removed. Removing data from a PDF is done by the Omitly desktop app on this " +
    "computer, and it is not running.\n" +
    `Omitly is free to try for ${TRIAL_TERMS}: ${OMITLY_SITE_URL}\n` +
    "If Omitly is already installed, open it and ask again.\n" +
    PIPELINE_SENTENCE
  );
}

/** No engine configured; the desktop app is running with accept-in-app off. */
export function removalSwitchOffText(): string {
  return (
    "Nothing was removed. The Omitly desktop app is running, but the switch that lets it " +
    "receive requests from an AI is off. The person can turn it on in Omitly under " +
    `${ACCEPT_SWITCH_PATH}, then ask again.`
  );
}

/** The app became ready between the caller's queue attempt and this text. */
export function removalNowReadyText(): string {
  return "Nothing was removed. The Omitly desktop app is now running and ready to receive requests from an AI. Ask again.";
}

/** Text for a removal write (`redact_pdf`, `redact_by_entity`) that cannot be queued and has
 *  no engine to run on. The caller has already tried the queue. Three cases, decided by the
 *  heartbeat read passed in: no app; app with accept-in-app off; app with accept-in-app on (the
 *  app became ready after the queue attempt, so asking again will queue). */
export function removalUnavailableText(presence: DesktopPresence | null): string {
  if (!presence) return removalNeedsAppText();
  // Turning the switch on, or asking again, would only reach the same refusal.
  if (isTrialOver(presence)) return removalTrialOverText();
  return presence.accept_in_app ? removalNowReadyText() : removalSwitchOffText();
}

/** `propose_redactions` when the proposal cannot be queued. With an engine configured the
 *  direct write is a real option; without one it is a dead end and is not offered. */
export function proposeUnavailableText(presence: DesktopPresence | null, engineConfigured: boolean): string {
  // Trial over: nothing can be queued for acceptance, whichever way the switch is set. With an
  // engine configured and the switch off the direct write below is the engine's own (it checks its
  // own licence), so that case is left exactly as it was.
  if (isTrialOver(presence) && (presence?.accept_in_app || !engineConfigured)) return removalTrialOverText();
  if (presence?.accept_in_app) return removalNowReadyText();
  if (!engineConfigured) return removalUnavailableText(presence);
  return presence
    ? `The Omitly desktop app is running, but "Accept proposals in Omitly" is switched off (${ACCEPT_SWITCH_PATH}), ` +
        "so a proposal cannot be queued. The person can switch it on, or you can call redact_pdf: this " +
        "server has an engine configured, so that writes directly and is recorded as an agent decision, " +
        "not a human-reviewed one."
    : "The Omitly desktop app is not running on this computer, so there is nobody to accept a " +
        "proposal. Ask the person to open Omitly and try again, or call redact_pdf: this server has an " +
        "engine configured, so that writes directly and is recorded as an agent decision, not a " +
        "human-reviewed one.";
}

/** The seal tools and `check_license` need the pipeline engine. No trial link here: this is a
 *  check, not a removal request. */
export function engineOnlyText(tool: "verify_seal" | "verify_document" | "check_license"): string {
  if (tool === "check_license") {
    return (
      "this tool needs the pipeline engine, which this server does not have. Licence and trial " +
      "status are shown in the Omitly desktop app."
    );
  }
  return (
    "this tool needs the pipeline engine, which this server does not have. The seal can be " +
    `checked in the Omitly desktop app: ${APP_VERIFY_PATH}. No pass or fail has been reached here.`
  );
}

/** A `redact_by_entity` proposal as the Omitly 5.5.0 app handles it: it lists no regions, so the
 *  person must open the document, run Auto-redact and review before anything can be accepted. */
export const ENTITY_PROPOSAL_STEPS =
  "This request lists no regions, so Omitly cannot accept it as sent: the person must open the " +
  "document in Omitly (Show), run Auto-redact and review what it finds, and then accept.";

/** Queued-result text for a proposal (any tool). The `redact_pdf` wording is the 5.5.0 text, unchanged. */
export function queuedText(
  tool: "redact_pdf" | "redact_by_entity",
  id: string,
  pdfPath: string,
  licence?: DesktopLicence,
): string {
  const head = `Proposal ${id} queued in Omitly for ${tool} on ${pdfPath}. `;
  const follow = `Call get_proposal_status with proposalId "${id}" to follow it.`;
  if (tool === "redact_by_entity") {
    return (
      head +
      `Nothing has been written. ${ENTITY_PROPOSAL_STEPS} ` +
      "To send regions the person can accept as sent, find them with find_sensitive_regions or " +
      "locate_text and call redact_pdf with those regions. " +
      follow +
      trialClause(licence)
    );
  }
  return (
    head +
    "Nothing has been written: a person must accept it in the Omitly desktop app, which then " +
    "removes, verifies and seals (the record will show a person decided). " +
    follow +
    trialClause(licence)
  );
}

/** The structured `note` for a queued proposal. */
export function queuedNote(tool: "redact_pdf" | "redact_by_entity"): string {
  return tool === "redact_by_entity"
    ? "Queued in the Omitly desktop app (accept-in-app is on). Nothing has been written. " +
        `${ENTITY_PROPOSAL_STEPS} Poll get_proposal_status with this proposalId.`
    : "Queued for a person to accept in the Omitly desktop app (accept-in-app is on). " +
        "Nothing has been written. Poll get_proposal_status with this proposalId. The " +
        "person chooses the real output path in Omitly's save dialog; outputPath is kept as your suggestion.";
}

/** `get_proposal_status` line for a pending proposal. */
export function pendingText(tool: string): string {
  return tool === "redact_by_entity"
    ? "Pending: waiting for a person in the Omitly desktop app. This request lists no regions, so " +
        "the person must open the document in Omitly (Show), run Auto-redact and review what it " +
        "finds before they can accept it."
    : "Pending: waiting for a person to accept or reject it in the Omitly desktop app.";
}
