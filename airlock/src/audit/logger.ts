/**
 * Audit logger.
 *
 * Persists one NDJSON line per action to a local file (default
 * ~/.lictor/airlock/audit.log) and prints a human line to the console for
 * anything that warns or blocks. The file is the tamper-evident "what did the
 * AI do" record — the CYA artifact that lets a regulated SMB say yes to AI.
 *
 * Everything written here is redacted first (see audit/english.ts + redact.ts).
 * The file lives on the local machine by design; shipping off-box is opt-in via
 * the separate Guardian telemetry path.
 */

import { appendFile, mkdir } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import type { AirlockEvent, Verdict } from "../types.js";
import { airlockVersion } from "../version.js";
import { fingerprint } from "../fingerprint.js";
import { redactSecrets } from "../redact.js";
import { summarize } from "./english.js";

/** Default audit log path: ~/.lictor/airlock/audit.log */
export function defaultAuditPath(): string {
  return join(homedir(), ".lictor", "airlock", "audit.log");
}

/** Build the privacy-safe, redacted event from a verdict. */
export function toEvent(verdict: Verdict): AirlockEvent {
  return {
    ts: verdict.ts,
    agentId: verdict.agentId,
    channel: verdict.action.channel,
    decision: verdict.decision,
    severity: verdict.severity,
    ruleIds: dedupe(verdict.hits.map((h) => h.ruleId)),
    summary: redactSecrets(summarize(verdict)),
    fingerprint: fingerprint(verdict.action.text),
    enforced: verdict.enforced,
    airlockVersion,
  };
}

/**
 * Append an event to the audit log file as NDJSON. Never throws — an audit
 * failure must not break the agent. Creates the parent directory on first use.
 */
export async function writeAudit(event: AirlockEvent, path: string): Promise<void> {
  try {
    await mkdir(dirname(path), { recursive: true });
    await appendFile(path, `${JSON.stringify(event)}\n`, "utf8");
  } catch {
    // Swallow — logging must never break the wrapped action.
  }
}

function dedupe<T>(xs: T[]): T[] {
  return Array.from(new Set(xs));
}
