/**
 * Plain-English rendering of a verdict.
 *
 * The audit trail is a product feature, not a debug log: the customer's whole
 * reason for installing Airlock is to be able to read, in their own words, what
 * the AI did on their machine. So these renderers avoid jargon and always pass
 * text through redaction before it's shown or stored.
 */

import type { Action, Verdict } from "../types.js";
import { redactSecrets } from "../redact.js";

/** "ran `<cmd>`" / "called tool `<tool>`" / "wrote `<path>`" — what happened. */
export function actionPhrase(action: Action): string {
  switch (action.channel) {
    case "shell":
      return `ran \`${redactSecrets(truncate(action.command ?? action.text, 160))}\``;
    case "mcp-tool":
      return `called tool \`${action.tool ?? "?"}\``;
    case "file-write":
      return `wrote \`${action.path ?? action.text}\``;
    case "network":
      return `made network request \`${redactSecrets(truncate(action.text, 160))}\``;
    default:
      return `did \`${redactSecrets(truncate(action.text, 160))}\``;
  }
}

const DECISION_WORD: Record<Verdict["decision"], string> = {
  allow: "ALLOW",
  warn: "WARN",
  block: "BLOCK",
};

/**
 * One-line summary for the AirlockEvent (shipped to Guardian + stored).
 * Always redacted. Example:
 *   "BLOCK — ran `rm -rf /tmp` — Recursive force-delete (rm -rf)"
 */
export function summarize(verdict: Verdict): string {
  const word = DECISION_WORD[verdict.decision];
  const top = verdict.hits[0];
  const phrase = actionPhrase(verdict.action);
  if (!top) return `${word} — ${phrase}`;
  return `${word} — ${phrase} — ${top.title}`;
}

/**
 * Fuller, multi-line explanation for the CLI / human review. Includes the
 * reason and remediation for each hit.
 */
export function explain(verdict: Verdict): string {
  const lines: string[] = [];
  lines.push(`${DECISION_WORD[verdict.decision]}  ${actionPhrase(verdict.action)}`);
  if (verdict.enforced) lines.push("  → stopped by Airlock (enforce mode)");
  for (const h of verdict.hits) {
    lines.push(`  • [${h.severity}] ${h.title}`);
    lines.push(`      ${h.reason}`);
    if (h.remediation) lines.push(`      ↳ ${h.remediation}`);
  }
  return lines.join("\n");
}

function truncate(s: string, n: number): string {
  return s.length > n ? `${s.slice(0, n)}…` : s;
}
