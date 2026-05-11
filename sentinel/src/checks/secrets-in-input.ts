/**
 * Secrets-in-input check.
 *
 * Runs on PREFLIGHT (user input → model). Catches API keys, credentials,
 * and connection strings being sent INTO the model prompt — a different
 * threat from `pii-leak` (which catches PII coming OUT).
 *
 * Threat model:
 *   - User pastes their `.env` file contents into a chat to get help
 *     debugging — the AI provider now sees production credentials.
 *   - Developer asks "why is this code failing" and pastes a snippet
 *     containing a hardcoded API key.
 *   - Tool output containing secrets is appended to the user message
 *     (an RAG / agent-tool failure mode).
 *
 * Patterns mirror `lictor-core/src/checks/secrets.rs`. Single source of
 * truth lives in the Rust crate's `SECRET_PATTERNS`; this is a deliberate
 * port for the TypeScript runtime path. Keep both in sync — when one
 * gets a new pattern, the other does too.
 *
 * Privacy: the matched value is fingerprinted (sha256, 16 hex chars) for
 * Guardian telemetry — never shipped raw.
 */

import type { Phase, Severity } from "../types.js";
import type { Check, CheckResult } from "../check-runner.js";
import { PASS } from "../check-runner.js";

export interface SecretPattern {
  re: RegExp;
  label: string;
  severity: Severity;
}

/**
 * Ported from lictor-core/src/checks/secrets.rs::SECRET_PATTERNS.
 * Keep these in lockstep with the Rust source.
 */
export const SECRET_PATTERNS: SecretPattern[] = [
  { re: /AIza[A-Za-z0-9_\-]{35}/g,                                                       label: "Google API key",                              severity: "high" },
  { re: /sk-ant-api\d{2}-[A-Za-z0-9_\-]{40,}/g,                                          label: "Anthropic API key",                           severity: "critical" },
  // Matches both legacy OpenAI (sk-...) and 2024+ project keys (sk-proj-...).
  { re: /sk-(?:proj-)?[A-Za-z0-9_\-]{20,}/g,                                             label: "OpenAI API key (or similar sk- token)",       severity: "critical" },
  { re: /sk_live_[A-Za-z0-9]{24,}/g,                                                     label: "Stripe live secret key",                      severity: "critical" },
  { re: /sk_test_[A-Za-z0-9]{24,}/g,                                                     label: "Stripe test secret key (still leaks logic)",  severity: "medium" },
  { re: /pk_live_[A-Za-z0-9]{24,}/g,                                                     label: "Stripe live publishable key (informational)", severity: "info" },
  { re: /ghp_[A-Za-z0-9]{36}/g,                                                          label: "GitHub personal access token",                severity: "critical" },
  { re: /ghs_[A-Za-z0-9]{36}/g,                                                          label: "GitHub server token",                         severity: "critical" },
  { re: /xox[abp]-[A-Za-z0-9-]{10,}/g,                                                   label: "Slack token",                                 severity: "high" },
  { re: /AKIA[0-9A-Z]{16}/g,                                                             label: "AWS access key ID",                           severity: "high" },
  { re: /-----BEGIN (?:RSA|EC|OPENSSH) PRIVATE KEY-----/g,                                label: "Private key block",                           severity: "critical" },
  { re: /eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}/g,                label: "JWT token (verify intended)",                 severity: "low" },
  { re: /mongodb(?:\+srv)?:\/\/[^\s"'<>]+/g,                                             label: "MongoDB connection string",                   severity: "critical" },
  { re: /postgres(?:ql)?:\/\/[^\s"'<>]+/g,                                               label: "PostgreSQL connection string",                severity: "critical" },
  { re: /redis:\/\/[^\s"'<>]+/g,                                                         label: "Redis connection string",                     severity: "high" },
];

const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

function maxSeverity(a: Severity, b: Severity): Severity {
  return SEVERITY_RANK[a] >= SEVERITY_RANK[b] ? a : b;
}

function runSecretsInInput(text: string, _phase: Phase): CheckResult {
  if (!text || text.length === 0) return PASS;

  // Dedup by exact matched value — same secret matching multiple patterns
  // (Anthropic key also matches the broader OpenAI `sk-` pattern) should
  // produce one finding under the more specific label. The order of
  // SECRET_PATTERNS determines which label wins; Anthropic precedes
  // OpenAI in the array so it wins for `sk-ant-api...` strings.
  const seen = new Set<string>();
  const matches: Array<{ label: string; severity: Severity }> = [];
  let topSeverity: Severity = "info";

  for (const pat of SECRET_PATTERNS) {
    pat.re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = pat.re.exec(text)) !== null) {
      const value = m[0];
      if (seen.has(value)) continue;
      seen.add(value);
      matches.push({ label: pat.label, severity: pat.severity });
      topSeverity = maxSeverity(topSeverity, pat.severity);
      if (matches.length >= 10) break;
      if (!pat.re.global) break;
    }
    if (matches.length >= 10) break;
  }

  if (matches.length === 0) return PASS;

  const labels = matches.map((m) => `  [${m.severity}] ${m.label}`).join("\n");
  const title =
    matches.length === 1
      ? `Secret in input: ${matches[0]!.label}`
      : `Secrets in input — ${matches.length} distinct credentials`;
  const detail =
    `Pattern-based detection of hardcoded credentials in the user's input.\n` +
    `Sending these to the model leaks them to the AI provider (logged, ` +
    `potentially trained on, or visible to provider support staff).\n\n` +
    `Matched:\n${labels}\n\n` +
    `Remediation: the secret should be redacted before the prompt is sent. ` +
    `If using @lictor/sentinel with onTrip: 'redact', secrets are stripped ` +
    `automatically. With onTrip: 'block', the request is rejected entirely. ` +
    `With onTrip: 'log' (default), the event is recorded but the call proceeds — ` +
    `you should rotate the leaked credential.`;

  return {
    tripped: true,
    severity: topSeverity,
    title,
    detail,
  };
}

export const secretsInInputCheck: Check = {
  id: "secrets-in-input",
  run: runSecretsInInput,
};
