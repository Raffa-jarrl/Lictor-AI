/**
 * Shared matching primitives for policy rules.
 *
 * Kept in its own module so rule files can import it without creating a cycle
 * with policy/index.ts (which imports the rules to register them).
 */

import type { Decision, RuleHit, RuleId, Severity, Action } from "../types.js";
import { redactSecrets } from "../redact.js";

export const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export const DECISION_RANK: Record<Decision, number> = {
  allow: 0,
  warn: 1,
  block: 2,
};

export function maxSeverity(a: Severity, b: Severity): Severity {
  return SEVERITY_RANK[a] >= SEVERITY_RANK[b] ? a : b;
}

export function maxDecision(a: Decision, b: Decision): Decision {
  return DECISION_RANK[a] >= DECISION_RANK[b] ? a : b;
}

/**
 * A declarative pattern: if `re` matches the action text, emit a hit. `guard`
 * (optional) lets a pattern suppress itself based on the full action (used to
 * avoid known false positives — e.g. don't flag `--force-with-lease` under the
 * blanket force-push pattern).
 */
export interface Pattern {
  re: RegExp;
  decision: Decision;
  severity: Severity;
  title: string;
  reason: string;
  remediation?: string;
  /** Return false to skip this pattern for this action. */
  guard?: (action: Action) => boolean;
}

/**
 * Run a list of patterns against an action and return one hit per matching
 * pattern. The matched substring is captured (and redacted) as evidence.
 */
export function matchPatterns(
  action: Action,
  patterns: Pattern[],
  ruleId: RuleId,
): RuleHit[] {
  const hits: RuleHit[] = [];
  const text = action.text;
  for (const p of patterns) {
    if (p.guard && !p.guard(action)) continue;
    p.re.lastIndex = 0;
    const m = p.re.exec(text);
    if (!m) continue;
    const hit: RuleHit = {
      ruleId,
      decision: p.decision,
      severity: p.severity,
      title: p.title,
      reason: p.reason,
      evidence: redactSecrets(m[0]).slice(0, 120),
    };
    if (p.remediation !== undefined) hit.remediation = p.remediation;
    hits.push(hit);
  }
  return hits;
}

/**
 * Private/loopback/link-local IPv4 + cloud metadata host detection. Shared by
 * the lateral-movement and exfiltration rules.
 *
 * Ranges: 10/8, 172.16/12, 192.168/16, 127/8, 169.254/16 (link-local, includes
 * the 169.254.169.254 cloud metadata endpoint), plus *.local / *.internal /
 * *.lan / *.corp mDNS-style names.
 */
export const PRIVATE_HOST_RE =
  /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3}|[a-z0-9-]+\.(?:local|internal|lan|corp|intranet))\b/i;

/** The cloud instance-metadata endpoint — stealing these = stealing cloud creds. */
export const METADATA_HOST_RE =
  /\b(?:169\.254\.169\.254|metadata\.google\.internal|fd00:ec2::254)\b/i;
