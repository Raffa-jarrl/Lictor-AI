/**
 * Policy engine — registry + evaluation dispatcher.
 *
 * Parallels @lictor/sentinel's check-runner: each rule registers itself, and
 * `evaluateAction()` runs the configured rules and folds their hits into a
 * single decision + severity. A bug inside one rule must never crash the
 * broker, so rule exceptions are swallowed (fail open to "allow" for that one
 * rule — the others still run).
 */

import type { Action, Decision, Rule, RuleHit, RuleId, Severity } from "../types.js";
import { maxDecision, maxSeverity } from "./match.js";

import { destructiveRule } from "./rules/destructive.js";
import { exfiltrationRule } from "./rules/exfiltration.js";
import { lateralMovementRule } from "./rules/lateral-movement.js";
import { supplyChainRule } from "./rules/supply-chain.js";
import { secretsAccessRule } from "./rules/secrets-access.js";

const REGISTRY = new Map<RuleId, Rule>();

export function registerRule(rule: Rule): void {
  REGISTRY.set(rule.id, rule);
}

export function getRule(id: RuleId): Rule | undefined {
  return REGISTRY.get(id);
}

export function registeredRuleIds(): RuleId[] {
  return Array.from(REGISTRY.keys());
}

// Register the built-in rule families at import time.
for (const r of [
  destructiveRule,
  exfiltrationRule,
  lateralMovementRule,
  supplyChainRule,
  secretsAccessRule,
]) {
  registerRule(r);
}

/** The default rule set (all registered rules). */
export const ALL_RULES: RuleId[] = registeredRuleIds();

export interface Evaluation {
  decision: Decision;
  severity: Severity;
  hits: RuleHit[];
}

/**
 * Run the given rules against an action and fold the hits into an aggregate
 * decision + severity. Hits are sorted most-severe-first so `hits[0]` is the
 * headline.
 */
export function evaluateAction(action: Action, ruleIds: readonly RuleId[]): Evaluation {
  const hits: RuleHit[] = [];
  for (const id of ruleIds) {
    const rule = REGISTRY.get(id);
    if (!rule) continue;
    try {
      const ruleHits = rule.evaluate(action);
      for (const h of ruleHits) hits.push(h);
    } catch {
      // Never let a buggy rule break the broker. Skip it.
    }
  }

  hits.sort(
    (a, b) =>
      severityRank(b.severity) - severityRank(a.severity) ||
      decisionRank(b.decision) - decisionRank(a.decision),
  );

  let decision: Decision = "allow";
  let severity: Severity = "info";
  for (const h of hits) {
    decision = maxDecision(decision, h.decision);
    severity = maxSeverity(severity, h.severity);
  }

  return { decision, severity, hits };
}

// Local rank helpers (kept here to avoid re-importing the maps).
function severityRank(s: Severity): number {
  return { info: 0, low: 1, medium: 2, high: 3, critical: 4 }[s];
}
function decisionRank(d: Decision): number {
  return { allow: 0, warn: 1, block: 2 }[d];
}

export { maxDecision, maxSeverity } from "./match.js";
