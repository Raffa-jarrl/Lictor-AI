/**
 * The broker — Airlock's single chokepoint.
 *
 * Every intercepted action goes through one path:
 *
 *   inspect()  → classify (pure): rules + allowlist + production escalation
 *   broker()   → inspect + side effects: audit log, onVerdict, Guardian, and
 *                (enforce mode only) throw AirlockBlockedError on a block.
 *
 * Observe vs enforce is the *same* classification — the only difference is
 * whether a "block" decision actually stops the action. That's the whole
 * product thesis: you run observe first (breaks nothing, builds the audit
 * trail), and when you trust the policy you flip to enforce with zero new
 * config. One broker produces both the proof and the containment.
 */

import type {
  Action,
  AirlockConfig,
  AirlockMode,
  Decision,
  RuleHit,
  RuleId,
  Severity,
  Verdict,
} from "./types.js";
import { AirlockBlockedError } from "./types.js";
import { ALL_RULES, evaluateAction, maxDecision, maxSeverity } from "./policy/index.js";
import { agentId } from "./agent-id.js";
import { shellAction, toolAction, type ActionOptions } from "./actions.js";
import { defaultAuditPath, toEvent, writeAudit } from "./audit/logger.js";
import { shipToGuardian } from "./telemetry.js";

/** Built-in production marker: matches `prod`/`production` as a bounded token. */
const DEFAULT_PROD_MARKERS = ["(?:^|[\\s\\-_./@:])prod(?:uction)?(?:$|[\\s\\-_./@:])"];

export interface Airlock {
  readonly mode: AirlockMode;
  /** Classify an action with no side effects. */
  inspect(action: Action): Verdict;
  /** Classify + log + (enforce) block. Throws AirlockBlockedError when blocked. */
  broker(action: Action): Promise<Verdict>;
  /** Convenience: broker a raw shell command. */
  guardShell(command: string, opts?: ActionOptions): Promise<Verdict>;
  /** Convenience: broker an MCP tool call. */
  guardToolCall(
    tool: string,
    args?: Record<string, unknown>,
    opts?: ActionOptions,
  ): Promise<Verdict>;
}

export function createAirlock(config: AirlockConfig = {}): Airlock {
  const mode: AirlockMode = config.mode ?? "observe";
  const ruleIds: RuleId[] = config.rules ?? ALL_RULES;
  const auditPath: string | false =
    config.auditLog === undefined ? defaultAuditPath() : config.auditLog;
  const redact = config.redactSecrets ?? true;
  const warnAction = config.warnAction ?? "allow";
  const id = agentId();

  const allowRes = compileRegexes(config.allowlist ?? []);
  const prodRes = compileRegexes(config.prodMarkers ?? DEFAULT_PROD_MARKERS);

  function inspect(action: Action): Verdict {
    const now = new Date().toISOString();

    // Allowlist short-circuit — explicit operator override.
    if (allowRes.some((re) => re.test(action.text))) {
      return {
        decision: "allow",
        severity: "info",
        hits: [],
        action,
        mode,
        enforced: false,
        ts: now,
        agentId: id,
      };
    }

    const evaluation = evaluateAction(action, ruleIds);
    let hits = evaluation.hits;

    // Production escalation: a destructive/exfil action touching a prod marker
    // is the nightmare scenario — force it to critical/block.
    const touchesProd = prodRes.some((re) => re.test(action.text));
    if (touchesProd) {
      hits = hits.map((h) => escalateForProd(h));
    }

    const { decision, severity } = fold(hits);

    return {
      decision,
      severity,
      hits,
      action,
      mode,
      enforced: false,
      ts: now,
      agentId: id,
    };
  }

  async function broker(action: Action): Promise<Verdict> {
    const verdict = inspect(action);

    // Decide whether enforce mode stops this action.
    const shouldBlock =
      mode === "enforce" &&
      (verdict.decision === "block" ||
        (verdict.decision === "warn" && warnAction === "block"));
    verdict.enforced = shouldBlock;

    // Side effects (never throw): audit file, callback, telemetry.
    const event = toEvent(verdict); // redaction happens inside toEvent
    if (auditPath !== false) {
      await writeAudit(event, auditPath);
    }
    try {
      config.onVerdict?.(verdict);
    } catch {
      // A bad callback must not break the agent.
    }
    if (config.guardian) {
      // Fire-and-forget; do not await on the agent's critical path beyond the
      // internal timeout in shipToGuardian.
      void shipToGuardian(event, config.guardian);
    }
    void redact; // redaction is applied in toEvent/english; flag retained for API symmetry

    if (shouldBlock) {
      throw new AirlockBlockedError(verdict);
    }
    return verdict;
  }

  function guardShell(command: string, opts?: ActionOptions): Promise<Verdict> {
    return broker(shellAction(command, opts ?? {}));
  }

  function guardToolCall(
    tool: string,
    args?: Record<string, unknown>,
    opts?: ActionOptions,
  ): Promise<Verdict> {
    return broker(toolAction(tool, args ?? {}, opts ?? {}));
  }

  return { mode, inspect, broker, guardShell, guardToolCall };
}

// ── helpers ─────────────────────────────────────────────────────────────────

function compileRegexes(patterns: string[]): RegExp[] {
  const out: RegExp[] = [];
  for (const p of patterns) {
    try {
      out.push(new RegExp(p, "i"));
    } catch {
      // Skip an invalid user-supplied pattern rather than crash.
    }
  }
  return out;
}

function escalateForProd(hit: RuleHit): RuleHit {
  if (hit.ruleId !== "destructive-command" && hit.ruleId !== "data-exfiltration") {
    return hit;
  }
  return {
    ...hit,
    decision: "block",
    severity: "critical",
    reason: `${hit.reason} This action targets something marked as PRODUCTION, which makes it especially dangerous.`,
  };
}

function fold(hits: RuleHit[]): { decision: Decision; severity: Severity } {
  let decision: Decision = "allow";
  let severity: Severity = "info";
  for (const h of hits) {
    decision = maxDecision(decision, h.decision);
    severity = maxSeverity(severity, h.severity);
  }
  return { decision, severity };
}
