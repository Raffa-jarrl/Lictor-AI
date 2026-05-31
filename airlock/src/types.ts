/**
 * Public types — the @lictor/airlock contract.
 *
 * Airlock is the *action* boundary. Where @lictor/sentinel sits on the prompt
 * boundary (what goes INTO and OUT of the model), Airlock sits on what the
 * agent DOES: the shell commands it runs and the MCP tool calls it makes.
 *
 * One broker, two modes:
 *   - observe  → classify + log every action in plain English. Blocks nothing.
 *   - enforce  → additionally refuse (throw / return blocked) on dangerous
 *                actions.
 *
 * Breaking changes here are a major version bump.
 */

/** Severity ranking, matching `lictor-core::Severity` and @lictor/sentinel. */
export type Severity = "critical" | "high" | "medium" | "low" | "info";

/** What a rule (or the aggregate verdict) wants to happen. */
export type Decision = "allow" | "warn" | "block";

/** The two operating modes of the broker. */
export type AirlockMode = "observe" | "enforce";

/** Where an intercepted action originated. */
export type ActionChannel = "shell" | "mcp-tool" | "file-write" | "network";

/** The built-in policy rules. v0.1 ships all five "root fear" families. */
export type RuleId =
  | "destructive-command"
  | "data-exfiltration"
  | "lateral-movement"
  | "supply-chain"
  | "secrets-access";

/**
 * A normalized action the broker evaluates. Callers build one of these (or use
 * the `shellAction()` / `toolAction()` helpers) before calling `broker()`.
 */
export interface Action {
  /** Origin channel. Drives which fields below are populated. */
  channel: ActionChannel;
  /** Full shell command line (channel === "shell"). */
  command?: string;
  /** MCP tool name (channel === "mcp-tool"). */
  tool?: string;
  /** MCP tool arguments (channel === "mcp-tool"). */
  args?: Record<string, unknown>;
  /** Target path (channel === "file-write"). */
  path?: string;
  /** Working directory context, if known. */
  cwd?: string;
  /**
   * Single-line, normalized text rendering of the action. This is what rules
   * pattern-match against and what (after redaction) lands in the audit log.
   * Built automatically by the action helpers.
   */
  text: string;
  /** Optional caller label (agent name, session id, ...). */
  source?: string;
}

/** One rule's opinion about an action. */
export interface RuleHit {
  ruleId: RuleId;
  decision: Decision;
  severity: Severity;
  /** Short headline (≤80 chars), plain English — no jargon. */
  title: string;
  /** Why this tripped, in a sentence a non-security founder understands. */
  reason: string;
  /** What to do instead, if there's an obvious safer path. */
  remediation?: string;
  /** The matched fragment, already redacted. For the audit trail. */
  evidence?: string;
}

/** A single policy rule. Pure — no I/O. */
export interface Rule {
  readonly id: RuleId;
  /** Evaluate an action. Return [] if the rule has no opinion. */
  evaluate(action: Action): RuleHit[];
}

/** The broker's decision about one action. */
export interface Verdict {
  /** Aggregate decision: the most severe of all hits (allow if none). */
  decision: Decision;
  /** Aggregate severity: the top severity among hits ("info" if none). */
  severity: Severity;
  /** Every rule hit, in evaluation order. */
  hits: RuleHit[];
  /** The action that was evaluated. */
  action: Action;
  /** Mode the broker was in. */
  mode: AirlockMode;
  /**
   * Whether the action was actually stopped. Only ever true when
   * mode === "enforce" and the decision resolved to "block".
   */
  enforced: boolean;
  /** ISO timestamp. */
  ts: string;
  /** Process/agent id (see agent-id.ts). */
  agentId: string;
}

/**
 * The privacy-safe event shipped to Guardian and persisted to the local audit
 * log. Carries a plain-English summary (secrets redacted) + a fingerprint, but
 * never the raw command verbatim. Mirrors @lictor/sentinel's IncidentEvent.
 */
export interface AirlockEvent {
  ts: string;
  agentId: string;
  channel: ActionChannel;
  decision: Decision;
  severity: Severity;
  ruleIds: RuleId[];
  /** Plain-English one-liner, secrets redacted. */
  summary: string;
  /** sha256/16 of the normalized action text. */
  fingerprint: string;
  enforced: boolean;
  airlockVersion: string;
}

/** Optional Guardian connector configuration (same shape as Sentinel). */
export interface GuardianConfig {
  endpoint: string;
  token: string;
  timeoutMs?: number;
}

/** Full Airlock configuration, passed to `createAirlock()`. */
export interface AirlockConfig {
  /** "observe" (default) logs only; "enforce" can block. */
  mode?: AirlockMode;
  /** Which rules to run. Default: all five. */
  rules?: RuleId[];
  /**
   * Audit log destination. A file path appends NDJSON; `false` disables file
   * logging. Default: `~/.lictor/airlock/audit.log`.
   */
  auditLog?: string | false;
  /** Called with every verdict (allow included). For custom sinks/UI. */
  onVerdict?: (verdict: Verdict) => void;
  /** Optional Guardian telemetry (fingerprints + metadata only). */
  guardian?: GuardianConfig;
  /** Regex strings; if any matches `action.text`, the action is force-allowed. */
  allowlist?: string[];
  /**
   * Strings that mark a target as production (hostnames, db names, AWS account
   * aliases). A destructive action touching one of these is escalated to
   * "block" severity. Default markers cover common cases (prod, production).
   */
  prodMarkers?: string[];
  /** Redact secrets before logging/shipping. Default: true. Keep it true. */
  redactSecrets?: boolean;
  /**
   * In enforce mode, how to treat a "warn" decision: "allow" (default, warn is
   * advisory) or "block" (paranoid — stop on warnings too).
   */
  warnAction?: "allow" | "block";
}

/** Thrown by the enforcing broker when an action resolves to "block". */
export class AirlockBlockedError extends Error {
  readonly verdict: Verdict;

  constructor(verdict: Verdict) {
    const top = verdict.hits[0];
    super(
      `[lictor:airlock] blocked ${verdict.action.channel} action` +
        (top ? `: ${top.title}` : ""),
    );
    this.name = "AirlockBlockedError";
    this.verdict = verdict;
  }
}
