/**
 * Public types — the contract from `docs/specs/sentinel-api.md`.
 *
 * Every consumer of `@lictor/sentinel` depends on these. Breaking changes
 * here are a major version bump and must update `docs/specs/sentinel-api.md`
 * + `docs/specs/wire-format.md` in the same commit.
 */

/** The set of checks Sentinel can run. v0.1 ships the first three. */
export type CheckId =
  | "prompt-injection"
  | "secrets-in-input"
  | "pii-leak"
  | "unsafe-tool-call"; // v0.2

/** Severity ranking, matching `lictor-core::Severity`. */
export type Severity = "critical" | "high" | "medium" | "low" | "info";

/** What to do when a check trips. */
export type TripAction = "log" | "block" | "redact";

/** Which side of the model call the check ran on. */
export type Phase = "preflight" | "postflight";

/** What action was taken on this specific event. */
export type IncidentAction = "logged" | "blocked" | "redacted";

/**
 * The single event Sentinel emits per check trip.
 *
 * Same shape goes to `onIncident` callbacks AND across the wire to Guardian.
 * Privacy invariant: never contains raw user content. See `docs/specs/wire-format.md` §4.
 */
export interface IncidentEvent {
  ts: string;
  agentId: string;
  phase: Phase;
  checkId: CheckId;
  severity: Severity;
  title: string;
  detail: string;
  model: { provider: "openai" | "anthropic" | "other"; name: string };
  fingerprint: string;
  action: IncidentAction;
  sentinelVersion: string;
}

/** Optional Guardian connector configuration. */
export interface GuardianConfig {
  endpoint: string;
  token: string;
  timeoutMs?: number;
}

/** The full Sentinel configuration, passed to `wrap()`. */
export interface SentinelConfig {
  preflight?: CheckId[];
  postflight?: CheckId[];
  onTrip?: TripAction;
  onIncident?: (event: IncidentEvent) => void;
  guardian?: GuardianConfig;
  rulesOverride?: Record<string, unknown>;
}

/** Thrown when a check trips and `onTrip === "block"`. */
export class SentinelBlockedError extends Error {
  readonly incident: IncidentEvent;

  constructor(incident: IncidentEvent) {
    super(`[lictor:sentinel] blocked by ${incident.checkId}: ${incident.title}`);
    this.name = "SentinelBlockedError";
    this.incident = incident;
  }
}
