/**
 * Guardian telemetry sink (optional, opt-in).
 *
 * Airlock is local-first: the audit log lives on the user's machine. Shipping
 * anything off-box happens ONLY when a guardian config is supplied, and even
 * then we send the privacy-safe AirlockEvent (redacted summary + fingerprint +
 * metadata) — never the raw command. Fire-and-forget with a short timeout so
 * telemetry can never block or break the agent.
 *
 * Wire format: Guardian's `/api/ingest` accepts the SAME envelope Sentinel
 * sends (see `guardian/src/lib/wire-format.ts` + `docs/specs/wire-format.md`).
 * Airlock is NOT Sentinel, so we map the action-boundary AirlockEvent onto the
 * shared incident wire shape:
 *
 *   channel   ── shell / mcp-tool / … ─→ checkId  (airlock-shell, airlock-mcp, …)
 *   decision  ── allow / warn / block ─┐
 *   enforced  ── true / false ─────────┴─→ action  (blocked if enforced, else logged)
 *   severity  ─→ severity (identical enum)
 *   summary   ─→ title + detail (redacted, never the raw command)
 *   fingerprint (sha256/16) ─→ fingerprint (same construction as Sentinel)
 *   —         ─→ model  ({ provider: "other", name: "airlock-broker" })
 *   —         ─→ phase  ("preflight": Airlock brokers BEFORE the action runs)
 *
 * The wire boundary mirrors Sentinel exactly: event fields are camelCase
 * (ts, agentId, checkId, sentinelVersion, …); envelope fields are snake_case
 * (envelope_version, sentinel_version, lictor_core_version, agent_id, sent_at).
 */

import type { AirlockEvent, GuardianConfig, ActionChannel } from "./types.js";
import { airlockVersion } from "./version.js";

/** Wire-envelope constants — must match Guardian's EnvelopeSchema. */
const ENVELOPE_VERSION = "1" as const;
const LICTOR_CORE_VERSION = "0.1.0";
const DEFAULT_TIMEOUT_MS = 2000;

/** Synthetic "model" for action-boundary events — Airlock is not on the model path. */
const AIRLOCK_MODEL = { provider: "other", name: "airlock-broker" } as const;

/**
 * One incident event in Guardian's wire format. Field names (camelCase) match
 * Guardian's `IncidentEventSchema` exactly — do not rename without updating
 * `guardian/src/lib/wire-format.ts` in the same change.
 */
export interface IncidentEventWire {
  ts: string;
  agentId: string;
  phase: "preflight" | "postflight";
  checkId: string;
  severity: AirlockEvent["severity"];
  title: string;
  detail: string;
  model: { provider: "openai" | "anthropic" | "other"; name: string };
  fingerprint: string;
  action: "logged" | "blocked" | "redacted";
  sentinelVersion: string;
}

/** The envelope Guardian's `/api/ingest` validates. Envelope keys are snake_case. */
export interface Envelope {
  envelope_version: typeof ENVELOPE_VERSION;
  sentinel_version: string;
  lictor_core_version: string;
  agent_id: string;
  sent_at: string;
  events: IncidentEventWire[];
}

/** Map an action channel onto a stable, bounded checkId (≤64 chars). */
function checkIdForChannel(channel: ActionChannel): string {
  switch (channel) {
    case "shell":
      return "airlock-shell";
    case "mcp-tool":
      return "airlock-mcp";
    case "file-write":
      return "airlock-file";
    case "network":
      return "airlock-network";
    default:
      return "airlock";
  }
}

/** Clamp a string to a max length so it always passes Guardian's CHECK/zod bounds. */
function clamp(s: string, max: number): string {
  return s.length <= max ? s : s.slice(0, max);
}

/**
 * Map a privacy-safe AirlockEvent onto Guardian's incident wire shape. Pure.
 *
 *   - phase    → "preflight" (Airlock brokers before the action executes)
 *   - action   → "blocked" when the broker actually stopped it, else "logged"
 *   - title    → redacted summary (≤200)
 *   - detail   → redacted summary + decision/channel/rule context (1..2000)
 */
export function mapAirlockEvent(event: AirlockEvent): IncidentEventWire {
  const checkId = checkIdForChannel(event.channel);
  // Airlock only "blocks" (enforce + block decision) or "logs". There is no
  // Airlock notion of "redacted" as an action — redaction applies to summary
  // text, not to the disposition — so we never emit action: "redacted".
  const action: IncidentEventWire["action"] = event.enforced ? "blocked" : "logged";

  const summary = event.summary && event.summary.length > 0 ? event.summary : "(no summary)";
  const ruleList = event.ruleIds.length > 0 ? event.ruleIds.join(", ") : "none";
  const detail =
    `${summary}\n\n` +
    `channel: ${event.channel}\n` +
    `decision: ${event.decision}${event.enforced ? " (enforced/blocked)" : ""}\n` +
    `rules: ${ruleList}\n` +
    `source: lictor-airlock@${event.airlockVersion}`;

  return {
    ts: event.ts,
    agentId: event.agentId,
    phase: "preflight",
    checkId,
    severity: event.severity,
    title: clamp(summary, 200),
    detail: clamp(detail, 2000),
    model: AIRLOCK_MODEL,
    fingerprint: event.fingerprint,
    action,
    sentinelVersion: event.airlockVersion,
  };
}

/** Build the wire envelope around a single Airlock event. Pure — no I/O. */
export function buildEnvelope(event: AirlockEvent): Envelope {
  const wire = mapAirlockEvent(event);
  return {
    envelope_version: ENVELOPE_VERSION,
    sentinel_version: airlockVersion,
    lictor_core_version: LICTOR_CORE_VERSION,
    agent_id: wire.agentId,
    sent_at: new Date().toISOString(),
    events: [wire],
  };
}

/** Pluggable fetch — overridden in tests to assert request shape without real network. */
export interface FetchLike {
  (input: string, init: RequestInit): Promise<{ ok: boolean; status: number; text(): Promise<string> }>;
}

let _fetch: FetchLike = globalThis.fetch as unknown as FetchLike;

/** Override the fetch used by shipToGuardian. Tests call this; pass null to restore. */
export function setFetchForTests(f: FetchLike | null): void {
  _fetch = f ?? (globalThis.fetch as unknown as FetchLike);
}

/**
 * In-flight sends. shipToGuardian() is fire-and-forget — callers do NOT await
 * it on the agent's critical path. But a short-lived process (the CLI) would
 * otherwise exit and tear down the request before it lands. `flushTelemetry()`
 * lets such a caller wait for pending sends right before it exits, WITHOUT the
 * broker ever blocking on telemetry. Each promise here already swallows its own
 * errors, so awaiting them can never throw.
 */
const _inFlight = new Set<Promise<void>>();

/** Number of pending sends. Exposed for tests. */
export function pendingCount(): number {
  return _inFlight.size;
}

/**
 * Await all in-flight Guardian sends (best-effort). Returns once every send
 * started before this call has settled. Safe to call when nothing is pending.
 * Used by the CLI to flush telemetry before `process.exit`.
 */
export async function flushTelemetry(): Promise<void> {
  await Promise.allSettled([..._inFlight]);
}

/**
 * Ship a single Airlock event to Guardian. Best-effort, fire-and-forget.
 *
 * Sends the SAME envelope Guardian accepts from Sentinel, so Airlock telemetry
 * works against an unmodified Guardian out of the box (no bridge). Any error —
 * network, timeout, 4xx, 5xx — is swallowed: telemetry must never break the
 * agent. Bearer auth via `config.token` against `accounts.ingest_token`.
 *
 * The returned promise is tracked so a short-lived process can `flushTelemetry()`
 * before exiting; long-running callers simply never await it.
 */
export function shipToGuardian(event: AirlockEvent, config: GuardianConfig): Promise<void> {
  const p = doShip(event, config).finally(() => {
    _inFlight.delete(p);
  });
  _inFlight.add(p);
  return p;
}

async function doShip(event: AirlockEvent, config: GuardianConfig): Promise<void> {
  const timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    await _fetch(config.endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${config.token}`,
      },
      body: JSON.stringify(buildEnvelope(event)),
      signal: controller.signal,
    });
  } catch {
    // Swallow. Telemetry must never break the app.
  } finally {
    clearTimeout(timer);
  }
}
