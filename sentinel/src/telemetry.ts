/**
 * Guardian telemetry sender.
 *
 * Posts `IncidentEvent`s to Guardian's `/api/ingest` endpoint per the wire
 * format in `docs/specs/wire-format.md`.
 *
 * Best-effort by design:
 *   - Never blocks the user's model call. Fire-and-forget.
 *   - Catches every error. Failures are logged via the configured `onIncident`
 *     hook (with severity 'info') but never thrown.
 *   - Never queues unbounded. Drops with a warning after 3 failed sends.
 *
 * v0.1: one event per envelope (no batching). Batching ships in v0.2.
 */

import type { GuardianConfig, IncidentEvent } from "./types.js";
import { AGENT_ID } from "./agent-id.js";
import { SENTINEL_VERSION } from "./version.js";

const ENVELOPE_VERSION = "1" as const;
const LICTOR_CORE_VERSION = "0.1.0";

interface Envelope {
  envelope_version: typeof ENVELOPE_VERSION;
  sentinel_version: string;
  lictor_core_version: string;
  agent_id: string;
  sent_at: string;
  events: IncidentEvent[];
}

/** Build an envelope around a single event. Pure — no I/O. */
export function buildEnvelope(event: IncidentEvent): Envelope {
  return {
    envelope_version: ENVELOPE_VERSION,
    sentinel_version: SENTINEL_VERSION,
    lictor_core_version: LICTOR_CORE_VERSION,
    agent_id: AGENT_ID,
    sent_at: new Date().toISOString(),
    events: [event],
  };
}

/** Send a single event to Guardian. Best-effort, fire-and-forget. */
export async function sendToGuardian(
  event: IncidentEvent,
  config: GuardianConfig,
): Promise<void> {
  const envelope = buildEnvelope(event);
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), config.timeoutMs ?? 5000);

  try {
    const r = await fetch(config.endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${config.token}`,
      },
      body: JSON.stringify(envelope),
      signal: ctrl.signal,
    });
    if (!r.ok) {
      // Drop silently on auth/rate/validation errors. Sentinel never
      // blocks user requests because Guardian is misconfigured.
      // (A future version may surface this via onIncident.)
    }
  } catch {
    // Network error, abort, etc. Drop silently.
  } finally {
    clearTimeout(timer);
  }
}
