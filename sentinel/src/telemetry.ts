/**
 * Guardian telemetry sender.
 *
 * Posts `IncidentEvent`s to Guardian's `/api/ingest` endpoint per the wire
 * format in `docs/specs/wire-format.md`.
 *
 * Best-effort by design:
 *   - Never blocks the user's model call. Fire-and-forget.
 *   - Catches every error. Failures are silent at v0.1 — a future option
 *     may surface them via `onIncident` with a `[telemetry-error]` event.
 *   - Bounded retries with exponential backoff for transient failures
 *     (5xx, network errors). 4xx (validation/auth) is permanent — drop.
 *   - Bounded queue. We never accumulate more than `MAX_QUEUE` pending
 *     sends — past that, we drop newest and log a warning. Keeps memory
 *     stable under outage.
 *
 * v0.1: one event per envelope (no batching). Batching ships in v0.2.
 */

import type { GuardianConfig, IncidentEvent } from "./types.js";
import { AGENT_ID } from "./agent-id.js";
import { SENTINEL_VERSION } from "./version.js";

const ENVELOPE_VERSION = "1" as const;
const LICTOR_CORE_VERSION = "0.1.0";
const DEFAULT_TIMEOUT_MS = 5000;
const MAX_RETRIES = 3;
const BASE_BACKOFF_MS = 200;

/** Cap on in-flight + pending sends. Past this, newest sends are dropped. */
const MAX_QUEUE = 100;

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

/** Pluggable fetch — overridden in tests to assert request shape without real network. */
export interface FetchLike {
  (input: string, init: RequestInit): Promise<{ ok: boolean; status: number; text(): Promise<string> }>;
}

let _fetch: FetchLike = globalThis.fetch as unknown as FetchLike;

/** Override the fetch used by sendToGuardian. Tests call this. */
export function setFetchForTests(f: FetchLike | null): void {
  _fetch = (f ?? (globalThis.fetch as unknown as FetchLike));
}

let _inFlight = 0;

/** Number of pending sends, for tests. */
export function pendingCount(): number {
  return _inFlight;
}

/**
 * Send a single event to Guardian. Best-effort, fire-and-forget.
 *
 * Retries:
 *   - 5xx / network error → retry up to MAX_RETRIES with exponential backoff
 *     (200ms, 400ms, 800ms — jittered ±20%)
 *   - 4xx → permanent failure, no retry (validation / auth)
 *   - 2xx → success
 */
export async function sendToGuardian(
  event: IncidentEvent,
  config: GuardianConfig,
): Promise<void> {
  if (_inFlight >= MAX_QUEUE) {
    // Drop. Don't accumulate unbounded under outage.
    return;
  }
  _inFlight++;
  try {
    await sendWithRetry(event, config);
  } finally {
    _inFlight--;
  }
}

async function sendWithRetry(event: IncidentEvent, config: GuardianConfig): Promise<void> {
  const envelope = buildEnvelope(event);
  const body = JSON.stringify(envelope);
  const timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);

    try {
      const r = await _fetch(config.endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${config.token}`,
        },
        body,
        signal: ctrl.signal,
      });
      clearTimeout(timer);

      if (r.ok) return; // 2xx — done.

      // 4xx: permanent. No retry.
      if (r.status >= 400 && r.status < 500) {
        return;
      }
      // 5xx: fall through to retry.
    } catch {
      clearTimeout(timer);
      // Network error / abort — fall through to retry.
    }

    if (attempt < MAX_RETRIES) {
      const backoff = BASE_BACKOFF_MS * Math.pow(2, attempt);
      const jitter = backoff * (0.8 + Math.random() * 0.4);
      await new Promise((r) => setTimeout(r, jitter));
    }
  }
  // All retries exhausted. Drop silently.
}
