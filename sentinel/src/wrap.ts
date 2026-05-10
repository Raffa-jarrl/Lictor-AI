/**
 * The `wrap()` function — Sentinel's entire user-facing API.
 *
 * Wraps an OpenAI / Anthropic / other client and intercepts model calls
 * to run pre-flight + post-flight checks. See `docs/specs/sentinel-api.md`.
 *
 * v0.1 implementation status:
 *   - API surface and types are LOCKED (don't change without bumping major)
 *   - Check dispatch is STUBBED (always returns no findings; Phase 1, weeks 4-10)
 *   - Telemetry sender is REAL (sends to Guardian if configured)
 *   - Provider detection is STUBBED (assumes openai/gpt-4 for now)
 */

import type {
  IncidentEvent,
  SentinelConfig,
} from "./types.js";
import { SentinelBlockedError } from "./types.js";
import { sendToGuardian } from "./telemetry.js";
import { AGENT_ID } from "./agent-id.js";
import { SENTINEL_VERSION } from "./version.js";

/**
 * Wrap an AI client (OpenAI, Anthropic, or any object) so model calls go
 * through Sentinel's checks before reaching the provider — and the
 * provider's response goes through Sentinel's checks before reaching the caller.
 *
 * v0.1 returns the client unchanged (with checks stubbed to always pass).
 * Phase 1 (weeks 4–10) replaces the stub dispatch with real check execution.
 */
export function wrap<T extends object>(client: T, config: SentinelConfig = {}): T {
  // Future: install a Proxy here that intercepts the chat.completions.create
  // call (OpenAI), messages.create (Anthropic), and any registered custom
  // entry points. The Proxy delegates to runChecks() pre-flight, forwards to
  // the underlying method, then runs post-flight on the response.
  //
  // For v0.1 we return the client unchanged — the API surface is what matters
  // first; we want callers to be able to write `wrap(client, { ... })` today
  // and have it compile. Real interception lands in W4.
  void config;
  return client;
}

/**
 * Internal: run the configured checks against a piece of text.
 *
 * Stubbed in v0.1 — always returns an empty array. Phase 1 wires this up
 * to `lictor-core` (via WASM in browsers, native FFI in Node) using the
 * pure `analyze_*` entry points exposed in `core/src/checks/*.rs`.
 */
export async function runChecks(
  _text: string,
  _checks: SentinelConfig["preflight"] | SentinelConfig["postflight"],
  _phase: "preflight" | "postflight",
): Promise<IncidentEvent[]> {
  return [];
}

/**
 * Internal: emit a single incident — fire onIncident, optionally send to
 * Guardian, optionally throw if onTrip === "block".
 *
 * Pure-ish: the `void` calls to telemetry are fire-and-forget.
 */
export function emit(event: IncidentEvent, config: SentinelConfig): void {
  config.onIncident?.(event);
  if (config.guardian) {
    void sendToGuardian(event, config.guardian);
  }
  if (config.onTrip === "block" && event.action === "blocked") {
    throw new SentinelBlockedError(event);
  }
}

/** Build an IncidentEvent skeleton with everything except check-specific fields. */
export function buildEvent(args: {
  phase: IncidentEvent["phase"];
  checkId: IncidentEvent["checkId"];
  severity: IncidentEvent["severity"];
  title: string;
  detail: string;
  model: IncidentEvent["model"];
  fingerprint: string;
  action: IncidentEvent["action"];
}): IncidentEvent {
  return {
    ts: new Date().toISOString(),
    agentId: AGENT_ID,
    sentinelVersion: SENTINEL_VERSION,
    ...args,
  };
}
