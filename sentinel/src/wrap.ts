/**
 * The `wrap()` function — Sentinel's entire user-facing API.
 *
 * Intercepts known SDK method paths (OpenAI: chat.completions.create, etc.;
 * Anthropic: messages.create) using a recursive Proxy. Pre-flight checks
 * run on input text; post-flight checks run on output text. Pass-through
 * preserves the original `this` binding so SDK internals keep working.
 *
 * Phase 0 (this commit): real Proxy interception, real check dispatch.
 * Real checks (prompt-injection, pii-leak, secrets-in-input) land W4-5.
 *
 * See `docs/specs/sentinel-api.md` for the contract.
 */

import type {
  IncidentEvent,
  SentinelConfig,
  TripAction,
} from "./types.js";
import { SentinelBlockedError } from "./types.js";
import { sendToGuardian } from "./telemetry.js";
import { AGENT_ID } from "./agent-id.js";
import { SENTINEL_VERSION } from "./version.js";
import { fingerprint } from "./fingerprint.js";
import {
  KNOWN_PATHS,
  extractInputText,
  extractOutputText,
  extractModelName,
} from "./extractors.js";
import { runChecks, type CheckResult } from "./check-runner.js";

/**
 * Wrap an AI client so model calls go through Sentinel's checks before
 * reaching the provider, and the provider's response goes through Sentinel's
 * checks before reaching the caller.
 *
 * Unintercepted methods (anything not in `KNOWN_PATHS`) pass through
 * unchanged. The wrap is recursive — `client.chat.completions.create` works
 * because every intermediate access returns a Proxy that watches for
 * known paths.
 */
export function wrap<T extends object>(client: T, config: SentinelConfig = {}): T {
  return wrapPath(client, [], config) as T;
}

/**
 * Recursive Proxy installer. `path` is the dot-path from the original
 * client. We check `KNOWN_PATHS[path.join('.')]` on every property access
 * and install an interceptor when we hit a known method.
 */
function wrapPath(target: unknown, path: string[], config: SentinelConfig): unknown {
  // Non-objects pass through unchanged.
  if (target === null || typeof target !== "object") {
    return target;
  }

  return new Proxy(target as object, {
    get(obj: object, prop: string | symbol, receiver: unknown): unknown {
      // Symbols (e.g. Symbol.iterator) — pass through, don't recurse.
      if (typeof prop !== "string") {
        return Reflect.get(obj, prop, receiver);
      }

      const next = Reflect.get(obj, prop, receiver);
      const newPath = [...path, prop];
      const intercept = KNOWN_PATHS[newPath.join(".")];

      // If this property is a known intercepted METHOD, install an interceptor
      // that captures the parent (`obj`) so we can call back into it with the
      // correct `this`.
      if (intercept && typeof next === "function") {
        return createInterceptor(next as (...a: unknown[]) => unknown, obj, intercept.provider, config);
      }

      // Otherwise, recurse — return a Proxy of the next level so that
      // `client.chat.completions.create` keeps wrapping all the way down.
      return wrapPath(next, newPath, config);
    },
  }) as unknown;
}

/**
 * Build the interceptor function for a known method. Captures `originalFn`
 * and `originalParent` (the unwrapped object that owns the method) so we
 * can call back with the right `this`.
 */
function createInterceptor(
  originalFn: (...args: unknown[]) => unknown,
  originalParent: object,
  provider: IncidentEvent["model"]["provider"],
  config: SentinelConfig,
): (...args: unknown[]) => Promise<unknown> {
  return async function intercepted(...args: unknown[]): Promise<unknown> {
    const modelName = extractModelName(provider, args);
    const model: IncidentEvent["model"] = { provider, name: modelName };

    // ── Preflight ──
    const inputText = extractInputText(provider, args);
    const preflightTrips = await runChecks(inputText, config.preflight ?? [], "preflight");
    for (const trip of preflightTrips) {
      const event = makeEvent({
        phase: "preflight",
        checkId: trip.id,
        result: trip.result,
        model,
        evidence: inputText,
        action: actionFor(config.onTrip),
      });
      emit(event, config);
    }

    // ── Forward to underlying SDK ──
    const response = await Reflect.apply(originalFn, originalParent, args);

    // ── Postflight ──
    const outputText = extractOutputText(provider, response);
    const postflightTrips = await runChecks(outputText, config.postflight ?? [], "postflight");
    for (const trip of postflightTrips) {
      const event = makeEvent({
        phase: "postflight",
        checkId: trip.id,
        result: trip.result,
        model,
        evidence: outputText,
        action: actionFor(config.onTrip),
      });
      emit(event, config);
    }

    return response;
  };
}

function actionFor(onTrip: TripAction | undefined): IncidentEvent["action"] {
  if (onTrip === "block") return "blocked";
  if (onTrip === "redact") return "redacted";
  return "logged";
}

interface MakeEventArgs {
  phase: IncidentEvent["phase"];
  checkId: IncidentEvent["checkId"];
  result: CheckResult;
  model: IncidentEvent["model"];
  evidence: string;
  action: IncidentEvent["action"];
}

function makeEvent(a: MakeEventArgs): IncidentEvent {
  return {
    ts: new Date().toISOString(),
    agentId: AGENT_ID,
    sentinelVersion: SENTINEL_VERSION,
    phase: a.phase,
    checkId: a.checkId,
    severity: a.result.severity,
    title: a.result.title,
    detail: a.result.detail,
    model: a.model,
    fingerprint: fingerprint(a.evidence),
    action: a.action,
  };
}

/**
 * Fire onIncident, optionally send to Guardian, and (if blocking) throw.
 * Exported for unit tests; not part of the public SDK surface.
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

/**
 * Build an `IncidentEvent` skeleton with the universal fields set. Used
 * by tests and any future caller that wants to construct events outside
 * the wrap() lifecycle.
 */
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
