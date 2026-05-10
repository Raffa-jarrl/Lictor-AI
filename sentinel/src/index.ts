/**
 * @lictor/sentinel — public entry point.
 *
 * The entire public API is `wrap()`, the configuration types, and
 * `SentinelBlockedError`. Everything else is implementation detail.
 *
 * See `docs/specs/sentinel-api.md` for the full contract.
 */

export { wrap } from "./wrap.js";
export { SentinelBlockedError } from "./types.js";
export type {
  CheckId,
  GuardianConfig,
  IncidentAction,
  IncidentEvent,
  Phase,
  SentinelConfig,
  Severity,
  TripAction,
} from "./types.js";
export { SENTINEL_VERSION } from "./version.js";

// Internal — for users implementing custom checks (advanced use). The
// `Check` interface is stable; the registry helpers may change before v1.0.
export type { Check, CheckResult } from "./check-runner.js";
export { registerCheck, getCheck, registeredCheckIds, PASS } from "./check-runner.js";
