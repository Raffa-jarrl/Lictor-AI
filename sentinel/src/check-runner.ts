/**
 * Check interface + dispatcher.
 *
 * Each Sentinel check (prompt-injection, pii-leak, secrets-in-input, ...)
 * implements the `Check` interface and gets registered. The dispatcher runs
 * the configured checks against a piece of text and returns any trips.
 *
 * v0.1 ships one stub check (`alwaysTrip`) used in tests and disabled by
 * default. Real checks land Phase 1 W4-5 — they'll plug into this same
 * interface, no changes needed at the wrap() call site.
 */

import type { CheckId, Phase, Severity } from "./types.js";

/** Result from a single check run. */
export interface CheckResult {
  /** Whether this check tripped. False = no incident. */
  tripped: boolean;
  /** Severity, if tripped. Ignored if `tripped: false`. */
  severity: Severity;
  /** Short title (≤80 chars). */
  title: string;
  /** Longer explanation. */
  detail: string;
}

/** A single check. */
export interface Check {
  readonly id: CheckId;
  /** Run the check against a piece of text. Pure if possible — no I/O. */
  run(text: string, phase: Phase): CheckResult | Promise<CheckResult>;
}

/** Result that didn't trip — convenience constant. */
export const PASS: CheckResult = {
  tripped: false,
  severity: "info",
  title: "",
  detail: "",
};

/**
 * In-process registry of available checks. Real checks register here at
 * import time; the wrap() dispatcher looks them up by `CheckId`.
 */
const REGISTRY = new Map<CheckId, Check>();

/** Register a check. Idempotent — re-registering replaces the existing one. */
export function registerCheck(check: Check): void {
  REGISTRY.set(check.id, check);
}

/** Look up a check by id. Returns undefined if not registered. */
export function getCheck(id: CheckId): Check | undefined {
  return REGISTRY.get(id);
}

/** All currently registered check ids. Mainly for diagnostics. */
export function registeredCheckIds(): CheckId[] {
  return Array.from(REGISTRY.keys());
}

/**
 * Run a list of checks against text and return any that tripped.
 * Failures inside a check (thrown errors) are swallowed — Sentinel never
 * blocks a user request because a check has a bug.
 */
export async function runChecks(
  text: string,
  checkIds: readonly CheckId[],
  phase: Phase,
): Promise<Array<{ id: CheckId; result: CheckResult }>> {
  const out: Array<{ id: CheckId; result: CheckResult }> = [];
  for (const id of checkIds) {
    const check = REGISTRY.get(id);
    if (!check) continue; // unknown / not yet implemented; skip silently
    try {
      const result = await check.run(text, phase);
      if (result.tripped) {
        out.push({ id, result });
      }
    } catch {
      // Drop — never block on a check bug.
    }
  }
  return out;
}

// ─── Built-in checks (used in tests; disabled in production) ─────────────────

/**
 * A test-only check that always trips. Registered manually by tests via
 * `registerAlwaysTripCheck()`. NOT auto-registered.
 */
export const ALWAYS_TRIP_ID = "prompt-injection" as const satisfies CheckId;

export const alwaysTripCheck: Check = {
  id: ALWAYS_TRIP_ID,
  run() {
    return {
      tripped: true,
      severity: "high" as Severity,
      title: "always-trip stub fired",
      detail: "This check exists for testing the wrap() lifecycle end-to-end.",
    };
  },
};
