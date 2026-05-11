/**
 * Built-in check registry.
 *
 * The check modules export their `Check` implementations; this file
 * registers them at import time so that any consumer of `@lictor/sentinel`
 * gets the catalog active by default.
 *
 * To opt out for a specific Sentinel instance, override the same `CheckId`
 * via `registerCheck()` with a no-op or your own implementation — the
 * registry is keyed by id, so re-registering replaces.
 *
 * Adding a new check (W5+):
 *   1. Create `checks/<your-check>.ts` exporting a `Check` impl.
 *   2. Re-export it here.
 *   3. Add it to `BUILTIN_CHECKS` below.
 *   4. Update `docs/specs/sentinel-api.md` if introducing a new `CheckId`.
 */

import { registerCheck, type Check } from "../check-runner.js";
import { promptInjectionCheck } from "./prompt-injection.js";

export { promptInjectionCheck, INJECTION_PATTERNS } from "./prompt-injection.js";
export type { InjectionPattern } from "./prompt-injection.js";

/** The full set of checks auto-registered at module load. */
export const BUILTIN_CHECKS: readonly Check[] = [promptInjectionCheck];

// Side-effect: register on import. Idempotent.
for (const check of BUILTIN_CHECKS) {
  registerCheck(check);
}
