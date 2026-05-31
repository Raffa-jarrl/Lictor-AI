/**
 * Stable fingerprint for a normalized action.
 *
 * sha256(value) truncated to 16 hex chars. Deterministic, non-reversible.
 * Lets Guardian dedupe/correlate audit events without ever seeing the raw
 * command. Same construction as @lictor/sentinel's fingerprint() so the two
 * products' telemetry can be correlated downstream.
 */

import { createHash } from "node:crypto";

export function fingerprint(value: string): string {
  return createHash("sha256").update(value).digest("hex").slice(0, 16);
}
