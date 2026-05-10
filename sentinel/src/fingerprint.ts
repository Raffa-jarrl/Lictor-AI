/**
 * Fingerprinting for privacy-preserving telemetry.
 *
 * Sentinel never ships raw user content. Instead, it ships a short hash of
 * the first 4 KB so duplicate detections can be correlated without
 * reversing the original input.
 *
 * See `docs/specs/wire-format.md` §4.
 */

import { createHash } from "node:crypto";

const FINGERPRINT_BYTES = 4096;
const FINGERPRINT_HEX_LEN = 16;

/** Compute a 16-hex-char fingerprint of the first 4 KB of `text`. */
export function fingerprint(text: string): string {
  const truncated = text.length > FINGERPRINT_BYTES
    ? text.slice(0, FINGERPRINT_BYTES)
    : text;
  return createHash("sha256")
    .update(truncated, "utf8")
    .digest("hex")
    .slice(0, FINGERPRINT_HEX_LEN);
}

/** Compute a 16-hex-char fingerprint of an arbitrary serializable object. */
export function fingerprintObject(obj: unknown): string {
  return fingerprint(JSON.stringify(obj));
}
