/**
 * Cryptographic primitives — token generation, hashing, session signing.
 *
 * Design choices:
 * - Tokens are 32 bytes of crypto-random hex (64 chars). High enough entropy
 *   that brute-force is irrelevant.
 * - Tokens are stored in DB as sha256(token) hex. Magic-link tokens are
 *   short-lived (15 min); bcrypt would be overkill and slower per verification.
 * - Sessions are HMAC-SHA256 signed cookie payloads. Server-side row in
 *   `sessions` table allows revocation; cookie carries the row id.
 * - Constant-time comparison for HMAC verification to prevent timing attacks.
 */

import {
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";

/** Fresh 64-char hex token suitable for magic-link or ingest_token use. */
export function generateToken(): string {
  return randomBytes(32).toString("hex");
}

/** sha256 hash of a token, hex-encoded. Stored in DB; never reversible. */
export function hashToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

/** sha256 of a string (general-purpose). */
export function sha256Hex(s: string): string {
  return createHash("sha256").update(s, "utf8").digest("hex");
}

// ─── Cookie signing ───────────────────────────────────────────────────────────

const SESSION_SECRET_ENV = "SESSION_SECRET";

function sessionSecret(): string {
  const s = process.env[SESSION_SECRET_ENV];
  if (!s || s.length < 32) {
    throw new Error(
      `${SESSION_SECRET_ENV} must be set to at least 32 bytes of hex. ` +
        `Generate with: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`,
    );
  }
  return s;
}

/** Sign a session id, producing `<id>.<hmac-hex>`. Carries no other data. */
export function signSessionId(sessionId: string): string {
  const mac = createHmac("sha256", sessionSecret())
    .update(sessionId, "utf8")
    .digest("hex");
  return `${sessionId}.${mac}`;
}

/**
 * Verify and unwrap a signed session id. Returns the session id on success,
 * `null` if the signature is invalid or malformed. Constant-time compare.
 */
export function verifySessionCookie(cookieValue: string | undefined): string | null {
  if (!cookieValue) return null;
  const dot = cookieValue.lastIndexOf(".");
  if (dot < 1) return null;
  const id = cookieValue.slice(0, dot);
  const provided = cookieValue.slice(dot + 1);
  const expected = createHmac("sha256", sessionSecret())
    .update(id, "utf8")
    .digest("hex");
  // Both must be the same length for timingSafeEqual.
  if (provided.length !== expected.length) return null;
  const a = Buffer.from(provided, "hex");
  const b = Buffer.from(expected, "hex");
  if (a.length !== b.length) return null;
  return timingSafeEqual(a, b) ? id : null;
}
