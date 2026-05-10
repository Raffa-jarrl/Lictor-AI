/**
 * Session lifecycle: create on magic-link consumption, load on each request,
 * revoke on logout. All sessions are stored server-side; the cookie carries
 * only the signed session id.
 */

import { db } from "./db";
import { signSessionId, verifySessionCookie } from "./crypto";

export const SESSION_COOKIE = "lictor_session";
export const SESSION_TTL_DAYS = 30;

/**
 * Cookie attributes for the session cookie. `secure: true` in production;
 * dev uses `secure: false` so it works over plain http://localhost:3100.
 */
export function sessionCookieAttrs(): {
  httpOnly: boolean;
  sameSite: "lax";
  secure: boolean;
  path: string;
  maxAge: number;
} {
  return {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env["NODE_ENV"] === "production",
    path: "/",
    maxAge: 60 * 60 * 24 * SESSION_TTL_DAYS,
  };
}

/** Create a session for an account. Returns the SIGNED cookie value. */
export async function createSession(accountId: string): Promise<string> {
  const row = await db()
    .insertInto("sessions")
    .values({ account_id: accountId })
    .returning("id")
    .executeTakeFirstOrThrow();
  return signSessionId(row.id);
}

/**
 * Load the session for the current request, given the cookie value.
 * Returns `null` for invalid/expired/revoked sessions.
 */
export async function loadSession(
  cookieValue: string | undefined,
): Promise<{ sessionId: string; accountId: string; email: string } | null> {
  const sessionId = verifySessionCookie(cookieValue);
  if (!sessionId) return null;

  const row = await db()
    .selectFrom("sessions")
    .innerJoin("accounts", "accounts.id", "sessions.account_id")
    .select([
      "sessions.id as session_id",
      "sessions.account_id as account_id",
      "sessions.revoked_at as revoked_at",
      "accounts.email as email",
    ])
    .where("sessions.id", "=", sessionId)
    .executeTakeFirst();

  if (!row || row.revoked_at !== null) return null;

  // Fire-and-forget update of last_seen_at (no need to await).
  void db()
    .updateTable("sessions")
    .set({ last_seen_at: new Date() })
    .where("id", "=", sessionId)
    .execute();

  return {
    sessionId: row.session_id,
    accountId: row.account_id,
    email: row.email,
  };
}

/** Revoke a session. Idempotent. */
export async function revokeSession(sessionId: string): Promise<void> {
  await db()
    .updateTable("sessions")
    .set({ revoked_at: new Date() })
    .where("id", "=", sessionId)
    .where("revoked_at", "is", null)
    .execute();
}
