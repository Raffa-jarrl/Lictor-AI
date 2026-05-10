/**
 * GET /api/auth/verify?token=XXX — magic-link consumption.
 *
 * Looks up the token by sha256 hash, marks consumed, creates a session,
 * sets the signed cookie, redirects to /dashboard.
 *
 * Token consumption is atomic: the UPDATE ... WHERE consumed_at IS NULL
 * RETURNING pattern ensures a token can only ever be redeemed once even
 * under concurrent clicks.
 */

import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { hashToken } from "@/lib/crypto";
import { SESSION_COOKIE, createSession, sessionCookieAttrs } from "@/lib/sessions";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const token = url.searchParams.get("token");
  if (!token || token.length < 32) {
    return redirectWithError("invalid_link");
  }

  const tokenHash = hashToken(token);
  const now = new Date();

  // Atomic claim: only the first request to redeem this token wins.
  const row = await db()
    .updateTable("magic_links")
    .set({ consumed_at: now })
    .where("token_hash", "=", tokenHash)
    .where("consumed_at", "is", null)
    .where("expires_at", ">", now)
    .returning(["account_id"])
    .executeTakeFirst();

  if (!row || !row.account_id) {
    return redirectWithError("expired_or_invalid");
  }

  const signedCookie = await createSession(row.account_id);

  // Audit: record the sign-in.
  await db()
    .insertInto("audit_log")
    .values({
      account_id: row.account_id,
      actor_email: await emailForAccount(row.account_id),
      action: "session.create",
      target_id: null,
      metadata: { source: "magic_link" },
      ip: request.headers.get("x-forwarded-for") ?? null,
      user_agent: request.headers.get("user-agent") ?? null,
    })
    .execute();

  const response = NextResponse.redirect(new URL("/dashboard", url.origin));
  response.cookies.set(SESSION_COOKIE, signedCookie, sessionCookieAttrs());
  return response;
}

function redirectWithError(code: string): Response {
  // Send the user back to the landing page with an error code in the URL.
  const base = process.env["NEXT_PUBLIC_GUARDIAN_URL"] ?? "http://localhost:3100";
  return NextResponse.redirect(`${base}/?error=${code}`);
}

async function emailForAccount(accountId: string): Promise<string> {
  const r = await db()
    .selectFrom("accounts")
    .select("email")
    .where("id", "=", accountId)
    .executeTakeFirst();
  return r?.email ?? "unknown";
}
