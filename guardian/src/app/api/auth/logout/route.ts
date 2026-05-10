/**
 * POST /api/auth/logout — revoke session, clear cookie, redirect home.
 */

import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { SESSION_COOKIE, revokeSession } from "@/lib/sessions";
import { verifySessionCookie } from "@/lib/crypto";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: Request): Promise<Response> {
  const cookieStore = await cookies();
  const cookie = cookieStore.get(SESSION_COOKIE);
  const sessionId = verifySessionCookie(cookie?.value);
  if (sessionId) {
    await revokeSession(sessionId);
  }

  const url = new URL(request.url);
  const response = NextResponse.redirect(new URL("/", url.origin));
  response.cookies.delete(SESSION_COOKIE);
  return response;
}
