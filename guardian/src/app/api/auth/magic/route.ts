/**
 * POST /api/auth/magic — magic-link request handler.
 *
 * Accepts an email, issues a single-use token (15-min expiry), sends an
 * email with the link. Always returns the same neutral response (whether
 * or not the email exists in the system) — prevents email enumeration.
 */

import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { generateToken, hashToken } from "@/lib/crypto";
import { sendMagicLinkEmail } from "@/lib/email";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const MAGIC_LINK_TTL_MIN = 15;

const NEUTRAL_RESPONSE = {
  message: "If that email is valid, a magic link is on its way.",
};

export async function POST(request: Request): Promise<Response> {
  // Accept either form-encoded (from the landing-page <form>) or JSON
  // (from a client-side fetch). Useful for both.
  const contentType = request.headers.get("content-type") ?? "";
  let email: unknown;
  if (contentType.includes("application/json")) {
    try {
      const body = (await request.json()) as { email?: unknown };
      email = body.email;
    } catch {
      return NextResponse.json({ error: "invalid_body" }, { status: 400 });
    }
  } else {
    const data = await request.formData();
    email = data.get("email");
  }

  if (typeof email !== "string" || !isReasonableEmail(email)) {
    return NextResponse.json(NEUTRAL_RESPONSE, { status: 202 });
  }

  const lowerEmail = email.toLowerCase().trim();

  // Upsert account by email (case-insensitive). For brand-new emails we
  // generate an ingest_token at creation time so they can start sending
  // Sentinel telemetry immediately after first sign-in.
  const ingestToken = generateToken();
  await db()
    .insertInto("accounts")
    .values({
      email: lowerEmail,
      ingest_token: ingestToken,
    })
    .onConflict((oc) => oc.column("email").doNothing())
    .execute();

  const account = await db()
    .selectFrom("accounts")
    .select(["id", "email"])
    .where("email", "=", lowerEmail)
    .executeTakeFirstOrThrow();

  // Issue magic link.
  const rawToken = generateToken();
  const tokenHash = hashToken(rawToken);
  const expiresAt = new Date(Date.now() + MAGIC_LINK_TTL_MIN * 60_000);

  await db()
    .insertInto("magic_links")
    .values({
      account_id: account.id,
      email: account.email,
      token_hash: tokenHash,
      expires_at: expiresAt,
    })
    .execute();

  const baseUrl =
    process.env["NEXT_PUBLIC_GUARDIAN_URL"] ?? "http://localhost:3100";
  const link = `${baseUrl}/api/auth/verify?token=${rawToken}`;

  // Send email (dev: stdout; prod: Postmark). Best-effort — failures here
  // shouldn't surface as enumeration vectors.
  await sendMagicLinkEmail({ to: account.email, link });

  return NextResponse.json(NEUTRAL_RESPONSE, { status: 202 });
}

/**
 * Looser-than-RFC email check — we don't accept obviously bad input but
 * don't try to validate every legal corner of RFC 5321 either. Postmark
 * does the real validation downstream.
 */
function isReasonableEmail(s: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s) && s.length <= 254;
}
