/**
 * POST /api/auth/magic — magic-link request handler.
 *
 * v0.1 stub: accepts an email, would email a magic link in real implementation.
 * Real magic-link issuance + email delivery lands W11.
 */

import { NextResponse } from "next/server";

export const runtime = "nodejs";

export async function POST(request: Request): Promise<Response> {
  const data = await request.formData();
  const email = data.get("email");
  if (typeof email !== "string" || !email.includes("@")) {
    return NextResponse.json({ error: "invalid_email" }, { status: 400 });
  }

  // TODO(W11):
  //   1. Upsert into accounts by lowercased email.
  //   2. Generate token, hash it, insert magic_links row with 15-min expiry.
  //   3. Send email via Postmark with link `${NEXT_PUBLIC_GUARDIAN_URL}/auth/verify?token=...`.

  return NextResponse.json(
    { message: "If that email is valid, a magic link is on its way." },
    { status: 202 },
  );
}
