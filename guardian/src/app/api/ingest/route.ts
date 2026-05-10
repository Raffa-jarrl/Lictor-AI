/**
 * POST /api/ingest — Sentinel telemetry endpoint.
 *
 * Validates the wire-format envelope (see `docs/specs/wire-format.md`),
 * resolves the bearer token to an account, and writes events to the
 * `incidents` table.
 *
 * v0.1 status: validation + auth wired; DB write is a stub (we accept and
 * count, but don't persist yet — that lands W11 once the migration runs).
 */

import { NextResponse } from "next/server";
import { EnvelopeSchema } from "@/lib/wire-format";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: Request): Promise<Response> {
  // 1. Auth — bearer token resolves to an account (stub for v0.1).
  const auth = request.headers.get("authorization") ?? "";
  const m = auth.match(/^Bearer\s+(.+)$/);
  if (!m) {
    return NextResponse.json(
      { error: "missing_token", message: "Authorization: Bearer <ingest_token> required" },
      { status: 401 },
    );
  }
  const token = m[1];
  if (!token || token.length < 8) {
    return NextResponse.json(
      { error: "invalid_token", message: "ingest_token is invalid or revoked" },
      { status: 401 },
    );
  }
  // TODO(W11): SELECT id FROM accounts WHERE ingest_token = $1. 401 if no row.

  // 2. Validate the envelope shape.
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json(
      { error: "validation", message: "body is not valid JSON" },
      { status: 400 },
    );
  }

  const parsed = EnvelopeSchema.safeParse(body);
  if (!parsed.success) {
    const first = parsed.error.issues[0];
    return NextResponse.json(
      {
        error: "validation",
        field: first?.path.join(".") ?? "unknown",
        message: first?.message ?? "envelope failed validation",
      },
      { status: 400 },
    );
  }
  const envelope = parsed.data;

  // 3. Persist (stub — W11 wires the real INSERT).
  // for (const event of envelope.events) {
  //   await db().insertInto("incidents").values({ ... }).execute();
  // }

  // 4. Respond 202 Accepted with an ingest id (per wire-format §3).
  return NextResponse.json(
    {
      received: envelope.events.length,
      ingest_id: `ing_${crypto.randomUUID().slice(0, 8)}`,
    },
    { status: 202 },
  );
}
