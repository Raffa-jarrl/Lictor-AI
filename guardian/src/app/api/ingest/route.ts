/**
 * POST /api/ingest — Sentinel telemetry endpoint.
 *
 * Validates the wire-format envelope (see `docs/specs/wire-format.md`),
 * resolves the bearer token to an account, and writes events to the
 * `incidents` table.
 *
 * Auth: bearer token, looked up in `accounts.ingest_token`. 401 on miss.
 * Validation: zod schema in `src/lib/wire-format.ts`. 400 on bad shape.
 * Success: 202 with the count of events accepted + an ingest_id.
 */

import { NextResponse } from "next/server";
import { EnvelopeSchema, type IncidentEventWire } from "@/lib/wire-format";
import { db } from "@/lib/db";
import { maybeFireSlackForIncident } from "@/lib/slack";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: Request): Promise<Response> {
  // 1. Auth — bearer token resolves to an account.
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

  let accountId: string;
  try {
    const account = await db()
      .selectFrom("accounts")
      .select("id")
      .where("ingest_token", "=", token)
      .executeTakeFirst();
    if (!account) {
      return NextResponse.json(
        { error: "invalid_token", message: "ingest_token is invalid or revoked" },
        { status: 401 },
      );
    }
    accountId = account.id;
  } catch (e) {
    console.error("[ingest] account lookup failed:", e);
    return NextResponse.json(
      { error: "internal", message: "auth lookup failed" },
      { status: 500 },
    );
  }

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

  // 3. Persist events. One INSERT batched for the whole envelope.
  //    `returning("id")` so we can pass real incident IDs to Slack fire.
  let inserted: Array<{ id: string }>;
  try {
    inserted = await db()
      .insertInto("incidents")
      .values(envelope.events.map((e: IncidentEventWire) => mapEventToRow(e, accountId)))
      .returning("id")
      .execute();
  } catch (e) {
    console.error("[ingest] insert failed:", e);
    return NextResponse.json(
      { error: "internal", message: "could not persist events" },
      { status: 500 },
    );
  }

  // 4. Fire Slack webhook for each event (best-effort, fire-and-forget).
  //    Latency note: we don't await — the webhook lives on its own clock.
  //    Errors are stored in slack_integrations.last_error for debugging.
  const guardianUrl =
    process.env["NEXT_PUBLIC_GUARDIAN_URL"] ?? "http://localhost:3100";
  for (let i = 0; i < envelope.events.length; i++) {
    const ev = envelope.events[i]!;
    const insertedRow = inserted[i];
    if (!insertedRow) continue;
    void maybeFireSlackForIncident(accountId, {
      ts: new Date(ev.ts),
      phase: ev.phase,
      check_id: ev.checkId,
      severity: ev.severity,
      title: ev.title,
      model_provider: ev.model.provider,
      model_name: ev.model.name,
      fingerprint: ev.fingerprint,
      action: ev.action,
      guardian_url: guardianUrl,
      incident_id: insertedRow.id,
    });
  }

  // 5. Respond 202 Accepted.
  return NextResponse.json(
    {
      received: envelope.events.length,
      ingest_id: `ing_${crypto.randomUUID().slice(0, 8)}`,
    },
    { status: 202 },
  );
}

/** Map a wire-format event onto an `incidents` row. */
function mapEventToRow(e: IncidentEventWire, accountId: string) {
  return {
    account_id: accountId,
    agent_id: e.agentId,
    ts: new Date(e.ts),
    phase: e.phase,
    check_id: e.checkId,
    severity: e.severity,
    title: e.title,
    detail: e.detail,
    model_provider: e.model.provider,
    model_name: e.model.name,
    fingerprint: e.fingerprint,
    action: e.action,
    sentinel_version: e.sentinelVersion,
  };
}
