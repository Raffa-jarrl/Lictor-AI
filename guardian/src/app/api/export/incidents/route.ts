/**
 * GET /api/export/incidents?format=csv|json&since=...&until=...
 *
 * Audit log export for SOC 2 / GDPR / EU AI Act evidence. Returns every
 * incident the account has access to in the requested window, streamed
 * back as CSV or JSON. Authenticated via session cookie.
 *
 * Records the export in audit_log so the export itself is auditable.
 */

import { getSession } from "@/lib/auth";
import { db } from "@/lib/db";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const MAX_ROWS = 100_000; // soft cap to prevent memory blowups; v0.2 streams

export async function GET(request: Request): Promise<Response> {
  const session = await getSession();
  if (!session) {
    return Response.redirect(new URL("/", new URL(request.url).origin));
  }

  const url = new URL(request.url);
  const format = url.searchParams.get("format") ?? "json";
  if (format !== "csv" && format !== "json") {
    return new Response(JSON.stringify({ error: "format must be 'csv' or 'json'" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  const since = parseDate(url.searchParams.get("since")) ?? new Date(Date.now() - 30 * 24 * 60 * 60_000);
  const until = parseDate(url.searchParams.get("until")) ?? new Date();

  if (since > until) {
    return new Response(JSON.stringify({ error: "since must be <= until" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  const rows = await db()
    .selectFrom("incidents")
    .selectAll()
    .where("account_id", "=", session.accountId)
    .where("ts", ">=", since)
    .where("ts", "<=", until)
    .orderBy("ts", "asc")
    .limit(MAX_ROWS)
    .execute();

  // Audit the export itself.
  await db()
    .insertInto("audit_log")
    .values({
      account_id: session.accountId,
      actor_email: session.email,
      action: "incident.export",
      target_id: null,
      metadata: {
        format,
        since: since.toISOString(),
        until: until.toISOString(),
        rows: rows.length,
      },
      ip: request.headers.get("x-forwarded-for") ?? null,
      user_agent: request.headers.get("user-agent") ?? null,
    })
    .execute();

  const filename = `lictor-incidents-${since.toISOString().slice(0, 10)}-to-${until.toISOString().slice(0, 10)}.${format}`;

  if (format === "csv") {
    const csv = toCsv(rows);
    return new Response(csv, {
      status: 200,
      headers: {
        "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": `attachment; filename="${filename}"`,
      },
    });
  }

  // JSON
  const json = JSON.stringify({ rows, count: rows.length, since, until }, null, 2);
  return new Response(json, {
    status: 200,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Content-Disposition": `attachment; filename="${filename}"`,
    },
  });
}

function parseDate(s: string | null): Date | null {
  if (!s) return null;
  const d = new Date(s);
  return isNaN(d.getTime()) ? null : d;
}

interface IncidentRow {
  id: string;
  account_id: string;
  agent_id: string;
  ts: Date;
  received_at: Date;
  phase: string;
  check_id: string;
  severity: string;
  title: string;
  detail: string;
  model_provider: string | null;
  model_name: string | null;
  fingerprint: string;
  action: string;
  sentinel_version: string;
}

function toCsv(rows: IncidentRow[]): string {
  const headers = [
    "id", "ts", "received_at", "phase", "check_id", "severity",
    "title", "detail", "model_provider", "model_name", "fingerprint",
    "action", "sentinel_version", "agent_id",
  ];
  const lines = [headers.join(",")];
  for (const r of rows) {
    lines.push([
      esc(r.id),
      esc(r.ts.toISOString()),
      esc(r.received_at.toISOString()),
      esc(r.phase),
      esc(r.check_id),
      esc(r.severity),
      esc(r.title),
      esc(r.detail),
      esc(r.model_provider ?? ""),
      esc(r.model_name ?? ""),
      esc(r.fingerprint),
      esc(r.action),
      esc(r.sentinel_version),
      esc(r.agent_id),
    ].join(","));
  }
  return lines.join("\n");
}

function esc(s: string): string {
  // CSV escape: wrap in quotes, double internal quotes, also handle newlines.
  if (/[,"\n\r]/.test(s)) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}
