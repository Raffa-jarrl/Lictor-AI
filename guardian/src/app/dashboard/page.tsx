/**
 * Dashboard — the authenticated incident timeline view.
 *
 * v0.1: auth-gated, queries real Postgres for severity rollup + recent
 * incidents. The full timeline UI (filters, pagination, detail drill-down)
 * lands W12.
 */

import { redirect } from "next/navigation";
import { getSession } from "@/lib/auth";
import { db } from "@/lib/db";
import { sql } from "kysely";
import type { ReactElement } from "react";

export const dynamic = "force-dynamic";

interface SeverityRow {
  severity: string;
  count: string | number;
}

interface IncidentRow {
  id: string;
  ts: Date;
  severity: string;
  check_id: string;
  title: string;
  model_name: string | null;
  fingerprint: string;
  action: string;
}

export default async function DashboardPage(): Promise<ReactElement> {
  const session = await getSession();
  if (!session) {
    redirect("/");
  }

  const since = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

  const [severities, recent, account] = await Promise.all([
    db()
      .selectFrom("incidents")
      .select(["severity", sql<string>`count(*)::text`.as("count")])
      .where("account_id", "=", session.accountId)
      .where("ts", ">=", since)
      .groupBy("severity")
      .execute(),
    db()
      .selectFrom("incidents")
      .select([
        "id",
        "ts",
        "severity",
        "check_id",
        "title",
        "model_name",
        "fingerprint",
        "action",
      ])
      .where("account_id", "=", session.accountId)
      .orderBy("ts", "desc")
      .limit(20)
      .execute(),
    db()
      .selectFrom("accounts")
      .select(["email", "ingest_token", "plan"])
      .where("id", "=", session.accountId)
      .executeTakeFirstOrThrow(),
  ]);

  const totals: Record<string, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const row of severities as SeverityRow[]) {
    totals[row.severity] = Number(row.count);
  }

  return (
    <main style={{ maxWidth: 1100, margin: "0 auto", padding: 32 }}>
      <header
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          marginBottom: 32,
        }}
      >
        <h1
          style={{
            fontFamily: "'Cormorant Garamond', Georgia, serif",
            fontSize: 28,
            fontWeight: 700,
            margin: 0,
          }}
        >
          Lictor <span style={{ color: "#C9A23B" }}>Guardian</span>
        </h1>
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          <a
            href="/incidents"
            style={{
              padding: "6px 12px",
              border: "1px solid #2A323E",
              borderRadius: 4,
              color: "#E8E2D5",
              textDecoration: "none",
              fontSize: 12,
            }}
          >
            All incidents →
          </a>
          <a
            href="/export"
            style={{
              padding: "6px 12px",
              border: "1px solid #2A323E",
              borderRadius: 4,
              color: "#C9A23B",
              textDecoration: "none",
              fontSize: 12,
            }}
          >
            Export
          </a>
          <span style={{ fontSize: 12, color: "#6E7780" }}>{account.email}</span>
          <form action="/api/auth/logout" method="POST">
            <button
              type="submit"
              style={{
                padding: "6px 12px",
                background: "transparent",
                color: "#6E7780",
                border: "1px solid #2A323E",
                borderRadius: 4,
                cursor: "pointer",
                fontSize: 12,
              }}
            >
              Sign out
            </button>
          </form>
        </div>
      </header>

      {/* Severity rollup */}
      <section
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(5, 1fr)",
          gap: 12,
          marginBottom: 32,
        }}
      >
        {(["critical", "high", "medium", "low", "info"] as const).map((sev) => (
          <div
            key={sev}
            style={{
              padding: 16,
              background: "#1A2028",
              borderRadius: 6,
              borderLeft: `3px solid ${severityColor(sev)}`,
            }}
          >
            <div style={{ fontSize: 11, color: "#6E7780", textTransform: "uppercase" }}>
              {sev}
            </div>
            <div style={{ fontSize: 24, fontWeight: 600 }}>{totals[sev] ?? 0}</div>
          </div>
        ))}
      </section>

      {/* Recent incidents */}
      <section style={{ marginBottom: 32 }}>
        <h2 style={{ fontSize: 14, fontWeight: 600, marginBottom: 12 }}>
          Recent incidents (last 20)
        </h2>
        {recent.length === 0 ? (
          <div
            style={{
              padding: 24,
              background: "#1A2028",
              borderRadius: 6,
              color: "#6E7780",
              textAlign: "center",
            }}
          >
            <div style={{ marginBottom: 12 }}>No incidents yet.</div>
            <div style={{ fontSize: 12 }}>
              Once you wire <code>@lictor/sentinel</code> into your AI app, incidents will
              appear here.
            </div>
          </div>
        ) : (
          <ul style={{ listStyle: "none", margin: 0, padding: 0 }}>
            {(recent as IncidentRow[]).map((row) => (
              <li
                key={row.id}
                style={{
                  padding: "12px 16px",
                  background: "#1A2028",
                  borderRadius: 6,
                  borderLeft: `3px solid ${severityColor(row.severity)}`,
                  marginBottom: 6,
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between" }}>
                  <span style={{ fontWeight: 500 }}>{row.title}</span>
                  <span style={{ fontSize: 11, color: "#6E7780" }}>
                    {new Date(row.ts).toISOString().slice(0, 19).replace("T", " ")} UTC
                  </span>
                </div>
                <div
                  style={{
                    display: "flex",
                    gap: 12,
                    fontSize: 11,
                    color: "#6E7780",
                    marginTop: 4,
                    fontFamily: "ui-monospace, monospace",
                  }}
                >
                  <span>{row.check_id}</span>
                  <span>{row.model_name ?? "—"}</span>
                  <span>{row.action}</span>
                  <span>{row.fingerprint}</span>
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>

      {/* Onboarding hint: ingest token */}
      <section
        style={{
          padding: 16,
          background: "#1A2028",
          borderRadius: 6,
          color: "#6E7780",
          fontSize: 12,
        }}
      >
        <div style={{ fontWeight: 600, marginBottom: 8, color: "#E8E2D5" }}>
          Sentinel ingest token
        </div>
        <div style={{ marginBottom: 8 }}>
          Set this in your application&apos;s environment to forward incidents to Guardian:
        </div>
        <pre
          style={{
            margin: 0,
            padding: 12,
            background: "#0F1419",
            borderRadius: 4,
            overflowX: "auto",
            color: "#C9A23B",
            fontSize: 11,
          }}
        >
          LICTOR_GUARDIAN_TOKEN={account.ingest_token}
        </pre>
      </section>
    </main>
  );
}

function severityColor(s: string): string {
  switch (s) {
    case "critical":
      return "#C0392B";
    case "high":
      return "#C0392B";
    case "medium":
      return "#D68910";
    case "low":
      return "#6E7780";
    case "info":
      return "#3D7C5E";
    default:
      return "#2A323E";
  }
}
