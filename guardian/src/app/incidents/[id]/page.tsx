/**
 * /incidents/[id] — per-incident detail view.
 *
 * Shows everything we stored at ingest time. No raw user content (the wire
 * format only carries fingerprints).
 */

import Link from "next/link";
import { redirect, notFound } from "next/navigation";
import type { ReactElement } from "react";

import { getSession } from "@/lib/auth";
import { db } from "@/lib/db";

export const dynamic = "force-dynamic";

interface PageProps {
  params: Promise<{ id: string }>;
}

export default async function IncidentDetailPage({ params }: PageProps): Promise<ReactElement> {
  const session = await getSession();
  if (!session) redirect("/");

  const { id } = await params;
  // Loose UUID shape check — defends against weird inputs hitting the DB.
  if (!/^[0-9a-f-]{36}$/i.test(id)) notFound();

  const row = await db()
    .selectFrom("incidents")
    .selectAll()
    .where("account_id", "=", session.accountId)
    .where("id", "=", id)
    .executeTakeFirst();

  if (!row) notFound();

  return (
    <main style={{ maxWidth: 800, margin: "0 auto", padding: 32 }}>
      <Link href="/incidents" style={{ fontSize: 12, color: "#6E7780", textDecoration: "none" }}>
        ← All incidents
      </Link>

      <header
        style={{
          marginTop: 12,
          padding: 20,
          background: "#1A2028",
          borderRadius: 6,
          borderLeft: `3px solid ${severityColor(row.severity)}`,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 8 }}>
          <SeverityPill severity={row.severity} />
          <span style={{ fontSize: 11, color: "#6E7780", fontFamily: "ui-monospace, monospace" }}>
            {row.check_id} · {row.phase}
          </span>
        </div>
        <h1 style={{ fontFamily: "'Cormorant Garamond', Georgia, serif", fontSize: 24, margin: 0 }}>
          {row.title}
        </h1>
      </header>

      <section style={sectionStyle}>
        <h2 style={h2Style}>Detail</h2>
        <pre style={detailPreStyle}>{row.detail}</pre>
      </section>

      <section style={sectionStyle}>
        <h2 style={h2Style}>Metadata</h2>
        <table style={tableStyle}>
          <tbody>
            <Row label="Event ID">{row.id}</Row>
            <Row label="Recorded">{new Date(row.ts).toISOString()} (event)</Row>
            <Row label="Received">{new Date(row.received_at).toISOString()} (Guardian)</Row>
            <Row label="Latency">{Math.max(0, row.received_at.getTime() - row.ts.getTime())} ms</Row>
            <Row label="Agent">{row.agent_id}</Row>
            <Row label="Model">
              {row.model_provider ?? "—"} / {row.model_name ?? "—"}
            </Row>
            <Row label="Action">{row.action}</Row>
            <Row label="Fingerprint">{row.fingerprint}</Row>
            <Row label="Sentinel">{row.sentinel_version}</Row>
          </tbody>
        </table>
      </section>

      <section style={sectionStyle}>
        <h2 style={h2Style}>Privacy</h2>
        <p style={{ color: "#6E7780", fontSize: 13, margin: 0 }}>
          The original input / output is <strong>not stored</strong>. Only the 16-character SHA-256
          fingerprint above. See{" "}
          <Link href="https://github.com/lictor-ai/lictor" style={{ color: "#C9A23B" }}>
            docs/specs/wire-format.md
          </Link>{" "}
          §4 for the privacy invariants.
        </p>
      </section>
    </main>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }): ReactElement {
  return (
    <tr style={{ borderBottom: "1px solid #2A323E" }}>
      <th style={{ padding: "8px 12px 8px 0", textAlign: "left", color: "#6E7780", fontWeight: 500, fontSize: 12, width: 140 }}>
        {label}
      </th>
      <td style={{ padding: 8, fontFamily: "ui-monospace, monospace", fontSize: 12, color: "#E8E2D5" }}>
        {children}
      </td>
    </tr>
  );
}

function SeverityPill({ severity }: { severity: string }): ReactElement {
  return (
    <span
      style={{
        padding: "3px 10px",
        background: severityColor(severity),
        color: "#0F1419",
        borderRadius: 3,
        fontSize: 11,
        fontWeight: 700,
        textTransform: "uppercase",
      }}
    >
      {severity}
    </span>
  );
}

function severityColor(s: string): string {
  switch (s) {
    case "critical":
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

const sectionStyle = { marginTop: 24 };
const h2Style = { fontSize: 14, fontWeight: 600, margin: "0 0 12px" };
const detailPreStyle = {
  padding: 16,
  background: "#1A2028",
  borderRadius: 6,
  whiteSpace: "pre-wrap" as const,
  wordWrap: "break-word" as const,
  fontFamily: "ui-monospace, monospace",
  fontSize: 12,
  lineHeight: 1.6,
  color: "#E8E2D5",
  margin: 0,
};
const tableStyle = {
  width: "100%",
  borderCollapse: "collapse" as const,
  background: "#1A2028",
  borderRadius: 6,
  overflow: "hidden",
};
