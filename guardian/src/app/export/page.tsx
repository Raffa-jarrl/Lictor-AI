/**
 * /export — audit log export form.
 *
 * Lets the user pick a date range + format and downloads the export.
 * Each download is recorded in audit_log via /api/export/incidents.
 */

import Link from "next/link";
import { redirect } from "next/navigation";
import type { ReactElement } from "react";

import { getSession } from "@/lib/auth";

export const dynamic = "force-dynamic";

export default async function ExportPage(): Promise<ReactElement> {
  const session = await getSession();
  if (!session) redirect("/");

  const today = new Date().toISOString().slice(0, 10);
  const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60_000).toISOString().slice(0, 10);

  return (
    <main style={{ maxWidth: 600, margin: "0 auto", padding: 32 }}>
      <Link href="/dashboard" style={{ fontSize: 12, color: "#6E7780", textDecoration: "none" }}>
        ← Dashboard
      </Link>
      <h1 style={{ fontFamily: "'Cormorant Garamond', Georgia, serif", fontSize: 28, margin: "8px 0 24px" }}>
        Audit log export
      </h1>

      <p style={{ color: "#6E7780", fontSize: 13, marginBottom: 24 }}>
        Download every incident in a date range, as CSV or JSON. Each export is itself recorded in
        the audit log (actor: {session.email}). Use this for SOC 2 evidence, GDPR Article 32
        record-of-processing, or EU AI Act Article 12 documentation.
      </p>

      <form action="/api/export/incidents" method="GET" style={formStyle}>
        <Field label="From">
          <input type="date" name="since" defaultValue={thirtyDaysAgo} required style={inputStyle} />
        </Field>
        <Field label="To">
          <input type="date" name="until" defaultValue={today} required style={inputStyle} />
        </Field>
        <Field label="Format">
          <select name="format" defaultValue="json" style={inputStyle}>
            <option value="json">JSON</option>
            <option value="csv">CSV</option>
          </select>
        </Field>
        <button type="submit" style={btnStyle}>
          Download
        </button>
      </form>

      <section style={{ marginTop: 32 }}>
        <h2 style={{ fontSize: 14, fontWeight: 600 }}>What's included?</h2>
        <ul style={{ color: "#6E7780", fontSize: 13, lineHeight: 1.8 }}>
          <li>Every incident your account recorded in the date range</li>
          <li>Full event metadata: ts, severity, check_id, model, fingerprint, action</li>
          <li>Up to 100,000 rows per export (v0.2 will stream larger sets)</li>
        </ul>
      </section>

      <section style={{ marginTop: 24 }}>
        <h2 style={{ fontSize: 14, fontWeight: 600 }}>What's NOT included?</h2>
        <ul style={{ color: "#6E7780", fontSize: 13, lineHeight: 1.8 }}>
          <li>The raw user input or model output — only fingerprints are ever stored</li>
          <li>Cross-account incidents (you only see your own)</li>
        </ul>
      </section>
    </main>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }): ReactElement {
  return (
    <label style={{ display: "flex", flexDirection: "column", gap: 4 }}>
      <span style={{ fontSize: 11, color: "#6E7780", textTransform: "uppercase" }}>{label}</span>
      {children}
    </label>
  );
}

const formStyle = {
  display: "grid",
  gridTemplateColumns: "1fr 1fr 1fr",
  gap: 16,
  padding: 24,
  background: "#1A2028",
  borderRadius: 8,
  alignItems: "end",
};

const inputStyle = {
  padding: "8px 12px",
  background: "#0F1419",
  color: "#E8E2D5",
  border: "1px solid #2A323E",
  borderRadius: 4,
  fontSize: 14,
};

const btnStyle = {
  padding: "10px 16px",
  background: "#C9A23B",
  color: "#0F1419",
  border: "none",
  borderRadius: 4,
  fontWeight: 600,
  cursor: "pointer",
  gridColumn: "1 / -1",
} as const;
