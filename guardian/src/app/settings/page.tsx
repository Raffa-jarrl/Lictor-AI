/**
 * /settings — account settings page.
 *
 * v0.1: Slack webhook config + ingest token display + plan info.
 */

import Link from "next/link";
import { redirect } from "next/navigation";
import type { ReactElement } from "react";

import { getSession } from "@/lib/auth";
import { db } from "@/lib/db";

export const dynamic = "force-dynamic";

interface PageProps {
  searchParams: Promise<{ ok?: string; err?: string }>;
}

export default async function SettingsPage({ searchParams }: PageProps): Promise<ReactElement> {
  const session = await getSession();
  if (!session) redirect("/");

  const params = await searchParams;

  const [account, slack, stripeCustomer] = await Promise.all([
    db()
      .selectFrom("accounts")
      .select(["email", "ingest_token", "plan"])
      .where("id", "=", session.accountId)
      .executeTakeFirstOrThrow(),
    db()
      .selectFrom("slack_integrations")
      .selectAll()
      .where("account_id", "=", session.accountId)
      .executeTakeFirst(),
    db()
      .selectFrom("stripe_customers")
      .select(["preview_started_at", "preview_ends_at"])
      .where("account_id", "=", session.accountId)
      .executeTakeFirst(),
  ]);

  const daysLeft = stripeCustomer
    ? Math.max(0, Math.ceil((stripeCustomer.preview_ends_at.getTime() - Date.now()) / (24 * 60 * 60_000)))
    : null;

  return (
    <main style={{ maxWidth: 800, margin: "0 auto", padding: 32 }}>
      <Link href="/dashboard" style={{ fontSize: 12, color: "#6E7780", textDecoration: "none" }}>
        ← Dashboard
      </Link>
      <h1 style={{ fontFamily: "'Cormorant Garamond', Georgia, serif", fontSize: 28, margin: "8px 0 24px" }}>
        Settings
      </h1>

      {params.ok === "slack" && (
        <Banner color="#3D7C5E">Slack webhook saved.</Banner>
      )}
      {params.err && (
        <Banner color="#C0392B">{decodeURIComponent(params.err)}</Banner>
      )}

      {/* Plan */}
      <Section title="Plan">
        <Row label="Tier">{account.plan}</Row>
        {daysLeft !== null && (
          <Row label="Preview ends">
            {daysLeft} day{daysLeft === 1 ? "" : "s"} from now
          </Row>
        )}
      </Section>

      {/* Ingest token */}
      <Section title="Ingest token">
        <p style={{ color: "#6E7780", fontSize: 12, marginTop: 0 }}>
          Set this in your application's environment to forward incidents to Guardian.
        </p>
        <pre style={tokenBoxStyle}>LICTOR_GUARDIAN_TOKEN={account.ingest_token}</pre>
      </Section>

      {/* Slack webhook */}
      <Section title="Slack webhook">
        <form action="/api/settings/slack" method="POST" style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          <Field label="Incoming webhook URL">
            <input
              type="url"
              name="webhook_url"
              required
              placeholder="https://hooks.slack.com/services/T.../B.../..."
              defaultValue={slack?.webhook_url ?? ""}
              style={inputStyle}
            />
          </Field>
          <Field label="Minimum severity to notify">
            <select
              name="min_severity"
              defaultValue={slack?.min_severity ?? "high"}
              style={inputStyle}
            >
              <option value="critical">Critical only</option>
              <option value="high">High and above</option>
              <option value="medium">Medium and above</option>
              <option value="low">Low and above</option>
              <option value="info">All (noisy)</option>
            </select>
          </Field>
          <Field label="Enabled">
            <select name="enabled" defaultValue={slack?.enabled === false ? "false" : "true"} style={inputStyle}>
              <option value="true">Yes</option>
              <option value="false">Paused</option>
            </select>
          </Field>
          <button type="submit" style={btnStyle}>
            Save webhook
          </button>
        </form>
        {slack?.last_fired_at && (
          <p style={{ marginTop: 12, fontSize: 12, color: "#6E7780" }}>
            Last fired: {new Date(slack.last_fired_at).toISOString().slice(0, 19).replace("T", " ")} UTC
          </p>
        )}
        {slack?.last_error && (
          <p style={{ marginTop: 6, fontSize: 12, color: "#C0392B" }}>
            Last error: {slack.last_error}
          </p>
        )}
      </Section>
    </main>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }): ReactElement {
  return (
    <section style={{ marginBottom: 32, padding: 20, background: "#1A2028", borderRadius: 8 }}>
      <h2 style={{ fontSize: 14, fontWeight: 600, marginTop: 0, marginBottom: 16 }}>{title}</h2>
      {children}
    </section>
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

function Row({ label, children }: { label: string; children: React.ReactNode }): ReactElement {
  return (
    <div style={{ display: "flex", marginBottom: 8 }}>
      <span style={{ width: 140, color: "#6E7780", fontSize: 12 }}>{label}</span>
      <span style={{ fontSize: 13 }}>{children}</span>
    </div>
  );
}

function Banner({ color, children }: { color: string; children: React.ReactNode }): ReactElement {
  return (
    <div
      style={{
        padding: "8px 12px",
        background: `${color}20`,
        border: `1px solid ${color}`,
        borderRadius: 4,
        marginBottom: 16,
        color: "#E8E2D5",
        fontSize: 12,
      }}
    >
      {children}
    </div>
  );
}

const inputStyle = {
  padding: "8px 12px",
  background: "#0F1419",
  color: "#E8E2D5",
  border: "1px solid #2A323E",
  borderRadius: 4,
  fontSize: 13,
  fontFamily: "ui-monospace, monospace",
};
const btnStyle = {
  marginTop: 8,
  padding: "10px 16px",
  background: "#C9A23B",
  color: "#0F1419",
  border: "none",
  borderRadius: 4,
  fontWeight: 600,
  cursor: "pointer",
  alignSelf: "flex-start",
} as const;
const tokenBoxStyle = {
  margin: 0,
  padding: 12,
  background: "#0F1419",
  borderRadius: 4,
  fontFamily: "ui-monospace, monospace",
  fontSize: 11,
  color: "#C9A23B",
  overflowX: "auto" as const,
};
