/**
 * /incidents — filtered timeline view.
 *
 * Query params:
 *   ?severity=critical|high|medium|low|info  — filter by severity
 *   ?check=prompt-injection|pii-leak|secrets-in-input  — filter by check id
 *   ?phase=preflight|postflight  — filter by phase
 *   ?since=7d|24h|1h  — relative time window (default: 7d)
 *   ?page=1  — pagination
 *
 * Pagination: 50 per page. The query takes O(log n) thanks to the
 * (account_id, ts DESC) composite index from migration 0001.
 */

import Link from "next/link";
import { redirect } from "next/navigation";
import { sql } from "kysely";
import type { ReactElement } from "react";

import { getSession } from "@/lib/auth";
import { db } from "@/lib/db";

export const dynamic = "force-dynamic";

const PAGE_SIZE = 50;

const VALID_SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
const VALID_CHECKS = ["prompt-injection", "pii-leak", "secrets-in-input", "unsafe-tool-call"] as const;
const VALID_PHASES = ["preflight", "postflight"] as const;

const TIME_WINDOWS: Record<string, number> = {
  "1h": 60 * 60_000,
  "24h": 24 * 60 * 60_000,
  "7d": 7 * 24 * 60 * 60_000,
  "30d": 30 * 24 * 60 * 60_000,
};

interface PageProps {
  searchParams: Promise<{
    severity?: string;
    check?: string;
    phase?: string;
    since?: string;
    page?: string;
  }>;
}

export default async function IncidentsPage({ searchParams }: PageProps): Promise<ReactElement> {
  const session = await getSession();
  if (!session) redirect("/");

  const params = await searchParams;
  const severity = params.severity && (VALID_SEVERITIES as readonly string[]).includes(params.severity)
    ? (params.severity as (typeof VALID_SEVERITIES)[number])
    : null;
  const check = params.check && (VALID_CHECKS as readonly string[]).includes(params.check)
    ? params.check
    : null;
  const phase = params.phase && (VALID_PHASES as readonly string[]).includes(params.phase)
    ? (params.phase as (typeof VALID_PHASES)[number])
    : null;
  const sinceKey = params.since && TIME_WINDOWS[params.since] !== undefined ? params.since : "7d";
  const sinceMs = TIME_WINDOWS[sinceKey]!;
  const since = new Date(Date.now() - sinceMs);
  const page = Math.max(1, parseInt(params.page ?? "1", 10) || 1);
  const offset = (page - 1) * PAGE_SIZE;

  // Build the filter chain — same for both count and select.
  let q = db()
    .selectFrom("incidents")
    .where("account_id", "=", session.accountId)
    .where("ts", ">=", since);
  if (severity) q = q.where("severity", "=", severity);
  if (check) q = q.where("check_id", "=", check);
  if (phase) q = q.where("phase", "=", phase);

  const [rows, countRow] = await Promise.all([
    q
      .select(["id", "ts", "phase", "severity", "check_id", "title", "model_name", "fingerprint", "action"])
      .orderBy("ts", "desc")
      .limit(PAGE_SIZE)
      .offset(offset)
      .execute(),
    q.select(sql<string>`count(*)::text`.as("c")).executeTakeFirstOrThrow(),
  ]);

  const total = Number(countRow.c);
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <main style={{ maxWidth: 1200, margin: "0 auto", padding: 32 }}>
      <header style={headerStyle}>
        <div>
          <Link href="/dashboard" style={crumbStyle}>
            ← Dashboard
          </Link>
          <h1 style={h1Style}>Incidents</h1>
        </div>
        <Link href="/export" style={exportLinkStyle}>
          Export audit log →
        </Link>
      </header>

      {/* Filter bar */}
      <FilterBar
        severity={severity}
        check={check}
        phase={phase}
        since={sinceKey}
        total={total}
      />

      {/* Results */}
      {rows.length === 0 ? (
        <EmptyState filtered={!!(severity || check || phase)} />
      ) : (
        <>
          <ul style={listStyle}>
            {rows.map((row) => (
              <IncidentRow key={row.id} row={row} />
            ))}
          </ul>
          <Pagination current={page} total={totalPages} params={params} />
        </>
      )}
    </main>
  );
}

// ─── Subcomponents ───────────────────────────────────────────────────────────

interface FilterBarProps {
  severity: string | null;
  check: string | null;
  phase: string | null;
  since: string;
  total: number;
}

function FilterBar({ severity, check, phase, since, total }: FilterBarProps): ReactElement {
  return (
    <form method="GET" style={filterFormStyle}>
      <Select name="severity" label="Severity" value={severity} options={["", ...VALID_SEVERITIES]} />
      <Select name="check" label="Check" value={check} options={["", ...VALID_CHECKS]} />
      <Select name="phase" label="Phase" value={phase} options={["", ...VALID_PHASES]} />
      <Select name="since" label="Window" value={since} options={["1h", "24h", "7d", "30d"]} />
      <button type="submit" style={applyBtnStyle}>
        Apply
      </button>
      <span style={{ marginLeft: "auto", color: "#6E7780", fontSize: 12 }}>
        {total} match{total === 1 ? "" : "es"}
      </span>
    </form>
  );
}

function Select({
  name,
  label,
  value,
  options,
}: {
  name: string;
  label: string;
  value: string | null;
  options: readonly string[];
}): ReactElement {
  return (
    <label style={selectLabelStyle}>
      <span style={{ fontSize: 11, color: "#6E7780", textTransform: "uppercase" }}>{label}</span>
      <select name={name} defaultValue={value ?? ""} style={selectStyle}>
        {options.map((opt) => (
          <option key={opt} value={opt}>
            {opt === "" ? "all" : opt}
          </option>
        ))}
      </select>
    </label>
  );
}

interface IncidentRowProps {
  row: {
    id: string;
    ts: Date;
    phase: string;
    severity: string;
    check_id: string;
    title: string;
    model_name: string | null;
    fingerprint: string;
    action: string;
  };
}

function IncidentRow({ row }: IncidentRowProps): ReactElement {
  return (
    <li
      style={{
        ...rowStyle,
        borderLeft: `3px solid ${severityColor(row.severity)}`,
      }}
    >
      <Link href={`/incidents/${row.id}`} style={{ display: "block", color: "inherit", textDecoration: "none" }}>
        <div style={{ display: "flex", justifyContent: "space-between" }}>
          <span style={{ fontWeight: 500 }}>{row.title}</span>
          <span style={{ fontSize: 11, color: "#6E7780", whiteSpace: "nowrap" }}>
            {new Date(row.ts).toISOString().slice(0, 19).replace("T", " ")} UTC
          </span>
        </div>
        <div style={metaRowStyle}>
          <Tag>{row.severity}</Tag>
          <Tag>{row.phase}</Tag>
          <Tag>{row.check_id}</Tag>
          {row.model_name && <Tag muted>{row.model_name}</Tag>}
          <Tag muted>{row.action}</Tag>
          <span style={{ color: "#6E7780", fontFamily: "ui-monospace, monospace" }}>{row.fingerprint}</span>
        </div>
      </Link>
    </li>
  );
}

function Tag({ children, muted = false }: { children: string; muted?: boolean }): ReactElement {
  return (
    <span
      style={{
        padding: "2px 6px",
        borderRadius: 3,
        background: muted ? "transparent" : "#0F1419",
        border: muted ? "1px solid #2A323E" : "none",
        fontSize: 10,
        color: muted ? "#6E7780" : "#E8E2D5",
        textTransform: muted ? "none" : "uppercase",
        fontFamily: muted ? "ui-monospace, monospace" : "inherit",
      }}
    >
      {children}
    </span>
  );
}

function EmptyState({ filtered }: { filtered: boolean }): ReactElement {
  return (
    <div style={emptyStateStyle}>
      <div style={{ marginBottom: 8, fontWeight: 600 }}>
        {filtered ? "No incidents match those filters." : "No incidents yet."}
      </div>
      <div style={{ fontSize: 12, color: "#6E7780" }}>
        {filtered ? (
          "Try widening the time window or clearing filters."
        ) : (
          <>
            Wire <code>@lictor/sentinel</code> into your AI app — the first incident lands here.
          </>
        )}
      </div>
    </div>
  );
}

function Pagination({
  current,
  total,
  params,
}: {
  current: number;
  total: number;
  params: Record<string, string | undefined>;
}): ReactElement | null {
  if (total <= 1) return null;
  const qs = (page: number) => {
    const p = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) {
      if (v && k !== "page") p.set(k, v);
    }
    p.set("page", String(page));
    return `?${p.toString()}`;
  };

  const prev = current > 1 ? current - 1 : null;
  const next = current < total ? current + 1 : null;

  return (
    <nav style={paginationStyle}>
      {prev !== null ? (
        <Link href={qs(prev)} style={paginationLinkStyle}>
          ← Prev
        </Link>
      ) : (
        <span style={paginationDisabledStyle}>← Prev</span>
      )}
      <span style={{ color: "#6E7780", fontSize: 12 }}>
        Page {current} of {total}
      </span>
      {next !== null ? (
        <Link href={qs(next)} style={paginationLinkStyle}>
          Next →
        </Link>
      ) : (
        <span style={paginationDisabledStyle}>Next →</span>
      )}
    </nav>
  );
}

// ─── Styles ──────────────────────────────────────────────────────────────────

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

const headerStyle = {
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  marginBottom: 32,
} as const;
const crumbStyle = { fontSize: 12, color: "#6E7780", textDecoration: "none" } as const;
const h1Style = {
  fontFamily: "'Cormorant Garamond', Georgia, serif",
  fontSize: 28,
  fontWeight: 700,
  margin: "8px 0 0",
} as const;
const exportLinkStyle = {
  fontSize: 12,
  color: "#C9A23B",
  textDecoration: "none",
  border: "1px solid #2A323E",
  padding: "6px 12px",
  borderRadius: 4,
} as const;
const filterFormStyle = {
  display: "flex",
  alignItems: "flex-end",
  gap: 12,
  marginBottom: 24,
  padding: 16,
  background: "#1A2028",
  borderRadius: 6,
  flexWrap: "wrap" as const,
};
const selectLabelStyle = {
  display: "flex",
  flexDirection: "column" as const,
  gap: 4,
};
const selectStyle = {
  padding: "6px 10px",
  background: "#0F1419",
  color: "#E8E2D5",
  border: "1px solid #2A323E",
  borderRadius: 4,
  fontSize: 13,
};
const applyBtnStyle = {
  padding: "8px 16px",
  background: "#C9A23B",
  color: "#0F1419",
  border: "none",
  borderRadius: 4,
  fontWeight: 600,
  cursor: "pointer",
} as const;
const listStyle = { listStyle: "none", margin: 0, padding: 0, display: "flex", flexDirection: "column" as const, gap: 6 };
const rowStyle = {
  padding: "12px 16px",
  background: "#1A2028",
  borderRadius: 6,
  transition: "background 0.1s",
} as const;
const metaRowStyle = {
  display: "flex",
  gap: 8,
  fontSize: 11,
  color: "#6E7780",
  marginTop: 6,
  alignItems: "center",
  flexWrap: "wrap" as const,
};
const emptyStateStyle = {
  padding: 32,
  background: "#1A2028",
  borderRadius: 6,
  color: "#6E7780",
  textAlign: "center" as const,
};
const paginationStyle = {
  display: "flex",
  justifyContent: "center",
  alignItems: "center",
  gap: 24,
  marginTop: 24,
} as const;
const paginationLinkStyle = {
  padding: "6px 12px",
  border: "1px solid #2A323E",
  borderRadius: 4,
  color: "#C9A23B",
  textDecoration: "none",
  fontSize: 12,
};
const paginationDisabledStyle = {
  padding: "6px 12px",
  border: "1px solid #2A323E",
  borderRadius: 4,
  color: "#3A4250",
  fontSize: 12,
};
