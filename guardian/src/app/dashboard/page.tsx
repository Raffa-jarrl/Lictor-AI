/**
 * Dashboard — the authenticated incident timeline view.
 *
 * v0.1 stub. The full Phase 2 implementation queries `incidents` per the
 * read patterns in `docs/specs/guardian-schema.md` §3 and renders a paged
 * timeline filtered by severity/check_id.
 */

export default function DashboardPage() {
  return (
    <main style={{ maxWidth: 1200, margin: "0 auto", padding: 32 }}>
      <header style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 32 }}>
        <h1 style={{ fontFamily: "'Cormorant Garamond', Georgia, serif", fontSize: 28, fontWeight: 700, margin: 0 }}>
          Lictor <span style={{ color: "#C9A23B" }}>Guardian</span>
        </h1>
        <div style={{ fontSize: 12, color: "#6E7780" }}>v0.1 dashboard stub</div>
      </header>

      <div style={{ padding: 24, background: "#1A2028", borderRadius: 8, color: "#6E7780" }}>
        Dashboard not yet implemented. This page lands W11–12 (July 20–Aug 2). It will show:
        <ul style={{ marginTop: 12, lineHeight: 1.8 }}>
          <li>Severity rollup (critical / high / medium / low / info counts, last 7 days)</li>
          <li>Incident timeline (latest 100 incidents, filterable by severity + check)</li>
          <li>Per-check breakdown (which check trips most)</li>
          <li>Audit log export (CSV / JSON download)</li>
        </ul>
      </div>
    </main>
  );
}
