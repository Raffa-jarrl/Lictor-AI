/**
 * Shared types between content / background / popup.
 *
 * Mirrors `lictor_core::finding::Finding` — keep these in sync if you ever
 * add fields to the Rust struct.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Category = "secrets" | "database" | "auth" | "cors" | "ai-agent" | "general";

export interface Finding {
  severity: Severity;
  category: Category;
  title: string;
  detail: string;
  where_found: string;
  remediation: string;
}

/** Wrapper that the WASM bridge returns for every check call. */
export interface WrappedFindings {
  findings: Finding[];
}

/** Per-tab audit state held by the background service worker. */
export interface TabAuditState {
  origin: string;
  status: "scanning" | "done" | "error";
  findings: Finding[];
  startedAt: number;
  completedAt?: number;
  error?: string;
}

// ─── Messages ────────────────────────────────────────────────────────────────

/** Sent by content → background when a page is detected as AI-built. */
export interface AuditRequest {
  type: "audit-request";
  origin: string;
  // Pre-fetched landing page HTML — so background doesn't need to refetch.
  landingHtml: string;
}

/** Sent by popup → background to fetch current state for a tab. */
export interface GetTabState {
  type: "get-tab-state";
  tabId: number;
}

/** Background's reply to popup. */
export interface TabStateReply {
  type: "tab-state";
  tabId: number;
  state: TabAuditState | null;
}

export type ContentMessage = AuditRequest;
export type PopupMessage = GetTabState;
export type BackgroundReply = TabStateReply;

// ─── Severity ranking ────────────────────────────────────────────────────────

const RANK: Record<Severity, number> = {
  info: 0, low: 1, medium: 2, high: 3, critical: 4,
};

export function severityRank(s: Severity): number {
  return RANK[s];
}

export function topSeverity(findings: Finding[]): Severity {
  return findings.reduce<Severity>(
    (acc, f) => (RANK[f.severity] > RANK[acc] ? f.severity : acc),
    "info",
  );
}
