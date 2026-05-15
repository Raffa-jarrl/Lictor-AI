/**
 * TypeScript types for AUDIT.json v0.1.
 *
 * These types mirror the schema at:
 *   ~/Lictor/docs/standards/AUDIT.schema.json
 *
 * Keep them in sync. If the schema changes, regenerate (or hand-update) these.
 *
 * A future version will auto-generate these from the schema via
 * `json-schema-to-typescript` — manual for v0.1.0-pre.0.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type TargetType =
  | "repository"
  | "deployed-site"
  | "container-image"
  | "package"
  | "binary"
  | "iac";

export type PlatformFingerprint =
  | "lovable"
  | "bolt"
  | "v0"
  | "cursor"
  | "replit"
  | "claude-code"
  | "windsurf"
  | "custom"
  | "unknown";

export interface Tool {
  name: string;
  version: string;
  vendor?: string;
}

export interface Target {
  type: TargetType;
  url_or_path?: string;
  platform_fingerprint?: PlatformFingerprint;
  platform_confidence?: number;
  commit_sha?: string;
  branch?: string;
}

export interface AuditMeta {
  started: string; // ISO 8601
  completed?: string;
  duration_ms?: number;
  checks_run?: number;
  partial?: boolean;
}

export interface Summary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}

export interface Evidence {
  file_path?: string;
  line?: number;
  line_end?: number;
  column?: number;
  code_snippet?: string;
  url?: string | null;
}

export interface Fix {
  summary?: string;
  diff_or_snippet?: string;
  rotated_secrets_needed?: string[];
  estimated_effort_minutes?: number;
}

export interface Finding {
  id: string;
  severity: Severity;
  category?: string;
  title: string;
  summary: string;
  evidence?: Evidence;
  fix?: Fix;
  agent?: string;
  agent_confidence?: number;
  references?: string[];
  cwe?: string[];
  cve?: string[];
  fingerprint?: string;
}

export interface AgentAttribution {
  agent: string;
  found_count?: number;
  scored_count?: number;
  confidence_avg?: number | null;
}

export interface AuditDocument {
  spec_version: string;
  tool: Tool;
  target: Target;
  audit: AuditMeta;
  summary: Summary;
  findings: Finding[];
  agent_attributions?: AgentAttribution[];
  notes?: string[];
}

/**
 * The severity color map — used by SeverityBadge component.
 * Matches the icon ladder used everywhere else in Lictor.
 */
export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "text-red-500",
  high: "text-orange-500",
  medium: "text-yellow-500",
  low: "text-blue-500",
  info: "text-zinc-500",
};

export const SEVERITY_ICONS: Record<Severity, string> = {
  critical: "🔴",
  high: "🟠",
  medium: "🟡",
  low: "🔵",
  info: "⚪",
};
