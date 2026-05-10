/**
 * Postgres connection — single source of truth.
 *
 * Uses Kysely (type-safe SQL builder) over `pg`. No ORM magic; no schema
 * generation; you write SQL in migrations and TypeScript types here.
 *
 * v0.1: connection lazily initialized on first use. No connection pooling
 * tuning yet — defaults are fine for the launch traffic estimate (<100 RPS).
 */

import { Kysely, PostgresDialect, type Generated } from "kysely";
import pg from "pg";

const { Pool } = pg;

// ─── Database schema (TypeScript mirror of `migrations/0001_initial.sql`) ───
// Keep these types in lockstep with the SQL. `Generated<T>` marks columns
// that the database fills in by default — these are optional on INSERT but
// always present on SELECT.

export interface Database {
  accounts: AccountsTable;
  magic_links: MagicLinksTable;
  sessions: SessionsTable;
  incidents: IncidentsTable;
  audit_log: AuditLogTable;
}

export interface AccountsTable {
  id: Generated<string>;
  email: string;
  name: string | null;
  org_name: string | null;
  plan: Generated<"preview" | "pro" | "team" | "org">;
  ingest_token: string;
  created_at: Generated<Date>;
  updated_at: Generated<Date>;
}

export interface MagicLinksTable {
  id: Generated<string>;
  account_id: string | null;
  email: string;
  token_hash: string;
  expires_at: Date;
  consumed_at: Date | null;
  created_at: Generated<Date>;
}

export interface SessionsTable {
  id: Generated<string>;
  account_id: string;
  created_at: Generated<Date>;
  last_seen_at: Generated<Date>;
  revoked_at: Date | null;
}

export interface IncidentsTable {
  id: Generated<string>;
  account_id: string;
  agent_id: string;
  ts: Date;
  received_at: Generated<Date>;
  phase: "preflight" | "postflight";
  check_id: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  detail: string;
  model_provider: string | null;
  model_name: string | null;
  fingerprint: string;
  action: "logged" | "blocked" | "redacted";
  sentinel_version: string;
}

export interface AuditLogTable {
  id: Generated<string>;
  account_id: string;
  actor_email: string;
  action: string;
  target_id: string | null;
  metadata: unknown;
  created_at: Generated<Date>;
  ip: string | null;
  user_agent: string | null;
}

let _db: Kysely<Database> | null = null;

/** Get the shared Kysely instance. Lazily initialized. */
export function db(): Kysely<Database> {
  if (_db) return _db;

  const url = process.env["DATABASE_URL"];
  if (!url) {
    throw new Error(
      "DATABASE_URL is not set. Copy .env.example to .env.local and fill it in.",
    );
  }

  _db = new Kysely<Database>({
    dialect: new PostgresDialect({
      pool: new Pool({ connectionString: url, max: 10 }),
    }),
  });

  return _db;
}
