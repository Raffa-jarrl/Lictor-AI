-- Lictor Guardian — initial schema.
-- See `~/Lictor/docs/specs/guardian-schema.md` for the contract this implements.
-- Don't edit this file in place; add a new numbered migration.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ─────────────────────────────────────────────────────────────────────────────
-- accounts
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE accounts (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email         text UNIQUE NOT NULL,
  name          text,
  org_name      text,
  plan          text NOT NULL DEFAULT 'preview'
                CHECK (plan IN ('preview', 'pro', 'team', 'org')),
  ingest_token  text UNIQUE NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_accounts_email_lower    ON accounts (lower(email));
CREATE INDEX idx_accounts_ingest_token   ON accounts (ingest_token);

-- ─────────────────────────────────────────────────────────────────────────────
-- magic_links
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE magic_links (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id  uuid REFERENCES accounts(id) ON DELETE CASCADE,
  email       text NOT NULL,
  token_hash  text NOT NULL,
  expires_at  timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_magic_links_token_hash ON magic_links (token_hash);

-- ─────────────────────────────────────────────────────────────────────────────
-- sessions
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE sessions (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id    uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  created_at    timestamptz NOT NULL DEFAULT now(),
  last_seen_at  timestamptz NOT NULL DEFAULT now(),
  revoked_at    timestamptz
);
CREATE INDEX idx_sessions_account_active ON sessions (account_id) WHERE revoked_at IS NULL;

-- ─────────────────────────────────────────────────────────────────────────────
-- incidents — the core append-only event store
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE incidents (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id        uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  agent_id          text NOT NULL,
  ts                timestamptz NOT NULL,
  received_at       timestamptz NOT NULL DEFAULT now(),
  phase             text NOT NULL CHECK (phase IN ('preflight', 'postflight')),
  check_id          text NOT NULL,
  severity          text NOT NULL
                    CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
  title             text NOT NULL CHECK (length(title) <= 200),
  detail            text NOT NULL CHECK (length(detail) <= 2000),
  model_provider    text,
  model_name        text,
  fingerprint       text NOT NULL,
  action            text NOT NULL CHECK (action IN ('logged', 'blocked', 'redacted')),
  sentinel_version  text NOT NULL
);
CREATE INDEX idx_incidents_account_ts        ON incidents (account_id, ts DESC);
CREATE INDEX idx_incidents_account_severity  ON incidents (account_id, severity, ts DESC);
CREATE INDEX idx_incidents_account_check_id  ON incidents (account_id, check_id, ts DESC);

-- ─────────────────────────────────────────────────────────────────────────────
-- audit_log — append-only, no UPDATE / DELETE allowed
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE audit_log (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id  uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  actor_email text NOT NULL,
  action      text NOT NULL,
  target_id   text,
  metadata    jsonb,
  created_at  timestamptz NOT NULL DEFAULT now(),
  ip          inet,
  user_agent  text
);
CREATE INDEX idx_audit_log_account_ts ON audit_log (account_id, created_at DESC);

-- Block UPDATE and DELETE on audit_log (compliance-grade append-only).
CREATE OR REPLACE FUNCTION block_audit_log_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_log is append-only';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER no_audit_log_update
  BEFORE UPDATE ON audit_log FOR EACH ROW EXECUTE FUNCTION block_audit_log_mutation();

CREATE TRIGGER no_audit_log_delete
  BEFORE DELETE ON audit_log FOR EACH ROW EXECUTE FUNCTION block_audit_log_mutation();
