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
-- audit_log.account_id is intentionally ON DELETE SET NULL (not CASCADE):
-- audit logs persist after the account is deleted so the historical event
-- record survives. GDPR Article 17 (right to erasure) is satisfied via
-- a separate anonymization path (planned: audit_log_anonymize(account_id)
-- privileged function) that nullifies actor_email + redacts ip/user_agent.
-- This is the standard pattern for compliance-grade audit logs — the log
-- IS the evidence; CASCADE-deleting it would defeat its purpose.
CREATE TABLE audit_log (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id  uuid REFERENCES accounts(id) ON DELETE SET NULL,
  actor_email text NOT NULL,
  action      text NOT NULL,
  target_id   text,
  metadata    jsonb,
  created_at  timestamptz NOT NULL DEFAULT now(),
  ip          inet,
  user_agent  text
);
CREATE INDEX idx_audit_log_account_ts ON audit_log (account_id, created_at DESC);

-- Block tampering with audit content. Two triggers:
--
--   1. UPDATE: allow if and only if the audit-content fields are unchanged.
--      This permits FK SET NULL on account_id (used for GDPR Article 17
--      account deletion — the audit row survives, account_id nullifies)
--      and the future audit_log_anonymize() function. It blocks every
--      attempt to modify what the row recorded.
--
--   2. DELETE: blocked unconditionally. The audit log IS the evidence.
--      Even our own CASCADE FK uses SET NULL, never DELETE.
--
-- Rationale documented in `docs/specs/guardian-schema.md` §audit-log-rules.
CREATE OR REPLACE FUNCTION block_audit_log_tampering() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    -- Allow UPDATE only if all audit-content fields are unchanged.
    -- account_id is allowed to change (FK SET NULL for GDPR account deletion).
    IF NEW.actor_email IS DISTINCT FROM OLD.actor_email
       OR NEW.action IS DISTINCT FROM OLD.action
       OR NEW.target_id IS DISTINCT FROM OLD.target_id
       OR NEW.metadata::text IS DISTINCT FROM OLD.metadata::text
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.ip::text IS DISTINCT FROM OLD.ip::text
       OR NEW.user_agent IS DISTINCT FROM OLD.user_agent
       OR NEW.id IS DISTINCT FROM OLD.id THEN
      RAISE EXCEPTION 'audit_log is append-only (cannot tamper with audit content)';
    END IF;
    RETURN NEW;
  END IF;

  -- DELETE is always blocked.
  RAISE EXCEPTION 'audit_log is append-only (cannot delete audit rows)';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER no_audit_log_tamper
  BEFORE UPDATE ON audit_log FOR EACH ROW EXECUTE FUNCTION block_audit_log_tampering();

CREATE TRIGGER no_audit_log_delete
  BEFORE DELETE ON audit_log FOR EACH ROW EXECUTE FUNCTION block_audit_log_tampering();
