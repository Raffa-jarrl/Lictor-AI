# Guardian — Multi-Tenant Migration Path

> **Status:** v0.1 ships single-tenant-per-account ("one user owns the org"). The schema is already multi-tenant-shaped. This doc is the migration recipe to flip the switch when we sell to platforms (Zapier, Make, Manus) that need org-scoped access.

## Why this matters

Selling Guardian to Zapier or any platform with multi-team customers requires multi-tenancy. Building it from day one would have slipped Phase 2. Building it *prepared* — schema-shaped, queries scoped, no architectural blockers — costs nothing now and saves 4–6 weeks when the enterprise sale happens.

## What's already correct in v0.1

The schema in [`guardian-schema.md`](./guardian-schema.md) was designed against this future. Specifically:

- **Every event row carries `account_id`.** No table is "global"; nothing scopes to `user.id` or session-only.
- **Indexes are `(account_id, ...)` shaped.** `idx_incidents_account_ts`, `idx_incidents_account_severity`, `idx_incidents_account_check_id`. They keep working unchanged when `account_id` becomes `org_id`.
- **The audit_log is per-account.** Append-only, foreign-keyed to `accounts(id)`.
- **Foreign keys cascade on account delete.** GDPR right-to-erasure works without code changes.
- **The ingest path resolves `Bearer <token>` → `account_id` server-side.** Token rotation per account is built-in. Multi-token-per-org is one INSERT away.

## What needs to flip when we go multi-tenant

A single migration. Here's the recipe.

### Step 1 — rename `accounts` to `orgs`, add `users` and `memberships`

```sql
-- 0010_multi_tenant.sql

ALTER TABLE accounts RENAME TO orgs;

CREATE TABLE users (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email       text UNIQUE NOT NULL,
  name        text,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE memberships (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id      uuid NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role        text NOT NULL CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
  created_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, user_id)
);

-- Move the `email` from orgs into users; create a membership for each.
INSERT INTO users (id, email, name)
SELECT gen_random_uuid(), email, name FROM orgs;

INSERT INTO memberships (org_id, user_id, role)
SELECT o.id, u.id, 'owner'
FROM orgs o JOIN users u ON u.email = o.email;

ALTER TABLE orgs DROP COLUMN email;
ALTER TABLE orgs DROP COLUMN name;
-- Keep org_name. Move the org-level fields (plan, ingest_token) as-is.
```

### Step 2 — rename `account_id` → `org_id` everywhere

```sql
ALTER TABLE incidents     RENAME COLUMN account_id TO org_id;
ALTER TABLE audit_log     RENAME COLUMN account_id TO org_id;
ALTER TABLE magic_links   RENAME COLUMN account_id TO org_id;

-- Sessions become user-scoped, not org-scoped.
ALTER TABLE sessions      RENAME COLUMN account_id TO user_id;
ALTER TABLE sessions      ADD COLUMN current_org_id uuid REFERENCES orgs(id);
```

### Step 3 — rename indexes

```sql
ALTER INDEX idx_incidents_account_ts        RENAME TO idx_incidents_org_ts;
ALTER INDEX idx_incidents_account_severity  RENAME TO idx_incidents_org_severity;
ALTER INDEX idx_incidents_account_check_id  RENAME TO idx_incidents_org_check_id;
ALTER INDEX idx_audit_log_account_ts        RENAME TO idx_audit_log_org_ts;
```

That's the whole DB migration.

### Step 4 — TS type updates

In `src/lib/db.ts`, rename the `account_id` column on every interface to `org_id` and add the new tables. The existing query patterns work unchanged.

### Step 5 — auth flow

- `magic_links` issuance now creates a `user`, not an account
- After magic-link consumption, if the user has 0 orgs, create a default org + owner membership
- Session middleware reads `current_org_id` from the session, falls back to first org by membership
- Add an org-switcher UI in the dashboard header

Estimated time end-to-end: **3–4 days of focused work.** Done in ~Q1 2027 when we have the first multi-team enterprise customer to motivate it.

## What we deliberately don't do until then

- No org-switcher UI (single org only at v0.1)
- No invitation / onboarding flow for org members
- No RBAC beyond owner-of-account
- No SSO/SAML (lands with multi-tenant migration)
- No org-level billing (v0.1 charges the account; multi-tenant moves billing to the org)

The cost of *not* shipping these in v0.1 is exactly zero — the schema accommodates them when they land. The cost of *shipping* them in v0.1 would be 4–6 weeks of Phase 2 time we don't have.

## Triggers for running this migration

Earliest of:

1. First enterprise customer asks for multi-team scoping during a sales call
2. We close a deal contingent on org-scoped access
3. Free-preview Guardian users start emailing to ask for it (signal: 3+ unsolicited requests in a single month)
4. Q1 2027 anyway, regardless of demand — by then we should be ready

When the trigger fires, this doc becomes the runbook.
