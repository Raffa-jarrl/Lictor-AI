# Lictor Guardian — Data Model

> **Status:** v0.1 contract. Locked W1 (May 2026). Schema migrations tracked in `~/Lictor/guardian/migrations/`.

Postgres-backed. Single-tenant per account at v0.1 (multi-tenant deferred to Phase 4 / Q1 2027).

---

## 1. Tables

### `accounts`

A Guardian account. One owner per account at v0.1. Multi-user / RBAC ships in Q1 2027.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` (PK) | `gen_random_uuid()` |
| `email` | `text` (UNIQUE, NOT NULL) | Login identity. Lowercased on write. |
| `name` | `text` | Display name, optional. |
| `org_name` | `text` | Optional organization label. |
| `plan` | `text` (NOT NULL, default `'preview'`) | One of: `preview`, `pro`, `team`, `org`. Preview = free, 90-day trial. |
| `ingest_token` | `text` (UNIQUE, NOT NULL) | The `LICTOR_GUARDIAN_TOKEN` value Sentinel SDKs send. Rotatable. |
| `created_at` | `timestamptz` (NOT NULL, default `now()`) | |
| `updated_at` | `timestamptz` (NOT NULL, default `now()`) | |

Indexes:
- `idx_accounts_email_lower` on `lower(email)`
- `idx_accounts_ingest_token` on `ingest_token` (covering — used on every ingest call)

### `magic_links`

Magic-link auth tokens. Short-lived. One row per request.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` (PK) | `gen_random_uuid()` |
| `account_id` | `uuid` (FK → accounts.id) | NULL until consumed if signing up |
| `email` | `text` (NOT NULL) | Where the magic link was sent |
| `token_hash` | `text` (NOT NULL) | **sha256(token) hex.** Tokens are 64-char hex (32 bytes random); high enough entropy that bcrypt's slow-by-design hashing is unnecessary and bcrypt's per-input salt would prevent the equality lookup we need at consumption time. The raw token never persists server-side. |
| `expires_at` | `timestamptz` (NOT NULL) | 15 minutes from creation |
| `consumed_at` | `timestamptz` | When the link was clicked. NULL = unused. |
| `created_at` | `timestamptz` (NOT NULL, default `now()`) | |

**Atomic consumption.** Magic links are claimed via `UPDATE ... WHERE consumed_at IS NULL AND expires_at > now() RETURNING account_id`. This is atomic at the row level — concurrent clicks on the same link can only one ever succeed. Verified in the integration test suite.

Indexes:
- `idx_magic_links_token_hash` on `token_hash`
- Auto-prune via cron job: `DELETE FROM magic_links WHERE expires_at < now() - interval '24 hours'`.

### `sessions`

Logged-in browser session. JWT in cookie; row in DB so we can revoke.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` (PK) | |
| `account_id` | `uuid` (FK, NOT NULL) | |
| `created_at` | `timestamptz` (NOT NULL) | |
| `last_seen_at` | `timestamptz` (NOT NULL) | Updated on each request |
| `revoked_at` | `timestamptz` | NULL = active |

### `incidents`

The core table. One row per `IncidentEvent` POSTed to `/api/ingest`. Append-only.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` (PK) | `gen_random_uuid()` |
| `account_id` | `uuid` (FK, NOT NULL) | Resolved from `ingest_token` at write time |
| `agent_id` | `text` (NOT NULL) | Stable per-process ID from Sentinel SDK |
| `ts` | `timestamptz` (NOT NULL) | Event time, from Sentinel (NOT receive time) |
| `received_at` | `timestamptz` (NOT NULL, default `now()`) | When Guardian received it |
| `phase` | `text` (NOT NULL) | `preflight` or `postflight` |
| `check_id` | `text` (NOT NULL) | `prompt-injection`, `pii-leak`, etc. |
| `severity` | `text` (NOT NULL) | `critical`, `high`, `medium`, `low`, `info` |
| `title` | `text` (NOT NULL) | ≤200 chars |
| `detail` | `text` (NOT NULL) | Longer detail; ≤2000 chars |
| `model_provider` | `text` | `openai`, `anthropic`, `other` |
| `model_name` | `text` | e.g. `gpt-4`, `claude-3-sonnet` |
| `fingerprint` | `text` (NOT NULL) | 16-char hex hash of input/output snippet |
| `action` | `text` (NOT NULL) | `logged`, `blocked`, `redacted` |
| `sentinel_version` | `text` (NOT NULL) | The SDK version that produced this |

Indexes:
- `idx_incidents_account_ts` on `(account_id, ts DESC)` — covers timeline queries
- `idx_incidents_account_severity` on `(account_id, severity, ts DESC)` — covers filtered timeline
- `idx_incidents_account_check_id` on `(account_id, check_id, ts DESC)` — covers per-check rollups
- Partition by month on `received_at` once we exceed ~10M rows (Q2 2027 estimate)

**Privacy invariant:** no raw user content in this table. Only fingerprints. If you find yourself adding a column with raw text, stop and reread `sentinel-api.md` §3.

### `audit_log`

Compliance-grade event log of state-changing operations on the account. The audit log IS the evidence the SOC 2 auditor reads; tampering with it (or being able to delete it through application code) defeats the purpose.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` (PK) | |
| `account_id` | `uuid` (FK, **nullable**) | `ON DELETE SET NULL` — see audit-log-rules below |
| `actor_email` | `text` (NOT NULL) | Who did the thing |
| `action` | `text` (NOT NULL) | e.g. `account.create`, `ingest_token.rotate`, `incident.export`, `session.create` |
| `target_id` | `text` | Optional reference to the affected resource |
| `metadata` | `jsonb` | Free-form context |
| `created_at` | `timestamptz` (NOT NULL, default `now()`) | |
| `ip` | `inet` | Source IP, for forensic correlation |
| `user_agent` | `text` | Browser/SDK UA |

#### Audit-log rules

The trigger `block_audit_log_tampering()` enforces:

1. **DELETE is unconditionally blocked.** Even our own FK uses `ON DELETE SET NULL`, never `CASCADE`. The audit log persists after account deletion.
2. **UPDATE is allowed only if the audit-content fields are unchanged.** The fields `actor_email`, `action`, `target_id`, `metadata`, `created_at`, `ip`, `user_agent`, `id` cannot change. Only `account_id` (and `revoked_at`-equivalents on other tables) may change — this is the carve-out that lets `ON DELETE SET NULL` work for GDPR Article 17 account deletion.
3. **Application code never UPDATEs audit content.** The only legitimate UPDATE is FK-driven (`SET NULL` of `account_id`) or future privileged anonymization (`audit_log_anonymize()` function — Phase 4).

This design satisfies both **SOC 2 CC7.5** (incident communication evidence) and **GDPR Article 17** (right to erasure of PII while retaining the system event record).

The trigger is verified by `tests/integration.test.ts` — direct UPDATE attempting to change `action` is rejected; FK-driven `SET NULL` succeeds.

---

## 2. The DDL skeleton

Lives in `guardian/migrations/0001_initial.sql`. Flyway-style numbered migrations, run on Guardian startup.

```sql
-- 0001_initial.sql

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE accounts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text UNIQUE NOT NULL,
  name text,
  org_name text,
  plan text NOT NULL DEFAULT 'preview',
  ingest_token text UNIQUE NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_accounts_email_lower ON accounts (lower(email));
CREATE INDEX idx_accounts_ingest_token ON accounts (ingest_token);

CREATE TABLE incidents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  agent_id text NOT NULL,
  ts timestamptz NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now(),
  phase text NOT NULL CHECK (phase IN ('preflight', 'postflight')),
  check_id text NOT NULL,
  severity text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
  title text NOT NULL CHECK (length(title) <= 200),
  detail text NOT NULL CHECK (length(detail) <= 2000),
  model_provider text,
  model_name text,
  fingerprint text NOT NULL,
  action text NOT NULL CHECK (action IN ('logged', 'blocked', 'redacted')),
  sentinel_version text NOT NULL
);
CREATE INDEX idx_incidents_account_ts ON incidents (account_id, ts DESC);
CREATE INDEX idx_incidents_account_severity ON incidents (account_id, severity, ts DESC);
CREATE INDEX idx_incidents_account_check_id ON incidents (account_id, check_id, ts DESC);

-- (magic_links, sessions, audit_log similar; see migrations/ for full DDL)
```

---

## 3. Read patterns Guardian's UI depends on

Listed in priority order. Indexes above are designed around these.

### Incident timeline (most common)

```sql
SELECT id, ts, severity, check_id, title, model_name, fingerprint, action
FROM incidents
WHERE account_id = $1
  AND ts >= $2  -- typically now() - interval '7 days'
  AND ($3::text IS NULL OR severity = $3)
ORDER BY ts DESC
LIMIT 100;
```

### Severity rollup (dashboard summary)

```sql
SELECT severity, count(*)
FROM incidents
WHERE account_id = $1
  AND ts >= $2
GROUP BY severity;
```

### Per-check breakdown

```sql
SELECT check_id, severity, count(*)
FROM incidents
WHERE account_id = $1 AND ts >= $2
GROUP BY check_id, severity
ORDER BY count(*) DESC;
```

### Audit log export (CSV/JSON download)

```sql
SELECT * FROM incidents
WHERE account_id = $1
  AND ts BETWEEN $2 AND $3
ORDER BY ts ASC;
```

---

## 4. What's deliberately OUT of v0.1

- Multi-tenant org/team scoping (Q1 2027)
- Per-user RBAC within an account (Q1 2027)
- Custom alerting rules / saved queries (post-launch)
- Real-time dashboards (websockets) — polling is fine for v0.1
- Time-series rollups / materialized views — wait until query latency demands it
- Soft-delete on incidents — append-only by design

---

## 5. References

- [`sentinel-api.md`](./sentinel-api.md) — what produces these rows
- [`wire-format.md`](./wire-format.md) — the JSON envelope on the wire
