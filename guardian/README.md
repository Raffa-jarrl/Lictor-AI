# Lictor Guardian

> Hosted dashboard for Sentinel telemetry. AI security monitoring + compliance evidence for teams.

## Status

Pre-alpha skeleton. Phase 2 build (W11–17, July 20 – Sep 6, 2026).

| Surface | Status |
|---|---|
| Next.js app shell | ✅ scaffolded |
| Postgres schema | ✅ migration 0001 written |
| `/api/ingest` endpoint | ✅ validates + auths; INSERT lands W11 |
| Magic-link auth | ⏳ W11 |
| Incident timeline UI | ⏳ W12 |
| Audit log export | ⏳ W14 |
| Slack webhook | ⏳ W15 |
| Stripe scaffolding | ⏳ W16 |

## Local development

```bash
# 1. Postgres up locally
brew install postgresql@16
brew services start postgresql@16
createdb lictor_guardian
createuser -s lictor_guardian || true

# 2. Env
cp .env.example .env.local
# Edit DATABASE_URL + SESSION_SECRET

# 3. Install deps
pnpm install

# 4. Run migrations
pnpm db:migrate

# 5. Dev server
pnpm dev
# → http://localhost:3100
```

## Architecture

- **Next.js 15 App Router** for server-rendered pages + API routes
- **Postgres** via Kysely (type-safe SQL builder) over `pg`. No ORM.
- **Magic-link auth** via Postmark; sessions backed by signed cookies + DB-side session rows
- **Append-only audit log** with DB triggers blocking UPDATE/DELETE — for SOC 2 / GDPR Article 32 evidence

## Specs

- [`../docs/specs/guardian-schema.md`](../docs/specs/guardian-schema.md) — data model
- [`../docs/specs/wire-format.md`](../docs/specs/wire-format.md) — Sentinel → Guardian envelope
- [`../docs/specs/sentinel-api.md`](../docs/specs/sentinel-api.md) — what produces these events

## License

Source-available, NOT MIT. The Guardian source is published in this repo for
transparency, but is licensed for hosted use through lictor-ai.com only — not for
self-hosting or redistribution. See the root `LICENSE`.
