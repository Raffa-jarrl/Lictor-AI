# Lictor Guardian

> ⚙️ **Part of the [Lictor AI security suite](../README.md)** — Platform. The dashboard every Lictor product reports into — one audit trail.

> Hosted dashboard for Sentinel telemetry. AI security monitoring + compliance evidence for teams.

## Status

Alpha. Phase 2 build complete (W11–16).

| Surface | Status |
|---|---|
| Next.js app shell | ✅ scaffolded |
| Postgres schema | ✅ migrations 0001 + 0002 |
| `/api/ingest` endpoint | ✅ validates + auths + INSERTs |
| Magic-link auth | ✅ done (`/api/auth/*`) |
| Incident timeline UI | ✅ done (`/incidents`) |
| Audit log export | ✅ done (`/api/export/incidents`) |
| Slack webhook | ✅ done (`/api/settings/slack`) |
| Stripe scaffolding | ✅ done (migration 0002 tables) |

## Run locally

Requires Node 20+ and pnpm. Postgres can be local (Homebrew) or via Docker.

```bash
# 1. Postgres up locally (option A — Homebrew)
brew install postgresql@16
brew services start postgresql@16
createuser -s lictor_guardian || true
createdb -O lictor_guardian lictor_guardian
#   (option B — Docker, if you don't want Homebrew Postgres)
#   docker compose up -d db

# 2. Env — copy the example and set a real session secret
cp .env.example .env.local
#   Generate a 32-byte hex secret and paste it into SESSION_SECRET:
openssl rand -hex 32
#   DATABASE_URL in .env.example already matches the steps above.

# 3. Install deps
pnpm install

# 4. Run migrations (loads .env.local via Node's --env-file)
pnpm db:migrate

# 5. (optional) Seed a tester account with ~60 sample incidents
pnpm db:seed
#   add --email you@example.com to use your own address

# 6. Dev server
pnpm dev
# → http://localhost:3100
```

No email provider is needed locally — when `POSTMARK_API_TOKEN` is unset, the
magic-link URL **prints to your terminal**. Submit your email on the sign-in
page, then click the link from the dev server's log output.

## Run with Docker

Brings up Postgres 16 + the app in one command (no Homebrew, no local Node):

```bash
docker compose up
# → open http://localhost:3100
```

The app container applies migrations on start. The magic-link URL prints to the
app container's logs (this terminal) — no email provider needed. Override the
dev session secret with `SESSION_SECRET="$(openssl rand -hex 32)" docker compose up`.

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

Source-available, NOT open-source. The Guardian source is published in this
repo for transparency. Local evaluation and development are permitted; hosting
Guardian for third parties and redistribution are not. See [`LICENSE`](./LICENSE)
in this directory (it supersedes the repo-root Apache 2.0 license for everything
under `guardian/`).
