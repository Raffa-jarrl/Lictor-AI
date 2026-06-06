# Lictor Guardian — multi-stage image for local development / evaluation.
#
# Source-available (see ./LICENSE): eval/dev is allowed; hosting Guardian for
# third parties is NOT. This image exists so you can run Guardian locally with
# one command, not to redistribute a hosted service.
#
# Build:  docker build -t lictor-guardian .
# Run:    use docker-compose.yml (it wires Postgres + env for you).

# ─── Stage 1: dependencies ──────────────────────────────────────────────────
FROM node:22-bookworm-slim AS deps
WORKDIR /app

# Guardian uses pnpm. Enable it via corepack (bundled with Node 22).
RUN corepack enable

# Install against the committed lockfile for reproducible builds.
COPY package.json pnpm-lock.yaml ./
# pnpm 11 blocks dependency build scripts (esbuild/sharp) by default; allow them
# non-interactively for a reproducible image build.
RUN pnpm install --frozen-lockfile --config.dangerouslyAllowAllBuilds=true

# ─── Stage 2: build ─────────────────────────────────────────────────────────
FROM node:22-bookworm-slim AS build
WORKDIR /app
RUN corepack enable

COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Build the Next.js app. Guardian reads DATABASE_URL / SESSION_SECRET lazily at
# runtime (not at build time), so no database is required to build.
RUN pnpm build

# Ensure a public/ dir exists so the runtime-stage COPY below never fails
# (this repo currently ships no static assets).
RUN mkdir -p public

# ─── Stage 3: runtime ───────────────────────────────────────────────────────
FROM node:22-bookworm-slim AS runtime
WORKDIR /app
RUN corepack enable

ENV NODE_ENV=production
ENV PORT=3100

# Bring over the built app + production deps + the migration runner.
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/.next ./.next
COPY --from=build /app/public ./public
COPY --from=build /app/package.json ./package.json
COPY --from=build /app/next.config.js ./next.config.js
COPY --from=build /app/migrations ./migrations
COPY --from=build /app/scripts ./scripts

EXPOSE 3100

# Apply pending migrations, then start. DATABASE_URL / SESSION_SECRET are
# injected by docker-compose, so the migration runner reads them from the
# process environment (NOT from a .env.local file — that's local-dev only).
CMD ["sh", "-c", "node scripts/migrate.mjs && pnpm start"]
