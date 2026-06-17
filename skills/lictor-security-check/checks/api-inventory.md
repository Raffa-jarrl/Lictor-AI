# Check — Stale & shadow API endpoints still wired into prod

**What you're looking for:** the *extra* doors on your own API that you forgot were still open. Not the polished `/api/v2` you ship today — the `/api/v1` you replaced six months ago but never unmounted, the `/api/_debug/dump` you added one stressful night, the `/api/test/reset` you used while building, the `/api/internal/users` the AI scaffolded. Every one of them is still registered on the live router, and every one is a path you've stopped *thinking* about — which means you've also stopped *securing* it. The new version gets the auth fix, the rate limit, the input validation. The old twin sitting next to it gets none of that, because you forgot it exists.

This is the bug behind a huge share of real breaches: the attacker doesn't beat your *current* code, they find the *forgotten* code. Your `/api/v2/orders` checks the session properly. Your `/api/v1/orders`, still mounted, was written before you added auth — and it's one URL away. Security people call this "improper inventory management": you can't protect an endpoint you don't know you're still serving.

**Why AI-built apps get this constantly:** the AI happily scaffolds a v1 router, then later scaffolds a v2 router, and never tells you to retire v1 — both stay `app.use()`'d. It generates `/test` and `/debug` helper routes to demo a feature and leaves them mounted. It writes config with `baseURL: "https://staging.yourapp.com"` because that's where you were testing, and that default rides into production. Nobody removed any of it; the app just kept accreting doors.

This check is about your app's **own** endpoints. The *discovery surface* (Swagger, GraphQL introspection, the API explorer that lists endpoints) is `open-services.md`. Whether any *single* route checks auth is `api-auth.md`. This check is the inventory pass: **how many doors are there, and should each one still exist?**

## How to scan

You're doing three passes: (1) build the route table, (2) flag the stale/shadow ones, (3) check config/env for non-prod hosts riding into prod. Read the code — no scanner needed.

### Pass 1 — Build the route table

Find every place routes get registered, across whatever stack the project uses.

```bash
# JS/TS — Next.js App Router (each route.ts is one endpoint), Pages Router,
# and Express/Hono/Fastify/NestJS mount points
find . -path ./node_modules -prune -o \
  \( -path '*/api/*' -name 'route.ts' -o -path '*/api/*' -name 'route.js' \
     -o -path '*/pages/api/*' -name '*.ts' -o -path '*/pages/api/*' -name '*.js' \) -print 2>/dev/null

grep -rEn --include='*.ts' --include='*.js' --exclude-dir={node_modules,.next,dist,build} \
  -e 'app\.(use|get|post|put|delete|patch|all)\(' \
  -e 'router\.(use|get|post|put|delete|patch|all)\(' \
  -e '\.route\(' \
  -e '@(Get|Post|Put|Delete|Patch|Controller)\(' \
  . 2>/dev/null | head -80

# Python — FastAPI/Flask/Django route declarations and version mounts
grep -rEn --include='*.py' --exclude-dir={venv,.venv,__pycache__} \
  -e '@(app|router|api|bp)\.(route|get|post|put|delete|patch)\(' \
  -e 'app\.include_router\(' \
  -e 'add_url_rule\(' \
  -e 'path\(|re_path\(|url\(' \
  . 2>/dev/null | head -80

# Go — net/http, chi, gin, echo, mux route registration
grep -rEn --include='*.go' \
  -e '\.(GET|POST|PUT|DELETE|PATCH|Handle|HandleFunc|Mount|Group)\(' \
  -e 'http\.Handle(Func)?\(' \
  . 2>/dev/null | head -80

# Ruby on Rails — the routes file is the whole inventory in one place
find . -path '*/config/routes.rb' -print 2>/dev/null
grep -rEn --include='routes.rb' \
  -e 'namespace|scope|resources?|get |post |put |delete |patch |match ' \
  . 2>/dev/null | head -80

# PHP — Laravel routes/, Symfony annotations/attributes
grep -rEn --include='*.php' --exclude-dir=vendor \
  -e 'Route::(get|post|put|delete|patch|any|prefix|group)\(' \
  -e '#\[Route\(' \
  -e '@Route\(' \
  . 2>/dev/null | head -80

# Mobile clients — the base URL the app talks to (the "host" half of inventory)
grep -rEn --include='*.swift' --include='*.kt' --include='*.java' \
  --include='*.dart' --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  --exclude-dir={node_modules,Pods,build} \
  -e 'baseURL|baseUrl|BASE_URL|API_BASE|apiBase|host\s*[:=]' \
  -e 'https?://(staging|dev|test|qa|sandbox|uat|internal)\.' \
  . 2>/dev/null | head -40
```

The output of Pass 1 is a list. Most of it is fine — current, intended routes. Now look for the four smells.

### Pass 2 — The four smells to flag

**Smell A — Two API versions coexisting, and the old one is still mounted.**

```bash
# Are there multiple version prefixes in the route table at all?
grep -rEn --exclude-dir={node_modules,.next,dist,build,vendor,venv,.venv} \
  --include='*.ts' --include='*.js' --include='*.py' --include='*.go' \
  --include='*.rb' --include='*.php' \
  -e '/v[0-9]/|/api/v[0-9]|version\s*[:=]\s*["'"'"']?v?[0-9]' \
  -e 'include_router\([^)]*v[0-9]' \
  -e 'app\.use\(["'"'"'][^"'"'"']*v[0-9]' \
  . 2>/dev/null | sed -E 's/.*(v[0-9]+).*/\1 &/' | sort | head -60
```

If you see both `v1` and `v2` (or `v1`/`v2`/`v3`) registered, the question is: **is anything still serving v1?** Look for the actual mount — `app.use('/api/v1', v1Router)`, `app.include_router(v1_router)`, `Route::prefix('v1')`, a `routes.rb` `namespace :v1`. If the old version is still wired in *and* a newer one exists doing the same job, that's the finding.

**Smell B — Route names that scream "not for production."**

```bash
grep -rEn --exclude-dir={node_modules,.next,dist,build,vendor,venv,.venv} \
  --include='*.ts' --include='*.js' --include='*.py' --include='*.go' \
  --include='*.rb' --include='*.php' \
  -e '/(test|tests|tmp|temp|old|legacy|deprecated|internal|beta|staging|sandbox|playground)/' \
  -e '/(_debug|debug|__debug|dev|devonly|scratch|wip|backup|bak)/' \
  -e '(test|debug|internal|legacy|reset|seed|dump|migrate|fixture)[-_]?(route|handler|endpoint|api)' \
  . 2>/dev/null | head -60
```

Also check Next.js / file-router projects by folder name — the path *is* the URL:

```bash
find . -path ./node_modules -prune -o -type d \
  \( -name 'test' -o -name 'tests' -o -name 'debug' -o -name '_debug' \
     -o -name 'internal' -o -name 'legacy' -o -name 'deprecated' \
     -o -name 'tmp' -o -name 'old' -o -name 'beta' -o -name 'dev' \) \
  -path '*/api/*' -print 2>/dev/null
```

A route literally named `/api/internal/users`, `/api/test/reset-db`, `/api/_debug/env`, `/api/legacy/export` that's added to the production app is the finding — *unless* it's env-gated (see "What NOT to flag").

**Smell C — An unauthenticated endpoint that mirrors an authed current route.**

This is the most dangerous one and it takes reading, not just grepping. For each *resource* (users, orders, files, messages…), check whether **two** handlers touch it: a current one with an auth check, and another — older version, "internal", "public", differently-prefixed — that touches the *same data* with **no** auth middleware.

```bash
# Surface candidate pairs: same resource word, find every handler that mentions it,
# then read each to see which ones check a session/token and which don't.
for R in users user orders order invoices customers payments files messages accounts; do
  echo "=== $R ===";
  grep -rEln --exclude-dir={node_modules,.next,dist,build,vendor,venv,.venv} \
    --include='*.ts' --include='*.js' --include='*.py' --include='*.go' \
    --include='*.rb' --include='*.php' \
    -e "$R" . 2>/dev/null | grep -Ei 'route|handler|controller|api|endpoint';
done | head -80
```

For the auth-presence check inside each candidate, reuse the signals from `api-auth.md`: `getServerSession`/`auth()`/`getSession`, `supabase.auth.getUser`, `currentUser()` (Clerk), a `@UseGuards`/`before_action`/middleware, an `Authorization`-header + JWT verify, a `requireAuth`/`@login_required` decorator. If `/api/v2/orders` has one and a still-mounted `/api/v1/orders` (or `/api/internal/orders`) returns the same data with none, flag it. (The single-route "no auth at all" case is `api-auth.md`; the *value here* is catching the **forgotten twin** of a route you already secured.)

### Pass 3 — Prod config pointing at staging/dev hosts

A base URL or host default that says `staging.` / `dev.` / `test.` and ships to production is its own inventory bug: prod traffic flows to a box that's almost always *less* locked down (debug on, weaker auth, test data, no WAF).

```bash
# Hard-coded non-prod hosts in config / env defaults / client base URLs
grep -rEn --exclude-dir={node_modules,.next,dist,build,vendor,venv,.venv,.git} \
  -e 'https?://(staging|dev|develop|test|qa|uat|sandbox|preview|internal)[.-]' \
  -e '(API_URL|API_BASE|BASE_URL|BACKEND_URL|NEXT_PUBLIC_API_URL|VITE_API_URL)\s*[:=]\s*["'"'"']?https?://(staging|dev|test|qa)' \
  . 2>/dev/null | head -40

# .env files committed with non-prod endpoints as the default
grep -rEn --include='.env' --include='.env.*' \
  -e 'https?://(staging|dev|test|qa|uat|sandbox)\.' \
  . 2>/dev/null
```

A staging URL inside `.env.development` or `.env.local` is fine. A staging URL inside `.env.production`, `.env` (the committed default), `next.config.js`, a Dockerfile `ENV`, or a mobile app's release config is the finding.

## The dangerous patterns

**Pattern 1 — Old version still mounted next to the new one (HIGH)**

```ts
// server.ts — the v2 router is what the app "uses" today...
app.use("/api/v2", v2Router);      // ← session-checked, rate-limited, validated
app.use("/api/v1", v1Router);      // ← still here. written before you added auth.
```

```python
# main.py (FastAPI)
app.include_router(v2_router, prefix="/api/v2")   # current
app.include_router(v1_router, prefix="/api/v1")   # ← never removed
```

```ruby
# config/routes.rb (Rails)
namespace :v2 do; resources :orders; end   # current
namespace :v1 do; resources :orders; end   # ← still routable
```

You fixed a bug, added auth, tightened a query — in v2. The exact same endpoint in v1 never got the fix and is one path segment away. Attackers fuzz `/v1/`, `/v0/`, `/api/old/` on every target precisely because the old version is so often the soft one. The breach isn't in the code you maintain; it's in the code you forgot you're still serving.

**Pattern 2 — Debug / internal / test route shipped to prod (HIGH → CRITICAL)**

```ts
// app/api/_debug/route.ts (Next.js) — the folder name IS the public URL
export async function GET() {
  return Response.json({ env: process.env, headers: ... });  // dumps your config
}
```

```python
@app.post("/api/test/reset")          # wipes + reseeds the DB, no auth
def reset_database(): ...

@app.get("/internal/users")           # "internal" is a comment, not a firewall
def all_users(): return db.query(User).all()
```

```go
mux.HandleFunc("/debug/dump", dumpEverything)   // left in from a debugging session
```

These were never meant for users. But "internal" / "debug" / "test" in the name does **nothing** — the route is on the public router, reachable by anyone who guesses the path (and bots guess these exact names all day). A `/reset` or `/seed` route is a denial-of-service or data-wipe button. A `/_debug` or `/dump` route is a config/secret leak. CRITICAL if it mutates data or dumps secrets; HIGH if it just exposes extra read surface.

**Pattern 3 — Unauthenticated twin of an authed route (CRITICAL)**

```ts
// app/api/v2/profile/route.ts  — current, correct
export async function GET() {
  const session = await auth();
  if (!session) return new Response("Unauthorized", { status: 401 });
  return Response.json(await getProfile(session.user.id));
}

// app/api/v1/profile/route.ts  — forgotten, no session check
export async function GET(req: Request) {
  const id = new URL(req.url).searchParams.get("id");
  return Response.json(await getProfile(id));   // ← anyone, any id
}
```

You secured the resource — in the version you remember. The old twin reads the same table with no auth and (often) an attacker-supplied `id`, which is also an IDOR (`idor.md`). This is the worst case because it *looks* secure from the outside: your live app uses v2, your tests hit v2, your security review read v2. v1 just quietly answers.

**Pattern 4 — Production config pointing at staging/dev (MEDIUM)**

```js
// next.config.js (shipped)
env: { API_BASE: "https://staging-api.yourapp.com" }   // ← prod talks to staging
```

```swift
// iOS release build
let baseURL = "https://dev.yourapp.com/api"   // ← in the App Store binary
```

Prod traffic hitting a staging/dev backend means real users (and real data) flow to the box you keep *deliberately* loose for testing: debug pages on, auth relaxed, seeded with test accounts, no rate limit, no WAF. It also keeps that non-prod host alive and internet-reachable, which is its own attack surface. MEDIUM, higher if the staging box has debug mode or weaker auth.

## Safe patterns

**Retire old versions — don't just stop documenting them, unmount them.**

```ts
// Keep only what you serve. If you must keep v1 alive for old clients,
// give it the SAME guards as v2 and a hard sunset.
app.use("/api/v2", v2Router);
// app.use("/api/v1", v1Router);  ← deleted. Or, if truly still needed:
app.use("/api/v1", deprecationGate({ sunset: "2026-09-01" }), authMiddleware, v1Router);
```

**Gate every non-prod route behind the environment — so it cannot exist in prod.**

```ts
// The route is only registered when you're NOT in production.
if (process.env.NODE_ENV !== "production") {
  app.post("/api/test/reset", resetDb);
  app.get("/api/_debug/env", dumpEnv);
}
```

```python
import os
if os.environ.get("APP_ENV") != "production":
    app.include_router(debug_router)   # absent from the prod process entirely
```

```go
if os.Getenv("APP_ENV") != "production" {
    mux.HandleFunc("/debug/dump", dumpEverything)
}
```

**Point prod config at prod, and let env override per-environment — never a hard-coded staging default.**

```js
// next.config.js
env: { API_BASE: process.env.API_BASE ?? "https://api.yourapp.com" }  // prod default
```

```swift
// iOS — choose host by build configuration, prod is the release default
#if DEBUG
let baseURL = "https://dev.yourapp.com/api"
#else
let baseURL = "https://api.yourapp.com/api"
#endif
```

**One source of truth for the route table.** Keep all mounts in one file (`server.ts`, `main.py`, `routes.rb`) so "what endpoints do we serve?" is answerable by reading one place. The endpoints you can't list are the endpoints you can't secure.

## Report a finding as

**Title:** "Your old `/api/v1` is still live next to `/api/v2` — and it never got the auth fix"

(use this title for Pattern 1/3; adapt for Pattern 2's debug/test routes and Pattern 4's staging host)

**Detail:**
> `server.ts:24` still has `app.use("/api/v1", v1Router)` mounted right below your current `app.use("/api/v2", v2Router)`. Both serve the same resources (`/orders`, `/profile`, `/users`). The v2 versions check the session at the top of each handler; the v1 versions in `routes/v1/profile.ts:6` do **not** — they read the record straight from an `id` in the query string.
>
> **What can go wrong:** you secured this API — in the version you ship and test against. But the old version is still answering. An attacker doesn't attack `/api/v2/profile` (it's locked); they try `/api/v1/profile?id=123`, `/api/v0/`, `/api/old/` — the exact paths bots fuzz on every target — and your forgotten v1 hands over any user's profile with no login. From the outside your app looks secure, because your live UI, your tests, and your last security pass all used v2. v1 just quietly keeps serving. This is how a lot of real breaches happen: not by beating your current code, but by finding the code you forgot you're still running.
>
> **What to do tonight:**
> 1. **Decide if v1 is still needed.** Check whether any real client still calls it (logs/analytics). If not — and that's the common case — delete the mount and the `routes/v1/` folder:
>    ```ts
>    // server.ts — remove this line
>    // app.use("/api/v1", v1Router);
>    ```
> 2. **If you must keep v1 alive** for old mobile clients, give it the *same* guards as v2 (run it through the same auth middleware) and put a sunset date on it:
>    ```ts
>    app.use("/api/v1", authMiddleware, deprecationGate({ sunset: "2026-09-01" }), v1Router);
>    ```
> 3. **Verify after deploy:** the old path should now 401 or 404, not return data:
>    ```bash
>    curl -i "https://yourapp.com/api/v1/profile?id=1"   # expect 401/404, not a user record
>    ```
> 4. **Do an inventory sweep** while you're here: list every route the app mounts (one pass through `server.ts` / `main.py` / `routes.rb`) and for each ask "do we still need this, and is it guarded?" Retire anything you can't answer "yes, yes" to. Pull `/test`, `/debug`, `/internal` routes out of the prod router (or env-gate them), and point any `staging.`/`dev.` base URL in prod config back at your prod host.

Repeat the report block for each stale/shadow endpoint, debug/test route, or non-prod-host config you found — they're independent doors; list each one and say which smell it is (old-version / debug-route / unauthed-twin / staging-host).

## What NOT to flag

The whole point of this check is the *forgotten* and *unguarded* surface. Don't cry wolf on the deliberate, current, or properly-gated kind:

- **Versioned routes that are all current and intended.** If `/api/v1` is the *only* version and it's your live API, that's not a finding — `v1` is just a name, not a smell. Same if you intentionally maintain v1 **and** v2 for a documented migration **and** both carry the same auth/guards. The finding is specifically an **old** version still mounted that a **newer** one has superseded *and left less-protected*.
- **Non-prod routes that are env-gated.** A `/api/test/reset` or `/api/_debug` wrapped in `if (process.env.NODE_ENV !== "production")`, `if APP_ENV != "production"`, a `@DevOnly` guard, or a feature flag that's off in prod is doing exactly the right thing — the route literally isn't registered in the production process. Not a finding (note as INFO at most).
- **Internal routes that are actually internal.** An endpoint reachable only on a private network / VPC / service mesh, bound to `127.0.0.1`, behind an internal-only gateway, or protected by mTLS / a network policy is genuinely internal — the word "internal" there is backed by a real boundary. Confirm the boundary exists before flagging; if it does, it's fine.
- **Staging/dev hosts in the right env file.** A `staging.` or `dev.` URL inside `.env.development`, `.env.local`, a `#if DEBUG` block, or a `development` config profile is correct — that's where it belongs. Only flag a non-prod host that ships as the **production** default (`.env.production`, committed `.env`, release build config, `next.config.js` with no env override).
- **`/health`, `/status`, `/version`, `/ping`, `/metrics`, `/.well-known/*`.** Standard operational endpoints. They're *meant* to be unauthenticated and present in prod. (A `/metrics` Prometheus endpoint exposed to the public internet is worth a LOW note, but it's not a stale-inventory finding.)
- **Webhook + OAuth-callback routes.** `/api/webhooks/stripe`, `/api/auth/callback/*` — these legitimately have no session check (they authenticate by signature / by the OAuth handshake). Covered by `webhooks-csrf.md`, not here.
- **The discovery surface itself.** Swagger UI, `/docs`, `/redoc`, GraphQL introspection, an OpenAPI JSON — those are `open-services.md`. This check is about your app's *own business endpoints*, not the explorer that lists them.
- **A single route with no auth where no protected twin exists.** That's a plain missing-auth finding for `api-auth.md`. The unique value *here* is the **mirrored** case: a still-mounted unguarded endpoint that duplicates one you already secured. If there's no current/secured counterpart, report it under `api-auth.md` instead of double-counting.
- **`beta`/`v2-beta` routes behind a feature flag or allow-list.** A genuinely-gated beta (flag off by default, or limited to opted-in accounts) is intended surface, not shadow surface. Only flag `beta`/`test`-named routes that anyone can reach unconditionally.
- **Monorepo / multi-service path names.** In a monorepo you'll see many `route.ts` files and many service prefixes; that's structure, not duplication. Only flag when two routes in the **same deployed service** serve the **same resource** and one is the stale/unguarded twin.
