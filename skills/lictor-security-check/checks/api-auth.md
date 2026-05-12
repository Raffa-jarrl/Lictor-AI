# Check 3 — Unauthenticated API routes

**What you're looking for:** `/api/*` route handlers that return user data without checking a session, cookie, or token. The classic vibe-coded SaaS bug: an AI generates `app/api/users/route.ts` that calls `db.user.findMany()` and the developer never adds auth because the AI didn't suggest it.

## How to scan

Find every API route handler in the project. The exact location depends on framework:

```bash
# Next.js App Router
find . -path ./node_modules -prune -o \
  \( -path '*/api/*' -name 'route.ts' -o -name 'route.js' \) -print 2>/dev/null

# Next.js Pages Router
find . -path ./node_modules -prune -o \
  -path '*/pages/api/*' -name '*.ts' -o -name '*.js' -print 2>/dev/null

# Express / Hono / generic
grep -rn --include='*.ts' --include='*.js' --exclude-dir={node_modules,.next,dist} \
  -E '(app\.(get|post|put|delete|patch)|router\.(get|post|put|delete|patch)|export\s+(async\s+)?function\s+(GET|POST|PUT|DELETE|PATCH))' \
  . 2>/dev/null | head -30

# SvelteKit
find . -path ./node_modules -prune -o \
  \( -path '*/routes/*' -name '+server.ts' -o -name '+server.js' \) -print 2>/dev/null

# Remix
find . -path ./node_modules -prune -o \
  -path '*/routes/api.*' -print 2>/dev/null
```

## For each route, look for auth presence

Read the file. The route is authenticated if you see ANY of:

- `getServerSession`, `auth()`, `getSession()` calls (NextAuth / Auth.js / Lucia)
- `await supabase.auth.getUser()` or `getSession()` at the top of the handler
- `clerk.user()`, `currentUser()` (Clerk)
- A middleware import that runs before the handler
- An explicit `Authorization` header check + JWT verification
- `await prisma.session.findUnique({ where: { token: ... }})` style lookups

If the file just does `return Response.json(await db.X.findMany())` with no auth check anywhere — it's unauthenticated and serves data publicly.

## Don't false-positive on

- **Public endpoints by design.** `/api/health`, `/api/version`, `/api/sitemap`, `/api/og-image` — these often legitimately return content with no auth. Use judgment based on the name + what the handler returns.
- **Webhook endpoints.** `/api/webhooks/stripe`, `/api/webhooks/github` — auth here is via signature verification, not session. Look for `stripe.webhooks.constructEvent` or `crypto.timingSafeEqual` calls.
- **OAuth callback routes.** `/api/auth/callback/*` — auth happens inside the callback itself.

## High-risk path names to flag aggressively

These almost always SHOULD have auth, and frequently don't:

- `/api/users`, `/api/customers`, `/api/orders`, `/api/invoices`
- `/api/admin/*`
- `/api/me`, `/api/profile`, `/api/settings`
- `/api/messages`, `/api/conversations`, `/api/chats`
- `/api/files`, `/api/uploads`, `/api/downloads`
- `/api/payments`, `/api/transactions`
- `/api/v1/*` mirrors of any of the above

## Report a finding as

**Title:** "`/api/users` returns all customer records with no auth"

**Detail:**
> `src/app/api/users/route.ts:8` exports a `GET` handler that calls `await db.user.findMany()` and returns the result. There is no session check, no Authorization header verification, no middleware guard. Anyone who hits `https://yourapp.com/api/users` after deploy gets your entire user table.
>
> This is the single most common bug in AI-built SaaS in 2026. The AI doesn't know about your auth system — it just generates a "list users" endpoint.
>
> **What to do tonight:**
> 1. Add a server-side session check at the top of the handler:
>    ```ts
>    import { auth } from '@/lib/auth';
>
>    export async function GET() {
>      const session = await auth();
>      if (!session) return new Response('Unauthorized', { status: 401 });
>      // ... existing logic
>    }
>    ```
> 2. For admin-only endpoints, also check the role:
>    ```ts
>    if (session.user.role !== 'admin') return new Response('Forbidden', { status: 403 });
>    ```
> 3. Apply the same pattern to every other route in `app/api/`. The fix is mechanical; do all of them in one pass.
> 4. Verify after deploy: `curl -i https://yourapp.com/api/users` should return 401, not your user data.
>
> If you use Supabase: the better fix is to enable Row Level Security on the underlying table (see the Supabase/Firebase check). Then even if this endpoint is exposed, the database refuses to return rows the requestor isn't authorized for.

Repeat the report block for each unauthenticated route you found.
