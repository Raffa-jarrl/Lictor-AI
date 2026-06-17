# Check — Users can see other users' data by changing the ID

**What you're looking for:** an endpoint that fetches or updates a record using an `id` (or `uuid`, `slug`, `orderId`...) taken straight from the URL or request body — and then never checks that the record actually *belongs to the person asking*. The classic shape: the route has a login check (so it feels safe), but it trusts the ID blindly. Logged-in user #42 changes `?orderId=43` in the address bar and reads user #43's invoice.

The security world calls this IDOR (Insecure Direct Object Reference) or "broken object-level authorization." Don't say either of those to the user. Say: **"a logged-in user can read other people's records by changing the number in the URL."**

This is different from [Unauthenticated API routes](./api-auth.md). There, the door has no lock at all. Here, the door has a lock — you have to log in — but once inside, *every* drawer opens, not just yours. An AI codegen tool almost always adds the login check and almost never adds the ownership check, because it doesn't know your data model. So this bug ships constantly.

## How to scan

The tell is a two-part smell, in the same handler:
1. it reads an identifier from `params` / `query` / `body` (not from the session), **and**
2. it queries by that identifier **without** also constraining to the current user.

### Step 1 — find handlers that take an ID from the request

```bash
# JS / TS — Next.js, Express, Hono, Remix, SvelteKit, Fastify
grep -rEn --include='*.ts' --include='*.tsx' --include='*.js' \
  --exclude-dir={node_modules,.next,dist,build,.svelte-kit} \
  'params\.(id|userId|uuid|slug|orderId)|req\.params|searchParams\.get\(|query\.id|req\.query|body\.(id|userId)' \
  . 2>/dev/null | head -40

# Python — Django, FastAPI, Flask
grep -rEn --include='*.py' --exclude-dir={venv,.venv,__pycache__,node_modules} \
  'def .*\(.*\b(id|pk|user_id|uuid|order_id)\b|request\.(GET|POST|args|json)|kwargs\[|path_params' \
  . 2>/dev/null | head -40

# Go — chi, gin, echo, net/http
grep -rEn --include='*.go' \
  'chi\.URLParam|c\.Param\(|mux\.Vars|r\.PathValue|Query\(\)\.Get|c\.Query\(' \
  . 2>/dev/null | head -40

# Ruby — Rails
grep -rEn --include='*.rb' --exclude-dir={vendor,node_modules} \
  'params\[:id\]|params\[:.*_id\]|params\.require' \
  . 2>/dev/null | head -40

# PHP — Laravel, raw
grep -rEn --include='*.php' --exclude-dir={vendor,node_modules} \
  '\$_GET\[|\$_POST\[|\$request->(input|query|route)|->find\(' \
  . 2>/dev/null | head -40
```

### Step 2 — for each hit, look at the query right below it

The bug is a query keyed **only** by the request ID. The fix is a query *also* keyed by the session user. Read the handler and ask one question: **does the database lookup mention the current user at all?**

🔴 Vulnerable — keyed by request ID alone:

```ts
const order = await db.order.findUnique({ where: { id: params.id } });
```
```python
order = Order.objects.get(pk=order_id)
```
```go
db.First(&order, "id = ?", chi.URLParam(r, "id"))
```
```ruby
@order = Order.find(params[:id])
```
```php
$order = Order::find($request->id);
```

✅ Safe — the query is fenced to the owner:

```ts
const order = await db.order.findFirst({
  where: { id: params.id, userId: session.user.id },   // ← the fence
});
if (!order) return new Response("Not found", { status: 404 });
```
```python
order = get_object_or_404(Order, pk=order_id, user=request.user)
```

The single most reliable signal: **the `where` / filter clause names the order's ID but never names the logged-in user.** If the only constraint is the attacker-supplied ID, flag it.

### Mobile apps count too

Mobile clients are just front-ends to the same API — the bug lives on the server. But mobile code reveals *which* endpoints take an ID, and how the app builds the URL. Grep the mobile source to map the attack surface, then check the matching server handler.

```bash
# Swift (iOS) — URL building with an id
grep -rEn --include='*.swift' \
  '/users/|/orders/|/api/.*\\(|URL\(string:|\.appendingPathComponent' . 2>/dev/null | head -30

# Kotlin / Java (Android) — Retrofit path params
grep -rEn --include='*.kt' --include='*.java' \
  '@GET\(|@POST\(|@Path\(|@Query\(|"/api/' . 2>/dev/null | head -30

# Flutter / Dart
grep -rEn --include='*.dart' \
  'http\.(get|post|put|delete)\(|Uri\.parse\(|/api/|\$userId|\$id' . 2>/dev/null | head -30

# React Native / Expo
grep -rEn --include='*.tsx' --include='*.ts' --include='*.js' --exclude-dir=node_modules \
  'fetch\(|axios\.(get|post|put|delete)|/api/.*\$\{' . 2>/dev/null | head -30
```

A red flag worth calling out: if a mobile app passes its **own** user ID up to the server (`GET /api/users/{myUserId}/profile`) and the server trusts that ID instead of reading it from the auth token, then anyone who decompiles the app — trivial on Android — can swap in someone else's ID. The client picking *which* account to load is the bug; the server must derive the user from the token, never from the path.

## What to report

**Title:** "Logged-in users can read other people's orders by changing the ID in the URL"

(swap "orders" for whatever record it actually is — invoices, messages, profiles, uploaded files, support tickets)

**Severity:** 🔴 **CRITICAL** when the record holds personal or financial data (orders, invoices, messages, medical info, documents) and the endpoint reads or writes it. 🟠 **HIGH** when the exposed field is low-sensitivity (e.g. a public-ish display name) but ownership still isn't enforced. A write/delete endpoint with no ownership check is always 🔴 — that's not just reading other people's data, it's editing it.

**Detail — write it as a story:**

> **Anyone logged in can read every customer's invoice, just by changing one number.**
>
> Your invoice page at `app/api/invoices/[id]/route.ts:11` looks up the invoice using the ID from the web address:
> ```ts
> const invoice = await db.invoice.findUnique({ where: { id: params.id } });
> return Response.json(invoice);
> ```
> There's a login check higher up, so it *feels* protected. But the lookup only asks "is there an invoice with this ID?" — never "does this invoice belong to the person asking?"
>
> **Here's what goes wrong:** A customer opens their own invoice and sees `app.yourapp.com/api/invoices/1042` in the address bar. Out of curiosity (or worse), they change it to `1041`. Up pops someone else's invoice — name, billing address, line items, amount. They try `1040`, `1039`, `1038`. In ten minutes a script walks every ID from 1 to 50,000 and downloads your entire customer base. You find out when it shows up on a forum, or when a customer emails asking why they can see a stranger's bill.
>
> **How to fix tonight (one line per endpoint):** add the logged-in user to the lookup, so the database can only ever return rows that belong to them.
> ```ts
> import { auth } from "@/lib/auth";
>
> export async function GET(req, { params }) {
>   const session = await auth();
>   if (!session) return new Response("Unauthorized", { status: 401 });
>
>   const invoice = await db.invoice.findFirst({
>     where: { id: params.id, userId: session.user.id },  // ← the fix
>   });
>   if (!invoice) return new Response("Not found", { status: 404 });  // not 403 — don't confirm the ID exists
>   return Response.json(invoice);
> }
> ```
> Return **404, not 403**, when the record isn't theirs — a 403 quietly confirms "this ID exists, you're just not allowed," which still leaks information.
>
> Then do the same to every sibling route — `GET`, `PUT`, `PATCH`, `DELETE` on invoices, and the same shape on orders, messages, files, profiles. The fix is mechanical; sweep all of them in one pass.
>
> **Verify after deploy:** log in as one test user, open one of your own records, then change the ID in the URL to a record you know belongs to a *different* test user. You should get a 404, not their data.

If the project uses **Supabase or Firebase**, add: the durable fix is Row Level Security / security rules on the table itself (see [the database check](./db-exposure.md)) — then even an endpoint that forgets the ownership filter can't hand back rows the requester doesn't own. The query fence above is the app-layer belt; RLS is the suspenders. Do both.

Repeat the report block for each vulnerable endpoint you find. If you find one, assume there are more of the same shape — grep the whole repo before you finish.

## What NOT to flag

The whole point of this product is to not cry wolf. Skip these — they look like the bug but aren't:

- **The ID is already fenced to the user.** If the query's `where` / filter names the session user (`userId: session.user.id`, `user=request.user`, `WHERE user_id = $current`, a `current_user.orders.find(...)` scope, a Rails `current_user.orders.find(params[:id])`), it's correct. Not a finding. This is the most common false positive — read the *whole* `where` clause, not just the first key.

- **The record is genuinely public by design.** Blog posts, public product pages, published profiles, a shared link feature, marketing pages. `GET /api/posts/[slug]` for a public blog has no owner to check. Look at *what the record is* — if it's meant for the whole internet, there's nothing to protect. Note as ⚪ INFO at most.

- **The ID comes from the session, not the request.** `db.user.findUnique({ where: { id: session.user.id } })` reads the *current* user's own row. The ID isn't attacker-controlled — it's whoever is logged in. Safe.

- **Ownership is enforced one layer up.** A `requireOwner(params.id, session)` helper, a route middleware, a Django `LoginRequiredMixin` + `get_queryset` that filters by `self.request.user`, a Rails `before_action` that scopes the record, a policy/guard class (Laravel `authorize()`, NestJS guards, Pundit/CanCanCan). If the check lives in a decorator, middleware, base class, or policy rather than inline, it still counts. Trace one level out before flagging.

- **Tenant/team scoping instead of per-user.** Many B2B apps key ownership to an organization, not an individual (`where: { id, orgId: session.orgId }`). That's a legitimate ownership fence — a record shared across a team the user belongs to is fine. Only flag if there's *no* scoping at all.

- **Unguessable, capability-style IDs used as the secret** — *with caution.* A long random token in a "anyone with the link can view" feature (share links, password-reset tokens, signed URLs) is intentionally the access control. That's a deliberate design, not IDOR. But a 128-bit UUID on a normal account record is **not** a substitute for an ownership check — UUIDs leak (logs, referer headers, the user's own browser history, support tickets) and "hard to guess" isn't "checked." Don't wave a UUID through just because it's not a sequential integer; only treat the random ID as the control when the feature is explicitly a shareable-link/token flow.

- **Admin endpoints that are *supposed* to read any record** — provided they verify an admin role (`if (session.user.role !== "admin") return 403`). An admin dashboard reading `GET /api/admin/users/[id]` by arbitrary ID is correct, *if* the role check is present. Flag only if the admin gate is missing — but that's the painted-lock / unauth check, not this one.

- **Static fixtures, seed scripts, tests, and migrations.** `seed.ts`, `*.test.ts`, `factories.py`, `fixtures/` — these query by hardcoded IDs on purpose and never run in production. Ignore.
