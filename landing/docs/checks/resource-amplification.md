# Check — Resource amplification (one request that does the work of ten thousand)

**What you're looking for:** Endpoints where a *single, well-behaved request* can force your server to do a huge amount of work — load a million rows, accept a 2 GB upload, or run a GraphQL query nested 40 levels deep. This is the cousin of the rate-limiting check (`rate-limiting.md`), but it slips through that net entirely. Rate limiting counts *how many* requests someone makes. Amplification is about *how expensive each request is*. A bouncer who only counts heads at the door won't stop one person who walks in and orders the entire kitchen.

The picture to hold in your head: you built a "list customers" endpoint and tested it with `?pageSize=20`. It felt instant. Then a bot sends `?pageSize=10000000`. Your database tries to serialize ten million rows into JSON, your server's memory balloons, the event loop stalls, and every other user gets a spinning page — or the box just falls over. You were never "attacked" in the dramatic sense. Someone just took you up on an offer you didn't realize you'd made.

Three classic shapes of this offer:
1. **Unbounded page size** — a list endpoint that hands the client the steering wheel on how many records to fetch, with no ceiling. Or worse, a query with no `LIMIT` at all, so it always returns the whole table.
2. **Unbounded GraphQL** — a GraphQL server with no query-depth limit and no cost/complexity limit, especially with aliasing or batching on, so one HTTP request can demand thousands of resolver runs.
3. **Unbounded body / upload size** — an endpoint that will happily read a multi-gigabyte JSON body or accept an arbitrarily large file upload into memory.

**Severity: 🟠 HIGH.** Maps to OWASP API Security Top 10 (2023) **API4:2023 — Unrestricted Resource Consumption.** It's the quietest way to take an app down, and on serverless/pay-per-use infra it converts straight into a surprise bill.

---

## How to scan

This is a "what's *missing*" check. You're reading handlers and config and asking: *is there a ceiling here?* Scan in three groups — page size, GraphQL, body/upload — and for each, the **absence** of a clamp is the finding.

### Group A — list endpoints with a client-controlled page size

Find where the client gets to pick how many rows come back:

```bash
# JS / TS — page-size params pulled from the request (query, body, params)
grep -rEn --include='*.ts' --include='*.js' --include='*.tsx' \
  --exclude-dir={node_modules,.next,dist,build,coverage} \
  -i '(limit|take|perpage|per_page|pagesize|page_size|count|first|\$top|pagelen)\b' \
  . 2>/dev/null | grep -iE 'req\.|query|params|searchParams|ctx\.|request\.|body\.' | head -40

# Prisma / TypeORM / Sequelize / Mongoose finders that may have no take/limit
grep -rEn --include='*.ts' --include='*.js' --exclude-dir={node_modules,.next,dist,build} \
  -i 'findMany|findAll|\.find\(|\.aggregate\(|\.scan\(' . 2>/dev/null | head -40

# Python — Django/DRF/SQLAlchemy/FastAPI page params + queries with no slice
grep -rEn --include='*.py' --exclude-dir={venv,.venv,site-packages,__pycache__} \
  -i 'request\.(args|GET|query_params).get\(.{0,20}(limit|per_page|page_size|count|size)|\.limit\(|\.all\(\)|\.query\(' \
  . 2>/dev/null | head -40

# Go — page-size from query, GORM/sqlx finds
grep -rEn --include='*.go' \
  -i 'Query\(.{0,12}(limit|per_page|page_size|pagesize|count|size)|\.Limit\(|db\.Find\(|\.Select\(' \
  . 2>/dev/null | head -40

# Ruby (Rails) — params-driven per_page, unbounded .all / .where
grep -rEn --include='*.rb' --exclude-dir={vendor} \
  -i 'params\[:(limit|per_page|page_size|count|size)\]|\.limit\(|\.all\b|\.where\(' \
  . 2>/dev/null | head -40

# PHP (Laravel) — request limit, unbounded ->get()/->all()
grep -rEn --include='*.php' --exclude-dir={vendor} \
  -i "request\(\)->(input|query)\(.{0,18}(limit|per_page|page_size|count|size)|->limit\(|->get\(\)|->all\(\)" \
  . 2>/dev/null | head -40

# Raw SQL with no LIMIT — find SELECTs and eyeball whether any cap the rows
grep -rEn --include='*.ts' --include='*.js' --include='*.py' --include='*.go' \
  --include='*.rb' --include='*.php' --include='*.sql' \
  --exclude-dir={node_modules,.next,dist,build,venv,.venv,vendor} \
  -i 'SELECT .* FROM' . 2>/dev/null | grep -viE 'LIMIT|TOP|FETCH FIRST|ROWNUM' | head -40
```

For each hit, read the handler and ask two questions:
- **Is the page size clamped to a server maximum?** (e.g. `Math.min(requested, 100)`)
- **If there's no page-size param at all, does the query still cap rows?** A bare `findMany()` / `.all()` / `SELECT * FROM orders` with no `LIMIT` returns *every* row — the page size is effectively infinity, set by how much data exists.

### Group B — GraphQL with no depth / cost / batching limits

First, confirm there's a GraphQL server at all:

```bash
# Is GraphQL even here?
grep -rEn --include='*.ts' --include='*.js' --include='*.py' --include='*.go' \
  --include='*.rb' --exclude-dir={node_modules,.next,dist,build,venv,.venv,vendor} \
  -i 'apollo-server|@apollo/server|graphql-yoga|express-graphql|mercurius|graphene|strawberry|ariadne|gqlgen|graphql-ruby|nestjs.*graphql|typeGraphQL|/graphql' \
  . 2>/dev/null | head -30
```

If GraphQL is present, check whether ANY of these guards exist:

```bash
# Depth, cost/complexity, and disabled-batching guards (JS/TS ecosystem)
grep -rEn --include='*.ts' --include='*.js' --exclude-dir={node_modules,.next,dist,build} \
  -i 'graphql-depth-limit|depthLimit|createComplexityRule|graphql-query-complexity|graphql-cost-analysis|graphql-validation-complexity|costAnalysis|maxAliases|maxDepth|maxComplexity|allowBatchedHttpRequests|@graphql-armor|disableBatching' \
  . 2>/dev/null | head -30

# Python — graphene/strawberry/ariadne validators
grep -rEn --include='*.py' --exclude-dir={venv,.venv,site-packages} \
  -i 'depth_limit|max_depth|cost_analysis|complexity|validation_rules|QueryDepthLimiter' \
  . 2>/dev/null | head -30

# Ruby — graphql-ruby has built-in max_depth / max_complexity
grep -rEn --include='*.rb' --exclude-dir={vendor} \
  -i 'max_depth|max_complexity|disable_introspection' . 2>/dev/null | head -30
```

If a GraphQL server is present and this pass finds **nothing**, that's your finding. The default for almost every GraphQL framework is *no* depth limit, *no* complexity limit, and (for Apollo Server 3 and graphql-yoga) batching **on** — so an unconfigured server is a vulnerable server.

### Group C — missing body / upload size caps

```bash
# JS / TS — body parsers + file-upload libraries, looking for a missing limit
grep -rEn --include='*.ts' --include='*.js' --exclude-dir={node_modules,.next,dist,build} \
  -i 'express\.json\(|express\.urlencoded\(|bodyParser|body-parser|app\.use\(express|multer\(|formidable\(|busboy|@fastify/multipart|next.*bodyParser|sizeLimit' \
  . 2>/dev/null | head -40

# Reading a raw request body into memory with no cap (often for webhooks/uploads)
grep -rEn --include='*.ts' --include='*.js' --exclude-dir={node_modules,.next,dist,build} \
  -i 'await req\.text\(\)|req\.arrayBuffer\(\)|\.read\(\)|getRawBody|raw-body|stream.*concat|Buffer\.concat' \
  . 2>/dev/null | head -30

# Python — Flask MAX_CONTENT_LENGTH, Django DATA_UPLOAD_MAX_MEMORY_SIZE, FastAPI/Starlette
grep -rEn --include='*.py' --exclude-dir={venv,.venv,site-packages} \
  -i 'MAX_CONTENT_LENGTH|DATA_UPLOAD_MAX|FILE_UPLOAD_MAX|request\.data|request\.get_data\(|await request\.body\(\)|UploadFile|\.read\(\)' \
  . 2>/dev/null | head -40

# Go — MaxBytesReader / Server.MaxHeaderBytes / ParseMultipartForm
grep -rEn --include='*.go' \
  -i 'MaxBytesReader|MaxHeaderBytes|ParseMultipartForm|ioutil\.ReadAll|io\.ReadAll|r\.Body' \
  . 2>/dev/null | head -40

# Ruby (Rails) — Rack body limits, ActiveStorage/Shrine/CarrierWave size validation
grep -rEn --include='*.rb' --exclude-dir={vendor} \
  -i 'Rack::.*Limit|content_length|file_size|size.*validate|validates.*size|max.*size' \
  . 2>/dev/null | head -30

# PHP — upload_max_filesize / post_max_size (php.ini) + Laravel max validation
grep -rEn --include='*.php' --include='*.ini' --include='*.htaccess' --exclude-dir={vendor} \
  -i 'upload_max_filesize|post_max_size|memory_limit|max:[0-9]|->validate' \
  . 2>/dev/null | head -30
```

The finding here is the same shape: a body parser or file handler with **no explicit size limit**, falling back to a generous (or infinite) default.

---

## The dangerous patterns

### Pattern 1 — client picks the page size, server doesn't argue (🟠 HIGH)

The classic AI-generated list endpoint. The model dutifully wires `limit` through to the query and never imagines a hostile value.

```ts
// JS/TS — Next.js / Express + Prisma
export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  const limit = Number(searchParams.get("limit") ?? 20); // ← no ceiling
  const orders = await prisma.order.findMany({ take: limit, orderBy: { id: "desc" } });
  return Response.json(orders);
}
// ?limit=10000000  →  Prisma asks Postgres for 10M rows, server tries to JSON-encode them all.
```

```python
# Python — FastAPI + SQLAlchemy
@app.get("/customers")
def list_customers(limit: int = 20, db: Session = Depends(get_db)):
    return db.query(Customer).limit(limit).all()   # ← limit comes straight from the query string
# ?limit=99999999
```

```go
// Go — net/http + GORM
func ListUsers(w http.ResponseWriter, r *http.Request) {
    limit, _ := strconv.Atoi(r.URL.Query().Get("limit")) // 0 or attacker-chosen
    var users []User
    db.Limit(limit).Find(&users) // GORM: Limit(-1) or huge value = no real cap
    json.NewEncoder(w).Encode(users)
}
```

```ruby
# Ruby on Rails
def index
  render json: Order.limit(params[:per_page]) # params[:per_page] = "50000000"
end
```

```php
// PHP / Laravel
public function index(Request $request) {
    return Order::limit($request->input('per_page', 20))->get(); // no max
}
```

### Pattern 2 — no `LIMIT` at all (🟠 HIGH)

Even sneakier, because there's no parameter to spot. The query just returns *everything*, and the page size is "however big this table grows." Fine on day one with 12 rows; a memory bomb at 4 million.

```ts
// "Just list the events" — returns the entire table, forever
const events = await prisma.event.findMany();          // no take:
return Response.json(events);
```

```python
return jsonify([o.to_dict() for o in Order.query.all()])  # .all() = whole table
```

```sql
-- Raw SQL in any language, no LIMIT clause
SELECT * FROM audit_log ORDER BY created_at DESC;
```

```go
db.Find(&allRecords) // no .Limit() anywhere
```

### Pattern 3 — GraphQL with no depth or cost limit (🟠 HIGH)

GraphQL's superpower — "ask for exactly the shape you want" — is also the footgun. With circular relations (`user → posts → author → posts → author …`) one query can recurse arbitrarily deep, and one HTTP request can fan out to thousands of resolver calls.

```ts
// Apollo Server with default config — NO depth limit, NO complexity limit
const server = new ApolloServer({ typeDefs, resolvers });
// Attacker sends:
//   query { user(id:1){ posts{ author{ posts{ author{ posts{ author{ ... }}}}}}} }
//   nested 50 levels deep → server melts before it ever returns.
```

**Aliasing amplification** — even a *shallow* query becomes huge by aliasing the same expensive field hundreds of times in one request:

```graphql
query {
  a1: searchProducts(q:"x"){ ...big }
  a2: searchProducts(q:"x"){ ...big }
  # ...repeated 1000×, all in ONE request → rate limiting never fires.
}
```

**Batching amplification** — Apollo Server 3 and graphql-yoga accept an *array* of operations in one HTTP POST by default. One request, hundreds of full queries.

### Pattern 4 — unbounded request body / upload (🟠 HIGH)

```ts
// Express — default body-parser had a 100kb cap, but people raise it to the moon:
app.use(express.json({ limit: "500mb" }));   // ← attacker sends a 500MB JSON blob
// or multer with no fileSize at all:
const upload = multer({ dest: "uploads/" }); // no limits.fileSize → any size accepted
```

```python
# Flask with no MAX_CONTENT_LENGTH set → no cap on request body size at all
app = Flask(__name__)
# (missing) app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024
```

```go
// Reading the whole body into RAM with no MaxBytesReader guard
body, _ := io.ReadAll(r.Body) // attacker streams gigabytes → OOM
```

### Mobile angle (Swift / Kotlin / Flutter / React Native)

Mobile clients are usually *victims* of server amplification, not the cause — but two things to check:

- **The client sets the page size, and the server trusts it.** If your iOS/Android/Flutter app sends `?pageSize=`, the *server* must still clamp it. Anyone can bypass the app and hit the API directly with `pageSize=9999999` — so a clamp baked only into the app is no clamp at all. Flag the server endpoint, not the app.
- **Infinite-scroll with a client-supplied `count`/`first`** (common in RN/Flutter GraphQL clients like Apollo or `graphql_flutter`) points at a GraphQL backend — make sure that backend has depth + cost limits (Pattern 3).

There is no mobile-only fix here: every fix in this check lives on the **server**.

---

## Safe patterns (these are NOT findings)

**Page size clamped to a server maximum:**

```ts
const MAX = 100;
const requested = Number(searchParams.get("limit") ?? 20);
const take = Math.min(Math.max(1, requested || 20), MAX); // floor 1, ceiling 100
const rows = await prisma.order.findMany({ take });
```

```python
limit = min(max(int(request.args.get("limit", 20)), 1), 100)  # clamped 1..100
```

```go
limit := 20
if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 {
    limit = min(v, 100) // hard ceiling
}
```

**Cursor pagination with a fixed page size** (DRF `CursorPagination`, Rails `pagy`, `keyset` cursors) — the page size is set by the *server*, not the caller. Safe.

**Body / upload caps in place:**

```ts
app.use(express.json({ limit: "1mb" }));
const upload = multer({ limits: { fileSize: 5 * 1024 * 1024 } }); // 5 MB
```

```python
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024   # 16 MB, Flask refuses larger
```

```go
r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB cap before reading
```

**GraphQL with guards configured:**

```ts
import depthLimit from "graphql-depth-limit";
import { createComplexityLimitRule } from "graphql-validation-complexity";
const server = new ApolloServer({
  typeDefs, resolvers,
  validationRules: [depthLimit(7), createComplexityLimitRule(1000)],
  allowBatchedHttpRequests: false, // batching off
});
```

…or `@escape.tech/graphql-armor` installed (it bundles depth + cost + alias + batch limits), or `graphql-ruby`'s `max_depth`/`max_complexity` set — any of these means **not a finding**.

---

## Report a finding as

**Title:** "`/api/orders` lets one request pull your entire orders table"

(adapt: "GraphQL API has no query depth or cost limit" for Pattern 3; "Upload endpoint accepts unlimited file size" for Pattern 4)

**Detail:**
> `src/app/api/orders/route.ts:6` reads `limit` straight from the query string and passes it to `prisma.order.findMany({ take: limit })` with no maximum. A request to `/api/orders?limit=10000000` makes your database fetch up to ten million rows and your server try to serialize all of them into one JSON response. One such request can exhaust memory and stall every other user; a handful in a loop can take the app down — and your rate limiter won't catch it, because to a request-counter this is just *one* request.
>
> This is OWASP API4:2023, *Unrestricted Resource Consumption*. It's the failure mode rate limiting (`rate-limiting.md`) is blind to: the danger isn't how *many* requests arrive, it's how *expensive* a single one is allowed to be.
>
> **What to do tonight:**
> 1. Clamp the page size to a server-side maximum — never trust the client's number:
>    ```ts
>    const MAX = 100;
>    const requested = Number(new URL(req.url).searchParams.get("limit") ?? 20);
>    const take = Math.min(Math.max(1, requested || 20), MAX);
>    const orders = await prisma.order.findMany({ take, orderBy: { id: "desc" } });
>    ```
> 2. Find every other list endpoint and do the same. Any query with no `LIMIT`/`take` at all is the same bug with the ceiling set to "the whole table" — give each one a hard cap.
> 3. Add a body-size limit so giant payloads bounce before they're parsed: `app.use(express.json({ limit: "1mb" }))` (Express), `app.config["MAX_CONTENT_LENGTH"] = 16*1024*1024` (Flask), or `http.MaxBytesReader(w, r.Body, 1<<20)` (Go).
> 4. If you run a GraphQL server, add a depth limit and a cost/complexity limit and turn off query batching — the defaults protect you from nothing (see Pattern 3 above).
> 5. Verify: hit the endpoint with an absurd page size (`curl "https://yourapp.com/api/orders?limit=9999999"`) and confirm it returns at most your max (e.g. 100 rows), not the whole table.

Repeat the report block for each amplifiable endpoint you found (each list route, the GraphQL server, each uncapped upload).

---

## Don't false-positive on

- **Already-clamped page sizes.** If you see `Math.min(requested, MAX)`, a clamp helper, or a validator that rejects `limit > N` (Zod `.max()`, DRF `max_page_size`, `class-validator` `@Max()`), it's handled. Not a finding.
- **Cursor / keyset pagination** where the server fixes the page size (DRF `CursorPagination`, `pagy`, Relay-style connections with a server `pageSize`). The caller can't inflate it. Safe.
- **Framework defaults that already cap.** Django REST Framework's `PageNumberPagination` respects `max_page_size`; Rails `express.json()` defaults to a 100kb body limit unless someone raised it; `@fastify/multipart` has a default `fileSize`. If a sane default cap is in force and nobody overrode it upward, don't flag.
- **GraphQL servers that already have guards.** `graphql-depth-limit`, `graphql-query-complexity`, `graphql-cost-analysis`, `@graphql-armor`, or `graphql-ruby`'s `max_depth`/`max_complexity` configured → covered. Also: a purely **internal** GraphQL endpoint that's network-isolated (not reachable from the internet) is lower priority — note it, don't alarm.
- **Admin-only / authenticated-internal listings** behind a real auth + role check where the only callers are trusted staff — lower severity. A logged-in admin pulling a big report is a feature, not an attack. Still worth a cap, but note it as 🟡, not 🟠.
- **Genuinely small, fixed tables** (a `countries` table, a `plan_tiers` lookup of 4 rows) returned with no `LIMIT`. The data can't grow unbounded, so there's nothing to amplify. Use judgment on the table, not just the query shape.
- **Bulk/export endpoints intentionally designed to stream everything** (a CSV export behind auth that uses a streaming response and back-pressure rather than buffering the whole result in memory). If it streams and is access-controlled, it's a deliberate feature — note the design, don't flag it as a bug.
- **The page-size clamp living only in the mobile/frontend client.** This is the *inverse* trap: don't let a clamp in the Swift/Kotlin/RN app convince you the endpoint is safe. The clamp must be on the server. If you only see it client-side, the server endpoint is still a finding.
