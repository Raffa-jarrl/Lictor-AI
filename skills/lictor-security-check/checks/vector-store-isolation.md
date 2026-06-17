# Check — Vector store has no per-tenant isolation (one customer can retrieve another's documents)

**What you're looking for:** a RAG / "chat with your docs" feature where every customer's documents live in **one shared vector index**, and the similarity search that powers it runs with **no filter for who's asking**. The model retrieves the nearest chunks to the question — and "nearest" doesn't care which company uploaded them. So Customer A asks a question, the search reaches across the whole index, and the model answers using Customer B's confidential contract, support ticket, or medical record. Nobody hacked anything. The retrieval just wasn't scoped.

The second half of this check: the **index credentials and endpoint** (Pinecone API key, Weaviate URL, Qdrant key, the pgvector connection string) sitting in client-reachable code or committed to the repo. If the key that can read and delete your entire embedding store is shippable to a browser or sitting in git history, the isolation question is moot — anyone can query the whole thing directly.

This is **OWASP Top 10 for LLM Applications 2025, LLM08: Vector and Embedding Weaknesses**. It's the RAG-specific cousin of the classic "users can see other users' data" bug (IDOR, `idor.md`) — except instead of changing an ID in a URL, the leak happens silently inside a similarity search the user never even sees.

## The one-sentence test

> **In a multi-tenant app, can a similarity search return a chunk that belongs to a different customer than the one asking?**

If the query has no namespace, no `filter={tenant_id: ...}`, no `WHERE tenant_id = ...` — then yes, and that's the finding. If your app is genuinely single-tenant (one company, one shared corpus, everyone allowed to see everything), there's nothing to isolate — skip it (see "Don't false-positive on").

## Why founders ship this by accident

The vector-DB quickstart everyone copies is single-tenant by design. The Pinecone "hello world", the LangChain RAG tutorial, the Supabase pgvector demo — they all create one index, stuff documents in, and query with no filter. It works perfectly with one user. Then the founder adds a second customer, a third, a tenth — all uploading into the same index because that's what the tutorial set up — and the `query(vector=...)` line never changed. The isolation was never there to remove; it was just never added.

The tell: documents get written **with** a tenant/user/org id in their metadata (because the upload code knew who was uploading), but the query reads back **without** filtering on it. Half the wiring is present — that's the smoking gun.

## How to scan

You're reading the repo, not running it. Two passes: **(1)** confirm it's multi-tenant and find the vector queries, **(2)** check whether each query is scoped.

### Step 1 — find the vector store queries

```bash
# Pinecone / Weaviate / Qdrant / Chroma / Milvus client query calls
grep -rEn --exclude-dir={node_modules,.next,dist,build,vendor,.venv,target} \
  --include='*.ts' --include='*.js' --include='*.py' --include='*.go' --include='*.rb' --include='*.php' \
  -E '\.query\(|\.search\(|similaritySearch|similarity_search|nearVector|near_vector|asRetriever|as_retriever|\.fetch\(|queryByVector|knn_search|search_batch' \
  . 2>/dev/null | head -40

# LangChain / LlamaIndex retriever construction (the filter, if any, is set here)
grep -rEn --exclude-dir={node_modules,.next,dist,build,vendor,.venv,target} \
  --include='*.ts' --include='*.js' --include='*.py' \
  -E 'as_retriever|asRetriever|VectorStoreIndex|from_documents|fromDocuments|search_kwargs|metadata_filter|PineconeStore|WeaviateStore|Chroma\(|QdrantClient|Milvus' \
  . 2>/dev/null | head -40

# pgvector / raw SQL nearest-neighbour: the <-> <=> <#> distance operators in an ORDER BY
grep -rEn --exclude-dir={node_modules,.next,dist,build,vendor,.venv,target} \
  --include='*.ts' --include='*.js' --include='*.py' --include='*.go' --include='*.rb' --include='*.php' --include='*.sql' \
  -E 'ORDER BY .*(<->|<=>|<#>)|embedding\s*(<->|<=>|<#>)|cosine_distance|l2_distance|inner_product' \
  . 2>/dev/null | head -40
```

### Step 2 — confirm multi-tenancy, then check each query for a scope

First, is this app multi-tenant at all? Look for the signal that more than one customer's data shares storage:

```bash
# Tenant/org/account/workspace columns and fields — the thing a query SHOULD filter on
grep -rEn --exclude-dir={node_modules,.next,dist,build,vendor,.venv,target} \
  -E 'tenant_?id|org_?id|organization_?id|account_?id|workspace_?id|customer_?id|team_?id|namespace' \
  . 2>/dev/null | head -40
```

If those ids show up in the **upload/embed** code (chunks written with `metadata: { tenantId }` or a `tenant_id` column) **but not in the query**, you've found it. For each query from Step 1, read the surrounding 15 lines and answer: *does this call constrain results to the caller's tenant?* A query is **scoped** if you see any of:

- A **namespace** pinned to the tenant: `index.namespace(tenantId).query(...)` (Pinecone), or a per-tenant collection/class name.
- A **metadata filter** on the tenant: `filter: { tenantId: { $eq: ctx.tenantId } }`, `where={"tenant_id": tid}`, `search_kwargs={"filter": {"tenant_id": tid}}`.
- A **SQL WHERE** on the tenant for pgvector: `WHERE tenant_id = $1 ORDER BY embedding <-> $2`, **and** `tenant_id` is server-derived (from the session), not from the request body.

If none of those are present, the query reads the whole index. Finding.

## What "isolated properly" looks like (so you know what's missing)

Two valid shapes — either is fine:

1. **Hard partition: one namespace / collection per tenant.** Every query is pinned to the caller's namespace, so a search physically cannot reach another tenant's vectors. Strongest option.
2. **Shared index + mandatory metadata filter.** One index, but every chunk carries `tenant_id` in its metadata and **every** query passes `filter: { tenant_id: <server-derived caller id> }`. Works, but it's only as safe as your discipline — one unfiltered query anywhere reopens the leak. Centralise the query behind one wrapper that always injects the filter.

The critical detail in both: the tenant id comes from the **authenticated session on the server**, never from a request field the client can set. A filter of `tenant_id = req.body.tenantId` is no protection — the attacker just sends someone else's id (that's IDOR wearing a vector-search costume).

## The dangerous patterns, across stacks

**JS / TS — Pinecone (no namespace, no filter)**

```ts
// Every tenant's vectors in one index, query scoped to nobody
const res = await index.query({
  vector: queryEmbedding,
  topK: 5,
  includeMetadata: true,
});                                    // ← returns the nearest chunks from ALL customers
```

**JS / TS — LangChain retriever with no filter**

```ts
const retriever = vectorStore.asRetriever({ k: 4 });   // ← no filter; pulls from the whole store
const docs = await retriever.invoke(question);
```

**Python — pgvector, raw SQL with no tenant WHERE**

```python
rows = db.execute(
    "SELECT content FROM documents ORDER BY embedding <-> %s LIMIT 5",
    (query_embedding,),
)                                       # ← nearest neighbours across every tenant's rows
```

**Python — LangChain / Chroma**

```python
retriever = vectordb.as_retriever(search_kwargs={"k": 4})   # ← no "filter" key
docs = retriever.invoke(question)
```

**Python — Qdrant**

```python
hits = client.search(
    collection_name="docs",             # one shared collection
    query_vector=q_vec,
    limit=5,
)                                       # ← no query_filter → cross-tenant hits
```

**Go — Weaviate / pgvector**

```go
// pgvector via database/sql — no tenant predicate
rows, _ := db.Query(
  `SELECT content FROM chunks ORDER BY embedding <-> $1 LIMIT 5`, qvec) // ← whole table
```

**Ruby — pgvector (neighbor gem) / Rails**

```ruby
# nearest_neighbors over the entire table, not the tenant's
Document.nearest_neighbors(:embedding, query_vec, distance: "cosine").first(5)
# ← no .where(tenant_id: Current.tenant.id) scope
```

**PHP — Laravel + pgvector**

```php
$rows = DB::select(
  'SELECT content FROM documents ORDER BY embedding <=> ? LIMIT 5',
  [$queryVec]                           // ← no tenant_id bound, no WHERE
);
```

**Mobile — Swift / Kotlin / Flutter / React Native**

On mobile the **isolation** flavour is usually fine (on-device RAG is one user's own data — see false positives). The dangerous mobile pattern is the **credentials** half: the app talks to a cloud vector DB **directly from the device** with the index key baked into the binary.

```swift
// Swift — Pinecone key shipped in the app, device queries the index directly
let key = "pcsk_3f9a...live"            // ← extractable from the binary; queries everyone's data
var req = URLRequest(url: URL(string: "https://my-index.svc.pinecone.io/query")!)
req.setValue(key, forHTTPHeaderField: "Api-Key")
```

```kotlin
// Kotlin (Android) — Weaviate endpoint + key in client code
val client = WeaviateClient(Config("https", "myorg.weaviate.network"), mapOf("Authorization" to "Bearer $WEAVIATE_KEY"))
```

```dart
// Flutter — Qdrant key in the app, no server in between
final res = await dio.post('https://xyz.qdrant.io/collections/docs/points/search',
  options: Options(headers: {'api-key': kQdrantKey}));   // ← key in the bundle
```

```js
// React Native — same shape: vector-DB SDK + key bundled into JS
```

Any device that holds a vector-DB read/write key can query the **whole** index, ignore every per-tenant filter your server would have applied, and (with a write/delete key) corrupt or wipe the embeddings. Vector DB access belongs **behind your server**, the same as a database password.

## The credentials half — hardcoded / client-reachable index keys

Independent of isolation, flag these:

```bash
# Vector-DB API keys and endpoints in committed / client-reachable code
grep -rEn --exclude-dir={node_modules,.next,dist,build,vendor,.venv,target} \
  -E 'pcsk_[A-Za-z0-9_]{20,}|[a-z0-9-]+\.svc\.[a-z0-9-]+\.pinecone\.io|[a-z0-9-]+\.weaviate\.(network|cloud)|[a-z0-9-]+\.qdrant\.io|QDRANT_API_KEY|WEAVIATE_API_KEY|PINECONE_API_KEY' \
  . 2>/dev/null | head -40
```

- A literal Pinecone key (`pcsk_...`), Qdrant key, or Weaviate token in source → treat like any leaked credential (**CRITICAL**; cross-ref `secrets.md` and `ai-keys.md` for rotation).
- A vector-DB endpoint + key referenced in a **client bundle** (`NEXT_PUBLIC_*`, `EXPO_PUBLIC_*`, `VITE_*`, a mobile binary, any browser-shipped JS) → the key is public the moment you deploy. **CRITICAL.**
- An **unauthenticated, internet-reachable** vector DB (a self-hosted Qdrant/Weaviate/Milvus/Chroma bound to `0.0.0.0` with auth disabled) → anyone who finds the host reads/writes everything (cross-ref `open-services.md`). **CRITICAL.**

## Severity

- 🔴 **CRITICAL / HIGH** — multi-tenant app, shared index, unscoped similarity search → **cross-tenant document retrieval**. One customer's questions surface another customer's confidential data through the model's answers. Default to **CRITICAL** when the retrieved content is sensitive (contracts, PII, health, financial, support history) or the app is clearly B2B SaaS; **HIGH** for lower-sensitivity shared corpora.
- 🔴 **CRITICAL** — vector-DB key/endpoint in client-reachable code or committed to the repo, OR an internet-reachable index with auth off. Direct, unfiltered access to the entire embedding store.
- 🟠 **HIGH** — the query *does* filter, but on a **client-supplied** tenant id (`filter: { tenantId: req.body.tenantId }`) rather than a server-derived one. That's not isolation, it's an honour system the attacker declines.

## Report a finding as

**Title:** "Vector search has no per-tenant filter — one customer can retrieve another's documents"

(adapt: "Pinecone query runs with no namespace", "pgvector nearest-neighbour has no tenant WHERE", "Pinecone key shipped in the mobile binary")

**Detail:**
> `src/lib/rag.ts:24` runs a similarity search (`index.query({ vector, topK: 5 })`) with **no namespace and no metadata filter**, even though documents are stored with a `tenantId` in their metadata (`src/lib/ingest.ts:31`). Every customer's chunks live in the same index, so this query returns the *nearest* chunks to the question regardless of which customer uploaded them.
>
> Concretely: Customer A asks "what's our renewal price?" Your app embeds the question, searches the shared index, and the nearest match happens to be a clause from **Customer B's** contract. The model reads it as context and answers Customer A using Customer B's confidential terms. No URL was tampered with, no auth was bypassed — the retrieval simply wasn't scoped to the asker. This is **OWASP LLM08 (Vector and Embedding Weaknesses)**, and it's the RAG version of letting one user read another's data (IDOR, `idor.md`) — just hidden inside a search the user never sees.
>
> **What to do tonight:**
>
> 1. **Derive the tenant id from the session on the server — never from the request.** Then scope every query to it. Two valid fixes:
>
>    **A — Namespace per tenant (Pinecone; strongest):**
>    ```ts
>    const tenantId = session.user.tenantId;          // server-side, from auth — NOT req.body
>    const res = await index
>      .namespace(tenantId)                           // physically can't reach other tenants
>      .query({ vector, topK: 5, includeMetadata: true });
>    ```
>    (Write into the same namespace at ingest time: `index.namespace(tenantId).upsert(...)`.)
>
>    **B — Mandatory metadata filter (shared index):**
>    ```ts
>    const tenantId = session.user.tenantId;          // server-side
>    const res = await index.query({
>      vector, topK: 5, includeMetadata: true,
>      filter: { tenantId: { $eq: tenantId } },       // every query, no exceptions
>    });
>    ```
>
>    **pgvector (SQL):**
>    ```sql
>    SELECT content FROM documents
>    WHERE tenant_id = $1               -- bound from the session, not the body
>    ORDER BY embedding <-> $2
>    LIMIT 5;
>    ```
>
> 2. **Funnel every vector query through one wrapper** that always injects the tenant scope, so a future hand-written query can't forget it. One choke point is far safer than ten call sites each remembering the filter.
>
> 3. **Move index credentials server-side.** If a Pinecone/Qdrant/Weaviate key or endpoint is in client/mobile code (`NEXT_PUBLIC_*`, `EXPO_PUBLIC_*`, a binary, browser JS), pull it out, put the vector DB behind your own authenticated API, and **rotate the exposed key** (see `ai-keys.md` / `lictor-rotate`). A leaked read/write key lets anyone query — or wipe — the whole store.
>
> 4. **Backfill the scope on existing data.** If older chunks were ingested without a `tenant_id` / namespace, you can't filter what isn't labelled — re-tag or re-ingest them before relying on the filter.
>
> 5. **Verify.** Log in as Customer A, ask a question whose answer only exists in Customer B's documents. You should get "I don't know," not B's data.

Repeat the report block for each unscoped query and each exposed index credential you find.

## Don't false-positive on

- **Genuinely single-tenant apps with one shared corpus.** A personal "chat with my notes," an internal company knowledge base where every employee is *meant* to see everything, a public docs Q&A bot over your own published content — there's one logical tenant and no one to isolate from. An unfiltered query is correct here. Not a finding. (The line: is there more than one customer whose data must stay apart? If no, skip.)
- **Queries already scoped by namespace or tenant metadata.** `index.namespace(tenantId).query(...)`, `filter: { tenantId }`, `WHERE tenant_id = $1`, `search_kwargs={"filter": {"tenant_id": tid}}` — **as long as the id is server-derived from the session.** That's the correct pattern; note INFO and move on.
- **Per-tenant physical separation.** One index/collection/database **per** customer (e.g. a Weaviate class or Qdrant collection named per tenant, or a separate pgvector schema per tenant). Cross-tenant retrieval is impossible by construction even with an "unfiltered" query, because the store only holds one tenant's data. Not a finding.
- **On-device / local mobile RAG over the user's *own* data.** A Swift/Kotlin/Flutter app embedding the user's own notes, photos, or downloaded files into a local store (SQLite-vec, ObjectBox, on-device Chroma) and querying it unfiltered — that's one user's data on their own device. No tenant boundary to cross. (Still flag it if the app ships a **cloud** vector-DB key in the binary — that's the credentials half, and it's a finding.)
- **Pure embedding generation, clustering, or dedup with no cross-tenant read-back.** Computing embeddings, running k-means, or de-duplicating within a single tenant's set — no similarity search that returns another tenant's content. Nothing to leak.
- **The `tenant_id` is genuinely server-derived.** Don't flag a filtered query just because the variable is named `tenantId` — trace where it comes from. From `session`/`auth()`/a verified JWT claim = safe. From `req.body`/`req.query`/a header the client sets = **that's the HIGH finding** above (IDOR-style), report it.
- **Already covered elsewhere — cross-reference, don't double-report.** *Poisoned* documents smuggling instructions into the prompt is **indirect prompt injection** (`indirect-prompt-injection.md`) — that's LLM01, a different bug from this LLM08 isolation/credentials slice. A leaked vector-DB key's *rotation* lives in `ai-keys.md`. A client filter trusting a request-supplied id is the vector-shaped face of IDOR (`idor.md`). Point at the right module rather than re-flagging the same line in two reports.
