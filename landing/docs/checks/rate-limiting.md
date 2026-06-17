# Check — No rate limiting (anyone can hammer your app — or run up your AI bill)

**What you're looking for:** Endpoints that anyone can call as fast as they want, with nothing in front of them counting the requests. Three flavors matter most: **login** (so a bot can guess thousands of passwords a minute), **password reset / email-send** (so someone can spam your users or burn your email quota), and — the big one in 2026 — **AI endpoints** (your "chat," "generate," "summarize" routes that call OpenAI/Anthropic/etc. and cost you real money *per request*). If there's no limiter, a single script — or one bored person with `curl` in a loop — can lock out accounts, flood inboxes, or wake you up to a four-figure model bill overnight.

The short version: a rate limit is the bouncer that says "you've had enough, come back in a minute." Without one, every expensive or sensitive action is a tap left running.

## How to scan

This is partly a "what's *missing*" check, so you scan in two passes: (1) find the endpoints that *should* be protected, then (2) check whether any limiter exists at all in the project.

### Pass 1 — find the sensitive / expensive endpoints

```bash
# Auth + password-reset + email-send routes (any stack)
grep -rEn --include='*.ts' --include='*.js' --include='*.py' --include='*.go' \
  --include='*.rb' --include='*.php' --exclude-dir={node_modules,.next,dist,build,venv,.venv,vendor} \
  -i 'login|signin|sign-in|authenticate|password.?reset|forgot.?password|reset.?password|send.?(otp|code|email|sms)|verify.?(otp|code)|/auth' \
  . 2>/dev/null | head -40

# The expensive AI endpoints — the routes that cost you money per call
grep -rEn --include='*.ts' --include='*.js' --include='*.py' --include='*.go' \
  --include='*.rb' --include='*.php' --exclude-dir={node_modules,.next,dist,build,venv,.venv,vendor} \
  -i 'openai|anthropic|claude|gpt-|chat\.completions|messages\.create|generate|/chat|/ask|/completion|/summarize|/embed|replicate|huggingface|/image' \
  . 2>/dev/null | head -40
```

### Pass 2 — does ANY rate limiter exist in the codebase?

If pass 1 found sensitive routes and pass 2 finds **nothing**, that's your finding.

```bash
# JS / TS — express-rate-limit, @upstash/ratelimit, rate-limiter-flexible, hono limiter, next limiter
grep -rEn --include='*.ts' --include='*.js' --exclude-dir={node_modules,.next,dist,build} \
  -i 'rate.?limit|ratelimit|express-rate-limit|rate-limiter-flexible|@upstash/ratelimit|slowDown|throttle|p-limit|bottleneck' \
  . 2>/dev/null | head -30

# Python — slowapi, flask-limiter, django-ratelimit, DRF throttling
grep -rEn --include='*.py' --exclude-dir={venv,.venv,site-packages,__pycache__} \
  -i 'slowapi|flask.?limiter|Limiter|ratelimit|django_ratelimit|@ratelimit|DEFAULT_THROTTLE|throttle_classes|RateThrottle' \
  . 2>/dev/null | head -30

# Go — common limiter packages + the stdlib token bucket
grep -rEn --include='*.go' \
  'golang.org/x/time/rate|rate\.NewLimiter|ulule/limiter|didip/tollbooth|httprate|throttled' \
  . 2>/dev/null | head -30

# Ruby — rack-attack is the standard; Rails 7.2+ has built-in rate_limit
grep -rEn --include='*.rb' --include='Gemfile' --exclude-dir={vendor} \
  -i 'rack.?attack|rack-attack|rate_limit|throttle' \
  . 2>/dev/null | head -30

# PHP / Laravel — the throttle middleware + RateLimiter facade
grep -rEn --include='*.php' --exclude-dir={vendor} \
  -i "throttle:|RateLimiter::|Limit::|middleware\(\s*['\"]throttle" \
  . 2>/dev/null | head -30

# Edge / platform limiters (often the ONLY thing protecting a serverless app)
grep -rEn --include='*.ts' --include='*.js' --include='*.toml' --include='*.json' \
  --exclude-dir={node_modules} \
  -i 'cloudflare.*rate|wrangler.*rate|vercel.*(firewall|rate)|@vercel/firewall|kv.*(limit|count)' \
  . 2>/dev/null | head -20

# Mobile / cross-platform — there is almost NEVER a real limiter client-side,
# which is the point: confirm the SERVER it talks to has one. Find the AI/auth
# calls the app makes, then go check the backend that answers them.
grep -rEn --include='*.swift' --include='*.kt' --include='*.dart' --include='*.tsx' \
  -i 'openai|anthropic|/chat|/login|/generate|URLSession|OkHttp|Retrofit|Dio\(' \
  . 2>/dev/null | head -20
```

### The question that decides if it's a finding

For each sensitive/expensive route from pass 1: **is there anything that counts requests and says "no more" — on this route, in a middleware that covers it, or at the edge (Cloudflare/Vercel rules)?** If you can trace a path from "request arrives" to "we call the model / check the password / send the email" with no counter anywhere in between, it's unprotected.

## The dangerous patterns

**Pattern 1: login with no limiter (password brute-force / credential stuffing)**

```ts
// app/api/login/route.ts
export async function POST(req: Request) {
  const { email, password } = await req.json();
  const user = await db.user.findUnique({ where: { email } });
  if (!user || !(await bcrypt.compare(password, user.hash))) {
    return new Response("Invalid", { status: 401 });   // ← no count of how many tries
  }
  return Response.json({ token: signToken(user) });
}
```

A bot can try 10,000 passwords a minute against one email, or one common password against 10,000 emails ("credential stuffing" with a leaked password list). Nothing stops it. **HIGH** — it's how accounts get taken over.

**Pattern 2: password-reset / "email me a code" with no limiter (spam + quota burn)**

```python
# anyone can fire this as fast as they like
@app.post("/forgot-password")
def forgot(email: str):
    send_reset_email(email)          # ← every call sends a real email
    return {"ok": True}
```

Someone loops this with a victim's address and floods their inbox (an "email bomb"), or loops it with thousands of addresses and burns through your Postmark/SendGrid/SES quota — getting your sending domain throttled or suspended so your *real* reset emails stop arriving. **HIGH.** (Same shape for SMS/OTP sends, where each one also costs you money.)

**Pattern 3: the expensive AI endpoint with no quota (cost-bombing / wallet-draining) — the 2026 special**

```ts
// app/api/chat/route.ts — every call hits the model, every call costs you money
export async function POST(req: Request) {
  const { messages } = await req.json();
  const completion = await openai.chat.completions.create({
    model: "gpt-4o",
    messages,                        // ← attacker controls length AND frequency
  });
  return Response.json(completion.choices[0].message);
}
```

This is the one that ends careers' worth of runway in a weekend. There's no login on it, or there is but no per-user cap. Someone writes a 20-line script that POSTs giant prompts in a tight loop. Each request is real tokens against *your* API key. You find out when the provider emails you about a $3,000 bill — or worse, your key has no spend cap and the bill is open-ended. This is sometimes called a "**denial-of-wallet**" attack: they don't take your app down, they make it bankrupt you to stay up. **CRITICAL** when the endpoint is public or the key has no hard spend cap.

**Pattern 4: a limiter exists but is keyed on something the attacker controls**

```ts
// looks protected... but the key is a header the client sets
const id = req.headers.get("x-user-id") ?? req.ip;
await limiter.limit(id);   // ← attacker rotates x-user-id → unlimited fresh buckets
```

Keying the limit on a spoofable header (or on a `userId` from the request body before auth) means the attacker just changes it every request and gets a brand-new allowance each time. The limiter is decorative. **MEDIUM–HIGH.** Key on the *authenticated* user id, or on the real client IP from a trusted source (e.g. Cloudflare's `CF-Connecting-IP`, not an arbitrary `X-Forwarded-For`).

**Pattern 5: "we set maxTokens, we're fine"**

```ts
const completion = await openai.chat.completions.create({
  model: "gpt-4o", messages, max_tokens: 500,   // ← caps ONE response, not the count of calls
});
```

`max_tokens` caps the size of a single answer. It does nothing about someone making 100,000 calls. A per-response cap is good hygiene, but it is **not** a rate limit. Still a finding if there's no limit on *how often* the route can be hit.

## The fix: a small limiter in front of the sensitive routes

You don't need a fancy service. Two shapes cover almost everyone.

**Shape A — serverless / edge (Next.js, Vercel, Cloudflare Workers): a shared store + a few lines.** `@upstash/ratelimit` is the common pick because serverless functions don't share memory, so you need a store both can see (Upstash Redis is free-tier and one signup):

```ts
// lib/ratelimit.ts
import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";

export const aiLimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(20, "1 d"),   // 20 AI calls per user per day
});
export const authLimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(5, "10 m"),   // 5 login attempts per IP per 10 min
});
```

```ts
// app/api/chat/route.ts
import { aiLimit } from "@/lib/ratelimit";
import { auth } from "@/lib/auth";

export async function POST(req: Request) {
  const session = await auth();
  if (!session) return new Response("Unauthorized", { status: 401 });

  // key on the AUTHENTICATED user, not a header they control
  const { success, reset } = await aiLimit.limit(session.user.id);
  if (!success) {
    return new Response("Daily AI limit reached — try again tomorrow", {
      status: 429,
      headers: { "Retry-After": String(Math.ceil((reset - Date.now()) / 1000)) },
    });
  }
  // ... existing model call
}
```

**Shape B — long-running server (Express / Fastify / Flask / FastAPI / Rails / Laravel): use the framework's limiter middleware.**

```ts
// Express — express-rate-limit, applied to the routes that need it
import rateLimit from "express-rate-limit";
const authLimiter = rateLimit({ windowMs: 10 * 60_000, limit: 5 });   // 5 / 10 min
const aiLimiter   = rateLimit({ windowMs: 24 * 60 * 60_000, limit: 20 }); // 20 / day
app.post("/login", authLimiter, loginHandler);
app.post("/api/chat", aiLimiter, chatHandler);
```

```python
# FastAPI — slowapi (a thin wrapper over the limits library)
from slowapi import Limiter
from slowapi.util import get_remote_address
limiter = Limiter(key_func=get_remote_address)

@app.post("/forgot-password")
@limiter.limit("3/hour")                 # 3 reset emails per IP per hour
def forgot(request: Request, email: str): ...

@app.post("/api/chat")
@limiter.limit("20/day")                  # cap the expensive route
def chat(request: Request, body: ChatIn): ...
```

```ruby
# Rails 7.2+ has it built in — no gem needed
class SessionsController < ApplicationController
  rate_limit to: 5, within: 10.minutes, only: :create   # 5 logins / 10 min
end
# Older Rails: rack-attack in config/initializers/rack_attack.rb
# Rack::Attack.throttle("logins/ip", limit: 5, period: 10.minutes) { |r| r.ip if r.path == "/login" && r.post? }
```

```php
// Laravel — the throttle middleware, named per route
Route::post('/login',  [AuthController::class, 'login'])->middleware('throttle:5,10');     // 5 / 10 min
Route::post('/api/chat',[ChatController::class, 'send'])->middleware('throttle:20,1440');  // 20 / day
```

> **The two backstops every AI app needs regardless of code:**
> 1. **Set a hard spend cap on your model key at the provider.** OpenAI: Billing → Usage limits. Anthropic: Plans & billing → spend limit. This is the seatbelt — even if a limiter has a bug, the bill can't run past the cap. Do this tonight; it takes two minutes and is the single highest-leverage fix here.
> 2. **Put auth in front of the expensive route** (see the api-auth check). A rate limit per *user* only works if there are users. A public AI endpoint with no login can be hit from unlimited fresh IPs — limit by IP *and* require a login.

## Report a finding as

**Title:** "Your AI chat endpoint has no limit — one script can run up a four-figure bill overnight"

(adapt to the route: "Your login page lets a bot guess unlimited passwords," "Your password-reset can be used to flood a user's inbox," etc.)

**Detail:**
> `app/api/chat/route.ts:3` takes a prompt and calls the model on every request, and there's no rate limit anywhere in the project — no `@upstash/ratelimit`, no middleware, no Cloudflare/Vercel rule. Every call to this endpoint spends real money on your API key, and nothing caps how many calls one person can make.
>
> **What can go wrong:** Someone — a competitor, a script kiddie, or just a bot scanning for open AI endpoints (they exist, and they look for exactly this) — points a 20-line loop at `your-app.com/api/chat` and sends thousands of large prompts a minute. Each one is real tokens billed to you. You don't notice until the model provider emails you about the bill, because the app keeps "working" the whole time — it's not down, it's just draining your account. People have woken up to bills bigger than their entire runway from this. It even has a name: a "denial-of-wallet" attack. The fix is cheap; the incident is not.
>
> **How to fix tonight (15 minutes):**
> 1. **Set a hard spend cap on your model key right now** (OpenAI Billing → Usage limits; Anthropic → spend limit). This alone stops the bill from being open-ended, before you touch any code.
> 2. **Put a login check on the route** if it doesn't have one — see the unprotected-API-routes finding. A public AI endpoint can be hit from unlimited IPs.
> 3. **Add a per-user limiter.** On Vercel/Next.js, `@upstash/ratelimit` + free-tier Upstash Redis is ~10 lines:
>    ```ts
>    import { Ratelimit } from "@upstash/ratelimit";
>    import { Redis } from "@upstash/redis";
>    const aiLimit = new Ratelimit({ redis: Redis.fromEnv(), limiter: Ratelimit.slidingWindow(20, "1 d") });
>
>    const { success } = await aiLimit.limit(session.user.id);   // key on the logged-in user
>    if (!success) return new Response("Daily limit reached", { status: 429 });
>    ```
> 4. Key the limit on the **authenticated user id** (or the real client IP from your CDN), never on a header the client can change.
> 5. Do the same for `/login` (try 5 per 10 min) and any "send email/SMS/code" route (try 3 per hour). Use the framework limiter for your stack from the fix section above.
> 6. Verify after deploy: hit the route in a quick loop — `for i in $(seq 1 30); do curl -s -o /dev/null -w "%{http_code}\n" -X POST https://yourapp.com/api/chat -d '{}'; done` — you should see `429`s kick in, not `200`s all the way down.

Repeat the report block for each unprotected sensitive/expensive route you found. Group the auth + reset routes together if they share a fix; call out the AI endpoint separately — it's usually the most severe one.

## Don't false-positive on

- **A limiter already covers the route** — directly, via middleware, or at the edge. If you find `express-rate-limit` on the router, a Laravel `throttle:` on the route group, `rate_limit` in the Rails controller, a `@limiter.limit` decorator, or a Cloudflare/Vercel WAF rate rule that fronts the app, it's handled. Note as INFO that the limits look sane (or flag if a limit is wildly high, like `1000/min` on login).
- **Read-only, cheap, cache-friendly GET routes.** `/api/health`, `/api/posts`, a public blog feed, a sitemap — these don't cost per-call money and aren't auth-sensitive. A missing limit here is at most LOW (scraping/cost-of-bandwidth), and often INFO. Don't treat every endpoint as a brute-force target. Spend your severity on auth, sends, and money-burning AI calls.
- **The expensive call is already gated by something stronger than a rate limit.** A paid-credits/quota system that decrements a balance before calling the model (and refuses at zero) *is* effectively a per-user cap — that's fine. Likewise a job queue that processes one model call at a time with a fixed worker pool bounds the spend by design.
- **Internal / admin / cron-only endpoints with no public route.** A function triggered by a scheduler or only reachable behind VPN/auth-required admin has no anonymous caller to throttle. Confirm there's genuinely no public path to it first.
- **`max_tokens` / response-size caps mistaken for the fix.** This cuts the other way: don't let a `max_tokens: 500` make you *call it protected*. It limits one answer, not the number of calls. The route still needs a request-count limit. (See Pattern 5.)
- **Client-side throttling / debounce in a frontend or mobile app.** A debounced button or a client-side cooldown is UX, not security — anyone can call the API directly with `curl` and skip the UI entirely. The limit has to live on the **server**. Don't credit a frontend-only throttle as protection.
- **A genuinely public, intentionally-free demo endpoint** the founder *wants* anonymous — that's a product choice, but it still needs an IP-based cap and a provider spend cap, so flag it as MEDIUM with "if this is intentional, at least bound it" rather than CRITICAL.
