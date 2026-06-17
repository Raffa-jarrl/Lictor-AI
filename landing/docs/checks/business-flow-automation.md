# Check — Anyone can run your money-making flow with a script (no bot gate)

**What you're looking for:** A flow that *hands out value* — creating accounts, checking out, granting a referral credit, sending an invite email, casting a vote, booking a seat — that a bot can drive thousands of times with a script, because there's **no human-verification gate** (Turnstile / hCaptcha / reCAPTCHA), **no bot signal**, and **no per-account-or-device cap** on the step that actually grants the thing.

This is *not* "no rate limit" (that's the rate-limiting check — same-request-too-fast). This is the next worry over: even at a *polite* pace, can one person spin up 5,000 fresh accounts, mint 5,000 referral bonuses, snap up every concert ticket, or stuff your "best product" poll? The attacker isn't trying to knock you over — they're trying to **farm the thing your flow gives away**. OWASP calls this *Unrestricted Access to Sensitive Business Flows* (API6:2023). Founders feel it as: "where did all these fake signups / free-tier abusers / scalped tickets / 1-star review-bomb come from?"

The short version: a rate limit is a bouncer counting how *fast* people come in. A bot gate is the bouncer checking whether you're a *person at all*. A value flow with neither is a vending machine with the front panel off.

> **Severity: 🟡 MEDIUM / advisory.** This is a "you should add a gate before this bites you" finding, not a "your data is exposed right now" emergency. Report it calmly. Do **not** inflate it to high — and skip it entirely on flows that already have a gate (see "What NOT to flag"). Crying wolf on a non-security founder is worse than the nit.

## What counts as a "sensitive business flow"

Flag only flows where each automated run **mutates value or grants/sends something**. The usual suspects:

| Flow | What a bot farms |
|------|------------------|
| **Signup / account-create** | Free-tier farming (1000 fake accounts → 1000× free quota / trial credits) |
| **Checkout / add-to-cart / purchase** | Scalping — buy out limited stock / tickets / drops, resell |
| **Referral / reward / credit grant** | Referral fraud — self-refer in a loop, mint credits/cash |
| **Invite / "email a friend" / share** | Spam relay off your domain (your reputation, your quota) |
| **Vote / review / rating / comment / "like"** | Review-bombing, vote-stuffing, fake social proof |
| **Reservation / ticket / waitlist / appointment** | Hoarding inventory, denying real customers |
| **Coupon / promo / gift-card redeem** | Brute-forcing or mass-claiming promo value |

If the flow is *read-only* (search, browse, view) or doesn't hand anything out, it's **not** this check — leave it.

## How to scan

Two passes: (1) find the value flows, then (2) check whether a bot gate or per-identity cap sits on the granting step. A flow is a finding only if pass 1 hits **and** pass 2 finds nothing on that flow.

### Pass 1 — find the value-granting handlers (any stack)

```bash
# Account-create / signup / referral / invite / credit / reward / vote / checkout / booking
grep -rEn --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  --include='*.py' --include='*.go' --include='*.rb' --include='*.php' \
  --exclude-dir={node_modules,.next,dist,build,venv,.venv,vendor,Pods} \
  -i 'sign.?up|signUp|register|create.?account|createUser|/users\b|referr|invite|reward|credit|bonus|promo|coupon|gift.?card|redeem|checkout|add.?to.?cart|reserve|reservation|book(ing)?|ticket|/vote|upvote|/review|/rating|sendInvite|send.?email|waitlist' \
  . 2>/dev/null | head -60
```

```bash
# Mobile / cross-platform — the app just calls a backend; find the call, then go
# audit the SERVER that answers it (the gate has to live server-side, never in the app).
grep -rEn --include='*.swift' --include='*.kt' --include='*.java' --include='*.dart' \
  --include='*.tsx' --include='*.jsx' \
  -i 'signUp|register|createAccount|referr|invite|redeem|checkout|purchase|/vote|review|booking|URLSession|OkHttp|Retrofit|Dio\(|fetch\(' \
  . 2>/dev/null | head -40
```

### Pass 2 — is there a human/bot gate or a per-identity cap on that step?

If pass 1 found a value flow and pass 2 finds **nothing for it**, that's the finding.

```bash
# Human-verification widgets — the thing that says "prove you're a person"
grep -rEn --exclude-dir={node_modules,.next,dist,build,venv,.venv,vendor,Pods} \
  -i 'turnstile|cf-turnstile|hcaptcha|h-captcha|recaptcha|g-recaptcha|grecaptcha|siteverify|cf-challenge|captcha|altcha|friendly.?captcha|arkose|funcaptcha|datadome|perimeterx|castle\.io|fingerprintjs|@fingerprintjs|botd' \
  . 2>/dev/null | head -40

# Server-side verification of the token (the half people forget — see Pattern 4)
grep -rEn --exclude-dir={node_modules,.next,dist,build,venv,.venv,vendor,Pods} \
  -i 'challenges\.cloudflare\.com/turnstile|hcaptcha\.com/siteverify|recaptcha.*siteverify|verify.*(turnstile|captcha|recaptcha)|TURNSTILE_SECRET|RECAPTCHA_SECRET|HCAPTCHA_SECRET' \
  . 2>/dev/null | head -30

# Per-account / per-device throttles & dedupe that bound how many times one identity can run it
grep -rEn --exclude-dir={node_modules,.next,dist,build,venv,.venv,vendor,Pods} \
  -i 'unique.*(email|phone|device|fingerprint)|one.?per.?(user|account|device|ip)|already.?(claimed|redeemed|referred|voted)|self.?refer|referrer\s*===|referrer\s*==|device.?id|deviceId|hasVoted|hasClaimed' \
  . 2>/dev/null | head -30
```

### The question that decides if it's a finding

For each value flow: **between "request arrives" and "we grant the credit / create the account / take the ticket / record the vote," is there anything that (a) proves a human is on the other end, OR (b) caps how many times one identity can do it?** If you can trace a clean path with neither, it's an unprotected business flow. Report it — medium.

## The dangerous patterns

**Pattern 1 — open signup, no gate (free-tier farming)**

```ts
// app/api/signup/route.ts — a script can mint accounts forever
export async function POST(req: Request) {
  const { email, password } = await req.json();
  const user = await db.user.create({ data: { email, hash: await bcrypt.hash(password, 10), credits: 50 } });
  //                                                                         ^^^^^^^^^^^^ every fake account = 50 free credits
  return Response.json({ token: signToken(user) });
}
```

No Turnstile, no email-verification-before-credit, no per-IP/device cap. A 20-line loop with throwaway `+tag@gmail.com` or disposable-domain addresses creates thousands of accounts, each carrying your free-tier quota / trial credits / model budget. **MEDIUM.**

**Pattern 2 — referral / credit grant with no anti-self-referral and no gate (referral fraud)**

```python
@app.post("/referral/claim")
def claim(referrer_id: int, new_user_email: str):
    db.add_credit(referrer_id, 10)        # ← grants $10 of value, no human check, no self-refer check
    return {"ok": True}
```

Bot signs up account B with account A's code, A gets credit; repeat 1,000×. There's no check that referrer ≠ referee, no device/fingerprint dedupe, no captcha on the signup that feeds it. This is *money out the door*. **MEDIUM** (lean HIGH only if the credit is directly cashable — then say so plainly and let the founder decide).

**Pattern 3 — checkout / reservation with no bot gate (scalping / inventory hoarding)**

```go
func AddToCart(w http.ResponseWriter, r *http.Request) {
    item := decode(r)
    reserveStock(item.SKU, item.Qty)   // ← holds limited inventory, no proof-of-human
    json.NewEncoder(w).Encode(ok)
}
```

For a limited drop / event tickets / scarce appointments, a bot clears the inventory in seconds and real customers see "sold out." Classic scalping. **MEDIUM.**

**Pattern 4 — there *is* a CAPTCHA widget, but the server never verifies it (the most common false sense of security)**

```ts
// frontend renders <Turnstile />, sends token... and the API ignores it
export async function POST(req: Request) {
  const { email, token } = await req.json();
  // token is never sent to challenges.cloudflare.com/turnstile/v0/siteverify ❌
  await grantReward(email);
}
```

A widget on the page does **nothing** unless the server calls the provider's `siteverify` endpoint with the secret key and *rejects the request on failure*. A bot just omits the token (or sends garbage) and posts straight to the API. **This still counts as unprotected** — flag it. The fix is the missing server check, not a new widget.

**Pattern 5 — vote / review with no one-per-identity rule (vote-stuffing / review-bombing)**

```php
Route::post('/poll/{id}/vote', fn($id) => Vote::create(['option' => request('option')]));
// no "one vote per authenticated user", no device dedupe, no captcha → ballot box stuffed
```

Anyone scripts thousands of votes/reviews, skewing your social proof or burying a competitor. **MEDIUM.**

## The fix: a bot-resistance gate + a per-identity cap on the sensitive step

Two pieces. You usually want both; on a value flow, at minimum one.

**Piece 1 — a human-verification gate, *verified on the server*.** Cloudflare Turnstile is the common free pick (privacy-friendly, no puzzle). The widget alone is not the fix — the server `siteverify` call is:

```ts
// lib/turnstile.ts — server verifies the token; reject on failure
export async function verifyTurnstile(token: string, ip?: string) {
  const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ secret: process.env.TURNSTILE_SECRET!, response: token, ...(ip ? { remoteip: ip } : {}) }),
  });
  const data = await res.json();
  return data.success === true;   // ← gate the value step on THIS
}
```

```ts
// app/api/signup/route.ts
import { verifyTurnstile } from "@/lib/turnstile";

export async function POST(req: Request) {
  const { email, password, turnstileToken } = await req.json();
  const ip = req.headers.get("cf-connecting-ip") ?? undefined;
  if (!(await verifyTurnstile(turnstileToken, ip)))
    return new Response("Bot check failed", { status: 403 });   // ← bots stop here
  // ... existing create-account logic
}
```

> Lictor ships a one-command Turnstile setup — run **`/turnstile-spin`** and it scans the repo, creates the widget via the Cloudflare API, deploys the server-side `siteverify` Worker, and writes the frontend snippet. That's the whole of Piece 1 done for you.

Other stacks, same shape (always verify server-side):
- **Python / FastAPI / Flask / Django:** POST the token to the provider's `siteverify` in a dependency / decorator before the handler runs; 403 on failure.
- **Go:** `http.Post` to `siteverify`, decode `{success bool}`, return 403 if false, before `reserveStock`.
- **Ruby / Rails:** a `before_action :verify_turnstile` that calls `siteverify` and `head :forbidden` on failure.
- **PHP / Laravel:** a `VerifyTurnstile` middleware on the route; reject before the controller.
- **Mobile (Swift / Kotlin / Flutter / React Native):** render the gate in a webview/SDK and send the token, **but the verification still happens on your backend** — never trust a "passed" flag the app sends. The app can be patched; the server is the only judge.

**Piece 2 — a per-account / per-device cap on the value step** (so even a human-passing-the-gate can't farm it):

```ts
// referral: bind value to a verified identity + block self-referral + dedupe by device
if (referrerId === newUserId) return new Response("Self-referral not allowed", { status: 400 });
const already = await db.referral.findFirst({ where: { deviceFingerprint } }); // one reward per device
if (already) return new Response("Reward already claimed", { status: 409 });
```

```ts
// signup: only grant trial credits AFTER email verification, and one trial per verified email/domain
// votes/reviews: a UNIQUE (user_id, poll_id) constraint at the DB layer — the simplest cap there is
```

> **Two backstops worth a sentence to the founder:**
> 1. **Require a verified account on the most-abusable flows** (referral, credit, vote, review). Tying value to a *verified email/phone* turns "infinite fresh identities" into "costs the attacker a real identity each time" — see the api-auth and authn-session checks.
> 2. **Prefer a DB unique constraint over app-level checks** for "one per X" (one vote per user, one reward per device). It can't be raced or forgotten in a code path.

## Report a finding as

**Title:** "Anyone can script your signup flow to farm free credits — there's no bot check"

(adapt to the flow: "Your referral flow can be looped to mint credits," "Your ticket checkout has no bot gate — scalpers can clear inventory," "Your poll can be vote-stuffed by a script.")

**Detail:**
> `app/api/signup/route.ts:4` creates an account and grants `credits: 50` on every request, and there's no human-verification gate (no Turnstile/CAPTCHA, verified server-side) and no per-device or per-verified-email cap anywhere in this flow. A script can create thousands of accounts and walk away with thousands of free credits / trial quota.
>
> **What can go wrong (medium, not a fire):** Nobody steals your data here — instead, someone *farms the thing this flow gives away*. With signup it's free-tier abuse (fake accounts soaking your model budget / free quota). With a referral or credit flow it's straight money out the door (loop a self-referral, mint credits). With checkout it's scalpers clearing a limited drop. With a poll or reviews it's vote-stuffing / review-bombing your social proof. The app keeps "working" the whole time — you just notice the fake-signup graph, the credit leak, or the "sold out in 4 seconds" later. This is OWASP API6: *Unrestricted Access to Sensitive Business Flows*. It's a "add a gate before it bites" item, not an exposed-database emergency.
>
> **How to fix (about 30 minutes):**
> 1. **Add a human-verification gate and verify it on the server.** The widget alone does nothing — your API must POST the token to the provider's `siteverify` and reject on failure. Easiest path: run **`/turnstile-spin`**, which sets up Cloudflare Turnstile end-to-end (widget + server verify Worker + snippet) for free.
> 2. **Add a per-identity cap on the value step.** Only grant trial credits *after* email verification; block self-referral (`referrer !== referee`); add a DB `UNIQUE` constraint for one-vote-per-user / one-reward-per-device.
> 3. **For the most abusable flows (referral, credit, vote), require a verified account** so each abuse costs the attacker a real identity, not a throwaway. (See the api-auth / authn-session checks.)
> 4. Verify after deploy: from a script with no Turnstile token, POST to the flow — it should return `403`, not a created account / granted credit. Then confirm the same email/device can't claim the value twice.

Repeat the report block for each unprotected value flow. Group flows that share one fix (e.g. signup + referral both fixed by the same Turnstile gate); call out a cashable-credit flow separately — it's the one most worth the founder's attention.

## What NOT to flag (false-positive guard)

- **The flow already has a verified bot gate.** If the value step is fronted by Turnstile / hCaptcha / reCAPTCHA **and the server actually verifies the token** (you can see a `siteverify` call / secret key, not just a widget) — it's handled. Note as INFO. *Caveat:* a widget with **no** server-side verify is still a finding (Pattern 4) — the front-end alone protects nothing.
- **The flow requires an authenticated, verified account.** If you must be logged in *and* email/phone-verified to reach the value step, "infinite fresh identities" is already expensive for the attacker. That's an acceptable control on its own for most flows — don't flag. (Login-only, with *open* unverified signup feeding it, is weaker — judge by how cashable the value is.)
- **There's already a per-account / per-device throttle or a `UNIQUE` constraint** bounding how many times one identity can run it (one vote per user, one reward per device, one trial per verified email). That's the cap doing its job — INFO, not a finding.
- **Read-only / no value granted.** Search, browse, view, public feeds, health checks — nothing is minted or sent, so this check doesn't apply. (A missing *rate* limit there belongs to the rate-limiting check, usually at most LOW.)
- **Internal / admin / cron-only flows with no public route.** A reward-grant only callable behind admin auth or by a scheduler has no anonymous bot to gate. Confirm there's genuinely no public path first.
- **Don't double-report with the rate-limiting check.** If you already flagged a route purely for "no request-frequency cap," and the *only* extra worry is volume, don't re-file it here. File *this* check when the issue is specifically **no proof-of-human / no per-identity cap on a value flow** — the mass-abuse angle (farming, scalping, fraud, stuffing), not the speed angle. One clear finding per real problem.
- **Client-side / in-app "are you human?" checks.** A mobile-app or SPA gate that the *app* evaluates and then tells the server "I passed" is not protection — the client can be patched or bypassed with `curl`. Only credit a gate whose verdict is decided **server-side**. Don't let an app-side check downgrade the finding.
- **Keep it medium.** Even a clearly-open value flow is advisory here unless the granted value is *directly cashable* (real money/credits a fraudster can withdraw or resell) — only then consider leaning HIGH, and say exactly why. Default tone: "worth adding a gate," not "you're breached."
