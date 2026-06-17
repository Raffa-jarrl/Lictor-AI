# Check — Unverified webhooks & missing CSRF protection

**What you're looking for:** Two related "trust the sender" bugs. (1) A webhook endpoint — `/api/webhooks/stripe`, `/api/webhooks/github`, a Svix/Clerk receiver — that reads the incoming JSON and acts on it *without checking the signature* that proves it really came from Stripe/GitHub. (2) A state-changing endpoint or form (login, delete-account, change-email, transfer-money) that's authenticated by a cookie and has *no CSRF token* — so another website can make your logged-in users do things without their knowledge.

Both come from the same blind spot: the code trusts that a request arrived means it's legit. The internet doesn't work that way. Anyone can send a request.

## How to scan

### Part A — Webhook endpoints with no signature check

First, find the webhook handlers. Then read each one and confirm a verification call exists.

```bash
# Find webhook route files / handlers across stacks
find . \( -path ./node_modules -o -path ./.next -o -path ./dist -o -path ./vendor -o -path ./.git \) -prune -o \
  -iname '*webhook*' -print 2>/dev/null | head -40

grep -rEin --exclude-dir={node_modules,.next,dist,vendor,.git,build} \
  'webhook|/hooks/|svix|stripe-signature|x-hub-signature|x-signature' \
  . 2>/dev/null | head -40
```

Now, for each handler, check whether it **verifies** the signature. These are the good signs (presence = safe). Their *absence* in a webhook handler is the finding:

```bash
# Verification calls that SHOULD be present in a webhook handler
grep -rEin --exclude-dir={node_modules,.next,dist,vendor,.git,build} \
  'constructEvent|webhooks\.verify|wh\.verify|Webhook\(.*secret|hmac|timingSafeEqual|compare_digest|hmac\.compare|Rack::Utils\.secure_compare|secure_compare|MessageDigest\.isEqual' \
  . 2>/dev/null | head -40
```

**The code smell:** a file matched by the *first* search (it's a webhook) but NOT by the *second* (no verification) — and it does something real with the body (`stripe.subscriptions`, `db.update`, `grantAccess`, `markPaid`, `prisma.user.update`). That's an unverified webhook.

Stack-specific verification calls to recognize:

- **JS/TS – Stripe:** `stripe.webhooks.constructEvent(rawBody, sig, endpointSecret)`
- **JS/TS – Svix/Clerk/Resend/etc.:** `new Webhook(secret).verify(payload, headers)`
- **JS/TS – GitHub/generic HMAC:** `crypto.createHmac('sha256', secret)` + `crypto.timingSafeEqual(...)`
- **Python – Stripe:** `stripe.Webhook.construct_event(payload, sig_header, secret)`
- **Python – generic HMAC:** `hmac.new(secret, body, hashlib.sha256)` + `hmac.compare_digest(...)`
- **Go:** `webhook.ConstructEvent(payload, sigHeader, secret)` (stripe-go) or `hmac.New` + `hmac.Equal`
- **Ruby:** `Stripe::Webhook.construct_event(payload, sig, secret)` or `Rack::Utils.secure_compare`
- **PHP:** `\Stripe\Webhook::constructEvent($payload, $sigHeader, $secret)` or `hash_hmac` + `hash_equals`

⚠️ Two extra things to confirm even when a verify call IS present:

1. **Raw body, not parsed JSON.** Signature checks must run on the exact raw bytes. If the framework already `JSON.parse`d the body (Express `app.use(express.json())` before the webhook route, a Next.js handler that called `await req.json()` first), the signature will either always fail or — worse — the dev "fixed" it by re-serializing, which silently breaks verification. Look for `express.raw(...)`, `bodyParser: false`, or `await req.text()` in the webhook route.
2. **`==` instead of a constant-time compare.** `if (sig == expected)` is a timing-leak. Flag use of `==`/`===`/`.equals()` on a signature where a `timingSafeEqual` / `compare_digest` / `hash_equals` belongs (LOW on its own, but a real smell).

### Part B — State-changing, cookie-authed endpoints with no CSRF protection

CSRF only matters when the browser *automatically* attaches the credential — i.e. **cookie/session auth**. So first figure out how the app authenticates.

```bash
# Is auth cookie/session-based? (CSRF-relevant) — look for these:
grep -rEin --exclude-dir={node_modules,.next,dist,vendor,.git,build} \
  'cookies\(\)|req\.cookies|set-cookie|express-session|cookie-session|iron-session|getServerSession|next-auth|flask_login|session\[|django\.contrib\.sessions|devise|cookie:' \
  . 2>/dev/null | head -40

# Is CSRF protection present anywhere? (its absence in a cookie app is the finding)
grep -rEin --exclude-dir={node_modules,.next,dist,vendor,.git,build} \
  'csrf|csrf_token|csurf|@fastify/csrf|double.?submit|samesite|sameSite|origin.*check|verify.*origin' \
  . 2>/dev/null | head -40
```

Then find the **state-changing** handlers (POST/PUT/PATCH/DELETE) that do something dangerous:

```bash
grep -rEin --exclude-dir={node_modules,.next,dist,vendor,.git,build} \
  -E '(app|router)\.(post|put|patch|delete)|export\s+(async\s+)?function\s+(POST|PUT|PATCH|DELETE)|@(app|router|bp)\.(route|post)|methods=\[.*(POST|PUT|DELETE)' \
  . 2>/dev/null | head -40
```

**The code smell:** the app authenticates with cookies (Part B search 1 hits), there's no CSRF defense anywhere (Part B search 2 empty), and there are POST/DELETE handlers that change account state — delete account, change email/password, post money, invite a teammate, toggle a setting.

Mobile note (Swift/Kotlin/Flutter/React-Native): native mobile apps that talk to your API with a **Bearer token in the `Authorization` header** are *not* CSRF-targets — the browser isn't attaching anything automatically. But many AI-built mobile apps also ship a companion web dashboard that *does* use cookies. Check the web side. And if the mobile app's WebView loads your cookie-authed site (`WKWebView`, `android.webkit.WebView`, `flutter_inappwebview`, RN `react-native-webview`), that WebView shares the cookie jar and IS exposed.

## The dangerous patterns

**Pattern 1: Stripe webhook that trusts the body (CRITICAL)**

```ts
// app/api/webhooks/stripe/route.ts  — NO signature check
export async function POST(req: Request) {
  const event = await req.json();              // ← just parses, never verifies
  if (event.type === "checkout.session.completed") {
    await db.user.update({
      where: { id: event.data.object.metadata.userId },
      data: { plan: "pro", credits: 10000 },   // ← grants paid access
    });
  }
  return new Response("ok");
}
```

Anyone who knows the URL can POST a fake `checkout.session.completed` and get a free Pro account, or fake a `refund` and drain a balance. There's no payment behind it — they just made up the JSON.

**Pattern 2: GitHub/generic HMAC webhook read but never checked (HIGH)**

```python
# trusts the payload; reads the secret header but does nothing with it
@app.route("/webhooks/github", methods=["POST"])
def github_hook():
    payload = request.get_json()
    sig = request.headers.get("X-Hub-Signature-256")   # ← read, then ignored
    deploy(payload["ref"])                              # ← triggers a deploy
    return "ok"
```

A spoofed push event triggers an arbitrary deploy. The header is read but never compared — a classic "looks secure, isn't."

**Pattern 3: Cookie-authed account change with no CSRF token (HIGH)**

```ts
// uses the session cookie; no CSRF token, no Origin check
export async function POST(req: Request) {
  const session = await getServerSession();          // ← cookie auth ✓
  const { newEmail } = await req.json();
  await db.user.update({ where: { id: session.user.id }, data: { email: newEmail }});
  return Response.json({ ok: true });
}
```

A logged-in user visits `evil.com`. A hidden form there auto-submits `POST https://yourapp.com/api/change-email` with `newEmail=attacker@evil.com`. The browser attaches your user's session cookie automatically. Their account email is now the attacker's — who then does a password reset and owns the account.

## Safe patterns

**Webhook — verify on the raw body, constant-time:**

```ts
// app/api/webhooks/stripe/route.ts (Next.js App Router reads raw body by default)
import Stripe from "stripe";
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

export async function POST(req: Request) {
  const body = await req.text();                       // ← RAW bytes, not .json()
  const sig = req.headers.get("stripe-signature")!;
  let event;
  try {
    event = stripe.webhooks.constructEvent(body, sig, process.env.STRIPE_WEBHOOK_SECRET!);
  } catch {
    return new Response("Bad signature", { status: 400 });  // ← reject unsigned/forged
  }
  // ...now it's safe to act on event...
  return new Response("ok");
}
```

**CSRF — pick one. SameSite cookies are the easiest "fix tonight":**

```ts
// Most cookie frameworks: set the session cookie SameSite=Lax (or Strict).
// This alone blocks the cross-site auto-submit in every modern browser.
cookies().set("session", token, {
  httpOnly: true,
  secure: true,
  sameSite: "lax",   // ← cross-site POSTs no longer carry the cookie
  path: "/",
});
```

For the belt-and-suspenders version, add a CSRF token (`csurf`, `@fastify/csrf-protection`, the framework's built-in — Django/Rails/Laravel ship it on by default) or verify the `Origin`/`Sec-Fetch-Site` header on state-changing routes.

## Report a finding as

**Title (webhook):** "Your Stripe webhook trusts anyone who knows the URL"

**Detail:**
> `app/api/webhooks/stripe/route.ts:3` reads the incoming request body with `await req.json()` and acts on it — it upgrades a user to the Pro plan when it sees a `checkout.session.completed` event. But it never checks the Stripe signature. Stripe signs every webhook so you can prove the message really came from Stripe. Without that check, the endpoint believes anyone.
>
> **What can go wrong:** Your webhook URL isn't secret — it shows up in browser network tabs, in logs, sometimes in your public repo. Someone POSTs a hand-written `checkout.session.completed` JSON to it and gets a free Pro account. Do it for `invoice.payment_succeeded` and they top up a balance that no card ever paid for. You find out when your Stripe dashboard and your app's "paid users" don't match.
>
> **How to fix tonight (10 minutes):**
> 1. Read the raw body and verify the signature before doing anything:
>    ```ts
>    const body = await req.text();
>    const sig = req.headers.get("stripe-signature")!;
>    let event;
>    try {
>      event = stripe.webhooks.constructEvent(body, sig, process.env.STRIPE_WEBHOOK_SECRET!);
>    } catch {
>      return new Response("Bad signature", { status: 400 });
>    }
>    ```
> 2. Get `STRIPE_WEBHOOK_SECRET` from the Stripe dashboard → Developers → Webhooks → your endpoint → "Signing secret" (starts `whsec_`). Put it in your env, not in code.
> 3. Make sure no JSON body-parser runs before this route (Express: mount `express.raw({type:'application/json'})` on the webhook path only). The signature is checked against the *exact bytes* Stripe sent — re-parsed JSON won't match.
> 4. Verify: replay a real event from the Stripe dashboard ("Send test webhook") → 200. POST junk with `curl` → 400.
>
> Same pattern for GitHub (`X-Hub-Signature-256` + HMAC-SHA256 + `crypto.timingSafeEqual`), Svix/Clerk (`new Webhook(secret).verify(body, headers)`), and any other provider.

**Title (CSRF):** "Another website can change your users' email behind their back"

**Detail:**
> `app/api/change-email/route.ts:5` lets a logged-in user change their account email. It's authenticated by the session cookie, which is correct — but there's no CSRF protection, and your session cookie isn't set `SameSite`. That combination means *another website* can trigger this action for any user who's logged into your app.
>
> **What can go wrong:** Your user is logged in and browsing the web. They land on a page an attacker controls (an ad, a forum post, a phishing link). That page silently submits a form to `yourapp.com/api/change-email` with the attacker's address. The browser attaches your user's session cookie automatically — it always does, for any request to your domain — so your server thinks the user asked for it. The email changes. The attacker requests a password reset to their own inbox and takes over the account. The user did nothing but visit a webpage.
>
> **How to fix tonight (5 minutes):**
> 1. Set your session cookie `SameSite=Lax` (or `Strict`). This alone stops the cross-site auto-submit in every current browser:
>    ```ts
>    cookies().set("session", token, { httpOnly: true, secure: true, sameSite: "lax", path: "/" });
>    ```
> 2. If you use NextAuth/Auth.js, Clerk, Supabase Auth, Django, Rails, or Laravel, this is usually one config line (or already the default) — check your auth config rather than hand-rolling.
> 3. For extra safety on money/account-critical routes, also verify the request `Origin` header matches your own domain, or add a CSRF token (`csurf`, `@fastify/csrf-protection`).
> 4. Verify: from a different site's console, try `fetch("https://yourapp.com/api/change-email",{method:"POST",credentials:"include",body:...})`. With `SameSite=Lax` the cookie won't ride along and the call fails the auth check.

## Don't false-positive on

- **Webhook handlers that DO verify.** If you see `constructEvent`, `Webhook(secret).verify`, `hmac` + `timingSafeEqual`/`compare_digest`/`hash_equals` in the handler, it's fine. Don't flag a verified webhook.
- **Token/Bearer APIs (no cookies) for CSRF.** If the app authenticates *only* with `Authorization: Bearer <token>` from a header the client sets explicitly — typical for SPAs and mobile apps — CSRF doesn't apply. The browser doesn't auto-attach header tokens. Don't flag these. (Re-confirm there's no cookie session hiding alongside it.)
- **Cookies already `SameSite=Strict`/`Lax`.** That's the mitigation. If the session cookie is set strict/lax, the cross-site auto-submit is already blocked — note it as handled, not a finding. (Caveat: `SameSite=None` is *not* protection — flag that.)
- **GET endpoints and read-only routes.** CSRF is about *state-changing* requests. A `GET /api/me` doesn't need a CSRF token. Only flag POST/PUT/PATCH/DELETE that actually mutate something.
- **Frameworks with CSRF on by default that haven't disabled it.** Django, Rails, Laravel, and SvelteKit form actions ship CSRF protection enabled. Don't flag them unless you can see it was explicitly turned off (`@csrf_exempt`, `skip_before_action :verify_authenticity_token`, `VerifyCsrfToken` excluded, `csrf: false`).
- **Local/dev webhook stubs and test fixtures.** A mock webhook in `__tests__/`, `*.test.*`, or a `scripts/` seeding file isn't your production endpoint. Note it, don't alarm.
- **Native mobile apps using header-based tokens.** A Swift/Kotlin/Flutter/RN app sending a Bearer token isn't a CSRF target. Only the cookie-authed web companion (or a cookie-sharing WebView) is.
