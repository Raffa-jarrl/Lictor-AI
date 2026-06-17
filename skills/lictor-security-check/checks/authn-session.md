# Check — Broken logins, busted tokens, and the "trust me" admin door

**What you're looking for:** the login and session machinery itself being soft. Four flavors, all common in AI-built apps:

1. **Routes that change things with no login check at all** — not just "list" endpoints (that's `api-auth.md`), but the `POST /api/transfer`, `DELETE /api/account`, `POST /api/admin/refund` mutations that anyone can fire.
2. **JWTs that aren't really verified** — tokens that are `decode()`'d instead of `verify()`'d, accept `alg: none`, have no expiry, or are signed with a secret that's sitting in the client bundle.
3. **Weak or guessable sessions** — session IDs built from `Math.random()`, a counter, the user's email, or a timestamp; sessions that never expire.
4. **Default or hardcoded credentials** — `admin/admin`, a `MASTER_PASSWORD = "..."` constant, an "if email === 'me@founder.com' you're an admin" backdoor left in from testing.

The thread tying these together: the app *has* a lock, but the lock is fake, the key is printed on the door, or the door only locks the front (the GET) and leaves the back (the POST) wide open.

## How to scan

Auth logic lives in middleware, route handlers, an `auth/`, `lib/auth`, or `utils/session` folder, and mobile keychain/token code. Cast a wide net across stacks.

### Find the login / token / session code

```bash
# JS/TS — the libraries and homerolled bits
grep -rEn --exclude-dir={node_modules,.next,dist,build,.git} \
  -E 'jwt\.(sign|verify|decode)|jsonwebtoken|jose|express-session|cookie-session|iron-session|next-auth|lucia|bcrypt|argon2|scrypt' \
  . 2>/dev/null | head -40

# Python (Flask/Django/FastAPI)
grep -rEn --include='*.py' --exclude-dir={venv,.venv,__pycache__,site-packages} \
  -E 'jwt\.(encode|decode)|PyJWT|flask_jwt|SECRET_KEY|SESSION_COOKIE|check_password|set_password|@login_required|Depends\(' \
  . 2>/dev/null | head -40

# Go
grep -rEn --include='*.go' \
  -E 'jwt\.(Parse|ParseWithClaims|NewWithClaims)|SigningMethodNone|gorilla/sessions|bcrypt\.' \
  . 2>/dev/null | head -40

# Ruby (Rails / Sinatra)
grep -rEn --include='*.rb' --exclude-dir={vendor,tmp} \
  -E 'JWT\.(encode|decode)|before_action|authenticate_user|has_secure_password|devise|session\[' \
  . 2>/dev/null | head -40

# PHP (Laravel / plain)
grep -rEn --include='*.php' --exclude-dir={vendor} \
  -E 'JWT::(decode|encode)|firebase/php-jwt|password_(hash|verify)|\$_SESSION|Auth::|middleware\(' \
  . 2>/dev/null | head -40

# Mobile — Swift / Kotlin / Flutter / React Native
grep -rEn --include='*.swift' --include='*.kt' --include='*.java' \
  --include='*.dart' --include='*.ts' --include='*.tsx' \
  -E 'JWT|jwt_decode|jwtDecode|Keychain|SharedPreferences|EncryptedSharedPreferences|flutter_secure_storage|AsyncStorage|SecureStore|UserDefaults' \
  . 2>/dev/null | head -40
```

### Find state-changing routes (the ones that MUST be locked)

```bash
# JS/TS — POST/PUT/PATCH/DELETE handlers
grep -rEn --include='*.ts' --include='*.js' --exclude-dir={node_modules,.next,dist} \
  -E '(app|router)\.(post|put|patch|delete)\(|export\s+(async\s+)?function\s+(POST|PUT|PATCH|DELETE)' \
  . 2>/dev/null | head -40

# Python
grep -rEn --include='*.py' --exclude-dir={venv,.venv} \
  -E '@(app|router|bp)\.(post|put|patch|delete)|methods=\[.*(POST|PUT|PATCH|DELETE)' \
  . 2>/dev/null | head -40

# Go / Ruby / PHP routers
grep -rEn --include='*.go' --include='*.rb' --include='*.php' \
  -E '\.(POST|PUT|PATCH|DELETE)\(|(post|put|patch|delete)\s+[\x27"]/|Route::(post|put|patch|delete)' \
  . 2>/dev/null | head -40
```

For each one, read the handler. If a `POST /api/...` mutates data (writes to a DB, charges a card, deletes a record, changes a role) and there's **no session/token check before the mutation**, that's a finding — even if the matching `GET` is locked. Attackers don't use your UI; they `curl` the `POST` directly.

### Sniff for the specific smells

```bash
# alg:none and unverified decode (JS/TS/Python/Go/Ruby/PHP)
grep -rEn --exclude-dir={node_modules,.next,dist,vendor,venv,.venv} \
  -E "alg(orithm)?['\"]?\s*[:=]\s*['\"]?none|algorithms\s*=\s*\[\s*['\"]none|jwt\.decode\(|jwtDecode\(|jwt_decode\(|SigningMethodNone|verify_signature['\"]?\s*[:=]\s*(False|false)" \
  . 2>/dev/null

# JWT signed/verified with no expiry set (no exp / expiresIn)
grep -rEn --exclude-dir={node_modules,.next,dist,vendor,venv,.venv} \
  -E 'jwt\.sign\(|jwt\.encode\(|NewWithClaims|JWT\.encode' \
  . 2>/dev/null | head -30   # then read each: is expiresIn / exp / setExpirationTime present?

# Guessable session/token generation
grep -rEn --exclude-dir={node_modules,.next,dist,vendor,venv,.venv} \
  -E 'Math\.random\(\)|Date\.now\(\)\s*\+|sessionId\s*=|token\s*=\s*.*(email|username|userId|\+\+|counter)|uuid\.uuid1\(|new Random\(' \
  . 2>/dev/null | head -30

# Default / hardcoded creds and backdoors
grep -rEn --exclude-dir={node_modules,.next,dist,vendor,venv,.venv} \
  -E "(password|passwd|pwd|secret|master).{0,12}['\"](admin|password|123456|changeme|root|test)['\"]|==\s*['\"]admin['\"]|isAdmin\s*=\s*true|email\s*===?\s*['\"][^'\"]+@" \
  . 2>/dev/null | head -30
```

## What to report — the four stories

### Story 1 — The unlocked back door (mutation with no auth)

```ts
// app/api/account/route.ts
export async function DELETE(req: Request) {
  const { userId } = await req.json();
  await db.user.delete({ where: { id: userId } });   // ← no session check
  return Response.json({ ok: true });
}
```

**Here's what goes wrong:** Your UI only shows the "delete account" button to logged-in users, so it *feels* protected. But the endpoint takes a `userId` from the request body and there's no check that you're logged in — let alone that you're allowed to delete *that* user. Anyone runs `curl -X DELETE yourapp.com/api/account -d '{"userId":"any-id"}'` and starts deleting accounts one by one. Same shape gives you free refunds (`/api/admin/refund`), free credits, role changes, password resets for other people.

**Severity: 🔴 CRITICAL** for money/account/role mutations; 🟠 HIGH for lower-stakes writes.

**Fix tonight:**
```ts
import { auth } from "@/lib/auth";

export async function DELETE(req: Request) {
  const session = await auth();
  if (!session) return new Response("Unauthorized", { status: 401 });

  // Don't trust a userId from the body — use the session's own id.
  await db.user.delete({ where: { id: session.user.id } });
  return Response.json({ ok: true });
}
```
The rule: every POST/PUT/PATCH/DELETE checks the session *before* it touches data, and derives "who am I acting as" from the **session**, never from the request body. Do all of them in one pass.

### Story 2 — The token that isn't really checked

```js
// "verifying" a login token — but not really
const payload = jwt.decode(token);          // ← decode, not verify
if (payload.userId) { /* you're in */ }
```
or
```python
jwt.decode(token, options={"verify_signature": False})   # ← signature off
```
or
```go
token, _ := jwt.Parse(raw, func(t *jwt.Token) (interface{}, error) {
    return nil, nil   // ← returns no key; accepts alg:none
})
```

**Here's what goes wrong:** A JWT is just base64 — `decode()` reads it without checking the signature. An attacker takes their own valid token, edits the middle (`{"userId":"me"}` → `{"userId":"the-founder","role":"admin"}`), and your app believes it because it never checked the signature. The `alg: none` trick is the same idea: the attacker sets the token's algorithm to "none," strips the signature, and a loose verifier accepts it. Result: log in as anyone, become admin at will.

**Severity: 🔴 CRITICAL.** This is full account takeover.

**Fix tonight** — always `verify` with an explicit algorithm allowlist:
```js
// JS/TS (jsonwebtoken)
const payload = jwt.verify(token, process.env.JWT_SECRET, {
  algorithms: ["HS256"],   // pin it; never allow "none"
});
```
```python
# Python (PyJWT)
payload = jwt.decode(token, SECRET, algorithms=["HS256"])  # signature ON, alg pinned
```
```go
// Go (golang-jwt) — reject unexpected signing methods
token, err := jwt.Parse(raw, func(t *jwt.Token) (interface{}, error) {
    if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
        return nil, fmt.Errorf("unexpected signing method")
    }
    return []byte(os.Getenv("JWT_SECRET")), nil
})
```

### Story 3 — Tokens with no expiry, or a secret living in the client

```js
const token = jwt.sign({ userId }, SECRET);   // ← no expiresIn → lives forever
```
```ts
// next.config / client bundle
const JWT_SECRET = "supersecret123";   // ← shipped to the browser
```

**Here's what goes wrong (no expiry):** a token captured once — from a shared computer, a leaked log, an old screenshot — works *forever*. There's no logout that actually invalidates it, no window that closes. **(secret in client):** if the signing secret is in any file that ends up in the browser bundle or a mobile app's binary, an attacker extracts it and signs their own valid tokens for any user. The lock is real, but the master key is taped to the door.

**Severity: 🟠 HIGH** for missing expiry; **🔴 CRITICAL** for a signing secret in the client/app bundle.

**Fix tonight:**
```js
const token = jwt.sign({ userId }, process.env.JWT_SECRET, {
  expiresIn: "1h",          // short-lived; pair with a refresh token
});
```
- Signing/verifying happens **only on the server**. The client gets the token, never the secret.
- Mobile: never embed a signing secret in the app. Apps are trivially decompiled. The server signs; the device only stores the issued token (in Keychain / EncryptedSharedPreferences / `flutter_secure_storage` / Expo `SecureStore` — not in `UserDefaults`, plain `SharedPreferences`, or `AsyncStorage`).

### Story 4 — Guessable sessions and default credentials

```js
const sessionId = Math.random().toString(36).slice(2);   // ← guessable
// or
sessions[userEmail] = true;                              // ← session = the email
```
```python
if username == "admin" and password == "admin":          # ← default creds
    login()
```
```php
if ($email === "founder@me.com") { $_SESSION['admin'] = true; }  // ← test backdoor
```

**Here's what goes wrong:** `Math.random()` isn't cryptographically random — with enough samples its output is predictable, so an attacker can forge a valid session ID and ride into someone's account. A session keyed on the email means guessing the email *is* logging in. And the `admin/admin` or "if it's my email, I'm admin" lines are the kind of thing that gets pasted in during testing and shipped to prod — the first thing anyone tries.

**Severity: 🔴 CRITICAL** for default/hardcoded creds and email-as-session; **🟠 HIGH** for `Math.random()` session IDs.

**Fix tonight:**
```js
import crypto from "node:crypto";
const sessionId = crypto.randomBytes(32).toString("hex");   // CSPRNG, unguessable
```
- Delete every default/hardcoded credential and every `if email === "..."` admin shortcut. Admin status comes from a real `role` column in the database, set deliberately — never from a string compare in code.
- Better: don't hand-roll sessions at all. Use a vetted library — NextAuth/Auth.js, Lucia, `iron-session` (JS); Devise (Rails); Django's built-in auth; Laravel Breeze/Sanctum (PHP). They get the random-ID, hashing, and expiry right for you.
- Passwords are stored hashed with bcrypt/argon2/scrypt — never plaintext, never MD5/SHA1.

## What NOT to flag (false-positive guards — read this before reporting)

- **Genuinely public mutations.** `POST /api/contact`, `POST /api/newsletter/subscribe`, `POST /api/waitlist`, anonymous analytics beacons — these are *meant* to be open. They need rate-limiting and spam protection, not a login. Note as INFO at most.
- **Webhooks.** `POST /api/webhooks/stripe`, `/api/webhooks/github` — these are authenticated by **signature verification** (`stripe.webhooks.constructEvent`, an HMAC compare), not a session. If you see a signature check, it's fine.
- **The login and signup routes themselves.** `POST /api/login`, `/api/register`, `/api/auth/*`, password-reset *request* endpoints — these are unauthenticated by definition. That's correct.
- **Public/publishable keys are not secrets.** `pk_live_…` (Stripe), `NEXT_PUBLIC_*` / `VITE_*` / `EXPO_PUBLIC_*` / Firebase web config, Supabase **anon** key — these are *designed* to ship to the client. A JWT *signing secret* in the client is the bug; a publishable key is not. (See the Secrets check for the key-type table.)
- **`jwt.decode()` used for non-security reads.** Decoding a token just to read a non-sensitive claim for display (e.g. show the user's name) *after* it's already been `verify`'d elsewhere, or decoding your own freshly-minted token, is fine. The bug is decode-*instead-of*-verify on the trust path. Check whether a real `verify` happens before any access decision.
- **`alg: none` in test fixtures, library docs, or a comment** — not in the live verification path. Confirm it's reachable code.
- **`Math.random()` for non-security things** — animation jitter, a random tip, picking a placeholder color, cache-busting. Only flag it when the output becomes a session ID, token, password-reset code, or anything an attacker would want to guess.
- **`admin`/`test` strings in seed scripts, fixtures, or `.env.example`** — a `seed.ts` that creates a dev admin with a known password is normal *as long as it doesn't run in production*. Flag it only if it's reachable in the prod code path or the seeded creds aren't changed on deploy.
- **Framework-managed session cookies.** If they're using NextAuth, Django, Devise, Laravel, etc., the session ID, expiry, and hashing are handled correctly by the library — don't flag the framework's own cookie as "guessable."

## Report a finding as

**Title:** be specific to the flavor you found, e.g.
- "`DELETE /api/account` deletes any user with no login check"
- "Login tokens are read with `jwt.decode()` — the signature is never checked"
- "JWT signing secret is shipped to the browser in `lib/auth.ts:6`"
- "Admin access granted by a hardcoded `admin/admin` login in `routes/auth.py:22`"

**Detail (example for the unverified-token case):**
> `src/lib/auth.ts:31` reads the login token with `jwt.decode(token)` and trusts the `userId` inside it. `decode()` only un-base64s the token — it never checks the signature. A JWT is three base64 chunks separated by dots, and the middle chunk is the data. Anyone can take their own valid token, change the middle chunk to say `"userId":"your-founder-account"` or `"role":"admin"`, and your app will believe it, because nothing verified that you signed it.
>
> **What can go wrong:** A curious user (or a researcher poking at launch) edits one field in their own token and is suddenly logged in as you, or as any customer. Full account takeover, no password needed. This is one of the most-exploited bugs in hand-rolled auth.
>
> **How to fix tonight (10 minutes):**
> 1. Change `jwt.decode` to `jwt.verify` with a pinned algorithm:
>    ```ts
>    const payload = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ["HS256"] });
>    ```
> 2. Make sure `JWT_SECRET` is a long random server-side env var (`openssl rand -hex 32`), not a short literal and not anything that ships to the client.
> 3. Add `expiresIn: "1h"` everywhere you `jwt.sign`, so a stolen token doesn't live forever.
> 4. Verify: take a valid token, change one character in the middle chunk, and send it. The app must now reject it (401), not log you in.

Repeat the report block for each flavor you found. If you spot default/hardcoded credentials, add the standing line: *"Even if you do nothing else from this audit: remove this and the equivalent of `admin/admin` before you deploy — it's the first thing anyone tries."*
