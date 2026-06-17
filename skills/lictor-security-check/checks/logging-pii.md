# Check — Secrets & personal data leaking through logs and error messages

**What you're looking for:** Three related habits that all leak sensitive data without anyone noticing. (1) Code that logs the actual secret — `console.log("token:", token)` — so your API keys and your users' passwords end up in plaintext in your hosting dashboard. (2) Error handlers that send the raw crash — the full stack trace, the SQL query, the database error — back to the browser, handing an attacker a map of your internals. (3) PII (emails, names, phone numbers, card numbers, auth tokens) written into log lines or piped to analytics, where it sits forever in a place you didn't lock down. None of these throw an error. Everything still works. That's exactly why they ship.

## How to scan

This bug lives wherever the code logs, catches, or responds. Cast a wide net across stacks, then read the hits in context.

```bash
# --- JS / TS: logging things that smell like secrets ---
grep -rEn --include='*.ts' --include='*.js' --include='*.tsx' --include='*.jsx' \
  --exclude-dir={node_modules,.next,dist,build,coverage} \
  -E "(console\.(log|info|debug|warn|error)|logger\.(log|info|debug|warn|error))\b.*(token|password|passwd|secret|api[_-]?key|apikey|authorization|bearer|cookie|session|credit[_-]?card|ssn|jwt|refresh[_-]?token)" \
  . 2>/dev/null | head -40

# --- JS / TS: logging whole request/user objects (PII firehose) ---
grep -rEn --include='*.ts' --include='*.js' --include='*.tsx' --include='*.jsx' \
  --exclude-dir={node_modules,.next,dist,build} \
  -E "console\.(log|info|debug)\s*\(\s*(req|request|body|headers|user|payload|event)\b" \
  . 2>/dev/null | head -40

# --- JS / TS: error handlers that ship the raw error to the client ---
grep -rEn --include='*.ts' --include='*.js' --include='*.tsx' --include='*.jsx' \
  --exclude-dir={node_modules,.next,dist,build} \
  -E "(res\.(send|json|status\([0-9]+\)\.(send|json))|Response\.json|new Response)\s*\(\s*\{?[^)]*\b(err|error|e)\b(\.message|\.stack|\.toString\(\))?" \
  . 2>/dev/null | head -40

# --- Python: logging secrets + returning the exception to the client ---
grep -rEn --include='*.py' --exclude-dir={venv,.venv,__pycache__,site-packages} \
  -E "(print|logging\.(debug|info|warning|error|exception)|logger\.(debug|info|warning|error|exception))\(.*(token|password|secret|api_?key|authorization|bearer|cookie|session|ssn|jwt)" \
  . 2>/dev/null | head -40
grep -rEn --include='*.py' --exclude-dir={venv,.venv,__pycache__,site-packages} \
  -E "(return|jsonify|JsonResponse|HttpResponse|abort)\(.*(str\(e\)|traceback|repr\(e\)|exc|\.message)" \
  . 2>/dev/null | head -40
# Flask/Django leaving debug ON in prod = full traceback page to every visitor
grep -rEn --include='*.py' --exclude-dir={venv,.venv,__pycache__} \
  -E "(DEBUG\s*=\s*True|debug\s*=\s*True|app\.run\([^)]*debug\s*=\s*True)" . 2>/dev/null

# --- Go: logging secrets + writing err straight to the response ---
grep -rEn --include='*.go' \
  -E "(log\.(Print|Printf|Println|Fatal)|fmt\.(Print|Printf|Println)).*(token|password|secret|apiKey|api_key|authorization|bearer|cookie|session)" \
  . 2>/dev/null | head -40
grep -rEn --include='*.go' \
  -E "http\.Error\(w,\s*err\.Error\(\)|fmt\.Fprintf?\(w,.*err" . 2>/dev/null | head -40

# --- Ruby / Rails ---
grep -rEn --include='*.rb' --exclude-dir={vendor,tmp} \
  -E "(Rails\.logger\.(debug|info|warn|error)|logger\.(debug|info|warn|error)|puts|p\s)\b.*(token|password|secret|api_?key|authorization|bearer|session)" \
  . 2>/dev/null | head -40
grep -rEn --include='*.rb' -E "render\b.*(:?json|:?plain).*=>?.*(e\.message|exception|backtrace)" . 2>/dev/null

# --- PHP ---
grep -rEn --include='*.php' --exclude-dir={vendor} \
  -E "(error_log|var_dump|print_r|echo|\\\$log->).*(token|password|secret|api_?key|authorization|bearer|session)" \
  . 2>/dev/null | head -40
grep -rEn --include='*.php' --exclude-dir={vendor} \
  -E "(echo|print|die|throw).*(getMessage\(\)|getTraceAsString\(\)|\\\$e\b)" . 2>/dev/null | head -40
grep -rEn --include='*.php' -E "display_errors\s*=\s*On|ini_set\('display_errors'\s*,\s*'?1" . 2>/dev/null

# --- Mobile: Swift / Kotlin / Flutter / React Native ---
grep -rEn --include='*.swift' \
  -E "(print|NSLog|os_log|debugPrint)\(.*(token|password|secret|apiKey|authorization|bearer|jwt)" \
  . 2>/dev/null | head -40
grep -rEn --include='*.kt' --include='*.java' \
  -E "(Log\.(d|v|i|w|e)|System\.out\.print(ln)?|println)\(.*(token|password|secret|apiKey|api_key|authorization|bearer|jwt)" \
  . 2>/dev/null | head -40
grep -rEn --include='*.dart' \
  -E "(print|debugPrint|log)\(.*(token|password|secret|apiKey|authorization|bearer|jwt)" \
  . 2>/dev/null | head -40
# React Native: console.* survives into production bundles unless stripped
grep -rEn --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  --exclude-dir={node_modules} \
  -E "console\.(log|debug|warn)\(.*(token|password|secret|apiKey|authorization|bearer|jwt)" \
  . 2>/dev/null | head -40

# --- Analytics SDKs fed raw PII (any stack) ---
grep -rEn --exclude-dir={node_modules,vendor,venv,.venv,dist,build} \
  -E "(analytics\.(track|identify|page)|mixpanel\.(track|identify)|posthog\.(capture|identify)|amplitude\.(logEvent|setUserId)|Sentry\.(captureException|setUser|setContext)|gtag|datadogLogs)\b" \
  . 2>/dev/null | head -40
```

## The dangerous patterns

**Pattern 1: logging the secret itself (very common, very quiet)**

```ts
// JS/TS — these strings land in your Vercel/Render/Railway log stream in plaintext
console.log("Incoming request headers:", req.headers);   // ← includes Authorization + Cookie
console.log("Stripe key:", process.env.STRIPE_SECRET_KEY); // ← a "did the env var load?" debug line, never removed
logger.info(`User login: ${email} / ${password}`);         // ← plaintext password in logs forever
```

```python
# Python — a "let me check what's coming in" line that survived to production
logging.info(f"Auth attempt: {request.headers}")           # ← Authorization header
print("DB url:", DATABASE_URL)                              # ← connection string w/ password
```

```swift
// Swift — survives into device/console logs and crash reporters
print("JWT for \(user.email): \(authToken)")
```

Why it's bad: your hosting provider's log viewer, your log-aggregation tool (Datadog, Logtail, CloudWatch), and anyone with read access to either now has your live secret or your user's password. Logs get shared in support tickets, get indexed, get retained for months, and almost never get the same access controls as your database. A leaked `STRIPE_SECRET_KEY` in a log line is the same emergency as one hardcoded in the source — see the Secrets check; this one is just hiding in the log stream instead of the repo. **HIGH** (🟠), or **CRITICAL** (🔴) if it's a live payment/cloud key or a user password being logged.

**Pattern 2: returning the raw error / stack trace to the client (REAL recon for an attacker)**

```ts
// Next.js / Express — the catch block that "just shows what went wrong"
} catch (err) {
  return Response.json({ error: err.message, stack: err.stack }, { status: 500 }); // ← ships internals
}
```

```python
# Flask — debug=True turns every 500 into an interactive traceback page
app.run(debug=True)              # ← strangers can read your source + run a console
# or, by hand:
except Exception as e:
    return jsonify({"error": str(e)}), 500   # ← leaks the DB error text, table names, SQL
```

```go
http.Error(w, err.Error(), 500)  // ← err.Error() can be the full pq/SQL driver message
```

What goes wrong: the error text is a free map. A database error leaks your table and column names. A file error leaks your server paths (`/home/deploy/app/...`). A stack trace leaks your framework versions and your internal module layout. An attacker probing your app reads these to plan the next attack — it's the difference between guessing in the dark and being handed the blueprint. **HIGH** (🟠). Flask/Django `DEBUG=True` in production is **CRITICAL** (🔴) — the debug page often exposes environment variables and an interactive code console to the public.

**Pattern 3: PII in log lines and analytics events**

```ts
// The whole user object gets logged on every request...
console.log("order placed", { user, card: order.card, address: order.shipping });
// ...or piped straight into analytics, where it's now in a third party's store
analytics.identify(user.id, { email, phone, dob, ssn: user.ssn }); // ← PII off to a vendor
Sentry.captureException(err, { extra: { requestBody } });          // ← body may contain passwords/cards
```

```python
logger.info("Checkout: %s", order.to_dict())   # ← name, address, card last4, email — all in logs
```

What goes wrong: this is the quiet GDPR/privacy problem. Personal data ends up somewhere you never threat-modeled — your log retention store, a third-party analytics vendor, an error-tracker that screenshots request bodies. When (not if) one of those is breached or over-shared, you're now the one explaining to users why their home address was in a log file, and to a regulator why PII was being shipped to a vendor without a data agreement. **MEDIUM** (🟡), rising to **HIGH** (🟠) when it's card numbers, government IDs, health data, or auth tokens.

## Safe patterns

Log the event, never the secret. Redact known sensitive fields. Send the user a generic message while logging the real error server-side under an ID.

```ts
// 1) Log that something happened — not the secret
console.log("stripe key loaded:", Boolean(process.env.STRIPE_SECRET_KEY)); // true/false, not the value
logger.info("login attempt", { email, success });                          // no password field

// 2) Redact before logging an object you don't fully control
const SENSITIVE = new Set(["password","token","authorization","cookie","apiKey","ssn","card"]);
const redact = (o: Record<string, unknown>) =>
  Object.fromEntries(Object.entries(o).map(([k, v]) =>
    [k, SENSITIVE.has(k.toLowerCase()) ? "[redacted]" : v]));
console.log("request body", redact(body));

// 3) Generic error to the client, real error to your server logs under an id
} catch (err) {
  const id = crypto.randomUUID();
  console.error(`[${id}]`, err);                       // full detail stays server-side
  return Response.json({ error: "Something went wrong", id }, { status: 500 });
}
```

```python
# Python — never run with debug on in production; return a generic message
app.run(debug=False)
except Exception:
    log_id = uuid4().hex
    app.logger.exception("request failed id=%s", log_id)   # full traceback in server log only
    return jsonify({"error": "Something went wrong", "id": log_id}), 500
```

For analytics: send IDs and non-identifying attributes, never raw PII; if you must, hash the email (`sha256`) so the vendor can't read it.

## Report a finding as

**Title:** "Your app is writing user passwords (and a Stripe key) into the logs"

(adapt the title to whichever of the three patterns you found — "logs your secret keys", "shows the raw crash to visitors", or "sends customer personal data into your logs/analytics")

**Detail:**
> `src/app/api/login/route.ts:22` runs `logger.info(\`User login: ${email} / ${password}\`)`, and `src/lib/stripe.ts:5` runs `console.log("Stripe key:", process.env.STRIPE_SECRET_KEY)`. Both look harmless — the app still works — but every one of those lines is now sitting in plaintext in your hosting dashboard's log viewer (Vercel, Render, Railway, CloudWatch — wherever you deploy).
>
> **What can go wrong:** Logs are the least-locked-down place in your whole stack. You'll paste a log snippet into a support chat to debug something, or give a contractor read access to your dashboard, or your log tool gets breached — and now your live Stripe key and a pile of real user passwords are out. The Stripe key alone lets someone issue refunds and read your customers. The passwords are worse: people reuse them, so a leak here becomes a leak everywhere your users have accounts.
>
> Separately, `src/app/api/orders/route.ts:40` does `return Response.json({ error: err.message, stack: err.stack })` in its catch block. When something breaks, the visitor's browser receives your full stack trace — your file paths, your database error text, your framework versions. That's a free blueprint for anyone poking at your app.
>
> **What to do tonight:**
> 1. Delete the secret/password log lines. If you were using one to check an env var loaded, log a boolean instead:
>    ```ts
>    console.log("stripe key loaded:", Boolean(process.env.STRIPE_SECRET_KEY));
>    logger.info("login attempt", { email, success });  // never log the password
>    ```
> 2. Make error responses generic, and keep the detail server-side under an id:
>    ```ts
>    } catch (err) {
>      const id = crypto.randomUUID();
>      console.error(`[${id}]`, err);     // full error stays in your logs
>      return Response.json({ error: "Something went wrong", id }, { status: 500 });
>    }
>    ```
>    (On Flask/Django, also confirm `DEBUG = False` in production — debug mode shows a public traceback page with a live code console.)
> 3. For anything that logs a whole object (`req`, `body`, `user`) or sends it to analytics/Sentry, redact the sensitive keys first (see the redact helper above), and send analytics only IDs + non-identifying fields — never raw email, phone, card, or SSN.
> 4. Because a live key was in your logs, treat it as exposed: rotate it. Run `/lictor-rotate` and I'll walk you through it provider by provider.
> 5. Verify: trigger an error on a deployed route and confirm the browser sees only `{"error":"Something went wrong","id":"..."}`, not a stack trace. Grep the repo once more for `console.log` / `print` / `Log.d` lines that touch `token`, `password`, `secret`, or a whole request object.

Repeat the report block per file/cluster you found. If you found only Pattern 2 (raw errors to client) with no secret/PII logging, you can drop the "rotate" step.

## Don't false-positive on

- **Logging that a thing happened, not its value.** `console.log("login attempt", { email, success })`, `logger.info("stripe key loaded:", Boolean(...))`, `log.Println("user authenticated", userID)` — these are exactly the safe pattern. A variable *named* `token` next to a log call isn't a finding unless the secret's **value** is what gets printed. Read the line.
- **Logging an opaque id, not PII.** `logger.info("order", { orderId, userId })` is fine. A `userId` / UUID / database row id is not personal data. Flag emails, names, phone numbers, addresses, card numbers, government IDs, DOB, health data, and auth tokens — not internal identifiers.
- **Test, seed, example, and script files.** `*.test.*`, `*.spec.*`, `__tests__/`, `scripts/`, `seed.*`, `examples/`, `*.stories.*` — a hardcoded fake token logged in a test is noise. Note at most as INFO.
- **Server-side-only logging of full errors.** `console.error(err)` / `logger.exception(...)` that stays in the server log and does NOT get returned to the client is the *correct* fix, not a bug. The problem is only when the raw error reaches the **browser/client** or when a **secret/PII value** is what's being logged.
- **`console.log` in client/browser code with no secret in it.** Frontend debug logging of non-sensitive UI state is a code-cleanliness nit, not a security finding. (Caveat: in React Native / Expo, `console.log` lines *ship in the production bundle* — so a `console.log(token)` there IS a real finding; a `console.log("rendered")` is not.)
- **Structured loggers that auto-redact.** If the project uses `pino` with `redact: [...]`, `winston` with a redaction format, or Rails' `filter_parameters` configured for `:password, :token`, then logging an object is already scrubbed. Check the logger config before flagging — if the sensitive keys are in the redact list, it's handled.
- **Error trackers configured to scrub.** Sentry/Datadog with `beforeSend` data-scrubbing or default PII-stripping on is the intended setup. Only flag when raw request bodies / user secrets are explicitly attached (`extra: { requestBody }`, `setUser({ ...everything })`) with no scrubbing.
