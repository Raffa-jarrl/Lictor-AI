# Check — Sensitive actions that leave no trace (missing audit logging)

**What you're looking for:** the *opposite* of the logging-PII check. There, the problem was logging too much. Here, the problem is logging **nothing** on the actions that matter most. A login fails. An admin deletes a user. Someone changes another account's role to "owner." A refund goes out. And in the code that handles it, there is **no `logger.*`, no `audit_log(...)`, no security-event emit — nothing.** The feature works perfectly. It just happens silently.

This is the bug you only notice *after* the breach. Someone gets into an account, grants themselves admin, drains the value, and leaves — and when you go looking for "who did what, when," there's no answer, because the code never wrote it down. You can't investigate an incident you have no record of. OWASP calls this **A09: Security Logging and Monitoring Failures**, and it's on the Top 10 precisely because the absence is invisible until it's catastrophic.

A founder's mental model: **the three flows that always need a paper trail are (1) who logged in / failed to log in, (2) who changed permissions or deleted accounts, and (3) who moved money or value.** If a handler for one of those finishes without writing a single audit line, that's the finding.

**Severity: 🟡 MEDIUM, advisory.** This is a "you'll regret this the day you're breached" finding, not a "you're being breached right now" one. Keep it calm and keep it scoped — see the strict guard at the bottom. We flag a *complete absence* of logging on a *clearly sensitive* flow. We never claim anything about alerting, SIEM, retention, or monitoring — none of that is visible in the code, so we don't assert it.

## How to scan

This is a two-pass check, and the second pass is the important one. **Pass 1: find the sensitive handlers. Pass 2: read each one and check whether *any* logging call appears inside it.** A grep alone can't conclude "no logging" — you have to open the handler and look. Cast the net across stacks, then read the hits.

```bash
# === PASS 1 — find the sensitive flows (the handlers that SHOULD log) ===

# --- Auth events: login, logout, password reset, MFA enroll (any stack) ---
grep -rEn --exclude-dir={node_modules,.next,dist,build,vendor,venv,.venv,__pycache__,Pods} \
  -E "(sign[_-]?in|signIn|log[_-]?in|logIn|authenticate|verifyPassword|comparePassword|checkPassword|password[_-]?reset|resetPassword|forgotPassword|change[_-]?password|updatePassword|mfa|totp|two[_-]?factor|2fa|enrollMfa|verifyOtp)" \
  . 2>/dev/null | grep -iE "function|def |func |route|handler|async|app\.(post|put)|router\.(post|put)|=>" | head -40

# --- Privileged / admin actions: role changes, deletes, grants, config ---
grep -rEn --exclude-dir={node_modules,.next,dist,build,vendor,venv,.venv,__pycache__,Pods} \
  -E "(setRole|updateRole|changeRole|assignRole|grantPermission|addPermission|makeAdmin|promote|deleteUser|removeUser|banUser|suspendUser|impersonate|updateSettings|updateConfig|setFlag|disableMfa|resetUserPassword)" \
  . 2>/dev/null | head -40

# --- Money / value mutations: charges, refunds, payouts, transfers, balances ---
grep -rEn --exclude-dir={node_modules,.next,dist,build,vendor,venv,.venv,__pycache__,Pods} \
  -E "(refund|payout|transfer|withdraw|chargeback|adjustBalance|creditAccount|debitAccount|issueCredit|cancelSubscription|applyCoupon|overridePrice|stripe\.(refunds|payouts|transfers)|createCharge)" \
  . 2>/dev/null | head -40

# === PASS 2 — once you have the handler files, check for ANY logging inside ===
# Run this against the SPECIFIC files Pass 1 surfaced, then READ the ones with 0 hits.
# Example for one file:
#   grep -nE "logger\.|log\.|console\.|audit|auditLog|audit_log|track\(|emit|securityEvent|logEvent|Rails\.logger|app\.logger|os_log|NSLog|Log\.[dviwe]" path/to/handler

# Broad sweep for what an audit call tends to look like across stacks (orientation only) ---
grep -rEn --exclude-dir={node_modules,.next,dist,build,vendor,venv,.venv,__pycache__,Pods} \
  -E "(audit[_-]?log|auditLog|securityEvent|security_event|logSecurityEvent|recordAuditEvent|AuditTrail|audit_trail|writeAudit)" \
  . 2>/dev/null | head -40
```

If you have ripgrep, the cleanest Pass 2 is per-file: for each handler from Pass 1, `rg -c 'logger|log\.|console|audit|emit|track|securityEvent' <file>` — a count of `0` is your candidate. Then open it and confirm there's genuinely no logging on the sensitive path (not just none in one branch).

## What "no audit trail" looks like (per stack)

**JS / TS — login handler that records nothing**

```ts
// app/api/auth/login/route.ts
export async function POST(req: Request) {
  const { email, password } = await req.json();
  const user = await db.user.findUnique({ where: { email } });
  if (!user || !(await bcrypt.compare(password, user.hash))) {
    return Response.json({ error: "Invalid credentials" }, { status: 401 });
    // ↑ failed login. No logger.warn. No record of WHO tried, from WHERE, HOW MANY times.
  }
  const token = signSession(user.id);
  return Response.json({ token });
  // ↑ successful login. Also unrecorded. You can't tell a normal login from a stolen-password one.
}
```

**JS / TS — admin role change with no trail**

```ts
// app/api/admin/users/[id]/route.ts
export async function PATCH(req, { params }) {
  const { role } = await req.json();
  await db.user.update({ where: { id: params.id }, data: { role } });
  return Response.json({ ok: true });
  // ↑ someone just became an admin/owner and there is no line anywhere saying who did it or when.
}
```

**Python (Flask/Django) — refund with no audit**

```python
@app.post("/admin/refund")
def refund():
    charge_id = request.json["charge_id"]
    stripe.Refund.create(charge=charge_id)        # money left the building
    return {"ok": True}
    # ↑ no logger.info("refund issued", ...). No who/what/when. Pure value mutation, zero trail.
```

**Go — password reset that completes silently**

```go
func ResetPassword(w http.ResponseWriter, r *http.Request) {
    userID := mux.Vars(r)["id"]
    db.Exec("UPDATE users SET hash=$1 WHERE id=$2", newHash, userID)
    w.WriteHeader(http.StatusOK)
    // ↑ a credential just changed. No log.Printf, no audit insert. Account takeover leaves no footprint.
}
```

**Ruby (Rails) — destroy action, no audit**

```ruby
# app/controllers/admin/users_controller.rb
def destroy
  User.find(params[:id]).destroy   # account deleted
  head :ok
  # ↑ no Rails.logger / no audit gem call. The deleted user and the actor both vanish from history.
end
```

**PHP (Laravel) — permission grant, silent**

```php
public function grant(Request $r, User $user) {
    $user->permissions()->attach($r->permission_id);   // privilege escalated
    return response()->json(['ok' => true]);
    // ↑ no Log::info / no activity-log call. No record of who got what access.
}
```

**Mobile (Swift / Kotlin / Flutter / RN):** the relevant audit for these flows lives **server-side**, so the gap is usually in the backend the app calls — that's where to look. The one mobile-specific case worth a note: an app that performs a **client-side privileged or money action and only talks to a third-party SDK** (e.g. a Firebase `update`, a direct Stripe mobile call) with no call back to *your* server means there's no place a trail could even be written. Flag the **server endpoint that should exist and log**, not the mobile line.

## Why this matters (the founder version)

- **You can't investigate what was never recorded.** After an account takeover, the first question is "what did they touch, and when?" If the role-change and refund handlers logged nothing, the honest answer is "we have no idea" — which is also the answer you'll give the affected customer and, in regulated spaces, the regulator.
- **Repeated failed logins are the earliest signal of an attack** (credential stuffing, brute force). If failed logins aren't logged, that signal doesn't exist for you to ever notice — not today, and not in a future review.
- **Privileged actions are exactly what an attacker uses you for.** Granting themselves admin, deleting evidence, issuing refunds to their own card. A trail on those three flows is the difference between a contained incident and an open-ended mystery.

## The safe pattern — emit one structured security event

The fix is small and the same shape everywhere: **on auth and privileged/value actions, write one structured line capturing who, what, when, and the outcome** — and (cross-ref the logging-PII check) **without** putting secrets or raw PII in it. Log the actor's *id*, not their password; the target's *id*, not their full record.

```ts
// A tiny helper, reused across handlers
function audit(event: string, fields: Record<string, unknown>) {
  // who / what / when / outcome — ids only, never secrets or PII
  console.info(JSON.stringify({ kind: "security", event, at: new Date().toISOString(), ...fields }));
}

// Failed + successful login
if (!ok) {
  audit("login.failure", { email_hash: sha256(email), ip: clientIp });   // hash, don't store the email raw
  return Response.json({ error: "Invalid credentials" }, { status: 401 });
}
audit("login.success", { actorId: user.id, ip: clientIp });

// Role change — capture before AND after
audit("user.role_changed", { actorId: session.user.id, targetId: params.id, from: prev.role, to: role });

// Refund — value mutation
audit("payment.refund", { actorId: session.user.id, chargeId, amount });
```

```python
# Python — structured event to your server log (stays server-side; no secrets/PII)
import logging, json
log = logging.getLogger("security")
log.info(json.dumps({"event": "payment.refund", "actor_id": current_user.id,
                     "charge_id": charge_id, "amount": amount}))
```

```go
// Go
log.Printf("security event=%s actor=%s target=%s from=%s to=%s",
    "user.role_changed", actorID, targetID, prevRole, newRole)
```

Rails (`audited` / `paper_trail` gems), Laravel (`spatie/laravel-activitylog`), and Django (`django-auditlog`) give you this for free — one line of model config and the create/update/delete trail is recorded automatically. If the project already pulls one of those in, this check is **satisfied** even if the handler itself looks bare (see the guard).

## Report a finding as

**Title:** "Your most sensitive actions leave no record — no way to investigate a breach"

(adapt to what you actually found: "Failed logins aren't logged", "Admin role changes leave no trail", "Refunds complete with no audit record")

**Detail:**
> `app/api/auth/login/route.ts:5` handles login. On both the failure path (line 7) and the success path (line 11), the handler returns a response without writing a single log or audit line — no `logger.*`, no audit call, nothing. Same story in `app/api/admin/users/[id]/route.ts:4`, which changes a user's `role` (the action that turns a normal account into an admin) and in `/admin/refund` (which issues money back), both of which complete silently.
>
> Everything works, so nothing looks wrong. The problem is what's *missing*: if someone gets into an account tomorrow, grants themselves admin, and issues a refund to their own card, there is no record anywhere of who did it or when. You'd be investigating a break-in with the security cameras unplugged. Repeated failed logins — the earliest sign someone's trying stolen passwords against you — also go unrecorded, so there's nothing to ever surface.
>
> This is advisory, not an active emergency: nothing here is being exploited *right now*. But it's the kind of gap you only discover the day you desperately need the logs and they don't exist. Worth a single focused pass.
>
> **What to do tonight:**
> 1. Add one tiny structured-audit helper and call it on the three flows that matter — auth (login success/failure, logout, password change/reset, MFA enroll), privileged actions (role change, user delete, permission grant, config change), and value mutations (refund, payout, transfer):
>    ```ts
>    function audit(event: string, fields: Record<string, unknown>) {
>      console.info(JSON.stringify({ kind: "security", event, at: new Date().toISOString(), ...fields }));
>    }
>    // login failure:  audit("login.failure", { email_hash: sha256(email), ip });
>    // login success:  audit("login.success", { actorId: user.id, ip });
>    // role change:     audit("user.role_changed", { actorId, targetId, from, to });
>    // refund:          audit("payment.refund", { actorId, chargeId, amount });
>    ```
> 2. Record **who / what / when / outcome** — and only **ids**, never the password, token, full email, or card. (If you're tempted to dump the whole user object, stop — that's the logging-PII check's bug. These two checks are a pair: log the *event*, not the *secrets*.)
> 3. If you're on Rails / Laravel / Django, reach for the maintained audit gem/package (`audited`, `paper_trail`, `spatie/laravel-activitylog`, `django-auditlog`) — one line of model config gives you the create/update/delete trail automatically.
> 4. Verify: trigger a failed login and an admin role change locally, then check your server log shows one `kind:"security"` line each, containing ids and outcome and **no** secrets.

Repeat the report block per sensitive handler (or cluster of handlers) you confirmed has no logging.

## What NOT to flag (false-positive guard — read this before reporting)

This check is deliberately conservative. A wrong "you have no audit trail" finding erodes trust fast, so only report when you've genuinely confirmed the absence on a genuinely sensitive flow.

- **Don't claim missing alerting, SIEM, monitoring, log retention, or anomaly detection.** None of that is visible in source code. The *only* thing you can assert from reading the repo is "this sensitive handler emits no log/audit call." Stay inside that. Never write "you have no monitoring" or "logs aren't being retained" — you cannot see that.
- **Logging present anywhere on the sensitive path = satisfied.** If the handler (or a middleware/decorator/interceptor that wraps it, or a service it calls) emits *any* `logger.*` / `log.*` / `audit*` / `securityEvent` / framework request log on that flow, do **not** flag it. A bare-looking controller behind a global audit middleware is fine. Look one layer out before concluding "nothing."
- **A project-wide audit library counts.** Rails `audited`/`paper_trail`, Laravel `activitylog`, Django `auditlog`, a NestJS audit interceptor, an ORM hook (`prisma $extends`, a Sequelize/TypeORM subscriber) — if one of these is wired up to the model being mutated, the trail exists even if the handler body is empty of log calls. Check `package.json` / `Gemfile` / `requirements.txt` / `composer.json` and the model definitions before flagging.
- **Only flag genuinely sensitive flows.** Auth, privilege/role/permission changes, account deletion, config changes, and money/value mutations — those three families. Do **not** flag ordinary CRUD: creating a todo, updating a profile bio, fetching a list, a read-only GET. Not every endpoint needs an audit line; reserve this for the handful that gatekeep identity, access, and value.
- **Don't flag the absence as CRITICAL/HIGH.** This is structurally advisory — it describes future investigability, not present exploitation. Keep it 🟡 MEDIUM. (If the *same* handler has a *different* live bug — e.g. it's also unauthenticated — that's a separate, higher-severity finding under the auth check; report that there, not here.)
- **Partial logging is usually fine.** If a handler logs the success path but not the failure path (or vice-versa), note it as a one-line improvement at most — don't escalate. The finding is for a **complete** absence of any logging on the sensitive action, not for imperfect coverage.
- **Tests, seeds, examples, scripts, migrations.** `*.test.*`, `*.spec.*`, `__tests__/`, `scripts/`, `seed.*`, `examples/`, `migrations/` — a sensitive-sounding function in these is noise. Skip.
- **Frameworks that log requests by default.** If the stack already emits a structured access log per request (some API gateways, certain middleware setups) that captures method/path/user/status on the sensitive route, the who/what/when/outcome is effectively there. Don't double-flag.
