# Disclosure 2 of 4 — Stripe sk_live key leak (MOST URGENT — 4 days fresh)

**Target:** https://github.com/codakyello/Seamless-point
**File:** `config.env` (commit `6e4e3f382784954b50dff762a9eafccb3e872121`)
**Last pushed:** 2026-05-17 (4 days ago — past Stripe auto-revoke window if it was going to fire)
**Action:** Open GitHub issue + email Stripe security

---

## Step A — open GitHub issue

URL: https://github.com/codakyello/Seamless-point/issues/new

**Title** (copy):
```
Security: Stripe live secret key (sk_live_*) committed to config.env — rotate immediately
```

**Body** (copy):
```markdown
Hi — security note.

`config.env` (commit `6e4e3f382784954b50dff762a9eafccb3e872121`) contains a **live** Stripe secret key (`sk_live_22…006f`) in the public main branch.

This is a Stripe LIVE-mode key — it can charge cards, refund customers, access your full Stripe dashboard programmatically.

**Action items (in order):**

1. **Roll the key NOW** at https://dashboard.stripe.com/apikeys → click the "..." next to the live secret key → "Roll key" → confirm. Stripe will issue a new key; the old one becomes inactive within seconds.
2. **Check recent activity** at https://dashboard.stripe.com/payments and https://dashboard.stripe.com/logs for any charges or API calls you don't recognize since 2026-05-17 (when the key landed in the public commit).
3. **Rewrite git history** to remove `config.env` from past commits: `git filter-repo --invert-paths --path config.env`. The GitHub-archived old commits will keep the key visible until you do this.
4. **Switch to env vars** going forward: load Stripe keys from environment variables, never commit them to git. Add `*.env` to `.gitignore`.

The leak was detected by Lictor (https://lictor-ai.com), open-source security scanner (Apache 2.0). No use of the key was attempted on my end.
```

## Step B — email Stripe Security

To: `security@stripe.com`

Subject:
```
Live Stripe sk_live_* key leaked on public GitHub
```

Body:
```
Hello,

A public GitHub repository contains an active Stripe sk_live_* secret key
in plaintext:

  Repository: https://github.com/codakyello/Seamless-point
  File:       config.env
  Commit:     6e4e3f382784954b50dff762a9eafccb3e872121
  Key prefix: sk_live_22… (full key intentionally redacted)
  Pushed:     2026-05-17

The repository owner has been separately notified via a GitHub issue
requesting they roll the key immediately.

Request: please investigate the leaked key and contact the Stripe account
holder directly if your records show the key is still active. This is the
most fresh of three sk_live_* leaks I discovered today; the other two
are at:
  https://github.com/Kryst-Investments-LLC/autopilot-ventures/blob/.../fitnesai.env (sk_live_51…8I3o)
  https://github.com/shatami1/Comcare/blob/.../stripe-key.env (sk_live_51…L5hO)

Discovered via Lictor (https://lictor-ai.com), open-source security scanner.
No use of the keys was attempted.

Thank you.
```
