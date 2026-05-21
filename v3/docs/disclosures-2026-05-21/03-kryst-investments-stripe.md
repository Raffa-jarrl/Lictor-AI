# Disclosure 3 of 4 — Stripe sk_live key leak (LLC, 12 days old)

**Target:** https://github.com/Kryst-Investments-LLC/autopilot-ventures
**File:** `fitnesai.env` (commit `b92cda5e7861a2035cc0b01df18bd3a4a170c1e4`)
**Last pushed:** 2026-05-09 (12 days ago)
**Action:** Open GitHub issue (Stripe will be informed via the email in disclosure #2)

---

## GitHub issue

URL: https://github.com/Kryst-Investments-LLC/autopilot-ventures/issues/new

**Title** (copy):
```
Security: Stripe live secret key (sk_live_*) committed to fitnesai.env — rotate immediately
```

**Body** (copy):
```markdown
Hi — security note for Kryst Investments LLC.

`fitnesai.env` (commit `b92cda5e7861a2035cc0b01df18bd3a4a170c1e4`) contains a **live** Stripe secret key (`sk_live_51…8I3o`) in the public main branch.

This is a Stripe LIVE-mode key — it can charge cards, refund customers, access your full Stripe dashboard programmatically. Because this is an LLC's repository, the key likely belongs to a business Stripe account with real customer transactions at risk.

**Action items (in order):**

1. **Roll the key NOW** at https://dashboard.stripe.com/apikeys → click the "..." next to the live secret key → "Roll key" → confirm. Old key becomes inactive within seconds.
2. **Check recent activity** at https://dashboard.stripe.com/payments and https://dashboard.stripe.com/logs for any unauthorized charges or API calls since 2026-05-09 (when the key landed in the public commit).
3. **Rewrite git history** to remove `fitnesai.env` from past commits: `git filter-repo --invert-paths --path fitnesai.env`. GitHub-archived old commits will keep the key visible until you do this.
4. **Switch to env vars** going forward: load Stripe keys from environment variables, never commit them. Add `*.env` to `.gitignore`.

The leak was detected by Lictor (https://lictor-ai.com), open-source security scanner (Apache 2.0). No use of the key was attempted on my end. This is a one-time courtesy notification.
```
