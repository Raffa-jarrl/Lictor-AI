# Disclosure 4 of 4 — Stripe sk_live key leak (possibly healthcare app — extra caution)

**Target:** https://github.com/shatami1/Comcare
**File:** `stripe-key.env` (commit `dd4209bbc9f09657105370581d7c5ecf0e1513c2`)
**Last pushed:** 2026-05-09 (12 days ago)
**Note:** Repo name "Comcare" suggests possible healthcare application — extra disclosure caution recommended
**Action:** Open GitHub issue (Stripe is informed via the email in disclosure #2)

---

## GitHub issue

URL: https://github.com/shatami1/Comcare/issues/new

**Title** (copy):
```
Security: Stripe live secret key (sk_live_*) committed to stripe-key.env — rotate immediately
```

**Body** (copy):
```markdown
Hi — security note.

`stripe-key.env` (commit `dd4209bbc9f09657105370581d7c5ecf0e1513c2`) contains a **live** Stripe secret key (`sk_live_51…L5hO`) in the public main branch.

This is a Stripe LIVE-mode key — it can charge cards, refund customers, access your full Stripe dashboard programmatically. The repository name (Comcare) suggests this may be a healthcare-related application, which would mean the Stripe account potentially handles patient/customer billing — additional sensitivity.

**Action items (in order):**

1. **Roll the key NOW** at https://dashboard.stripe.com/apikeys → click the "..." next to the live secret key → "Roll key" → confirm.
2. **Check recent activity** at https://dashboard.stripe.com/payments and https://dashboard.stripe.com/logs for any unauthorized charges or API calls since 2026-05-09 (when the key landed in the public commit).
3. **Rewrite git history** to remove `stripe-key.env` from past commits: `git filter-repo --invert-paths --path stripe-key.env`.
4. **Switch to env vars** going forward: load Stripe keys from environment variables, never commit them. Add `*.env` to `.gitignore`.
5. **If this Stripe account handles healthcare-related transactions**, also review your HIPAA / data-handling posture given the exposure window (12 days).

The leak was detected by Lictor (https://lictor-ai.com), open-source security scanner (Apache 2.0). No use of the key was attempted on my end. This is a one-time courtesy notification.
```
