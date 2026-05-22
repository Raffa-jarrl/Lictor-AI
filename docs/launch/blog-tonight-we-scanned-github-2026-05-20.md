# Tonight, Lictor scanned ~1,500 recent GitHub commits and found 32 leaked production keys

**Date:** 2026-05-20
**Audience:** Indie devs, solo founders, anyone who's ever typed `git add .`
**Read time:** ~3 minutes

---

## The TL;DR

We pointed [Lictor](https://lictor-ai.com) — our Apache-2.0 indie security scanner — at GitHub for one evening. It walked:

- **600 recently-created gists**
- **300 recently-pushed terraform repos**
- **100 recently-committed .env files**
- **100 recent Stripe-related commits**
- **258 recent cloudflare-config commits**
- **100 recent mailchimp integrations**

And it found:

| Type of secret | Count | What an attacker can do with one |
|---|---|---|
| Live Stripe API keys (`sk_live_*`) | **9** | Process refunds, read customer data, issue payouts to attacker-controlled bank |
| AWS access keys + paired secrets (`AKIA*`) | **20+** | Spin up crypto-mining EC2s on your card, exfiltrate S3 buckets, escalate to root |
| Mailchimp API keys | **2** | Read your entire email list, send phishing as your brand |
| Slack incoming webhooks | **1** | Inject messages into private channels, phish your team |

**All public.** All findable by anyone with 20 lines of Python (or a $0 weekend project like Lictor).

These aren't enterprise security failures. These are **solo founders, indie devs, and small teams** — exactly the people we built Lictor for.

---

## The three patterns we keep seeing

### Pattern 1 — `.env` committed before `.gitignore` updated

> The classic. You created the project, started coding, dropped your `STRIPE_SECRET_KEY` into `.env` to test locally, ran `git add .`, committed. Two days later you added `.env` to `.gitignore` — but git history still has it. Public forever.

**Tonight's count:** 6 of the 9 Stripe live keys.

### Pattern 2 — Terraform `providers.tf` with literal credentials

> Someone follows an AWS Terraform tutorial. The tutorial says "put your credentials in providers.tf and run `terraform init`." They do. They push to GitHub to share with their team. The `aws { access_key = "AKIA..." secret_key = "..." }` block is now indexed by GitHub Code Search within hours.

**Tonight's count:** 15+ of the 20+ AWS leaks.

### Pattern 3 — "Gist for quick share, I'll delete it later"

> Pasting your `.env` into a private gist to share with a contractor. Setting it to "secret" instead of "private" because the difference is unclear. (Spoiler: "secret" gists are unlisted but **anyone with the URL can read them, and they leak via GitHub search**.)

**Tonight's count:** 0 (the gist API path returned 0 verified hits, but Lictor's main S/N comes from code search — gists are usually rotated faster).

---

## How to not be us in three weeks

### If you're about to commit
```bash
# Install Lictor's pre-commit hook (one line, free, Apache 2.0)
curl -sSL https://lictor-ai.com/install-precommit.sh | bash

# Now git commit will block + warn before any secret pattern lands in history
```

### If you already committed
```bash
# Rotate the key FIRST (the leak window is already open)
# Then purge it from history:
git filter-repo --invert-paths --path .env --force
git push --force origin main
```

But honestly — **rotate first, history-purge second**. Bots scrape GitHub commits in seconds, not days. Anyone who got the key before you purge still has it.

### If you want Lictor to scan your own org
```bash
git clone https://github.com/Raffa-jarrl/Lictor-AI
cd Lictor-AI
./scripts/patrol-aws-keys.py     # scan recent AWS-key commits
./scripts/patrol-stripe.py       # scan recent Stripe-key commits
./scripts/patrol-gists.py        # walk recent gists for any secret pattern
```

Apache 2.0. No telemetry. No paid tier. Run it on yourself before someone else does.

---

## What Lictor isn't doing

We're **not** emailing the 32 people whose keys we found tonight. We're publishing the patterns publicly so anyone — including them — can self-audit. The names of the leaking repos aren't in this post (and never will be).

If you recognize yourself in one of the patterns above and want to check: clone Lictor and run it against your own GitHub username. Takes 60 seconds.

---

## Why we built this

Indie devs and small teams **can't afford the $20K/year enterprise secret scanners**. They also don't have a security team to set up GitGuardian, Gitleaks, TruffleHog, and Snyk individually. So they end up running nothing.

Lictor exists so the same pre-commit hook + repo scanner that protects FAANG eng teams is one `curl` away for the solo founder shipping their MVP on a Saturday.

**Apache 2.0. Forever.** No "Enterprise tier with the real features." No telemetry. Run it locally, run it in your CI, fork it, sell-derivatives of it. We just want fewer keys leaking.

---

*Lictor is built by [Raffa Jarrl](https://github.com/Raffa-jarrl), a 20-year cybersec engineer who got tired of watching small projects bleed secrets. Repo: [github.com/Raffa-jarrl/Lictor-AI](https://github.com/Raffa-jarrl/Lictor-AI) · Website: [lictor-ai.com](https://lictor-ai.com)*
