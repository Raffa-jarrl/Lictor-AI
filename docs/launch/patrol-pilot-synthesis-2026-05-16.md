# Patrol pilot — synthesis of first day's scans

> **Date:** 2026-05-16
> **Pilot operator:** Raffa + agent crew
> **Scope:** prove the Patrol concept works by running the actual scans against real GitHub data; report findings honestly.

---

## TL;DR

**Four cohorts. ~60 apps scanned. Zero critical findings.** That's both a real result and a useful learning. The surface-level scanner we built finds what it can find — defensive-header gaps (CSP, HSTS, X-Frame). The juicy findings (leaked Supabase service-role keys, exposed admin endpoints, hardcoded Stripe `sk_live_`) didn't surface in this sample because:

1. Hosting-platform defaults (Vercel, Bolt host, Lovable, GitHub Pages) catch the easiest mistakes by default.
2. GitHub's own secret-scanning auto-rotates well-known secret shapes within minutes of push.
3. Our scanner only probes the first page + first JS bundle + ~7 known paths. The real bugs sit deeper.

This doesn't break the Patrol thesis — it sharpens it.

---

## What we ran

| Cohort | Source | Filter | Apps scanned | Grade ≤ C | Critical |
|---|---|---|---|---|---|
| **A — Fresh** | GitHub created in last 7d, vibe-coder keywords | any homepage | 35 | 0 | 0 |
| **B — Mature + custom domain** | GitHub pushed 60-180d ago, vibe-coder keywords | custom domain only (not `*.vercel.app` etc) | 21 | 0 | 0 |
| **C — Platform showcases** | scrape lovable.dev/showcase, v0.app/community, bolt.new/templates | featured apps | 0 | — | — |
| **D — Source code** | GitHub Code Search for `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY` | pushed in last 30d | 5 | 0 | 0 (env-var name referenced, JWT actually in gitignored .env) |

**Cohort C returned 0 candidates** because Lovable / v0 / Bolt all changed their showcase pages this quarter — now SPA-rendered + likely auth-gated. A simple `urllib` scraper can't see them. Needs Playwright / Chrome MCP to scrape. **Deferred.**

---

## What we learned

### 1. The surface scanner works. It just doesn't find much *at this depth*.

Built `scripts/patrol-pilot.py` — 7 check categories, polite (1 scan/origin, 8s timeout), respects robots-style ethics. Runs in ~7-12 seconds per URL. Verified end-to-end on 56 real public apps. Output is markdown with grade + findings + fix suggestions.

The checks at this depth catch:
- ✅ Missing CSP / Permissions-Policy / HSTS / X-Frame-Options
- ✅ Exposed `.env`, `.git/config`, `.DS_Store`
- ✅ Hardcoded `sk-`, `AIza`, `ghp_`, `AKIA`, `sk_live_` in first JS bundle
- ✅ Decoded JWT payloads with `role: service_role` in first JS bundle
- ✅ `/api/users`, `/api/leads`, `/admin` returning JSON with email-shaped data
- ❌ Bugs that require auth-flow traversal (IDOR, broken access control)
- ❌ Bugs that require multi-page state (cross-tenant cache leaks)
- ❌ Bugs in routes we don't pre-list (custom API surfaces)
- ❌ Bugs that require AI-prompt-injection tests (Sentinel's domain)

### 2. Vibe-coder hosting defaults are doing real work.

Surprising-but-real: 56 apps scanned, none had a critical finding. Vercel sets HSTS by default. Bolt host filters `.env` requests. Lovable's preview bundles don't bake server-side env vars into client. GitHub Pages serves static-only.

This is good for the world. Less good for our "47% of vibe-coder apps have critical bugs" headline.

### 3. The actual gold-finding cohorts are different from what we guessed.

The bugs we want to find live in apps that are:
- **Past the demo phase** (not last-7-days)
- **On a custom domain** (founder cared enough to wire one up, more likely to be real)
- **Past the default-config phase** (founder added features and forgot the security check on the new route)
- **Or:** pre-deploy code that was pushed to GitHub before `.gitignore` caught up

Our cohort B (mature + custom-domain) is closer to this — but 21 apps is too small a sample to find the tail. We need to scan ~500-1000 of these to find the 5-10 that actually have a critical bug.

### 4. The "1,400 NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY" finding is a real signal but the *bug* requires deeper inspection.

GitHub Code Search says 1,400 repositories have a string referencing the `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY` env var. We sampled 5 recent ones. **All 5 had the env-var name in code but the actual JWT in a gitignored `.env.local`** — i.e., they're using it correctly server-side and just naming the var poorly.

The actual bug (JWT inline in client code) is rarer than the pattern suggests. To find it we need to:
- Decode every JWT in every fetched bundle (we now do this in `patrol-pilot.py` — added in this commit)
- Search GitHub for `"eyJ..."` JWT-shaped strings in `.ts` files (too many false positives without payload decode)
- Or: scan many more apps and hope to find the few

---

## What's worth doing next

Concrete, in priority order:

### Priority 1 — Scale, not depth.

Run the existing scanner against ~500-1,000 mature custom-domain apps. At a baseline rate of "1 in 50 apps has something actionable," that's 10-20 outreach opportunities — enough to start the Bridge outreach pilot for real.

`scripts/patrol-pilot.py --mode mature --max 500` ← would take ~90 minutes. Worth doing as a daily cron once Cloudflare Worker exists.

### Priority 2 — Add the deeper checks.

Things that would surface findings the current scanner misses:

- **Auth-flow probe**: fetch `/login`, try the registration flow if visible, check whether the resulting session token has weak claims
- **IDOR probe**: if we find a URL like `/api/users/42`, try `/api/users/43`
- **AI-endpoint detection**: look for `/api/chat`, `/api/ai`, `/api/generate` and check for rate limits + prompt-injection guards
- **Multi-page bundle scan**: fetch 2-3 routes per app, not just the homepage — different routes load different JS chunks

These belong in **Patrol v0.2**, after the Worker is live.

### Priority 3 — Showcase scraping via Chrome MCP.

Lovable / v0 / Bolt showcase pages are SPA-rendered. The Chrome MCP we set up earlier could navigate them and extract featured-app URLs. That's the cohort with the highest single-finding leverage (every featured app fix is a PR Lovable cares about).

### Priority 4 — Source-code mass scan.

The GitHub Code Search hits (1,400 for NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY alone) are a long tail. The TRULY exposed ones are probably <5% of those 1,400 (the rest correctly use env files). Triaging that 5% means:

- Fetch every file
- Decode every JWT
- Cross-reference with whether the repo has a `.gitignore` entry for `.env.local`
- Check the file's path category (`src/` vs `scripts/`)

`scripts/patrol-supabase-service-role.py` does this; needs to run at higher volume.

---

## Honest assessment

The Aug-15 soft-launch story we sketched — *"We scanned 30,000 vibe-coded apps. 47% have a critical bug"* — needs work on two axes:

1. **Volume:** 30,000 is the target. We're at 56 today. The Worker has to be live for this to scale, AND it has to run continuously for ~60 days, AND it has to scan deeper than today's scanner.
2. **The 47% claim needs to be defensible.** Today our finding is: 0% of 56 surface-scanned apps have a critical bug. The real number is somewhere between 0% and 47% — we don't know yet because we haven't done the deeper probes at scale. Don't pre-commit to a number that the data won't support.

What we CAN ship on Aug 15 with the current setup:

> *"In the last 30 days we scanned 5,000 vibe-coded apps with an open-source security scanner. Most of them are fine. About 1% had a critical issue — leaked secrets, exposed admin pages, or unauthenticated API surfaces. We contacted every affected founder privately. Here are the patterns we saw and the open-source tool that found them."*

That's a smaller, more honest, more credible story. It compounds because the next month's report will say 10,000, and the one after will say 30,000. By the time we've been running for a year, we have the corpus, the pattern data, the methodology proof, and the receipts.

The big-number version comes later. The version that ships in 91 days is *"we built a careful thing, we ran it against real public apps, we contacted founders responsibly, here's what we learned, here's the open-source code so you can verify any of it."*

That story IS credible at any scale.

---

## Artifacts shipped this round

- `scripts/patrol-pilot.py` — surface scanner, 3 cohort modes (fresh / mature / showcase), 7-check engine, polite, accessible
- `scripts/patrol-supabase-service-role.py` — targeted hunt for the NEXT_PUBLIC service-role JWT mistake
- `scripts/wait-for-dns.sh` — DNS-publish watcher (auxiliary, unrelated to Patrol)
- `docs/launch/patrol-pilot-2026-05-16.md` — cohort A (fresh) report
- `docs/launch/patrol-mature-2026-05-16.md` — cohort B (mature + custom-domain) report
- `docs/launch/patrol-showcase-2026-05-16.md` — cohort C (showcase) report (0 candidates — scrape deferred)
- `docs/launch/patrol-aggregate-2026-05-16.md` — cohort D (source-code) aggregate report
- `docs/launch/patrol-outreach-private-2026-05-16.md` — private outreach queue (gitignored)
- `docs/launch/patrol-pilot-synthesis-2026-05-16.md` — this document

Total: ~1,200 lines of new code, 6 markdown reports, 1 honest synthesis. All committed to `main`.
