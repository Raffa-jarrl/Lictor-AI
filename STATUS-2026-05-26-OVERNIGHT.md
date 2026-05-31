# Overnight Status — 2026-05-26 (session resume)

## What I did this session

### 1. Restarted Telegram listener
- Old listener (PID 32739) appeared frozen but was actually processing — confirmed via `telegram-commands.jsonl`
- Killed duplicate spawn (PID 33760), kept the working one
- You can still text the bot from your phone (/status, /findings, /running, etc.)

### 2. Verified the 3 prior top leads — all NOT $50K class
| Lead | Status | Reason |
|---|---|---|
| airbnb admin-lite.airbnb.com CORS | NOT $50K | GCP IAP-protected, IAP cookie SameSite=Lax blocks cross-site exploit. Real but $500-2K range. |
| arrow_electronics api-wolken-cms CORS | FP Class #22 | ACAH lists Authorization+wolken_token+serviceAccount = Bearer-API. Standard CORS+creds attack fails. |
| cfp_time api.cfptime.org GitLab | FP | Body contained word "version" → matched GitLab fingerprint. Actually Swagger UI. |

### 3. Fixed 2 orchestrator bugs
- `patrol-sourcemap-leak.py`: added `--ledger` arg (was erroring on every company)
- `patrol-cicd-admin-panels.py`: added `port_alive()` fail-fast check (3s timeout), tightened fingerprints
  - Jenkins: required `hudson.model` in /api/json body (not just `_class` which matches HTML class attrs)
  - GitLab: required platform name `GitLab` not generic `version`
  - TeamCity: required `teamcity` body content
  - Tekton: required `tekton.dev` (K8s API group)
  - Drone: required `drone-ci`
  - Added anti-markers for Swagger UI, Cloudflare Access, Google Help Center

### 4. Retracted 511 stale-fingerprint FPs in 3 passes
- **Pass 1**: 499 retractions (loose markers `version`/`items`/`login` on non-platform bodies)
- **Pass 2**: 5 retractions (`_class` matched in Next.js HTML class attrs)
- **Pass 3**: 7 retractions (DataStax vouch-proxy SSO gate, not real Jenkins)
- **Final survivors**: 4 (eslint Jenkins API, greenhouse GitLab — both LOW class with auth)

### 5. Restarted F500 orchestrator with all fixes
- 20 workers, --resume
- Current state (snapshot at session end): **192/577 completed**
- 25 active scanner processes
- Auto-resumes from on-disk summary.json files (resilient if state file lost)
- ETA: ~6-8 hours to finish remaining 385 companies

### 6. Verified the BEST CORS lead (Arlo) — still NOT $50K
- `myapi.arlo.com` + `beta.arlo.com` reflect arbitrary Origin with credentials=true
- BUT ACAH lists `Authorization`, `accessToken`, `securitytoken` → Bearer-token auth pattern
- Cookies set are `__cf_bm` (Cloudflare bot management), not user session
- Realistic class: $500-2K hardening, not session-stealable

## Verified-real findings inventory (post-cleanup)

| Class | Count | Notes |
|---|---|---|
| Jenkins API readable | 2 (eslint jenkins2.eslint.org :80 :443) | /script protected → LOW |
| GitLab readable | 2 (greenhouse gitlab.greenhouse.io :80 :443) | SAML protected → LOW info disc |
| CORS CDN-edge with creds | ~134 CRITICAL | Mostly no real sensitive content on edge-served paths. Filtered list: 19 candidates with status=200, but most use Bearer auth (FP Class #22). |
| terraform-state | 0 | None found |
| sourcemap | 0 | Scanner was broken; new orchestrator will populate |

**$50K+ class findings**: **0** so far across 225+ scanned companies.

## Honest outlook

The F500 surface scan is producing many CORS findings but the vast majority are:
- CDN-edge permissive policies (no actual sensitive data on probed paths)
- Bearer-API auth patterns (FP Class #22 — CORS+creds attack doesn't work)
- Static SPA fallbacks (FP Class #11)
- IAP/SAML/SSO-protected admin panels (no auth bypass)

Per PRIORITY-QUEUE.md, the **honest probability of 1+ $50K+ payout in next 14 days = 30-50%**. We are not closer to that goal from this session's work, but we have:
1. **Reduced our FP surface dramatically** (511 FPs retracted, scanner fingerprints tightened)
2. **Restored telemetry** (Telegram bot working again)
3. **Fixed orchestrator** so it can run the remaining 385 companies cleanly

## Next steps to consider when you're back

1. **Wait for F500 sweep to finish** — fresh post-fix data will be cleaner; might surface a real lead
2. **Sourcemap deep-dive** — once the now-fixed sourcemap scanner runs through all companies, manually grep collected `.map` files for secrets
3. **Pivot to higher-impact scanner types** — generic CORS/cicd panel scanning is not producing $50K findings. Consider:
   - GraphQL introspection + auth-bypassable mutations on financial/crypto targets
   - Direct subdomain takeover claim-ability check (per Floqast lesson)
   - GitHub code search for secrets in committed code (already partially done)
   - Open S3 bucket prefix patterns

## Files to check tomorrow

- `/Users/raffa/Lictor/v3/ledgers/f500/_orchestrator.log` — orchestrator progress
- `/Users/raffa/Lictor/v3/ledgers/f500/_orchestrator-state.json` — completion state
- `/Users/raffa/Lictor/v3/ledgers/telegram-commands.jsonl` — your Telegram commands
- `/Users/raffa/Lictor/v3/ledgers/telegram-listener.log` — listener health

## Commands to check status from your phone

- `/status` — overall status
- `/f500` — F500 orchestrator progress
- `/findings 20` — top 20 recent findings (post-cleanup)
- `/running` — active scanner processes
