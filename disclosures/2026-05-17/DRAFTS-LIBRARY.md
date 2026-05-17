# Disclosures library — all verified-real findings, paste-ready

> **Created 2026-05-17.** Every entry below has been manually verified — not just scanner output. Paste the title + body into the linked submission URL. Tracking column at the bottom of this file.
> **Drafts are private** (gitignored). Aggregate stats go public; individual repos go public only via consenting maintainer OR 30-day window expiration.

---

## Status legend

- ✅ **Submitted** — fill in advisory ID / issue URL when sent
- ⏳ **Ready, awaiting your click**
- 🔵 **Needs verification** — read the file first
- ❌ **Determined false-positive** — don't send

---

## 🔴 CRITICAL severity — send these first

### 1. `reflex-app/reflex` — `pull_request_target` + checkout-PR-head (CRITICAL — runs build commands after checkout)

| | |
|---|---|
| **Severity** | 🔴 CRITICAL (HIGH + workflow runs build/install steps after checkout) |
| **Stars** | 34 |
| **Try PVR first** | https://github.com/reflex-app/reflex/security/advisories/new |
| **Fallback (issue)** | https://github.com/reflex-app/reflex/issues/new |
| **File** | `.github/workflows/dependabot-yarn2.yml` |

**Paste-ready title:** `pull_request_target workflow checks out PR head + runs build — RCE via malicious PR`

**Paste-ready body:** (use [`02-punkpeye-mcp-servers.md`](./02-punkpeye-mcp-servers.md), section "Description") — replace `<repo>` with `reflex-app/reflex` and the file with `.github/workflows/dependabot-yarn2.yml`. CVSS `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:L`.

---

### 2. `alejandrosanchez1/backup` — hardcoded Supabase service-role JWT (valid until 2036)

| | |
|---|---|
| **Severity** | 🔴 CRITICAL |
| **Stars** | 1 (low traffic but still real exposure) |
| **Try PVR first** | https://github.com/alejandrosanchez1/backup/security/advisories/new |
| **Fallback (issue)** | https://github.com/alejandrosanchez1/backup/issues/new |
| **File** | `app/AdminView.tsx` line 14 |
| **JWT decode** | `iss=supabase, ref=wrjenrtnojmhianqzxlo, role=service_role, exp=2036-02-09` |

**Paste-ready title:** `Hardcoded Supabase service-role JWT in app/AdminView.tsx (valid until 2036)`

**Paste-ready body (PVR version):**
```
## Summary

`app/AdminView.tsx` line 14 contains a hardcoded Supabase service-role JWT as a fallback value:

```typescript
const SERVICE_ROLE_KEY = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY 
  || 'eyJ...GME1KUAeu-Z1ndUpNsQ9OFr0AnW0tcmGGU19eQG9d4U'
```

Decoded payload confirms `role: service_role` for Supabase project `wrjenrtnojmhianqzxlo`, expires 2086157618 (2036-02-09 — 10+ years).

Two things make this maximum-urgency:
1. The JWT is in public GitHub source. Bots scrape GitHub for `service_role` JWT patterns 24/7.
2. The 10-year expiry means rotating eventually doesn't help — once leaked, this key works until 2036 unless explicitly revoked via Supabase dashboard.

## Fix (5 minutes)

1. **Rotate immediately**: Supabase dashboard → Project Settings → API → Reset JWT secret (invalidates old keys, regenerates new ones).
2. **Update `.env.local`** with new keys.
3. **Edit `app/AdminView.tsx`**: remove the `|| 'eyJ...'` fallback. Fail loudly if env var missing.
4. **Rename env var** away from `NEXT_PUBLIC_*` (which inlines into JS bundle). Use `SUPABASE_SERVICE_ROLE_KEY` (no prefix) and only access from server code.

## How I found this

Open-source security scanner Lictor (Apache 2.0): https://github.com/Raffa-jarrl/Lictor-AI
Scan script: `scripts/patrol-supabase-service-role.py`

Standard disclosure terms: privately reported, 30-day window before any aggregate stats publish. Your repo is never named publicly without consent.

— Raffa · raffa@lictorai.com · lictorai.com
```

**Paste-ready body (public-issue version, if PVR is off):**
```
Hi —

I have a security finding to share with you privately. I'm not posting details here for responsible-disclosure reasons.

Please contact me at raffa@lictorai.com (or DM via GitHub) and I'll send the full report.

The issue is critical and time-sensitive — please respond within 24-48h if possible.

— Raffa · Lictor AI · https://lictorai.com
```

---

### 3. `sahilaa1719-ops/medspa-opus` — hardcoded Supabase service-role JWT (valid until 2035, PVR is OFF)

| | |
|---|---|
| **Severity** | 🔴 CRITICAL |
| **Stars** | 0 |
| **PVR** | ❌ Disabled (we already confirmed) |
| **Channel** | Public issue → https://github.com/sahilaa1719-ops/medspa-opus/issues/new |
| **File** | `src/lib/supabaseAdmin.ts` line 16 |
| **JWT decode** | `iss=supabase, ref=tjrophtadiovtimgobsf, role=service_role, exp=2035-12-13` |

**Use the public-issue body from #2 above.**

---

### 4. `logistiga/PG1` — hardcoded Supabase service-role JWT (valid until 2035)

| | |
|---|---|
| **Severity** | 🔴 CRITICAL |
| **Stars** | 0 |
| **Try PVR** | https://github.com/logistiga/PG1/security/advisories/new |
| **Fallback** | https://github.com/logistiga/PG1/issues/new |
| **File** | `vitest.config.ts` line 16 |
| **JWT decode** | `iss=supabase, ref=sddylemgwftvatzfrjer, role=service_role, exp=2035-02-13` |
| **Note** | JWT is in test config — maintainer should verify whether the Supabase project is real-production or a sandbox; either way, rotate. |

**Use the same paste-ready body as #2** with the file/JWT details swapped.

---

## 🟠 HIGH severity — second batch

### 5. `ibis-project/ibis` — `pull_request_target` + checkout-PR-head (6,540 stars)

| | |
|---|---|
| **Severity** | 🟠 HIGH |
| **Stars** | **6,540** (highest-leverage in this round) |
| **Try PVR first** | https://github.com/ibis-project/ibis/security/advisories/new |
| **Fallback** | https://github.com/ibis-project/ibis/issues/new |
| **File** | `.github/workflows/snowflake.yml` |

**Title:** `pull_request_target workflow checks out PR head — RCE via malicious PR (CWE-78)`
**CVSS:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:L`
**Body:** Use [`02-punkpeye-mcp-servers.md`](./02-punkpeye-mcp-servers.md) Description section.

---

### 6. `RoboSats/robosats` — `pull_request_target` + checkout-PR-head (988 stars)

| | |
|---|---|
| **Severity** | 🟠 HIGH |
| **Stars** | 988 (high-profile P2P platform) |
| **Try PVR first** | https://github.com/RoboSats/robosats/security/advisories/new |
| **Fallback** | https://github.com/RoboSats/robosats/issues/new |
| **File** | `.github/workflows/py-linter.yml` line 25 |

Same paste-ready content as #5.

---

### 7. `ansible-lockdown/RHEL7-CIS` — two affected workflows (486 stars)

| | |
|---|---|
| **Severity** | 🟠 HIGH × 2 (one advisory covers both) |
| **Stars** | 486 |
| **Try PVR first** | https://github.com/ansible-lockdown/RHEL7-CIS/security/advisories/new |
| **Files** | `.github/workflows/main_pipeline_validation.yml` + `.github/workflows/devel_pipeline_validation.yml` |

Same template. Mention both files in the body.

---

### 8. `modelcontextprotocol/python-sdk` (Anthropic)

| | |
|---|---|
| **Severity** | 🟠 HIGH (spec-level) |
| **Status** | ⏳ Form open in Chrome (or open the URL fresh) |
| **URL** | https://github.com/modelcontextprotocol/python-sdk/security/advisories/new |
| **Title** | `Tool descriptions interpolated from external content create prompt-injection vector` |
| **Body** | Already in `01-anthropic-mcp-servers.md` (or already in your Chrome tab if still open) |

---

## ❌ Determined false-positive — do NOT send (paper trail)

For the discipline record (verifying we don't bot-spam):

- `mcp-use/mcp-use` — descriptions are static literals; scanner regex matched "fetch" elsewhere in same file
- `Gindhar2112/frida-mcp` — Frida IS code injection; the exec tools are intentional/required
- `Cristophereasygoing927/compare-mcp` — `compare_run` calls LLMs, not shell
- `getsentry/XcodeBuildMCP` — only tag-pinned action findings; major org, handled by Dependabot
- `firecrawl/firecrawl-mcp-server` — same
- `modelcontextprotocol/csharp-sdk` — same
- ~40 other queue entries — most are `mcp-desc-fetch` false positives now caught by the tightened regex (just pushed in `cc59e32`)

---

## Tracking — fill in as you submit

| # | Repo | Submitted | Channel | Advisory/Issue ID | Response | Fix landed |
|---|---|---|---|---|---|---|
| 1 | reflex-app/reflex | | | | | |
| 2 | alejandrosanchez1/backup | | | | | |
| 3 | sahilaa1719-ops/medspa-opus | | Public issue (PVR off) | | | |
| 4 | logistiga/PG1 | | | | | |
| 5 | ibis-project/ibis | | | | | |
| 6 | RoboSats/robosats | | | | | |
| 7 | ansible-lockdown/RHEL7-CIS | | | | | |
| 8 | modelcontextprotocol/python-sdk | | PVR | | | |

You said you submitted 3 — please add the advisory IDs above so I can update the tracking and start the 30-day clocks.

---

## Cron — keep the queue growing while you sleep

`scripts/patrol-auto.py` runs every 6h (when you set the cron line). The queue at `disclosures/queue/` grows. Each new draft gets a notification ping. **The queue is shadow output**; this DRAFTS-LIBRARY is the curated/verified subset that's safe to send. Keep this file as the source of truth; ignore the raw queue unless you want to manually verify more.

When the cron + Aug 15 launch ramp up, this becomes the operational rhythm:
- Cron scans
- You scan THIS file once a week
- For each verified-real entry → submit, mark, move on
- Aggregate counts (anonymous) go to `lictorai.com/in-the-wild` monthly

That's the "shadow scans, light serves" loop you described, fully operational.
