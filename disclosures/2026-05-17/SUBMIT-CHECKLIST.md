# Disclosure submission checklist — 2026-05-17

> **5 verified-real findings ready to submit.** Each one is either a private security advisory (PVR-enabled) or a public contact-request issue (PVR-disabled).
> Work through these at your own pace. Tabs keep closing in MCP sessions; this checklist is browser-state-independent.

---

## ✅ #1 — `modelcontextprotocol/python-sdk` (PVR enabled, tab already filled)

**Status:** Tab `1477344636` is already open in Chrome with the form populated. Title is "Draft Advisory · modelcontextprotocol/python-sdk".

**Action:** Switch to that tab → scroll to bottom → click green **"Submit report"** button.

If tab closed: open `https://github.com/modelcontextprotocol/python-sdk/security/advisories/new` and paste from `disclosures/2026-05-17/01-anthropic-mcp-servers.md`.

---

## 🔴 #2 — `sahilaa1719-ops/medspa-opus` — Supabase service-role JWT in client code (PVR DISABLED)

**The bug:** `src/lib/supabaseAdmin.ts` line 16 hardcodes a Supabase service-role JWT as fallback. Decoded payload confirms `role=service_role`, `ref=tjrophtadiovtimgobsf`, valid until **2035-12-13** (10 years).

**Channel:** PVR returns 404 → use **public contact-request issue**, NOT details.

**URL to open:** https://github.com/sahilaa1719-ops/medspa-opus/issues/new

**Title to paste:**
```
Security report (please contact privately)
```

**Body to paste:**
```
Hi —

I have a security finding to share with you privately. I'm not posting details here for responsible-disclosure reasons.

Please contact me at raffa@lictorai.com (or DM via GitHub) and I'll send the full report.

The issue is high-severity and time-sensitive. Apologies for the indirect channel — your repo doesn't have private security advisories enabled, and I didn't want to publish details that could be exploited.

— Raffa
Lictor AI · https://lictorai.com · github.com/Raffa-jarrl/Lictor-AI
```

Click **"Submit new issue"** at the bottom.

---

## 🔴 #3 — `logistiga/PG1` — Supabase service-role JWT in test config (PVR likely DISABLED)

**The bug:** `vitest.config.ts` line 16 hardcodes a Supabase service-role JWT. Even though it's in test config (and could be a test fixture), the JWT decodes to a real `role=service_role` token with `ref=sddylemgwftvatzfrjer`, valid until **2035-02-13**. Maintainer needs to verify whether the Supabase project is real-production or a sandbox.

**Channel:** Try PVR first → fallback to public issue

**URL to try first:** https://github.com/logistiga/PG1/security/advisories/new
- If form loads: use the medspa-opus template, adjust title to mention "Supabase service-role JWT in vitest.config.ts"
- If 404: open contact-request issue at https://github.com/logistiga/PG1/issues/new with the body from #2 above

---

## 🔴 #4 — `alejandrosanchez1/backup` — Supabase service-role JWT (PVR likely DISABLED — from yesterday's scan)

**The bug:** `app/AdminView.tsx` line 14 — same hardcoded-fallback pattern. JWT decodes to `role=service_role`, `ref=wrjenrtnojmhianqzxlo`, valid until **2036-02-09**. Vercel deployment is gone but source is still public.

**Channel:** Try PVR first → fallback to public issue

**URL to try first:** https://github.com/alejandrosanchez1/backup/security/advisories/new
- If form loads: use the medspa-opus template, adjust title
- If 404: open contact-request issue at https://github.com/alejandrosanchez1/backup/issues/new

---

## 🟠 #5 — `RoboSats/robosats` — pull_request_target + checkout-PR-head RCE (988 stars, likely PVR enabled)

**The bug:** `.github/workflows/py-linter.yml` lines 11+25 — workflow uses `pull_request_target` AND checks out `${{ github.event.pull_request.head.sha || github.ref }}`. Classic RCE class: any attacker-opened PR runs code with the repo's secrets in scope.

**URL to try first:** https://github.com/RoboSats/robosats/security/advisories/new

**Title:**
```
pull_request_target workflow checks out PR head — RCE on main branch via malicious PR
```

**CVSS:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:L`

**Body:** Full version in `disclosures/2026-05-17/02-punkpeye-mcp-servers.md` — copy from there, replace `<repo-name>` with `RoboSats/robosats`, and reference the specific file `.github/workflows/py-linter.yml` line 25 (the `ref:` line).

If PVR returns 404: open public issue with contact-request template.

---

## After each submission

1. **Save the advisory ID** (URL becomes `.../security/advisories/GHSA-xxxx-xxxx-xxxx`) — paste here as you go
2. **Update** `disclosures/2026-05-17/tracking.md` (or append to this file):
   - submission timestamp
   - response received (Y/N)
   - fix shipped (Y/N + commit hash)
3. **30-day clock starts** for each submission

---

## Tracking — fill in as you go

| # | Repo | Channel | Submitted at | Advisory/Issue ID | Maintainer response | Fix landed |
|---|---|---|---|---|---|---|
| 1 | modelcontextprotocol/python-sdk | PVR | | | | |
| 2 | sahilaa1719-ops/medspa-opus | Public issue | | | | |
| 3 | logistiga/PG1 | PVR or Issue | | | | |
| 4 | alejandrosanchez1/backup | PVR or Issue | | | | |
| 5 | RoboSats/robosats | PVR or Issue | | | | |

---

## What we deliberately are NOT submitting from the 56-draft queue tonight

After verification:

- **mcp-use/mcp-use** — Scanner flagged 2 critical `mcp-desc-fetch` findings, but verification shows descriptions are static string literals. **False positive.** Scanner regex `DESC_FETCHY_RX` is too loose.
- **Gindhar2112/frida-mcp** — Scanner flagged exec tools without sandbox. Frida itself IS a code-injection toolkit; exec tools are the intended functionality. **Context false positive.**
- **Cristophereasygoing927/compare-mcp** — Scanner flagged `compare_run` as an exec tool name. Function actually calls LLMs, not shell. **False positive.**
- **getsentry/XcodeBuildMCP, firecrawl/firecrawl-mcp-server, modelcontextprotocol/csharp-sdk** — All findings are tag-pinned third-party actions (HIGH per CWE-829 but operationally minor). Major orgs already manage this via Dependabot. Sending formal security advisories for this would read as scanner noise and damage the brand. Worth a friendly PR or issue, not a CVE-style disclosure.
- **The other ~50 queue files** — mix of false-positive `mcp-desc-fetch` (the loose regex) + legitimate tag-pinned-action findings. Each needs individual verification before sending. Patrol-auto will keep the queue updated; verify in batches.

This is the responsible-disclosure-at-scale operating model:
- Patrol scans broadly
- The queue is everything that LOOKS actionable
- A human pass eliminates false positives and triages by severity/leverage
- Only verified-real findings get sent
- Aggregate stats (count of repos scanned, count of REAL findings, distribution of pattern types) goes to the public monthly transparency report
