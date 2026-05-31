# 🚨 Lictor Submission Verification Protocol — 100% Certainty Gate

**Status:** MANDATORY before any bounty submission. No exceptions.
**Created:** 2026-05-26 (after Uphold spam-closure + dep-confusion 44% FP wave)

## The rule

**Do NOT submit any finding until ALL gates pass for that finding's class.**
If any gate is uncertain, classify as **"NEEDS HUMAN REVIEW"** and hold.
A held finding is better than a rejected/spam finding.

---

## Gates per finding class

### Subdomain takeover (Heroku / Vercel / Netlify / Azure / etc.)

**Critical lesson from Floqast HackerOne #3749215 closure ("spam — no proven impact"):**
Fingerprint match alone is NOT enough. Triagers need PROOF that the underlying
account/app NAME is currently claimable. The report must demonstrate this
without us actually claiming the asset.

- [ ] **DNS still resolves** to a takeover-class target (re-check immediately before submission)
- [ ] **HTTP response matches platform-specific "no app" fingerprint EXACTLY** (the documented string per platform, not a generic 404)
- [ ] **Status code matches expected** (404 for most; 503 only for Heroku "Application Error" which is ambiguous → MEDIUM only)
- [ ] **Body length plausible** for fingerprint (Heroku no-app is ~1.5KB; if response is 50KB+, may be a legit page that happens to contain the keyword)
- [ ] **24-hour re-verify** before filing (rules out transient outages misclassified as takeovers)
- [ ] **Manual eyeball** the page — does it actually look like an unclaimed app, or a real maintenance page?
- [ ] **Scope check** — the subdomain belongs to an org with an active bug-bounty program covering this asset
- [ ] **Underlying-name-claimability proof** — explicitly demonstrate in the report that:
    - Heroku: the app name in `<NAME>.herokudns.com` returns "There's nothing here, yet" (proves NAME unclaimed at Heroku, not just DNS dangling)
    - GitHub Pages: the github.io URL (`<USER>.github.io/<REPO>`) returns 404 (proves USER/REPO not claimed)
    - Vercel/Netlify: the underlying deployment URL returns "Deployment not found"
    - Azure App Service: NAME returns "404 Web Site not found" (Microsoft's documented unbound-name signal)
    - S3: `NoSuchBucket` error on direct `<bucket>.s3.amazonaws.com` GET
- [ ] **Real customer-facing context** — the subdomain shows up in the org's public docs, app config, or DNS as a customer-routable name (not just a forgotten internal test)
- [ ] **Severity wording** — report says "CRITICAL if claimed, currently CLAIMABLE" not "CRITICAL — already taken over". We didn't claim it. Triagers downgrade reports that overstate impact.

### Dependency confusion (npm / PyPI)

- [ ] **FP Class #23 specifier gate passes** (specifier is semver: `^x`, `~x`, `x.y.z`, `*`, `latest` — NOT `github:`, `git+`, `file:`, `link:`, `workspace:`, `npm:`, `http(s)://`)
- [ ] **Package STILL unclaimed** on public npm/PyPI (re-check immediately before submission — squat windows close fast)
- [ ] **Manifest is on the default branch** (not an old commit reference) — finding is stale otherwise
- [ ] **The package is actually referenced as a runtime/dev dependency** (not in description, comments, or examples)
- [ ] **The internal-scope name signals real internal use** (matches the org's known naming convention, not a typo or vanity scope)
- [ ] **Scope check** — the GitHub org maps to the bug-bounty-program org (not a subsidiary with separate ownership)

### Sourcemap exposure

- [ ] **URL still returns HTTP 200** (re-verify immediately before submission)
- [ ] **Content-type is `application/json` or `application/octet-stream`** (not `text/html` — that's an SPA fallback FP)
- [ ] **Body parses as valid JSON** with `version`, `sources`, `mappings` fields (it's a real source map, not a 404 page wearing a `.map` suffix)
- [ ] **Custom code revealed** (vs purely vendor library — vendor-only sourcemaps are LOW/INFO)
- [ ] **Host is in-scope** for the bug-bounty program

### Host-header injection

- [ ] **Reflection actually present** (re-verify with curl `-H "X-Forwarded-Host: attacker.example"`)
- [ ] **Reflection lands in EXPLOITABLE header**: `Set-Cookie`, `Location` (302 redirects), `Content-Security-Policy`, or response body where it's used as a URL
- [ ] **Context is auth-relevant**: `/login`, `/reset`, `/forgot-password`, `/verify` — generic page reflection is LOW
- [ ] **Endpoint actually generates URLs from the Host header** (e.g. password-reset emails) — pure header echo without URL-generation impact is LOW
- [ ] **In-scope for the bounty program**

### CORS credentials-reflection

- [ ] **FP Class #22 Bearer/Basic gate passes** (probed endpoint returns `Set-Cookie` OR no `WWW-Authenticate: Bearer/Basic`)
- [ ] **Server reflects Origin and ACAC: true** (re-verify with curl `-H "Origin: https://attacker.example"`)
- [ ] **Endpoint returns sensitive authenticated data** (not just empty 200) when accessed with cookies
- [ ] **In-scope for the bounty program**

### API key / credential leak (Stripe / OpenAI / Anthropic / etc.)

- [ ] **Key still present in the public source** (re-verify immediately — may have been rotated)
- [ ] **Key matches the official format** (`sk_live_*`, `sk-ant-api03-*`, `sk-proj-*`, etc.) — not a placeholder/dummy
- [ ] **Repo is NOT a known security-research / honeypot / test fixture** (check repo name + description)
- [ ] **Use the correct routing** (security@stripe.com for Stripe keys; usersafety@anthropic.com for Anthropic abuse; etc. — check provider's documented routing)

### Typosquat / phishing domain

- [ ] **Not a defensive registration**: check redirect — does the squat 301/302 to the legit canonical?
- [ ] **Not a legit alternate property**: WHOIS check + SSL cert SAN check (does the squat share infrastructure with the legit org?)
- [ ] **Wallet-drainer pattern confirmed**: deep content analysis shows known drainer-kit signatures, not just wallet-connect UI
- [ ] **Discovered via Wayback Machine first-seen date** — recent registrations + no historical content = more likely phishing

### GitHub Actions `pull_request_target` RCE

- [ ] **Workflow triggers `pull_request_target`** (re-verify on default branch)
- [ ] **Workflow checks out attacker-controlled ref** (`github.event.pull_request.head.sha` or `head.repo.full_name`)
- [ ] **Workflow executes code after checkout** (npm install, pip install, build, test, custom action with attacker-controllable input)
- [ ] **GITHUB_TOKEN or other secrets are accessible** to the executed code
- [ ] **No gate** (no required label, no maintainer approval) blocking the malicious PR from triggering

---

## Pre-submission checklist (every submission)

Before clicking "Submit" on any platform:

- [ ] All class-specific gates above PASS
- [ ] Re-verified within last 6 hours
- [ ] Scope: target is in the program's published scope (read the program page!)
- [ ] No similar report from us is already in triage for the same finding (avoid dup-tagging ourselves)
- [ ] Severity is appropriately scored (do NOT inflate to attract triage — triagers downgrade and that hurts our reputation)
- [ ] Audit-trail line ("I did NOT...") included
- [ ] Disclosure window stated (60-day standard)

## What happens to "NEEDS HUMAN REVIEW"

- Goes into `/Users/raffa/Lictor/disclosures/needs-human-review/` (NOT submitted)
- Reviewed at weekly cadence with fresh eyes
- Either promoted to submission OR killed with a documented FP-class

## FP catalog (lessons learned)

- #1-13: documented in tasks #38-46
- **#19**: trusted-publisher native install (npm postinstall) — gate via download count
- **#20**: redirect-defensive registration (typosquat) — gate via follow-redirect-to-legit
- **#21**: legit-alt-property (typosquat) — gate via SSL SAN match
- **#22**: Bearer/Basic API CORS reflection — gate via WWW-Authenticate probe
- **#23**: non-registry specifier in package.json — gate via specifier-prefix check
- New FP classes get added HERE the moment they're discovered.

---

**This protocol exists because we shipped wrong findings. It will not happen again.**
