# Lictor Anti-False-Positive Catalogue

Every false-positive class Lictor's scanners have encountered, documented as
filter rules. This is the most valuable single artifact in the codebase —
each class represents a real disclosure mistake we caught **before** sending
it, plus the code fix that prevents repetition.

The discipline: **a finding that looks impressive but isn't real damages the
brand more than 100 missed findings.** Procurement at a Fortune 500 will reject
Lictor immediately if they see one "you have an admin panel exposed!" report
that turns out to be a 404 page. Anti-FP rigor is the product.

---

## FP Class #1 — Diverse-shape canaries

**Discovered:** Day 1 of patrol scanning
**Symptom:** Scanner reports finding "exposed `/admin` path" on every domain — even ones that don't have one
**Root cause:** Many sites return `200 OK` with the homepage content for ANY non-existent path (SPA routing, marketing-site wildcards). Our canary was only `/admin` — too narrow to detect the wildcard pattern.
**Fix:** Use multiple canary paths of different shapes (`/admin`, `/zzz-lictor-canary-XXXX`, `/_/random/path`) and compare responses. If all canaries return identical bodies, the host is a wildcard — skip.
**Code:** `v3/scripts/scanners/scan-il-crm-paths.py:probe_with_canaries()`

---

## FP Class #2 — HEAD-CL canary (apples-to-apples Content-Length)

**Discovered:** Day 1, after the first FP wave
**Symptom:** GET-based canary returns different sizes than the real probed path because servers gzip/cache differently
**Root cause:** Comparing `len(GET /admin response)` to `len(GET /canary response)` isn't reliable — encoding/transfer differs.
**Fix:** Use `HEAD` requests and compare Content-Length headers. Identical CL = same payload = wildcard.
**Code:** `v3/scripts/scanners/scan-il-crm-paths.py`

---

## FP Class #3 — Text/HTML drop on JSON-expected endpoints

**Discovered:** Day 1
**Symptom:** Scanner reports "exposed `/api/admin`" but the response is the homepage HTML
**Root cause:** Server returned `200 OK` with `Content-Type: text/html` for an API path — that's a SPA fallback, not an API.
**Fix:** If the probed path is an API endpoint (`/api/`, `/v1/`, `/graphql`) and the response Content-Type is `text/html`, classify as FP.
**Code:** Applied across all scanners that probe API endpoints.

---

## FP Class #4 — Post-hoc CL-cluster dedup

**Discovered:** Day 2
**Symptom:** Same host reports 50 different "exposed paths" — all with identical Content-Length
**Root cause:** A single wildcard pattern caught 50 different probes — each one gets logged as a separate finding. They're all the same FP.
**Fix:** After scanning, group findings by host + Content-Length. If 3+ paths cluster on the same CL, mark all but the smallest as FP-by-clustering.
**Code:** Post-scan dedup pass in `v3/scripts/lictor-report.py`

---

## FP Class #5 — Wrong-shape endpoint

**Discovered:** Day 2
**Symptom:** Scanner reports "wallet exposure" on news sites (BuzzFeed, Reddit, Forbes) finding `/wallet.json`
**Root cause:** Many news/social sites have a `/wallet.json` endpoint for tracking user engagement (`{"user_uuid": "..."}`) — totally unrelated to crypto wallets.
**Fix:** Validate the response body for crypto-wallet markers (`mnemonic`, `private_key`, BIP39 seed words, `0x[40 hex]` addresses). If absent, it's the wrong wallet.
**Code:** `v3/scripts/scanners/scan-wallet-files-v2.py:is_real_wallet_content()`

### #5a — GitHub test fixtures matching credential regex

**Discovered:** Day 3
**Symptom:** Scanner finds "DEPLOYER_PRIVATE_KEY in .env" on Compound Finance, Uniswap, Lido — all top-tier audited protocols
**Root cause:** The matched file is `.env.example`, `.env.sample`, or `test_keys.env` — documentation files showing variable NAME but not the actual key value. Or the value is the well-known Anvil/Hardhat test private key (`0xac0974be...`) which holds $0.
**Fix:** Strict path exclusion: `/test/`, `/tests/`, `__tests__/`, `/spec/`, `/__mocks__/`, `/fixtures/`, `.example`, `.sample`, `.template`, `/example/`, `/demo/`. Plus exclude known test keys by content.
**Code:** `v3/scripts/scanners/scan-github-defi-secrets-v2.py:PATH_FP_FRAGMENTS`

---

## FP Class #6 — Shopify Storefront API GraphQL (intentionally public)

**Discovered:** Day 3
**Symptom:** Scanner reports "GraphQL introspection enabled in production" on Decathlon, Charles River, Fox.co.il, etc. — all returning 415 types + Mutation
**Root cause:** Shopify's Storefront API is **intentionally publicly accessible** with introspection enabled. It's a designed feature, not a misconfiguration. Detected by `_shopify_essential` cookie and `x-shopify-api-version` header.
**Fix:** Before flagging GraphQL introspection as a vulnerability, check vendor fingerprint headers. If `Shopify` is in the response chain, skip.
**Code:** `v3/scripts/scanners/scan-graphql-introspection.py:is_shopify_storefront()`

---

## FP Class #7 — WAF anti-recon (accept-all-ports)

**Discovered:** Day 4
**Symptom:** Scanner reports "RDP exposed on Bank Hapoalim" (a major Israeli bank — clearly NOT the kind of mistake they would make)
**Root cause:** Imperva and Cloudflare WAFs silently accept TCP connections on ALL ports as anti-reconnaissance behaviour. A simple `socket.connect()` returns success even when nothing is listening behind. Looks like "RDP/3389 open" to a naive scanner.
**Fix:** Send a real protocol handshake. RDP: `\x03\x00\x00\x13\x0e\xe0...` and expect a specific reply prefix. SMB: Negotiate Protocol Request. FTP: expect `220` banner. If no protocol-level response → WAF anti-recon, NOT exposed.
**Code:** `v3/scripts/scanners/scan-ransomware-exposure-v2.py:probe_rdp/smb/ftp()`

---

## FP Class #8 — Vendor-name collision in bucket scanner

**Discovered:** May 2026 launch sprint, while preparing customer disclosure drafts
**Symptom:** Scanner flagged "safe-storage" bucket, attributed to Gnosis Safe ($1M Immunefi program). Content turned out to be Danish digital-safety education videos.
**Root cause:** Scanner tags by name match (`safe-anything` → assume Gnosis Safe). But the bucket owner is whoever bought that S3/GCS name first. `polygon` bucket might belong to Polygon Labs or Polygon.com (3D modeling).
**Fix:** Before attributing a bucket to a brand, verify ownership via content fingerprint (Rails Sprockets manifest pattern, webpack hash, language detection, DNS owner lookup). Without content evidence, attribution is unsafe.
**Code:** TODO — needs implementation in `v3/scripts/scanners/scan-buckets-massive.py`

---

## FP Class #9 — Sourcemap content quality (existence ≠ exploitable)

**Discovered:** May 2026, after HackerOne triagers closed Visa + Expedia sourcemap reports as Informative
**Symptom:** Scanner reports "292 hosts have frontend source code leaks." Actual reality: most sourcemaps contain only Stencil.js framework boilerplate (2.6KB of vendor code), no customer logic.
**Root cause:** "Sourcemap file exists at URL" is true. "Sourcemap reveals proprietary code" requires content analysis — count custom source paths (non-`node_modules`), check `sourcesContent` size, extract internal URLs/API paths.
**Fix:** Tier classification:
- **HIGH:** ≥5K chars custom code + internal endpoints or hardcoded secrets
- **MEDIUM:** ≥10K chars custom code, no endpoints
- **LOW:** <5K chars custom (framework boilerplate)
- **EMPTY:** <500 bytes or unparseable

Applied: 292 raw findings → 44 HIGH / 81 MEDIUM / 116 LOW / 45 EMPTY. **The validated 44 is what we publish, not the inflated 292.**
**Code:** `v3/scripts/scanners/validate-sourcemap-content.py:analyze_sourcemap()`

---

## FP Class #10 — Generic JSON-200 error wrapper APIs

**Discovered:** May 2026, while verifying a "5 critical admin API exposure" finding on bingx.com (major crypto exchange)
**Symptom:** Admin panel scanner reports `200 OK` with `application/json` content-type on `/api/admin`, `/api/admin/users`, `/api/admin/settings` — looks like a CRITICAL exposed admin API on a top-tier exchange
**Root cause:** BingX's API returns `{"code":100003,"msg":"Your device's time is incorrect","success":false}` for **every** unauthenticated request — including completely fake paths like `/api/lictor-baseline-doesnotexist-9387462`. Generic error wrapper looks like real API output to a HEAD-only scanner.
**Fix:** Before flagging JSON-200 as a real finding, probe a definitely-fake baseline path. If the flagged endpoint returns a body identical to the fake-path baseline (after normalising timestamps/IDs), classify as `CATCHALL-FP`.
**Code:** `v3/scripts/scanners/scan-protocol-admin-panels.py:get_baselines() + normalize_body()`

---

## FP Class #11 — SPA fallback (HTML index.html for all routes)

**Discovered:** Same session as #10
**Symptom:** Admin panel scanner reports 758 "POTENTIAL-PANEL" findings across 80 tier-1 DeFi hosts. Every host has `/admin`, `/dashboard`, `/governance`, `/multisig` returning `HTML 200`.
**Root cause:** Single-page apps (React, Vue, Next.js, Nuxt) serve the same `index.html` for ANY route — `/admin`, `/anything-doesnt-exist`, `/foo` all return the same body. To a HEAD-only scanner, they all look like "admin panel exposed with no auth."
**Fix:** Fetch the home page (`/`) as baseline + a definitely-fake HTML route (`/lictor-fake-route-XXX`). If a flagged endpoint's body matches either baseline, classify as `SPA-FALLBACK-FP`.
**Code:** Same as #10 — handled by the unified baseline-compare in `get_baselines()`.

---

## FP Class #12 — Third-party library sourcemap attribution

**Discovered:** May 2026, while verifying 4 bounty-eligible drafts
**Symptom:** Validator classified `dydx.trade` as HIGH-tier sourcemap finding. Verified URL: `https://d2wy8f7a9ursnm.cloudfront.net/v7/bugsnag.min.js.map` — **Bugsnag's CDN**, not dydx.
**Root cause:** Site uses a CDN-served library (Bugsnag, Sentry, Azure Insights). The library's sourcemap is served from the library vendor's CDN. Scanner sees "host XYZ has sourcemap exposure" but the code inside belongs to the vendor.
**Fix:** Check if the sourcemap URL's netloc matches the host (or major subdomain). If not (URL is on a third-party CDN), classify as `VENDOR-CDN-FP`.
**Code:** Filter applied in `/tmp/build-chaos-corpus.py` and `generate-courtesy-disclosures.py:is_own_domain()`

**Caught at scale:** 49 of 87 courtesy-email drafts were FP #12. Would have sent "your bundle is leaking" to companies whose bundles aren't theirs.

---

## FP Class #13 — Self-hosted vendor library sourcemaps

**Discovered:** Same session as #12, during draft review
**Symptom:** Even after FP #12 filter, drafts to buyucoin.com referenced `buyucoin.com/js/bootstrap.bundle.min.js.map` — the URL IS on buyucoin's domain (passes #12), but the content is Bootstrap, not buyucoin's code.
**Root cause:** Many sites self-host vendor libraries (Bootstrap, HubSpot HsStatic, Adobe AEM, jQuery, GSAP) instead of using a CDN. The URL is on the host's own domain, but the code inside is OSS library code.
**Fix:** Pattern-match the URL path for vendor identifiers (`bootstrap`, `hsstatic`, `hubspot`, `jquery`, `lodash`, `moment`, `core-js`, `babel`, `polyfill`, `_catalogs/masterpage`, `adobe-aem`). If matched, classify as `VENDOR-SELF-HOSTED-FP`.
**Code:** Filter applied in `generate-courtesy-disclosures.py:VENDOR_PATTERNS`

**Caught at scale:** 9 additional FPs caught in the courtesy-draft review (Bootstrap on buyucoin/harman/heidelberg, HubSpot on delen.bank/be/lu/ch + cadelux/cadelam).

---

## Combined impact of FP filters #8–#13

Tonight's sourcemap-disclosure cohort:
```
91 raw drafts initially generated
-49 FP #12 caught (third-party CDN attribution)
- 9 FP #13 caught (self-hosted vendor library)
= 33 verified-clean drafts (eventually 29 sent via Gmail)

Plus from the bounty-eligible list:
4 of 4 drafts caught as FP #12 (dydx/Bugsnag, dotnet.microsoft/Azure Monitor,
                                  decentraland/marketing-only, galaxy/vendor bundle)
1 additional (binance.us → Sentry CDN, FP #12)
```

**62% of generated drafts were caught as FPs before being sent.** Without these
filters, the courtesy email cohort would have generated 49 misattributed
"your bundle is leaking" emails to companies whose bundles aren't theirs.
That would have caused real brand damage.

This is why anti-FP rigor is the product, not the scanners themselves.

---

## FP Class #14 — HEAD response Content-Type trusted

**Symptom**: A scanner's anti-FP filter uses the Content-Type from a HEAD
response to decide whether to engage. The filter never runs because the HEAD
returns a different Content-Type than the GET body.

**Example**: `streamlabscharity.com/metrics` returns:
- HEAD: `Content-Type: text/plain; charset=utf-8`
- GET body: 40 KB of HTML (SPA index.html)

Scanner gated FP #11 SPA-fallback check on `"html" in ct` (where ct came from HEAD).
The check never engaged, so 3 phantom DEBUG-EXPOSED findings shipped.

**Root cause**: Servers (especially behind Cloudflare or WAFs) can return
different headers on HEAD vs GET, including different Content-Type.

**Fix**: Always fetch the body, always compare against all baselines regardless
of HEAD's Content-Type. Use the GET response's CT if a CT check is needed.

**Code location**:
`v3/scripts/scanners/scan-protocol-admin-panels.py` line 290+
(see comment block tagged `FP #14`)

**Bonus fix shipped alongside**: prefix + size-fuzzy SPA-fallback match
(`SPA-FALLBACK-FP-FUZZY` verdict). Normalization can't catch every variable
token (CSRF, session-ID, build hash, nonce in script tags), so two-body
comparison: if first 500 bytes of normalized body match AND total sizes are
within 10%, classify as SPA fallback.

---

## FP Class #15 — Intentional public infrastructure endpoint

**Symptom**: Scanner flags `/health`, `/status`, `/ping`, `/ready` (or `/api/*`
variants) as "JSON-200 reachable" findings. These are *intentionally* public on
most stacks (Spring Boot Actuator, k8s liveness/readiness probes, AWS ALB
health checks). Flagging them as findings burns credibility.

**Example**:
- `paylution.com/health` returns `{"status":"UP","checks":[]}` (Spring Actuator default)
- `app.concrete.xyz/api/health` returns `{"ok":true}` (k8s probe pattern)
- `app.yuzu.money/api/health` returns `{"status":"ok","mode":"api","timestamp":...}`

These pass canary-different checks (real /health and fake-path responses ARE
different), so they look like real findings. But they're public by design.

**Root cause**: Confusing "endpoint is reachable" with "endpoint is a vulnerability."
A health endpoint is a vulnerability only if it leaks sensitive state (e.g.
`/actuator/env`, `/actuator/heapdump`) — the wrapper `/health` itself is fine.

**Fix**: In `classify_response()`, allow-list the known infra endpoint paths
(`/health`, `/healthz`, `/api/health`, `/status`, `/ping`, `/ready`, `/live`,
plus underscore-prefix variants) and classify as `PUBLIC-INFRA-ENDPOINT` /
`info` severity. The deeper-leak endpoints (`/actuator/*`, `/debug/*` with
real prometheus output) still get flagged.

**Code location**:
`v3/scripts/scanners/scan-protocol-admin-panels.py` line 208+
(see comment block tagged `FP #15`)

---

## FP Class #16 — WAF block page returns HTTP 200

**Symptom**: Scanner gets HTTP 200 on a "sensitive" path (e.g. `/admin.php`,
`/wp-admin/admin-ajax.php`) and flags it as POTENTIAL-PANEL. The body is
actually a WAF block-page — F5 BIG-IP ASM, Imperva, Cloudflare, Sucuri, etc. —
politely telling the scanner to go away while returning 200 instead of 403.

**Example**: `paylution.com` returned 200 on `/wp-admin/admin-ajax.php`,
`/admin.php`, `/admin/index.php` — all 3 with body:
```
<html><head><title>Request Rejected</title></head>
<body>The requested URL was rejected. Please consult with your administrator.
<br><br>Your support ID is: 16448510482374349072 ...
```

That's F5 BIG-IP ASM doing its job. Not a real exposure.

**Root cause**: Some WAFs return 200 + a block-page HTML body instead of the
more correct 403 / 451. The scanner sees `status=200` and a "title" element,
treats it as legitimate content. Each block-page has a unique support ID,
so normalize-and-compare against a baseline won't catch them either (no two
WAF blocks normalize to identical bytes).

**Fix**: Add a body-string check for known WAF block-page signatures:
- "Request Rejected" (F5 BIG-IP ASM)
- "The requested URL was rejected"
- "support ID is:" (F5 unique-per-response pattern)
- "Access Denied"
- "blocked by our security"
- "<title>Attention Required" (Cloudflare)
- "Sucuri WebSite Firewall"
- "Imperva Incapsula"
- "Akamai Reference"

If any of these appear in the body, classify as `WAF-BLOCKED-FP` / `info`.

**Code location**:
`v3/scripts/scanners/scan-protocol-admin-panels.py` line ~295
(see `waf_signatures` list)

**Validation result**: After FP #14 + #15 + #16 fixes, the 6-host test corpus
(streamlabscharity, bingx, paylution, app.uniswap, app.concrete.xyz, app.yuzu.money)
produced 0 findings — correct, since none of those hosts have a real admin panel
exposed. Before the fix: 9 findings (all FPs).

---

## How to add a new FP class

When a scanner produces a finding that turns out to be a false positive in
manual review:

1. Document the class here with: symptom, root cause, fix, code location
2. Implement the filter in the responsible scanner
3. Re-run the scanner on the same input — verify the FP is now filtered
4. Add a memory note at `~/.claude/projects/-Users-raffa-GenerationAI/memory/feedback_lictor_scanner_fp_classes.md`
5. Commit with message: `fix(v3): FP class #N — <short name>`

Calibration is a continuous process. The FP catalogue grows with experience.
That's a feature.
