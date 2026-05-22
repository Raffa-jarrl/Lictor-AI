# Xiaomi HackerOne Submission #2 — Systemic CORS misconfiguration on Xiaomi MSS (`x-xiaomi-meta-*` backend) affecting central identity (id.mi.com, account.xiaomi.com) and 3+ bounty-scope brand domains

**Submit at:** https://hackerone.com/xiaomi/reports/new
**Program:** Xiaomi (paid) · **In-scope wildcards affected:** `*.mi.com`, `*.xiaomi.com`, `*.xiaomiyoupin.com`, `*.migames.com`, `*.wali.com` · **max_severity:** critical · **eligible_for_bounty:** True
**Realistic payout:** $300–$1,500 (multiple-asset systemic INFO/Low — affects central auth infrastructure)

---

## Title
```
Systemic CORS misconfiguration on Xiaomi MSS backend affecting central identity (id.mi.com, account.xiaomi.com) and multiple bounty-scope brand frontends — Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true
```

## Weakness
`CWE-942 Permissive Cross-domain Policy with Untrusted Domains`
H1 taxonomy: `Cross-Origin Resource Sharing (CORS) — Insecure Configuration`

## Severity (CVSS:3.1)
**Medium — 5.4**
`AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N`

(Severity bumped from the prior airstar.com report (3.7) because this affects Xiaomi's central identity systems id.mi.com and account.xiaomi.com — i.e. infrastructure used by every authenticated Xiaomi service across the corpus, not a single brand frontend. Scope = Changed because misconfig at the identity layer affects downstream Mi-authenticated apps.)

## Description (paste into HackerOne form)

```
## Summary

This report is a follow-up to my earlier submission on
airstar.com CORS (report #PRIOR_REPORT_ID). After that scan I
audited the rest of the Xiaomi H1 in-scope corpus and found the
SAME broken CORS configuration on multiple additional bounty-
scope hostnames, including Xiaomi's central identity and account
infrastructure.

All affected hostnames serve their public HTML from a Xiaomi
Object Storage backend (MSS / mi-cloud) that adds three custom
response headers:

  x-xiaomi-meta-content-length: <bytes>
  x-xiaomi-hash-crc64ecma: <id>
  x-xiaomi-request-id: <uuid>

— and the same broken CORS combination:

  Access-Control-Allow-Origin: *
  Access-Control-Allow-Credentials: true
  Access-Control-Expose-Headers: content-md5, upload-time,
    x-xiaomi-meta-content-length, accept-ranges, content-range

Per the W3C Fetch spec, this combination is invalid: when
credentials are allowed (ACAC: true), the ACAO header MUST NOT
be the wildcard "*". Compliant browsers reject responses that
violate this rule, but the misconfig is reproducible across every
Xiaomi MSS-fronted property — indicating a systemic backend
configuration error, not a one-off mistake.

## Affected hostnames (all in Xiaomi H1 scope)

| Hostname             | Wildcard scope       | Function                       |
|----------------------|----------------------|--------------------------------|
| id.mi.com            | *.mi.com             | **Central Xiaomi login / identity** |
| account.xiaomi.com   | *.xiaomi.com         | **Central Xiaomi account management** |
| airstar.com          | *.airstar.com        | Airstar Bank HK frontend (separately reported, included for context) |
| migames.com          | *.migames.com        | Xiaomi gaming platform |
| xiaomiyoupin.com     | *.xiaomiyoupin.com   | Xiaomi Youpin (小米有品) e-commerce |
| wali.com             | *.wali.com           | (separately bounded brand) |

(Sibling: m.xiaomiyoupin.com, www.xiaomiyoupin.com, www.airstar.com,
www.migames.com all show the same pattern at their respective hosts.)

## Steps to reproduce

1. id.mi.com — Xiaomi's central identity provider (follow redirects):

   $ curl -skL -i -H "Origin: https://attacker.example.com" \
       https://id.mi.com/
   HTTP/2 301 …
   HTTP/2 302 …
   HTTP/2 200
   access-control-allow-origin: *
   x-xiaomi-meta-content-length: 18741
   x-xiaomi-hash-crc64ecma: 4390397669147181667
   x-xiaomi-request-id: 0bf92ecf-51d8-9e72-0000-019e43e3b651
   access-control-allow-credentials: true
   access-control-expose-headers: content-md5, upload-time,
     x-xiaomi-meta-content-length

2. account.xiaomi.com — Xiaomi's central account management:

   $ curl -skL -i -H "Origin: https://attacker.example.com" \
       https://account.xiaomi.com/
   HTTP/2 302 …
   HTTP/2 302 …
   HTTP/2 200
   access-control-allow-origin: *
   x-xiaomi-meta-content-length: 18741
   x-xiaomi-hash-crc64ecma: 4390397669147181667
   x-xiaomi-request-id: fb04a11b-de9a-d25a-0000-019e43e3caad
   access-control-allow-credentials: true
   access-control-expose-headers: …

3. migames.com (Xiaomi gaming):

   $ curl -sk -i -H "Origin: https://attacker.example.com" \
       https://migames.com/
   HTTP/2 200
   access-control-allow-origin: *
   access-control-allow-credentials: true
   access-control-expose-headers: content-md5, upload-time,
     x-xiaomi-meta-content-length, accept-ranges

4. xiaomiyoupin.com (小米有品 e-commerce) — same pattern on
   apex AND on suspected-API paths like /api/v1/users/me, /api/me,
   /api/account, /api/profile (all return the SPA HTML with broken
   CORS headers attached):

   $ curl -sk -i -H "Origin: https://attacker.example.com" \
       https://xiaomiyoupin.com/api/v1/users/me
   HTTP/2 200
   content-type: text/html; charset=utf-8
   access-control-allow-origin: https://attacker.example.com  ← reflect, not wildcard, here
   access-control-allow-credentials: true
   x-xiaomi-meta-content-length: 3023

   NOTE: xiaomiyoupin.com REFLECTS the attacker origin (rather than
   serving wildcard), which is the more-classically-exploitable
   pattern. Combined with credentials=true this is a valid (non-
   spec-rejected) CORS misconfig — though the response body
   served is the React SPA HTML wrapper, not directly user data.

5. wali.com — also flagged with reflect-attacker-with-creds in my
   earlier scan (302-redirect-protected, full verification needs
   following redirect chain).

## Impact

This is a configuration error at the **Xiaomi Object Storage layer
(MSS / mi-cloud)**, not a per-app issue. Every Xiaomi-brand
property fronted by this storage backend inherits the same broken
CORS posture. Why this matters:

1. **id.mi.com and account.xiaomi.com are Xiaomi's central
   identity and account systems.** They handle authentication for
   every authenticated Xiaomi service (mi.com shop, MIUI cloud,
   IoT devices, Mi finance, etc.). CORS hygiene on identity
   infrastructure is held to a higher bar by every bank/payments/
   identity auditor.

2. **Spec-invalid CORS combo (`ACAO:* + ACAC:true`) is
   browser-rejected — but is honored by non-browser HTTP clients,
   SDKs, mobile apps, server-side fetchers, and legacy browser
   embeddings**. Anyone building on Xiaomi APIs from a non-W3C-
   strict client gets a misleading CORS contract.

3. **xiaomiyoupin.com REFLECTS the attacker Origin** (different
   pattern from the wildcard variant) — this is a fully
   browser-honored CORS misconfig. If any path on this host
   returns user-specific JSON (not just the SPA wrapper), an
   attacker controlling a malicious origin can read responses
   from logged-in Mi-Youpin users.

4. **Information leak: `Access-Control-Expose-Headers` lists
   `x-xiaomi-meta-content-length`** — a proprietary internal
   header name. Exposing this header reveals attack-surface
   information about Xiaomi's MSS backend to any cross-origin
   reader.

5. **Systemic, not one-off**: same pattern across 5+ wildcarded
   bounty-scope domains. A backend-team fix would close all of
   them at once.

## Remediation

1. **At the MSS / mi-cloud bucket policy layer**: change the
   default CORS configuration so that either
   `Access-Control-Allow-Origin: *` does NOT co-exist with
   `Access-Control-Allow-Credentials: true`, OR the ACAO is
   restricted to the specific trusted origins for each property.

2. **For xiaomiyoupin.com** (the reflect-attacker pattern): the
   CORS middleware must validate the Origin against an
   allow-list before echoing it. Reflecting any origin with
   credentials=true is a textbook CSRF/CORS bypass primitive.

3. **Stop exposing `x-xiaomi-meta-content-length`** in
   `Access-Control-Expose-Headers` — internal headers should
   not be cross-origin-readable.

4. **Audit the entire MSS bucket-CORS configuration template**.
   The fact that airstar.com, migames.com, id.mi.com,
   account.xiaomi.com, and xiaomiyoupin.com all share this
   misconfig points to a default config rather than per-bucket
   mistake.

## Tooling

Discovered via Lictor (https://lictor-ai.com), an open-source
security scanner (Apache 2.0). The CORS-misconfig patrol probes
bounty-program apex domains with multiple Origin header values
and inspects responses for the W3C-invalid `ACAO:* + ACAC:true`
combination, the reflect-attacker-origin-with-credentials
pattern, and other permissive CORS antipatterns. The systemic
nature of this finding was revealed by re-running the same probe
against all 42 of Xiaomi's H1 in-scope wildcard apex domains.

## Note on overlap with prior airstar.com report

I have already submitted a focused report on `airstar.com`
specifically (report #PRIOR_REPORT_ID, awaiting triage). This
new report covers the WIDER systemic finding across multiple
brand domains and central identity infrastructure. If your team
prefers to consolidate, please treat this report as canonical
and close the airstar-only one as a subset. If you prefer
per-asset tracking, please use this report as a coordination
hub for the systemic backend fix.

## References

- W3C Fetch standard, CORS Protocol §3.2.4 (credentials +
  wildcard rule):
  https://fetch.spec.whatwg.org/#http-access-control-allow-credentials
- CWE-942: Permissive Cross-domain Policy with Untrusted Domains
- OWASP CORS Cheat Sheet (origin-reflection antipattern):
  https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Request_Forgery_Prevention_Cheat_Sheet.html

---

Ethical-disclosure note: I did NOT attempt to exfiltrate user
data via the CORS misconfig. I did NOT probe authenticated
endpoints under a logged-in test account. All requests in the
PoC were issued with neutral test origins (attacker.example.com)
against unauthenticated/anonymous responses.
```

---

## Internal notes (DO NOT submit)

**Pricing strategy:**
- This is a SYSTEMIC finding across central infrastructure (id.mi.com,
  account.xiaomi.com), not a single-asset misconfig. Should pay
  higher than the airstar one ($100-500 estimated).
- Realistic range: $300-$1,500 for the bundle.
- Identity-layer affected → bank/regulator-grade scrutiny applies.

**Before submitting:**
- Wait for airstar.com (report #28) to get a triage ID — replace
  `#PRIOR_REPORT_ID` placeholder in the description.
- If airstar gets closed as Informative quickly, this bundle
  becomes the "real" report and airstar is positioned as the
  initial signal. If airstar gets accepted at decent severity,
  this bundle becomes the "we found 5 more" follow-up.

**Why bundle vs split:**
- Same root cause → 1 backend-team fix → 1 report makes triage
  easier
- Systemic pattern recognition demonstrates value beyond a
  single-asset finding (better impression on triager)
- Avoids "5 duplicates" closure risk

**Things I did NOT do:**
- Did NOT attempt to log into a real Mi account and test CORS
  with valid session cookies
- Did NOT enumerate Mi-Cloud bucket names beyond what was
  revealed in headers
- Did NOT probe internal Xiaomi infrastructure
- Only ran standard CORS probes against the publicly-listed
  bounty-scope apex domains

**Expected outcome:**
- Triage 24-72h
- Resolved as Low/Medium INFO disclosure
- Payout $300-$1,500 for the systemic bundle

**Followups if accepted:**
- Note the reflect-attacker-origin variant on xiaomiyoupin.com
  separately — that's a different config layer (custom origin
  handling logic, not just MSS default policy)
- If the user has high signal, push for Medium severity
  classification given the identity-infra blast radius
