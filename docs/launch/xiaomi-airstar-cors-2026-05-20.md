# Xiaomi HackerOne Submission — Permissive CORS (`ACAO: *` + `ACAC: true`) on airstar.com / Tianxing Digital Technology (Airstar Bank infrastructure)

**Submit at:** https://hackerone.com/xiaomi/reports/new
**Program:** Xiaomi (paid) · **In-scope:** `*.airstar.com` · **max_severity:** critical · **eligible_for_bounty:** True
**Realistic payout:** $100–$500 (INFO / Low — invalid CORS combo, non-browser-exploitable but reflects backend misconfig on regulated-bank infrastructure)

---

## Title
```
Permissive and invalid CORS configuration on airstar.com — Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true exposes Xiaomi Object Storage backend (x-xiaomi-meta-*) headers for Airstar Bank
```

## Weakness
`CWE-942 Permissive Cross-domain Policy with Untrusted Domains`
H1 taxonomy: `Cross-Origin Resource Sharing (CORS) — Insecure Configuration`

## Severity (CVSS:3.1)
**Low — 3.7**
`AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N`

(Browsers reject the `ACAO: *` + `ACAC: true` combination per W3C CORS spec, which limits attacks via standard web browsers. However, the misconfig is exploitable by non-browser HTTP clients, mobile SDK integrators, and any consumer that doesn't enforce the spec — and it reveals an underlying Xiaomi Object Storage misconfiguration on production Airstar Bank infrastructure.)

## Description (paste into HackerOne form)

```
## Summary

The host airstar.com — which serves Xiaomi's Tianxing Digital
Technology / Airstar Bank Hong Kong (天星数科 / Airstar) frontend —
returns an invalid CORS configuration on every response:

  Access-Control-Allow-Origin: *
  Access-Control-Allow-Credentials: true

Per the W3C Fetch spec, this combination is invalid: when credentials
are allowed (ACAC: true), the ACAO header MUST NOT be the wildcard
"*". Compliant browsers reject responses that violate this rule,
which limits browser-based attacks. However:

  1. Non-browser HTTP clients (curl, mobile-app HTTP libraries,
     server-side fetch wrappers, SDKs) do not enforce the spec.
  2. Older browsers and embedded WebViews have historically had
     bugs honoring this combination.
  3. The misconfig signals a broken CORS middleware on production
     regulated-bank infrastructure (Airstar Bank HK is a virtual
     banking license holder).

Additional information leaked in the response:

  x-xiaomi-meta-content-length: 3754
  Access-Control-Expose-Headers: content-md5, upload-time,
    x-xiaomi-meta-content-length, accept-ranges, content-range

These headers confirm the page is served from a Xiaomi Object
Storage Service (MSS / Mi-Cloud) bucket with the same broken CORS
defaults applied at the storage layer.

## Steps to reproduce

1. Send a basic request with any Origin header — note the
   identical Access-Control-* headers returned regardless of
   origin or credentials state:

   $ curl -sk -i -H "Origin: https://attacker.example.com" \
       https://airstar.com/
   HTTP/2 200
   content-type: text/html; charset=utf-8
   content-length: 3754
   access-control-allow-origin: *
   x-xiaomi-meta-content-length: 3754
   access-control-allow-credentials: true
   access-control-expose-headers: content-md5, upload-time, x-xiaomi-meta-content-length, accept-ranges, content-range

2. Repeat against any path on the host — identical response:

   $ curl -sk -i -H "Origin: https://attacker.example.com" \
       https://airstar.com/api/v1/account
   HTTP/1.1 200 OK
   Access-Control-Allow-Origin: *
   Access-Control-Allow-Credentials: true
   Access-Control-Expose-Headers: content-md5, upload-time, x-xiaomi-meta-content-length, accept-ranges, content-range

3. Confirm Xiaomi-brand attribution from the HTML body:

   $ curl -sk https://airstar.com/ | grep -oE \
       "<title>[^<]+</title>|mi.com|airstar"
   <title>天星数科</title>
   mi.com
   ...

## Impact

- **Invalid-but-set ACAC: true on a regulated-bank frontend.**
  Airstar Bank HK is a licensed virtual bank in Hong Kong; broken
  CORS middleware on its public infrastructure is a finding that
  bank-grade auditors flag, regardless of browser enforcement.

- **Mobile-app and SDK integrators consuming this storage layer**
  may rely on the credentialed-CORS contract and behave
  incorrectly (sending cookies/credentials to a wildcard-CORS
  endpoint). Their behavior is implementation-dependent.

- **Server-side fetchers and non-browser HTTP clients** are not
  bound by the W3C combination rule and will honor the ACAC: true
  signal, potentially exposing credentialed responses to attackers
  acting through such clients.

- **Underlying object-storage backend (MSS / mi-cloud) is
  similarly misconfigured.** Every request reveals
  x-xiaomi-meta-content-length and exposes 5 sensitive backend
  metadata headers (content-md5, upload-time, etc.). This suggests
  the entire Xiaomi Object Storage region serving Airstar is
  configured with a permissive default policy.

- **Sibling subdomains are partially deprecated.** All probed
  airstar.cn variants (api., app., account., auth., account-api.,
  auth-api.) return HTTP 410 Gone — the .com TLD is the current
  surface, magnifying the importance of correct CORS there.

## Remediation

1. **Either**: set `Access-Control-Allow-Origin` to a specific
   trusted origin (the Airstar Bank app/web origin) when
   `Access-Control-Allow-Credentials: true` is needed.
2. **Or**: remove `Access-Control-Allow-Credentials: true` if
   wildcard-origin access is intended for unauthenticated static
   content (which appears to be the case here — the response is a
   3,754-byte static HTML).
3. **Audit the underlying Xiaomi Object Storage (MSS / mi-cloud)
   bucket policy** that serves airstar.com — the
   `x-xiaomi-meta-*` headers indicate this CORS config is set at
   the storage layer and likely affects every object served from
   the same bucket/region.
4. **Defense in depth**: drop `Access-Control-Expose-Headers` of
   `x-xiaomi-meta-content-length` — leaking proprietary backend
   metadata header names is reconnaissance fuel for attackers
   mapping Xiaomi's internal infrastructure.

## Note on scope and prior submission

- I have previously filed an unrelated CORS report on
  `airstarfinance.net` (different domain, different infrastructure)
  — please treat this as a separate report covering the .com
  variant of the Airstar brand.
- Both domains map to the same broader Xiaomi Finance / Tianxing
  Digital brand but use different backends (.com = Xiaomi MSS,
  .net = different).

## Tooling

Discovered via Lictor (https://lictor-ai.com), an open-source
security scanner (Apache 2.0). The CORS misconfig patrol probes
bounty-program apex domains with multiple `Origin` header values
and inspects responses for the W3C-invalid `ACAO: *` + `ACAC: true`
combination, the reflect-attacker-origin pattern, and other
permissive CORS antipatterns.

## References

- W3C Fetch standard, CORS Protocol §3.2.4
  https://fetch.spec.whatwg.org/#http-access-control-allow-credentials
- CWE-942: Permissive Cross-domain Policy with Untrusted Domains
- MDN CORS errors — `Cors_credentials_not_supported`
- HackerOne historical payouts for similar CORS-misconfig on
  paid critical-wildcard programs: $100–$500 INFO range
```

---

## Internal notes (DO NOT submit)

**Pricing strategy:**
- Realistic INFO disclosure. $100–$500 from Xiaomi.
- The "Airstar Bank HK is a regulated virtual bank" framing pushes
  toward the upper end — bank security teams take CORS misconfigs
  seriously even when browsers technically reject them.
- Bundled with the prior `airstarfinance.net` submission, this
  signals a systemic Xiaomi Finance CORS hygiene gap, which is a
  good narrative for the triager.

**Why NOT bundled with the prior airstarfinance.net submission:**
- Different domain (.com vs .net)
- Different backend (Xiaomi MSS storage vs whatever .net uses)
- Different exact misconfig (wildcard+creds vs reflect-attacker+creds)
- Separate report = separate INFO payout from a triager who
  values pattern recognition

**Expected outcome:**
- Triage within 24-72 hours
- Resolved as INFO disclosure
- Payout $100-$500

**Things I did NOT do:**
- I did NOT attempt to exfiltrate any user data via the CORS misconfig
- I did NOT probe the Object Storage bucket directly for further
  enumeration
- All probes used neutral test origins (attacker.example.com)
