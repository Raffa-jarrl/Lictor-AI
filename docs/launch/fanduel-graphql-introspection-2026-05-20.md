# FanDuel HackerOne Submission — GraphQL introspection enabled on production fanduel.com/graphql

**Submit at:** https://hackerone.com/fanduel/reports/new
**Program:** FanDuel (paid) · **In-scope:** `*.fanduel.com` (max_severity: critical)
**Realistic payout:** $300–$1,000 (INFO disclosure)

---

## Title
```
GraphQL introspection enabled on production fanduel.com/graphql — reveals full Promotion/Reward schema
```

## Weakness
`CWE-200 Exposure of Sensitive Information to an Unauthorized Actor` (or H1's "Information Disclosure > Sensitive Data Exposure")

## Severity (CVSS:3.1)
**Medium — 5.3**
`AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`

## Description (paste into HackerOne form)

```
## Summary

The production GraphQL endpoint at `https://fanduel.com/graphql` has
introspection queries enabled. Sending a standard `__schema` query
returns the complete schema definition including all 23 types covering
the Promotion / Reward / CustomerPromotion subsystem, plus the
Mutation root type.

Introspection should be disabled on production GraphQL endpoints
because it gives attackers a complete map of the API surface:
all queryable types, all mutations, all fields, all enum values.
This dramatically accelerates further vulnerability research
(IDOR hunting, mass-assignment, authorization bypass, etc.).

## Steps to reproduce

1. Send a tiny introspection query to the production endpoint:

   $ curl -sk -X POST -H "Content-Type: application/json" \
       -d '{"query":"{ __schema { queryType { name } types { name } } }"}' \
       https://fanduel.com/graphql

2. Response (truncated):

   {"data":{"__schema":{"queryType":{"name":"Query"},"types":[
     {"name":"Badge"},
     {"name":"CallToAction"},
     {"name":"ContextRule"},
     {"name":"CustomerPromotionState"},
     {"name":"CustomerPromotionStep"},
     {"name":"DateTime"},
     {"name":"Mutation"},
     {"name":"OptInResponse"},
     {"name":"ProductName"},
     {"name":"Promotion"},
     {"name":"PromotionCTAAction"},
     {"name":"PromotionImage"},
     {"name":"PromotionImageTag"},
     {"name":"PromotionOptInState"},
     {"name":"Query"},
     {"name":"RedirectOpenStrategy"},
     {"name":"Reward"},
     {"name":"TermsAndC..."
   ]}}}

3. From there, an attacker can pull the full schema using a more
   complete introspection query and reconstruct every field, type,
   enum, and mutation argument.

## Impact

INFO disclosure with specific risk multipliers for FanDuel:

- **Promotion / Reward system schema fully visible** — attackers can
  enumerate every mutation related to promotion opt-in, reward
  redemption, promotion state transitions. Useful for hunting
  IDOR / privilege escalation / bonus abuse.
- **Mutation root type exposed** — every state-changing operation
  is documented, including parameter types and required arguments.
- **Accelerates further attacks** — without introspection, an
  attacker would need to fuzz the API. With it, they have a
  complete API spec.
- **Bonus / promotion abuse risk** — FanDuel's promotion system
  is a known high-value target (free credits, signup bonuses,
  referral rewards). A leaked schema makes abuse-vector research
  significantly easier.

## Remediation

1. **Disable introspection in production**. The standard pattern is
   to gate introspection behind a `NODE_ENV !== 'production'` check
   or use a middleware that strips `__schema` and `__type` queries
   in production builds.
2. **Apollo Server**: set `introspection: false` in production config.
3. **GraphQL Yoga**: pass `{maskedErrors: true, introspection: false}`.
4. **graphql-php / Hot Chocolate / etc.**: each framework has an
   equivalent flag.
5. **Defense in depth**: also rate-limit `/graphql` queries that
   contain `__schema` or `__type` introspection tokens.

## Tooling

Discovered via Lictor (https://lictor-ai.com) — open-source security
scanner (Apache 2.0). Lictor probes bounty-program apex domains and
common API subdomains for `/graphql` endpoints that respond to
introspection queries.

## References

- OWASP GraphQL Cheat Sheet (introspection section):
  https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
- HackerOne example payouts for GraphQL introspection: #1075842, #851725
```
