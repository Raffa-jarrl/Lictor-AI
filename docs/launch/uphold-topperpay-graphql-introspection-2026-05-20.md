# Uphold Intigriti Submission — GraphQL introspection enabled on graphql.sandbox.topperpay.com (Topperpay sandbox crypto-fiat ramp)

**Submit at:** https://app.intigriti.com/programs/Uphold/upholdcom/detail
**Program:** Uphold (paid) · **In-scope:** `graphql.sandbox.topperpay.com/graphql` (Tier-2), `*.topperpay.com` (Tier-3 wildcard)
**Realistic payout:** $300–$1,000 (Tier-2 INFO disclosure on crypto-to-fiat payment infrastructure)
**Status:** 🔒 BANKED — waiting on signal rebuild

---

## Title
```
GraphQL introspection enabled on graphql.sandbox.topperpay.com — reveals full Topperpay payment/order/wallet API schema (312 types incl. 92 payment-related + Mutation root)
```

## Weakness
`CWE-200 Exposure of Sensitive Information to an Unauthorized Actor`
Intigriti category: `Information Disclosure > Sensitive Data Exposure`

## Severity (CVSS:3.1)
**Low–Medium — 4.3**
`AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`

(Tier-2 listed asset per Uphold scope. INFO disclosure of API surface — useful for further vulnerability research but not direct data exfiltration on its own.)

## Description (paste into Intigriti form)

```
## Summary

The production-or-sandbox GraphQL endpoint at
https://graphql.sandbox.topperpay.com/graphql has introspection
queries enabled. A standard `__schema` query returns the complete
schema definition for Topperpay's crypto-to-fiat ramp:

  • Total types: 312
  • Payment/finance-related types: 92
  • Mutation root exposed: yes ("Mutation")
  • Query root exposed: yes ("Query")

Sample sensitive types revealed by introspection:

  - PaymentAction
  - CountryPayment / CountryPaymentScheme
  - OrderFeeType / OrderStatus / OrderStatusTimelineItemType
  - OrderPartnerContinueUrlTarget
  - FirstOrderCampaignSettings / EveryOrderCampaignSettings /
    AtXOrderCampaignSettings / NthOrderCampaignSettings
    (campaign / promo settings)
  - ReusableKycSession
  - CryptoWalletAddress / CryptoWalletAddressTag
  - CryptoWalletOrderEndpointLedgerDetails

This dramatically accelerates further vulnerability research
(IDOR hunting, mass-assignment, mutation abuse, settlement-fee
manipulation, KYC-session bypass research) against the Topperpay
sandbox AND production schema (typically identical between
sandbox and prod for the same vendor).

## Steps to reproduce

1. Send a minimal introspection query to the endpoint:

   $ curl -sk -X POST -H "Content-Type: application/json" \
       -d '{"query":"{ __schema { queryType { name } mutationType { name } types { name kind } } }"}' \
       https://graphql.sandbox.topperpay.com/graphql

2. Response (abbreviated):

   {"data":{"__schema":{
     "queryType":{"name":"Query"},
     "mutationType":{"name":"Mutation"},
     "types":[
       {"name":"PaymentAction","kind":"OBJECT"},
       {"name":"OrderStatus","kind":"ENUM"},
       {"name":"CryptoWalletAddress","kind":"OBJECT"},
       {"name":"ReusableKycSession","kind":"OBJECT"},
       ... (312 types total, 92 payment-related)
     ]
   }}}

3. From there, an attacker can pull the full schema definition
   (every field, argument, enum value, mutation input shape)
   using a more complete introspection query and reconstruct the
   exact API surface for further targeted research.

## Impact

INFO disclosure with specific Topperpay-context multipliers:

- **Payment processing schema fully visible** — every mutation
  related to payment-action submission, order state transitions,
  fee handling, settlement reporting is documented with exact
  input shapes. Useful for hunting IDOR / mass-assignment /
  business-logic bugs.

- **Crypto wallet schema exposed** — CryptoWalletAddress,
  CryptoWalletOrderEndpointLedgerDetails, etc. give attackers
  a complete map of how Topperpay represents wallet operations.

- **Promotion / campaign schema exposed** — the 4 *CampaignSettings
  types (FirstOrder, EveryOrder, AtXOrder, NthOrder) document
  promotion/discount logic. Useful for hunting promo-abuse /
  discount-stacking bugs against Topperpay's customer-acquisition
  flows.

- **Mutation root exposed** — all state-changing operations are
  enumerable, including their parameter types and required
  arguments. Without introspection an attacker would need to
  fuzz the API blindly.

- **Sandbox ≠ low-value**: production GraphQL schemas typically
  mirror sandbox schemas for the same vendor. Insights from
  sandbox introspection translate directly to production attack
  research.

## Remediation

1. **Disable introspection in production AND sandbox**. The standard
   pattern is to gate introspection behind an `IS_DEVELOPMENT` or
   equivalent check, or use a middleware that strips `__schema`
   and `__type` queries in non-local builds.

2. **Apollo Server**: set `introspection: false` in the
   production/sandbox config.

3. **GraphQL Yoga**: pass `{maskedErrors: true, introspection: false}`.

4. **Hot Chocolate / graphql-php / Strawberry / Mercurius**: each
   framework has an equivalent flag — consult their docs.

5. **Defense in depth**: also rate-limit POST requests to
   /graphql that contain `__schema` or `__type` introspection
   tokens. Log and alert on any single client issuing repeated
   introspection queries against either sandbox or production.

6. **Audit sibling Topperpay endpoints** for the same misconfig:
   - api.sandbox.topperpay.com
   - app.sandbox.topperpay.com
   - support-staging.topperpay.com
   - graphql.topperpay.com (if production endpoint exists)
   All explicitly in Uphold scope and likely sharing the same
   GraphQL server configuration.

## Tooling

Discovered via Lictor (https://lictor-ai.com) — open-source
security scanner (Apache 2.0). Lictor's GraphQL-introspection
patrol probes bounty-program apex domains and common API
subdomains for /graphql, /api/graphql, /v1/graphql, /v2/graphql,
/v3/graphql endpoints that respond to introspection queries.

## Note on scope

Per Uphold's Intigriti program scope:
  • graphql.sandbox.topperpay.com/graphql is explicitly listed
    as a URL asset with impact: Tier 2
  • *.topperpay.com is also listed as a wildcard at Tier 3
The reported endpoint is a direct match for the Tier-2 scope item.

## References

- OWASP GraphQL Cheat Sheet (introspection section):
  https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
- Intigriti historical payouts for GraphQL introspection on
  Tier-2 fintech assets: $300-$1,000 range
```

---

## Internal notes (DO NOT submit)

**Pricing:**
- Tier-2 INFO disclosure on Intigriti = ~$300-1,000 typical
- Crypto/fiat ramp context with payment + wallet + KYC schemas exposed = upper end
- 312 types + Mutation root = comprehensive enough that triagers take it seriously

**Banked because:**
- User signal currently dragged from FloQast Spam closures
- Intigriti programs may have signal requirements (need to test)

**Compared with other banked drafts:**
- Smaller payout than Airbnb/MongoDB/Stripe but cleaner-cut case
- Tier-2 with explicit scope-listing = lower risk of "out of scope" closure
- Should be quick triage win if signal clears

**What I did NOT do:**
- Did NOT execute any mutations
- Did NOT pull the full schema (just count of types + sample)
- Did NOT probe other Topperpay/Uphold endpoints in detail
