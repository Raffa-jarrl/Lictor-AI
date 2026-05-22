# Logitech HackerOne Submission — GraphQL introspection enabled on production www.logitechclub.com (Shopify Storefront)

**Submit at:** https://hackerone.com/logitech/reports/new
**Program:** Logitech (open submission state) · **In-scope:** `www.logitechclub.com` (URL asset, max_severity: critical, **eligible_for_bounty: False**)
**Realistic outcome:** **Rep + responsible-disclosure credit, no monetary bounty** (the specific URL asset is marked $:False on H1)

---

## Title
```
GraphQL introspection enabled on production www.logitechclub.com — reveals full Shopify Storefront schema (415 types including 21 cart-state-changing Mutation payloads)
```

## Weakness
`CWE-200 Exposure of Sensitive Information to an Unauthorized Actor`
H1 taxonomy: `Information Disclosure > Sensitive Data Exposure`

## Severity (CVSS:3.1)
**Low — 3.7**
`AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`

## Description (paste into HackerOne form)

```
## Summary

The production GraphQL endpoint at https://logitechclub.com/api/graphql
has introspection queries enabled. Sending a standard `__schema` query
returns the complete schema definition for Logitech Club's Shopify
Storefront API: 415 types total, including the full Query / Mutation
roots and 21 Cart-state-changing mutation payloads.

While the Shopify Storefront API is designed to be queried by client
apps, Shopify's official guidance is to disable introspection on
production stores because it gives attackers a complete map of the
API surface (queryable types, mutations, fields, enums, input shapes).
This dramatically accelerates further vulnerability research (IDOR
hunting, mass-assignment, mutation abuse, etc.).

## Steps to reproduce

1. Send a minimal introspection query to the production endpoint:

   $ curl -sk -X POST -H "Content-Type: application/json" \
       -d '{"query":"{ __schema { queryType { name } mutationType { name } types { name kind } } }"}' \
       https://logitechclub.com/api/graphql

2. Response (truncated):

   {"data":{"__schema":{
     "queryType":{"name":"QueryRoot"},
     "mutationType":{"name":"Mutation"},
     "types":[
       {"name":"ApiVersion","kind":"OBJECT"},
       {"name":"ApplePayWalletContentInput","kind":"INPUT_OBJECT"},
       {"name":"AppliedGiftCard","kind":"OBJECT"},
       {"name":"Article","kind":"OBJECT"},
       {"name":"Cart","kind":"OBJECT"},
       {"name":"CartAttributesUpdatePayload","kind":"OBJECT"},
       {"name":"CartBillingAddressUpdatePayload","kind":"OBJECT"},
       {"name":"CartBuyerIdentityUpdatePayload","kind":"OBJECT"},
       {"name":"CartCreatePayload","kind":"OBJECT"},
       {"name":"CartDeliveryAddressesAddPayload","kind":"OBJECT"},
       {"name":"CartDeliveryAddressesRemovePayload","kind":"OBJECT"},
       {"name":"CartDeliveryAddressesUpdatePayload","kind":"OBJECT"},
       {"name":"CartDiscountCodesUpdatePayload","kind":"OBJECT"},
       {"name":"CartGiftCardCodesRemovePayload","kind":"OBJECT"},
       {"name":"CartGiftCardCodesUpdatePayload","kind":"OBJECT"},
       ... (415 types total)
     ]
   }}}

3. Confirm the endpoint is unauthenticated — a basic shop query
   succeeds with no auth header:

   $ curl -sk -X POST -H "Content-Type: application/json" \
       -d '{"query":"{ shop { name primaryDomain { url } } }"}' \
       https://logitechclub.com/api/graphql
   {"data":{"shop":{"name":"Logitech Club","primaryDomain":{"url":"https://www.logitechclub.com"}}}}

## Impact

Lower severity (INFO disclosure) but specific risks worth flagging:

- **Full attack-surface mapping**: an attacker pulls the entire schema
  and immediately knows every Cart, Customer, Product, Discount, and
  Checkout mutation/query available. Without introspection they'd
  need to fuzz the API blindly.

- **21 Cart mutation payloads exposed**: CartCreatePayload,
  CartAttributesUpdatePayload, CartDiscountCodesUpdatePayload,
  CartGiftCardCodesUpdatePayload, CartDeliveryAddressesAddPayload,
  etc. Each reveals the exact argument shape needed to invoke
  cart-state-changing operations. Combined with any future
  authorization bug, this becomes a roadmap for cart/checkout
  abuse (gift-card stuffing, discount-code enumeration, address
  injection, etc.).

- **Article / Blog / Brand schemas exposed**: ArticleConnection,
  ArticleEdge, ArticleAuthor, Blog, BlogConnection — these reveal
  the content surface and can be used to enumerate unpublished
  drafts if any exist.

- **Shopify guidance is to disable production introspection**:
  https://shopify.dev/docs/api/storefront#introspection
  Default-on is a configuration oversight, not intended behavior
  for production stores.

## Remediation

1. **Disable introspection on the production Shopify storefront**:
   In your Shopify admin / Storefront API access scope settings,
   uncheck "Allow introspection" for the production storefront
   access token. Or, if you've built a custom GraphQL proxy in
   front of Shopify, add a middleware that strips `__schema` and
   `__type` queries in production.

2. **Apollo Server (if used as proxy)**: set
   `introspection: false` in the production config.

3. **Defense in depth**: rate-limit POST requests to
   /api/graphql that contain `__schema` or `__type` introspection
   tokens. Log and alert on any single client issuing repeated
   introspection queries.

4. **Audit other Logitech-brand Shopify-backed sites for the same
   default-on misconfig**: the standard Logitech storefront
   subdomains may have the same issue if they share Shopify
   templates or proxy configurations.

## Tooling

Discovered via Lictor (https://lictor-ai.com), an open-source
security scanner (Apache 2.0). The GraphQL-introspection patrol
probes bounty-program apex domains and common API subdomains for
/graphql, /api/graphql, /v1/graphql, /v2/graphql, /v3/graphql,
/api/v1/graphql, /api/v2/graphql endpoints that respond to
introspection queries.

## Note on scope and bounty eligibility

I acknowledge from the Logitech program scope page that
www.logitechclub.com is listed as in-scope but marked NOT eligible
for monetary bounty (`eligible_for_bounty: false`). Filing this
report for responsible disclosure and reputation credit only, not
for compensation. If the program team decides this finding
warrants a bounty, that is entirely at your discretion.

## References

- Shopify Storefront API introspection guidance:
  https://shopify.dev/docs/api/storefront
- OWASP GraphQL Cheat Sheet (introspection section):
  https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
- HackerOne example payouts for GraphQL introspection on Shopify
  storefronts: typically Informative/Low, but reputation-positive
```

---

## Internal notes (DO NOT submit)

**Realistic outcome:**
- Closed as Informative or Resolved with rep credit, no $$
- www.logitechclub.com explicitly listed `$:False` in Logitech H1 scope
- Could be considered "intended Shopify behavior" by triager
- Best case: rep points for responsible disclosure

**Why submit anyway:**
- Builds rep with Logitech security team for future submissions
- Genuinely a misconfig per Shopify's own guidance
- Low effort to write, low risk to credibility (we're upfront about scope/bounty status)
- Helps the broader Logitech security posture

**Things I did NOT do:**
- Did NOT exfiltrate any customer/order data
- Did NOT attempt any state-changing mutations
- Did NOT enumerate products or unlisted content
- Only ran the standard introspection query + a shop-name probe

**Filing decision: yes, file it.** Low downside, possible upside on rep score for future paid submissions where Logitech is a $ program.
