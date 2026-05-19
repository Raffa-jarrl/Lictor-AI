# Bounty queue — 2026-05-19

**Findings scanned:** 187
**Matched to bounty programs:** 0
**Expected payout (sum of midpoints):** $0

## Submit-now queue (sorted by expected $)

| Expected | Min–Max | Channel | Company | Class | Repo | Issue |
|---|---|---|---|---|---|---|

_No matches in this run. Most findings are in customer repos, not company-owned. Bounty-eligible findings are ones where the LEAKING repo is owned by the company that operates the leaked service (e.g., a Stripe-owned repo leaking a Stripe key)._


## Pivot: third-party leak channels

Most of our findings are 'customer X leaked vendor Y's key.' For those:

- **Stripe Secret Scanner Partnership** auto-revokes some; we don't get paid but the user benefits

- **Direct outreach to the LEAKING company** (not the vendor) is the bounty path — if customer X has their own bounty program, our finding qualifies under 'leaked credentials in source'

- Run `bounty-matcher.py --scan-customer-bounties` (TODO) to cross-ref repo owners against H1/BC public directory
