# Patrol — pull_request_target attack-class scan (aggregate)

**Run:** 2026-05-17 05:28 UTC
**Method:** GitHub Code Search for `pull_request_target` in workflow YAML, raw-file content verification of checkout-PR-head pattern.

## Aggregate counts

- Candidate workflow files searched: **13**
- Confirmed checkout-PR-head pattern: **13**
- High severity (PR head checked out, no build step yet): **11**
- Critical severity (PR head checked out + runs build/test): **2**
- Outreach-eligible (above + ≥10 stars + not archived): **5**