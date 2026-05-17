# Patrol — pull_request_target attack-class scan (aggregate)

**Run:** 2026-05-17 07:31 UTC
**Method:** GitHub Code Search for `pull_request_target` in workflow YAML, raw-file content verification of checkout-PR-head pattern.

## Aggregate counts

- Candidate workflow files searched: **30**
- Confirmed checkout-PR-head pattern: **30**
- High severity (PR head checked out, no build step yet): **28**
- Critical severity (PR head checked out + runs build/test): **2**
- Outreach-eligible (above + ≥10 stars + not archived): **6**