# Patrol — pull_request_target attack-class scan (aggregate)

**Run:** 2026-05-17 06:49 UTC
**Method:** GitHub Code Search for `pull_request_target` in workflow YAML, raw-file content verification of checkout-PR-head pattern.

## Aggregate counts

- Candidate workflow files searched: **22**
- Confirmed checkout-PR-head pattern: **22**
- High severity (PR head checked out, no build step yet): **22**
- Critical severity (PR head checked out + runs build/test): **0**
- Outreach-eligible (above + ≥10 stars + not archived): **4**