# Patrol — pull_request_target attack-class scan (aggregate)

**Run:** 2026-05-19 10:35 UTC
**Method:** GitHub Code Search for `pull_request_target` in workflow YAML, raw-file content verification of checkout-PR-head pattern.

## Aggregate counts

- Candidate workflow files searched: **42**
- Confirmed checkout-PR-head pattern: **42**
- High severity (PR head checked out, no build step yet): **38**
- Critical severity (PR head checked out + runs build/test): **4**
- Outreach-eligible (above + ≥10 stars + not archived): **9**