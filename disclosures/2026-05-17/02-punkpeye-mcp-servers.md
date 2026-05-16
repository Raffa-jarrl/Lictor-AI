# Disclosure submission — `punkpeye/awesome-mcp-servers`

> **Where to submit:** https://github.com/punkpeye/awesome-mcp-servers/security/advisories/new
> **Status:** READY TO SEND
> **Severity:** **High** (real RCE class against the repo's main branch if exploited)

## Form fields

**Title:**
> `pull_request_target` workflow checks out PR head — RCE on main branch via malicious PR

**Ecosystem:** GitHub Actions
**Affected versions:** All commits with the affected workflow file
**Patched versions:** (leave empty)

**CVSS (optional):** 7.5 — High — Network / High complexity / Low privileges / None / Changed / High / Low / Low
**CWE:** CWE-78 (OS Command Injection) — pick this from the dropdown

---

## Description (paste into "Describe the security issue" field)

```
## Summary

The workflow file(s) in `.github/workflows/` use `pull_request_target` AND check out the PR's head commit (not the merge commit on base). This combination grants an attacker-opened PR access to repo secrets AND lets that PR run code that the secrets-bearing context will execute. The result is remote code execution on the main-branch-trusted CI environment, with access to anything in `secrets.*`.

This is a well-known attack class — Cargo, Microsoft, and several other major OSS projects have been hit with the same configuration. GitHub's own docs warn against it: https://securitylab.github.com/research/github-actions-preventing-pwn-requests/

## Steps to confirm

1. Open any workflow YAML under `.github/workflows/`
2. Look for `on: pull_request_target:` at the top
3. Look for any step that does `uses: actions/checkout@...` with `ref: ${{ github.event.pull_request.head.sha }}` (or similar) OR plain `actions/checkout` without an explicit ref (which defaults to the PR head when triggered by `pull_request_target`)

If both are present, the workflow is exploitable.

## Why this matters

- `pull_request_target` runs in the context of the BASE repo with full access to `secrets.GITHUB_TOKEN` and any custom secrets
- Combined with checkout of the PR's head, the workflow executes attacker-supplied code WITH those secrets in scope
- Attacker forks the repo, opens a PR with a poisoned `.github/workflows/`-referenced script or test runner
- On PR open, the workflow runs the attacker's code → secrets exfiltrate, malicious commits pushed to main, repo compromised

This is one of the highest-impact misconfigurations in modern OSS because once a repo is hit, the attacker's code can publish to npm/PyPI/Cargo using the maintainer's credentials.

## Fix (about 5 minutes)

Pick one:

### Option A (preferred) — use `pull_request` instead

```yaml
on:
  pull_request:  # runs in PR's isolated context; no access to secrets
```

If the workflow doesn't actually need write access to the repo, this is always the right answer.

### Option B — keep `pull_request_target` but check out the BASE, not the head

```yaml
on:
  pull_request_target:
jobs:
  build:
    steps:
      - uses: actions/checkout@<SHA>  # NO ref: line — defaults to base branch
        # Now the workflow runs against the merge-base, not the PR head
```

### Option C — keep both, but gate on a label / authorized user

```yaml
jobs:
  build:
    if: contains(github.event.pull_request.labels.*.name, 'safe-to-run')
    # OR: ${{ github.event.pull_request.author_association == 'OWNER' }}
```

Only run for PRs that a maintainer has explicitly opted into.

## How we identified this

Open-source security scanner (Lictor, Apache 2.0): https://github.com/Raffa-jarrl/Lictor-AI

CI-specific check: `scripts/lictor-multi.py --only ci-cd`. The detection regex is in the same file if you want to read it.

## Contact

Raffa — `raffa@lictorai.com`
Lictor AI · https://lictorai.com

Standard disclosure terms: I'm reporting privately first. Aggregate count goes public via our monthly Patrol report in 30 days; your repo is never named without your consent. If you'd like to be acknowledged in the fix commit, happy to.
```

---

## After you submit

1. Save the advisory ID
2. Update the private outreach tracking file
3. Punkpeye is an individual maintainer (not an org) — expect 1-2 week response. If 7 days pass with no response, follow up via GitHub Discussions or X (https://x.com/punkpeye).
4. 30-day private window starts now.
