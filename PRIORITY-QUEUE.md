# 🎯 Lictor Priority Queue — Day 5 ($50K+ pivot)

**Last updated:** 2026-05-26
**Strategy change:** Stop chasing $500-class. Go for 3× $50K+ findings.
**Honest probability:** 0-2 confirmed $50K-class findings in next 5-10 days.

---

## Phase 1: New scanners built (Day 5)

| # | Scanner | Status | Target class | Realistic find rate |
|---|---------|--------|--------------|---------------------|
| 73 | `patrol-cicd-admin-panels.py` | ✅ Built + syntax-clean | Jenkins/GitLab/Bamboo RCE | 0.5-2% of corp IPs |
| 74 | `verify-ssrf-to-cloud-metadata.py` | ✅ Built + syntax-clean | SSRF → cloud creds | 5-15% of confirmed SSRF |
| 75 | `patrol-terraform-state-exposure.py` | ✅ Built + syntax-clean | .tfstate w/ cloud creds | 0.1-0.5% of orgs |

## Phase 2: Deep-dive existing data (parallel, takes days)

| Source | Findings | Status |
|--------|----------|--------|
| `http-smuggling.jsonl` | 95 desync candidates | Verify each for real impact (3 8x8 hostnames first) |
| `ssrf-candidates.jsonl` | 506 (FP wave) | Re-probe with #74 against metadata |
| `port-exposure-candidates.jsonl` | 154 | Categorize by port, check for known service fingerprints |
| `hardhat-exposed.jsonl` | 18 | Check JSON-RPC unlocked accounts |
| `graphql-mutations.jsonl` | 50 | Identify auth-bypassable mutations |

## Phase 3: Per-finding verification (1+ hour each, gates from SUBMISSION-VERIFICATION-PROTOCOL.md)

For each candidate that surfaces:
1. Read all public docs/code for the target
2. Build attack-chain hypothesis
3. Test with safest possible PoC (no exploitation)
4. Verify multi-signal (not just one indicator)
5. Submit only when 1000% certain

## Currently in flight (no change needed)

| Tier | Item | Status |
|------|------|--------|
| A | Visa HackerOne #3759378 | Passed pre-triage (host-header has been FIXED — strengthens claim) |
| A | Slack HackerOne #3758135 | Received |
| A | HERE Intigriti | Triage |
| D-ready | WP Engine takeover | Intigriti draft saved |
| D-ready | VMware @vmware/vrdt-common | Bugcrowd, never sent |

## Verified-real but lower-value findings (parking lot)

- 9 dep-confusion findings (mostly signal-blocked on HackerOne)
- 26 sourcemap exposures (mostly no bounty channel)
- 1 RPC key leak on Ribbon (channel dead)

## Killed by verification this week

- 100% of 28 typosquats (defensive/legit-alt)
- 44% of dep-confusion (FP Class #23 specifier types)
- 100% of chaos non-MS subdomain takeovers (already remediated or GitHub-internal)
- 5 host-header findings (all remediated — good for security)
- Bracket apply_claim "no-auth" claim (insufficient evidence to call it bypass)
- airstar-finance LFI (pre-canned hostname response, not real LFI)
- Wallet files on BuzzFeed/Forbes/Leonardo (media content, not crypto)

## Hard rule

**No submission without:**
- All gates in SUBMISSION-VERIFICATION-PROTOCOL.md pass
- 1+ hour of careful verification
- Multi-signal confirmation (not just one indicator)
- 1000% certainty

## Realistic outlook

- Day 5-7: scanners run, deep-dive existing data
- Day 7-10: per-finding verification (hours each)
- Day 10-14: first confirmed $50K-class submission (if lucky)
- Day 14-21: bounty payout (if accepted)
- **Probability of 1+ $50K+ payout in next 14 days: 30-50%**
- **Probability of 3+ $50K+ payouts in next 14 days: 10-20%**

This is the honest math.
