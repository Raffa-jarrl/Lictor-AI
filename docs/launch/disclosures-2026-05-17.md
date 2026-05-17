# Disclosure run — 2026-05-17

## Summary
**79 verified vulnerabilities responsibly disclosed to maintainers** in a single day.

All via GitHub public contact-request issues (no PVR available for these targets).
Body redacted — exact file/line/JWT-payload-decode shared only via private email/DM after maintainer responds.

## Breakdown
| Round | Sent | Class | Notes |
|---|---|---|---|
| Prior session | 14 | mixed | 12 generic + 2 IL /admin |
| Firebase remaining-21 | 20 | Firebase service-account JSON | 1 fail: deleted repo notkojak/NEW_DIRECT |
| Firebase batch 001 | 20 | Firebase | Includes Hospital-Admin-Panel-Backend (healthcare), AssistantLivingApp_Production (eldercare), alexcolls/z-trading (16★ trading) |
| Firebase batch 002 | 20 | Firebase | **kubevela/terraform-controller (162★ CNCF infra)** is the highest-impact target |
| Mixed batch 003 | 5 | 1 fb + 4 DB-creds | postgres/mongodb conn strings with embedded passwords |
| **TOTAL** | **79** | | |

## Method
1. `patrol-firebase.py` — GitHub Code Search for `private_key_id` + `private_key` co-presence, raw-file verify, placeholder filter (drops your-project/example/placeholder/sample/demo)
2. `patrol-db-creds.py` — postgres/mongodb/mysql/redis URLs with non-placeholder passwords + real (non-RFC1918) hosts
3. Manual triage: skip README/docs paths, archived repos, repos pushed >365d ago
4. Bulk submit via raw GitHub REST API (gh CLI was stalling)

## Filter window
All targets pushed in last 365 days. Cuts out abandoned repos where rotation is unlikely.

## Skipped (this round)
- Bot-tokens scan (17 finds, mostly phishing-bot repos / leak databases / README placeholders — not legitimate maintainers)
- Supabase service-role scan (0 actionable after freshness filter)
