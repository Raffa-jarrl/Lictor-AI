# Sprint S-22 — "Beyond GitHub"

**Dates:** Sun 2026-05-17 → Sun 2026-05-24
**Team:** Raffa (solo) + agent crew
**Sprint Goal:** Triple disclosure-source coverage by adding 3+ non-GitHub corpora — while sustaining ≥20 verified disclosures per day.

## Banked Day 0 (Sun 5/17)
- ✅ 83 disclosures sent (4 days ahead of 20/day target)
- ✅ `patrol-huggingface` scanner shipped (1 verified Gemini key found)
- ✅ `patrol-npm` scanner skeleton shipped (0 hits on popular AI pkgs — needs retune)
- ✅ Site relaunch: logo + FX motion layer + shell.css design system + lean nav + mobile defer + in-the-wild page
- ✅ Both `lictorai.com` and `lictor-ai.com` serving

## Remaining backlog

### P0 (must)
- Sustain 20+/day disclosure cadence
- `patrol-pypi` (PyPI tarball + key scan, reuse npm shape)
- Maintainer response monitor (cron + email digest)
- Manual HF discussion for `habibch/immigration-chatbot`

### P1 (should)
- `patrol-gitlab` (GitLab.com search API — fresh corpus)
- Retune `patrol-npm` to surface hobbyist packages
- `/transparency` page with live disclosure counter
- Retrofit `/scan` + `/patterns` heroes to `.page-hero`

### P2 (stretch, drop first)
- `patrol-postman` (public Postman workspace scan)
- Browser ext scanner (manifest v3 audit)

## Sprint exit metrics
- ≥140 total disclosures
- ≥5 distinct disclosure source classes
- ≥10 verified maintainer responses
- 3 new scanners shipped

## Daily plan
| Day | Focus |
|---|---|
| Sun 5/17 ✅ | 83 disclosures + 2 scanners + site relaunch |
| Mon 5/18 | Resume HF v2 scan + build `patrol-pypi` + 20-batch |
| Tue 5/19 | `patrol-gitlab` + first scan + 20-batch |
| Wed 5/20 | Response monitor + retune npm + 20-batch |
| Thu 5/21 | `/transparency` page + hero retrofit + 20-batch |
| Fri 5/22 | Reply day — handle inbound from the 83 |
| Sat-Sun | Async only |

## Risks
- Reply backlog swamps new-scanner days → Friday reserved for replies
- GitHub anti-spam triggers → max 30/day, vary titles, 4 vuln classes
- npm retune fails → pivot to pypi (same arch)
- GitLab auth-walled → scrape public projects fallback
