# Lictor AI — Roadmap

*Updated 2026-05-18 · Now / Next / Later format*

---

## 🟢 NOW (in flight — this week, sprint S-22)

- ✅ Sustain ≥20 disclosures/day — 53 today, on track
- ✅ `patrol-pypi` scanner — found 5 hits in zohencel-ai
- ✅ `drain-queue` auto-firer — 39 fires today across 2 rounds
- ✅ Install copy-paste section (sitewide)
- 🟡 `patrol-gitlab` scanner — bumped from Tue → Wed
- 🟡 Maintainer-response monitor — PROMOTED to NOW (inbound replies landing today)
- 🟡 Manual HF discussion for habibch/immigration-chatbot

## 🟠 NEXT (next 1-3 weeks)

| Item | Why | Effort |
|---|---|---|
| 4 new vuln classes (Cloudflare/Twilio-SID/Datadog/Linear) | Volume ceiling on existing 4 classes | ~12 hrs total |
| `patrol-gitlab` | Separate corpus, +30-50% pool | 3 pts |
| `patrol-sourcegraph` | Covers GH+GL+Bitbucket via single API | 2 pts |
| `patrol-postman` | Public workspaces have real keys in saved requests | 2 pts |
| Maintainer-reply monitor (cron + auto-draft) | 175 disclosures = inbound starting | 2 pts |
| Cursor + JetBrains extensions for /lictor-security-check | Distribution beyond Claude Code | 3 pts each |
| `/transparency` page with live disclosure counter | Public proof = social distribution | 1 pt |
| Browser extension scanner (manifest v3 audit) | Listed in /in-the-wild, real demand | 5 pts |

## ⚪ LATER (3-8 weeks)

- Mobile (iOS + Android) scanner — pattern catalog written, parser sketched
- Sentinel SDK 1.0 (npm + pip) — runtime guardrails for AI features
- MCP server audit as standalone CLI
- Lictor for Teams ($19/mo flat) — first commercial revenue (optional)
- Public "Hall of Patrol" scorecard
- CI/CD GitHub Action for in-PR scanning

---

## Changes since S-22 plan (Sun 2026-05-17)

- **Added:** 4 new vuln classes (volume ceiling reached on existing scanners after 175 cumulative disclosures)
- **Added:** Sourcegraph as a multi-corpus shortcut
- **Promoted to NOW:** Maintainer-reply monitor (first replies landing today)
- **Demoted to NEXT:** /transparency page (less urgent than reply monitor)
- **Added:** Cursor + JetBrains extensions (distribution wedge)
- **No change:** Mobile / Sentinel / MCP / Teams (all stay Later)

## Risks

- 🟠 Reply backlog (175 issues outbound) overwhelms solo maintainer → mitigate with reply-monitor this week
- 🟠 GitHub anti-spam from issue-creation volume → cap stays at 50/day
- 🟡 Query saturation → diversify with 4 new vuln classes
- 🟡 PVR re-contact → maintain PVR_SENT set
- 🔴 Solo-maintainer burnout → recruit 1 contributor by end of June

## Sprint S-22 status

- **Target:** 140 disclosures this sprint
- **Cumulative live across all days:** 175
- On track ✅
