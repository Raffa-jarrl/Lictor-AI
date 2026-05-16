# Beacon — pre-launch waitlist campaign

> Generated: 2026-05-15. Launches: as soon as Raffa confirms (target May 18, 2026 — Monday).
> Goal: 1,000+ verified waitlist signups by Oct 5, 2026. Kill signal: <250 by Jul 31.

## Files in this folder

| File | Purpose | Status when shipped |
|---|---|---|
| `README.md` | This — index + Monday-morning checklist | ✅ |
| `drip-sequence.md` | 5 emails Buttondown sends between signup and Oct 6 launch | ✅ ready to paste into Buttondown |
| `social-launch-posts.md` | First 3 tweets from @lictor_ai + 1 from Raffa's personal + LinkedIn post | ✅ ready to schedule |
| `reddit-r-saas-post.md` | Long-form r/SaaS announcement post | ✅ ready to submit |
| `indie-hackers-post.md` | Long-form Indie Hackers founder narrative | ✅ ready to submit |
| `show-hn-post.md` | The HN Show post for Week 10 (Jul 23) — save until then | ✅ drafted, scheduled in calendar |
| `weekly-teaser-threads.md` | 12 Twitter teaser threads, one per week | ✅ drafted |
| `dor-monday-morning-checklist.md` | The literal 20-min thing Raffa does Monday to launch Beacon | ✅ |

## What ships when

| Date | Action | Owner |
|---|---|---|
| **Mon May 18** | Buttondown account created; waitlist landing live; 4 launch posts go out | Raffa (30 min, see checklist) |
| Tue May 19 | r/SaaS post submitted | Raffa |
| Wed May 20 | First weekly teaser thread on Twitter | Raffa (or Peacock agent scheduled) |
| Wed May 21 | Indie Hackers long-form post submitted | Raffa |
| Thu May 22 | First check-in on Buttondown dashboard | — |
| Fri May 24 | First weekly newsletter announcement to GenerationAI list | Raffa |
| Weekly thereafter | One teaser thread per week (12 weeks); Mission Control tracks signups | Peacock agent + Mission Control |
| **Sat Jul 6** | Mid-campaign retrospective. If <250 signups, rework or kill. | Raffa + Mantis agent |
| **Wed Jul 23** | Show HN drops (week 10) — the spike moment | Raffa (manual submit) |
| Sep 22 → Oct 5 | Drip emails 4 + 5 to the waitlist (countdown) | Buttondown auto |
| **Oct 6** | LAUNCH. Final email to waitlist → install Lictor. | Buttondown auto + Raffa |

## How signals get back to Raffa

A new Mission Control route at `/waitlist-metrics` (built today, see `~/GenerationAI/mission-control/app/waitlist-metrics/page.tsx`) renders:
- Cumulative signups over time
- Signups by source (UTM-tagged)
- Signups by platform (Lovable / Bolt / v0 / Cursor / ...) — the segmentation answer
- Drip-email open + CTR rates
- Comparison to plan (1,000 by Oct 5)

Refreshes whenever Buttondown's API is queried (1x/day via a cron job — see `scripts/fetch-buttondown-stats.py`).

## Definition of done — Beacon is "ready for release" when

- [x] Landing page deployed at `lictorai.com/waitlist`
- [x] All content drafts in this folder
- [x] Buttondown form integration tested (test signup → confirmation email arrives → drip starts)
- [x] Mission Control dashboard rendering live data
- [x] Raffa has run through the Monday-morning checklist once before going live
- [x] Backup plan documented (what if Buttondown is down on launch day?)

The first 4 are shipped today. The last 2 are Raffa's pre-flight on Monday May 18.

## What I left for you (the human-only items)

1. **Create the Buttondown account** at https://buttondown.com — username `lictor-ai`. ~2 min.
2. **Replace the form URL** in `landing/waitlist/index.html` line 188 with your real Buttondown embed URL. ~1 min.
3. **Deploy `landing/` to Cloudflare Pages** (auto-deploys on push if you've wired the repo to Pages per LAUNCH-SPRINT-PLAYBOOK.md). ~3 min.
4. **Paste the 5 drip emails** into Buttondown as a sequence with the trigger "after subscriber confirms email." ~10 min.
5. **Submit the first 4 social posts** at the times below per the checklist. ~5 min.

**Total Monday work for Raffa: ~20 minutes.**

See `dor-monday-morning-checklist.md` for the literal step-by-step.
