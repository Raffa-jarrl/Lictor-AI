# Launch Day — Tuesday Oct 6, 2026

This directory holds every piece of copy that goes live on launch day. Each file is a draft — finalize during W20 (Sep 21-27), schedule everything by W20 EOW, then NO code or copy touching during W21 except posting.

## Schedule (all Pacific)

| Time | Channel | Artifact | File |
|---|---|---|---|
| 06:00 am | Hacker News | "Show HN" post | [`hn-post.md`](./hn-post.md) |
| 07:00 am | Twitter / X | 12-tweet launch thread | [`twitter-thread.md`](./twitter-thread.md) |
| 09:00 am | YouTube | Case-study video (TODO: shoot W19) | — |
| 09:30 am | Blog | Long-form "Why I built Lictor" | [`blog-post.md`](./blog-post.md) |
| 11:00 am | Email | Press list (individual sends) | [`press-email.md`](./press-email.md) |
| 11:00 am – 11:00 pm | All channels | Comment / reply triage | — |

## Pre-launch checklist (W21 only — code freeze week)

- [ ] HN post draft locked, copied into ready-to-paste form
- [ ] Twitter thread scheduled or pre-loaded in TweetDeck
- [ ] Blog post published as `/blog/why-lictor` (status: draft, scheduled for 09:30)
- [ ] Press emails personalized + drafted in Gmail (one per recipient — don't BCC)
- [ ] YouTube video uploaded as "unlisted", scheduled to go public at 09:00
- [ ] OG images verified on lictor-ai.com (1200×630 — required for Twitter/Slack previews)
- [ ] HN post in personal HN account drafts (so it's ready to paste — HN doesn't have scheduling)
- [ ] One trusted friend has the timing sheet so they can watch HN at 06:00 if Raffa can't be awake
- [ ] All `npm publish` / `twine upload` commands ready to run from W19 prep (don't actually publish until post-launch — Chrome Web Store review can take 14 days, and the npm/PyPI publish is what triggers HN engagement)

## What's still TODO

- **Screenshots / hero images** for the Twitter thread (tweets #1, #4, #5, #8 need attachments)
- **OG image** at 1200×630 (lictor-ai.com meta tags reference it; need to render from the lockup SVG)
- **YouTube case-study video** — needs shooting in W19. 90-second cut: wrap → adversarial input → blocked + Guardian dashboard shows the incident. Should be doable in one focused day.
## Why these specific channels

- **HN** — highest-density technical audience. The "Show HN" framing pre-qualifies us as "open-source, free to try, here to discuss." Bad HN reception is recoverable; not posting on HN at all means we lose the consumer-developer crossover audience.
- **Twitter** — picks up the AI safety / dev tools community. 12-tweet threads outperform single tweets 4-6× on engagement.
- **YouTube** — the case-study video is the one piece of content that converts CISO-level viewers more than text. It's also the asset that survives the launch week and keeps recruiting customers for months.
- **Press** — leverage. A single TLDR AI mention reaches 100K+ developers. A Stratechery / Acquired follow-up reaches CISOs. Both require a substantive launch (HN landing on the front page helps).

## Why these times

- **06:00 Pacific = 09:00 Eastern** = peak HN morning load + start of European workday
- **07:00 Pacific = peak Twitter morning** for US tech audience
- **09:00 Pacific** = YouTube goes live after HN has had 3 hours to react (HN comments inform the YouTube reply pinned at top)
- **11:00 Pacific** = press emails — by now the HN URL is real, the Twitter thread has some engagement, journalists can verify the launch is happening

## Day-of rules

- **Sleep 8 hours the night before.** Tired Raffa on launch day damages 6 weeks of work.
- **Block all calendar from 05:00 to 23:00.** This is the only thing happening.
- **Respond to every HN comment within 30 min for the first 4 hours.** Late-replied comments tank engagement.
- **Don't push code.** Hot-fixing on launch day is how launches fail. Anything found is logged for post-launch.
- **Don't make announcements about user counts / star counts / install numbers.** Premature metrics distract from the story.
- **At 11:00 pm Pacific, stop responding and sleep.** The launch keeps running tomorrow.

## Post-launch (Wed Oct 7+)

- Triage every bug from launch day. Critical bugs get hot-fixes the next morning.
- Reply to every press email that came in during launch.
- Schedule follow-up content for the next 14 days: one technical deep-dive, one customer case-study (need permission), one regulatory deep-dive (EU AI Act). These extend the news cycle.

---

Last updated: 2026-05 (W20 prep — content drafted; finalize during the actual W20 sprint).
