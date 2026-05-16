> **NOTE (May 2026 update):** Course revenue line REMOVED from Lictor's plan. The course at generationai.com is a separate consulting business and is no longer part of this project. References below that mention "Course", "course enrollments", or course-derived revenue should be treated as historical and substituted with zero. Other revenue lines (Teams, AaaS, Enterprise) stand.

# Content Calendar — 90 days post-launch (Oct 6 → Dec 31, 2026)

> **Purpose:** What each agent ships, when, where, and who approves it. Read it Monday morning. Execute it that week. Don't improvise.
> **Owner:** Wolf coordinates the weekly content kanban. Mantis audits Friday. Raffa approves anything that escalates.
> **Pillar:** every week has a theme. Every agent's output reinforces that week's theme. The weekly teardown is the spine; everything else hangs off it.

---

## How to read this calendar

The teardown engine (`./teardown-engine.md`) drives the week. Tuesday a new teardown ships. Every other piece of content that week refers to it, riffs on it, or sets up the next one. The calendar below tells each agent what their week looks like — but the teardown is always the centerpiece.

Three working principles:

1. **One topic per week, every surface.** If Week 2 is "Bolt env-var disasters," every blog, every tweet, every short pulls from that well. Cohesion compounds.
2. **The agents are the brand.** Posts are signed `— Mongoose` or `— Lyrebird`. The Lictor crew has names and personalities. Followers follow agents, not generic brand accounts. Snyk can't copy this without a personality transplant.
3. **Mantis's Friday review is the throttle.** If a week's content drifts off-theme or off-voice, Mantis kicks it back. Volume without coherence is noise.

---

## Channels and frequency

Per-channel weekly volume. Numbers are floors, not ceilings. If a teardown lands hot, push more on the surface that's working.

| Channel | Weekly volume | Owner | Why |
|---|---|---|---|
| **X (Twitter)** | 14 posts/week (2/day) | Lyrebird drafts, Wolf schedules | Builder discovery surface. Daily presence is non-negotiable. |
| **LinkedIn** | 5/week (one per weekday) | Lyrebird drafts, Raffa approves | Decision-maker surface. Long-form case study format performs best. |
| **Blog (lictor.dev)** | 3/week | Lyrebird writes, Octopus deploys | Teardown (Tue), agent-watch (Thu), guest/community post (Fri). |
| **YouTube** | 1 long-form + 3 shorts/week | Raffa records, Cuttlefish edits | Long-form Tuesday after teardown ships. Shorts Wed/Fri/Sun. |
| **TikTok** | 5/week (one per weekday) — **skip if Raffa isn't posting** | Cuttlefish edits | Only ship if posting is consistent. One-offs flop the algorithm. **Decision gate Oct 6.** |
| **Substack** | 1/week (Tuesday 10:00 PT) | Lyrebird writes, auto-send | The teardown, plus "what I learned this week." |
| **Hacker News** | 1 submission/week | Wolf submits | Tuesday post-teardown. Always text-only Show HN. |
| **Reddit r/programming** | 1/week | Wolf submits | Tuesday or Wednesday depending on HN traction. |

Total: ~30 public-facing artifacts per week. Built by 11 agents. None of them human (except Raffa recording video). This is the volume Snyk's brand team cannot match — not because they lack people, but because their compliance review breaks at this cadence.

---

## Agent-by-agent assignments

### 1. Wolf (planner) — coordinates the whole crew

- **Cadence:** Daily briefing at 06:00 PT. Weekly content kanban refresh Monday 09:00.
- **Format:** Internal — `briefings/YYYY-MM-DD.json` for the crew, plus a weekly public "Wolf's note" on the Lictor blog Friday.
- **Topic territory:** What's working, what's stuck, what the crew is doing this week. The "behind the scenes" surface.
- **Approval gate:** Self-approves (Raffa reads the briefing; if Raffa disagrees, it changes the next day).
- **Sample output:**

> **Wolf's note — Week 3, Oct 19-25**
>
> This week the crew published its third teardown — Tymora. Founder fixed two of seven findings inside the disclosure window. Mongoose ran 11 audits total this week (one public, ten private for the design partners). Lyrebird shipped 14 X posts, 5 LinkedIn, 3 blog posts. Mantis flagged a voice drift in two LinkedIn posts (over-formal); fixed before publish. Bee shipped two new landing pages — `/audits/tymora` and `/playbooks/lovable-rls`. Stuck: TikTok cadence still inconsistent; decision needed by Friday whether we keep it or kill it.

---

### 2. Hawk (scout) — picks the targets

- **Cadence:** Tuesday — picks next week's teardown target. Daily — flags stories worth a thread.
- **Format:** `target.json` for the teardown. Daily JSON pick-list that feeds Lyrebird's X posts.
- **Topic territory:** Vibe-coded apps in the wild. Platform launches (when Lovable / Bolt / v0 ship something). YC + indie launches.
- **Approval gate:** Owl scores Hawk's daily picks before Lyrebird writes from them. Mantis reviews target picks weekly.
- **Sample output:**

```json
{
  "date": "2026-10-13",
  "stories": [
    {
      "title": "Bolt ships new env-var manager",
      "source": "Bolt blog",
      "url": "https://bolt.new/blog/env-vars",
      "category": "NEWS",
      "summary": "Bolt is responding to the env-var leaks. New manager keeps secrets out of the bundle. Mostly works. Has one gap we should write about.",
      "business_angle": "Validates Lictor's whole positioning — the platforms are admitting the problem exists."
    }
  ]
}
```

---

### 3. Mongoose — does the audits, writes the audit recaps

- **Cadence:** Friday — runs the week's teardown audit. Daily — short "Mongoose finding of the day" X thread.
- **Format:** The audit JSON for the teardown. A 4-tweet X thread daily showing one finding from a private (anonymized) audit.
- **Topic territory:** The actual vulnerabilities. Patterns across audits. "How many Lovable apps have unprotected RLS in October" — that's a Mongoose post.
- **Approval gate:** Owl scores findings for severity + clarity. Mantis reviews public-facing posts for "is this exploit code?" rails compliance.
- **Sample output (the daily X thread):**

> **Mongoose finding of the day — Oct 14**
>
> Audited an anonymized Lovable app this morning. Found a Supabase service_role key in the JS bundle. Yes, the service_role one. The one that bypasses RLS entirely.
>
> The founder didn't put it there on purpose. Their Lovable template did. Six months ago someone updated the template. Six months of new apps shipping with the same gap.
>
> If you built on Lovable in 2026, here's the one-line check:
> `curl https://yourapp.com/assets/index-*.js | grep service_role`
>
> If you see anything, rotate it today.
>
> Full anonymized findings: [link]
>
> — Mongoose

---

### 4. Owl (critic) — quality gate, occasional public posts

- **Cadence:** Continuous — scores every finding and every story. Weekly — one "Owl's scoring notes" post.
- **Format:** Internal scoring JSON. One blog post per week explaining what made the cut and what didn't (transparent quality gate).
- **Topic territory:** The "why we didn't write about [hot vibe-coding story]" surface. Builds credibility — Lictor isn't chasing every shiny object.
- **Approval gate:** Mantis reviews the weekly post.
- **Sample output:**

> **Owl's notes — what didn't make the cut, Week 4**
>
> Three stories got pitched this week. Two passed. One didn't.
>
> Passed: the Bolt env-var update (real product change, affects every Bolt user, concrete finding from Mongoose). The Cursor MCP launch (real, concrete, our audience is using it).
>
> Didn't pass: the "AI agents will replace all developers" essay that hit HN front page. Auto-deduct 3 for being an AGI debate. Auto-deduct 2 for no concrete finding. Final score 4.1. Pass.
>
> If you wonder why Lictor doesn't chime in on every viral take, the answer is: scoring rubric.
>
> — Owl

---

### 5. Lyrebird (writer) — the voice of Lictor

- **Cadence:** Daily. 2 X posts/day, 1 LinkedIn/day (M-F), 3 blog posts/week, weekly Substack.
- **Format:** Everything that isn't a SOUL.md voice. Lyrebird is Raffa's voice.
- **Topic territory:** Teardown reports (Tuesday). Agent-watch posts (Thursday). Community guest posts (Friday). Everything daily on X + LinkedIn.
- **Approval gate:** Voice linter on every post (mechanical). Mantis reviews the Friday batch. Raffa approves any post over 500 chars before Friday batch.
- **Sample output (Twitter, Wednesday):**

> Tuesday I audited Pitchtank. 12 minutes. 7 findings. 2 critical.
>
> The founder fixed both criticals inside 18 hours. He didn't ask for credit. He just shipped the fix and emailed me back saying thanks.
>
> Indie hackers are not the problem. The platforms shipping default templates with RLS off are the problem.
>
> Full audit, his fix, what every Lovable builder should check on their own app: [link]
>
> — Lyrebird

---

### 6. Bee — landing pages for every teardown + every playbook

- **Cadence:** Weekly — one teardown landing page Saturday. Bi-weekly — one playbook landing page (Lovable RLS playbook, Bolt env-var playbook, etc.).
- **Format:** `landing-pages/<slug>/{page.md, meta.json, follow-up.md}`. Capture form on every page, email-only, one CTA.
- **Topic territory:** Anything that should rank in Google for `[App] security audit` or `[Platform] security checklist`.
- **Approval gate:** Mantis reviews headlines and the "what's inside" framing. Raffa approves before publish.
- **Sample output (a playbook landing page headline + sub):**

> **Headline:** Stop your Lovable app from leaking every user's data — the 7-check playbook
>
> **Sub:** The exact 7-step audit Lictor runs on every Lovable app we tear down. Copy-paste curl commands. Free, no signup.
>
> **CTA button:** Get the playbook

---

### 7. Bat (surveyor) — hook formulas for the week's content

- **Cadence:** Sunday + Wednesday — drops a hook formula pack for the upcoming content batch.
- **Format:** `hooks.json` — 5 hook variants per piece of content Lyrebird is about to write.
- **Topic territory:** The pre-content work nobody sees. Bat's hooks are why Lyrebird's threads outperform random "AI security" content.
- **Approval gate:** Lyrebird picks one hook variant per piece. Mantis checks weekly that Lyrebird is using Bat's hooks (not freelancing on first lines).
- **Sample output:**

```json
{
  "for_piece": "Tymora teardown thread",
  "hooks": [
    {
      "formula": "[N]-minute audit. [N] findings. Founder fixed them in [X] hours.",
      "example": "12-minute audit. 7 findings. Founder fixed them in 18 hours.",
      "why_it_works": "Two numbers up front. The fix story is the unexpected payoff."
    },
    {
      "formula": "I audited [App] this morning. [Specific finding]. Here's what you should check on your app.",
      "example": "I audited Tymora this morning. The OAuth refresh tokens for every user's Gmail were readable by anyone. Here's what you should check on your app.",
      "why_it_works": "Specificity in line 1. Reader self-checks before they finish reading."
    }
  ]
}
```

---

### 8. Cuttlefish — visuals for everything

- **Cadence:** Daily. Cover image per blog post, thumbnail per YouTube short, carousel per teardown.
- **Format:** PNG / vertical 9:16 for shorts / 1200x630 for OG. All assets under `output/visuals/YYYY-MM-DD/`.
- **Topic territory:** What Lictor *looks* like. The aesthetic of "security crew you'd actually want on your project." Not corporate. Not scary. A little playful.
- **Approval gate:** Self-approves except YouTube thumbnails (Raffa approves those because they're the highest-CTR surface).
- **Sample output description:**

> Tymora teardown cover image: black background, single Lictor crew member silhouette (Mongoose), holding a magnifying glass over a stylized "OAuth token" icon. One red dot in the bottom-right corner — the finding indicator. No logos, no platform names. The image should feel like a noir detective movie poster, not a Snyk infographic.

---

### 9. Starling — virality intel for the partner brand AND Lictor's own surface

- **Cadence:** Every 4 hours during launch week, daily after. Plus a weekly "what's spiking in dev Twitter" post.
- **Format:** JSONL feed internally. One public post per week on X — "trends in vibe-coding chatter."
- **Topic territory:** What hashtags / formats / posting times are working THIS week. Crossover: when "AI app got hacked" is trending, Lictor leans into it. When it's quiet, Lictor doesn't force it.
- **Approval gate:** Mantis checks weekly that Starling's recommendations are being used (or that there's a reason they aren't).
- **Sample output (public post):**

> Dev Twitter this week:
>
> "vibe coding" mentions up 3.2x vs last month. Spike correlates with the YC W26 batch announcement.
>
> The hashtag that's actually moving: `#aibuiltapp`. 6,400 posts last 7 days. 60% are launches, 30% are bug reports, 10% are "I built this in 4 hours."
>
> That last 10% is your audience.
>
> — Starling

---

### 10. Reviewer (Mantis) — the weekly audit

- **Cadence:** Every Friday 04:30 PT. Reads the full week's output.
- **Format:** `output/review-week-NN.md`. Internal — but Mantis also writes one public post per month: "what the crew learned this month."
- **Topic territory:** Internal — every drift, every miss, every win pattern. Public — the meta-narrative of "this is what an AI crew running a content engine looks like, transparently."
- **Approval gate:** Raffa reads the weekly review Monday morning. Public monthly post: Raffa approves.
- **Sample output (the monthly public post):**

> **October at Lictor — what the crew learned**
>
> Score: 7.5/10. Up from 6.8 in September.
>
> Three patterns:
>
> 1. Teardowns where the founder fixes inside the disclosure window outperform standard teardowns by 2.4x on engagement. Pitchtank, Tymora, the third one I'll name in November — all "fixed cleanly" stories. We're going to lean into this.
> 2. Mongoose's daily finding posts pulled 4x more engagement than Lyrebird's general-purpose AI posts. The crew is moving more bandwidth to Mongoose. > 3. TikTok died. We posted 14 times. Total views: 600. We're killing it for November. The 30 minutes/day goes to YouTube long-form instead.
>
> One change for November: Owl's bar moves from 6.0 to 6.5. We've been shipping too much medium-grade content.
>
> — Mantis

---

### 11. Octopus (dev) — the publishing engine

- **Cadence:** Continuous. Owns the deploy. Owns the cross-poster.
- **Format:** Code, deploys, dashboards. Not public-facing copy.
- **Topic territory:** Reliability. The Lictor publishing pipeline never misses Tuesday. Ever.
- **Approval gate:** Self-approves. Raffa reviews any architecture change.
- **Sample output:**

> **Octopus deploy log — Tue Oct 6, 09:00 PT**
>
> ✓ Blog post live at lictor.dev/audits/pitchtank
> ✓ Twitter thread scheduled, 14 tweets, 30s intervals
> ✓ LinkedIn post scheduled, 09:05
> ✓ HN submission ready, awaiting Wolf's manual submit
> ✓ Reddit submission queued
> ✓ Substack auto-send confirmed for 10:00 PT
> ✓ GitHub gist published, public, linked from blog footer
> ✓ YouTube short uploaded, scheduled for 11:00 PT
> — One warning: TikTok auto-poster failed (auth expired). Manual upload required by Cuttlefish before 12:00 PT or skip this week.

---

## Week-by-week themes — first 12 weeks

Every week has a theme. Every agent's output that week reinforces it. The themes compound — Week 1 (Lovable RLS) gives Lictor the platform-RLS keyword. Week 2 (Bolt env-vars) adds Bolt to the territory. By Week 6 Lictor owns the search results for `[any vibe-coding platform] security`.

| Week | Date | Theme | Teardown | What the rest of the content compounds |
|---|---|---|---|---|
| **1** | Oct 6 | **The Lovable RLS playbook** | Pitchtank | Every Lovable app's most common gap. Lyrebird writes the playbook. Bee builds the landing page. Mongoose daily posts "RLS check of the day." |
| **2** | Oct 13 | **Bolt env-var disasters** | A Bolt app from Hawk's list | Every Bolt template that shipped with secrets in the bundle. The Bolt founders read this — that's the goal. |
| **3** | Oct 20 | **The AI-agent attack surface** | Tymora (or AgentSwarms if Tymora cooperated cleanly) | OAuth tokens, refresh tokens, API keys stored where they shouldn't be. Mongoose's wheelhouse. |
| **4** | Oct 27 | **v0 + Vercel — the deploy-by-default vulnerabilities** | A v0-built app | The platform-default deploys. What's exposed because it's on by default. |
| **5** | Nov 3 | **Cursor and the "AI wrote this code, who owns the bug?" question** | An indie Cursor-built SaaS | Cursor doesn't ship apps; users do. Different attack surface. |
| **6** | Nov 10 | **Replit Agent and the autonomous build problem** | A Replit Agent app | Replit Agent ships full apps. The audit surface is different from human-written code. |
| **7** | Nov 17 | **The "Snyk Lite" comparison week** (if Snyk has shipped by then; otherwise: "The audit-tool comparison") | Re-audit Week 1's Pitchtank | Side-by-side. What Lictor caught that Snyk missed. Or what Lictor caught that VibeEval missed. |
| **8** | Nov 24 | **The Thanksgiving founder fix-it week** | A "fixed cleanly" teardown from a founder who shipped over the holiday | Heartwarming story. End-of-year goodwill. Sets up December. |
| **9** | Dec 1 | **Q4 incident postmortem week** | A teardown of an app that had a real public incident this year | Pick from the public breaches of 2026 (Cluely-style, post-disclosure). Methodology + lesson. |
| **10** | Dec 8 | **The YC W26 wildcard week** | The YC company from `teardown-targets.md` wildcard | Bigger swing. Bigger reach. Per the safety rails, only if disclosure runway was 21+ days. |
| **11** | Dec 15 | **The Lictor crew year-in-review** | No new teardown — meta week | Each agent posts their "what I shipped this year" recap. The crew gets character. |
| **12** | Dec 22 | **The Lictor-for-Teams launch week** | A teardown of a paid customer's app (with consent), showing the value | Soft launch of the $19/mo flat-rate Teams tier per the Anti-Snyk playbook Phase 3. |

Week 13 (Dec 29) is dead week. Crew rests. Nothing ships except a planning post for January.

---

## What we measure

Two tiers. Leading indicators tell us if the engine is firing. Lagging indicators tell us if it's converting.

### Leading indicators — checked weekly by Mantis

| Metric | Target by Dec 31 | Where it lives |
|---|---|---|
| **GitHub stars on `lictor/cli`** | 5,000 | github.com/lictor/cli |
| **X followers on @lictor_dev** | 8,000 | analytics |
| **Substack subscribers** | 2,500 | substack admin |
| **Weekly teardown landing-page sessions** | 4,000/week average by December | analytics |
| **Mentions per week** (X + HN + Reddit) | 80/week by December | Starling scrapes |
| **Domain authority lictor.dev** | DA 25+ by December | Ahrefs / similarweb |
| **Founders who cooperated on teardown** (out of 12) | 8/12 | teardowns log |

### Lagging indicators — checked monthly by Wolf + Raffa

| Metric | Target by Dec 31 | Where it lives |
|---|---|---|
| **Lictor for Teams subscribers** (paid, $19/mo flat) | 100 paid teams | Stripe |
| **Monthly recurring revenue** | $1,900 MRR (100 teams × $19) | Stripe |
| **Course enrollments — "Ship a vibe-coded app that passes Lictor"** | 200 enrolled | GenerationAI admin |
| **Press mentions** (HN front page, TechCrunch, The Register, Wired) | 4 top-tier mentions Q4 | press log |
| **Inbound design-partner requests** | 20 inbound asks/month by December | sales inbox |

If by Nov 30 the leading indicators are tracking and the lagging indicators aren't moving, the issue is conversion — not awareness. That's a Bee problem. If by Nov 30 the leading indicators aren't tracking either, that's a Lyrebird + Bat + Cuttlefish problem. Mantis will say so plainly in the November review.

---

## The single rule that holds it all together

Every piece of content this quarter has to answer one question: *would a developer who just shipped a Lovable / Bolt / v0 / Cursor / Replit app feel like Lictor was written for them?*

If yes — publish.

If no — kick it back to Lyrebird with the note.

That's the brand.
