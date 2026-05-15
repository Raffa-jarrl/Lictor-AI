# Lictor — Monthly Investor / Acquirer Update Template

> **Generated:** 2026-05-15
> **First send:** July 1, 2026 (per year-plan-2026-2027.md, M2)
> **Companion docs:** year-plan-2026-2027.md, m-and-a-strategy.md, weekly-operating-rhythm.md
> **What this doc is for:** the monthly cadence and exact format Raffa uses to keep ~10 carefully chosen people warm for 12+ months before any of them are needed.

---

## 1. The strategic posture

Two jobs. Always two.

**Job 1: Build relationships before they're needed.** When a Snyk corp-dev director, a Bessemer partner, or a retired Sailpoint CISO finally has a reason to talk to Raffa — an acquisition discussion, a funding round, a board seat — the conversation should not start cold. It should start at "I've been reading your monthly updates for 14 months. I know your numbers. I know what's hard. Let's talk." Founders who only contact investors when they need money have weak leverage. Founders who provide monthly updates have warm channels when the moment arrives.

**Job 2: Force honest monthly self-assessment.** The act of writing the update — same template, same metrics, same "what's hard" section — exposes drift. The month Raffa can't fill in the "what shipped" section, the month MRR went sideways, the month the hard part repeats from last month — those are the months the update format is doing its real job: telling Raffa the truth before reality does.

**Not weekly.** Weekly is noise. Weekly devalues each touch — by month 3 the recipient archives without reading. Weekly also makes "what's hard" performative (no real friction surfaces in 7 days).

**Not quarterly.** Quarterly is too rare to build relationship gravity. The recipient forgets the prior update. The cadence doesn't compound. Quarterly is what a CEO with a board sends; monthly is what a founder building a category sends.

**The list size.** Start at ~10. Never above 25, even when the temptation is strongest (it will be — Q1 2027, post-conference, post-press-hit). Every name on the list should be one Raffa would personally call to discuss a $500k decision. If Raffa wouldn't call them, they don't belong on the list.

**The tone.** Never asking for anything until there's a genuine ask. Never bragging — numbers do the bragging on their behalf. Always honest about what's hard. Plain English. Same voice as every other Lictor artifact. If a recipient could mistake the update for a marketing newsletter, it has failed.

---

## 2. The list — who should be on it

By archetype. Examples are illustrative, not commitments.

**Plausible acquirers (3-5 people).** *Personal* contacts within target companies — never the vendor PR address, never the corp-dev intake form. Examples:

- A senior PM or director at Snyk who works on the OSS-friendly side — Sentinel Cloud, the Snyk Open Source team, the Invariant Labs integration crew. Someone who already lives in the OSS-and-security overlap.
- Someone at GitHub Security, Anthropic Safety, or Cloudflare's developer-security team. Title matters less than mandate — they should be allowed to take an exploratory coffee.
- An M&A advisor or boutique investment banker in the security / dev-tools space. *Not* for a current deal. For the network — they introduce founders to corp-dev teams a year before either side knows there's a deal.

**Strategy.** Cold-warm via LinkedIn + conference intros + content engagement. Target one new warm intro per quarter. Never lead with the acquisition frame — always lead with the work. The acquisition conversation happens, eventually, because the relationship existed first.

**VC partners (2-3 people).** Specifically Series A partners at firms that have done OSS developer tools — Bessemer (Sentry, HashiCorp), a16z (GitLab, Material Security), Founders Fund (Anduril-adjacent), Index (Datadog), or a sector-specific cyber fund (Ten Eleven Ventures, Forgepoint Capital, YL Ventures). Not seed (Lictor is past seed-stage on metrics by Q4 2026). Not growth (Lictor is below their threshold for a year+).

**Strategy.** Get on their radar through the content engine — Series A partners read everything in their thesis areas. Be findable. Twitter, the newsletter, the conference talk all feed the funnel. They self-introduce when ready.

**Strategic mentors (3-4 people).** People with no transactional interest. They give the calls, the texts, the "you're about to make a mistake" emails.

- A cybersecurity veteran — a CISO at a F500, a retired exec from Snyk / Palo Alto / Sailpoint / CrowdStrike. They've seen the deal flow from the buyer side.
- An OSS-business veteran — alum from HashiCorp, GitLab, Tailscale, PostHog, Sentry. They've solved the Foundation/LLC governance question, the dual-license question, the community-vs-commercial tension.
- A category-creating founder in an adjacent space — someone who built a brand category from an OSS root. They've made the calls Raffa will make.
- A startup-CEO-mentor for the founder-level support — someone whose first-call status is just "Raffa, what are you doing?"

**Friendly competitors (1-2 people).** A founder at Aikido, VibeEval, or Symbioticsec. The frame: the AI-app-security category is large enough that all of us win if the category wins, and small enough that we all lose if it doesn't. Open channel for shared learnings, shared press contacts, shared "this acquirer is asking weird questions" signals. Avoid pure-zero-sum competition. Don't share customer lists, pricing experiments, or unreleased product strategy — share the rest.

---

## 3. The list management process

**Where the list lives.** A private CRM — Notion, Airtable, or a simple Google Sheet. *Not* in the Lictor repo. *Not* in any agent's context. Anything pseudo-private the recipient could later read about themselves is a relationship-ender.

**What's tracked per person.** Name, role, company, last contact (date + medium), what they're interested in (1-3 tags: "OSS governance," "AI safety," "DevSecOps M&A"), open-rate on the last 3 updates, any notes from real conversations.

**How people get added.** Organic only. Raffa has had 2+ meaningful conversations with them (not a single conference hello). They've shown they read carefully — replied to a tweet thread, sent a thoughtful question, made a real intro. Cold-add is forbidden — the moment someone first hears from Raffa via a monthly update they'd never asked for is the moment the update reads as spam.

**How people get removed.** Silently. If 3 consecutive monthly updates with no acknowledgment (no reply, no open, no in-person reference), drop them. No farewell email. No "I noticed you stopped engaging." Just remove. If they later resurface, they get re-added.

**Same body, personalized intro.** The 80/20 trick: same body for everyone (the numbers, the shipped list, the what's hard, the next month). Personalized intro line per recipient — references the last conversation, a thing they posted, a relevant news item in their world. One line. Two minutes per recipient. The personalization signal is the relationship; the body is the substance.

---

## 4. The monthly update template

This is the literal format. Raffa pastes this into the email tool, fills it in, sends it.

```markdown
# Lictor Monthly Update — [MONTH YEAR]

Hi [Name],

[1-line personal intro — reference the last conversation, something they posted, or a relevant news item. The signal that this isn't a blast.]

## TL;DR

- [Most important — could be a metric, a customer, a hire, a partnership]
- [Second]
- [Third]

## Numbers

| Metric | This month | Trend |
|---|---|---|
| GitHub stars | X | +Y vs last month |
| Weekly active skill users | X | +Y |
| Paying Teams subs | X | +Y |
| Newsletter subscribers | X | +Y |
| MRR | $X | +$Y |
| Cash position | $X (Y months runway at current burn) | — |

## What shipped

[3-5 bullet points of concrete things shipped this month. Code, content, partnerships, customer logos, product launches. Be specific.]

## What's hard

[1-2 honest paragraphs about the actual challenges this month. NOT theatrical "things are great." Real friction. This is the section that earns trust.]

## What's next month

[2-3 bullet points of what we're optimizing for in the next 30 days. Stay specific. Not "we're going to keep growing."]

## How you can help (optional)

[Only when there's a real ask. Some months: blank. Some months: one specific ask — an intro, advice on a decision, feedback on a draft. Never multi-ask. Never desperate.]

## Bonus

[Optional. A piece of long-form thinking, a teardown to read, a video to watch. Provides value without demanding action.]

— Raffa
```

---

## 5. Section-by-section guidance

**TL;DR.** 3 bullets, max. Pick the most *newsworthy* item first — not the one Raffa is proudest of. Not "we shipped a thing"; "we landed first Lovable platform partnership." The first bullet is the one that survives if the recipient reads nothing else.

**Numbers.** Same metrics every month. Consistency is the asset. Don't add a metric in month 6 because it makes you look good — adding it makes month 5's update look incomplete in hindsight, and the recipient notices. If a metric stops mattering, keep it for 3 more months, then announce its removal in the body with a sentence on why.

**What shipped.** Concrete. "We shipped Studio v0.1.0 with 340 downloads in week 1" not "we made progress on Studio." If the bullet doesn't have a number or a proper noun, rewrite it.

**What's hard.** The most important section. Most founders skip this. It's what builds genuine relationship over the year. Examples:

- "Teams conversion is below expectations — 35% of pre-orders converted vs. 60% target. We're running 10 customer-dev calls to understand why."
- "Cron broke for 30h overnight; 9 of 11 agents went dark until we caught it. Fixed in 4 hours. Documented at [link]."
- "The self-teardown found a real auth bug in Lictor itself. Patched, disclosed, postmortem written."

If the section reads as humble-brag ("our biggest challenge is how to handle all this inbound"), Raffa is not yet writing it correctly.

**What's next month.** Falsifiable predictions. Next month Raffa will be able to write "we said X, we shipped Y." That's how the list builds confidence that Raffa can predict his own work. Vague predictions ("keep growing") signal an unsteady founder. Specific predictions ("VS Code v0.1 ships Dec 22, 100 Teams subs by Dec 31") signal a builder.

**How you can help.** The moment Raffa uses this in month 1, recipients ignore it for months 2-11. Use it sparingly — about 1 month in 3, on average. Specific asks ("intro to [Name] at [Company] re: bug-bounty program design") work; vague asks ("any advice on positioning?") don't. Never multi-ask. Never desperate.

**Bonus.** Optional. A teardown link, a long essay, a recorded talk. Signals "I'm thinking big" without asking for anything. Eventually, recipients reply to the bonus — that's the moment the relationship becomes mutual.

---

## 6. Cadence + send mechanics

**Send date.** 1st business day of the month. No later than the 3rd. Late = worse than skipping. Skipping = signals burnout or a quiet death. Reliability is the asset.

**Send time.** 10-11am recipient's local timezone. Use a tool that handles per-recipient timezone, or batch to 3 timezones (US East, US West, Europe/Israel) and send each batch separately. Never sent at 2am-anywhere.

**Send mechanism.** Gmail merge (GMass, Mailmeteor) or a founder-grade tool like Buttondown — *not* Mailchimp, *not* a generic newsletter platform. The personalization line must look hand-typed because it was. Generic-newsletter unsubscribe footers are the signal that breaks the relationship frame.

**Reply protocol.** Respond to every reply within 48h. Even short ones. Even one-word "thanks." The reply is the relationship.

**Tracking.** A separate sheet — who's opening vs not. If someone hasn't opened 3 in a row, drop them silently. Don't ask. Don't follow up. They're not the right person on the list right now; the seat is more valuable than the relationship at that point.

**The "list never grows wild" rule.** Every Q1 and Q3, prune. Net additions cap: 2 per quarter. The list grows slowly or not at all. The temptation to add the new "interesting" person every conference week will be constant; resist.

---

## 7. The first 3 months of updates — content sketch

The first three months establish the rhythm. By month 3, recipients know to expect it.

**July 2026 (first update — pre-launch, pre-public).** TL;DR: "Lictor goes public Oct 6. Foundation work shipped this month — repo public, first 4 founder videos, AUDIT.json proposal sent to 5 vendors." Numbers: GitHub stars 500, design partners installed 5, newsletter 100, MRR $0. What's hard: "Audience-building from zero is slow. 500 stars in a month feels fine on paper; one weekend of one Krebs newsletter would 10x it. The compound has to start somewhere." Ask: none. Just FYI. Bonus: link to the first founder video.

**August 2026.** TL;DR: "First 5 design partners running. Self-teardown landed — Lictor audited Lictor, found 3 bugs, fixed and documented. Press list compiled." What's hard: "The self-teardown found a real RLS bypass in our own onboarding flow. Embarrassing to find, useful to publish. The writeup is at [link] — the act of publishing it is the point." Ask: maybe one specific intro — a cybersec journalist Raffa wants to brief pre-launch. Bonus: the self-teardown writeup.

**September 2026.** TL;DR: "Pre-launch prep complete. Sentinel 0.1.0 GA. 50 pre-orders captured. Disclosure emails out to 5 teardown targets." What's hard: "Disclosure responses from 5 teardown targets came back mixed — 2 acknowledged and patched, 1 quietly fixed without acknowledging, 2 silent. Our Sept 22 disclosure window expires Oct 6. We hold to the timeline." Ask: none. Bonus: the dress-rehearsal post-mortem.

By October, the list knows: monthly. First business day. Numbers, ships, hard, next, sometimes ask, sometimes bonus. The shape is now an asset.

---

## 8. What the year-1 endgame looks like

By June 2027 (the month after this 12-month plan ends), Raffa has sent 12 monthly updates to ~10-20 people. Roughly:

- 30-40% engage actively — reply, retweet, send intros, attend the conference talk
- 30-40% read consistently, never reply, are quietly compounding
- 20-30% have been dropped after 3 silent months

Of the active 30-40%, by mid-2027 there should be 2-3 people in the list who would *take Raffa's call any time*, who *already know Lictor's numbers cold*, and who *have introduced Raffa to at least one corp-dev contact, one Series A partner, or one customer*. Those 2-3 people are the entire purpose of the cadence.

If they don't materialize by mid-2027, the cadence is not the problem — the relationship-building inside the cadence is. Adjust then.

---

— End of template doc.
