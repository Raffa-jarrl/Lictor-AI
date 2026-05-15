> **NOTE (May 2026 update):** Course revenue line REMOVED from Lictor's plan. The course at generationai.com is a separate consulting business and is no longer part of this project. References below that mention "Course", "course enrollments", or course-derived revenue should be treated as historical and substituted with zero. Other revenue lines (Teams, AaaS, Enterprise) stand.

# Lictor quarterly retrospective — template

> **Generated:** 2026-05-15
> **Cadence:** Last 3 days of each quarter — Mar 29-31, Jun 28-30, Sep 28-30, Dec 29-31
> **Owner:** Raffa + agent crew (Mirror, Probe, Conductor feed inputs; Raffa writes the synthesis)
> **Companion docs:** `year-plan-2026-2027.md` (the plan to retro against), `weekly-operating-rhythm.md` (the cadence this slots into), `operation-triumph-expanded.md` (the 5-track structure)
> **Output destination:** `~/Lictor/docs/business/quarterly/YYYY-QN.md`

---

## 1. The retro thesis

Plans drift. Drift compounds. The retro is the only structural moment where Raffa stops shipping and looks at the year from outside the week.

Lictor is solo founder plus agent crew. Without the retro, Raffa optimizes locally — this Tuesday's teardown, this Friday's newsletter, this month's metric. Nobody on the team can zoom out to "are we still building the right thing?" except Raffa, and Raffa only zooms out if the calendar forces it.

The retro is also where causation gets captured, not just outcomes. "We shipped 12 teardowns" is a count. "The cornerstone post drove 4x the newsletter signups of a teardown in a slow week" is a *learning*. The next quarter benefits more from one captured learning than ten captured counts.

This is NOT a sprint review. NOT a 1-1. NOT a metrics dashboard glance. It is a 2-3 day dedicated strategic reflection with structured inputs, structured output, and a decision to keep or change the next quarter's plan.

So next quarter: enter the retro days knowing they exist, and protect them.

---

## 2. When to run it

- **Q3 2026:** Sep 28-30 (the first one; right after pre-launch hardening, before launch)
- **Q4 2026:** Dec 29-31 (year-end; review of the launch quarter)
- **Q1 2027:** Mar 29-31 (Scale quarter review; AI Engineer Summit just shipped)
- **Q2 2027:** Jun 28-30 (Dominate quarter review; the year ends here)

Pre-scheduled in the year plan. Block the calendar — no meetings, no shipping during retro days. If retro falls on a Tuesday teardown day, shift the teardown to the Tuesday after.

Run from home or somewhere quiet. Not a coffee shop. The work is reflection, not output — interruptions kill it.

Recommended: do the Q4 (Dec) retro from a different location than the other three. A hotel, a co-working space, a borrowed house. Year-end retro deserves a setting change — the year-end question is bigger ("what's the next year for?") and the new setting helps the brain answer it.

So next quarter: the retro days are on the calendar already. Don't take a meeting that overrides them.

---

## 3. The retro inputs

Gather these in the week BEFORE the retro starts. Block 2-3 hours mid-quarter-end-week. The retro itself is reflection, not data-collection — if you're still hunting inputs on day 1, it becomes a status review.

**Numbers**
- 3 monthly metric snapshots from `docs/business/metrics/YYYY-MM.md`
- 12-13 weekly Mirror reviews from `output/review-week-NN.md`
- Probe's 12-13 weekly competitive scans (look for cumulative drift, not single-week noise)
- Conductor's daily briefings from `briefings/YYYY-MM-DD.json` — scan for escalation patterns
- The data-room quarterly financial summary at `docs/business/diligence/financials-qN-YYYY.md`

**Artifacts**
- Teardowns shipped — count, headlines, post-publish engagement (HN points, newsletter conversion, attributable stars)
- Blog posts shipped — same engagement breakdown
- Founder videos — view counts, completion rates, comment threads worth surfacing
- Newsletter sends — open rate, click-through, unsub deltas
- Product ships — skill updates, Studio + VS Code milestones, SDK versions

**Decisions**
- What did Raffa decide that wasn't pre-planned? (Search `docs/business/decisions/`; if none, that itself is a signal.)
- What did agents propose that Raffa accepted vs rejected?
- What customer requests or community feedback shifted the roadmap (even slightly)?

**Calibration**
- 5 entries from `~/GenerationAI/calibration/dor-voice/` — what Raffa edited in writer drafts (these reveal what the voice rules don't yet capture)
- 5 rejection entries — what didn't make the cut and why (these reveal what the brand is hardening against)

The inputs are the receipts. The retro is what you make of them. Pulling receipts during the retro corrupts the reflection.

So next quarter: input-gathering is a recurring calendar event the Friday before retro week.

---

## 4. The 5-track review

Walk each of the 5 cross-cutting tracks. For each, fill in the five cells.

### Track: Product

- **Plan said:** _[paste the per-track ship list from the year plan for these 3 months]_
- **Reality shipped:** _[specific — files, version tags, releases. "Studio v0.1 shipped Dec 22" not "on time"]_
- **Drift:** _[e.g., "plan said VS Code v0.1 by Dec 22; actual Dec 28; 6-day slip"]_
- **Why:** _[honest. "Code signing failed twice due to entitlement mismatch; 4 days lost."]_
- **One lesson:** _[the insight that should change next quarter's product plan]_

Good drift: 1-2 weeks late because scope grew and the bigger scope is right. Concerning: 3+ weeks late on a critical-path ship from an untracked dependency.

### Track: Content

- **Plan said:** _[teardown count, video count, blog count, newsletter sends]_
- **Reality shipped:** _[actual numbers + headlines]_
- **Drift:** _[e.g., "plan said 12 teardowns; shipped 10; skipped Weeks 6 and 11"]_
- **Why:** _[honest. "Bolt founder declined disclosure, no fallback ready"]_
- **One lesson:** _[e.g., "always have 2 teardown targets in flight per week"]_

Good drift: a teardown swap because original target got fixed/sold/abandoned. Concerning: cadence missed without a swap on deck. The teardown cadence IS the asset; 2+ weeks consecutive miss is the engine stalling.

### Track: Community

- **Plan said:** _[stars, design-partner installs, Discord size, external PRs, press]_
- **Reality shipped:** _[actuals]_
- **Drift:** _[numerical gap]_
- **Why:** _[honest. "Design partners stalled at 3 of 5 — install was rough"]_
- **One lesson:** _[e.g., "design partner install must be 10 minutes flat; instrument it"]_

Good drift: organic momentum exceeded plan. Concerning: stars grew but weekly-active didn't (vanity inflation), or external PRs are zero (no contributor pipeline).

### Track: Business

- **Plan said:** _[Teams subs, MRR, AaaS customers, Course pre-orders, Enterprise pilots]_
- **Reality shipped:** _[actuals + dollar amounts]_
- **Drift:** _[e.g., "plan 100 Teams subs by Dec 31; shipped 67; $1,273 MRR vs $1,900 target"]_
- **Why:** _[honest. Pricing? Value prop? Audience size? Checkout friction?]_
- **One lesson:** _[what changes about the business model next quarter]_

Good drift: one stream overshoots, another undershoots, summing to plan. Concerning: all streams underperform — audience isn't ready, OR products don't match desire (Teams sells, Course doesn't).

### Track: Acquisition-readiness

- **Plan said:** _[diligence docs, financial cleanups, IP register, lawyer engagements, acquirer conversations]_
- **Reality shipped:** _[artifacts that exist now that didn't 90 days ago]_
- **Drift:** _[gaps in the diligence folder; missing summary; un-engaged lawyer]_
- **Why:** _[honest — usually "deprioritized for shipping," which IS the trap]_
- **One lesson:** _[which item compounds vs which is a checkbox]_

Good drift: scope expanded because something new became diligence-relevant. Concerning: nothing changed all quarter — the position is decaying.

So next quarter: each track's "one lesson" feeds plan ratification (section 8) as a candidate change.

---

## 5. The "what worked" log

The 3-5 things that worked BETTER than planned this quarter. Not "what didn't fail" — what overshot.

For each:

- **What worked:** _[specific. "Self-teardown post hit 4,200 stars in 48h vs 800 modelled."]_
- **Why (the actual mechanism):** _[timing? audience receptivity? a founder's response? viral moment? luck? structural advantage? "Lucky timing on HN" is a real answer.]_
- **Can we reproduce it?** _[Yes → next quarter's plan includes the mechanism. Probably-no → catalog as one-time gift. Unsure → schedule a small experiment.]_

Often the most valuable section for the YEAR. Most retros over-index on what didn't work because failure is loud. The "what worked" log is the asymmetric upside — moves that overshot are moves to lean into structurally.

Lictor-specific tendency: under-celebrating overshoot. The week the cornerstone post hit, Raffa's instinct will be "noted, on to the next teardown." Resist.

So next quarter: a "what worked" gets added to the plan as either a structural change (reproduce) or a watch item (catalog).

---

## 6. The "what we didn't see coming" log

Surprises — both directions.

**Pleasant:** _[e.g., "A Register journalist reached out unsolicited after Teardown #7." or "Lovable's CTO replied to the AUDIT.json proposal."]_

**Unpleasant:** _[e.g., "Snyk shipped a free vibe-coder tier in Nov, 2 months earlier than predicted." or "AaaS Customer #2 churned — wanted one-time, not quarterly."]_

For each surprise, note:

- **The signal you should have caught earlier:** _[Probe intel ignored? Community comment dismissed? Customer call flag missed?]_
- **What to change in the sensing apparatus:** _[e.g., "Probe scans Snyk press releases weekly, not just product pages" or "customer 1:1 log adds explicit 'recurring vs one-time?' field"]_

The point isn't self-flagellation. The point is the sensing apparatus. Surprises are diagnostic — they tell you where your instruments are pointing and where they're not.

So next quarter: Probe's scan list gets at least one addition based on this quarter's surprises.

---

## 7. The narrative summary

A 200-word strategic summary of the quarter. Write this LAST, at retro-end. The summary captures the work, not the intention.

It goes in three places:
1. The monthly investor/acquirer update for the quarter-end month
2. The data-room quarterly financial summary file
3. The internal quarterly review at `~/Lictor/docs/business/quarterly/YYYY-QN.md`

Structure:

- **Sentence 1:** the quarter's headline (the single most important thing that happened — a launch, a metric crossed, a relationship formed, a thing that nearly broke and didn't)
- **Sentences 2-3:** position now vs 90 days ago (what *changed* about the company's standing, not what shipped)
- **Sentences 4-5:** what we learned (the meta-insight, not the tactic — e.g., "Indie hackers pay to prevent embarrassment more readily than to prevent loss" not "We added a checkout upsell")
- **Sentence 6:** what we're optimizing for next quarter (one priority, named)
- **Sentence 7:** the named risk we're watching (the one that, if it materializes, would matter most)

Builder dialect. First person. Specific numbers. No vague claims. The summary should read like Raffa wrote it, because Raffa did.

So next quarter: paste this paragraph into the investor update — no rewrite, no softening.

---

## 8. The next-quarter plan ratification

Open the year plan and read the next quarter's section. Then answer three questions:

1. **Is the plan still right?** Given what this quarter taught us, is the next 90 days' commitment still the right commitment? Or has reality moved enough that the plan is now a slightly-wrong artifact?

2. **What's no longer relevant?** Missed bets or no-longer-needed moves. (Example: "Plan says ship Spanish translation in Feb. Q1 data shows LATAM is 4% of traffic, not the 15% modelled. Defer; reallocate to Hebrew at 12%.")

3. **What's missing?** A new thing this quarter taught us should be added. (Example: "Q3 surfaced that 30% of teardown founders ask for a private remediation call before publish. Add to disclosure process; budget 4 hrs/week.")

If material change is warranted: **update the year plan in writing.** Edit `year-plan-2026-2027.md` directly.

For every material change, **log a decision** in `docs/business/decisions/YYYY-MM-DD.md` with three fields: what changed, why (citing retro evidence), what it costs. The decision log is what makes the retro durable; without it, the same decisions get re-litigated every quarter.

If no material change: write "Plan ratified, no changes" in the decision log anyway. That itself is a decision worth dating.

So next quarter: the year plan as of retro-end is the operating plan. No revisiting until next retro unless something extraordinary breaks.

---

## 9. The personal check-in

The solo-founder anti-burnout protocol. Write this even if no one will read it. The function is forcing the self-honest moment.

- **Hours worked this quarter (honest count):** _[an actual number, not "felt like a lot."]_
- **Days off this quarter (honest count):** _[real days. No Slack, no Twitter, no commits, no email past triage.]_
- **Energy level 1-10 entering next quarter:** _[7+ is fine. 5-6 needs attention. ≤4 means the plan changes before next quarter starts.]_
- **1 thing about the work that's draining:** _[the specific item — name it.]_
- **1 thing about the work that's energizing:** _[the specific item — lean into it structurally.]_
- **Is the next quarter sustainable at the current pace? If no, what changes?** _[if no, the plan ratification gets a deletion. Cadence > velocity. A skipped Tuesday is recoverable; a 6-month burnout is not.]_

This section never goes public. It lives in the quarterly file. Re-reading the previous three quarters' check-ins at the start of the current retro is part of the process — that's how the personal trend gets visible.

So next quarter: if energy dropped 2+ points from last retro, that's the retro's primary finding.

---

## 10. The deliverable

Output of the retro:

- **Quarterly file:** `~/Lictor/docs/business/quarterly/YYYY-QN.md` with all 9 sections filled in. The canonical record.
- **Year-plan updates:** any edits to `year-plan-2026-2027.md`.
- **Decision log entries:** 1-3 new entries in `~/Lictor/docs/business/decisions/YYYY-MM-DD.md` capturing material changes (or "no changes").
- **Investor/acquirer update insert:** the 200-word narrative summary copy-pasted into the next monthly investor/acquirer update.
- **Public summary:** a 1-paragraph version for the Lictor newsletter. Quarter-end editions are good content; the audience benefits from seeing how the company thinks about itself.

The deliverables are the proof the retro happened. Without them, it's journaling. With them, the retro becomes a load-bearing piece of the operating system — every input has an output, every output feeds something downstream.

So next quarter: open the previous quarter's file before starting this one. The continuity is the asset.

---

## File naming convention

- Quarterly retro file: `docs/business/quarterly/2026-Q3.md`, `2026-Q4.md`, `2027-Q1.md`, `2027-Q2.md`
- Decision log: `docs/business/decisions/2026-09-30-retro-decisions.md` (date = retro completion date)
- Both directories exist by Sep 30, 2026 (create at the first retro)

The first retro is Sep 28-30, 2026. Show up with the inputs gathered, the days blocked, and this template open.
