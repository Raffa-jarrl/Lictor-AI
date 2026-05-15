# Founder content templates — Dor's video kit

> **Generated:** 2026-05-15
> **Target audience:** Dor — recording founder content for Lictor's content engine
> **The thesis:** Snyk has no face. Lictor has Dor. Weekly founder content is the moat Snyk's PR team literally cannot copy. But the kit has to make recording *easy*, not aspirational. This is the kit.

---

## The three formats Dor will rotate

You'll record one long-form (8–12 min) and two shorts (under 60s) per week. Three formats rotate so the content doesn't get repetitive:

| Format | Cadence | Length | Production tier |
|---|---|---|---|
| **The Teardown Walkthrough** | Weekly long-form | 8–12 min | Lo-fi-but-credible: webcam + voice-over + screen recording |
| **The Crew Demo** | Bi-weekly long-form | 8–12 min | Same lo-fi production. Showcase 1 of the 11 agents at work. |
| **The Quick Take** | 2x/week shorts | 30–60s | Webcam only. One specific finding or hot take. Mobile-friendly. |

**Lo-fi-but-credible matters.** Vibe-coders are allergic to over-produced YouTuber slickness. They want a real expert showing real work. Don't try to be Theo Browne. Be the senior engineer who's been in cybersec for 20 years and now does this in his garage with one light and a USB mic. That's the believable shape.

---

## Long-form template — The Teardown Walkthrough (8–12 min)

This is the workhorse. One per week. Pull the subject from the [teardown engine pipeline](./teardown-engine.md) — by the time you record on Friday, Probe has already audited the target and Quill has drafted the writeup. You're narrating the artifact.

### Beat structure (8 beats, ~1 min each)

```
[BEAT 1 — Open (0:00–0:45)]
Hook (3 sec): a specific number or named consequence.
"I just audited [App Name] in 12 minutes. We found 7 things wrong.
Two of them would let anyone with a browser drain their database."

Set the table (15 sec): who this app is, who built it, why we picked it.
"[App Name] is built on Lovable. Solo founder. ~50K users. Featured on
madewithlovable.com last month. They've got a real product —
they're handling actual money — and they're shipping the same way
every Lovable founder ships."

Why you should care (15 sec): zoom out to the pattern.
"What I'm about to show you isn't unique to [App Name]. It's how
Lovable's default setup works. If you built on Lovable, half this video
applies to you."

[BEAT 2 — The setup (0:45–2:00)]
Show the audit running on screen. Voiceover narrates what's happening.
"This is /lictor-security-check running inside Claude Code. Eleven AI
agents walk the project. They check seven things..."

Show the report rendering as you watch. Don't speed it up.
The slow scroll is the suspense.

[BEAT 3–5 — The findings (2:00–7:00)]
Walk through the top 3 findings. ~90 seconds each.

Per finding:
- Severity + what the finding is, in 1 sentence
- Show the actual code on screen — the line that's broken
- Explain in plain English what's wrong ("anyone with the URL has full
  database write access")
- Show what an attacker would do — narrate the steps, don't demo the
  exploit (legal rail: never publish exploit code)
- Show the fix in 2-3 lines of code

[BEAT 6 — What the founder did about it (7:00–8:30)]
This is where credit gets given. If the founder fixed it before publication,
this is the redemption arc.
"I emailed [founder] on Sep 22 with these findings. By Sep 28, three of
the four were already patched. The fourth one took longer because it
required a Supabase RLS rewrite. As of this recording: the app is fixed.
That's a 6-day responsible-disclosure-to-patch cycle from a solo founder
running a single Lovable app. That's good."

If they didn't fix it: be measured. Not snide.
"I emailed [founder] on Sep 22. No response. The fixes are simple but
they require somebody to make them. If you're using [App Name], be aware.
If you're [founder] and watching this: my email is in the description.
I'm happy to help."

[BEAT 7 — Lessons (8:30–10:00)]
The "this is for you, the viewer" beat.
"Three things to take away:
 1. If you built on Lovable, your Supabase RLS policies are probably
    wrong. Here's how to check..."
 2. ...
 3. ..."

Specific, actionable. Each item < 30 sec.

[BEAT 8 — Close + CTA (10:00–11:00)]
Tight close. ONE CTA. (See CTA library below.)
"That's it. If you want to run this audit on your own project, the
skill is free, it's at lictor.ai/skill. Drop it in Claude Code, type
slash-lictor-security-check, get your report in 60 seconds.
See you next Tuesday."
```

### Pre-recording checklist
- [ ] Teardown subject confirmed (Pitchtank / target for the week)
- [ ] Quill's draft report read top-to-bottom
- [ ] AUDIT.json from the audit pulled up on screen for the walkthrough
- [ ] Founder disclosure email sent at least 14 days prior
- [ ] If founder fixed it: get their consent to mention them by name on camera
- [ ] If founder did not respond: pre-clear with legal review at risk ≥ 3 (see [teardown-engine.md](./teardown-engine.md))

---

## Long-form template — The Crew Demo (8–12 min)

Every other week, swap the teardown for a "meet the crew" piece. These build the agent-as-character equity that becomes Lictor's brand moat.

### Beat structure (6 beats, ~1.5 min each)

```
[BEAT 1 — Open (0:00–1:00)]
Hook: tease the agent and what they do.
"Lictor's audit doesn't run on one big AI. It runs on eleven. Today
I want you to meet Sieve."

Why this matters (15 sec):
"Most security tools are a black box: input goes in, findings come
out. Sieve is the reason ours isn't. Sieve scores every finding before
it ships to you. Anything below 6 out of 10 doesn't make the report.
That's why our reports are shorter than other tools'."

[BEAT 2 — Introduce the agent (1:00–2:30)]
Show the agent's SOUL.md file on screen. Read 2-3 key lines aloud.
"Here's Sieve's SOUL.md — every agent has one. It's a markdown file.
It's open source. You can read it..."

The point: transparency. Snyk's agents are proprietary; ours are files
you can fork.

[BEAT 3 — Show the agent working (2:30–5:00)]
Run a real audit on a real project. When the audit hits Sieve, pause
the screen and walk through what's happening.
"See here? Sieve just rejected this finding. 5.8 out of 10 — below the
bar. The audit ran but you didn't see this in the report. That's the
job."

Show the JSON output. Show the rejected findings. Be transparent.

[BEAT 4 — Why this agent matters (5:00–7:00)]
The "you should care" beat.
"You might think: why would I want my security tool to hide findings
from me? Three reasons..."

Lead with the user benefit, not the architecture.

[BEAT 5 — Show how to read the agent's output (7:00–9:00)]
Practical: if a user looks at their own audit report, how do they know
which agent found what?
"In every finding, you'll see an agent field. radar, sieve, probe..."

This is where you teach the user to use the transparency. It's only
valuable if they know it's there.

[BEAT 6 — Close + CTA (9:00–10:30)]
"Sieve is one of 11. Next month I'll do Probe. The agents are open —
github.com/lictor-ai. The skill is free — lictor.ai/skill. If you've
got ideas for an agent we should add, the roadmap is public —
lictor.ai/roadmap. See you next week."
```

The crew-demo series eventually does all 11. Sequence:
1. Sieve (quality gate — most novel mechanic)
2. Probe (course-currency tester — teaches the second-job concept)
3. Radar (story scout — bridge to the teardown narrative)
4. Quill (writer — plain-English voice as character)
5. Conductor (orchestrator — the "chief of staff" frame)
6. Magnet (lead-magnet designer — convert curiosity to action)
7. Mirror (weekly auditor — the meta-agent)
8. Vibe + Trends (sister-brand pair, do together)
9. C-3PO (dev — the engineering side)
10. The four new specialists once they ship (Translator / Reel / Booth / Bridge)

---

## Short-form template — The Quick Take (30–60s)

Two per week. Cheap to produce. Webcam only — no screen recording, no fancy editing.

### Beat structure (3 beats, 15-20 sec each)

```
[BEAT 1 — Hook (0:00–0:08)]
One sentence. Specific. Slightly contrarian.
"Snyk just shipped their free tier. Here's the one thing it doesn't do."

OR

"I audited a Lovable app. The Supabase service key was in the JavaScript
bundle. Here's how it gets there — and the 90-second fix."

[BEAT 2 — The substance (0:08–0:45)]
Make ONE point. Not three. Not five. One.

Use specifics. Name the file, the function, the version number, the
exact number of users affected. The 60-second format collapses without
specifics.

[BEAT 3 — Close + CTA (0:45–0:60)]
ONE CTA, even more compressed than long-form.
"Check yours. Lictor's free. Link in bio."

OR

"Full breakdown in this week's teardown. lictor.ai/teardowns."
```

### The 8 best Quick Take shapes (rotate)

1. **The single finding** — "I found this thing in this app. Here's what it means."
2. **The competitor announcement reaction** — "[Competitor] just shipped X. Here's what it actually does."
3. **The pattern callout** — "If you built on [Lovable/Bolt/v0], do this one check right now."
4. **The voice-bug** — "The worst compliance dialect I read this week was..."
5. **The agent moment** — "Sieve just rejected a finding in today's audit. Here's why."
6. **The 1-line fix** — "Lovable's RLS gap is real. Here's the one paste that fixes it."
7. **The honest comparison** — "Lictor caught X. Snyk caught Y. Both right. Different jobs."
8. **The behind-the-scenes** — "Building Lictor's content engine. Today: setting up the public roadmap."

---

## Opener library — 12 proven hooks

Memorize these patterns. They work across long-form and shorts. Pick the one that fits the day's content.

1. **The specific number** — "I just audited [X] in 12 minutes. We found 7 things wrong."
2. **The named consequence** — "[18,000 users] just had their data exposed because of [one missing line of code]."
3. **The contrarian frame** — "Everyone says [common belief]. After 20 years in cybersec, here's why they're wrong."
4. **The receipt** — "Last week I said [prediction]. Today [vendor] shipped exactly that. Here's what it means."
5. **The discovery story** — "I wasn't looking for this. I was auditing [X]. Then I found [Y]."
6. **The "the part nobody talks about"** — "Everyone covers [the obvious bit]. Nobody mentions [the actual issue]."
7. **The unfair comparison** — "[Tool A] costs $X/month per seat. Lictor is free. Here's the catch."
8. **The before/after** — "This is [App] before the audit. This is [App] after. Two-line fix."
9. **The on-camera demo** — "Watch me find [specific bug] in 90 seconds. Starting now."
10. **The cultural moment** — "Y Combinator just funded [N] vibe-coded apps. None of them ran a security audit. Here's what happens next."
11. **The teach-by-mistake** — "I almost shipped [X] last month. Here's what I missed and how I caught it."
12. **The named expert** — "[Cybersec person] tweeted [claim] this week. I disagree, and here's why."

For each video, pick ONE opener pattern. Don't try to combine.

---

## Closer library — 8 proven closes

Match the closer to the energy of the video. Don't over-engineer.

1. **The straight CTA** — "If you want to run this audit yourself, the skill is free — lictor.ai/skill. See you next Tuesday."
2. **The community ask** — "If you've found a vibe-coder pattern Lictor misses, file an issue — github.com/lictor-ai. Real PRs welcome."
3. **The next-week tease** — "Next week I'm auditing [N App]. Watch what we find. Subscribe so you don't miss it."
4. **The honest sign-off** — "That's all I had. If you want more, come back. If not, that's fine too."
5. **The thank-you to the founder** — "Big thanks to [founder] for fixing this so fast and letting me publish the story. Go check out [their app]."
6. **The contrarian close** — "If you disagree with anything I said, my email's in the description. Tell me where I'm wrong. I read everything."
7. **The "I'm not a salesman" close** — "I'm not going to ask you to buy anything. The tool is free. If it helps, great. If not, no hard feelings."
8. **The newsletter handoff** — "If video isn't your format, I write all of this up in the Lictor weekly newsletter. lictor.ai/newsletter."

---

## CTA library — 6 by purpose

Match the CTA to what stage of awareness the viewer is in. Don't ask for too much.

| Stage | Purpose | CTA template |
|---|---|---|
| **Cold** | First exposure to Lictor | "If you build with AI, check out lictor.ai. Five-minute read tells you what we do." |
| **Curious** | Aware, hasn't tried it | "The skill is free. Drop it in Claude Code, audit one of your projects, see what comes back. lictor.ai/skill." |
| **Tried it** | Has run an audit | "If Lictor found something useful, share it with one builder who needs it. That's the best thing you can do for us." |
| **Engaged** | Reads weekly, on the newsletter | "Open issues, vote on the roadmap, propose patterns we should add — lictor.ai/roadmap. Lictor goes where the community pushes." |
| **Advocate** | Has shared / starred / told friends | "If your team would use Lictor for Teams (flat $19/mo, unlimited seats), it ships [date]. lictor.ai/teams to get on the list." |
| **Pro-curious** | Privacy-paranoid or wants more | "Lictor Studio (offline native app) ships Dec 31. Pro tier with custom checks ships Q1 2027. lictor.ai/studio." |

**Hard rule:** one CTA per video. Never two. The viewer's brain can't hold two action items. The metric is "how many people actually did the thing," not "how many things did we mention."

---

## B-roll cue patterns

"B-roll" = the visual that plays while you talk. Lo-fi setup: you're showing your screen or your face. Patterns that work:

| When you're saying... | Show on screen... |
|---|---|
| "[App Name] has 50K users" | Their landing page, scrolling slowly |
| "Lictor's audit runs..." | Claude Code terminal with the skill output streaming |
| "The bug is in [file]:[line]" | The actual code, syntax highlighted, line highlighted |
| "The fix is..." | Side-by-side diff: before / after |
| "Most tools say [jargon]..." | Snippet of a competitor's report, jargon highlighted |
| "Lictor says [plain English]..." | Lictor's report rendering the same finding |
| "Meet [Agent Name]" | The agent's SOUL.md file on screen |
| "The Discord / GitHub community..." | Scrolling through issues or PRs (sped up) |

If you don't have a B-roll for a beat: just stay on the webcam. Cuts between webcam and screen are fine; cuts between webcam and bad B-roll feel desperate.

---

## Title formulas (YouTube + LinkedIn)

Titles drive 80% of click-through. Patterns that work for this audience:

1. **`I audited [App]. Here's what I found.`** (the workhorse)
2. **`[App]'s [N] users are exposed. The fix is [N] lines of code.`** (specifics + urgency)
3. **`[Competitor] just shipped [thing]. Here's what it actually does.`** (reactive, time-sensitive)
4. **`Why Lictor uses 11 AI agents instead of one`** (curiosity + a number)
5. **`The Lovable security gap nobody talks about`** (insider framing)
6. **`Snyk vs Lictor on a real Lovable app — the honest comparison`** (comparison shopping)
7. **`90-second fix: [specific bug]`** (urgency + utility)
8. **`Meet [Agent Name] — the Lictor crew member who [specific verb]`** (character-driven)

**Avoid:**
- ❌ Anything with "ULTIMATE" or "EVERYTHING YOU NEED"
- ❌ Listicles ("5 Ways To...")
- ❌ Clickbait ("YOU WON'T BELIEVE...")
- ❌ Anything with three exclamation marks
- ❌ All caps in the title

---

## YouTube description template

Use this every time. Keep the structure consistent across all videos so viewers know where to find what.

```
[ONE SENTENCE description of what's in the video]

[ONE PARAGRAPH: the actual point of the video, written as if explaining
to a friend. 2-3 sentences.]

🔗 Run the audit yourself: https://lictor.ai/skill
📖 Full writeup: https://lictor.ai/teardowns/[slug]
🐦 Twitter: https://twitter.com/lictor_ai
💌 Weekly newsletter: https://lictor.ai/newsletter
⭐ GitHub: https://github.com/Raffa-jarrl/Lictor-AI

== Timestamps ==
0:00 [Beat 1 description]
0:45 [Beat 2 description]
...

== Mentioned in this video ==
- [Tool / link / reference 1]
- [Tool / link / reference 2]

== About Lictor ==
Lictor is the security crew for apps you built with AI. 11 AI agents
audit your Lovable / Bolt / v0 / Cursor project in plain English.
Free, open source, Apache 2.0. Built by a 20-year cybersec engineer.
https://lictor.ai

== Disclosure ==
[If this video reviewed a real third-party product, name the responsible
disclosure timeline here. e.g., "I emailed [founder] on Sep 22, 2026
with these findings. They patched 3 of 4 by Sep 28. The fourth was
patched Oct 4. Video published Oct 11."]
```

---

## Filming setup — the minimum viable kit

If Dor doesn't already have these, the kit is ~$200 one-time:

| Item | Spend | Why |
|---|---|---|
| **USB mic** (Audio-Technica ATR2100x-USB or Samson Q2U) | $80 | Voice is 80% of perceived quality. Built-in mic is the #1 thing that makes lo-fi look amateur. |
| **Webcam** (Logitech Brio or use iPhone via Continuity Camera) | $0–200 | iPhone Continuity is free + better than 90% of webcams. Use it. |
| **Light** (Elgato Key Light Air or any soft daylight LED panel) | $130 | One light, off-axis 45°. Fixes the "lit by laptop screen" look. |
| **Backdrop** | $0 | Plain wall behind you is fine. Avoid clutter that screams "messy garage." |

Total minimum: ~$80 (mic only, use phone for camera, use a window for light).
Recommended: ~$210 (mic + cheap light, phone for camera).

**Framing rules:**
- Eyes in the top third of the frame
- Headroom: small (close to the top of your head)
- Background: anything except a doorway. Bookshelves and plain walls both work.
- No fish-eye distortion (pull the phone back, don't zoom in)

**Lighting rules:**
- Light source on your face, off-axis 45° (not directly in front, not behind you)
- No window behind you (you become a silhouette)
- Daylight-balanced light (5000–6500K)

**Mic rules:**
- USB direct into laptop
- Fist-distance from your mouth (~10cm)
- Pointed at you, not at the table
- Test recording before every video — listen back on headphones

---

## The first 5 videos to record (in order)

If you're starting from zero, record these five in this sequence. They build on each other.

1. **"Hi, I'm Dor. This is Lictor."** (3–5 min — short long-form intro)
 - Who you are (20 years cybersec)
 - What Lictor is (the security crew for apps you built with AI)
 - What this channel will be (weekly teardowns + agent demos)
 - One concrete example finding from a Lovable app
 - CTA: lictor.ai

2. **"Meet Conductor — the orchestrator behind every Lictor audit"** (8–12 min Crew Demo)
 - Why a crew not a single AI
 - Show Conductor's SOUL.md
 - Walk through a Conductor briefing on screen
 - The "transparency is the product" frame
 - CTA: github.com/lictor-ai

3. **"I audited Pitchtank. Here's what we found."** (8–12 min Teardown, assuming Pitchtank is the launch teardown subject)
 - The launch artifact

4. **"Snyk speaks compliance. Lictor speaks English. Here's the same finding in both."** (60s Quick Take)
 - Side-by-side comparison of jargon vs plain English

5. **"The Lovable RLS playbook in 6 minutes."** (8–12 min long-form, educational)
 - Teach the most-common vibe-coder bug
 - This becomes evergreen — it'll get pulled up every time someone asks "what's an RLS gap?"

---

## Anti-patterns — what NOT to do on camera

These are the easy ways to nuke trust. Avoid them.

| Don't | Why |
|---|---|
| Read a script verbatim while staring at notes | Sounds robotic. Use bullets, not paragraphs. Memorize beats, improvise transitions. |
| Use the words "leverage," "revolutionary," "transform," "synergize" | Lictor's brand depends on plain English. These words are the brand-killers. |
| Bash a competitor by name | Generous to Snyk. Generous to Aikido. Snide to none. The community remembers. |
| Promise things you can't deliver | "Lictor is the #1 best security tool" is unprovable hyperbole. "Lictor catches the bugs the AI-built app tools miss" is provable. |
| Add a face-cam reaction zoom every 8 seconds | YouTuber slick. Not the brand. Lo-fi-but-credible. |
| Record on a bad day | If you're tired or off-voice, push to tomorrow. One great video beats four mid ones. |
| Hide the founder when they responded well | When a Lovable founder patches in 6 days after disclosure, name them with gratitude. Real story always wins. |
| Use stock footage / AI-generated B-roll | Vibe-coders smell this instantly. Real screen recordings only. |

---

## The pre-publication checklist

Before a video goes live:

- [ ] Title fits one of the proven formulas
- [ ] Thumbnail (if any) shows your face OR a specific finding — not a generic graphic
- [ ] One opener used (not blended)
- [ ] One CTA at the close (not multiple)
- [ ] B-roll cues match what you're saying at each beat
- [ ] No forbidden words ("leverage," "transform," etc.)
- [ ] Description filled out per template
- [ ] Disclosure section added if reviewing a real third-party product
- [ ] Captions auto-generated and reviewed for any technical-term mistakes
- [ ] Audio listened to start-to-finish on headphones (no clipping, no background hum)
- [ ] Companion Twitter thread drafted (post within 1h of video going live)
- [ ] LinkedIn version drafted (different framing — see [content-calendar.md](./content-calendar.md))
- [ ] Newsletter blurb included in this week's Substack draft

---

## What this kit doesn't cover

These are for next session:

- **Podcast appearance prep** (when Booth agent books your first one) — different format, different prep
- **Conference talk decks** — when the first CFP gets accepted, we'll write the deck template
- **Multi-language video versions** (when Translator agent ships, Q4 2026)
- **Interview prep** for when journalists call after a viral teardown

Ship the first 5 videos. Then we extend the kit based on what worked.
