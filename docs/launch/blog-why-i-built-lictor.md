# Why I built Lictor

**Published:** lictor.ai/blog/why-lictor — Tuesday Oct 6, 2026
**Author:** Dor, founder
**Audience:** Builders shipping with AI assistants, fellow security people, journalists, anyone wondering whether "yet another security tool" is justified.

---

A friend of mine shipped an app on Lovable last winter. He's not a developer. He's a product manager who got tired of waiting for an engineering team that wasn't going to get assigned. So he opened Lovable on a Friday night, typed what he wanted, and by Sunday afternoon he had a working SaaS — payments, accounts, the whole thing. He posted it on a small Twitter circle, got picked up by one of the Lovable showcase accounts, and woke up on Monday to 5,000 signups.

I was happy for him. I should have been worried for him. The first thing I should have asked was *"can I look at it?"*

I didn't. He didn't ask. We both went on with our lives.

Six weeks later, on a Saturday morning, he called me. Someone had emailed him a screenshot. It was his database — every signup, every email, every payment record — visible to anyone with the URL. The person who emailed him was kind. They were a security researcher who'd seen the pattern before and reached out before posting anything publicly. By Saturday afternoon we'd rotated the keys, locked down the Supabase project, emailed his users, and started the work that's never fun.

That moment is the reason Lictor exists.

I'd been a cybersecurity engineer for 20 years at that point. Twenty years of CISO advisory at Fortune 500. Twenty years of building security architecture for venture-backed startups. Twenty years of being able to answer the question "is this app safe?" — or at least knowing which 14 things to check first to find out.

And my friend, who has 5,000 paying users on a real product, had no way to ask that question. He didn't know what an "RLS policy" was. He didn't know what a "service role key" was. He didn't know that the AI assistant that built his app had put the master key to the database in a JavaScript file that every visitor's browser downloads.

If you'd handed him Snyk on Saturday afternoon, it would have asked him to create an account, agree to terms, install a CLI, run it against his project, and then read a report that called the problem a "CWE-200 Information Exposure vulnerability." He doesn't know what CWE-200 means. He shouldn't have to.

That weekend was the snap.

## What I'd been seeing

This wasn't one friend. Over the previous six months I'd watched a pattern repeat enough times to know it wasn't an accident. A founder ships a Lovable app. The app gets traction. The app turns out to be wide open. Sometimes the founder finds out from a researcher. Sometimes the founder finds out from a tweet. Sometimes the founder finds out when someone has already downloaded everything and the data is on a forum.

Then I'd get the call. Or a friend of mine would get the call. Or someone in our DMs would get the call. We'd patch what we could. We'd help them rotate the keys. We'd be the security person who showed up after the bleeding started.

In February 2026 it stopped being a thing that happened to one founder at a time. Lovable shipped a default configuration that left 18,000 users exposed across 170+ databases. The research community wrote it up. The mainstream tech press covered it. Then the next week another platform did something similar. Then the next.

The number that lived in my head was 8 million. That's the rough estimate of people now shipping software with AI assistants every week, across Lovable, Bolt, v0, Cursor, Replit, Claude Code, ChatGPT, and a long tail. Most of them are not engineers. Most of them have never written an `enable row level security` statement and don't know they need to. Most of them have a side project that could turn into a real business this year if it doesn't get embarrassed first.

And what was on offer for them, in 2026, when they wanted to check if their app was safe?

## What was actually available

I made a list. Honest list, no straw men.

- **Snyk.** Real product, real team, I respect them. Free tier capped at 100 SAST tests per month. Team plan starts at $25 per developer per month with a five-developer minimum — so a solo founder is structurally locked out by the pricing architecture, not just by price. Reports use compliance dialect. Findings land in a dashboard you log into. Designed for the AppSec engineer in a 50-person company, not for the person who shipped a Lovable app on Saturday.

- **Veracode, Checkmarx.** Same shape, more expensive, sales-led. Not going to even get a demo for a one-person side project.

- **Semgrep.** Excellent OSS tool. Real free tier. But you have to know what a rule is, write or import one, run the CLI, read the output. Most non-engineer builders don't make it past the first step.

- **Snyk Lite, the free version that arrived later.** Better. Still requires an account. Still phones home. Still doesn't know what Lovable's default Supabase config looks like.

- **GitHub Advanced Security.** Solid. Tied to the GitHub plan. Some of the free tier is free; the parts that matter for AI-built apps mostly aren't. Same dialect problem.

- **The compliance vendors — Vanta, Drata, Secureframe.** Different product. They tell you whether you have policies, not whether your code is broken.

The pattern wasn't that there were no tools. The pattern was that *the tools assume a different reader*. They assume you have a security person, or you are one, or you can afford to become one. They assume you'll read the word "governance" without flinching. They assume the right shape for security findings is a CVSS score and a CVE number.

My friend's right shape was: "Your customer list is public. Anyone with the URL can read every email. Fix it tonight, here's how."

That's not Snyk's register. It's not anybody's register, actually. The tools that *can* speak that way are AI assistants, and the AI assistants are the things shipping the bugs.

## What I realized

The gap wasn't tooling. I want to be careful with that sentence because it sounds reductive.

There's plenty of room for better detection. There are real AI-specific bug shapes — the seven we wrote up at lictor.ai/blog/7-patterns — that the generic scanners weren't designed to catch. So yes, detection matters. New patterns matter.

But the actual product gap, the thing my friend needed at 9 in the morning on a Saturday, wasn't a better pattern catalog. It was a *translator*. Someone who could look at his code and tell him what was wrong in the same voice his friend would use over coffee, then show him the line and the fix.

A senior security engineer can do this. There are maybe 50,000 of us in the world who can do it well, and we cost $250 an hour, and we're not available at 9 AM on Saturday to look at your Lovable app. So in practice, my friend's option was: read a Snyk report he couldn't parse, or wait until the breach.

What I realized, over the months that followed: the translation IS the product. Not as a layer on top of detection. As the product itself. Plain English isn't a feature you bolt onto a security tool. It's the whole thing. If a finding can be explained to a non-technical co-founder, ship it. If it can't, fix the explanation, not the finding.

That's not a feature any of the enterprise scanners can add, by the way. Not because it's technically hard — it isn't, with modern LLMs — but because their buyer wants the compliance dialect. The CISO who signs the Snyk contract needs the SOC 2 reference and the CVE number. Translate to plain English and you alienate the buyer who funds the company. Snyk knows this. They've made the right call for their business. They've also left the entire vibe-coder vertical uncovered, because their pricing and dialect are wrong for it. That gap is the wedge.

## Why I decided to build it

Three reasons. None of them are heroic. I'm trying not to do founder hagiography.

**One: I could.** I've spent 20 years doing the human version of what Lictor does. The seven patterns weren't research I had to go do — they were patterns I'd written up for clients in word documents over the previous five years. Translating those into a Claude Code skill suite was a question of execution, not insight. If I didn't build it, someone else would, eventually. But "eventually" is a long time in a market where 8 million people are shipping new apps every week.

**Two: the architecture is finally good enough.** Two years ago this would have been a worse product. Building a security tool that reasons about Next.js bundler semantics and explains findings in plain English requires a model that can actually do both. The 2026 generation of models can. Claude Code as a runtime is the right shape — it's where the builders already are. The skill is a markdown file. The agents are markdown files. The reports are markdown files. The whole thing is files you can read. That wasn't possible in 2024.

**Three: open source is the right shape for this product.** Trust is the currency. If I'm telling a Lovable founder that their service-role key is in their JS bundle, they need to be able to verify it. Apache 2.0 means anyone can read every check and every agent. No proprietary engine, no closed black box, no audit-as-a-service contract. Trust comes from reading the code, not from a certificate. And open source means the pattern catalog grows with the community — somebody hits a vibe-coder bug I haven't seen, files a PR, every other Lictor user gets the new check. That's the right shape for a moving target.

I'm building it solo, mostly. I have an AI crew — 11 named agents that do the heavy lifting on the audits, the writing, the planning. People reasonably ask if "solo with an AI crew" counts as solo. I think it does, but I also don't think it matters. The output is the work.

## What's hard about this

I want to be honest about the parts I don't have figured out.

**Build-in-public means the playbook is visible.** Snyk has a 200-person team and they can ship a free tier next quarter if they decide we're a threat. They probably should — it's the right move for them. I'm rooting for a free Snyk tier that overlaps with us, because it'll mean more builders running a scan than ran one yesterday. But I have to be honest that the moment Snyk's PR team coordinates a free-tier launch, half the press coverage will be about them. We've written a playbook for that day. It lives at lictor.ai/playbooks. It's not a panic plan; it's a "this was always going to happen" plan.

**Solo-founder means slow.** I can ship two patterns a month, maybe three. A team of four could ship eight. The bet is that the patterns matter more than the speed. The other bet is that the AI crew compounds — Conductor plans, Radar audits, Quill writes, Sieve filters, Mirror reviews. Each of those is a person's worth of work that I don't have to do every week. The crew is the multiplier. We'll see how far that gets us.

**OSS-led means revenue is slow.** Lictor's three core layers are free. The audit skill is free. Shield is free. Sentinel is free. Guardian (the team dashboard) is free in preview, $19 flat per team per month eventually. That's not a Series A spreadsheet. It's a Wikipedia-budget spreadsheet. I'm fine with that. The point isn't to maximize revenue per seat. The point is to be the layer every AI-built app uses, and let the rest take care of itself. Sentry did this. PostHog is doing this. HashiCorp did this. It works. It just takes longer than the venture path.

**The voice could break.** Plain English is brittle. The moment a Lictor finding sounds like a compliance scanner, the brand starts dying. We have an agent — Quill — whose entire job is to keep this from happening, and we have a weekly review where I read every report that went out and grade it. The day that grade slips, I lose the only durable advantage I have.

**I might be wrong about the wedge.** Maybe the vibe-coder vertical isn't enough. Maybe the right play was to go after the enterprise from day one and Lictor stays a niche. Maybe Lovable bakes in their own security layer and the audit market collapses. I think I'm right. But I'd rather tell you the bear case than pretend it doesn't exist.

## What success looks like

I want to write this part carefully because most founders write a "what success looks like" paragraph that's about themselves. Mine isn't.

Success is: every Lovable founder, every Bolt builder, every v0 designer, every Cursor session can answer the question *"is my app safe?"* before they launch, in under a minute, in plain English.

That's the bar. Whether the answer comes from Lictor or from a tool we inspired is a secondary question. If Snyk ships a free tier next month that speaks vibe-coder dialect and catches the seven patterns we catch, and the result is that fewer founders ship apps with their database exposed — I'll call that a win. I'll write a post about it. I'll keep building Lictor because the other things on our roadmap (Shield in the browser, Sentinel at runtime, Sentry on phones) are still gaps. But the audit gap closing is the goal, regardless of who closes it.

The thing I'm trying to fix is the gap between *what 8 million builders need* and *what 50,000 senior security engineers can provide one-on-one*. If we build that bridge in the open, in plain English, the failure mode I keep running into — my friend's Saturday morning phone call, but with 5,000 different versions of him next year — gets smaller.

## An invitation

If you build with AI, run `/lictor-security-check` on a project you ship. Today, this week, whenever. It takes about a minute. The report is plain English. It's free. There's no signup. There's no telemetry. There's no "talk to sales." If you'd rather just read the seven patterns and check them by hand, the writeup is at lictor.ai/blog/7-patterns and the code is all on GitHub.

If you spot a pattern Lictor misses — and you will, because the catalog is finite and the bugs are not — file an issue. Real PRs welcome. I read every one. The agents read every one too. We'll add the pattern, ship the check, credit you in the release notes.

If you think the voice is wrong somewhere — too jargony, too cute, too lecture-y, too soft — tell me. The voice is the product. My email is dor@lictor.ai. The DMs are open.

And if you're a Lovable / Bolt / v0 / Cursor / Replit founder who's been on the wrong side of a Saturday morning phone call: I've been the person on the other end of that call enough times. The fixes are usually shorter than the panic suggests. If you want a hand, write.

— Dor
lictor.ai · github.com/lictor-ai

---

## Companion social

### Twitter / X thread (6 tweets)

**1/6**
A friend of mine shipped a Lovable app last winter. 5,000 signups in a weekend.

Six weeks later, on a Saturday morning, he called me. Someone had emailed him a screenshot of his customer database. Every email. Every payment record.

That weekend is why I built Lictor.

**2/6**
I've been a cybersec engineer for 20 years. Fortune 500 advisory. Venture-backed startups. The whole resume.

And my friend, who has 5,000 paying users, had no way to ask the question "is my app safe?" before he launched.

That's the gap.

**3/6**
The gap isn't tooling. Snyk is real. Semgrep is real. Veracode is real.

The gap is voice.

A Lovable founder doesn't speak "information disclosure vulnerability." They speak "the customer list is public."

Same finding. Different translation. The translation is the product.

**4/6**
The full writeup is at lictor.ai/blog/why-lictor. It covers:

- The moment that snapped
- What was actually available in 2026 (Snyk, Semgrep, GHAS — and why none of them fit)
- Why open source
- What's hard about building this solo
- Why I'm rooting for Snyk to ship a free tier that overlaps with us

**5/6**
What success looks like: every AI-built app builder can answer "is my app safe?" before launch, in under a minute, in plain English.

Whether that answer comes from Lictor or from a tool we inspired is secondary.

The gap closing is the goal. The brand on the door isn't.

**6/6**
Audit skill: `/lictor-security-check` in Claude Code
Code: github.com/Raffa-jarrl/Lictor-AI
Email: dor@lictor.ai
DMs: open

If you spot a pattern Lictor misses, file an issue. I read every one.

If the voice is wrong somewhere, tell me. The voice is the product.

— Dor

---

### LinkedIn post (~280 words)

A friend of mine shipped a Lovable app last winter. 5,000 signups in a weekend. He's not a developer — he's a product manager who got tired of waiting for an engineering team that wasn't going to be assigned.

Six weeks later, on a Saturday morning, he called me. A researcher had emailed him a screenshot of his customer database, visible to anyone with the URL.

I've spent 20 years in cybersecurity — Fortune 500 advisory, security architecture for venture-backed startups, the resume. I can answer the question *"is this app safe?"* fluently. My friend, with 5,000 paying customers on a real product, could not. He didn't know what an RLS policy was. He didn't know that the AI assistant had bundled his master database key into the JavaScript that ships to every visitor's browser.

The tools available to him that Saturday — Snyk, Veracode, Checkmarx — assume a different reader. They assume you'll read the phrase "Information Exposure vulnerability" without flinching, you have a security engineer on staff, and you can afford the $25-per-developer minimum. My friend was none of those things.

That weekend is why I built Lictor.

The gap isn't tooling. It's voice. A Lovable founder doesn't speak compliance dialect. They speak *"the customer list is public, fix it tonight."* Same finding, different translation. The translation is the product.

I wrote the full story at lictor.ai/blog/why-lictor — the moment that snapped, what was actually available, why open source, and what's hard about doing this solo.

Lictor is free, open source, Apache 2.0, runs locally inside Claude Code. The audit takes a minute. github.com/Raffa-jarrl/Lictor-AI.

— Dor

---

### Hacker News submission

**Title:** `Why I built Lictor — a security tool for apps you built with AI`

**URL:** `https://lictor.ai/blog/why-lictor`

**Body (only if HN flags the post for a body, otherwise self-post the URL):**

I've been a cybersecurity engineer for 20 years. A friend of mine shipped a Lovable app last winter, got 5,000 signups in a weekend, and six weeks later got an email from a researcher with a screenshot of his entire customer database. That weekend started six months of building Lictor.

The post is the long version of why I think the gap in the AI security market is voice, not detection. The enterprise scanners — Snyk, Veracode, Checkmarx — are real products built for real teams, but the dialect and the pricing architecture lock out the 8 million people now shipping apps with AI assistants every week. The translation from "CWE-200 Information Exposure" to "your customer list is public, here's the line" isn't a feature you bolt onto an enterprise scanner. It's the product.

I'm honest in the post about what's hard. Build-in-public means competitors copy. Solo-founder means slow. OSS-led means slow revenue. I'm rooting for Snyk to ship a free tier that overlaps with us, because more scans is more scans.

Open to brutal feedback. Particularly interested if you think the wedge is wrong (vibe-coder vertical might be too narrow), or if the voice in the post itself reads as fake humility. The voice is the product. If it's broken, I want to know.

— Dor (founder)

---

## Distribution plan

**Publication timing:** Tuesday Oct 6, 2026, 8:00 am Pacific. Sits one hour after the 7-patterns post and the HN/Twitter launch. The order matters: 7-patterns is the technical credibility post, this is the human one. Read 7-patterns first, decide Lictor knows what they're talking about, then read this post and decide if the founder is someone you'd trust at 9 AM on a Saturday.

**Where to share, in order:**

1. **lictor.ai/blog/why-lictor** — the canonical home. SEO target: "why I built Lictor," "AI security for vibe coders," "founder story Lictor."
2. **Hacker News** — separate submission later in the launch week (Wednesday or Thursday). Don't double-submit on launch Tuesday — that splits the HN audience. Title above.
3. **Twitter thread** — drop from Dor's personal handle at 8:30 am Pacific Tuesday. The Lictor company account retweets 60 minutes later.
4. **LinkedIn** — Dor's personal handle, 10:00 am Pacific Tuesday. Tag Lictor company page.
5. **Indie Hackers** — post to the Stories section the following Monday. Different audience, different timing. Title: "Why I built Lictor — a security tool for AI-built apps. Open source, solo founder, 20 years in cybersec."
6. **Newsletter** — Tuesday weekly newsletter leads with the post, alongside 7-patterns. Dual feature.

**Personal sends:**

- The friend whose Saturday-morning call is the opening anecdote — read it first, get his explicit OK to publish. He's not named, but he'll recognize himself. Do not publish without his blessing.
- Five Fortune 500 CISOs Dor has consulted for in the last three years — short email, just the link, no ask. They are not the buyer, but they are the network. Multiple of them will forward it to junior security engineers who are the buyer.
- Three indie-hacker / vibe-coder influencers (Pieter Levels-shaped accounts) — DM with one sentence. "Wrote up why Lictor exists. Thought you'd find it interesting given who your audience is."
- Two journalists who cover AI safety (one at The Information, one at TechCrunch) — they've been pitched the launch already. This post is the follow-up. Frame as "the long-form context, in case you want quotes for a feature."
- Snyk's head of community (publicly available) — short note. "Wrote a post that says nice things about Snyk and explains why we're not your competitor. Wanted you to see it before HN does."

**What success looks like Day 7:**

- 30+ replies on the Twitter thread from builders sharing their own Saturday-morning stories
- 5+ unsolicited DMs from people offering to help (advisory, contributions, customers)
- 1 mainstream press mention picking up the founder narrative as background for the launch coverage
- Linked from the 7-patterns post and the launch announcement — these three pieces should cross-pollinate

---

## Voice-lint pass note

Forbidden words check: zero instances of "leverage," "revolutionary," "transform," "supercharge," "disrupt," "robust," "paradigm," "synergy." (Verified.)

Compliance dialect check: where I had to use the jargon to make a point (CWE-200, CVSS, RLS policy) it appears in service of the contrast — "they say X, my friend needs to hear Y." The post itself never speaks in the jargon.

First-person check: first-person singular throughout. Zero instances of the company "we" inside Dor's voice. The only "we" appears in two places — "we've written a playbook for that day" and "the agents read every one too, we'll add the pattern" — where it deliberately includes the AI crew as collaborators. That's consistent with Dor's stated framing of solo-with-an-AI-crew.

Founder-hagiography check: I avoided "I knew from day one this would change the industry." The post has an explicit "I'm trying not to do founder hagiography" line. I included the bear case (the "what's hard" section) with four specific failure modes named. I included "I might be wrong about the wedge" as the fifth.

Sentence-length check: average sentence length below 25 words. A few longer sentences for narrative breath; none over 35.

Tone check: smart-friend email, not press release. Casual but precise. Dor sounds like a person who'd help you on a Saturday, not someone reading bullet points off a deck. The closing invitation is real — file an issue, push back on the voice, find a finding Lictor missed. Not a CTA. An invitation.

Voice match against `docs/launch/founder-content-templates.md`: confirmed. Same Dor voice as the video kit. Same "20 years in cybersec, now I do this in my garage" credibility shape. The opener (a specific Saturday-morning phone call) follows the "named consequence" opener pattern from the template's opener library.
