# Lictor Patrol — Aug 15 soft-launch publication (DRAFT)

> **Status:** draft for Aug 15 2026 publication. Updated by Quill from the actual numbers once the 30-day silent run completes (Jul 15 → Aug 14). Numbers in `[brackets]` will be replaced with real figures.
> **Channels:** HN "Show HN" post (06:00 PT), Twitter/X thread (07:00), blog post at `lictor-ai.com/blog/patrol-30-days` (09:30), press emails (11:00).
> **Voice:** First-person Raffa, with one disclosed AI co-author (Bridge). Direct, technical, no hype. The numbers do the work.

---

## Hacker News post

**Title:** Show HN: We scanned [30,000] vibe-coded apps for security bugs. Here's what we found.

**Body:**

I've spent the last 30 days running a tool I built (Lictor) against every public app I could find that was deployed from Lovable, Bolt, v0, Cursor, or Replit.

I scanned **[30,142]** apps in total. The headline finding: **[47%]** of them have at least one critical security issue that the AI assistant that wrote them didn't catch. Most common categories:

- **[14,200] apps** (47%) ship a Supabase service-role key inside their JavaScript bundle. Anyone who opens devtools has full database write access.
- **[9,300] apps** (31%) have at least one `/api/*` endpoint that returns user data with no authentication check.
- **[6,600] apps** (22%) accept Stripe webhooks without signature verification. A forged webhook can mark any order paid.
- **[4,200] apps** (14%) have at least one of the above AND are already processing real customer money.

I contacted every affected founder privately first. **[71%]** of them responded; **[58%]** had shipped a fix within 14 days. The full anonymized breakdown is in the report — [link to `lictor-ai.com/in-the-wild`].

Lictor is open source under Apache 2.0. The scanner that found all of this is free: `lictor-ai.com/scan/<your-url>` (no signup) or `npm install -g lictor-cli`. Continuous monitoring is also free for OSS / hobby / pre-revenue, and $19/mo flat (no per-seat) for commercial. Source: [github.com/Raffa-jarrl/Lictor-AI].

The full suite (Studio desktop app, browser extension, runtime SDK, hosted dashboard) launches Oct 6.

Happy to answer anything. The "how did you build the scanner without a giant ML model" question I know is coming — it's a Rust crate with 7 narrowly-tuned checks targeting the specific patterns AI assistants get wrong on each platform. Boring but precise.

— Raffa

---

## Twitter thread (1/13)

**1/** I spent 30 days scanning every public app I could find that was deployed from Lovable, Bolt, v0, Cursor, or Replit.

I scanned [30,142] apps. Found that [47%] ship with at least one critical security bug.

Here's what I found and what we did about it. 🧵

**2/** First, the methodology. I built a scanner called Lictor — open source, Apache 2.0, 7 checks tuned specifically for AI-assistant-generated code.

It runs on a Cloudflare Worker. Paste any vibe-coded app URL → 30 seconds → letter grade + the 5 worst findings in plain English.

**3/** The most common issue, by far: Supabase service-role keys in the JS bundle.

[14,200] of [30,142] apps had one. That's the "front door key to your entire database, broadcast publicly" mistake.

Lovable/Bolt/v0 will sometimes paste the service-role key when they mean the anon key. Easy mistake, devastating consequence.

**4/** Second most common: unprotected API routes.

[9,300] apps have at least one `/api/users` or `/api/orders` style route that returns real user data to anyone who knows the URL.

The AI builds the route. It doesn't always build the lock.

**5/** Third: Stripe webhooks with no signature verification.

[6,600] apps will mark any order as paid if you POST to their webhook URL with the right shape. No signature check. The "you can be the bank" bug.

**6/** And [4,200] apps had at least one of the above AND were already taking real money from real customers.

That's the part I lost sleep over.

**7/** So here's what we did about it.

For every app I scanned with a HIGH or CRITICAL finding, I had Bridge (Lictor's AI community agent) draft a personalized email to the founder. I reviewed every one. I sent them privately, with the specific finding and a 5-minute fix.

**8/** Of [21,400] private outreaches sent:

- [71%] responded within 7 days
- [58%] shipped a fix within 14 days
- [12%] said "I had no idea, thank you"
- [3%] said "we know, working on it"
- [<1%] were upset that I scanned them

**9/** The "<1% upset" group is the part I want to be honest about.

Public-info scanning is well-established (Shodan, HIBP, SSL Labs, Lighthouse). But it can still feel like a stranger DM'ing you about a bug in your private project.

That's why we use a 30-day responsible-disclosure window for individuals, and 90 days for companies. Specifics in the methodology doc.

**10/** What we did NOT do: publish individual scorecards without consent. Names, URLs, app-specific findings — all kept private during the disclosure window.

The only thing public is the aggregate. "47% of Lovable apps have X" is public; "yourapp.com has X" is not.

**11/** What this is, ultimately:

The first complete public picture of what's actually shipping from the AI app generation. Built in 30 days by one person and an 11-agent crew, on top of an open-source scanner anyone can run themselves.

**12/** What's next:

The scanner is live now at lictor-ai.com/scan — paste any vibe-coded app, get a grade in 30 seconds. Free, no signup, no telemetry.

Continuous monitoring (we DM you when new bugs appear) is also free for OSS / hobby / pre-revenue. $19/mo flat for commercial.

**13/** Full suite — desktop app (Studio), browser extension (Shield), runtime SDK (Sentinel), hosted dashboard (Guardian), VS Code extension, Claude Code skill — all launches Oct 6.

Source: github.com/Raffa-jarrl/Lictor-AI

Report: lictor-ai.com/in-the-wild

Try it: lictor-ai.com/scan

If you've built something with Lovable/Bolt/v0/Cursor and want a free 30-second check, that last URL is the one.

---

## Press emails (sent 11:00 PT)

### To: TechCrunch / The Information / The Verge / TLDR / The Register / Ars Technica security desks

**Subject:** Story idea — 47% of AI-built apps ship with a critical security bug; we have the numbers

[Reporter first name],

I'm Raffa — solo open-source maintainer of Lictor AI, an Apache 2.0 security scanner for AI-built web apps.

For the last 30 days I've been running Lictor against every public app I could find that was deployed from Lovable, Bolt, v0, Cursor, or Replit. That's [30,142] apps. I'd like to share what I found with you ahead of the public release at 06:00 PT today (Aug 15).

The headline: **[47%] of vibe-coded apps ship at least one critical security finding**. The most common is a Supabase service-role key in the JavaScript bundle ([14,200] apps), which is "front door key to your database, publicly broadcast" severity.

The full methodology, anonymized findings, and an explanation of how we handled responsible disclosure (private notice to every affected founder first; 30-day window) is in the report at lictor-ai.com/in-the-wild.

I'd be happy to:
- Walk you through the methodology over a 20-min call (today or tomorrow)
- Demo Lictor live on any URL you pick
- Connect you with affected founders who consented to talk on the record about the fix

The story is real, the numbers check, and we have receipts for every claim.

Lictor is open source (github.com/Raffa-jarrl/Lictor-AI) — no funding, no PR firm, just me + an agent crew + Apache 2.0.

— Raffa
[phone] · [email]

---

## Blog post — `lictor-ai.com/blog/patrol-30-days`

> Full long-form version of the HN post + thread. ~2,500 words. Includes:
>
> 1. Why I built Lictor in the first place (1 paragraph — same as the README's "why")
> 2. What Patrol is, in plain English (3 paragraphs)
> 3. The 30-day methodology (with explicit ethical guardrails section)
> 4. The findings, all of them, in the same plain-English voice as Lictor's audit reports — not jargon-y. Charts where they help.
> 5. The outreach we did — voice templates, real numbers, real responses
> 6. The fixes that landed — anonymized case studies from founders who consented to be in the post
> 7. What this means for the vibe-coder ecosystem
> 8. What's free, what's paid, what's next
>
> Drafted by Quill from the spec; Raffa edits the "why" paragraph and the case studies; Mirror reviews for voice; published Aug 15 09:30.

---

## What we DON'T do in the launch

| Avoid | Why |
|---|---|
| Name specific affected apps in the press release | Disclosure window. Aggregate only. |
| Imply that Lovable / Bolt / v0 are negligent platforms | They're not. They're shipping the best AI app builders on the market. The issue is the AI assistant's blind spots, not the platforms. We're allies, not adversaries. |
| Pitch the launch as a Snyk competitor | We're not competing on enterprise sales calls. We're competing on "the tool you've actually heard of." Different game. |
| Promise enterprise features we don't have | Stick to what's shipped. Studio is in beta. Mention it; don't oversell it. |
| Use the word "AI" in 4 different ways in one sentence | Lictor IS AI-built and audits AI-built apps. Pick one frame per sentence. |
| Quote any individual founder without explicit on-the-record consent | Anonymous quotes only unless they signed off. |

---

## What success looks like for Aug 15 (the soft launch)

| Metric | Target | Stretch | Kill |
|---|---|---|---|
| HN front-page | Top 5 by noon PT | #1 | Off front page by noon |
| HN comments | 200+ substantive | 500+ | <50 |
| Twitter impressions on the launch thread | 100k | 500k | <10k |
| Press placements within 7 days | 2 | 5 | 0 |
| `lictor-ai.com/scan` user-initiated scans in week 1 | 5,000 | 20,000 | <500 |
| `lictor-cli` installs in week 1 | 2,000 | 8,000 | <200 |
| Sentinel npm downloads in week 1 | 1,000 | 5,000 | <100 |
| GitHub stars added in week 1 | 1,500 | 5,000 | <200 |
| Beacon waitlist net signups in week 1 | 2,000 | 8,000 | <300 |
| Founders who took the offer for continuous monitoring | 500 | 2,000 | <50 |

If we hit the stretch numbers on any 4 of these, Lictor exits soft-launch week as a known thing in the vibe-coder community. If we hit the kill numbers on 3+, the methodology or the voice was wrong and we post-mortem before Oct 6.

---

## Final note on framing

The launch is not "we built a thing." Hacker News doesn't reward that.

The launch IS "we ran an investigation, here's what we learned, here are the numbers, here's the open-source tool we used so you can verify any of it yourself." That's the genre that compounds.

Every reader of the HN post should walk away with three things:

1. **A scary number** about the state of vibe-coder app security
2. **A specific action they can take in 30 seconds** (paste their URL at lictor-ai.com/scan)
3. **A reason to trust this person they've never heard of** (the methodology is in the open, the tool is in the open, the affected founders are vouching anonymously, and the maintainer is signing his name)

If we get those three things into every reader's head, Oct 6 doesn't need to be announced — it's the natural next chapter of an investigation that's been compounding since August.
