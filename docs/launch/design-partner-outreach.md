# Design partner outreach — Sprint 1, Week 1

Five email templates for the five people you're recruiting to bug-bash Lictor before launch. Each is personalized for a different *kind* of person — you customize the opening sentence with whatever specifics make it feel handwritten.

**Goal of the outreach:** get 3 confirmed testers from the 5 emails. Each tester runs `/lictor-security-check` on a project of theirs in Week 2 and reports findings via the `BUG_BASH.md` flow.

**What you offer them:** a free private security audit of their app, performed by a 20-year cybersec engineer (via the tool but also via your eyes). What you ask for: 30 minutes of bug-bash testing + a willingness to be quoted (optionally) in the launch.

---

## Email 1 — Course alumni who shipped an AI-built SaaS

Use this for the GenerationAI course alumni you stay in touch with — especially anyone who recently shared a launch screenshot.

**Subject:** Quick favor — bug-bashing my new security tool against your app

```
Hey [first name],

Quick favor, no rush.

I'm shipping a free open-source security tool for AI-built apps in early October — Lictor. The wedge is a Claude Code skill (`/lictor-security-check`) that runs a 7-check audit against any project and writes a plain-English report. The 20-year cybersec audit logic, just packaged in a way someone without a security background can use.

Before launch I'm bug-bashing with 5 people. You're on the shortlist because [SPECIFIC THING — "you shipped [App Name] last month and that's exactly the kind of project this is designed to help" / "your work on [X] is the audience this is built for" / "you're the most honest tester I know and I want to find issues before launch, not after"].

What I'd ask: 30 minutes of testing. Clone the repo, install the skill, run it against ONE of your projects. Tell me what it found — and more importantly, what it MISSED. False negatives are the most valuable bug reports I can get.

What you get: a free real audit of one of your apps from me personally. If the tool catches something real, I'll walk you through fixing it (the suite has a `/lictor-fix-it` skill for that). If it misses something I should have caught, I add a pattern + you're credited in the changelog.

Install is 3 lines:

git clone https://github.com/Raffa-jarrl/Lictor-AI ~/Code/lictor
mkdir -p ~/.claude/skills
cp -r ~/Code/lictor/skills/lictor-* ~/.claude/skills/

Then `/lictor-security-check` from any project.

Worth 30 minutes of your time before I show this to the world?

— Raffa
```

---

## Email 2 — Indie hacker friend you've vouched for publicly

Use this for someone who's repeatedly built things and might enjoy the meta-challenge of trying to break your tool.

**Subject:** Built a security tool. Want to try to break it?

```
[First name],

You know I've been hinting at this for months — finally close enough to show. Lictor: open-source AI security suite. Apache 2.0. Free forever. Four products under one brand: Chrome extension, npm/pip SDK, hosted dashboard, Claude Code skill plugins.

Launch is October 6. Before then I want 3-5 people to break it.

Specifically: I want someone to point Lictor at their own code and tell me everywhere it's wrong. False negatives (real bugs it missed) get a pattern + a CHANGELOG credit. False positives (it flagged safe code) get a tightening of the rule + same credit.

You'd be a great fit because [SPECIFIC: "you're the only person I trust to actually look at the code instead of just running the tool" / "your taste in dev tools is uncalibrated — I want to know if this passes your bar" / "you build security-adjacent things and would notice the pattern gaps fastest"].

The whole testing protocol is in BUG_BASH.md — 3 days, ~3 hours total. Day 1 the dashboard, Day 2 the SDK against a real app, Day 3 the Chrome extension.

Repo (currently private — I'll add you as a collaborator): [link to be added once they confirm]
Bug bash guide: [GitHub link once public, or attach the file]

In?

— Raffa
```

---

## Email 3 — Someone who's complained about AI security publicly

Use this for a Twitter mutual or LinkedIn connection who has posted publicly about "vibe-coded apps are a security disaster" or similar.

**Subject:** You were right about [X] — built something that tries to fix it

```
[First name],

Saw your [tweet / LinkedIn post / Hacker News comment] about [SPECIFIC TOPIC — "the security disaster of vibe-coded SaaS" / "Lovable apps leaking API keys" / "AI agents getting prompt-injected"]. That problem has been on my mind for a year. I just shipped something that tries to address it.

It's called Lictor — open-source AI security suite. The wedge is a Claude Code skill (`/lictor-security-check`) that runs a 7-check audit against any project a vibe-coder built and writes a plain-English report. Same engine also ships as a Chrome extension, an npm/pip SDK that wraps OpenAI/Anthropic clients, and a hosted dashboard.

The point of the framing is: don't speak SOC 2 to a designer. Tell them "your API key is in your JavaScript bundle, anyone can charge their card to your account."

Launch is October 6. I'm bug-bashing with 5 people before then. Your name came up because you've described the exact problem this is built to fix — I'd love your honest read on whether it actually does.

What I'd ask: 30 minutes. Either point it at your own code, or pick a public vibe-coded GitHub repo and run it against that. Tell me where the audit voice is wrong (the most common failure mode of security tools is sounding like a corporate scan). False negatives + false positives both go in the changelog with credit.

Free, no NDA, no pitch. The whole thing is Apache 2.0 and the code is at github.com/Raffa-jarrl/Lictor-AI (currently private; will be public around launch).

Worth a try?

— Raffa

P.S. If you're more excited about the Sentinel SDK (the runtime defense against prompt injection) than the audit skill, that's also testable — `npm install @lictor/sentinel` post-launch. Same offer applies.
```

---

## Email 4 — Engineering manager / CTO at a Series A startup using AI

Use this for someone running a team that ships AI features and would have a real interest in the "audit log for compliance" angle of Guardian.

**Subject:** Sentinel SDK + audit log — free for your team, want to test it?

```
[First name],

Quick one. I'm shipping Lictor — open-source AI security suite — on October 6. Before launch I'm testing with 5 teams. Wondered if [Company] would be one.

The angle that's most relevant to you: Lictor Sentinel is a `wrap()` around your OpenAI/Anthropic SDK that catches prompt injection, secrets-in-input, and PII-leak. It pushes incident telemetry (privacy-preserved — fingerprints only, no raw content) to Lictor Guardian, which gives you an audit-log export for SOC 2 / GDPR Article 32 / EU AI Act Article 12 evidence.

In plain terms: if your CISO or your biggest customer ever asks "how do you secure AI agents," you have an answer that isn't a slide deck.

It's all free. Apache 2.0 for the SDK; Guardian's hosted at app.lictorai.com with a 90-day free preview that's effectively permanent for testers.

The ask: integrate Sentinel into one of your AI endpoints for a week. Tell me what false positives we trip, what real attacks it catches, and whether the Guardian dashboard surfaces the right things. If it's net useful, you keep using it free.

I'll set up your account manually, send a personalized API token, and walk through the integration if useful — should be one line of code in your existing app.

Worth 30 minutes for a call to evaluate?

— Raffa

(20 years in cybersec — built this because every Series A I've consulted with in the last 12 months has had this exact question and nobody has had a clean answer for them.)
```

---

## Email 5 — Skeptic / generic fallback

Use this when you've exhausted your "warm" list and need to email someone you don't know well — maybe a contact from a conference, or a former colleague you haven't talked to in years.

**Subject:** 30 min favor — testing my new security tool

```
[First name],

Hope you're well. Not asking for anything routine — I'm shipping a new open-source security tool (Lictor) for AI-built apps in October and looking for 5 people to bug-bash it before launch.

Why I thought of you: [SPECIFIC reason — "you mentioned at [event] that your last project was AI-heavy and shipped fast" / "you've always been the most honest reviewer I know" / "you mentioned [thing] and Lictor is adjacent to it"].

The product: four free open-source plugins for Claude Code that audit your project for the 7 most common security bugs in AI-built apps. No signup, no telemetry, Apache 2.0. Same engine also ships as a Chrome extension and an npm/pip SDK.

The pitch is "security tooling that doesn't speak SOC 2 — built for builders, not for compliance teams."

The favor: 30 minutes. Install the plugins, point them at a real project of yours, tell me what they got wrong. False negatives (it should have caught X) and false positives (it flagged something safe) are both equally useful.

What you get: free 1:1 audit of any project of your choosing from me personally (20 years cybersec). Plus credit in the changelog for any pattern your testing produces.

Github will be public for the launch but currently private. I can add you as a collaborator and send over the bug-bash guide. Let me know.

Thanks,
— Raffa
```

---

## Tracking the responses

Set up a simple spreadsheet:

| Name | Email | Sent | Status | Notes |
|---|---|---|---|---|
| [name 1] | x@y.com | 2026-05-16 | replied — confirmed | starting Tuesday, will test the Claude skill |
| [name 2] | x@y.com | 2026-05-16 | replied — passing | "busy this month, ask me in Q3" |
| [name 3] | x@y.com | 2026-05-16 | no response | follow up 2026-05-19 |

**Status values:**
- `sent` — email out, no response yet (give it 3 business days before chasing)
- `replied — confirmed` — they're in
- `replied — passing` — they declined; thank them, don't push
- `replied — needs info` — they have questions; answer them, then wait
- `no response` — chase once, then move on

**Follow-up:** ONE chase email after 3 business days, then drop. Pushing harder converts at <5% and damages the relationship.

If you're at 3 confirmed by Day 5 of Sprint 1, stop emailing — you're at goal. If you're at 1-2 confirmed by Day 5, send 3 more from a second-tier list.

---

## What to do with confirmed testers (after replies come in)

Once someone confirms:

1. **Reply with `BUG_BASH.md`** attached (or linked once the repo is public). Tell them they have 5 days from confirmation to start testing.
2. **Add them as a collaborator** on the GitHub repo (Settings → Collaborators → Add). This gives them issue + PR access without committing to your branch.
3. **Slack / Discord / WhatsApp** for fast questions during testing — set up a shared channel if you have 3+ testers running concurrently.
4. **Schedule a 20-min debrief call** for each tester at the end of Week 2. Don't skip this — the verbal feedback always reveals more than the written reports.

---

## What you're NOT promising

- A pitch deck
- A future paid subscription
- A reference in a sales call (unless they explicitly want to be)
- A continuing relationship beyond the bug-bash

Keep the ask small. If they like the tool enough to become a public advocate after launch, that's a bonus — don't ask for it up front.
