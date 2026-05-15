# Teardown Engine — one audit a week, every week

> **Purpose:** The operating manual for Lictor's weekly public teardown. Read it Monday morning, follow it verbatim, ship a teardown every Tuesday.
> **Owner:** Conductor coordinates. Every agent has a named role below.
> **First teardown:** Oct 6, 2026 (launch). Pitchtank if it hasn't fixed everything by Sep 22. Tymora if it has.

---

## The cadence — one week, day by day

The week runs **Tuesday-publish → Tuesday-publish**. Disclosure is the gate; the calendar bends around it, not the other way.

| Day | Who | What | Output |
|---|---|---|---|
| **Tue (Week 0)** publish | Quill + Magnet | This week's teardown ships at 09:00 PT | Blog, Twitter, LinkedIn, HN, Reddit, Substack, GitHub gist, YouTube short |
| **Tue (Week 1)** | Radar | Pick next week's target from the rolling candidate list | `teardowns/next/target.json` |
| **Wed (Week 1)** | Conductor + Dor | Send responsible disclosure email | `teardowns/next/disclosure.eml` saved with timestamp |
| **Thu (Week 1)** | (founder window) | Quiet day. Founder reads the email. Don't poke. | — |
| **Fri (Week 1)** | Probe + Sieve | Run the audit. Score every finding. | `teardowns/next/findings.json` |
| **Sat (Week 1)** | Quill + Magnet | First draft of the report + the landing page | `teardowns/next/report.md`, `landing-pages/<slug>/page.md` |
| **Sun (Week 1)** | Vibe + Pulse | Visuals, hook variants, thumbnail | `teardowns/next/hooks.json`, `teardowns/next/cover.png` |
| **Mon (Week 1)** | Mirror | Review the full package against the rails below. Approve or kick back. | `teardowns/next/review.md` |
| **Tue (Week 1)** publish | C-3PO | Push live across all surfaces at 09:00 PT | (next teardown's `Week 0`) |

**Disclosure window minimum: 14 days.** If you pick a target Tuesday and the disclosure email goes Wednesday, the earliest you can publish is the Tuesday two weeks later. The "Friday audit" of Week 1 happens *inside* the disclosure window — you're auditing privately, the report drafts privately, the founder sees what you found before the public does.

**For launch (Oct 6):** disclosure emails went Sep 22 per `teardown-targets.md`. By Oct 6 the 14-day window has elapsed. Publish.

---

## The agent-by-agent role

Each agent has one job that week. Conductor coordinates. No one freelances.

| Agent | Role | What ships from them |
|---|---|---|
| **Radar (scout)** | Picks the target. Reads the candidate pool, ranks by the `teardown-targets.md` criteria, picks one. | `target.json` — app name, URL, platform, founder name, public traction, risk score |
| **Conductor (planner)** | Sends the disclosure email Wednesday. Owns the calendar. Escalates to Dor if the founder responds. | `disclosure.eml`, `briefings/YYYY-MM-DD.json` entry |
| **Probe** | Runs the audit Friday. Catalogs every finding with file/URL evidence. | `findings.json` — full structured findings, severity per finding, evidence path |
| **Sieve (critic)** | Scores each finding for severity + clarity. Anything below `severity ≥ medium` AND `evidence: solid` gets cut. | `findings.scored.json` |
| **Quill (writer)** | Writes the report in Dor's voice. One pass to draft, one pass to tighten. | `report.md` |
| **Magnet** | Builds the landing page that ranks for `[App Name] security audit`. SEO meta, OG image, capture form. | `landing-pages/<slug>/{page.md, meta.json, follow-up.md}` |
| **Pulse (surveyor)** | Writes 5 hook variants for the Twitter thread, LinkedIn post, and HN title. | `hooks.json` |
| **Vibe** | Designs the cover image, the YouTube short thumbnail, and the carousel visuals. | `cover.png`, `thumbnail.png`, `carousel/*.png` |
| **Trends** | Cross-checks: which hashtags + formats are spiking this week. Pulse uses this when crafting hooks. | `output/trends-pulse-YYYY-MM-DD.jsonl` |
| **Mirror (reviewer)** | Reads the full package Monday. Checks the rails. Approves or kicks back with specific fixes. | `review.md` — score + go/no-go |
| **C-3PO (dev)** | Pushes everything live Tuesday 09:00 PT. Handles the GitHub gist + the blog deploy + the cross-posting. | git commits, deploy logs |

If an agent has nothing to do that week (e.g., Trends if the audit is purely technical), they say so in their memory file. Silence isn't allowed — "no contribution this week" is a real result.

---

## The report template

This is the `teardowns/YYYY-MM-DD-app-slug/report.md` template. Fill every section. If a section doesn't apply, write "N/A — [why]" rather than delete it.

```markdown
# [App Name] — what Lictor's 11 AI agents found in 12 minutes

> Audited: [date] · Platform: [Lovable | Bolt | v0 | Cursor | Replit | Anything]
> Disclosed to founder: [date] · Founder response: [responded / fixed / silent]
> Total findings: [N] · Critical 🔴 [N] · High 🟠 [N] · Medium 🟡 [N]

## The headline

[One sentence. The thing a journalist would screenshot. Specific number + specific app + specific consequence. No hedging.]

## The app

[2-3 sentences. What it does, who uses it, what's at stake. Link the live URL. Name the founder if they've cooperated.]

## How we picked it

[2-3 sentences. Why this app, why this week. Cite the criteria from `teardown-targets.md`. Be honest that this is a public teardown.]

## The audit — 12 minutes, 11 agents

| Severity | Finding | Agent who found it |
|---|---|---|
| 🔴 Critical | [1-line summary] | Probe |
| 🟠 High | [1-line summary] | Probe |
| 🟡 Medium | [1-line summary] | Sieve flagged after Probe scan |
| ... | | |

## Finding #1 — [Severity icon] [Plain-English title]

**File / URL:** `[exact path or endpoint]`
**What's wrong, in plain English:** [2-3 sentences. No jargon. Could a non-technical founder understand?]
**Who's affected:** [Users? Customers? The founder? Be specific about who eats the cost.]
**The 1-line fix:** [Literal code or config change. Paste the exact line.]
**Rotate-the-secret runbook** (if applicable): [Step-by-step: revoke the leaked key, rotate it in Supabase/Stripe/wherever, redeploy, audit logs for usage during exposure window.]

[Repeat for every finding.]

## What the founder did about it

[If they fixed it: name them, link their fix, credit them publicly.]
[If they didn't respond: state the disclosure dates and the silence. Don't editorialize.]
[If they pushed back: quote the pushback verbatim if they consent, paraphrase if not.]

## Lessons for every vibe-coder

[3-5 bullets. Generic patterns this teardown exposes. Phrased as "if you built on [platform], check for [specific pattern]." This is the part that ranks in Google.]

## Lictor crew credits

- **Radar** — picked the target [link memory entry]
- **Probe** — found [N] of the [N] findings [link probe report]
- **Sieve** — scored every finding for severity + clarity [link sieve output]
- **Quill** — wrote what you're reading
- **Magnet** — built the landing page
- **Mirror** — reviewed the package Monday before publish
- **Conductor** — coordinated the week

## Disclosure timeline

| Date | Event |
|---|---|
| [date] | Lictor sent responsible disclosure email to [founder email] |
| [date] | Founder responded: [yes / no / fix shipped] |
| [date] | Public publish |

## Methodology

[2-3 paragraphs. How Probe runs the audit. What tools it uses. What it does NOT do (e.g., "no active exploitation, no exfiltration, read-only access only"). Anyone should be able to read this and trust the audit was ethical.]

## Reproduce it yourself

[Step-by-step. Anyone with the free Lictor install can rerun the exact audit. Include the slash command. Link the GitHub gist with the full JSON output. This is the proof-of-work that makes the teardown defensible against "you cherry-picked findings."]

```bash
# install Lictor
npm install -g @lictor/cli
# run the same audit we ran
lictor audit https://[app-url]
```

## Get the full crew working on your app

[Magnet's CTA. Link to the landing page Magnet built. One ask, not three.]
```

---

## The "if the founder fixed it" branch

Sometimes the founder reads the disclosure, fixes everything inside the 14-day window, and the public teardown becomes a teardown of *nothing*. That's not a content failure — it's the best possible outcome and even better content.

**The fixed-cleanly story is published anyway**, with this structure:

- **Headline:** *"[Founder name] fixed every critical issue in [N] days. Here's exactly how — and why other vibe-coders should copy this playbook."*
- **Frame:** the responsible-disclosure-to-quick-fix loop is the aspirational story. The founder is the hero. Lictor is the audit. The reader is the next founder who could do this.
- **What changes vs the standard template:**
  - The findings section becomes "what we found AND what they shipped to fix it" — paired before/after.
  - Add a section: **"Their fix-it timeline"** with day-by-day what the founder did.
  - Add a section: **"What this proves about the platform"** — if Lovable's RLS gaps fix in 2 hours, that's a story about Lovable too.
  - Founder gets the byline credit. Lictor gets the audit credit. Both win.

**The fixed-cleanly publish still ships to every surface.** It's actually *easier* on the founder's lawyers, easier to get HN front-paged ("indie founder fixes 7 security issues in 48 hours" is more compelling than another vulnerability post), and easier to get the founder to retweet — because they look great.

If two teardowns in a row land "fixed cleanly," that's a feature, not a bug. The Lictor narrative becomes *"we audit, founders fix, the ecosystem gets safer."*

---

## The publishing checklist — every surface, Tuesday 09:00 PT

Every teardown ships to every surface below. C-3PO owns the deploy. Each surface has its own format requirements; do not paste the same copy everywhere.

| Surface | Format | Owner | Requirement |
|---|---|---|---|
| **Lictor blog** | Long-form (1500-3000 words), the full report | Quill writes, C-3PO deploys | Canonical URL. All other surfaces link here. |
| **Twitter / X thread** | 14-18 tweets, hook in tweet 1, findings 2-12, fix CTA tweet 13, link to full report tweet 14 | Pulse drafts hooks, Quill writes the thread | Use the hook variant Pulse scored highest. Image per finding (Vibe). |
| **LinkedIn post** | 1200-1500 chars, framed as a case study, no thread format | Quill | Tag the platform (Lovable / Bolt). Tag the founder if they cooperated. |
| **Hacker News** | Text-only "Show HN: I audited [App] with 11 AI agents. Here's what we found." | Quill writes the title, Conductor submits | No URL submission — text post with the full TL;DR + link to blog at bottom. HN penalizes URL-only posts. |
| **Reddit r/programming** | Same as HN but slightly more technical framing | Conductor submits | Title is a question or a finding. "[App] leaks every user's [X] — here's why and how to prevent it." |
| **Substack newsletter** | The full teardown, plus a sidebar of "what this week taught me" | Quill | Goes to the Lictor list every Tuesday 10:00 PT |
| **GitHub gist** | The full structured `findings.json` + reproducer script | C-3PO | Public gist under the Lictor org. Linked from the blog. The proof-of-work. |
| **YouTube short** | ≤60 seconds. Hook, 3 findings, fix, CTA. | Vibe storyboards, Quill scripts, Dor records | Vertical 9:16. Captions hardcoded. |
| **TikTok** | Same script as YouTube short, reshot if needed for platform-native pacing | Skip if Dor isn't shipping TikTok regularly | Only ship if the TikTok account has consistent posting — one-offs flop |
| **Lictor landing page** | `lictor.dev/audits/[app-slug]` — SEO-optimized to rank for "[App Name] security audit" | Magnet | Headline matches the search query. Capture form below the fold. |

**Cross-posting timing:** blog goes live at 09:00 PT. Twitter thread goes 09:01. LinkedIn 09:05. HN at 09:10 (HN voting is timezone-sensitive — 09:10 PT = 12:10 ET = good NYC/east-coast audience). Reddit at 09:30. Substack auto-sends at 10:00. YouTube short at 11:00 (gives the blog post time to rank for the search query the short will drive).

---

## The legal safety rails — non-negotiable

These are not suggestions. Break any of them and Mirror kicks the teardown back. Break them twice and Lictor loses the right to do public teardowns at all.

1. **14-day minimum disclosure window.** No exceptions. If the founder asks for more time and the request is in good faith, grant up to 30 days. If they ask for more than 30, escalate to Dor.
2. **Never publish exploit code.** Findings describe *what's wrong*, not *how to weaponize it*. "The Supabase anon key is in the JS bundle" — yes. "Here's a curl command that drains the database" — no.
3. **Never punch down.** No teardown of apps with under 1,000 users unless the owner explicitly consents. The point is to teach the ecosystem, not bully indie hackers.
4. **Never name an individual user.** If a leaked record contains a real person's email, redact it. Show the schema, not the row.
5. **Always name and credit the founder if they cooperate.** Cooperation = response within disclosure window + fix attempt. If they cooperate, they get the byline credit in the "fixed cleanly" version, or a positive callout in the standard version.
6. **No teardown of paying Lictor customers.** Obvious. Mirror checks this every Monday before approving.
7. **No teardown of platforms Lictor has a partnership with.** Lovable, Bolt, v0, Cursor, Replit — if any of these become Lictor partners, their built-on apps stay off the teardown list. Audit the platform's tutorial apps instead.

---

## Output paths — where teardowns live in the repo

```
/Users/raffa/Lictor/teardowns/
├── 2026-10-06-pitchtank/
│   ├── target.json              ← Radar's output
│   ├── disclosure.eml           ← Conductor's email, timestamped
│   ├── findings.json            ← Probe's raw findings
│   ├── findings.scored.json     ← Sieve's scored cut
│   ├── report.md                ← Quill's final draft
│   ├── hooks.json               ← Pulse's hook variants
│   ├── cover.png                ← Vibe's cover image
│   ├── carousel/                ← Vibe's per-finding visuals
│   ├── thumbnail.png            ← YouTube short thumbnail
│   ├── review.md                ← Mirror's Monday review
│   └── publish-log.md           ← C-3PO's deploy log per surface
├── 2026-10-13-tymora/
│   └── ...
└── next/                         ← In-flight teardown, gets renamed once published
    └── ...
```

Plus, per teardown, Magnet writes to `/Users/raffa/Lictor/landing-pages/<app-slug>/{page.md, meta.json, follow-up.md}` — same convention as GenerationAI.

The `target.json` is the lightest file but the most-read. Here's its shape:

```json
{
  "app_name": "Pitchtank",
  "url": "https://pitchtank.io",
  "platform": "Lovable",
  "founder": "@founder_handle",
  "founder_email": "founder@pitchtank.io",
  "public_traction_estimate": "10K-50K users",
  "risk_score": 1,
  "rationale": "Solo Lovable founder, modest traction, near-certain RLS gaps, narrative-perfect for launch",
  "picked_by": "Radar",
  "picked_at": "2026-09-22T10:00:00Z",
  "disclosure_sent": "2026-09-22T11:00:00Z",
  "publish_target": "2026-10-06T16:00:00Z"
}
```

That's the entire engine. Run it Tuesday. Repeat.
