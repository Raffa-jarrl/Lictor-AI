# 12 teardown scaffolds — Oct 6 → Dec 22, 2026

> **Generated:** 2026-05-15
> **Purpose:** runway for the launch engine. The teardown rhythm cannot break in the first 12 weeks — that's how the category-defining position locks in. These scaffolds let the agent crew (Radar/Probe/Quill/Magnet) start producing each week's teardown 14 days before publication without re-inventing the structure each time.
> **How to use:** Week N's scaffold lives at `~/Lictor/teardowns/YYYY-MM-DD-slug/scaffold.md`. The agent crew fills in the audit findings, the founder response, and the final copy. Headline + structure already locked.
> **Companion docs:** [teardown-engine.md](./teardown-engine.md) (operational spec), [teardown-targets.md](./teardown-targets.md) (target research), [content-calendar.md](./content-calendar.md) (cross-channel distribution per week).

---

## Master scaffold (the shape every teardown follows)

```yaml
# Front matter (used by Magnet for the landing page)
publish_date: YYYY-MM-DD
target_app: [App name]
target_url: https://...
platform: lovable | bolt | v0 | cursor | replit | other
founder: [name + handle]
founder_response_status: pending | engaged | fixed | non-responsive
disclosure_sent: YYYY-MM-DD
publication_authorized: YYYY-MM-DD
risk_level: 1-5 (see teardown-targets.md scoring)
headline: [final headline used at publish]
agent_credits: { radar: N findings, sieve: N scored, probe: N validated, quill: drafted }

# Body sections (filled by Quill from Probe's audit + agent crew)
1. Hook (3-second open)
2. Setup — who built this, why we picked it
3. Audit at a glance — total findings + severity histogram
4. Finding #1 (critical) — with evidence + plain English + fix
5. Finding #2 (critical or high)
6. Finding #3 (high or medium)
7. Founder response section (varies by branch)
8. Lessons for every [platform]-builder
9. How to check your own project
10. Crew credits + disclosure timeline
11. CTA — try /lictor-security-check yourself

# Companion content (drafted by Magnet + Pulse + Reel)
twitter_thread: 6 tweets, last one links to landing page
linkedin_post: 1 post in Raffa's voice (different framing from Twitter)
hn_submission: text-only submission, 200 words
substack_newsletter: 800-word email version
youtube_long: 8-12 min walkthrough
youtube_short: 60s teaser
```

Every scaffold below follows this shape. Variance is in the *target*, *predicted findings*, and *positioning angle*.

---

## Week 1 — Oct 6, 2026 — Pitchtank (the launch)

### Target & context
- **App:** Pitchtank (`pitchtank.io`) — Lovable-built community voting platform for startup ideas
- **Founder:** solo indie, listed on madewithlovable.com
- **Traction:** modest, real running business, ~Product Hunt presence
- **Risk level:** 1 (safest first demo per [teardown-targets.md](./teardown-targets.md))
- **Why Week 1:** founder almost certainly responds gratefully; teardown reads as "indie founder gets free security audit from Lictor's AI agents" — perfect launch frame

### Disclosure timeline
- **Sep 22:** disclosure email sent (with explicit Oct 6 publication notice)
- **Sep 22 – Oct 5:** 14-day fix window
- **Oct 4:** final check — if fully fixed, switch to "Tymora" as launch target (Week 2 swap)
- **Oct 6:** publish

### Predicted findings (working hypothesis — Probe validates)

| # | Severity | Category | Predicted finding |
|---|---|---|---|
| 1 | 🔴 critical | rls | Missing RLS on `votes` table → any logged-in user reads everyone's votes |
| 2 | 🔴 critical | rls | Missing RLS on `ideas` table → user can read every submitted idea before it's public |
| 3 | 🟠 high | secrets | Supabase anon key visible in client JS (expected — anon is OK, but service-role key check) |
| 4 | 🟠 high | rate-limit | No rate limit on voting endpoint → ballot-stuffing |
| 5 | 🟡 medium | webhook | Stripe webhook signature not verified (if Stripe is wired) |

### Headline candidates (rank order)
1. *"Pitchtank pays out $X to top-voted ideas every month. Lictor's 11 agents audited the voting system. Here's what we found."* (specifics + named stake)
2. *"We audited an indie Lovable app in 12 minutes. The founder fixed 4 of 5 findings in 6 days. Here's the story."* (if fully-fixed branch)
3. *"What every Lovable founder should check before payday: the Pitchtank teardown."* (educational frame)

### The angle
**Frame 1 (default):** indie founder gets generous free audit; founder is the hero of the story.
**Frame 2 (alt if non-responsive):** measured, no snark, founder credited by handle, fixes are concrete.

### Companion content sketch
- **Twitter thread:** open with the specific number ("$X paid out monthly"), 3 findings as numbered cards, founder credit, CTA to lictorai.com/skill
- **LinkedIn post:** "I'm announcing Lictor today. Here's the kind of audit we run." Pitchtank teardown as the proof artifact.
- **HN submission:** text-only "Show HN: Lictor — open-source AI security audit, with example teardown" + link in first comment
- **Substack:** "Why I'm building Lictor" essay + the Pitchtank case attached

---

## Week 2 — Oct 13, 2026 — Tymora

### Target & context
- **App:** Tymora (`tymora.ai`) — Lovable-built AI executive assistant (reads email, calendar, texts)
- **Founder:** public-facing on X, on madewithlovable
- **Traction:** visible Lovable showcase, real OAuth flows with sensitive scopes
- **Risk level:** 2 — second-safest, strongest "AI agent era" narrative match

### Disclosure timeline
- **Sep 29:** disclosure email
- **Oct 12:** confirmation of publication date with founder

### Predicted findings
| # | Severity | Category | Predicted finding |
|---|---|---|---|
| 1 | 🔴 critical | secrets-in-storage | OAuth refresh tokens stored in Supabase table without RLS |
| 2 | 🔴 critical | secrets | Google API keys + Twilio API keys in client bundle |
| 3 | 🟠 high | audit-log | No audit log of agent actions — exact problem Sentinel solves |
| 4 | 🟡 medium | prompt-injection | User-facing text fields passed unsanitized to model |

### Headline candidates
1. *"Tymora reads your Gmail. Lictor's 11 agents audited it. Here's what we found."* (specific + memorable)
2. *"AI agents doing real-world actions need real-world security. Tymora teardown."* (narrative-aligned)

### The angle
This teardown is the launch-week-2 *consolidation*. Pitchtank introduced the format; Tymora makes the "AI agent era" thesis concrete. The Sentinel SDK gets a natural plug (audit-log finding).

### Companion content sketch
- Twitter thread: lead with "Tymora reads your Gmail" — irresistible curiosity hook
- LinkedIn: deeper essay on "why AI assistants need their own security model"
- HN: this is the post that targets the AI/dev audience harder than Pitchtank did

---

## Week 3 — Oct 20, 2026 — FindMeMail

### Target & context
- **App:** FindMeMail (`findmemail.io`) — Lovable-built B2B email lookup ("15K+ verified emails")
- **Founder:** Witarist IT Services Pvt. Ltd. (small Indian software studio)
- **Traction:** paying customers, $200 lifetime deals, real PII database
- **Risk level:** 2.5

### Disclosure timeline
- **Oct 6:** disclosure email (note longer window — foreign jurisdiction may slow response)
- **Oct 19:** publication confirmation

### Predicted findings
| # | Severity | Category | Predicted finding |
|---|---|---|---|
| 1 | 🔴 critical | rls | Email database queryable via anon key from browser — entire B2B contact list exfiltrable |
| 2 | 🟠 high | webhook | Stripe webhook unauthenticated → fake "paid" signals possible |
| 3 | 🟠 high | rate-limit | Email-validity-check endpoint un-rate-limited → free unlimited email verification for any attacker |

### Headline candidates
1. *"We audited a leaked-email-finder for leaked emails. Reader, we found them."* (irresistible irony)
2. *"FindMeMail's 31K+ email database is one anon-key query away from public. Here's the audit."* (specific + technical)

### The angle
Pure narrative gold. The irony writes itself. Be respectful — they're a small business in India running a serious product. Frame as cautionary tale, not punchline.

### Companion content sketch
- Twitter: lead with the irony hook
- Press: this is the teardown that gets picked up by *The Register* — pitch them Oct 14 with embargo to Oct 20
- HN: "Show HN" framing for the methodology + the FindMeMail case

---

## Week 4 — Oct 27, 2026 — AgentSwarms

### Target & context
- **App:** AgentSwarms (`agentswarms.fyi`) — Lovable-built multi-agent AI sandbox
- **Founder:** public on X (@AgentSwarmsAI)
- **Traction:** active educational platform, users plug in API keys + run real SQL + send emails
- **Risk level:** 3

### Disclosure timeline
- **Oct 6:** early disclosure email (21-day window — higher risk requires more lead time)
- **Oct 26:** final publication confirmation

### Predicted findings
| # | Severity | Category | Predicted finding |
|---|---|---|---|
| 1 | 🔴 critical | secrets-in-storage | User-supplied OpenAI/Anthropic API keys in plaintext in Supabase without RLS — the apocalyptic finding |
| 2 | 🟠 high | prompt-injection | Agent execution sandbox escape via prompt injection in lesson content |
| 3 | 🟡 medium | webhook | Webhook URLs reachable from public clients without signing |

### Headline candidates
1. *"AgentSwarms teaches multi-agent AI. We audited it with multi-agent AI. Here's what one crew found in the other."* (the meta-frame)
2. *"User API keys stored in plaintext in an AI-agent sandbox. The 14-minute audit."* (sharper)

### The angle
The meta-frame is irresistible — Lictor's AI agents audit an AI-agent platform. Use it. The educator framing also opens partnership potential: AgentSwarms founder might engage publicly as a "thanks for the security teaching moment."

### Companion content sketch
- Reach out to the founder for a co-recording — 10x amplification if they appear in the YouTube long-form
- Twitter thread leads with the meta-frame
- This is the first teardown where Reel agent's video script writes itself

---

## Week 5 — Nov 3, 2026 — Anything (`anything.so`)

### Target & context
- **App:** an app shipped *via* Anything (the vibe-coding platform) — not Anything itself. Pick a public app with App Store presence.
- **Founder of Anything:** Dhruv Amin & Marcus Lowe — public, $11M raise, $100M valuation, ex-Google
- **Risk level:** 4 (week-2 follow-up tier, NOT launch week — keeping the position narrative consistent)

### Disclosure timeline
- **Oct 13:** disclosure email — 21-day minimum window, possibly 28
- **Nov 2:** final confirmation
- **Disclosure to:** the shipped-app's developer AND, as courtesy, Anything's security email

### Predicted findings
| # | Severity | Category | Predicted finding |
|---|---|---|---|
| 1 | 🔴 critical | secrets | Hardcoded API keys in shipped iOS bundle (App Store binaries extracted with `class-dump` show them) |
| 2 | 🟠 high | transport | No certificate pinning → any of these apps MitM-able on a coffee-shop wifi |
| 3 | 🟡 medium | secrets-in-storage | No Keychain storage for user secrets in default template |

### Headline candidates
1. *"Anything raised $11M to let anyone ship an iOS app. We audited one. Here's what shipped to the App Store."* (specifics + the meta)
2. *"The case of the hardcoded API keys. An Anything-built app, an iOS extraction, a $14k OpenAI bill."* (story-shaped if findings include API-key extraction)

### The angle
Higher-stakes target → higher-stakes legal preparation. **Get legal review on the writeup before publishing.** Frame: education, not attack. The founders of Anything are sharp and well-resourced; they will respond publicly. Be airtight.

### Companion content sketch
- Press: pitch *TechCrunch* — they already covered Anything's raise + the Apple-pulled story. They'll bite.
- Twitter: longer thread (10+ tweets) with the methodology explained
- LinkedIn: this is the post that ends up on dev-Twitter's screenshot tour

---

## Week 6 — Nov 10, 2026 — [open archetype: a Bolt.new app]

### The archetype
Pick a public Bolt.new-built app with: real user base (1K+ users), public founder (Twitter or LinkedIn), no past public breach. Bolt's default stack (Vite + Supabase or Drizzle) has its own pattern set distinct from Lovable's.

### Why Week 6
Diversify away from Lovable. The first 5 weeks were heavy on Lovable; if the pattern set is "Lovable only" by week 6, Bolt and v0 founders write Lictor off as "not for them."

### Suggested candidates (Radar to confirm closer to date)
- A Bolt-built SaaS featured on Product Hunt in the last 90 days
- One of the Bolt hackathon winners with public traction
- A Bolt-built B2B tool aimed at small dev teams

### Predicted Bolt-pattern findings (archetype-level)
| Category | Pattern |
|---|---|
| Environment | `VITE_*` prefixed vars exposed in client bundle (Bolt's Vite default) |
| API | Bolt API routes deployed as Netlify functions with weak auth |
| Storage | Bolt's Supabase migrations often miss RLS on `auth.users` foreign-key tables |
| Build | Source maps shipped to production (Bolt default — exposes uncompiled source) |

### Headline shape
"[Bolt app], audited. The 4 patterns Lictor catches that Bolt's defaults don't."

### The angle
Establishes Lictor as multi-platform competent. By Week 6, the audience knows Lictor on Lovable — Week 6 says "and Bolt, and next week v0, and the week after that…"

---

## Week 7 — Nov 17, 2026 — [open archetype: a v0 app]

### The archetype
v0 by Vercel — different stack again (Next.js App Router + their UI library + often Supabase or Postgres direct). Pick a public v0-built app, ideally one that's a B2C product.

### Why Week 7
Complete the trio. Lovable + Bolt + v0 is the holy trinity of vibe-coder platforms. By Week 7, Lictor has audited all three publicly.

### Predicted v0-pattern findings (archetype-level)
| Category | Pattern |
|---|---|
| Auth | Next.js Server Actions misused for auth — easy to bypass |
| API | v0's generated API routes lack input validation by default |
| Caching | `unstable_cache` used with user-tenant data — cross-tenant leakage |
| Headers | Missing security headers (CSP, X-Frame-Options) in v0's default deploy |

### Headline shape
"v0 ships apps that look great. We audited the security. Here's what we found in [App]."

### The angle
By the end of Week 7, you can publish a *recap* post: "We audited Lovable, Bolt, and v0 apps in 3 weeks. Here are the 12 patterns common to all three." That recap is shareable and SEO-durable.

---

## Week 8 — Nov 24, 2026 — Thanksgiving week — a Cursor "vibe-coded" project

### The archetype
US Thanksgiving falls Nov 26-27, 2026. Audience attention is lower. Use this week for a *teach* not a *teardown* — pick a Cursor-built personal project (a friend's, with permission) and walk through the audit as a tutorial.

### The pivot
Don't waste Thanksgiving week on a high-stakes named teardown. Use it for evergreen educational content that compounds:
- "How I audit my own Cursor-built side project — a 12-minute walkthrough"
- Voice: tutorial, not exposé
- Founder/owner: Raffa, or a friend with permission

### Why it still counts as a teardown
The structure is the same. The audit is real. The findings are real. But the energy is "build with me" not "look what we found."

### Headline shape
"I audited my own Cursor project on Thanksgiving. Here's the 12-minute audit walkthrough."

### The angle
Slow week → slower energy. The teardown rhythm doesn't break; the *tone* shifts. Counter-cyclical with the audience.

---

## Week 9 — Dec 1, 2026 — A Replit-deployed app

### The archetype
Replit has a massive community of indie devs and an emerging "Replit Agent" feature for shipping AI apps. Pick one Replit-deployed app with traction. Likely candidates: Replit Bounty winners, Replit Spotlight apps.

### Predicted Replit-pattern findings
| Category | Pattern |
|---|---|
| Storage | Replit's free-tier ReplDB used for sensitive data (no encryption at rest) |
| Auth | Replit's "Always On" repls with auth tokens visible in the env panel (shared workspace risk) |
| API | Replit Agent-generated endpoints often lack rate limiting |

### Headline shape
"Replit makes shipping easy. Here's what we found when we audited a popular Replit app."

### The angle
By Week 9, Lictor has covered Lovable + Bolt + v0 + Cursor + Replit publicly. That's the full vibe-coder platform set. Any user of any platform can find a Lictor teardown that's *relevant to them specifically*. This is the SEO-durable position the year plan is built around.

---

## Week 10 — Dec 8, 2026 — A "Windsurf-built" or "Claude Code-built" app

### The archetype
Newer AI coding platforms — Windsurf (Codeium) and Claude Code itself — are emerging. The community of public projects is smaller but growing. Pick one with traction.

### Why Week 10
Show that Lictor handles the newest tools too. Distinguish from competitors that only support established stacks. This is the "we're current" signal.

### Headline shape
"Windsurf can ship a full SaaS in an afternoon. We audited the security in 14 minutes."

---

## Week 11 — Dec 15, 2026 — Lictor for Teams launch + a flagship teardown

### Double-duty
This week ALSO launches Lictor for Teams paid tier (per year plan). Pair the teardown with the launch:

### Suggested target
A *Lictor user* who's been using the free skill since the Oct launch and built something cool. With their permission, audit their improved-post-Lictor app — show the before/after of an app that went through Lictor's audit cycle.

### Headline shape
"Three months after the launch, we re-audited [User's App]. Here's how Lictor's findings changed the product."

### The angle
The customer-success teardown. Pairs naturally with the Teams launch announcement: "And if you want this as a recurring service for your team, Lictor for Teams ships today at $19/month flat."

---

## Week 12 — Dec 22, 2026 — The 12-week recap

### Format
NOT a new audit — the year-end recap meta-post. "Lictor audited 12 apps in 12 weeks. Here's what we learned."

### Sections
1. The 12 apps audited (with link to each writeup)
2. The patterns that came up in every audit (the durable insights)
3. The platform-specific surprises (what Lovable does that Bolt doesn't, etc.)
4. The 5 changes Lictor itself shipped because of community feedback
5. The 3 categories of bug we missed in some audits (honest)
6. What's coming in 2027

### Strategic role
This is the post that:
- Ranks for "vibe-coder security" forever
- Becomes the "if you only read one Lictor post, read this one" canonical reference
- Provides the year-end recap content that journalists and newsletter writers love to link to
- Resets the engine before the Q1 2027 push

### Headline candidates
1. *"12 audits, 12 weeks, ~500 findings. What I learned about vibe-coder security in 2026."*
2. *"The 2026 Lictor year-end report: every audit, every pattern, every lesson."*

---

## How the agent crew uses these scaffolds

```
Sun, week-of:    Radar agent confirms target from this week's scaffold
                 Probe agent starts the audit against the target
Mon:             Probe's audit complete; findings come back to Sieve
                 Sieve scores; only ≥6 findings make the report
                 Quill drafts the writeup using the scaffold structure
Tue (target -8 days): Disclosure email sent (for high-risk targets)
                      OR (for risk-1-2 targets) disclosure sent Tue of week prior
Wed of pub-week: Quill's draft reviewed by Mirror
Thu of pub-week: Founder response logged (engaged | fixed | non-responsive)
                 Branch chosen: standard teardown OR "fixed cleanly" story
Fri of pub-week: Raffa records video using Reel's script
                 Magnet builds the landing page
                 Pulse drafts companion social
Mon AM:          Final review by Raffa
Tue PUBLISH:     See teardown-engine.md publication sequence
```

If a scaffold's target doesn't pan out (founder threatens legal action, target goes offline, founder partners with us pre-disclosure), the fallback is:
- Week 1-5: defer one week, use the listed alternate target
- Week 6-10: pick a fresh archetype-matching target from Radar's then-current candidate list
- Week 11-12: protected weeks — don't sub in a contentious target on Teams-launch / year-end-recap weeks

## What's NOT in these scaffolds (deliberate)

- **Exploit code.** No teardown ever publishes runnable exploit code. Predicted findings describe shape of vulnerability and impact; published findings describe the same. Demos are conceptual, not actionable.
- **Individual user data.** No teardown names an end-user of the target. Aggregated counts only ("18K users exposed"), never names.
- **Founder home addresses, family info, anything personal.** Founders are public personae in their professional capacity; that's the limit.
- **Speculation about the founder's competence.** Every founder shipping anything is doing harder work than the critic. Stay measured.

## What the next 12 weeks (Jan-Mar 2027) look like

Once Week 12 publishes (Dec 22, 2026), the second 12-week cycle begins. Plan that batch in early Dec based on what worked in the first 12. Don't pre-write the second batch now — the data isn't in yet. But reserve the slot.

The pattern from Q3+Q4 2026 should be: 5 specific high-confidence targets + 7 archetype-shaped flexibles. Q1 2027 onward shifts toward 3 high-confidence + 9 flexible, as Lictor's audience grows and *they* start sending targets.
