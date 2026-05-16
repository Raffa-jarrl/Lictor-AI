> **NOTE (May 2026 update):** Course revenue line REMOVED from Lictor's plan. The course at generationai.com is a separate consulting business and is no longer part of this project. References below that mention "Course", "course enrollments", or course-derived revenue should be treated as historical and substituted with zero. Other revenue lines (Teams, AaaS, Enterprise) stand.

# Anti-Snyk-Free-Tier Playbook — what Lictor does in the 90 days after Snyk ships a free SMB / vibe-coder tier

> **Generated:** 2026-05-15
> **Context:** Snyk has the brand, the engine, and explicit gaps in vibe-coder coverage. Probability they ship a free SMB tier (or `snyk vibe-check` CLI, or a Lovable plugin) within 12 months: **high — ~70%.** Within 6 months: ~35%. The playbook assumes *when*, not *if*.
> **Strategic principle:** Lictor cannot win a price war (already free) or a distribution war (Snyk has 10+ years GTM machinery). Lictor wins on **product shape**, **community ownership**, and **founder visibility** — three things Snyk's org structure prevents them from copying without breaking their CISO business.

---

## Bottom line

The day Snyk ships a free SMB tier is not the day Lictor dies. It's the day Lictor's positioning gets *easier*, because the contrast becomes visible to every developer. Snyk's free tier will leak compliance dialect, telemetry requirements, and 5-seat-team upsells. Lictor's job in those 90 days is **not** to out-feature them — it's to make the contrast undeniable on every channel where vibe-coders look.

If Lictor follows this playbook, Snyk's free tier becomes Lictor's biggest marketing asset. If Lictor panics and races to add features, Lictor becomes a cheaper-Snyk and dies in 6 months.

---

## Phase 0 — Pre-empt (now → launch + 60 days)

These move regardless of when Snyk ships. They are the bedrock that makes the response playbook work.

| Move | Why it matters |
|---|---|
| **Own the keyword "vibe-coder security"** | Land 3 cornerstone blog posts + 1 weekly teardown rhythm. When a developer Googles the phrase, Lictor is the answer. Snyk's SEO machine cannot pivot a 10,000-page domain authority toward a new keyword in under 12 months. |
| **Lock in the Claude Code skill suite as the wedge product** | This is where vibe-coders live. Snyk's CLI is an extra install; Lictor's `/lictor-security-check` is one slash command in the chat they're already in. *Distribution-by-context* is Snyk's hardest gap to close. |
| **Publish the 11-agent crew as a transparent feature, not infrastructure** | Snyk's Evo agents are a black box. Make Lictor's crew named, visible, and personable. People follow agents with names. People don't follow "Workflow Orchestrator." This is asymmetric branding Snyk can't replicate. |
| **Build the founder-on-camera channel** | Snyk has no face. Lictor has Raffa. Ship one talking-head video per week — teardown, agent-watch, security explainer. By the time Snyk ships free, "Raffa's videos" is a known content category. Founder content is the moat Snyk's PR team literally cannot copy. |
| **Co-opt the small competitors** | Reach out to VibeEval and Symbioticsec *now*. Offer integration, cross-citation, joint teardowns. Two small competitors fighting each other = both dead. Allied = collectively too big to ignore. |

---

## Phase 1 — Day 0 to Day 14 — Snyk announces

**Probable shape of the announcement:** something like *"Snyk Lite: Free AI security for solo founders. Powered by Evo. Scans your repo for AI-specific vulnerabilities."* Probably bundled with a `snyk vibe` CLI, possibly with a Lovable plugin. Probably gated on email signup.

### Day 0 — the same day

- **Don't panic. Don't tweet first.** Wait 4 hours. Watch how indie Twitter reacts.
- **Read the actual product surface.** Sign up. Install it. Test it on a Lovable app. Find the gaps inside 6 hours.
- **Write a one-page side-by-side** based on real testing — not based on marketing copy. Lictor vs Snyk Lite, on 10 specific dimensions. Concrete examples on each row.
- **Post the side-by-side to the Lictor blog** with a confident headline like *"Snyk Lite is here. Here's exactly what it does — and what Lictor does that it can't."* No bashing. Just specifics.

### Day 1–3 — the contrast post

- **Lead with what's the same.** Snyk Lite is good for some things. Naming the overlap honestly builds trust before the differentiation. *"If you're a developer who already pays for a Snyk plan and needs SCA + SAST, Snyk Lite is a fine add. If you're a solo founder shipping a Lovable app this weekend, here's what Lictor does that Snyk Lite doesn't."*
- **Show the dialect difference live.** Same Lovable app, audited by both. Screenshot of Snyk's compliance-dialect findings next to Lictor's plain-English findings. Side-by-side images travel faster than essays.
- **Demonstrate Snyk's telemetry vs Lictor's local-only.** Run a network monitor during both audits. Show what data leaves each tool's process. This is a one-image moat.
- **Publish the Claude Code experience.** Screenshot of `/lictor-security-check` running inline in Claude Code vs the user having to alt-tab to Snyk's dashboard. Vibe-coders feel this instantly.

### Day 4–14 — the teardown amplification

- **Pick one Snyk-Lite-audited app and re-audit it with Lictor.** Find at least 3 things Snyk Lite missed. Publish the comparison transparently. *"Snyk Lite found 4 issues. Lictor's 11 agents found those + 7 more. Here's what each agent caught."*
- **Get 3 indie hackers to do the same comparison on their own apps and publish.** Don't pay them. Send a Lictor swag pack and an honest *"would love your independent take"* DM. Authentic third-party comparisons compound.
- **Host a public live-audit on Twitch / YouTube** — *"I'm going to audit a random Lovable app with both tools. Live. Comments open."* This is the kind of content Snyk's brand team will never approve.
- **Submit to Hacker News** with a story-shaped angle: not *"Lictor vs Snyk"* (combative) but *"What Snyk's free tier means for indie founders"* (commentary). Be magnanimous in the post; let the comments do the differentiation.

---

## Phase 2 — Day 14 to Day 45 — lock in the position

This is where Lictor either becomes the durable second option or becomes a footnote.

### Tactical moves

| Move | Specific output |
|---|---|
| **Triple down on the weekly teardown** | Pick a different Lovable / Bolt / v0 app every week. By Day 45 you have 6 published teardowns, all indexed under "vibe-coder security." Snyk's marketing engine will not start a weekly teardown series because it would expose specific named apps and create legal headaches at their scale. |
| **Publish the "audit your audit" tool** | A Lictor skill that takes Snyk Lite's JSON output and translates it into plain English. Position it as helpful, not hostile. *"Already using Snyk Lite? Run `lictor explain snyk-output.json` to get the report in human."* Half of indie hackers will try it; some will switch entirely. |
| **Open a public roadmap with community voting** | Snyk's roadmap is closed. Lictor's roadmap is a public GitHub project with vote-up issues. The contrast on this single dimension converts more developers than any feature could. |
| **Run a "found by Lictor, missed by Snyk Lite" leaderboard** | Encourage testers to submit findings Lictor caught and Snyk missed (or vice versa, honestly). Show real numbers. This is the kind of public scoreboard that makes vendors quietly improve their products. You win either way. |
| **Build the Lovable / Bolt integration before Snyk does** | Push a one-click "audit my Lovable project" button into the Lovable / Bolt ecosystem. Approach platform teams as *"we make your platform safer for free."* If Snyk gets there first, you've lost this round. |

### What to **say** on every channel during this phase

Pick a tight messaging frame and repeat it across every surface. Suggested frames (pick ONE, hammer it):

1. **"Snyk Lite is for the team that has 5 developers. Lictor is for the developer who is the team."**
2. **"Your AI built the app. Let our AIs audit it."**
3. **"Same findings, plain English, no signup."**
4. **"Open source security for the open-builder generation."**

I'd pick **#1** because it makes the 5-developer minimum explicit and unforgettable.

---

## Phase 3 — Day 45 to Day 90 — pivot to the moat Snyk can't follow

By Day 45, Snyk Lite has shipped, the initial news cycle is over, and the developer audience has formed opinions. Lictor's Day 90 goal: be the *obvious* second tool every vibe-coder pairs with their primary scanner — even if that primary is Snyk Lite.

### The moves

| Move | Why Snyk can't follow |
|---|---|
| **Launch Lictor for Teams (paid, but cheap) — $19/mo flat for unlimited seats** | Snyk's pricing architecture (per-seat, $25/dev/mo minimum) cannot accommodate flat-rate without burning their enterprise tier's pricing power. Lictor can. Flat rate is a defensible moat at the indie-team tier. |
| **Ship "Lictor Studio" — a desktop app for offline-only audit** | Snyk's product is cloud-attached by design (Evo telemetry, dashboard sync). Lictor can ship a fully-offline `.dmg` / `.exe` that runs the entire crew without ever opening a network socket. Privacy-paranoid devs (a growing segment) will pay for this. |
| **Open the audit-output spec as a community standard** | Propose `AUDIT.json` as a shared output format Lictor, Snyk Lite, VibeEval, and Symbioticsec all emit. Lictor authors the spec. Standards-owners win the long game. |
| **Build the "Lictor crew remix" — let users author their own agents** | Snyk's agents are proprietary modules. Lictor's are SOUL.md markdown files. Let users write their own crew member, share via the Lictor skill registry, vote on the best ones. This becomes a flywheel Snyk's architecture cannot replicate. |
| **Course revenue: "How to ship a vibe-coded app that passes Lictor's audit"** | GenerationAI already exists. Lictor is its security wedge. Course revenue is one of the few revenue streams where being *the* community-ed brand for vibe-coder security is the actual product. Snyk doesn't sell courses; their attempts would feel cynical. |

### Revenue posture by Day 90

You should have:
- 1 paid tier live (Teams flat-rate)
- 2 monetization experiments running (Studio premium, Course)
- A clear public commitment that the OSS Lictor stays free forever (so the community trusts the paid offering)

By Day 90, *"Snyk for the enterprise, Lictor for the builder"* should be a fully-baked split developers articulate on their own without prompting.

---

## What NOT to do — the 3 traps

### Trap 1 — Race them on features
The moment Snyk Lite ships, your inbox will fill with *"why doesn't Lictor have X?"* Resist 90% of those feature requests. Snyk has a 200-person engineering team and a public roadmap that you cannot out-build. Compete on *shape*, not *coverage*. The agent personalities, the plain-English voice, the inline-Claude-Code experience — those are the moat. Adding another scanner check is not.

### Trap 2 — Go enterprise
Three months after Snyk Lite ships, someone will say *"the enterprise market is where the money is — let's also sell to CISOs."* This kills Lictor in 6 months. The moment Lictor's marketing copy starts speaking compliance dialect, the indie-hacker community senses the pivot and abandons you, and the enterprise buyers buy Snyk anyway because Snyk has the brand. Stay in your lane. The vibe-coder market is huge and durable.

### Trap 3 — Match their pricing
The moment Snyk Lite advertises *"free forever for 1 developer"*, the temptation is to match exactly. Don't. Lictor is free forever for everyone (always was), AND the paid Teams tier is a *flat rate*, not per-seat. The differentiation is structural pricing, not bigger free tier. Don't get baited into a free-tier feature race.

---

## Early warning signals — what to monitor

Add these to weekly Mongoose scans / Starling agent feeds:

| Signal | Interpretation |
|---|---|
| Snyk job postings for *"product manager, SMB"* or *"developer experience, individual users"* | High-probability free-tier in 60–120 days |
| Snyk blog posts about *"securing vibe-coded apps"* or *"AI-built application security"* | Imminent — they're warming the keyword |
| `snyk vibe` or `snyk lite` mentioned in Snyk changelog / GitHub | They've shipped a private preview — public launch within 30–60 days |
| Snyk acquires VibeEval / Symbioticsec / a similar small player | Worst-case — they've bought the niche players to shortcut to market |
| Snyk announces a Lovable / Bolt / Cursor partnership | High-threat — they're claiming Lictor's wedge channel |
| Pricing page changes (especially: free tier limits, removal of 5-seat minimum) | Inflection point — react within 7 days |

Set up Mongoose to check the Snyk blog + Snyk pricing page + Snyk GitHub releases page weekly. Any change in those should escalate to the Lictor team within 24h.

---

## Confidence + caveats

- **Snyk's probability of shipping a free vibe-coder tier:** ~70% within 12 months. Driven by (a) market pressure from this exact narrative, (b) their existing agent-scan being already-public, (c) their stated 2026 priority of "developer-first" GTM.
- **Speed at which they could ship:** 60–120 days from internal greenlight. The product surface is essentially Evo + a different marketing wrapper.
- **What this playbook assumes:** Lictor has shipped publicly by then with the vibe-coder positioning live. If Lictor is still pre-launch when Snyk ships free, this playbook needs significant revision — call me back to rewrite.
- **What could change the math fast:** if Anthropic / OpenAI ship native code-audit features in Claude / GPT, both Snyk and Lictor lose distribution overnight. Different playbook entirely.
