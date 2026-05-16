# New specialist agents — Q1 2027 hires

> **Generated:** 2026-05-15
> **Context:** Operation Triumph EXPANDED calls for the agent crew to grow from 11 → 15 in Q1 2027. This doc specifies the 4 new specialists, what they do, when they fire, what they cost, and what's required to bring them online.
> **Implementation surface:** Each new agent gets a workspace at `~/GenerationAI/agents/<name>/` with the standard 5+ injection files (SOUL.md, IDENTITY.md, AGENTS.md, TOOLS.md, USER.md, plus the agent's own memory/ and skills/ subfolders).

---

## Agent 12 — 🌐 Translator (linguistic specialist)

### What this agent does
Renders every Lictor + GenerationAI public artifact into Hebrew, Spanish, Portuguese, and Japanese — the 4 languages with the highest combined value for the bigger market thesis:

- **Hebrew** — Raffa's native language. Authentic-voice content for the Israeli tech ecosystem. Differentiator: nobody else in the AI-security category speaks Hebrew well.
- **Spanish (LATAM dialect)** — biggest growth region for vibe-coder platforms outside the US. Mexico, Argentina, Colombia all hot.
- **Portuguese (BR dialect)** — Brazilian indie-hacker scene is enormous and underserved by English-only tools.
- **Japanese** — Japan has the second-highest concentration of Cursor + Claude Code users per capita (after the US). Notoriously underserved by Western dev tools.

### What this agent does NOT do
- Doesn't auto-translate technical security terms when their English form is canonical (CVE, RLS, OAuth, JWT — these stay in English with a parenthetical first time)
- Doesn't translate Raffa's personal voice content (founder videos, personal tweets) — those stay in English unless Raffa explicitly requests translation
- Doesn't translate teardowns of non-English-language apps without local context (a teardown of a Japanese app should be translated by a native speaker, not the agent)

### Cadence
- **Continuous** — heartbeat every 6 hours
- Pulls from a queue of "to-translate" artifacts populated by Quill / Magnet
- One artifact per heartbeat per language (so 4 outputs per fire if all 4 queues have work)
- Falls back to "no work" state cleanly when queues are empty

### Model recommendation
**Claude Sonnet** — translation quality matters; this isn't filler work. Cheap-model translations of security copy create credibility problems.

### Cost estimate
~$2.50/day at expected volume = ~$75/mo

### Output paths
- `~/GenerationAI/output/translations/<lang>/<original-slug>.md`
- Updates a manifest at `~/Lictor/landing/translations/<lang>/manifest.json` with available pages
- Logs every translation to `~/GenerationAI/agents/translator/memory/YYYY-MM-DD.md`

### Quality gate
Mirror reviews every Friday — spot-checks 3 translations per language for fidelity, tone, technical accuracy. Bad translations get re-flagged for re-translation.

### Inter-agent contracts
- **Reads from:** Quill (writer), Magnet (landing pages), the teardown engine output
- **Writes for:** Mirror (review), dev (landing-site translation manifests)
- **Coordination protocol:** Files on disk. No API calls.

---

## Agent 13 — 🎬 Reel (video-script writer)

### What this agent does
Generates weekly scripts for Raffa's talking-head videos and short-form content. Three formats per week:

- **1 long-form script** (8-12 minutes) — a teardown walkthrough, a security explainer, or a "behind the scenes of the agent crew" piece
- **2 short scripts** (under 60s each) — single-finding teardowns, quick concept explainers, voice-bug callouts ("here's the worst compliance-speak I read this week")

Each script includes: hook (first 3 seconds), beats (3-5 named segments), B-roll cues (what to show on screen), CTA (one specific action).

### What this agent does NOT do
- Doesn't write Raffa's personality — pulls voice from `~/GenerationAI/calibration/dor-voice/` and the previous week's video performance
- Doesn't produce video — it produces scripts that Raffa records
- Doesn't pick the topic — Conductor (planner) assigns the week's video themes from the teardown calendar

### Cadence
- **Weekly heartbeat** — Sundays at 10:00 IST (after Mirror's weekly review so Reel can incorporate what worked last week)
- Outputs 3 scripts per fire

### Model recommendation
**Claude Sonnet** — script writing benefits from quality. Cheap models produce stiff hooks.

### Cost estimate
~$1/week per script × 3 scripts/week = ~$13/mo

### Output paths
- `~/GenerationAI/output/scripts/YYYY-Www-{long|short1|short2}.md`
- Memory entry: `~/GenerationAI/agents/reel/memory/YYYY-MM-DD.md`

### Inter-agent contracts
- **Reads from:** Quill's teardown drafts, Trends' viral-format intel, Pulse's hook formulas, Mirror's last-week performance review
- **Writes for:** Raffa (recording), Conductor (Friday brief)
- **Coordination protocol:** Files on disk

### Special handling
Reel maintains a "what's hitting" file — `~/GenerationAI/output/video-performance.jsonl` — fed by Raffa weekly with view counts and engagement metrics from past videos. This is the feedback loop. Without it, Reel optimizes blind.

---

## Agent 14 — 🎙️ Booth (podcast booker + conference scout)

### What this agent does
Two jobs:

**Job 1 — Podcast booking.** Identifies 5 podcasts per week that:
- Booked guests in the AI security / dev tools / OSS founder space in the last 3 months
- Have an audience that includes vibe-coders or indie hackers
- Are still actively publishing (last episode within 30 days)

Drafts a personalized cold outreach email for each. Includes: a specific reference to a recent episode, the angle Raffa would bring, a 1-line pitch for the host's audience. Saves drafts to `~/GenerationAI/output/outreach/podcasts/`.

**Job 2 — Conference CFP scouting.** Weekly digest of:
- Open CFPs for AI / security / OSS / developer-tool conferences worldwide
- Filter for: 2027 events, in-person or hybrid (not pure online), CFP deadline within next 90 days
- Match against Raffa's pitch repertoire (teardown findings, agent crew demo, plain-English-security thesis)

Output: a Markdown digest at `~/GenerationAI/output/conferences/YYYY-MM-DD-cfp-digest.md`.

### What this agent does NOT do
- Doesn't send emails (only drafts)
- Doesn't apply to CFPs (only flags)
- Doesn't engage with the booked hosts after Raffa accepts a podcast — that's Raffa's job

### Cadence
- **Weekly heartbeat** — Mondays at 09:00 IST

### Model recommendation
**Claude Haiku** — this is volume + recall work, not creative. Cheap model is the right call.

### Cost estimate
~$0.50/week = ~$2/mo. The cheapest agent on the crew.

### Output paths
- `~/GenerationAI/output/outreach/podcasts/YYYY-Www/<podcast-name>.md` (5 per week)
- `~/GenerationAI/output/conferences/YYYY-Www-cfp-digest.md` (1 per week)
- Memory: `~/GenerationAI/agents/booth/memory/YYYY-MM-DD.md`

### Inter-agent contracts
- **Reads from:** Trends (what's hot this week in the dev tool space), Probe (recent competitive moves that make for relevant pitch angles), Conductor's briefings
- **Writes for:** Raffa (review + send)

### Special handling
Booth maintains a `~/GenerationAI/output/outreach/sent-podcasts.jsonl` log of what got sent vs ignored. After 6 weeks of data, Booth starts ranking which outreach patterns convert better. This is the long-game asymmetry.

---

## Agent 15 — 🤝 Bridge (community manager + GitHub triage)

### What this agent does
Continuously triages incoming GitHub activity on the `lictor` repo. Three jobs:

**Job 1 — Issue triage.** Every 4h heartbeat, fetches new issues + PRs. For each:
- Label appropriately (bug, feature-request, pattern-request, false-positive, false-negative, voice-bug, etc.)
- Draft a first-response (welcoming + asking for the missing repro info if needed)
- Escalate to Raffa or dev only if the issue is non-trivial (security advisory, breaking change, architectural decision)

**Job 2 — Contributor welcome.** First-time contributors get a personalized welcome comment on their first PR. Includes: thanks, a link to CONTRIBUTING.md, and a "your PR will be reviewed within 48h" expectation.

**Job 3 — Weekly user spotlight.** Every Friday, find one cool thing a community user did with Lictor (a custom check, a creative use case, a teardown they ran themselves). Draft a 1-paragraph spotlight post that Quill polishes for the weekly newsletter.

### What this agent does NOT do
- Doesn't merge PRs (escalates to dev)
- Doesn't close issues without explicit Raffa approval
- Doesn't respond to anything that looks like a security disclosure — escalates immediately to security@lictorai.com

### Cadence
- **Heartbeat every 4 hours** for triage and welcomes
- **Weekly digest Fridays at 14:00 IST** for the user spotlight

### Model recommendation
**Claude Sonnet** — community-facing voice matters. Cheap models produce robotic-sounding responses that damage the OSS community feel.

### Cost estimate
~$0.80/day = ~$24/mo

### Output paths
- Triage actions: direct GitHub API writes (label + comment)
- Memory: `~/GenerationAI/agents/bridge/memory/YYYY-MM-DD.md`
- Weekly spotlight draft: `~/GenerationAI/output/spotlights/YYYY-Www-spotlight.md`

### Inter-agent contracts
- **Reads from:** GitHub API (issues, PRs, contributors)
- **Writes for:** Quill (spotlight draft), dev (escalated triages), Conductor (weekly issue volume metrics)

### Special handling
Bridge needs a GitHub Personal Access Token with `repo` + `issues` scope, stored in `~/.openclaw/secrets/github-bridge.token`. Set up before the agent comes online.

Bridge respects a `do-not-respond.txt` file at the repo root — any issue authors listed there get human-only review (used for known harassers or hostile actors).

---

## Cost summary (all 4 new agents)

| Agent | Monthly inference cost |
|---|---|
| Translator | ~$75 |
| Reel | ~$13 |
| Booth | ~$2 |
| Bridge | ~$24 |
| **Total** | **~$114/mo** |

Within the Q1 2027 revenue assumptions of $10-11k MRR. ~1% of expected revenue.

---

## When to bring each online

| Agent | Bring online when... |
|---|---|
| **Bridge** | Repo flipped public + first 10 community issues filed. ~Oct 13, 2026. |
| **Reel** | Raffa commits to weekly video cadence + the founder channel pilot succeeds. ~Nov 1, 2026. |
| **Translator** | First Spanish + Portuguese landing pages ship (Q4 2026). ~Dec 1, 2026. |
| **Booth** | Raffa has bandwidth for 2-3 podcasts/month + Reel is producing reliably. ~Jan 15, 2027. |

Don't bring them all online at once. Each new agent adds operational surface area. Sequence based on user-facing demand, not on the strategic plan calendar.

---

## Implementation checklist (per agent)

For each agent, when bringing online:

- [ ] Create workspace at `~/GenerationAI/agents/<name>/`
- [ ] Write SOUL.md (mission, voice, output format, operating principles from `_reference/openclaw-prompts.md`)
- [ ] Write IDENTITY.md (name, theme, emoji)
- [ ] Write AGENTS.md (relationships with other agents)
- [ ] Write TOOLS.md (which skills + APIs)
- [ ] Write USER.md (Raffa's context for this agent's domain)
- [ ] Add to openclaw.json agent registry
- [ ] Add cron heartbeat in `~/GenerationAI/scripts/genai.crontab` (don't forget Referer header)
- [ ] Add to Mission Control's /api/run VALID_AGENTS whitelist
- [ ] Mirror reviews the agent's output for 2 weeks before the agent runs unsupervised
- [ ] Document any new tokens / API keys in `~/.openclaw/secrets/`
- [ ] Add to monitoring (mission-control office view)
