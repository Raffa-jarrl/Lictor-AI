# Lictor Scan + Lictor Patrol — combined v0.1 spec

> **Status:** spec, May 15 2026. Build start: Jun 1. Pilot scan: Jun 8 (last-7-days cohort). Soft launch: Aug 15 with the 30-day finding report. Hard launch: Oct 6 alongside the rest of the suite.
> **Scope:** This doc covers (1) **Lictor Scan** — the public paste-a-URL surface — and (2) **Lictor Patrol** — the autonomous engine that scans every new public vibe-coder asset and feeds Scan. They ship together because they only make sense together.

---

## TL;DR

**Lictor Scan** is `lictor.ai/scan/<url>` — paste any vibe-coded app's URL, get a letter-grade scorecard with the 5 worst findings, share the result. PageSpeed Insights for AI-built apps.

**Lictor Patrol** is the cron-driven crawler that enumerates every new vibe-coder app that hit the public internet in the last N days, runs Scan on each, and — when it finds something serious — has Bridge agent draft a private heads-up to the founder ("Lictor AI found this in your app — here's the fix; the tool's free if you want continuous monitoring").

**Pilot week target:** last 7 days only (~500-1,000 assets). Validate the playbook with a manageable cohort. **Then expand to last 30 days.**

---

## Pilot — Week of Jun 8

Tight scope so we can hand-review every outreach.

### Pilot intake (target: 500-1,000 assets)

| Source | 7-day expected | Notes |
|---|---|---|
| GitHub repos with `lovable` / `bolt-new` / `v0` / `cursor` topic, created in last 7d | 100-400 | Use Search API `created:>YYYY-MM-DD topic:lovable` |
| Lovable showcase weekly delta | 50-100 | Scrape `lovable.app/showcase`; diff vs last week's snapshot |
| Bolt featured templates last 7d | 10-30 | Scrape `bolt.new/templates?sort=new` |
| v0 community new last 7d | 30-80 | Scrape `v0.dev/community` |
| Product Hunt AI / No-Code launches last 7d | 30-60 | API `launched_after` filter |
| Show HN posts mentioning Lovable/Bolt/v0 last 7d | 5-15 | Algolia API |
| Hand-picked YC W26 / S26 / F26 launches | 20-40 | YC API |

### Pilot success criteria

| Metric | Pilot target (Week 1) | Kill |
|---|---|---|
| Apps scanned successfully | ≥400 | <100 = engine isn't ready |
| Apps with at least one HIGH/CRITICAL finding | ≥30% | <10% = our checks aren't tuned for the platforms |
| Private outreach sent | ≥50 | <20 = our prioritization is too conservative |
| Founder responses within 7 days | ≥10% of outreach | <3% = the outreach voice is wrong |
| Reported bug actually fixed within 30d | ≥60% of responses | <30% = we're nagging without value |
| Zero public backlash or legal complaints | yes | one credible complaint = stop and rethink |

If we hit these, expand to last-30-days for Week 2. If we miss them, post-mortem with Mirror before doing anything else.

---

## How the engine works

```
            ┌────────────────────────────────────────┐
            │  CRON every 6h (extends to 1h post-launch) │
            └────────────────┬───────────────────────┘
                             ▼
                ┌────────────────────────┐
                │ Source Enumerators (10)│ ← Patrol agent ownership
                │ GitHub / PH / HN / YC  │
                │ Lovable / Bolt / v0 /  │
                │ Cursor / npm / Twitter │
                └────────────┬───────────┘
                             ▼
                ┌────────────────────────┐
                │ Dedup + queue          │
                │ (Cloudflare Workers KV)│
                └────────────┬───────────┘
                             ▼
                ┌────────────────────────┐
                │ Lictor Scan engine     │ ← lictor-core compiled to WASM,
                │ (Cloudflare Worker)    │   deployed as Worker
                │ 7 checks per URL       │
                │ ~5-15 sec per scan     │
                └────────────┬───────────┘
                             ▼
            ┌────────────────┴────────────────┐
            ▼                                 ▼
   ┌────────────────┐                ┌─────────────────┐
   │ Audit Corpus   │                │ Severity Router │
   │ (KV append-only)│               │ A/B → public    │
   │ Fingerprints   │                │ C/D/F → gated   │
   └────────────────┘                └────────┬────────┘
                                              ▼
                                ┌─────────────────────────┐
                                │ Disclosure State Machine│
                                │ - private 30 days       │
                                │ - aggregate-only public │
                                │ - opt-out anytime       │
                                └─────────┬───────────────┘
                                          ▼
                              ┌─────────────────────────┐
                              │ Bridge Outreach Drafting│ ← Bridge agent
                              │ Personalized, with name │
                              │ + finding + fix + offer │
                              └─────────┬───────────────┘
                                        ▼
                              ┌─────────────────────────┐
                              │ Dor reviews → Sends     │
                              │ (Week 1-4 manual; later │
                              │ Bridge auto-sends low-  │
                              │ risk classes)           │
                              └─────────┬───────────────┘
                                        ▼
                              ┌─────────────────────────┐
                              │ Response tracking +     │
                              │ Audit corpus enrichment │
                              └─────────────────────────┘
```

---

## The outreach voice

Every outreach is signed `— Bridge (Lictor's community agent) · lictor.ai`. Honest about being an AI agent, honest about the finding, honest about the offer.

### Template — HIGH severity, individual founder

> Subject: Heads-up — Lictor AI found a security issue in [appname]
>
> Hi [name],
>
> I'm Bridge, the community agent for Lictor AI — an open-source security audit tool for AI-built apps. We're an Apache 2.0 project run by Dor, a 20-year cybersecurity engineer.
>
> Our scanner picked up your project ([url]) earlier this week and flagged one issue we thought you'd want to know about before anyone else does:
>
> **🟠 HIGH — [one-sentence plain-English description]**
>
> Specifically: [the finding, with line numbers / URL paths / specific evidence — no jargon]
>
> What can go wrong: [1-2 sentences, concrete consequence]
>
> Fix (about [N] minutes): [3-5 concrete steps, with code snippets where helpful]
>
> No catch on this — we're flagging it because we'd want the same heads-up if someone found it in our code. The scanner that found this is free and open source: `npm install -g lictor-cli` (or paste your URL at lictor.ai/scan).
>
> If you'd like Lictor to keep watching this project as you add features — we DM you when new issues appear, weekly summary email, that kind of thing — it's free for OSS / hobby / pre-revenue projects, and $19/mo flat for commercial use (no per-seat). Up to you, no pressure.
>
> One ask: if you fix it within 30 days, your scorecard stays private. If 30 days pass and the finding's still live, it goes on our public weekly aggregate (anonymized counts only, never your name or URL without your consent).
>
> Happy to answer anything.
>
> — Bridge (Lictor's community agent) · lictor.ai
> Co-signed by Dor on outreach reviewed personally in pilot weeks.

### Template — CRITICAL severity, escalated to Dor

Drops the AI-agent framing. Dor writes personally. Bridge prepares the draft + the finding + the fix; Dor sends from his email. CRITICAL findings are the moment to be a human, not an agent.

### Template — aggregate weekly report (always public, never names individuals)

> *"In the week of [date range], Lictor Patrol scanned [N] new vibe-coder apps across Lovable, Bolt, v0, Cursor, and Replit. We found:*
>
> *- 47% had a publicly readable Supabase service-role key in their JS bundle*
> *- 31% had at least one /api/* route returning user data with no auth check*
> *- 22% had Stripe webhook handlers with no signature verification*
> *- 14% had at least one of the above AND were already taking real money*
>
> *We contacted every affected founder privately with specifics + fixes. [N]% have responded so far; [N]% have shipped the fix. We're publishing aggregate counts because vibe-coders deserve to know what's happening in their ecosystem. We're publishing individual scorecards only when (a) the founder consents or (b) 30 days have passed with the finding still live."*

---

## Ethical guardrails — non-negotiable

These are in the spec because they're load-bearing for the project's existence, not because they're nice-to-haves.

| Rule | Why | Mechanism |
|---|---|---|
| Only scan publicly accessible URLs | Authenticated content is off-limits | Engine refuses any 401/403/auth-redirected URL |
| Respect `robots.txt` + `/.well-known/security.txt` | Industry-standard | Workers check before scanning |
| Rate-limit aggressively per origin | Never DoS a founder's site | Max 1 scan per origin per 24h |
| 30-day private disclosure window for individuals | Solo founders are not Equifax | State machine enforces, can't be overridden |
| 90-day window for companies ≥10 employees / VC-backed | Industry-standard responsible disclosure | Manual classification flag |
| Aggregate stats public immediately; individual scorecards gated | Press value without weaponizing scorecards | Severity router separates the two paths |
| One-click opt-out at `lictor.ai/scan/<hash>/remove` | Bridge processes within 24h | Standard form → Bridge queue |
| We scan ourselves first, publicly, before launching Patrol | Modeling the behavior we expect | Aug 1: `lictor.ai/scan/lictor.ai` published |
| No facial / personal-data scraping | Out of scope, in tension with security purpose | Engineering constraint — checks are URL+JS+headers only |
| Audit corpus stores fingerprints, never raw findings | Privacy by design | Hash: SHA-256(finding-type + severity + platform), no URL |

If we discover Patrol is being used in a way that violates these, **we stop Patrol and write publicly about what happened.** That's the contract.

---

## The scoring rubric — how 7 checks become a letter grade

Letter grades because nobody understands CVSS. Mapping:

| Grade | Meaning | Conditions |
|---|---|---|
| **A** | Clean | Zero HIGH/CRITICAL findings; ≤2 MEDIUM |
| **B** | Solid | Zero CRITICAL; ≤1 HIGH; ≤4 MEDIUM |
| **C** | Concerns | Zero CRITICAL; ≤3 HIGH; OR ≥5 MEDIUM |
| **D** | Trouble | 1 CRITICAL OR ≥4 HIGH |
| **F** | Don't ship | ≥2 CRITICAL OR ≥6 HIGH |

**Anti-gaming protection:** the rubric is published, but specific check weights and the order they run are not. A bad actor cannot trivially game an A by hiding specific findings — Lictor's check engine evolves quarterly, and grades from older check engines remain visible on historical scorecards (with a "scanned by Lictor v0.X" timestamp).

**Re-scoring:** when a founder fixes their findings and clicks "rerun scan," the new score replaces the old one but the timeline of grades stays on the public scorecard (if public). The dopamine loop is watching `D → C → B → A` in your own scorecard's history graph.

---

## Audit corpus — the moat

Every Patrol scan + every user-initiated Scan stores **one row** in append-only Cloudflare Workers KV:

```json
{
  "scan_id": "sha256(url+timestamp)",
  "timestamp": "2026-06-08T14:23:00Z",
  "platform_fingerprint": "lovable+supabase+stripe",
  "findings": [
    {"check": "secrets:supabase-service-role", "severity": "critical", "confidence": "high"},
    {"check": "auth:unprotected-api", "severity": "high", "confidence": "medium"},
    ...
  ],
  "grade": "D",
  "scanner_version": "lictor-core@0.4.2"
}
```

**No URL, no app name, no founder email** — that's stored in a separate, access-controlled outreach store.

The corpus IS the moat. Within 12 months at projected scan rates, Lictor will have:

- The largest known public dataset of vibe-coder app security postures (≥200,000 fingerprints)
- Trend lines for which checks fail most on which platforms — feeding back into check tuning
- A defensible research artifact: a peer-reviewable paper at end of Year 1 ("The Vibe-Coder Security Landscape: 200K Apps Scanned"). The kind of artifact that ends up cited by Gartner, Forrester, every "state of AI security" report from 2027 onward.

---

## Build plan — 5 weeks from Jun 1

| Week | What ships | Owner |
|---|---|---|
| **W22 (Jun 1-7)** | Source enumerators (GitHub, Lovable, Bolt, v0, PH, HN) — 6 of 10. Cron + dedup + queue. Scan engine deployed as Worker. | dev (C-3PO) builds; Conductor wires cron |
| **W23 (Jun 8-14)** | **PILOT SCAN WEEK** — last-7-days cohort, 500-1,000 assets. Manual review of every outreach. | All hands: Dor reviews findings, Bridge drafts outreach, Mirror watches voice |
| **W24 (Jun 15-21)** | Disclosure state machine + opt-out flow + scorecard page + OG image renderer | dev + designer (you, with the new design-system spec) |
| **W25 (Jun 22-28)** | Audit corpus (KV append-only) + aggregate-stats dashboard at `lictor.ai/in-the-wild` (gated, internal only at first) | dev + Conductor for stats aggregation |
| **W26 (Jun 29 - Jul 5)** | Expand to last-30-days cohort. Add remaining 4 sources (YC, Cursor, npm, Twitter/X). | Probe (already does competitive watch) extends to general patrol |
| **W27 (Jul 6-12)** | Public Scan surface goes live at `lictor.ai/scan/<url>` — paste-a-URL form. Embeddable badge ready. | dev + Quill for the launch copy |
| **W28 (Jul 13-19)** | Bridge auto-sends low-risk outreach (B/C grades); Dor still reviews D/F manually. Leaderboard v0.1 published (one platform: Lovable). | Bridge gets auto-send permission for low-risk classes only |
| **W29-W32 (Jul 20 - Aug 15)** | **Silent run for 30 days.** Collect data, refine voice, hand-write everything, measure. No public announcement yet. | All agents in production mode |
| **Aug 15** | **SOFT LAUNCH:** publish the 30-day finding report. HN post. Twitter thread. Press emails. | Quill drafts; Dor sends; Bridge handles the deluge |
| **Aug 16 - Oct 6** | Compound on the soft-launch attention. Weekly leaderboard reports. Lovable / Bolt / v0 integration outreach (the AUDIT.json adoption play, suddenly easy because we have proof). | Booth pivots to platform integration outreach |
| **Oct 6** | **HARD LAUNCH:** the rest of the suite (Studio, CLI, full crew, SDK, Guardian). By now everyone already knows what Lictor IS. | Coordinated multi-channel launch |

---

## What goes ON the Q3 roadmap

| Date | Item | Outcome target | Kill |
|---|---|---|---|
| Jun 1 | Patrol architecture deployed | Cron firing; first 100 URLs scanned | Engine fails on >30% of URLs |
| Jun 8 | Pilot scan (last 7 days) | 500-1,000 apps scanned, 50+ private outreaches sent | <100 apps scanned |
| Jun 15 | Disclosure state machine live | 30-day timer running on every D/F finding | Any leak of private finding before window |
| Jul 6 | `lictor.ai/scan` public surface live | 100 user-initiated scans in first week | <10 |
| Jul 15 | Last-30-days Patrol running | 4,000-6,000 apps scanned cumulative | <1,500 |
| Aug 15 | Soft-launch publication | 30,000 apps scanned; HN front page; ≥3 inbound press | <10,000 scanned, no HN traction |
| Oct 6 | Hard launch with full suite | The rest of the OSS suite, on the back of Patrol's credibility | — |

---

## What comes OFF the Q3/Q4 roadmap to make room

| Cut / defer | Why | Replacement |
|---|---|---|
| Lictor Studio v0.1 (was Dec 31) → defer to Q1 2027 | Local desktop is a worse magnet than a public scanner. Studio still ships, just later. | Patrol takes Studio's launch slot. |
| 3 cornerstone blog posts → cut to 1 | Patrol auto-generates content (weekly reports). One launch essay beats 3 evergreens. | Weekly Patrol report = the content engine. |
| 12 weekly teardowns → cut to 10, automate the rest | Teardowns become Patrol byproducts — when a high-profile app scores F, its scorecard IS the teardown. | Patrol replaces ~2 manual teardowns per quarter. |
| "First 5 founder videos by Jun 1" → 2 videos | One on what Lictor is, one explaining a Patrol finding. Reel agent picks up the cadence in Nov anyway. | — |

Net new effort: ~5 weeks of build. Net cuts: ~8 weeks of stuff that compounds less. **Patrol replaces inferior surfaces; it doesn't add to the workload.**

---

## Risks and what we do about them

| Risk | Likelihood | Mitigation |
|---|---|---|
| Lovable / Bolt / v0 block our scraping | medium | Have a backup: offer them the scoring service as a publish-flow integration in exchange for an app-index API. Already aligned with AUDIT.json adoption play. |
| Twitter scraping is brittle / breaks | high | Low priority. Drop it if it costs us more than 2 days of maintenance per month. |
| A high-profile founder publicly attacks us | medium-high | Mitigations: 30-day private window prevents the worst version; Bridge voice is rigorously friendly; we scan ourselves first on Aug 1 publicly to model behavior; one-click opt-out exists. |
| Legal complaint from a company | low | Public-info scanning is well-established (Shodan, Censys, HIBP, SSL Labs, Lighthouse). Legal-structure-memo needs a Patrol-specific addendum. |
| Bridge sends an outreach that's tone-deaf or wrong | medium (pilot weeks), low (after voice is dialed) | Manual review in pilot. Mirror reviews all outreach in weeks 1-4. Bridge gets auto-send permission only after voice is stable. |
| Scan engine produces a false positive that we publish | medium | False positives are part of the model. We publish corrections immediately on the same surface. The Bridge outreach script literally says "if you think this is a false positive, reply and we'll re-examine." |
| Cloudflare Worker costs balloon | very low | At 50K scans/mo: ~$30. At 500K scans/mo: ~$300. Trivial. |
| We get acquired faster than we expected because Patrol is too good | this would be a good problem | We have the acquirer deck. We have the foundation governance plan. We have leverage because the OSS core can't be unforked. Proceed normally. |

---

## What this becomes by end of Year 1

If Patrol runs from Jun 8 → May 15 2027 at projected rates:

- **~200,000 vibe-coder apps scanned**
- **~20,000 private founder outreaches sent**
- **~6,000 confirmed fixes shipped because of our outreach**
- **~50,000 public scorecards live** (founders who consented OR aged out of the 30-day window)
- **~2,500 weekly returning users on `lictor.ai/scan`** (paste-a-URL surface)
- **The largest public dataset of AI-app security postures in existence** — the moat
- **Lovable / Bolt / v0 integrated `lictor.ai/scan` into their publish flow** (at least 1 of 3 — the AUDIT.json adoption play, fully landed)
- **3-5 inbound acquirer conversations** (because by then "what's your Lictor score?" is a real question developers ask)
- **The Year 1 paper:** "The Vibe-Coder Security Landscape: 200,000 Apps Scanned" — peer reviewed, cited everywhere

That's not a roadmap item. That's a category-defining position.

---

## One sentence summary, for everyone who skims

**Patrol is how Lictor stops asking vibe-coders to come find us and starts going to them with a specific finding under our name — politely, privately first, with the fix in hand and the free tool sitting next to it.**

That's the move. That's the land everyone is leaving open.
