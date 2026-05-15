# AUDIT.json v0.1 — adoption outreach

> Generated: 2026-05-15. Send timing: Q4 2026 (after launch + the spec proves usable in production via Lictor's own teardowns).
> Drafts are ready to personalize + send. Per the legal-structure memo, Dor signs from a Lictor LLC email once that exists.
> Each draft is written in the **collaborative-not-competitive** voice — we're proposing a standard, not announcing one we control.

---

## Strategic posture

The pitch is NOT "adopt Lictor's spec." The pitch is:

> *"Security tools all emit findings in incompatible formats. Every developer who runs more than one tool eats this tax. We drafted v0.1 of a shared format under CC0 — your team is the one we'd most want to read it before v1.0. If you see fit, co-author. If not, fork. Either way, the spec gets stronger."*

Five companies receive the draft (in order of likelihood of engagement):

1. **Semgrep** — OSS-friendly culture, founders care about developer ergonomics, likely to engage substantively
2. **VibeEval** — small + aligned target audience, low coordination cost
3. **Symbioticsec** — same as VibeEval
4. **Aikido Security** — commercial but founder-friendly, has shipped real AI-security tooling
5. **Snyk** — biggest validation if they engage; lowest probability of engagement

Don't email all 5 simultaneously. Sequence over 2-3 weeks so each conversation has air.

---

## Email 1 — Semgrep

**To:** `[FILL: Semgrep's OSS / community lead — likely findable via their team page or Slack community]`
**CC:** `[FILL: Dor's lawyer if Semgrep responds positively and a co-authorship discussion starts]`
**Subject:** Draft v0.1 of a shared AUDIT.json format — would Semgrep want to read it?

```
Hi [NAME],

I'm Dor — 20-year cybersec engineer building Lictor, an OSS security audit tool
specifically for AI-built apps (Lovable / Bolt / v0 / Cursor / Replit). We
launched October 6.

Quick reason for this email: I've been frustrated for a year about every
security tool emitting findings in its own incompatible format. A team running
Semgrep + Trivy + npm audit + a custom scanner ends up writing 4 different
parsers. The community has flirted with SARIF for years but it's heavy + IBM-y
+ doesn't model the AI-built-app patterns we increasingly need.

I drafted v0.1 of a lighter format called AUDIT.json — CC0, no Lictor branding
anywhere in the spec, no commercial entanglement. The full spec + the JSON
Schema are at:

  https://github.com/Raffa-jarrl/Lictor-AI/blob/main/docs/standards/AUDIT.json.md
  https://github.com/Raffa-jarrl/Lictor-AI/blob/main/docs/standards/AUDIT.schema.json

Why I'm writing to Semgrep specifically: your team has the strongest taste for
developer ergonomics in the security-tool space. The way Semgrep emits findings
already gets ~80% of what I'd want from a shared spec. If we coordinated on the
remaining 20%, I think we could push the rest of the ecosystem forward.

What I'd love (in descending order of ask):

1. A read by someone on your team. Honest feedback. If it's a bad idea, I want
   to know before more tools build against it.

2. If you see fit, co-authorship on v0.2 — your name + Lictor's on the spec,
   roughly equal weight. We coordinate on what changes between v0.1 and v0.2.
   Semgrep gets to shape the schema before commercial adoption locks in.

3. (Stretch) Semgrep emits AUDIT.json alongside its native format as an option.
   No exclusivity, no marketing claim, just a `--format audit-json` flag.

None of this requires any Lictor dependency on Semgrep's side — the spec is
plain JSON, Lictor isn't in the loop, the schema lives in a CC0 repo.

If this is interesting, happy to chat. 30 min, no agenda beyond a real read.

If it's not — also fine. I appreciate the considered no.

— Dor

[Lictor signature block — repo, lictor.ai, security@]

P.S. If you want context on Lictor before deciding whether to engage, the
audit-our-own-audit protocol page is the most representative thing we've
published. Same dispositionsl as Semgrep's own approach to false positives —
log them in public, fix them in public.
```

**Why this works for Semgrep specifically:** acknowledges their developer-ergonomics taste, doesn't ask for marketing favors, offers real architectural authorship. Semgrep founders (and the broader r2c team) respond best to high-context technical proposals from people who clearly read their work.

---

## Email 2 — VibeEval

**To:** `[FILL: VibeEval founder email — found via vibe-eval.com/contact or their LinkedIn]`
**Subject:** Quick collab idea — shared findings format across vibe-coder security tools

```
Hi [NAME],

I'm Dor — building Lictor (open-source security audit for vibe-coded apps,
launched October 6 — github.com/Raffa-jarrl/Lictor-AI). I've been a quiet admirer
of VibeEval's vibe-coding-security work since the Feb 2026 Lovable report.

Quick collab idea: I drafted a CC0 spec for security tool output called
AUDIT.json (v0.1). Lictor and VibeEval both surface findings about
vibe-coded apps; right now they're in totally different shapes and a builder
using both has to context-switch.

If we both emit AUDIT.json:
- The same finding-renderer UI works for both
- Cross-tool dedup becomes possible
- A community-built dashboard can ingest from either tool
- The next 5 vibe-coder security tools that show up have a default format to
  adopt instead of inventing their own

Spec is at:
  https://github.com/Raffa-jarrl/Lictor-AI/blob/main/docs/standards/AUDIT.json.md

It's deliberately small (8 fields per finding). Easy to emit. Easy to consume.

What I'd love:

1. A read + feedback. Where would VibeEval's findings not fit the schema as
   currently drafted? I'd rather adjust v0.2 than have you fork.

2. If you see fit, co-authorship on v0.2 — your name alongside Lictor's.

3. (Stretch goal) Both of us emit AUDIT.json alongside our native formats
   starting Q1 2027. Both link to the spec from our docs.

No competition framing here — we're targeting overlapping audiences but our
products serve different use cases. The standard helps both of us more than
it helps any single tool.

Quick 20-min chat?

— Dor

[signature]

P.S. I've been linking to your Feb 2026 Lovable security report in my own
content for months — credit where due. The detail in that report is the bar
this whole category should be measured against.
```

**Why this works for VibeEval:** acknowledges them by name, opens with collaboration not competition, ends with sincere credit. Small companies value genuine engagement disproportionately.

---

## Email 3 — Symbioticsec

**To:** `[FILL: Symbioticsec contact, found via symbioticsec.ai]`
**Subject:** AUDIT.json spec — would Symbioticsec want to co-author v0.2?

```
Hi [NAME],

I'm Dor — building Lictor (open-source AI security audit tool, launched
October 6 — github.com/Raffa-jarrl/Lictor-AI). I've been following Symbioticsec's
Lovable scanner work; you're one of the very few teams shipping
vibe-coder-specific security tooling.

Quick proposal: I drafted v0.1 of a shared output format for security tools —
called AUDIT.json — and put it under CC0 so no single vendor owns it.

  https://github.com/Raffa-jarrl/Lictor-AI/blob/main/docs/standards/AUDIT.json.md
  https://github.com/Raffa-jarrl/Lictor-AI/blob/main/docs/standards/AUDIT.schema.json

The motivation: every developer running >1 security tool eats a parser tax
today. If Symbioticsec + Lictor + a handful of other vibe-coder-focused tools
emit a shared format, we collectively make the ecosystem better — and
indirectly make our individual tools more useful (your output feeds into
dashboards / IDE plugins / aggregators that ingest the shared format).

The ask:

1. A read. Feedback on where the schema doesn't fit your tool's output.
2. If you see fit, your name on v0.2 as co-author.
3. (Stretch) Symbioticsec emits AUDIT.json alongside the native format
   sometime in Q1 2027.

No exclusivity, no Lictor branding in the spec, no lock-in. Plain JSON, CC0.

Worth a 15-min call? Happy to talk on any platform.

— Dor

[signature]
```

**Note:** keep this one short. Symbioticsec is a smaller player; long emails feel like spam.

---

## Email 4 — Aikido Security

**To:** `[FILL: Aikido founder team, via aikido.dev/contact or LinkedIn]`
**Subject:** AUDIT.json spec — Aikido perspective would shape v0.2 meaningfully

```
Hi [NAME],

I'm Dor — 20-year cybersec engineer, building Lictor (OSS security audit for
vibe-coded apps; launched October 6 — github.com/Raffa-jarrl/Lictor-AI).

Aikido's approach to AI-first security tooling has been one of the references
I look at when calibrating my own thinking. The 95% noise-reduction claim,
the autonomous pentesting agents — these are the right primitives for the
category.

Quick proposal: I drafted v0.1 of a shared output format called AUDIT.json
(CC0, no Lictor branding, no commercial entanglement). Spec at:

  https://github.com/Raffa-jarrl/Lictor-AI/blob/main/docs/standards/AUDIT.json.md

The case for Aikido caring: your customers run more than just Aikido. They
also run dependency scanners, secret scanners, sometimes ad-hoc Semgrep runs.
Each tool emits its own format. If a shared format exists, your Aikido
customers can ingest non-Aikido findings into Aikido's UI (and vice versa) —
without complex per-tool adapters.

There's also a Snyk angle: Snyk is unlikely to adopt unless multiple
mid-market AI-security vendors do first. Aikido + Lictor + Semgrep would
pressure them in a way none of us could alone.

What I'd love:

1. A read + honest feedback. Specifically: where does the schema fail to
   represent Aikido findings well?

2. Co-authorship on v0.2 (your name on the spec, roughly equal weight).

3. (Stretch) Aikido emits AUDIT.json alongside its native format starting
   Q2 2027. We coordinate the announcement.

Aikido has the commercial reach Lictor doesn't. If we agreed on a spec, we'd
both get to grow the category without competing on the format layer.

Quick chat?

— Dor

[signature]

P.S. I'd love to read whatever's been published internally about Aikido's
schema choices. If there's anything you can share, even informally, it
would directly improve the v0.2 draft.
```

**Why this works for Aikido:** acknowledges their commercial position (instead of pretending we're equals), names the Snyk angle (giving them a strategic reason to engage), asks for their schema knowledge (flatters expertise + gets real info).

---

## Email 5 — Snyk

**To:** `[FILL: Snyk OSS / community / standards lead — research via LinkedIn for someone who's a known OSS voice at Snyk]`
**Subject:** AUDIT.json — Snyk would shape this more than anyone else

```
Hi [NAME],

I'm Dor — building Lictor, an OSS AI-security audit tool that launched October
6 (github.com/Raffa-jarrl/Lictor-AI). I'm writing because Snyk has shaped my
thinking on what good security tooling looks like for the last 5 years, and
because Snyk's adoption (or thoughtful rejection) of a draft I've shipped
would shape it more than anyone else's.

The draft: AUDIT.json v0.1. CC0, no Lictor branding, no commercial
entanglement. Lightweight alternative to SARIF for tools that find security
issues in code or deployed services.

  https://github.com/Raffa-jarrl/Lictor-AI/blob/main/docs/standards/AUDIT.json.md
  https://github.com/Raffa-jarrl/Lictor-AI/blob/main/docs/standards/AUDIT.schema.json

I'm under no illusion about Snyk's adoption probability — you have SARIF
support, you have your own internal format, you have customers paying for
exactly that shape. So this email isn't a "please adopt" email. It's a "would
your team read v0.1 and tell me what's wrong with it before v0.2" email.

Three specific reads I'd most value:

1. Where does the schema fail to model what Snyk's Code Scanning produces?
   (This is the gap that would prevent practical adoption later.)

2. The agent_attributions field — Snyk Agent Security has its own multi-agent
   architecture; how does the field shape compare to your internal model?

3. The audit-our-own-audit protocol section (a separate doc) — Snyk has
   handled vulnerability disclosure at scale for a decade; what does Lictor
   get wrong about the public-accountability discipline?

I'm not asking for time. A pointer to "ask this team member; they'd have
opinions" is enough.

(If, after reading, Snyk did see strategic upside in co-shipping a CC0
standard with one of the AI-security upstarts — happy to discuss. Lictor's
positioning is deliberately complementary to Snyk's, not competitive. The
audience overlap is small.)

— Dor

[signature]

P.S. The Evo announcement in March '26 is the single most important product
shift in our category. The fact that you all shipped it before the rest of
the industry was even using "agentic AI security" as a phrase reset
expectations across the entire AppSec market. I'd like to learn from the
team that shipped it whether or not anything else comes from this email.
```

**Why this works for Snyk:** doesn't pretend to be peer-level (acknowledges asymmetry honestly), doesn't ask for adoption (asks for a read), explicitly opens the door to a strategic conversation without making the email feel like one. Snyk's leadership will respect the explicit framing.

---

## Sequencing + tracking

| Week | Send |
|---|---|
| Q4 W1 (Oct 6-12, post-launch) | Don't send yet — let the launch land first |
| Q4 W3 | Email 1 (Semgrep) — easiest to engage; sets the precedent |
| Q4 W5 | Email 2 + 3 (VibeEval, Symbioticsec) — smaller players, low coordination cost |
| Q4 W7 | Email 4 (Aikido) — mid-market commercial player |
| Q4 W9 | Email 5 (Snyk) — biggest validation if positive, lowest probability |

If Email 1 (Semgrep) responds positively: the others get a "Semgrep is reading the draft; happy to coordinate" line added. That single line increases response probability 3-5x.

If Email 1 responds with substantive critique: incorporate the critique into v0.2 BEFORE sending Emails 2-5. The drafts adapt.

If Email 1 doesn't respond in 3 weeks: send a single one-paragraph chase email. Then drop and don't follow up.

**Tracking spreadsheet shape:**

| Company | Sent | Status | Notes | Next action |
|---|---|---|---|---|
| Semgrep | YYYY-MM-DD | pending / replied-positive / replied-skeptical / no-response | … | chase YYYY-MM-DD |
| VibeEval | … | … | … | … |
| Symbioticsec | … | … | … | … |
| Aikido | … | … | … | … |
| Snyk | … | … | … | … |

Keep this private (in `~/Lictor/docs/business/data-room/05-sales-marketing/audit-json-outreach.csv` once that path exists).

---

## What "success" looks like

| Outcome | Probability | What it means |
|---|---|---|
| 2+ vendors co-author v0.2 | 30% | Strong outcome. The spec has real legitimacy by Q2 2027. |
| 1 vendor co-authors v0.2 | 40% | Moderate outcome. Use Year 2 to build out more adopters. |
| 0 co-authors but substantive feedback from 2-3 | 20% | The spec improves but stays Lictor-led. Still useful — Lictor + the OSS standard are both stronger. |
| Total silence | 10% | The spec is well-formed but the strategic moment isn't ripe yet. Try again with v0.2.5 in 12 months. |

The asymmetry: even the "0 co-authors" outcome is a positive signal for Lictor's positioning. Drafting a thoughtful CC0 standard is itself the kind of move that gets noticed by the right people quietly, even when no email response is generated. The standard lives forever; the outreach is the launch event.
