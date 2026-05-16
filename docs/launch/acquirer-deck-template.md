> **NOTE (May 2026 update):** Course revenue line REMOVED from Lictor's plan. The course at generationai.com is a separate consulting business and is no longer part of this project. References below that mention "Course", "course enrollments", or course-derived revenue should be treated as historical and substituted with zero. Other revenue lines (Teams, AaaS, Enterprise) stand.

# Lictor — Acquirer Deck Template

> **Generated:** 2026-05-15
> **Use:** First informational meeting with a plausible acquirer (Snyk, Anthropic, GitHub, Aikido, Cloudflare, Datadog, etc.)
> **Posture:** Informational. Lictor is NOT for sale at this meeting. The deck establishes that Lictor would be a serious target if a serious offer arrived.
> **Source documents:** `m-and-a-strategy.md`, `year-plan-2026-2027.md`, `business/data-room/README.md`, `operation-triumph-expanded.md`
> **Target length when narrated:** 25–30 minutes of slides + 30–45 minutes of conversation
> **Format:** markdown that converts cleanly to Keynote / PowerPoint / Pitch / Tome at presentation time

---

## Section 0 — Cover

**[SLIDE 0.1 — Cover]**

> # Lictor
> ### Informational overview — [MONTH YEAR]
>
> Prepared for: **[ACQUIRER_NAME]**
> Presented by: Raffa [LAST_NAME], Founder
>
> Version [DECK_VERSION] · [PAGE_COUNT] pages · **Confidential**
>
> ---
>
> *Lictor is the security crew for apps you built with AI — an open-source agentic auditor that lives where vibe-coders ship: inside Claude Code, Cursor, the browser, and the runtime.*

**Talking-point overlay (Raffa, not on screen):**
> "Thanks for the time. Quick note before we start — this is informational, not a pitch. We're sharing where Lictor is because the category we're in started to matter to your team and we wanted you to hear it from us, not from a third-party deck. I'd rather get your honest read than try to sell you on anything today."

---

## Section 1 — TL;DR

**[SLIDE 1.1 — What Lictor is, in 3 sentences]**

> **What Lictor is:**
> 1. Lictor is an open-source security platform for apps built with AI coding tools — Lovable, Bolt, v0, Cursor, Claude Code, Replit, and the long tail behind them.
> 2. We ship as a **15-agent crew** that audits code, sites, runtime, and incident timelines in plain English — no security PhD required.
> 3. We're [MONTHS_SINCE_LAUNCH] months past public launch, [MRR_VALUE] MRR, [GITHUB_STARS] stars, [WAU_VALUE] weekly active users on the Claude Code skill.

**[SLIDE 1.2 — The category claim]**

> **The category:**
> Lictor defines the **AI-built-app security** category — the security tool for the [VIBE_CODER_COUNT]+ developers shipping apps they didn't fully write themselves.
>
> The closest existing-tool framing: *"Snyk for vibe-coders."* The closest emerging-tool framing: *"the indie-hacker default in the same way Vercel became the indie-hacker default for hosting."*

**[SLIDE 1.3 — The disposition signal]**

> **Why we're sharing this:**
>
> - Lictor is not for sale today.
> - Several teams — yours included — have started asking us category-shaped questions over the last [MONTHS_OF_INBOUND] months.
> - We thought it was worth walking you through where we are and where we're going before any of this turns into rumor.
> - If a real strategic conversation ever made sense, we'd want you to have an accurate picture going in. This deck is that picture.

**Talking-point overlay (Raffa, not on screen):**
> "We didn't reach out cold. [SPECIFIC_TRIGGER — e.g., your security team starred our repo, your product lead DMed me about the AUDIT.json proposal, your M&A team requested a teardown PDF]. So I figured an hour with the actual founder was more useful than another GitHub click."

---

## Section 2 — The category

**[SLIDE 2.1 — The market we serve]**

> **The audience:**
> Vibe-coders, AI-app builders, indie-hacker founders, citizen developers — anyone shipping production code they generated with an AI coding tool.
>
> **The platforms feeding this audience:**
> Lovable · Bolt · v0 · Cursor · Claude Code · Replit · Windsurf · Devin · Manus · the next 12 to launch in 2027.

**[SLIDE 2.2 — Market size + growth]**

> | Signal | Value | Source |
> |---|---|---|
> | Vibe-coder population (active monthly) | [VIBE_CODER_COUNT]M+ | Lovable + Bolt + Cursor + Claude Code published stats, May 2027 |
> | Vulnerability rate in AI-generated code | 40–62% | [STUDY_CITATION — e.g., Stanford CS, GitGuardian 2026, IBM X-Force 2026] |
> | Year-over-year growth of category | ~10x | [SOURCE — e.g., Lovable's 2026 → 2027 user growth, Bolt's annual numbers] |
> | Lictor weekly active users (May 2027) | [WAU_VALUE] | Lictor anonymous build-ID telemetry |

**[SLIDE 2.3 — Why this category needs its own security tool]**

> **It's not Snyk-shaped:**
> Snyk's diligence target is the AppSec engineer at a 200+ person company. Vibe-coders don't have those. Snyk's UI assumes someone reads CVE descriptions. Vibe-coders don't.
>
> **It's not Aikido-shaped either:**
> Aikido leans toward small-team CISO-lite — still a security-aware buyer. Vibe-coders self-identify as "non-technical builders." That's a different product, a different price point, a different voice.
>
> **What this category actually needs:**
> - **Plain-English findings.** No CVE numbers in the headline.
> - **Distribution by context** — inside the tools they already use (Claude Code, Cursor, the browser).
> - **Transparent agents** — the audit is explainable, not a black-box score.
> - **Price point that matches indie-hacker reality** — $19/mo flat, not $40/dev seat.

**[SLIDE 2.4 — Validation that the category is real]**

> **External validation, last 12 months:**
> - **Lovable Feb 2026 incident** — 18,000 user accounts exposed through misconfigured Supabase RLS. The single most-cited security incident in the vibe-coder world. Drove a 3-week press cycle. Lictor's response teardown still ranks #1 organic for the keyword.
> - **Snyk Agent Security** (Snyk's AI-built-app product line, June 2026) — competitor entering the category from the enterprise direction.
> - **Aikido Vibe-Coder Edition** ([LAUNCH_MONTH] 2027) — competitor entering from the small-team direction.
> - **[OTHER_VALIDATION — e.g., GitGuardian's 2026 State of Secrets Sprawl naming AI-generated code specifically; Forrester analyst note Q1 2027]**

**[SLIDE 2.5 — 5-year forecast]**

> **Where this category goes:**
> One of two paths.
>
> **Path A:** AI-built-app security becomes its own $1–3B category by 2031, parallel to traditional AppSec — same way DAST + SAST + SCA each became standalone billion-dollar categories rather than collapsing into one.
>
> **Path B:** It absorbs half of traditional AppSec. Vibe-coding eats software development; the security tooling for vibe-coding eats the security tooling for software development. This is the more aggressive read but the math isn't crazy — Snyk's TAM 2030 numbers assume continued enterprise-developer dominance, which isn't a given.
>
> **Either path benefits an acquirer who already owns the brand of the category.**

---

## Section 3 — Lictor's position

**[SLIDE 3.1 — The 4-product stack]**

> **What Lictor actually ships:**
>
> | Product | What it is | Surface | Status May 2027 |
> |---|---|---|---|
> | **Claude Code skill suite** | The wedge. `/lictor-security-check`, `/lictor-explain`, `/lictor-teardown`, `/lictor-rls-check` | Claude Code, Cursor (via plugin) | GA, [WAU_VALUE] WAU |
> | **Lictor Shield** | Chrome extension — passive audit of any deployed site | Browser | GA, [SHIELD_USERS] installs |
> | **Lictor Sentinel** | npm + PyPI SDK — runtime defense, security event API | Production codebases | GA, [SENTINEL_INSTALLS] installs |
> | **Lictor Guardian** | Hosted dashboard — incident timeline + compliance evidence | Web app (Teams tier) | GA, [GUARDIAN_TEAMS] paying teams |

**[SLIDE 3.2 — The 15-agent crew]**

> **What powers all of it:**
> A documented, named, open-source crew of 15 AI agents. Each has a public SOUL.md file — purpose, prompts, evaluation criteria.
>
> **The core 11 (launched June 2026):**
> - Wolf (project lead) · Owl (code auditor) · Mongoose (competitive watch) · Lyrebird (plain-English writer) · Mantis (self-audit) · Bee (community signal) · Starling (viral-format intel) · Bat (hook generator) · Sage (architecture review) · Sentinel (runtime watcher) · Forge (CI/release)
>
> **The Q1 2027 additions:**
> - 🌐 Parrot (multilingual) · 🎬 Peacock (video scripts) · 🎙️ Nightingale (booking + CFPs) · 🤝 Meerkat (community manager)
>
> **Why this matters as IP:**
> The architecture is open. The *configuration* — agent prompts, calibration scoring, voice, eval traps — is the value. That's a year of public work, hard to replicate in a quarter.

**[SLIDE 3.3 — The brand]**

> **What "Lictor" means to the market:**
>
> *"The security crew for apps you built with AI."*
>
> The brand owns 4 things:
> 1. **The keyword "vibe-coder security"** — Google trends shows Lictor as the highest-volume associated entity since Q4 2026.
> 2. **The voice** — "plain-English security writer who makes the others sound like lawyers." Lyrebird agent's voice is recognizable across [TEARDOWN_COUNT]+ public teardowns.
> 3. **The Lictor Foundation pledge** — public commitment that the OSS core stays open. [FOUNDATION_INCORP_DATE] incorporated.
> 4. **AUDIT.json v0.1** — Lictor-authored community standard. Adopted by [STANDARD_ADOPTERS_COUNT] other tools as of May 2027.

**[SLIDE 3.4 — The community + content engine]**

> | Asset | Value | Note |
> |---|---|---|
> | GitHub stars | [GITHUB_STARS]+ | top 0.1% of OSS repos |
> | Weekly active skill users | [WAU_VALUE]+ | anonymous build-IDs |
> | Newsletter subs | [NEWSLETTER_SUBS]+ | [NEWSLETTER_OPEN_RATE]% open rate |
> | Twitter followers (combined) | [TWITTER_FOLLOWERS]+ | Lictor + Raffa personal |
> | Public teardowns archived | [TEARDOWN_COUNT]+ | weekly cadence, [TEARDOWN_WEEKS] weeks running |
> | Conference talks delivered | [TALKS_DELIVERED]+ | including [TIER_1_CONF_NAME] [TIER_1_CONF_DATE] |

**[SLIDE 3.5 — Under construction]**

> **What's shipping in the next 4 quarters:**
> - **Lictor Studio v1.0** — offline desktop app (Mac + Windows). Q1 2028.
> - **VS Code + JetBrains extensions** — IDE distribution beyond Claude Code. VS Code GA Q4 2027; JetBrains Q1 2028.
> - **Lictor Certified Auditor course** — paid curriculum, [COURSE_ALUMNI]+ alumni in pipeline.
> - **Audit-as-a-Service** — productized for dev agencies + VC firms. [AAAS_CUSTOMERS] active customers May 2027.
> - **Enterprise edition** — on-prem deploy, custom agents, premium support. First pilot signed [ENTERPRISE_SIGNED_DATE].

---

## Section 4 — The metrics

**[SLIDE 4.1 — Headline dashboard]**

> **State of Lictor — [MONTH YEAR]**
>
> | Metric | Value | Note |
> |---|---|---|
> | GitHub stars | [GITHUB_STARS]+ | top 0.1% of OSS repos |
> | Weekly active users (Claude Code skill) | [WAU_VALUE]+ | anonymous build-IDs |
> | Newsletter subscribers | [NEWSLETTER_SUBS]+ | [NEWSLETTER_OPEN_RATE]% open rate |
> | Twitter followers (Lictor + Raffa personal) | [TWITTER_FOLLOWERS]+ | |
> | Paying Teams subscriptions | [TEAMS_PAYING]+ | $19/mo flat |
> | Course alumni | [COURSE_ALUMNI]+ | "Lictor Certified Auditor" badges |
> | Audit-as-a-Service customers | [AAAS_CUSTOMERS]+ | small dev studios + [VC_FIRM_COUNT] VC firms |
> | Enterprise pilots running | [ENTERPRISE_PILOTS] | [ENTERPRISE_SIGNED_COUNT] signed contract(s) |
> | **MRR** | **[MRR_VALUE]** | mix of recurring + AaaS |
> | Net revenue (12-mo trailing) | [TTM_REVENUE]+ | |
> | Cumulative burn since incorporation | ~[CUMULATIVE_BURN] | self-funded |
> | Net cash position | ~[CASH_POSITION]+ | from operations |
> | Employees | 1 (Raffa) + 15-agent crew | + outside accountant + lawyer |

**[SLIDE 4.2 — Retention + satisfaction]**

> **The cohort story (what we're proudest of):**
>
> | Cohort | Retention metric | Value |
> |---|---|---|
> | Teams (90-day cohorts) | retained after 3 months | [TEAMS_RETENTION]% |
> | Course alumni | NPS | [COURSE_NPS] / 5 |
> | Course alumni | would recommend | [COURSE_NPS_RECOMMEND]% |
> | Audit-as-a-Service | renewal rate (first cohort) | [AAAS_RENEWAL]% |
> | Sentinel SDK | weekly heartbeat retention | [SENTINEL_RETENTION]% |

**[SLIDE 4.3 — The unit economics rough sketch]**

> | Stream | Avg revenue per customer | CAC | Gross margin |
> |---|---|---|---|
> | Teams | $228/yr | ~$8 (organic) | [TEAMS_MARGIN]% |
> | Course | $99 one-time | ~$11 (newsletter funnel) | [COURSE_MARGIN]% |
> | Audit-as-a-Service | $4–10k engagement | ~$200 (outbound) | [AAAS_MARGIN]% |
> | Enterprise (pilot) | $50–100k/yr | ~$1.5k (inbound + sales loop) | [ENTERPRISE_MARGIN]% |
>
> Honest read: numbers are early. AaaS payback is the strongest. Enterprise pilots are too few to draw conclusions. Teams CAC is enviably low because community drives the funnel — but if community plateaus, that number gets worse fast.

---

## Section 5 — The competitive moat

**[SLIDE 5.1 — Six things that make Lictor hard to displace]**

> **1. Brand + community ownership of "vibe-coder security."**
> Lictor owns the keyword. [TEARDOWN_COUNT]+ public teardowns are SEO-durable assets. Indie-hacker audience trusts Lictor specifically — surveyed [SURVEY_N] users May 2027, [SURVEY_TRUST_PCT]% picked Lictor over Snyk or Aikido for "tool I'd trust to audit my Lovable app."

**[SLIDE 5.2]**

> **2. The 15-agent crew as IP.**
> Snyk's agents are proprietary modules — black boxes. Aikido's are similar.
> Lictor's agents are public SOUL.md files. The architecture is open by design.
> The defensible value is the *configuration* — agent prompts, calibration ladders, scoring logic, voice — tuned over [PUBLIC_WORK_MONTHS] months of public work, against real teardowns, with public eval scores.
> An acquirer buys a tuned crew, not a code repo.

**[SLIDE 5.3]**

> **3. The plain-English voice.**
> Structurally hard to copy.
> - Snyk would have to alienate their CISO base.
> - Aikido would have to retrain their writers.
> - GitHub Advanced Security operates in security-team conventions.
> Lictor's voice is a year of consistent execution. Not replicable in a quarter. Not replicable by a team unless they're willing to break their existing audience.

**[SLIDE 5.4]**

> **4. Distribution-by-context.**
> Lictor lives inside the tools developers already use:
> - Claude Code skill suite (the wedge)
> - Cursor (via plugin)
> - VS Code (GA Q4 2027)
> - Chrome (Lictor Shield)
> - Runtime (Lictor Sentinel SDK)
> Most security tools require alt-tabbing to a dashboard. Distribution-by-context is structural, not toggleable. An acquirer's existing distribution does not replicate Claude Code presence overnight.

**[SLIDE 5.5]**

> **5. The audit-our-own-audit protocol.**
> Lictor publicly audits its own code monthly.
> Every false-positive logged in public.
> Every false-negative logged in public.
> Every agent prompt change documented with before/after eval scores.
> This is trust infrastructure competitors don't have because they can't introduce it without exposing their own quality gaps.

**[SLIDE 5.6]**

> **6. AUDIT.json standard authorship.**
> Lictor authored AUDIT.json v0.1 — the community standard for sharing AI-built-app audit findings.
> Adopted by [STANDARD_ADOPTERS_COUNT] other tools.
> Other tools that adopt it implicitly cite Lictor. Acquirer captures a standards position, not just a product.

**[SLIDE 5.7 — Pulling it together]**

> **The combined moat:**
> Brand + IP + voice + distribution + trust + standard.
>
> Any one of these can be copied. All six together is a 2–3-year displacement project at minimum, and that's assuming the displacing team starts now.
>
> The category clock is ticking faster than that.

---

## Section 6 — The strategic options

**[SLIDE 6.1 — Frame]**

> **We're not asking you to pick.**
>
> But we've thought about how a real conversation might shape up, and we figured it was more useful to surface the options than pretend we haven't considered them.
>
> Four shapes, in rough order of size:

**[SLIDE 6.2 — Option A: Acqui-hire shape]**

> ### Option A — Acqui-hire ($5–10M)
>
> **Shape:** Brand + Raffa + 15-agent crew + IP transfer.
> **What acquirer gets:** Lictor absorbs into your AI security GTM motion. Brand survives or sunsets at your discretion. Raffa + agent crew become the AI-built-app security team inside your org.
> **Best fit:** Snyk, Aikido, GitHub (precedent: GitHub → Dependabot at similar stage).
> **Strongest comp:** Snyk → Invariant Labs (June 2025 — sub-1-year-old company acquired to plant a category flag).
> **Why this shape is real:** Categories get won by the team holding the brand. Acquiring early is cheaper than fighting Lictor for 2 years.

**[SLIDE 6.3 — Option B: Product-line acquisition]**

> ### Option B — Product-line acquisition ($15–30M)
>
> **Shape:** Lictor continues operating semi-autonomously under acquirer's brand portfolio. Lictor team + product survives 24+ months.
> **What acquirer gets:** A standalone product line targeting an audience their main product doesn't reach. Brand stays "Lictor" inside marketing.
> **Best fit:** Cloudflare, Datadog, Atlassian (companies with strong brand portfolios that operate sub-brands well).
> **Strongest comp:** Cisco → Duo Security (kept Duo brand for 5+ years), GitLab → Oxeye ($30–40M).
> **Why this shape is real:** Lictor's audience is structurally different from any acquirer's existing audience. Folding the brand loses what you bought.

**[SLIDE 6.4 — Option C: Talent + tech with Foundation carve-out]**

> ### Option C — Talent + tech with Foundation carve-out ($10–25M)
>
> **Shape:** Acquirer buys Lictor LLC (commercial revenue + IP). Lictor Foundation (OSS code) remains independent — non-acquired, governed by community.
> **What acquirer gets:** Commercial business + agent crew + Raffa. Community keeps the OSS, which protects acquirer from "they killed the open source" backlash.
> **Best fit:** Anthropic (precedent: Bun acquisition Dec 2025; OSS-friendly culture), GitHub, vendors with strong OSS-respect cultures.
> **Strongest comp:** Anthropic → Bun (carve-out maintained), HashiCorp post-IBM (delayed-but-instructive).
> **Why this shape is real:** OSS audience has a long memory. Acquirers who've done badly here pay for it for years.

**[SLIDE 6.5 — Option D: Strategic investment, not acquisition]**

> ### Option D — Strategic investment + commercial agreement ($5–10M)
>
> **Shape:** Acquirer takes a strategic stake — say $5–10M at $50–100M valuation — plus a commercial partnership (e.g., GTM bundle, distribution agreement).
> **What acquirer gets:** Option value on Lictor's outcome + a real strategic relationship without integration overhead.
> **Best fit:** Earlier-stage moves for any of the acquirers listed above. Anthropic's [HYPOTHETICAL_ECOSYSTEM_FUND] precedent fits here.
> **Why this shape is real:** Lowest-risk for both sides. Buys time for a fuller picture to emerge in 12–18 months.

**[SLIDE 6.6 — The frame, restated]**

> **Why we're showing these:**
> Not to pitch a shape — to show we've thought about how this would work and we're not naïve about valuation, structure, or trade-offs.
>
> Your job, if and when this becomes a real conversation, is to think about which of these fits your strategic thesis. We're going to keep building either way.

---

## Section 7 — What we'd want from an acquisition

**[SLIDE 7.1 — Frame]**

> **Honest version of what makes this a healthy deal for both sides:**

**[SLIDE 7.2]**

> 1. **2+ year commitment to the open-source roadmap.**
> No immediate re-licensing of the core. The Lictor community trusts that decision and would notice instantly if it broke. An acquirer that flips that bit in month 3 destroys part of what they bought.

**[SLIDE 7.3]**

> 2. **Formal commitment to Lictor Foundation independence.**
> Whatever the structure, the Foundation continues to exist with independent governance. This protects the acquirer too — it's the brand-defense mechanism if community drama escalates later.

**[SLIDE 7.4]**

> 3. **Founder vesting + retention package aligned with the strategic thesis.**
> Raffa isn't trying to vest-and-leave. The interesting work is just starting. A reasonable 3-4 year structure is fine. What's not interesting: a structure where the strategic thesis gets quietly de-prioritized in year 2.

**[SLIDE 7.5]**

> 4. **A specific GTM channel the acquirer brings.**
> The acquisition only makes sense if 1 + 1 = 3. Specifically:
> - **Snyk:** enterprise sales motion + CISO trust + global support infrastructure
> - **Anthropic:** Claude Code reach + AI-safety credibility + research credibility
> - **GitHub:** developer mindshare + Marketplace + Copilot bundle paths
> - **[ACQUIRER_NAME]:** [SPECIFIC_GTM_LEVER]
>
> Without a specific lever, this is a brand purchase, not a strategic acquisition. We'd want to know which lever before saying yes.

**[SLIDE 7.6]**

> 5. **Mutual respect on the brand voice.**
> Lictor's plain-English voice survives the acquisition. The voice IS the product to a meaningful slice of the audience. We'd want operational autonomy on writing, content, and community communication for at least 24 months.

**[SLIDE 7.7 — Frame]**

> These aren't demands. They're what would make us answer "yes, let's keep talking" rather than "thanks, but this won't work."
>
> Most of them protect the acquirer's investment as much as ours.

---

## Section 8 — What's next

**[SLIDE 8.1 — Title]**

> **The 18-month forward roadmap — independent of acquisition status.**

**[SLIDE 8.2]**

> | Quarter | Headline ship | Why it matters |
> |---|---|---|
> | **Q3 2027** | Lictor Foundation incorporated | The OSS commitment becomes structurally protected — by acquisition or by default. |
> | **Q4 2027** | Lictor for Enterprise GA | Highest-revenue product line. Moves us from "indie tool" to "tool you can ask procurement to approve." |
> | **Q1 2028** | Lictor Studio v1.0 | Offline desktop. Paid Pro tier. Reaches audiences that can't or won't run cloud-hosted security tools. |
> | **Q2 2028** | Course at 1,000 alumni; 200+ certified auditors | Lictor Certified Auditor program reaches "professional credential" density. |

**[SLIDE 8.3 — Revenue forecast]**

> **Forecast (under-promising the curve):**
>
> | Period | MRR | Notes |
> |---|---|---|
> | Q2 2027 (today) | [MRR_VALUE] | the dashboard slide |
> | Q4 2027 | $50–100k | Enterprise GA + Studio Pro |
> | Q2 2028 | $100–200k | Course at scale + 2nd Enterprise cohort |
> | Q4 2028 | $200–500k | The "real company" point |
> | 2029 outlook | $2–5M MRR | Compounding inbound + Enterprise pull |
>
> The forecast assumes no acquisition. It also assumes no second-order shock (a major acquirer ships a free vibe-coder tier; a foundation model ships native code-audit). The plan-B doc for those scenarios is in the data room.

---

## Section 9 — The team

**[SLIDE 9.1 — Raffa bio]**

> **Raffa [LAST_NAME] — Founder**
> - 20+ years in cybersecurity. Background: [BACKGROUND_HIGHLIGHTS — e.g., IDF Unit 8200, [COMPANY_1], [COMPANY_2], [SPECIFIC_RESEARCH_WORK]].
> - Founded Lictor in [FOUNDING_YEAR] after watching Lovable + Bolt code repeatedly fail the same security audits.
> - Day-job context: continues to run GenerationAI consulting (the consulting entity is structurally separate from Lictor LLC — clean books from day one).
> - Public presence: [TWITTER_HANDLE] · [PERSONAL_NEWSLETTER] · [PODCASTS_DOR_HOSTED_OR_GUESTED]

**[SLIDE 9.2 — The 15-agent crew]**

> **How Lictor is operationally staffed:**
> - **1 human:** Raffa (founder, eng, content, GTM)
> - **15 AI agents:** documented in `/agents/SOUL.md` in the open monorepo
> - **Outside professionals:** [ACCOUNTANT_FIRM] (bookkeeping monthly), [LAW_FIRM] (legal, IP, contracts), [CONTRACTOR_COUNT] specialist contractors on rotating basis
>
> Each agent has a public job description, prompt library, eval history, and ownership of specific outputs. The "team" is small because the agents do real work, not because Raffa is heroically grinding alone.

**[SLIDE 9.3 — Planned human hires]**

> **First 2 human hires (post-acquisition or post-Series-A, whichever first):**
> 1. **Community manager + dev advocate** ($90–110k, fully remote, Q3–Q4 2027 hire window)
> Owns: Discord, GitHub triage at scale, weekly office hours, Lovable/Bolt/v0 partner relationships.
> 2. **Senior security researcher** ($150–180k, fully remote, Q1 2028 hire window)
> Owns: novel vulnerability research, conference talks, the Lictor Labs publication, deeper teardown work.
>
> The 15-agent crew handles the rest at the current size. Re-evaluate at $1M ARR.

---

## Section 10 — Appendix references

**[SLIDE 10.1 — What's in the data room]**

> **Acquirer-ready diligence pack — available under NDA:**
>
> | Section | What's inside | Last refreshed |
> |---|---|---|
> | 00 — Company | overview, org chart, cap table, entity registrations | [LAST_REFRESH] |
> | 01 — Financials | 4 quarters P&L, balance sheet, cash flow, revenue by stream, unit economics, 24-mo forecast | [LAST_REFRESH] |
> | 02 — Customers | full customer list (anonymized for first review; named under NDA), [REFERENCE_CUSTOMER_COUNT] reference customers consenting to calls | [LAST_REFRESH] |
> | 03 — Product | architecture overview, public roadmap, feature list, GitHub stats (12 months), known-issues log | [LAST_REFRESH] |
> | 04 — Technology + IP | license audit, trademark registrations (US + EU + IL), OSS dependency inventory, CLA records (every contributor), Raffa's IP assignment, domain registrations | [LAST_REFRESH] |
> | 05 — Sales + marketing | pipeline, marketing analytics, channel mix, press log, community signal | [LAST_REFRESH] |
> | 06 — Legal | standard customer contract, vendor contracts (Stripe, Paddle, Cloudflare, GitHub, hosting), partner agreements, insurance, GDPR posture | [LAST_REFRESH] |
> | 07 — Operations | vendor list, critical-process runbooks, disaster recovery, security policy, runbook index | [LAST_REFRESH] |
> | 08 — Risk | the honest risk register (the same 12 risks our year-plan flags), competitive landscape, regulatory exposure | [LAST_REFRESH] |
> | 09 — Community + content | teardown archive index ([TEARDOWN_COUNT]+ teardowns), content metrics (12 months), partnership list, brand assets | [LAST_REFRESH] |

**[SLIDE 10.2 — The 3 docs that answer most diligence questions first]**

> **If you want a deeper conversation, here's what we'd share first under NDA:**
> 1. **`01-financials/statements/[CURRENT_QUARTER]-pnl.pdf`** — the books speak for themselves.
> 2. **`04-technology-ip/license-audit.md` + `cla-records/`** — clean IP provenance is the single most-asked diligence question for OSS-led companies.
> 3. **`02-customers/reference-customers.md`** — 5–7 customers who've pre-consented to take an unscheduled call from a diligence team.
>
> That gets a serious acquirer 70% of the way through "is this real?" in about 3 hours of reading. The rest is structure.

**[SLIDE 10.3 — Final slide]**

> ## Thank you.
>
> **Raffa [LAST_NAME]**
> Founder, Lictor
> [EMAIL] · [TWITTER_HANDLE] · [SIGNAL_OR_PREFERRED_CHANNEL]
>
> *Not for distribution. Confidential — for [ACQUIRER_NAME] only.*

---

# Appendix — How to use this deck

## A. Pre-meeting prep checklist (T-7 days)

- [ ] **Refresh every `[BRACKETED_PLACEHOLDER]`** with current numbers from the data room. Specifically:
  - Dashboard metrics (Slide 4.1) — pull from `01-financials/revenue-streams/*.csv`
  - GitHub stars + WAU — pull from `03-product/github-stats-monthly.csv`
  - Teardown count + last-refresh dates — pull from `09-community-content/teardown-archive-index.md`
- [ ] **Update screenshots** of the live product:
  - Claude Code skill in action — fresh capture, current build
  - Lictor Shield Chrome extension on a recent teardown target
  - Guardian dashboard with current month's data
- [ ] **Swap acquirer-specific bullets:**
  - Slide 1.3 — the "specific trigger" line. What was the actual signal from this acquirer?
  - Slide 6.2–6.4 — reorder strategic options so the most-likely-shape-for-this-acquirer appears first.
  - Slide 7.5 — the GTM-lever line. Fill in this acquirer's specific lever.
- [ ] **Verify cover slide** — version, date, "for [ACQUIRER_NAME]" all current.
- [ ] **Re-read the acquirer-specific row** in `m-and-a-strategy.md` Section 2 ("Acquirer landscape") right before walking in. The risks and fit notes there should shape what Raffa emphasizes verbally.
- [ ] **Print 1 paper copy + carry on iPad.** Paper for them, iPad for Raffa (no projector dependency).

## B. Slide-by-slide talking points (what Raffa says vs what's on screen)

| Slide | On screen | Raffa says (~) |
|---|---|---|
| 0 — Cover | Title, logo, name | "Quick framing — this is informational. Not for sale today. Just wanted you to have an accurate picture." |
| 1.1 — What | 3-sentence definition | "Three sentences, then we go deeper. If any of these feel off, push back now." |
| 1.2 — Category | Category claim | "We think the category is real. The room may disagree. That's fine — but the data we'll show is the data." |
| 1.3 — Disposition | The non-pitch frame | "We weren't going to come find you. But [SPECIFIC_TRIGGER] made us think the right move was to walk you through it ourselves." |
| 2.1–2.5 — Category | Market sizing, validation | "The market is bigger than vibe-coders. Vibe-coders are the wedge. The leak-through is what makes this a category bet, not a niche bet." |
| 3.1–3.5 — Position | Products + crew + brand | "Four products, one crew. The crew is the IP. The brand is the moat." |
| 4.1–4.3 — Metrics | Dashboard + retention | "Numbers are early. We'll show you the actuals, not the forecast, and let the forecast speak for itself in the data room." |
| 5.1–5.7 — Moat | Six factors | "Don't fixate on any single one. The combined moat is the point. Each one is copy-able alone. All six together is years." |
| 6.1–6.6 — Options | Four deal shapes | "I'm not asking you to pick. I'm showing we've thought about it. Your job, if this ever becomes real, is to think about which fits your thesis." |
| 7.1–7.7 — What we'd want | Terms framing | "These aren't demands. They're what would make this a deal we'd say yes to. Most protect you as much as us." |
| 8.1–8.3 — Roadmap | 18-month forward | "This is the plan with or without you. The acquisition only matters if it accelerates a plan that already works." |
| 9.1–9.3 — Team | Bio + crew | "One person, 15 agents, real outside professionals. The structure is the asset." |
| 10.1–10.3 — Appendix | Data room | "We can share the data room under NDA. Three docs answer 70% of diligence questions in the first 3 hours of reading." |

## C. The 3 questions Raffa asks the acquirer (informational, not negotiating)

> Ask all three. Order them based on the room's energy.

1. **"What signal made AI-built-app security land on your radar?"**
> Tells you whether their interest is strategy-driven (good for Lictor) or board-asks-driven (volatile). Their answer also tells you which internal champion you're talking to.

2. **"In your category bets historically — Wiz, Snyk, [INSERT_ACQUIRER_PRECEDENT] — what did the brand do that the product alone couldn't?"**
> Tests whether they understand brand-as-IP. If they reduce brand to "marketing collateral," they're the wrong acquirer for Lictor.

3. **"If you were building Lictor — same audience, same starting point — what would you ship differently in the next 12 months?"**
> The most revealing question. Tells you what they'd want post-acquisition without anyone naming acquisition. Also tells you whether they actually understand the audience or are pattern-matching from afar.

## D. What "this meeting was productive" looks like vs. "polite no-thanks"

**Productive signals:**
- They ask about specific metrics not on a slide (revenue cohorts, Sentinel telemetry, churn drivers)
- They name a specific internal champion who'd own the relationship
- They reference internal conversations that have already happened ("our M&A team flagged you in Q1")
- They commit to a specific follow-up date or named follow-up person
- They ask about the data room — and specifically which 3 docs to read first
- They push back on Section 6 options ("we wouldn't do Option B, but Option C is interesting") — engagement = real interest
- Post-meeting: their team stars the repo, follows Raffa on Twitter, or downloads Sentinel within 48 hours

**Polite-no-thanks signals:**
- Generic praise without follow-up specifics ("really impressive what you've built")
- "We'll think about it" with no named owner, no date
- Conversation stays at marketing-deck altitude — never drops into product specifics or metrics
- No questions about the data room
- Nobody from the acquirer side commits to a next meeting
- 7 days later: silence

**Mixed signals (the most common case):**
- They asked good questions but didn't commit to anything specific
- **Action:** Send the follow-up email at T+7 (see Section E). Treat as productive until proven otherwise. If T+30 silence, treat as polite-no.

## E. 60-day follow-up cadence

| Day | Action | Owner |
|---|---|---|
| **T+1** | Thank-you note. 3 sentences. No deck attached. Reference one specific thing from the conversation. Mention the data room is available under NDA when they want it. | Raffa |
| **T+7** | Soft update — "FYI, [SPECIFIC_RECENT_SHIP] launched this week, thought you'd be interested." Demonstrate momentum without selling. | Raffa |
| **T+14** | If they responded to T+1 or T+7 — propose a follow-up call with a specific person on their side (the internal champion they named). If no response — do nothing yet. | Raffa |
| **T+30** | Monthly investor/acquirer update email goes out (uses `investor-acquirer-update-template.md`). They're on the list. This is the "you're on the list" cadence, not direct outreach. | Raffa + Meerkat agent |
| **T+45** | If still silence: one final direct note. "Hey, given [RECENT_INDUSTRY_EVENT], wondered if anything had changed on your side. No need to reply if not." Then stop. | Raffa |
| **T+60** | If reaching out has happened from their side — proceed at their pace, with a real diligence ask (data room access, second meeting, named champion). If no reach-out happened — they're parked. Re-evaluate in 6 months. | Raffa |

**Important discipline:**
- **Never ask for an offer.** The point is they reach out for the next conversation, not Raffa.
- **Never run two acquirer conversations as if they don't know about each other.** Acquirer ecosystems are small. The leverage of multiple plausible acquirers comes from their *suspicion* that other acquirers exist — not from Raffa confirming it.
- **The monthly update email is the steady-state.** It's calibrated to maintain awareness without selling. Don't break cadence to ping someone individually unless you have a real reason.

---

*End of deck template. Convert to presentation format at presentation time. Maintain markdown source as authoritative — it travels better, diffs cleanly, and survives audience-switching.*
