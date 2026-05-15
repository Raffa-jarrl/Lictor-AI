# Snyk Agent Security — Gap analysis

> **Generated:** 2026-05-15
> **Purpose:** Specific, evidence-backed gaps in Snyk's "Agent Security" + Evo product line that Lictor can credibly differentiate against. NOT a feature parity list — a position map.
> **Sources verified:** snyk.io/platform · snyk.io/news/snyk-launches-agent-security-solution · snyk.io/news/snyk-launches-evo · github.com/snyk/agent-scan · snyk.io/plans · evo.ai.snyk.io · snyk.io/blog/old-ai-security-vs-evo

---

## The 7 gaps where Lictor wins

### 1 — Evo and Agent Security are not in the free tier
**Evidence:** `snyk.io/plans` lists no Evo or Agent Security access in the free plan. Free tier caps at 100 SAST tests/month. Team plan starts at **$25/dev/month with a 5-developer minimum** — solo founders are structurally excluded by pricing design, not just price.

**Lictor counter:** Apache 2.0, no seat minimum, no token, no signup. `npx lictor` is the entire installation. The solo Lovable / Bolt / v0 builder Snyk has chosen to gate out is exactly who Lictor is for.

### 2 — `agent-scan` requires a Snyk account + sends data to Snyk's API
**Evidence:** github.com/snyk/agent-scan README requires `SNYK_TOKEN` env var and explicitly "shares skills, agent applications, tool names, and descriptions with Snyk's API for analysis."

**Lictor counter:** Lictor runs 100% local. No token, no telemetry, no cloud round-trip on the audit path. Sentinel's only outbound traffic is 16-char fingerprints — never raw input/output. **Privacy-by-default is a hard-coded differentiator that Snyk's architecture cannot match without rewriting their product.**

### 3 — agent-scan is OSS in license only — community contributions are rejected
**Evidence:** github.com/snyk/agent-scan is Apache-2.0 licensed but explicitly "closed to external contributions; accepts issues and feature requests only." It's read-only OSS — a different category than community OSS.

**Lictor counter:** Lictor accepts PRs, treats the vibe-coder community as co-authors, and ships open governance. The "we read your issue" vs "we merge your PR" distinction is the difference between OSS-as-marketing and OSS-as-product.

### 4 — Zero mention of Lovable, Bolt, or v0 anywhere in Snyk's surface
**Evidence:** None of snyk.io/platform, evo.ai.snyk.io, the March 2026 press release, or the agent-scan repo mention Lovable, Bolt, v0, or vibe coding. Marketing target audience explicitly listed on evo.ai.snyk.io: "CISOs, Engineering Leaders, Security Engineers."

**Lictor counter:** Lictor's entire positioning is *"open-source autonomous AI security for apps you built with Lovable / Bolt / v0."* Snyk has ceded the entire vibe-coder beachhead — not by accident, but because their go-to-market motion is wrong for it.

### 5 — Findings land in Snyk's dashboard, not the developer's terminal
**Evidence:** evo.ai.snyk.io makes no mention of IDE or terminal output for Evo findings. snyk.io/blog/old-ai-security-vs-evo emphasizes "platform-level capabilities" and "reducing manual review burden for gatekeepers." Snyk Studio IS embedded in Claude Code / Cursor / Devin — but that's the CI/CD validation product, not Evo's discovery / red-team / AI-BOM findings.

**Lictor counter:** Lictor's findings appear as inline plain-English markdown inside Claude Code, exactly where vibe-coders already live. No dashboard tab to remember to check. No second login. The audit IS the conversation with the AI.

### 6 — Compliance dialect, not plain English
**Evidence (direct quotes from Snyk surface):**
- *"Agentic architectures turn governance into a software supply chain problem"*
- *"Gain visibility and governance for AI adoption without adding fragmented security tools"*
- *"enforcement layer," "governance gaps," "machine-enforceable guardrails"*

**Lictor counter:** Lictor speaks the vibe-coder dialect — *"your Supabase service key is in your JS bundle, anyone can charge their card to your account"* — not *"policy agent enforcement architecture."* This is the most defensible gap on the list because changing it requires Snyk to alienate their CISO-buyer.

### 7 — Evo's multi-agent reasoning is opaque to the user
**Evidence:** Snyk lists Discovery Agent, Risk Intelligence Agent, Policy Agent, Agent Guard, Agent Red Teaming — but the user-facing surface across evo.ai.snyk.io and the press release shows only aggregated findings. No per-sub-agent attribution surfaced. CIO testimonial: *"Claude finds. Snyk confirms. The agent fixes only what's real"* — a black-box pipeline framing.

**Lictor counter:** Lictor's TEAM_CONTRACT and planner sweep already surface *which sub-agent found what*. The user sees the crew work — Radar surfaced this story, Sieve scored it, Probe validated it. Transparency of process is itself the product. "Look how my agents argued with each other to find this" is content marketing Snyk cannot run.

---

## 3 Snyk marketing claims Lictor copy should directly counter

1. **Snyk:** *"Claude finds. Snyk confirms. The agent fixes only what's real."* — Manoj Nair, CIO
 **Lictor:** *"Claude finds. Lictor confirms. You stay in Claude Code the whole time — no second dashboard, no second login, no second invoice."*

2. **Snyk:** *"Agentic architectures turn governance into a software supply chain problem."*
 **Lictor:** *"Your weekend Lovable app isn't a supply chain problem. It's a leaked-API-key problem. Lictor finds it in 30 seconds, locally, for free."*

3. **Snyk:** *"Old AI security takes weeks. Evo starts working immediately."*
 **Lictor:** *"Evo starts working after sales, procurement, and a 5-seat minimum. Lictor starts working after `npx lictor`."*

---

## Do not fight here (concede explicitly)

1. **Enterprise CISO governance / AI-BOM / SOC2-friendly reporting** — Snyk's Discovery Agent + AI-SPM are real GA products designed for the $1,260/dev/year Ignite-tier buyer. Lictor cannot win the Fortune-500 CISO RFP and should not try. Compliance evidence export stays in Guardian as a feature, never as the headline.

2. **Runtime / production enforcement (Agent Guard, real-time destructive-command blocking)** — Snyk has a private-preview real-time enforcement layer with cloud telemetry needed to operate at scale. Lictor is build-time / audit-time, not runtime. Don't pretend otherwise.

3. **CI/CD pipeline depth (Snyk Studio in Claude Code / Cursor / Devin)** — Snyk Studio is already shipping inside coding agents for pipeline-stage validation. Lictor should position as the *local-first audit complement* to pipeline gates, not as a pipeline-gate replacement. Integrate, don't compete.

---

## Bottom line for positioning

Snyk has explicitly built Evo for the AppSec / CISO buyer with a 5-seat floor. Every dimension that matters to the solo Lovable / Bolt / v0 builder — **free, local, plain-English, Claude-Code-native, vibe-coder-aware, contribution-open** — is a gap Snyk has *not chosen* to close.

Lictor wins by being unambiguously the *other* product. Not a cheaper Snyk.
