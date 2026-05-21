# Lictor v3 — Security AI for AI-first companies

> Multi-agent security scanner. AI infrastructure deserves AI-grade security tooling.

Lictor v3 is a **complete rewrite** of the Lictor scanner suite as a multi-agent system on [OpenClaw](https://github.com/openclaw/openclaw). Each agent has a specialized role; the agents hand off via files in this workspace.

## Why a fresh start

v0.1 was a single Python script with regex fingerprints.
v0.2 added header-aware FP filters (CloudFront x-amz-cf-id, Azure 4xx-only, GitHub Pages org-exists, Netlify drop-domain markers, Heroku 404-required).

**v0.2 still produced false positives** in one critical class: **CORS reflect-with-creds on 4xx error pages** that disappears on real 200-OK endpoints. An afternoon of "verified hits" on Radware / JFrog / Amazon.nl / Kroger / SpaceX / OpenSea all turned out to be CDN-default error-page behavior, NOT exploitable application-level misconfigs. Submitting any of them would have damaged our HackerOne signal and credibility.

The pattern was missed because v0.2 is a single-pass scanner — it doesn't reason about whether a finding is actually impactful, only whether it matches a fingerprint. **A second-line reasoner is required.**

v3 adds that reasoner as a dedicated `critic` agent and elevates the architecture from procedural to multi-agent.

## The seven agents

| Agent | Role | Model | What it does |
|---|---|---|---|
| 🐳 **Orca** (planner) | Director | `qwen2.5:14b` | Orchestrates daily campaigns. Schedules other agents. Tracks the funnel. |
| 🦅 **Hawk** (scout) | Surface mapper | `mistral:7b` | Discovers subdomains via crt.sh + Wayback + Hackertarget + Certspotter. |
| 🦦 **Otter** (prober) | First-line verifier | `mistral:7b` | HTTP probes. Captures body + headers + status. No reasoning, just facts. |
| 🦉 **Owl** (critic) | FP filter & impact reasoner | `deepseek-r1:14b` | THE gatekeeper. Reasons about ambiguous findings. Won't let weak ones through. |
| 🐦‍⬛ **Raven** (writer) | Submission scribe | `qwen2.5:14b` | Generates paste-ready H1/BC/Intigriti/YWH drafts. |
| 🦁 **Lion** (reviewer) | Per-draft QA | `anthropic/claude-sonnet` | Final QA per draft. Checks ethics, scope, severity, voice. Re-runs curls. |
| 🧙 **Oracle** (meta-verifier) | Whole-chain meta-review | `anthropic/claude-opus` | THE Raffa-proxy. Audits the whole chain (Owl → Raven → Lion). Re-runs curls FRESH. Only after Oracle says GO does Telegram fire. |

## The funnel

```
[bounty targets corpus]
        ↓ daily 06:00 IST
   ┌─────────┐
   │  Orca   │  picks today's slice
   └────┬────┘
        ↓
   ┌─────────┐
   │  Hawk   │  → output/scout-YYYY-MM-DD.jsonl   (subdomains)
   └────┬────┘
        ↓
   ┌─────────┐
   │  Otter  │  → output/prober-YYYY-MM-DD.jsonl  (raw HTTP + secondary 200-probe)
   └────┬────┘
        ↓
   ┌─────────┐
   │  Owl    │  → output/critic-YYYY-MM-DD.jsonl  (passes/rejects with reasoning)
   └────┬────┘                                     → ledgers/filtered-fps.jsonl
        ↓
   ┌─────────┐
   │  Raven  │  → output/writer-YYYY-MM-DD/<finding>.md  (paste-ready drafts)
   └────┬────┘
        ↓
   ┌─────────┐
   │  Lion   │  → output/reviewer-YYYY-MM-DD/<finding>.md  (APPROVE/REJECT/NEEDS_FIX)
   └────┬────┘
        ↓ if APPROVE
   ┌─────────┐
   │ Oracle  │  → output/oracle-YYYY-MM-DD/<finding>.md  (GO/NO-GO meta-verification)
   └────┬────┘
        ↓ if GO
   ┌──────────┐
   │ Submitter│  → Telegram bot: 📲 [✅ SUBMIT] [❌ DEFER] [✏️ VIEW]
   │  (tool)  │
   └────┬─────┘
        ↓ on Raffa tap ✅
   ┌──────────┐
   │ Platform │  → ledgers/shipped.jsonl
   │   API    │
   └──────────┘
```

## Strategic positioning

**Security for AI-first companies.**

AI-first companies ship code AI wrote, run agents that touch production, and deploy infrastructure faster than any human security team can review. Traditional scanners don't reason — they pattern-match and overwhelm with noise. Lictor v3 is a security scanner BUILT WITH the same multi-agent pattern AI-first companies build their products with. We mirror the architecture, we mirror the discipline.

## Project structure

```
v3/
├── README.md            ← this file
├── USER.md              ← canonical user context (Raffa, mission, constraints)
├── AGENTS.md            ← canonical team description (for agents to read)
├── openclaw.config.json ← agent registrations + model assignments
├── agents/
│   ├── planner/         ← Orca 🐳
│   ├── scout/           ← Hawk 🦅
│   ├── prober/          ← Otter 🦦
│   ├── critic/          ← Owl 🦉
│   ├── writer/          ← Raven 🐦‍⬛
│   └── reviewer/        ← Lion 🦁
├── shared/
│   ├── voice-guide.md   ← submission writing style
│   ├── targets/         ← bounty corpus + sec-vendor + mega-corpus
│   ├── fingerprints/    ← provider fingerprints (60+ takeover patterns)
│   └── fp-patterns/     ← documented FP classes + verifier rules
├── ledgers/
│   ├── confirmed.jsonl  ← real findings
│   ├── filtered-fps.jsonl
│   └── shipped.jsonl
├── output/              ← per-day per-agent outputs (the protocol)
└── scripts/             ← v0.2 patrol scripts (kept as Otter's tools)
```

## License

Apache 2.0 — same as v0.2. The whole stack is open source.
