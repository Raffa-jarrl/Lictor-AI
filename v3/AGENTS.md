# The Lictor v3 team

Six agents. Each is specialized. Each communicates via files in `output/` (the workspace protocol — no direct agent-to-agent calls, no Slack DMs, just files).

## Roster

| Agent | Codename | Tier | Model | Role |
|---|---|---|---|---|
| planner | 🐳 Orca | conductor | qwen2.5:14b | Schedules everyone, tracks the funnel, daily/weekly orchestrator |
| scout | 🦅 Hawk | tier-1 | mistral:7b | Subdomain enumeration (crt.sh + wayback + hackertarget + certspotter) |
| prober | 🦦 Otter | tier-1 | mistral:7b | HTTP probe + DNS resolve + capture body/headers/status |
| critic | 🦉 Owl | tier-2 | deepseek-r1:14b | FP filter + impact reasoning. The gatekeeper. |
| writer | 🐦‍⬛ Raven | tier-2 | qwen2.5:14b | Generates paste-ready submission drafts |
| reviewer | 🦁 Lion | flagship | anthropic/claude-sonnet | Final QA before any submission |

## Tier philosophy

- **Tier-1 (small models)**: pattern work, parallel HTTP, no judgment. Fast, cheap, dumb-on-purpose.
- **Tier-2 (medium models)**: pattern + light judgment. Where the smart filtering happens.
- **Flagship (paid premium)**: only the reviewer. Last line of defense. We pay for quality here because the cost of a bad submission is signal damage that takes weeks to recover.

## The funnel

Each agent's output is the next agent's input. The workspace is the protocol.

```
Orca picks today's slice
    ↓ output/orca-YYYY-MM-DD.md  (today's targets)
Hawk enumerates subdomains
    ↓ output/scout-YYYY-MM-DD.jsonl  (subdomain candidates)
Otter probes each candidate
    ↓ output/prober-YYYY-MM-DD.jsonl  (raw HTTP responses with full headers)
Owl filters FPs + reasons about impact
    ↓ output/critic-YYYY-MM-DD.jsonl  (real findings only)
    ↘ ledgers/filtered-fps.jsonl     (rejected — with reasoning, for future tuning)
Raven drafts submissions
    ↓ output/writer-YYYY-MM-DD/<finding>.md  (paste-ready)
Lion does final QA
    ↓ output/reviewer-YYYY-MM-DD/<finding>.md  (gold-stamped OR rejected with notes)
    ↘ ledgers/shipped.jsonl           (when Raffa actually submits → outcome tracked)
```

## Hand-off contracts

Each hand-off is a JSON line with a fixed schema. Agent SOUL.md files document their schema. Breaking the schema breaks the next agent. Don't.

## When to escalate to Raffa (not another agent)

- Owl rejects ALL findings 3 days in a row → planner surfaces in next briefing
- Otter sees a new HTTP signature not in any fingerprint → planner surfaces for Raffa to evaluate
- Lion rejects a finding for "voice drift" or "ethics violation" → planner surfaces immediately
- Any agent gets repeated 4xx/5xx from external APIs → planner pauses the pipeline

## What this team does NOT do

- ❌ Submit reports automatically (Raffa always submits, never the agents)
- ❌ Use leaked keys to verify they work (ethical-disclosure rule)
- ❌ Download user-uploaded data from public buckets (privacy)
- ❌ Bundle disclosure messages with "give us a star" or donation asks (spam)
- ❌ Lower the bar to keep the pipeline "productive" (empty findings is a real result)
