# OpenClaw Migration Plan — Lictor agent orchestration

**Status:** PLANNED · 2026-05-19 · Drafted in response to user request to move Lictor's autonomous machine onto OpenClaw agent crew.

---

## Why migrate

Today Lictor runs as **6 cron jobs + 1 daemon + ~13 standalone Python scripts**. It works, but:

- All orchestration lives in `crontab` (fragile, no observability, no retry, no parallel coordination)
- Agents (Wolf/Hawk/Owl/etc) exist as **persona docs** but not as actual processes — every script just runs as `raffa@host`
- No agent-to-agent handoffs (e.g., Hawk discovers → Bat verifies → Owl rechecks → Bee submits). It all happens in-process.
- One machine = one point of failure
- Hard to add a 12th agent or change a workflow

OpenClaw gives us: real agent processes, declarative routing (Hawk → Bat → Owl), persistent state, observability, parallel execution, and a UI we can wire to `/mission-control`.

---

## What an "agent-shaped" Lictor looks like

Each scanner becomes an OpenClaw agent. Each cron becomes a triggered workflow.

```
┌─────────────────────────────────────────────────────────────────┐
│  WOLF (planner) — picks what to scan next, kicks off Hawk       │
└─────────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│ HAWK         │     │ MONGOOSE     │     │ STARLING     │
│ (Scout)      │     │ (Probe)      │     │ (Trends)     │
│ GH Code      │     │ URL scan IL  │     │ Reply Watch  │
│ Search       │     │              │     │              │
└──────────────┘     └──────────────┘     └──────────────┘
        │                     │
        └──────────┬──────────┘
                   ▼
            ┌──────────────┐
            │ BAT          │
            │ (Surveyor)   │
            │ Fetch raw    │
            │ + verify     │
            └──────────────┘
                   │
                   ▼
            ┌──────────────┐
            │ MANTIS       │
            │ (Reviewer)   │
            │ Verifier     │
            │ gate         │
            └──────────────┘
                   │
        ┌──────────┴──────────┐
        ▼                     ▼
┌──────────────┐     ┌──────────────┐
│ LYREBIRD     │     │ CUTTLEFISH   │
│ (Writer)     │     │ (Vibe check) │
│ Draft body   │     │ Voice review │
└──────────────┘     └──────────────┘
        │                     │
        └──────────┬──────────┘
                   ▼
            ┌──────────────┐
            │ BEE          │
            │ (Magnet)     │
            │ Submit       │
            └──────────────┘
                   │
                   ▼
            ┌──────────────┐
            │ OWL          │
            │ (Critic)     │
            │ Recheck 3h   │
            └──────────────┘

OCTOPUS (Dev) — out-of-band: ships site changes, new scanners, infra
```

## Migration phases

### Phase 0 — Today (DONE)
- All 11 agents exist as persona docs in `~/Lictor/agents/`
- Each agent's "work" is implemented as a Python script in `~/Lictor/scripts/`
- Orchestration via crontab

### Phase 1 — Single-agent OpenClaw prototype (1 day)
- Pick the **Owl** agent (recheck) — small, well-bounded, clear interface
- Convert `scripts/recheck.py` into an OpenClaw agent definition (`~/.openclaw/agents/owl.yaml`)
- Replace the `0 */3 * * *` cron with an OpenClaw scheduled trigger
- Validate: agent runs, posts thank-you comments, updates state file
- **Success criteria**: same behavior as cron, but visible in OpenClaw UI + retryable on failure

### Phase 2 — Migrate the discovery pipeline (2-3 days)
- Wolf (planner) → kicks off Hawk every 5 minutes
- Hawk (scout) → runs one patrol scanner per cycle, writes findings to a queue tool
- Bat (surveyor) → consumes queue, runs verify-finding, writes verified findings to a second queue
- Each handoff is an OpenClaw `route_to` directive
- **Success criteria**: same throughput as discover-loop, but each handoff visible + interruptible

### Phase 3 — Migrate disclosure pipeline (1-2 days)
- Mantis → final pre-flight (security.txt / repo-alive / dedup)
- Lyrebird + Cuttlefish → parallel: draft body + voice-check it
- Bee → submit when both approve
- This is where the **rate limit** lives — Bee enforces 50/day cap regardless of upstream pressure
- **Success criteria**: drain-queue equivalent, with each disclosure visible as a workflow run

### Phase 4 — Observability hookup (1 day)
- The `/mission-control` dashboard subscribes to OpenClaw's event stream
- Each agent panel shows real-time current task (instead of static "Wolf: Orchestrates the rotation")
- Add a "trigger Hawk now" button → click on dashboard fires a Hawk run on demand

### Phase 5 — Multi-host (later)
- Run Wolf on the Mac mini (always-on)
- Run Hawk on a Cloudflare Worker or low-end VPS (no rate-limit headaches)
- Owl can run anywhere
- Each agent picks up work from the shared queue → no single point of failure

---

## What stays as-is (don't over-migrate)

- **Scanner logic** (`patrol-*.py`) stays as Python scripts — they're the agents' tools, not the agents themselves
- **State files** (`~/.lictor/*.json`) stay — OpenClaw doesn't need to own the state of the world
- **Cron entry for backups** — keep one minimal cron as a watchdog ("if OpenClaw didn't fire in 24h, alert")
- **The CLI + MCP server** — completely separate user-facing surface, no migration needed

---

## Risks

1. **OpenClaw learning curve** — first agent migration will take longer than the cron equivalent
2. **Debugging multi-agent flows is harder than `tail -f /var/log/cron`** — need to invest in OpenClaw's tracing
3. **Rate limit must be enforced in ONE place (Bee)** — distributed enforcement = double submissions
4. **State coherence** — when 3 agents read the same JSON, who owns writes? Need a single owner per file.

---

## Concrete first step (Phase 1) — to do this week

1. Install OpenClaw locally if not already
2. Write `~/.openclaw/agents/owl.yaml` that wraps `recheck.py`
3. Set up scheduled trigger (every 3h, same as current cron)
4. Run for 24h alongside existing cron — diff the outputs
5. If equivalent: disable the cron, leave OpenClaw running

If Owl works, Phases 2-3 follow the same pattern. Estimated total: 5-7 working days for full migration.

---

*Honest note: this is genuine engineering work, not a weekend project. The cron-based system is good enough to scale to ~500 disclosures/day. The OpenClaw migration is worth doing when (a) we hit cron's limits or (b) we want a 12th agent and the orchestration is the bottleneck — whichever comes first.*
