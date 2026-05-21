# Tools

## Skills

- `scripts/enum-crtsh.py` — Certificate Transparency log enumeration
- `scripts/enum-certspotter.py` — alternate CT source
- `scripts/enum-hackertarget.py` — passive DNS (rate-limited free tier)
- `scripts/enum-wayback.py` — Internet Archive CDX query
- `scripts/dedupe-subdomains.py` — union the four source outputs

These are wrappers around the four enumeration sources, each taking an apex domain and returning a deduplicated list of subdomains.

## Files you read

- `output/orca-YYYY-MM-DD.md` (today's apex slice — list of apex domains)
- `shared/scout-config.yaml` — rate limits, per-apex cap, retry policy
- `agents/scout/memory/*.md` — your own memory (yesterday's notes)

## Files you write

- `output/scout-YYYY-MM-DD.jsonl` (append-only — one subdomain per line)
- `agents/scout/memory/YYYY-MM-DD.md` (daily summary)
- `tasks/<short>.md` (when something needs Raffa or planner attention)

## What you DON'T have

- HTTP client capabilities (don't probe subdomains)
- DNS resolver (don't try to validate that subdomains are alive)
- Pattern matcher (don't filter "looks like" takeover targets)

All of that is Otter's. Stay in your lane.
