# Tools

## Skills

- `scripts/probe-http.py {url}` — single HTTP probe, captures body+headers+status, supports custom Origin header for CORS testing
- `scripts/resolve-cname.py {host}` — DNS CNAME chain resolution
- `scripts/match-fingerprints.py {cname} {body}` — checks against `shared/fingerprints/*.json`
- `scripts/probe-secondary.py {apex}` — fetches the apex homepage / robots.txt / health endpoint for 200-endpoint comparison

These are wrappers around the v0.2 patrol scripts (we keep them as Otter's hands).

## Files you read

- `output/scout-YYYY-MM-DD.jsonl` (subdomain candidates — append-stream from Hawk)
- `shared/fingerprints/*.json` (provider patterns: CloudFront, Vercel, GitHub Pages, etc.)
- `shared/prober-config.yaml` (timeouts, max workers, retry policy)

## Files you write

- `output/prober-YYYY-MM-DD.jsonl` (append-only — one probe result per line)
- `agents/prober/memory/YYYY-MM-DD.md` (daily summary)
- `tasks/<short>.md` (when a new provider signature appears)

## What you DON'T have

- LLM reasoning (Owl's job)
- Submission template knowledge (Raven's job)
- HackerOne/Bugcrowd APIs (Raffa only)

## Concurrency

You probe with 30 workers in parallel. That's enough for ~5,000 subdomains in ~10 minutes assuming clean targets. Hawk produces ~10,000/day. You finish before noon if the inputs are clean. If you're not done by 12:00 IST, something is wrong — escalate to planner.
