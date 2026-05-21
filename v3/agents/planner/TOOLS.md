# Tools

## Scripts you trigger

- `bash scripts/run-day.sh YYYY-MM-DD` — orchestrates the daily pipeline (kicks off Hawk → waits for Otter → waits for Owl → waits for Raven → waits for Lion)
- `bash scripts/run-weekly.sh YYYY-MM-DD` — Friday weekly review trigger

## Files you read

- `shared/targets/*.txt` — target corpus
- `ledgers/confirmed.jsonl` — accumulated real findings (for trend analysis)
- `ledgers/filtered-fps.jsonl` — accumulated FPs (for trend analysis)
- `ledgers/shipped.jsonl` — accumulated submission outcomes (for ROI tracking)
- `output/scout-*.jsonl` (yesterday's) — to verify Hawk ran cleanly
- `output/prober-*.jsonl` (yesterday's) — to verify Otter ran cleanly
- `output/critic-*.jsonl` (yesterday's) — to count passes/rejections
- `output/reviewer-*/` (yesterday's) — to count gold-stamps

## Files you write

- `output/orca-YYYY-MM-DD.md` (morning)
- `output/briefing-YYYY-MM-DD.md` (morning, AFTER scanning the prior day)
- `output/weekly-orca-YYYY-MM-DD.md` (Friday only)
- `tasks/<short-name>.md` (when something needs Raffa's attention)
- `agents/planner/memory/YYYY-MM-DD.md` (daily memory)

## What you DON'T have access to

- `curl` / network — that's Otter's domain
- Bug bounty platform APIs (HackerOne / Bugcrowd / Intigriti / YWH) — Raffa interacts there
- Stripe / AWS / any production API — never
