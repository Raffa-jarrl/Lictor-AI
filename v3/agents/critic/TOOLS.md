# Tools

## Skills

- `scripts/fp-cloudfront.py {probe-json}` — applies the x-amz-cf-id header check (v0.2 logic)
- `scripts/fp-azure-cloudapp.py {probe-json}` — applies the 4xx-status + canonical-body check
- `scripts/fp-github-pages.py {probe-json}` — applies the org-exists check via api.github.com
- `scripts/fp-netlify.py {probe-json}` — applies the strict marker requirement
- `scripts/fp-heroku.py {probe-json}` — applies the "No such app" + 404 check
- `scripts/fp-cors-error-page.py {probe-json}` — **THE NEW v0.3 FILTER** — compares 4xx vs secondary 200 probe CORS headers
- `scripts/check-bounty-scope.py {host} {program}` — checks if a host is in scope of a given bounty program

You may also call LLM inference for reasoning-heavy filtering (the deepseek-r1:14b is locally available via the gateway).

## Files you read

- `output/prober-YYYY-MM-DD.jsonl` (Otter's append-stream)
- `shared/fp-patterns/*.md` (documented FP classes + verifier rules)
- `shared/fingerprints/*.json` (provider patterns)
- `ledgers/filtered-fps.jsonl` (historical FPs — pattern memory)
- `ledgers/confirmed.jsonl` (historical real findings — pattern memory)

## Files you write

- `output/critic-YYYY-MM-DD.jsonl` (passes — go to Raven)
- `ledgers/filtered-fps.jsonl` (rejects with FP class — for tuning)
- `agents/critic/memory/YYYY-MM-DD.md` (daily review)
- `tasks/<short>.md` (when something needs Raffa or Otter)

## When to escalate

- A finding is genuinely ambiguous after applying all 6 FP filters → output with `next_action: "owl-needs-more-info"` AND write a task for Raffa
- A new FP pattern appears that isn't covered by any of the 6 filters → write to `shared/fp-patterns/<class-name>.md` (draft) + task for Raffa to formalize
