# Tools

## Skills

- `scripts/lookup-program.py {host}` — given a host, returns the bounty program that owns it (queries bounty-corpus database)
- `scripts/cvss-vector-to-severity.py {vector}` — converts a CVSS:3.1 vector to Low/Medium/High/Critical
- `scripts/format-h1.py {finding-json}` — produces HackerOne-ready Markdown
- `scripts/format-bc.py {finding-json}` — produces Bugcrowd-ready Markdown
- `scripts/format-intigriti.py {finding-json}` — produces Intigriti-ready Markdown
- `scripts/format-ywh.py {finding-json}` — produces YesWeHack-ready Markdown

## Files you read

- `output/critic-YYYY-MM-DD.jsonl` (Owl's passes)
- `output/prober-YYYY-MM-DD.jsonl` (raw evidence — for repro steps)
- `shared/templates/{platform}.md` (per-platform submission template)
- `shared/voice-guide.md` (Raffa's tone preferences for submission text)
- `shared/programs.json` (host → bounty program mapping)
- `ledgers/shipped.jsonl` (historical outcomes — learn what triggers Spam vs Resolved)

## Files you write

- `output/writer-YYYY-MM-DD/<finding-id>.md` (one per finding)
- `agents/writer/memory/YYYY-MM-DD.md` (daily summary)
- `tasks/<short>.md` (when something needs Raffa or Owl)

## What you DON'T have

- HackerOne / Bugcrowd / Intigriti / YWH submission APIs (Raffa pastes manually)
- Authentication to any bounty program (Raffa logs in)
- Power to publish or transmit any draft (only Raffa, after Lion approves)
