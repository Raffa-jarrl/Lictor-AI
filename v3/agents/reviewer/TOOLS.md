# Tools

## Skills

- `scripts/verify-scope.py {host} {program}` — fetches the program's scope page, checks if {host} is listed with eligible_for_bounty=true
- `scripts/lint-voice.py {draft.md}` — checks the draft against `shared/voice-guide.md` rules (hype words, first-person speculation, money/star asks)
- `scripts/re-run-curl.py {draft.md}` — extracts the curl commands from the draft's Steps-to-Reproduce and re-runs them, comparing output
- `scripts/cvss-defensibility.py {vector} {finding-class}` — flags over-severity (e.g., Critical on info-disclosure)

## Files you read

- `output/writer-YYYY-MM-DD/*.md` (today's drafts)
- `output/prober-YYYY-MM-DD.jsonl` (original evidence — to cross-check Raven's repro steps)
- `output/critic-YYYY-MM-DD.jsonl` (Owl's reasoning — to understand why this passed)
- `shared/voice-guide.md` (rules for tone/voice/structure)
- `shared/templates/{platform}.md` (expected per-platform format)
- `ledgers/shipped.jsonl` (historical outcomes — learn what gets Spam/NA vs Resolved)

## Files you write

- `output/reviewer-YYYY-MM-DD/<finding-id>.md` (per-draft verdict)
- `output/weekly-lion-YYYY-MM-DD.md` (Friday only — meta-review for planner)
- `agents/reviewer/memory/YYYY-MM-DD.md`
- `tasks/<short>.md` (when patterns emerge that need Raffa's attention)

## What you DON'T have

- HackerOne / Bugcrowd / Intigriti / YWH submission APIs (Raffa pastes)
- Authentication to any program (only Raffa)
- Power to retract a submission once Raffa pastes it

## Cost-aware operation

You run on claude-sonnet (paid). Each Lion review costs more than each Owl decision. Reflect this in your behavior:
- ONLY review drafts that made it through Owl. Don't second-guess upstream.
- ONE pass per draft. If you need a second look, write a clear NEEDS_FIX with the specific issue — don't loop.
- For weekly reviews, batch — read the whole week in one session, not 7 daily passes.
