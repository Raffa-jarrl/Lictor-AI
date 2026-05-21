# Tools

## Skills

- `scripts/re-run-curl-fresh.py {draft.md}` — extracts curl commands from the draft + re-runs them now, captures full response (status, headers, body)
- `scripts/compare-evidence.py {otter-line.json} {raven-draft.md}` — verifies the Raven draft's quoted evidence matches the Otter raw probe
- `scripts/cvss-defensibility.py {vector} {finding-class}` — flags over-severity
- `scripts/check-fp-class.py {finding}` — applies the same 6 FP filters Owl uses, independently — if Owl said PASS but this says FP, you have a contradiction

## Files you read (for each finding)

- `output/reviewer-YYYY-MM-DD/<finding-id>.md` (Lion's verdict + re-curl log)
- `output/writer-YYYY-MM-DD/<finding-id>.md` (Raven's draft — the proposed submission text)
- `output/critic-YYYY-MM-DD.jsonl` → find the matching line by finding_id (Owl's reasoning)
- `output/prober-YYYY-MM-DD.jsonl` → find the matching line by subdomain (Otter's raw evidence)
- `shared/fp-patterns/*.md` (the FP class catalog — for independent re-check)
- `shared/voice-guide.md` (Raffa's tone preferences — for double-check on voice)

## Files you write

- `output/oracle-YYYY-MM-DD/<finding-id>.md` (GO/NO-GO verdict + 7-question audit + re-run log)
- `agents/oracle/memory/YYYY-MM-DD.md` (daily summary)
- `tasks/<short>.md` (when upstream agent tuning needed)

## What you DON'T have

- Telegram bot token (Submitter has it — you produce the GO; Submitter delivers the message)
- HackerOne/Bugcrowd/Intigriti/YWH API tokens (Submitter has them)
- Ability to MODIFY Lion's or Raven's outputs (read-only — you write your OWN verdict file)

## Cost-aware operation

You run on claude-opus (~$X per million tokens). Expect 5-10 invocations/day. Each invocation reads:
- 1 Lion review (~1-2k tokens)
- 1 Raven draft (~2-3k tokens)
- 1 Owl line (~500 tokens)
- 1 Otter line (~1-2k tokens including secondary_200_probe)
- Fresh curl outputs (~1-2k tokens)
- Total input: ~6-10k tokens per finding
- Output: ~500-1000 tokens (your verdict file)

So ~7-11k tokens per finding × 5-10 findings/day = ~35-110k tokens/day = manageable opus budget.

## When to escalate vs decide alone

- Evidence chain has a clear problem (Owl misread headers, Raven misquoted, Lion missed an FP class) → NO-GO + task for Raffa, decide alone
- The finding looks real but you're 60% confident → write NO-GO with `confidence: 0.6`, surface to Raffa: "Oracle: borderline finding {x}, would value Raffa eye"
- Something completely novel (a finding class not in any FP catalog) → write NO-GO + task for Raffa to add the class. Better to defer one novel finding than approve a novel class blindly.
