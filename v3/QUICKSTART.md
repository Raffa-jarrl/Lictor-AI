# Lictor v3 — Quickstart (after fresh build)

You're sitting in front of the Mac Mini M4. v3 is built. Here's the 8-step path from "files on disk" to "Telegram message arriving on your phone with a submit button".

## 1. Pull Ollama models (if not already)

```bash
ollama pull mistral:7b          # Hawk + Otter
ollama pull qwen2.5:14b         # Orca + Raven
ollama pull deepseek-r1:14b     # Owl
# Anthropic models (Lion + Oracle) run via the API — no local pull
```

## 2. Authenticate Anthropic in OpenClaw

```bash
openclaw infer model auth login --provider anthropic
# Follow the prompts. Sets up claude-sonnet-4-5 (Lion) and claude-opus-4-1 (Oracle).
```

## 3. Register the 7 agents

```bash
bash ~/Lictor/v3/scripts/register-agents.sh
```

Verify:
```bash
openclaw agents list | grep lictor-v3   # should show 7 entries
```

## 4. Set up the Telegram bot (5 minutes — see `docs/TELEGRAM-SETUP.md` for full walkthrough)

```bash
# Create the bot via @BotFather on Telegram, get the token. Then:
mkdir -p ~/.lictor/secrets && chmod 700 ~/.lictor/secrets
echo "YOUR-BOT-TOKEN" > ~/.lictor/secrets/telegram.bot-token
echo "YOUR-CHAT-ID" > ~/.lictor/secrets/telegram.chat-id
chmod 600 ~/.lictor/secrets/telegram.*
```

Test:
```bash
python3 ~/Lictor/v3/scripts/telegram-test.py
# Expect "✅ Test message sent successfully!" + a Telegram message arrives.
```

## 5. Set platform tokens (only the ones you actually use)

```bash
# HackerOne — token from https://hackerone.com/settings/api_token
echo "raffaja:YOUR-H1-API-TOKEN" > ~/.lictor/secrets/hackerone.token
chmod 600 ~/.lictor/secrets/hackerone.token

# Optional: bugcrowd / intigriti / yeswehack tokens (see docs/SUBMIT-FLOW.md)
```

## 6. Start the Submitter daemon

```bash
# Test in dry-run mode first — composes Telegram messages but DOESN'T call platform APIs
python3 ~/Lictor/v3/scripts/submitter.py --dry-run --once

# When happy, install as launchd daemon for permanent operation
cp ~/Lictor/v3/launchd/com.lictor.v3.submitter.plist ~/Library/LaunchAgents/
launchctl load -w ~/Library/LaunchAgents/com.lictor.v3.submitter.plist

# Verify it's running
launchctl list | grep lictor   # should show com.lictor.v3.submitter

# Logs
tail -f ~/Lictor/v3/output/submitter.log
```

## 7. Verify the ledgers (the encoded findings from 2026-05-21)

```bash
wc -l ~/Lictor/v3/ledgers/*.jsonl
# Expect:
#   6 confirmed.jsonl      — the 4 banked CORS + Elastic + Topperpay
#   4 disclosure-cases.jsonl
#   1 needs-verification.jsonl
#   7 filtered-fps.jsonl
```

## 8. Trigger the first pipeline run

```bash
# Manual trigger (instead of waiting for 06:00 IST cron)
openclaw run lictor-v3-planner

# Then watch the funnel
tail -f ~/Lictor/v3/output/scout-*.jsonl    # Hawk's output
tail -f ~/Lictor/v3/output/prober-*.jsonl   # Otter's output
tail -f ~/Lictor/v3/output/critic-*.jsonl   # Owl's output
ls -la ~/Lictor/v3/output/writer-*/         # Raven's drafts
ls -la ~/Lictor/v3/output/reviewer-*/       # Lion's verdicts
ls -la ~/Lictor/v3/output/oracle-*/         # Oracle's verdicts
```

When Oracle writes a GO file, the Submitter daemon picks it up within 30s and sends a Telegram message. You tap. If you tap ✅ SUBMIT, the platform API call fires (or, in dry-run, just logs the intent).

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Submitter exits immediately | Token file missing or wrong perms | Check `ls -la ~/.lictor/secrets/` — all files should be `-rw-------` (0600) |
| Telegram test fails with 401 | Bot token wrong | Re-check BotFather conversation, copy token exactly |
| Telegram test sends but no message | Chat ID wrong | Send any message to your bot first, then re-fetch chat ID via @userinfobot |
| Owl never produces passes | Probe data too thin OR Owl's bar too high | Check `agents/critic/memory/*` for Owl's reasoning; tune fingerprints |
| Oracle NO-GOs everything | Oracle's bar too high OR Lion is approving FPs | Read `agents/oracle/memory/*` for patterns; tighten upstream |
| `openclaw agents list` doesn't show lictor-v3 | Gateway not running | `openclaw gateway start` then re-run register-agents.sh |
| Platform submit returns 422 | Lion's draft has a validation issue | Check the error body in submitter logs, fix in Raven template |

## When it's working

You'll see a flow like this in your Telegram:

```
[03:24, LictorV3ApprovalsBot]
🦉 Lion APPROVED + 🧙 Oracle GO
Finding: CORS reflect-with-creds on api.au.frontegg.com
[✅ SUBMIT NOW] [❌ DEFER] [✏️ VIEW]
```

You tap ✅. Five seconds later:

```
[03:24, LictorV3ApprovalsBot]
✅ Submitted to HackerOne — report #3749999 created.
Triage status: Pending. I'll notify you when it moves.
```

That's the entire user experience. From any device. From anywhere. With full audit trail.
