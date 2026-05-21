# Submission flow — Lion → Oracle → Telegram → API

## The principle

Lion gold-stamps. **Oracle (opus) does a META-verification of the whole chain.** If Oracle says GO, a Telegram message fires to Raffa's bot chat. Raffa taps an inline button. If ✅ → agent submits via platform API. If ❌ → defer.

**Total friction: 1 tap. Total time from Lion-approve to platform-submit: ≤ 60 seconds (the 30s extra is Oracle's opus run).**

## Why two QA layers (Lion + Oracle)

| Lion (sonnet) | Oracle (opus) |
|---|---|
| Per-draft technical QA | Meta review of whole chain |
| Voice, scope, severity, ethics footer | Does Owl's reasoning + Raven's draft + Lion's verdict all hang together? |
| Re-runs curls in the draft | Re-runs curls FRESH (catches changes since Lion's review) |
| ~10-20 drafts/day | ~5-10 Lion-APPROVED drafts/day |
| Approves drafts | Approves Lion's approvals |

Two-layer review = defense-in-depth. Lion catches per-draft issues. Oracle catches chain-level issues that Lion missed because Lion only sees the draft, not the full evidence trail.

## Architecture

```
Otter probes → output/prober-YYYY-MM-DD.jsonl
                                       │
                                       ▼
Owl filters → output/critic-YYYY-MM-DD.jsonl (passes)
                                       │
                                       ▼
Raven drafts → output/writer-YYYY-MM-DD/<finding-id>.md
                                       │
                                       ▼
Lion QAs → output/reviewer-YYYY-MM-DD/<finding-id>.md (APPROVE/REJECT/NEEDS_FIX)
                                       │
                                  if APPROVE
                                       ▼
🧙 Oracle audits (claude-opus, 7-question audit + fresh curl re-run)
   → output/oracle-YYYY-MM-DD/<finding-id>.md (GO/NO-GO)
                                       │
                                   if GO
                                       ▼
Submitter composes payload + sends Telegram:
   Title: "Lion+Oracle approved: {title}"
   Body: <draft preview>
   Buttons: [✅ SUBMIT] [❌ DEFER] [✏️ VIEW FULL DRAFT]
                                       │
                                       ▼
Raffa taps ✅ on Telegram
                                       │
                                       ▼
Submitter calls platform API:
   - HackerOne: POST /v1/reports
   - Bugcrowd: POST /v2/submissions
   - Intigriti: POST /external/researcher/v1/submissions
   - YesWeHack: POST /api/private/programs/{slug}/reports
                                       │
                                       ▼
Append outcome to ledgers/shipped.jsonl
                                       │
                                       ▼
Track triage status (poller runs hourly, updates ledgers/shipped.jsonl)
                                       │
                                       ▼
When status changes (Triaged / Resolved / NA / Spam):
   → Append outcome to ledgers/shipped.jsonl
   → Trigger Lion's weekly review (incorporate outcome into next week's calibration)
   → Notify Raffa via Telegram of any Resolved (positive signal event!)
```

## Telegram message format

What lands in Raffa's Telegram chat (one message per Lion+Oracle-approved finding):

```
🦉 Lion APPROVED + 🧙 Oracle GO

Finding: CORS reflect-with-creds on api.au.frontegg.com
Platform: HackerOne — Frontegg program
Severity: High (CVSS 8.1)
Estimated payout: $500–$2,500

🦦 Otter probe: api.au.frontegg.com/identity/resources/users/v3/me → 401
   + acao=<attacker> + acac=true + permissive PUT/POST/DELETE

🦉 Owl reasoning: gateway-level CORS template, applies to authenticated
   /me responses = real PII exfil

🦁 Lion verdict: APPROVE (re-curl matched, voice clean, scope cited)

🧙 Oracle verdict: GO (re-curl now still matches, severity defensible,
   ethics footer present)

[✅ SUBMIT NOW] [❌ DEFER] [✏️ VIEW FULL DRAFT]
```

Tap any button → callback fires within seconds.

## Authentication / token storage

Raffa sets these ONCE on his Mac Mini:

```bash
mkdir -p ~/.lictor/secrets && chmod 700 ~/.lictor/secrets

# Telegram bot (created via @BotFather on Telegram)
echo "1234567:ABCdef..." > ~/.lictor/secrets/telegram.bot-token
echo "123456789" > ~/.lictor/secrets/telegram.chat-id
chmod 600 ~/.lictor/secrets/telegram.*

# Bug bounty platform tokens (one per platform Raffa uses)
echo "raffaja:YOUR-H1-TOKEN" > ~/.lictor/secrets/hackerone.token
echo "YOUR-BC-TOKEN" > ~/.lictor/secrets/bugcrowd.token
echo "YOUR-INTIGRITI-TOKEN" > ~/.lictor/secrets/intigriti.token
echo "YOUR-YWH-TOKEN" > ~/.lictor/secrets/yeswehack.token
chmod 600 ~/.lictor/secrets/*.token
```

Tokens are read at submit time. Never logged. Never committed.

Full Telegram bot setup walkthrough: see `docs/TELEGRAM-SETUP.md`.

## Failure modes

| Failure | Recovery |
|---|---|
| Oracle NO-GO | Move to `ledgers/deferred.jsonl` with Oracle's reasoning. No Telegram message fires. Raffa sees it in next morning's briefing. |
| Telegram bot token missing | Submitter declines, writes task: "Set up Telegram bot per docs/TELEGRAM-SETUP.md" |
| Telegram API returns 401 | Token rotated/expired. Same as above. |
| Telegram message fires but Raffa doesn't tap in 4 hours | Default to ❌ DEFER. Move to `ledgers/deferred.jsonl`. Try again tomorrow. |
| Raffa taps ❌ DEFER | Move to `ledgers/deferred.jsonl` with reason. |
| Raffa taps ✏️ VIEW FULL DRAFT | Bot replies with the full Raven draft as a file attachment. Inline buttons re-present. |
| Platform API token missing | Submitter declines, writes task for Raffa to generate. |
| Platform API returns 422 (validation error) | Task for Lion to re-review with the specific validation error. |
| Platform API returns 429 (rate limit) | Wait 1 hour, retry once. If still rate-limited, defer. |
| Platform doesn't have an API for submission | Telegram message includes the paste-ready text + direct submit URL. Raffa pastes manually. |

## What the system NEVER does

- ❌ Submit without Lion APPROVE + Oracle GO + Raffa tap
- ❌ Bypass Oracle (Lion-APPROVE alone is NOT sufficient)
- ❌ Resubmit a deferred finding without Raffa's explicit re-request via Telegram
- ❌ Submit on weekend (Raffa's policy: weekday submissions only — triagers respond faster)
- ❌ Send a Telegram message without Oracle's GO (a message that lies to Raffa = worst outcome)

## Implementation status

- [x] Architecture (this doc) ✅
- [x] Token storage convention ✅
- [x] Oracle agent (SOUL + AGENTS + TOOLS + USER + IDENTITY) ✅
- [ ] Telegram bot setup walkthrough (next: docs/TELEGRAM-SETUP.md)
- [ ] Submitter tool implementation (Python — Telegram API client + per-platform API client + callback handler)
- [ ] Triage-status poller (Python — hourly cron, updates shipped.jsonl)
