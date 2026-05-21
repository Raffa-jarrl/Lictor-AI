# Telegram bot setup for Lictor v3

One-time setup (~5 minutes). After this, every Lion+Oracle-approved finding lands in your Telegram chat with inline ✅/❌ buttons.

## 1. Create the bot via @BotFather

1. Open Telegram. Search for `@BotFather`. Start a chat.
2. Send `/newbot`.
3. BotFather asks for a name: type something like `Lictor v3 Approvals`.
4. BotFather asks for a username: type something ending in `bot`, e.g. `LictorV3ApprovalsBot`.
5. BotFather returns your **bot token**. Looks like `1234567890:ABCDEFghijk-LMNOPqrstuv...`. **Save this — it's your bot's password.**

## 2. Find your chat ID

You need to tell the bot WHO to message (you). Two ways:

### Option A: use @userinfobot
1. Search for `@userinfobot` on Telegram. Start a chat.
2. It immediately replies with your numeric chat ID. Looks like `123456789`.

### Option B: message your new bot first, then query
1. Search for your bot by its username (e.g., `@LictorV3ApprovalsBot`). Start a chat.
2. Send any message (e.g. "hello").
3. In a terminal, fetch the chat ID:
   ```bash
   curl "https://api.telegram.org/bot<YOUR-BOT-TOKEN>/getUpdates" | python3 -m json.tool | grep '"id"' | head -3
   ```
4. Find the `"id"` under the `"chat"` object — that's your chat ID.

## 3. Store the credentials

```bash
mkdir -p ~/.lictor/secrets && chmod 700 ~/.lictor/secrets

# Bot token (from BotFather)
echo "1234567890:ABCDEFghijk-LMNOPqrstuv..." > ~/.lictor/secrets/telegram.bot-token
chmod 600 ~/.lictor/secrets/telegram.bot-token

# Your personal chat ID
echo "123456789" > ~/.lictor/secrets/telegram.chat-id
chmod 600 ~/.lictor/secrets/telegram.chat-id
```

## 4. Test the integration

```bash
# Should send "Lictor v3 alive" to your Telegram chat
python3 ~/Lictor/v3/scripts/telegram-test.py
```

If you see the message arrive on Telegram → setup complete.

If not, check:
- Bot token file exists and is readable
- Chat ID file exists and is correct (you sent at least one message to the bot first)
- Bot is not blocked in your Telegram client

## 5. Privacy / control

- The bot ONLY messages YOUR chat ID. No one else can receive Lictor messages.
- You can MUTE the bot in Telegram if you don't want notifications during a meeting (messages still arrive, just no sound).
- You can BLOCK the bot at any time. The Submitter detects this (Telegram returns 403) and falls back to deferring all findings until you re-enable.
- Bot conversations stay in your Telegram history — useful as a permanent audit trail of every approval/defer decision.

## 6. Group chat option (NOT recommended for Lictor)

You CAN add the bot to a group chat instead of using your personal chat. Lictor messages would then go to the group. BUT:
- Tap-button callbacks are per-user (anyone in the group could tap)
- Security risk: a coworker could approve a submission you'd reject
- For Lictor specifically, stick with personal-chat-only

## 7. Telegram message rate limits

Telegram Bot API allows:
- 30 messages/second to different chats (we only message 1 chat — irrelevant)
- 1 message/second to the same chat (Lictor sends ~5-10/day — irrelevant)
- 20 messages/minute to large groups (not applicable to us)

Lictor's load is tiny relative to Telegram limits. No throttling concerns.

## 8. Inline button mechanics

Telegram inline buttons fire `callback_query` events. The Submitter has a poller:

```python
# scripts/submitter-poll.py — runs every 30 seconds
import urllib.request, json
TOKEN = open(os.path.expanduser("~/.lictor/secrets/telegram.bot-token")).read().strip()
offset = 0  # tracks already-processed callbacks

while True:
    resp = json.load(urllib.request.urlopen(
        f"https://api.telegram.org/bot{TOKEN}/getUpdates?offset={offset}&timeout=25"
    ))
    for update in resp["result"]:
        offset = update["update_id"] + 1
        if "callback_query" in update:
            cb = update["callback_query"]
            finding_id = cb["data"]  # e.g., "SUBMIT:elastic-docs-staging-vercel-takeover-2026-05-20"
            action, fid = finding_id.split(":", 1)
            if action == "SUBMIT":
                trigger_platform_api_submit(fid)
            elif action == "DEFER":
                move_to_deferred(fid)
            elif action == "VIEW":
                send_full_draft_as_file(fid, cb["from"]["id"])
            # ACK the callback (removes the loading spinner from the button)
            urllib.request.urlopen(
                f"https://api.telegram.org/bot{TOKEN}/answerCallbackQuery?callback_query_id={cb['id']}"
            )
```

This poller runs as a launchd daemon. When it sees a callback, it acts.

## What you'll see on your phone

After setup, when Lion+Oracle approve a finding, your Telegram looks like:

```
[LictorV3ApprovalsBot, 03:24]

🦉 Lion APPROVED + 🧙 Oracle GO

Finding: CORS reflect-with-creds on api.au.frontegg.com
Platform: HackerOne — Frontegg program
Severity: High (CVSS 8.1)
Estimated payout: $500–$2,500

[ otter probe summary, owl reasoning, lion verdict, oracle verdict ]

[✅ SUBMIT NOW]  [❌ DEFER]  [✏️ VIEW FULL DRAFT]
```

You tap. Within 5 seconds, you get a confirmation:

```
[LictorV3ApprovalsBot, 03:24]

✅ Submitted to HackerOne — report #3749999 created.
   Triage status: Pending. I'll notify you when it moves.
```

That's the entire user experience. From any device. From anywhere. With full audit trail.
