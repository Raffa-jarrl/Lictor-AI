# Twitter / X — "I audited my own ops dashboard" thread

**Use case:** the demo thread, posted ~2 weeks before the official Oct 6 launch as a "building in public" warmup. Lower stakes than the main launch thread (`twitter-thread.md`), but seeds the audience.

**The story this thread tells:** I built a security tool. To prove it works, I ran it on my own private ops dashboard. It found 3 real bugs. I fixed them in 15 minutes. Here are the bugs, in plain English.

**Why this works as a launch warmup:**

1. It's a true story, not a synthesized demo. The audit log is in `~/GenerationAI/SECURITY-AUDIT.md`. The fix commit is `c7d6bb3` in `~/GenerationAI/`. Anyone who asks for proof can be shown the diff.
2. It demonstrates self-application — "the tool's creator runs it on themselves." This is the strongest credibility signal in security. Bonus: it's slightly self-deprecating ("I built this and missed these bugs"), which reads honest rather than salesy.
3. The findings are in plain English exactly as `/lictor-security-check` outputs them — proves the "no jargon" claim without needing a separate explanation.
4. Every tweet references a real file path. No "imagine if..." copy. Concrete code, concrete fix, concrete time.

---

## The thread (10 tweets — tighter than the main launch thread)

### 1/10

I built a security tool for vibe-coded apps. To prove it works, I ran it on the dashboard I built for my own business.

It found 3 high-severity bugs in 60 seconds.

I fixed them in 15 minutes.

Here's what they were, in plain English ↓

*[attach: screenshot of `/lictor-security-check` chat output showing the verdict]*

---

### 2/10

The dashboard is "mission-control" — a Next.js app I built for managing the AI agent crew that runs my consulting business.

Solo build. Never had it audited. Has been running on my Mac for months.

The audit ran in 60 seconds. Found three things that would have hurt me.

---

### 3/10

**Bug #1: All 20+ API routes had no login check.**

Anyone on the same WiFi as my laptop could navigate to `[mac-ip]:3000/api/customers` and download my full customer pipeline.

Plain-English version (which is what the tool actually printed):

> "Your data is on the open internet"

*[attach: screenshot of finding #1 from SECURITY-AUDIT.md showing the plain-English title]*

---

### 4/10

The fix wasn't complicated. The audit told me:

1. Change `next dev` to `next dev -H 127.0.0.1` (bind to localhost only)
2. Add a 95-line `proxy.ts` that checks for a token or same-origin Referer
3. Generate a random token, put it in `.env.local`

Total time: 12 minutes.

---

### 5/10

**Bug #2: One of my API routes returned my own API keys.**

`/api/config` read my OpenClaw config file and returned the whole thing as JSON — including the auth blobs for every model provider.

Combined with bug #1, anyone on my WiFi could have walked away with my Anthropic key.

---

### 6/10

The fix: instead of returning the config blob, return only the fields the UI needs.

```ts
return NextResponse.json({
  gateway: { host, port },
  agents:  agents.map(a => ({ name: a.name, model: a.model })),
  models:  Object.keys(providers),
});
```

Whitelist beats blacklist. Three minutes.

---

### 7/10

**Bug #3: My internal "chat with Claude" endpoint had no input limit.**

Anyone reachable could `POST /api/claude-chat` with arbitrary prompts and burn through my Claude Max plan.

A script could have drained my monthly token allotment in an afternoon.

---

### 8/10

The fix: 30 lines of input validation + a simple rate limit.

- Reject prompts over 8KB
- Cap at 4 requests/minute per process

Belt and suspenders on top of the auth check from bug #1.

---

### 9/10

The audit tool that found all three is **/lictor-security-check** — one of four free Claude Code skills I'm shipping.

It's not a YAML-config tool you need to learn. You type one command. It reads your project. It writes a markdown report.

It speaks plain English. It tells you what to fix. It doesn't pretend to know more than it does.

---

### 10/10

If you build with AI (Lovable, Bolt, v0, Cursor, Claude directly) — run it on your project before you ship.

Open source, Apache 2.0, no signup, no telemetry phoning home:

🔗 github.com/Raffa-jarrl/Lictor-AI

Install (3 lines):

```bash
git clone https://github.com/Raffa-jarrl/Lictor-AI ~/Code/lictor
mkdir -p ~/.claude/skills
cp -r ~/Code/lictor/skills/lictor-* ~/.claude/skills/
```

Then in Claude Code, from any project: `/lictor-security-check`

---

## What to attach as images

| Tweet | Image | Source |
|---|---|---|
| 1 | The "🟡 Fix before this app ever leaves localhost" verdict (chat output) | Screenshot the actual chat with Claude where the audit verdict was given |
| 3 | The Finding #1 section from `SECURITY-AUDIT.md`, in plain English | Crop the rendered markdown |
| 4 | A diff snippet showing `next dev -H 127.0.0.1` | Either Code screenshot or Carbon |
| 6 | The whitelist code (above) | Carbon-rendered code block |
| 8 | The `RATE_LIMIT_PER_MIN = 4` constants + the `isRateLimited` function | Carbon |
| 10 | The install snippet OR a screenshot of `/lictor-security-check` running with a finding popping up | Real chat screencap |

---

## Reply hooks for the first 4 hours

**Expected question:** "Did you really find this on your own production system?"
**Answer:** Yes. The repo is private but the audit file + the fix commit are public on the lictorai.com/blog/dogfood page (link in bio). Specifically, mission-control is a Next.js 16 app and the proxy.ts fix is 95 lines.

**Expected question:** "What's different from Lakera/Protect AI/etc.?"
**Answer:** They're enterprise SaaS. I built four free Claude Code skills. Same engine, three orders of magnitude lower friction. The tools are at github.com/Raffa-jarrl/Lictor-AI.

**Expected question:** "Can I just see what it found?"
**Answer:** Yes — pasted the full SECURITY-AUDIT.md as a GitHub gist: [link to gist]. Look at the "plain English" descriptions — that's the voice the audit ships in by default.

**Expected pushback:** "This is just regex/static analysis, not a real security tool."
**Answer:** Correct. It's a pre-deploy linter for the 7 most common AI-built-app bugs, not a pentest replacement. The README says exactly this. The point is it catches the bugs that get founders publicly humiliated, with zero install friction. After deploy, you graduate to @lictor/sentinel for runtime protection.

---

## Posting cadence

- **Day 0** (publish): post the thread, pin it
- **Day 0 + 4h**: retweet tweet #3 from personal account
- **Day 0 + 24h**: reply to the thread with "engagement notes" — what surprised me most about my own bugs, what other patterns I see most in friend repos
- **Day 0 + 72h**: cross-post the thread as a LinkedIn post (longer-form). LinkedIn audience cares about the "20-year cybersec engineer" framing more than Twitter does — emphasize that.

---

## What this thread is NOT

- Not the launch thread for Oct 6. That's the more polished `twitter-thread.md` covering all four products in the suite + the AI-agent-era frame.
- Not a pitch for Sentinel / Guardian. Those are mentioned in tweet 9-10 as the next products in the suite; the thread itself is purely about the audit skill.
- Not a fundraising thread. No mention of funding, hiring, business model. This is product credibility content.

---

*Source material: `~/GenerationAI/SECURITY-AUDIT.md` + commit `c7d6bb3` in the same repo. The thread is one possible framing of that story; if a different framing tests better, this doc is the starting point not the final.*
