# Lictor Security Suite — Claude Code plugins

> Four free plugins that keep your AI-built app from doing something stupid in public.

If you built your app with Lovable, Bolt, v0, Cursor, or by prompting Claude/ChatGPT — the AI didn't tell you about the bugs that get founders publicly embarrassed. This suite catches them before you ship.

**No jargon. No "SOC 2 control mapping." No enterprise sales call.** It looks at your code, tells you what's broken in plain English, and walks you through fixing it.

## The four plugins

| Plugin | What it does | When to run it |
|---|---|---|
| **`/lictor-security-check`** | Scans your project for 7 common bugs that get AI-built apps hacked | Before you deploy. Before you tweet about your app. Before you send it to a customer. |
| **`/lictor-explain`** | Takes any security finding and explains it like you're talking to a friend | When you don't understand what the audit found, or what an error means |
| **`/lictor-fix-it`** | Applies the fixes the audit recommended (with your permission) | After you read the audit and decided you want help fixing it |
| **`/lictor-rotate`** | Walks you through rotating a leaked API key — step by step | When the audit found a key in your code that's been pushed to the internet |

All four are open-source (Apache 2.0), free forever, no signup, no telemetry leaving your machine.

## Five real stories (this is what we're trying to prevent)

These are composite stories from real founders. Names changed. The bugs are real and we see them every week.

### Sarah: the Lovable founder who almost ate a $50K Stripe bill

Sarah built a paid SaaS in Lovable over a weekend. Stripe checkout, Supabase database, OpenAI for the AI feature. She was about to send the URL to her first 10 beta testers — paid customers at $20/mo each.

She ran `/lictor-security-check`. The audit found her **Stripe live secret key** in her JavaScript bundle. Anyone who opened DevTools on her site could copy that key and use it to make charges on her account.

The fix took 5 minutes. She rotated the key, moved the new one to her server-side environment variables, deployed.

If she'd skipped the check: at her launch traffic of 50 visitors on day one, she'd have had maybe a 5% chance of someone noticing the key. At 5,000 visitors on month two, it's a coin flip. At 50,000 visitors by month six, someone definitely finds it. Worst case: tens of thousands in fraudulent charges before Stripe's anomaly detection kicks in.

**She avoided the worst day of her founder life.**

### Marcus: the Bolt builder whose user list got tweeted

Marcus built a productivity app in Bolt. Launched on Twitter. By hour 18 a security researcher tweeted a screenshot of his full user table — every user's email and name. Marcus's `/api/users` route returned the whole database with no authentication check. The AI generated the endpoint, didn't generate the auth check, and Marcus didn't know enough to add it.

He spent the next 48 hours emailing his 200 users apologizing.

If he'd run `/lictor-security-check` before launch: the audit would have flagged that route on line 8 of `src/app/api/users/route.ts`. The fix is 4 lines of code.

**The audit would have saved 48 hours of damage control and a Twitter callout that still ranks first in his Google results.**

### Aisha: the Cursor user whose AI tutor got jailbroken

Aisha built an AI tutor for kids using Cursor. She wrapped OpenAI's chat completions API. Within two days of going public, screenshots circulated of her tutor giving explicit content to students after a "ignore previous instructions" prompt.

The press response was brutal. She had to pull the app.

If she'd run `/lictor-security-check`: the audit would have flagged her AI endpoint and walked her through installing `@lictor/sentinel` — a one-line wrap of her OpenAI client that blocks the 32 most common jailbreak patterns.

**Five minutes of work would have prevented a brand-destroying incident.**

### Daniel: the v0 builder who exposed his `.env` file

Daniel built a marketing site in v0.dev. He had API keys in a `.env` file. His deploy script copied the entire project directory to the build output. When the site went live, navigating to `yoursite.com/.env` returned every key he'd ever used.

He noticed three months later because his AWS bill suddenly included $4,000 of crypto-mining traffic.

If he'd run `/lictor-security-check` before deploy: the audit would have shown the `.env` file inside the `out/` build directory. One line in his `.vercelignore` would have fixed it.

**Three months of leaked-key abuse, fixable in 30 seconds.**

### Priya: the Claude builder who shipped Supabase with RLS off

Priya built an MVP by prompting Claude directly. She used Supabase. She never enabled Row Level Security because she didn't know it existed. Her Supabase anon key was in her client code — by design, that's fine — but with RLS off, that key was effectively a master password to her whole database.

Six weeks in, a competitor downloaded her full customer list and re-engaged her users with their own product.

If she'd run `/lictor-security-check`: it would have noticed her client code queries Supabase tables with no RLS migrations in the repo, and warned her exactly which tables needed lockdown.

**She'd still have her users.**

## What kind of bugs the suite catches

In plain language:

1. **Keys you weren't supposed to share.** API keys that ended up in your website's JavaScript or in files you put online.
2. **The "open door" mistake.** API routes (`/api/users`, `/api/orders`) that return your data to anyone who asks, no login required.
3. **The "lock that's only painted on" mistake.** Admin pages that "redirect to login if you're not signed in" — but only after sending you the data. Someone with DevTools can read everything before the redirect happens.
4. **The "unlocked database" mistake.** Supabase or Firebase set up without security rules, so anyone with your public key can read every row.
5. **The "we let everyone in" mistake.** CORS settings that let any website on the internet read your authenticated API responses.
6. **The "the AI will do whatever you tell it" mistake.** Chat features that pass user input straight to an AI with no defense — users tell your AI to ignore its rules, and it does.
7. **The "we left the diary on the porch" mistake.** Config files (`.env`, `.git`) that got bundled into your deployed site.

## Install

```bash
git clone https://github.com/Raffa-jarrl/Lictor-AI.git ~/Code/lictor
mkdir -p ~/.claude/skills
cp -r ~/Code/lictor/skills/lictor-* ~/.claude/skills/
```

Then in any Claude Code session, from your project directory:

```
/lictor-security-check
```

## Who built this

A 20-year cybersecurity engineer who got tired of watching artists ship vibe-coded apps with bugs that get them publicly humiliated.

Most security software is built for people who already speak the language. SOC 2, GDPR, OWASP, CVE — these are real things, but if you're trying to launch a SaaS over the weekend, those words mean nothing to you. You don't have a compliance team. You don't have a security engineer. You have you, your laptop, and an AI assistant.

Lictor is built for you.

The same engine in this skill suite also powers:
- **[Lictor Shield](https://lictor.ai)** — a free Chrome extension that warns you when an AI-built site you're about to sign up for has these bugs
- **[Lictor Sentinel](https://lictor.ai)** — a free SDK (`npm install @lictor/sentinel`) that wraps your AI calls and blocks attacks in production
- **[Lictor Guardian](https://lictor.ai)** — a free hosted dashboard if your team wants to track AI safety incidents across multiple apps

All four are open source. All four are free to use. There is no paid trap.

If this helps you, star the repo: [github.com/Raffa-jarrl/Lictor-AI](https://github.com/Raffa-jarrl/Lictor-AI).

## License

Apache 2.0.
