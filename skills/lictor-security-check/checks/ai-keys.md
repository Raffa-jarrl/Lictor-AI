# Check — Leaked AI keys (the flagship check)

**What you're looking for:** the secret key for an AI provider — OpenAI, Anthropic, Gemini, HuggingFace, Groq, Replicate and friends — sitting somewhere a stranger can read it. That means: hardcoded in front-end code, committed to the repo, or baked into a mobile app you handed to the App Store. These are the keys that bill *you* by the token. This is the bug that gets vibe-coded AI apps drained in a weekend, and it's the single most common thing we find — so we scan for it hard.

This is the AI-specific cousin of the general "secrets in code" check. That one casts a wide net (database URLs, Stripe, GitHub tokens). This one goes deep on the keys that make an AI app an AI app, and especially on the two places founders leak them: **the browser bundle** and **the mobile binary**.

## Why this one matters more than the others

A leaked database password is bad. A leaked AI key is bad *and* metered. The moment your key is public:

- Bots scrape it (GitHub, npm, and public Cloudflare/Vercel deploys are crawled within **minutes**).
- They run it flat-out — usually mining crypto-adjacent junk, reselling your quota, or generating spam.
- Your provider bill goes from $12 to $4,000 before the alert email arrives.
- Anthropic / OpenAI keys especially: they're priced per-token and have high default limits. A scraped `sk-ant-` key has cost people thousands overnight.

So when this check fires, it's a "do not ship, rotate tonight" situation, not a backlog item.

## How to scan

You're reading the repo — no paid scanner, no network calls. Run these from the project root.

### 1. The provider-key grep (all stacks at once)

Secret keys have strong, recognizable prefixes. Matching the prefix keeps false positives near zero.

```bash
# AI provider secret keys — strong-prefix patterns
grep -rEn \
  --exclude-dir={node_modules,.next,dist,build,.git,.turbo,out,vendor,Pods,.dart_tool,build,DerivedData} \
  'sk-ant-api[0-9]{2}-[A-Za-z0-9_-]{40,}|sk-proj-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{20,}|AIza[A-Za-z0-9_-]{35}|hf_[A-Za-z0-9]{30,}|gsk_[A-Za-z0-9]{40,}|r8_[A-Za-z0-9]{30,}|pplx-[A-Za-z0-9]{40,}|csk-[A-Za-z0-9]{20,}|xai-[A-Za-z0-9]{40,}|key-[a-f0-9]{32}' \
  . 2>/dev/null
```

| Prefix | Provider | Severity if exposed |
|---|---|---|
| `sk-ant-api03-…` | Anthropic | 🔴 CRITICAL |
| `sk-proj-…` / `sk-…` | OpenAI (project + legacy) | 🔴 CRITICAL |
| `AIza…` (35 chars) | Google — Gemini / AI Studio / Cloud | 🟠 HIGH (see Firebase note below) |
| `hf_…` | HuggingFace | 🟠 HIGH |
| `gsk_…` | Groq | 🟠 HIGH |
| `r8_…` | Replicate | 🟠 HIGH |
| `pplx-…` | Perplexity | 🟠 HIGH |
| `csk-…` | Cohere | 🟠 HIGH |
| `xai-…` | xAI (Grok) | 🟠 HIGH |
| `key-…` (32 hex) | Mistral (older format) | 🟠 HIGH |

The two `sk-` rows are CRITICAL because they're the biggest, most aggressively scraped, highest-default-limit keys on the internet. Everything else is HIGH — still rotate tonight, just less likely to bankrupt you by breakfast.

### 2. Find where the key actually *lives* (this decides severity)

A key in a server-only file that's properly git-ignored is a near-miss. A key in the browser bundle is already public. So after you get hits, ask: **can a stranger reach this file?**

```bash
# Is the key in CLIENT-side code? (this is the worst case — it ships to every visitor)
grep -rEn \
  --include='*.tsx' --include='*.jsx' --include='*.vue' --include='*.svelte' \
  --include='*.html' \
  --exclude-dir={node_modules,.next,dist} \
  'sk-ant-|sk-proj-|sk-[A-Za-z0-9]{20}|hf_|gsk_|r8_|AIza' . 2>/dev/null

# Is it exposed through a PUBLIC env var? (NEXT_PUBLIC_, VITE_, REACT_APP_, EXPO_PUBLIC_, PUBLIC_ all ship to the browser)
grep -rEn \
  --exclude-dir={node_modules,.next,dist,.git} \
  '(NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|PUBLIC_|VUE_APP_|GATSBY_)[A-Z_]*(OPENAI|ANTHROPIC|CLAUDE|GEMINI|GOOGLE|GROQ|HUGGING|HF|REPLICATE|MISTRAL|COHERE|PERPLEXITY|AI)[A-Z_]*KEY' \
  . 2>/dev/null

# Is the key already committed to git history? (deleting the file later does NOT remove it)
git log --all -p -S 'sk-ant-api' -S 'sk-proj-' 2>/dev/null | grep -E 'sk-(ant-api|proj-)' | head -5
git log --all --pretty=format: --name-only --diff-filter=A 2>/dev/null | sort -u | grep -E '\.env(\.|$)' | head
```

The env-var grep is the highest-value line here. **Any framework prefix like `NEXT_PUBLIC_`, `VITE_`, `EXPO_PUBLIC_`, or `REACT_APP_` means "inline this into the JavaScript the browser downloads."** Founders constantly name a key `NEXT_PUBLIC_OPENAI_KEY` because the non-public version "didn't work in the component" — and that single prefix turns a private key into a public one. Treat a real AI secret behind a `*_PUBLIC_*` var as already-leaked.

### 3. Mobile — the bundle is not a vault

Mobile devs assume a compiled app hides its secrets. It doesn't — anyone can unzip an `.ipa`/`.apk` and `strings` it in 30 seconds. Scan the source AND any built artifacts.

```bash
# Swift / iOS
grep -rEn --include='*.swift' --include='*.plist' --include='*.xcconfig' \
  'sk-ant-|sk-proj-|sk-[A-Za-z0-9]{20}|AIza|hf_|gsk_|r8_' . 2>/dev/null

# Kotlin / Java / Android (incl. resource & gradle files where keys love to hide)
grep -rEn --include='*.kt' --include='*.java' --include='*.xml' \
  --include='*.properties' --include='*.gradle' --include='*.gradle.kts' \
  --exclude-dir={build,.gradle} \
  'sk-ant-|sk-proj-|sk-[A-Za-z0-9]{20}|AIza|hf_|gsk_|r8_' . 2>/dev/null

# Flutter / Dart
grep -rEn --include='*.dart' --exclude-dir={.dart_tool,build} \
  'sk-ant-|sk-proj-|sk-[A-Za-z0-9]{20}|AIza|hf_|gsk_|r8_' . 2>/dev/null

# React Native (JS/TS + the native shells)
grep -rEn --include='*.ts' --include='*.tsx' --include='*.js' \
  --exclude-dir={node_modules,ios/Pods,android/build} \
  'sk-ant-|sk-proj-|sk-[A-Za-z0-9]{20}|AIza|hf_|gsk_|r8_' . 2>/dev/null

# A built mobile artifact lying around? Confirm the leak the way an attacker would:
#   unzip -p app.apk | strings | grep -E 'sk-(ant|proj)|AIza|hf_'
#   strings MyApp.ipa | grep -E 'sk-(ant|proj)|AIza|hf_'
```

If you find a real key in `Info.plist`, `local.properties`, `strings.xml`, a `--dart-define` baked into the build, or any committed `.env` next to the mobile project — that key ships inside every install. CRITICAL, because you can't quietly rotate it: existing app installs keep the old key until users update.

### 4. Other stacks (server-side leaks still count)

Even server keys leak when committed to a public repo or printed into logs.

```bash
# Python — .py, notebooks, settings, Django/Flask config
grep -rEn --include='*.py' --include='*.ipynb' --include='*.cfg' --include='*.toml' \
  --exclude-dir={venv,.venv,__pycache__,site-packages} \
  'sk-ant-|sk-proj-|sk-[A-Za-z0-9]{20}|AIza|hf_|gsk_|r8_' . 2>/dev/null

# Go
grep -rEn --include='*.go' --exclude-dir=vendor \
  'sk-ant-|sk-proj-|sk-[A-Za-z0-9]{20}|AIza|hf_|gsk_|r8_' . 2>/dev/null

# Ruby
grep -rEn --include='*.rb' --include='*.erb' --include='*.yml' \
  'sk-ant-|sk-proj-|sk-[A-Za-z0-9]{20}|AIza|hf_|gsk_|r8_' . 2>/dev/null

# PHP
grep -rEn --include='*.php' --exclude-dir=vendor \
  'sk-ant-|sk-proj-|sk-[A-Za-z0-9]{20}|AIza|hf_|gsk_|r8_' . 2>/dev/null
```

## Code smells (catch the ones the prefix grep misses)

A founder may have already pasted the key behind a variable. These shapes are worth a closer read even without a prefix match:

- `const apiKey = "..."` / `let key = "..."` / `OPENAI_API_KEY = "..."` assigned to a **string literal** rather than read from the environment.
- `openai.api_key = "..."`, `new OpenAI({ apiKey: "..." })`, `new Anthropic({ apiKey: "..." })`, `genai.configure(api_key="...")`, `InferenceClient(token="...")` — SDK constructors with a literal where `process.env.X` / `os.environ[...]` belongs.
- `dangerouslyAllowBrowser: true` in OpenAI's JS SDK — this is OpenAI literally warning you "you are about to put your key in the browser." If you see this flag set to true in client code, the key is almost certainly exposed. Flag it on sight.
- `fetch("https://api.openai.com/...", { headers: { Authorization: \`Bearer ${...}\` }})` **inside a component / client file** — direct calls to a provider from the browser mean the key has to be in the browser.
- `--dart-define=OPENAI_KEY=...` in a Flutter build script or CI file.

## What to report

### The story

> **Your AI key is sitting in your front-end code — anyone visiting your site can take it.**
>
> In `src/lib/ai.ts` you've got your OpenAI key written straight into the code as `const apiKey = "sk-proj-..."`. The problem: this file gets bundled and sent to every visitor's browser. Right-click → "View Source," a quick search, and they've got your key. It's not hidden — front-end code is *public by definition*.
>
> **Here's what goes wrong:** You launch, you post on a Friday. By Sunday a bot that crawls public sites for keys has found it. It runs your key non-stop generating garbage. Monday morning you've got a $3,200 OpenAI bill and a rate-limit error in your actual app, because the bot ate your whole quota. There is no "undo" on the spend — you eat the bill while you scramble to rotate.

**Severity:** 🔴 CRITICAL for `sk-ant-` / `sk-proj-` / `sk-` in client code, a public env var, mobile bundle, or git history. 🟠 HIGH for the other providers in those same places, or for any AI key found server-side but committed to a public repo.

### Fix tonight

The order matters — **rotate first**, because once a key is public it's compromised forever; moving it doesn't un-leak it.

1. **Rotate the key right now.** The leaked one is burned. (We have a `/lictor-rotate` helper that walks you through the exact buttons for each provider.)
   - OpenAI: platform.openai.com → API keys → revoke → create new
   - Anthropic: console.anthropic.com → Settings → API Keys → delete → create new
   - Google/Gemini: aistudio.google.com/apikey (and check Cloud Console if it's a Cloud key)

2. **Move the key behind a tiny server route.** The browser should call *your* server; your server holds the key and calls the AI provider. The key never leaves the backend.

   ```ts
   // app/api/chat/route.ts  — runs on YOUR server, key stays here
   import OpenAI from "openai";
   const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY }); // server-only env, NO "NEXT_PUBLIC_"

   export async function POST(req: Request) {
     // (add your auth check here — see the api-auth check)
     const { messages } = await req.json();
     const r = await openai.chat.completions.create({ model: "gpt-4o-mini", messages });
     return Response.json(r.choices[0].message);
   }
   ```

   ```tsx
   // the component calls YOUR route — no key in the browser
   const res = await fetch("/api/chat", {
     method: "POST",
     body: JSON.stringify({ messages }),
   });
   ```

3. **Rename the env var so it can't ship to the browser.** Drop any `NEXT_PUBLIC_` / `VITE_` / `EXPO_PUBLIC_` / `REACT_APP_` prefix — `OPENAI_API_KEY`, not `NEXT_PUBLIC_OPENAI_API_KEY`. Put it in `.env.local` and confirm `.env*` is in `.gitignore`.

4. **Mobile:** never embed a provider key in the app. Put a thin backend (a Cloud Function / small server) between the app and the provider, and have the app authenticate to *your* backend. If the key was already shipped in a release, rotate it and ship an update — existing installs are carrying the old key until users upgrade.

5. **If it touched git history**, deleting the file isn't enough — the key is in past commits forever. Rotate (mandatory), then scrub history with `git filter-repo` or BFG if you care about the old commits. On a public GitHub repo, assume it was scraped the moment it was pushed.

## What NOT to flag

This is the part that keeps the tool honest. Crying wolf on these makes founders ignore the real findings.

- **Firebase web config / `apiKey` (`AIza...`) in client code is PUBLIC BY DESIGN — do not flag it as a leak.** Every Firebase web app ships its config (`apiKey`, `authDomain`, `projectId`, …) in the browser; that's how the SDK is meant to work. That `apiKey` is an *identifier*, not a secret — it does not grant data access on its own. The real protection is Firebase Security Rules. So: if an `AIza...` key sits inside a `firebaseConfig = { ... }` object or a `initializeApp(...)` call, it's expected — note it ⚪ INFO at most and instead point the user at the **Open Supabase / Firebase** check (`db-exposure.md`), which checks whether their *rules* are locked down. Only escalate an `AIza...` key when it's clearly a standalone Gemini / AI Studio / Maps / Cloud key used outside a Firebase config block.
- **Public/publishable keys that are designed to be seen.** Stripe `pk_live_` / `pk_test_`, PostHog/analytics project keys, Algolia *search-only* keys, Sentry public DSNs, Clerk/Supabase *anon* (publishable) keys. These are meant to be in the browser. Not a finding. (A Supabase *service_role* key in the browser, on the other hand — that's CRITICAL; it bypasses row-level security.)
- **`.env.example` / `.env.sample` / `.env.template` files.** These are placeholders for other devs. `OPENAI_API_KEY=sk-your-key-here` or `OPENAI_API_KEY=` is documentation, not a leak. Skip unless the value is an actual well-formed key.
- **Placeholder and obviously-fake values.** `sk-xxxxxxxx`, `sk-ant-api03-REPLACE_ME`, `your-key-here`, `<OPENAI_KEY>`, `sk-1234567890`, `sk-test`. If the body is repeated chars, all-caps words, or angle-bracketed, it's a template.
- **Keys read from the environment.** `process.env.OPENAI_API_KEY`, `os.environ["ANTHROPIC_API_KEY"]`, `os.getenv(...)`, `System.getenv(...)`, `ENV["..."]`, `Deno.env.get(...)` — this is the *correct* pattern. Never flag it. The bug is a string *literal*; a reference is the fix.
- **Documentation, comments, and tests.** A key-shaped string in a README code sample, a comment explaining the format, or a test fixture using a deliberately-revoked key. Use judgment from the surrounding context.
- **OpenAI org/project IDs.** `org-...` and `proj_...` (note: that's the *identifier* `proj_`, different from the secret-key prefix `sk-proj-`) are not secret keys. Don't confuse them.

When in doubt, read the five lines around the hit. **A string literal that matches a provider prefix and isn't in an example/test/comment is real. Everything else is context.** If you genuinely can't tell whether a key is live, flag it 🟡 MEDIUM with "I couldn't confirm this is live — if it's a real key, rotate it; if it's a placeholder, ignore this," rather than screaming CRITICAL at a maybe.
