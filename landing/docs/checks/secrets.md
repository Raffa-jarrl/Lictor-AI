# Check — Secrets in code

**What you're looking for:** Hardcoded API keys, tokens, and connection strings shipped in source files or build output. The classic "vibe-coded app pasted the API key into a `const` because the AI told them to."

## How to scan

Use `grep -r` against the project (excluding `node_modules`, `.next`, `dist`, `build`):

```bash
# Strong-prefix patterns — very low false positive
grep -rEn --exclude-dir={node_modules,.next,dist,build,.git,.turbo,out} \
  'sk-ant-api[0-9]{2}-[A-Za-z0-9_-]{40,}|sk-(proj-)?[A-Za-z0-9_-]{20,}|sk_live_[A-Za-z0-9]{24,}|sk_test_[A-Za-z0-9]{24,}|AIza[A-Za-z0-9_-]{35}|ghp_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}|AKIA[0-9A-Z]{16}|xox[abp]-[A-Za-z0-9-]{10,}' \
  . 2>/dev/null

# Connection strings
grep -rEn --exclude-dir={node_modules,.next,dist,build,.git} \
  '(mongodb(\+srv)?|postgres(ql)?|redis|mysql)://[^\s"<>]+' \
  . 2>/dev/null | grep -v "://localhost\|://127.0.0.1\|://\$\|://YOUR_"

# Private key blocks
grep -rln --exclude-dir={node_modules,.next,dist,build,.git} \
  -E '^-----BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY' \
  . 2>/dev/null
```

## Pattern reference (severity by type)

| Pattern | Catches | Severity |
|---|---|---|
| `sk-ant-api[0-9]{2}-[A-Za-z0-9_-]{40,}` | Anthropic API key | CRITICAL |
| `sk-(proj-)?[A-Za-z0-9_-]{20,}` | OpenAI API key (legacy + 2024+ project keys) | CRITICAL |
| `sk_live_[A-Za-z0-9]{24,}` | Stripe live secret key | CRITICAL |
| `sk_test_[A-Za-z0-9]{24,}` | Stripe test secret key | MEDIUM |
| `pk_live_[A-Za-z0-9]{24,}` | Stripe live publishable key | INFO (these are public by design) |
| `AIza[A-Za-z0-9_-]{35}` | Google API key | HIGH |
| `ghp_[A-Za-z0-9]{36}` | GitHub personal access token | CRITICAL |
| `ghs_[A-Za-z0-9]{36}` | GitHub server token | CRITICAL |
| `xox[abp]-[A-Za-z0-9-]{10,}` | Slack token | HIGH |
| `AKIA[0-9A-Z]{16}` | AWS access key ID | HIGH |
| `eyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}` | JWT (verify intended) | LOW |
| `-----BEGIN ... PRIVATE KEY-----` | Private key file | CRITICAL |
| `postgres://...` | Postgres connection string with credentials | CRITICAL |
| `mongodb://...` | MongoDB connection string with credentials | CRITICAL |
| `redis://...` | Redis connection string with credentials | HIGH |

## Don't trigger on

- Strings inside `.env.example` files (those are templates with placeholder values)
- Comments that document the format ("e.g. sk-xxxxx")
- Test fixtures that use known-public keys (`sk_test_...` is fine in tests)
- TypeScript type definitions that mention a key format

If unsure, look at the surrounding context. If it's `process.env.OPENAI_KEY`, that's fine. If it's `const k = "sk-proj-..."`, that's the bug.

## Report this finding as

**Title:** "OpenAI API key hardcoded in `src/lib/openai.ts:14`" (be specific)

**Detail:**
> The OpenAI API key is hardcoded as a string literal in `src/lib/openai.ts` line 14. Once you deploy this app, anyone who views the JavaScript bundle in their browser can extract the key and run unlimited requests on your OpenAI account. You will be billed for whatever they do.
>
> **What to do tonight:**
> 1. Rotate the key — go to platform.openai.com → API keys → revoke this one, generate a new one
> 2. Move the new key to a server-side environment variable (`OPENAI_API_KEY=...` in `.env.local`, never `.env.public` or anything ending in `.example`)
> 3. Add a server-side API route that calls OpenAI; have your client code call YOUR API, not OpenAI's directly
> 4. Add `.env*` to `.gitignore` and verify the file isn't already in git history: `git log --all -- .env.local`
>
> Even if you do nothing else from this audit: rotate the leaked key tonight.

## Special case: `.env*` files in git history

After the secrets grep, also run:

```bash
git log --all --pretty=format: --name-only --diff-filter=A 2>/dev/null | sort -u | grep -E '\.env(\.|$)' | head -10
```

If any `.env`, `.env.local`, `.env.production` etc. shows up — the secrets in them are **in the git history forever** even if you delete the file in a new commit. Flag as CRITICAL and tell the user to:

1. Rotate every key that was ever in those files
2. Then optionally rewrite history (`git filter-repo` or BFG) if the repo is private
3. If the repo is public on GitHub: GitHub may have already scraped the keys and notified the provider; assume rotation is mandatory
