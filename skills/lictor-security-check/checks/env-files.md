# Check — Exposed config files

**What you're looking for:** Configuration files that contain secrets and accidentally get served by the production web server. The classic: `/.env` works in `curl` against the deployed site.

## Why this happens

Static-site generators and SSR frameworks sometimes copy the entire project directory to the deploy artifact. If `.env` is in the project root and the build doesn't explicitly exclude it, it ends up in `out/`, `dist/`, `build/`, or `.next/standalone/` — and the production CDN serves it as a regular file at `/.env`.

## How to scan locally

```bash
# What's in the build output (if present)?
for dir in out dist build .next/standalone public; do
  if [ -d "$dir" ]; then
    echo "=== $dir ==="
    find "$dir" -maxdepth 3 -name ".env*" -o -name ".git" -o -name "wp-config*" -o -name "config.json" 2>/dev/null
  fi
done

# Is .env at the project root and missing from .gitignore?
if [ -f .env ] || [ -f .env.local ] || [ -f .env.production ]; then
  echo "Local .env files present:"
  ls -la .env* 2>/dev/null
  echo ""
  echo ".gitignore contents:"
  grep -E '\.env' .gitignore 2>/dev/null || echo "  (no .env pattern in .gitignore — DANGEROUS)"
fi

# Is `public/` a dump of the whole project? (Some vibe-coded scaffolds do this.)
if [ -d public ]; then
  find public -maxdepth 2 -name ".env*" -o -name ".git" 2>/dev/null
fi
```

## Files that should NEVER be deploy artifacts

| File | What's typically in it |
|---|---|
| `.env`, `.env.local`, `.env.production` | API keys, DB passwords, OAuth client secrets |
| `.git/config`, `.git/HEAD` | Reveals repo URL + branch structure |
| `wp-config.php` | WordPress DB credentials + secret salts |
| `config.json`, `config.yml` | App configuration including secrets |
| `id_rsa`, `id_ed25519` | SSH private keys |
| `*.pem`, `*.key` (private keys) | TLS / signing keys |
| `docker-compose.yml` (with literal passwords) | Service credentials |

## Report this finding as

**Title:** ".env file will be served by your production site" (when found in build output)

**Detail:**
> Your `.env.local` file is copied into `out/.env.local` by your build (verified at `out/.env.local`, file is {N} bytes). When you deploy this to Vercel/Netlify/anywhere that serves the contents of `out/` as static files, anyone who navigates to `https://yourapp.com/.env.local` downloads the entire file — including every API key in it.
>
> Test the assumption: run `curl https://yourapp.com/.env.local` after deploying. If the file content comes back instead of a 404, you have a CRITICAL exposure.
>
> **What to do tonight:**
> 1. Verify which `.env*` files are in your `.gitignore`. Add `.env*` and `!.env.example` if missing.
> 2. Check your framework's deploy-ignore config:
>    - Next.js: `.env*.local` is already deploy-excluded by default. `.env.production` is NOT — that file gets bundled into server-side code and exposed via Vercel's environment-variable UI, but should never be in the public build output.
>    - Vite: by default `.env*` files are excluded from `dist/`, but only if you didn't move them into `public/`.
>    - Astro: same — `.env*` is build-excluded but `public/` is verbatim-copied.
> 3. The simplest verification: after deploy, run `curl -I https://yourapp.com/.env.local`. If you get a 200 response, you have the bug. If 404, you're fine.
> 4. Rotate any key that was in a `.env` file you can't be 100% sure was never deployed.

## Edge case: `.git/config` exposed

If the entire `.git` directory ends up in the deployed site (it happens — `cp -r` in deploy scripts, accidentally committing `public/.git/`), an attacker can:

1. `curl https://yourapp.com/.git/HEAD` → get the active branch
2. Download the full repo via dumb-HTTP git fetch
3. Read every line of source, every commit message, every credential ever leaked in history

This is a CRITICAL finding worth its own remediation paragraph.

## What NOT to flag

Don't cry wolf — these are normal and should **not** be reported:

- **`.env.example` / `.env.sample` / `.env.template`** with placeholder values (`API_KEY=your-key-here`). These are *meant* to be committed — they document what env vars the app needs, with no real secrets. Only flag them if they contain a real-looking key.
- **A `.env` that's correctly in `.gitignore` and NOT in any build output.** That's exactly right — local secrets staying local. Confirm it's not in `out/`/`dist/`/`public/` and move on; don't flag the mere existence of a local `.env`.
- **`.env*.local` in a Next.js project.** Next.js deploy-excludes `.env*.local` by default, so it's not in the public build unless someone moved it into `public/`. Only flag if you actually find it in the build output.
- **`.env` files containing ONLY public-by-design vars** — `NEXT_PUBLIC_*`, `VITE_*`, `EXPO_PUBLIC_*`, `PUBLIC_*`. Those values are compiled into the client bundle on purpose. If that's *all* the file has, it's not a secret leak (though serving the file is still untidy — note it as LOW, not CRITICAL). If it also has non-prefixed secrets, that's the real finding.
- **`config.json` / `docker-compose.yml` with no secrets** — just ports, service names, public URLs, feature flags. Structure isn't a secret. Only flag when a literal password/key/token is in it.
- **`.git` folders that are NOT in the deploy artifact.** Every repo has a local `.git/`; that's normal. Only flag it when it ends up under `public/`/`out/`/`dist/` or is reachable on the live site.
