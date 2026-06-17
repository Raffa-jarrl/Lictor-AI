# Check — CI/CD pipeline integrity

**What you're looking for:** The "trust" gaps in *how your app gets built and shipped*, not in the app itself. Your code can be perfect, but if your build pipeline runs a third-party robot (a GitHub Action, a CircleCI orb, a downloaded installer) that some stranger controls, then that stranger controls your build. And your build has the keys to everything: your deploy tokens, your signing certs, your cloud creds, your source.

Here's the story that bites founders. Your `.github/workflows/deploy.yml` says `uses: some-dev/cool-action@v3`. That `@v3` looks like a version number, but it's not frozen — it's a **movable sticky note**. Whoever owns `some-dev/cool-action` can peel that `v3` sticky note off the safe code and slap it onto malicious code any time they want. Next time your pipeline runs, it runs *their* new code — with your secrets in the room. You didn't change anything. They did. This actually happened at scale in March 2025 (the `tj-actions/changed-files` compromise dumped CI secrets from tens of thousands of repos), and it's exactly the kind of thing the AI that scaffolded your workflow never warned you about — it just copied a `@v3` from a tutorial.

Same family of bug, two more flavors:
- **`curl | bash`** — your pipeline (or your install docs) downloads a script from the internet and pipes it straight into a shell, no checksum, no signature. Whoever can tamper with that URL (or sits on the wire) runs code as your build.
- **Auto-update / self-update** — your app or installer fetches a new binary and *runs it* with no signature check. That's a remote-code-execution backdoor you built yourself.

OWASP calls this whole family **A08: Software and Data Integrity Failures**. The package-install half (typosquats, lockfiles, `postinstall` scripts) lives in the `dependencies.md` check; webhook signature verification lives in `webhooks-csrf.md`. **This module owns the build/release half: pinning, checksums, and signed updates.**

## How to scan

All free, all just reading repo config. No paid scanner, no CI access needed.

### Step 1 — Find the pipeline config

```bash
# CI/CD definitions across the common platforms
ls -la .github/workflows/ .gitlab-ci.yml .circleci/config.yml \
       azure-pipelines.yml bitbucket-pipelines.yml Jenkinsfile \
       .drone.yml .travis.yml appveyor.yml cloudbuild.yaml \
       2>/dev/null

find . -path ./node_modules -prune -o \
  \( -path '*/.github/workflows/*.yml' -o -path '*/.github/workflows/*.yaml' \
     -o -name '.gitlab-ci.yml' -o -path '*/.circleci/config.yml' \) -print 2>/dev/null
```

### Step 2 — Find Actions/steps pinned to a MOVABLE tag (the big one)

A safe pin is a full **40-character commit SHA**. A `@v3`, `@v3.1.2`, `@main`, `@master`, `@latest`, or a short SHA is movable.

```bash
# GitHub Actions: list every third-party `uses:` and how it's pinned.
# A safe line ends in @<40 hex chars>. Everything else here is movable.
grep -rEn 'uses:\s*[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+@' .github/workflows/ 2>/dev/null \
  | grep -vEi 'uses:\s*\./' \
  | grep -vE 'uses:\s*[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+@[0-9a-f]{40}\b'
# Anything this prints is a third-party Action pinned to a TAG/BRANCH, not a SHA.

# GitLab CI: includes pulled from a remote/project without a pinned ref
grep -nE 'include:|ref:|remote:|project:' .gitlab-ci.yml 2>/dev/null

# CircleCI orbs: `name/orb@1.2.3` (orbs are versioned, but `@volatile`/`@dev:` is movable)
grep -nE 'orbs:|@(volatile|dev:)' .circleci/config.yml 2>/dev/null
```

### Step 3 — Find `curl | bash` and unverified downloaded installers

```bash
# Pipe-to-shell anywhere in CI config or setup scripts (any language ecosystem)
grep -rEn '(curl|wget|iwr|Invoke-WebRequest)[^|\n]*\|[[:space:]]*(sudo[[:space:]]+)?(ba)?sh' \
  .github .gitlab-ci.yml .circleci Jenkinsfile azure-pipelines.yml \
  Dockerfile* scripts/ install.sh 2>/dev/null

# Download-then-run with no hash check nearby (heuristic: a fetch followed by chmod+x / run)
grep -rEn '(curl|wget)[^|\n]*-o[[:space:]]' \
  .github .gitlab-ci.yml .circleci Dockerfile* scripts/ 2>/dev/null
```

### Step 4 — Find auto-update / self-update code

```bash
grep -rEn --exclude-dir={node_modules,.git,vendor,Pods,build,dist} \
  -i 'autoUpdater|electron-updater|self.?update|auto.?update|downloadAndInstall|sparkle|squirrel|app_update|checkForUpdates' \
  . 2>/dev/null | head -30
```

## The dangerous patterns

### Pattern 1 — Third-party Action pinned to a movable tag (HIGH)

```yaml
# .github/workflows/deploy.yml  — DANGEROUS
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4          # tag → movable
      - uses: tj-actions/changed-files@v44 # tag → movable (this is the one that got compromised)
      - uses: some-dev/cool-action@main    # branch → movable, even worse
    env:
      DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}  # ← this is in the room with whatever they run
```

Whoever owns that Action can repoint the tag at any time and your next run executes their code with `secrets.DEPLOY_TOKEN`, your `GITHUB_TOKEN`, and everything else in scope. Severity scales with what the job can touch: a job with deploy creds or `id-token: write` → HIGH; a docs-lint job with no secrets → low/INFO.

**Safe version — pin to a full commit SHA, with the version as a comment:**

```yaml
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - uses: tj-actions/changed-files@4edb3e336a4b1c61c2ae0a2b8c4d6ac9bf...  # 40-hex SHA # v44
```

A SHA is content-addressed — it can't be silently repointed. If the upstream code changes, the SHA changes, and you'd have to choose to update it.

### Pattern 2 — `curl | bash` with no verification (HIGH)

```yaml
# CI step, Dockerfile, or install docs — DANGEROUS
- run: curl -fsSL https://get.sometool.io/install.sh | bash
```

```dockerfile
# Dockerfile — same bug
RUN curl -sSf https://sh.rustup.rs | sh
```

If that URL is ever tampered with (compromised host, hijacked CDN, MITM on a flaky runner), arbitrary code runs as your build/root. No checksum means you can't tell.

**Safe version — download, verify a pinned hash, *then* run:**

```yaml
- run: |
    curl -fsSL https://get.sometool.io/install-1.4.2.sh -o install.sh
    echo "9f2c...e1  install.sh" | sha256sum -c -   # hash you reviewed once, pinned in the repo
    bash install.sh
```

### Pattern 3 — Auto-update that runs unsigned code (HIGH → CRITICAL)

This one spans every client stack. The bug is the same everywhere: **fetch a new binary/bundle and execute it without verifying a signature.**

```js
// JS / Electron — DANGEROUS: applies whatever the server hands back
const { autoUpdater } = require("electron-updater");
autoUpdater.checkForUpdatesAndNotify();   // OK *only if* update feed is signed-and-pinned
// ...but if the feed URL is http://, or code signing/notarization is disabled, an attacker
// who controls the feed ships a malicious "update" straight onto every user's machine.
```

```swift
// Swift / macOS (Sparkle) — DANGEROUS if EdDSA/DSA signature check is off
let updater = SPUUpdater(...)   // must have SUPublicEDKey set + feed served over https
```

```kotlin
// Android / Kotlin — DANGEROUS: download an APK and launch the installer with no checks
val apk = downloadFrom("http://updates.example.com/app.apk")
startActivity(installIntent(apk))   // no signature pinning → swap the APK, own the device
```

```dart
// Flutter — DANGEROUS: pulling a new bundle/binary and running it without a signature gate
final bytes = await http.get(Uri.parse('http://cdn.example.com/update.bin'));
await applyUpdate(bytes);   // no signature verification
```

```go
// Go self-updating CLI — DANGEROUS
resp, _ := http.Get("http://releases.example.com/myapp-latest")  // http + no signature
io.Copy(out, resp.Body); os.Chmod(out, 0o755)                    // now run it as the user
```

**Safe version — sign releases, ship the update feed over HTTPS, verify before applying:**
- Electron: enable OS code signing + notarization; `electron-updater` then refuses unsigned updates. Feed URL must be `https://`.
- Sparkle (macOS/iOS): set `SUPublicEDKey` and sign each release with the matching EdDSA private key; Sparkle rejects anything that doesn't verify.
- Android: verify the downloaded APK's signing certificate against a pinned hash before installing; prefer in-app updates via the store.
- Go/Flutter/anything custom: detach-sign each release artifact (`minisign`/`cosign`/`gpg`), ship the signature, and verify it with a **pinned public key** baked into the app before you execute or apply the bytes.

## Report a finding as

**Title:** "CI runs third-party Action `tj-actions/changed-files@v44` pinned to a movable tag"

(use this shape for Pattern 1; adapt the title for `curl | bash` and auto-update findings)

**Detail:**
> `.github/workflows/deploy.yml:14` runs `uses: tj-actions/changed-files@v44`. The `@v44` is a Git **tag**, not a commit — the person who owns that Action can repoint the tag at new code at any moment, and your next pipeline run will execute it. This job has `DEPLOY_TOKEN` and the default `GITHUB_TOKEN` in scope, so a malicious repoint could exfiltrate your deploy credentials and push to your repo. This is not hypothetical: the March 2025 `tj-actions/changed-files` compromise leaked CI secrets from tens of thousands of repositories this exact way.
>
> **What to do tonight:**
> 1. Find the commit SHA the tag currently points at:
>    ```bash
>    # 40-char SHA for the tag you're using
>    git ls-remote https://github.com/tj-actions/changed-files refs/tags/v44
>    ```
> 2. Replace the tag with that full SHA, keeping the version as a comment so humans can still read it:
>    ```yaml
>    - uses: tj-actions/changed-files@<40-char-sha>  # v44
>    ```
> 3. Do this for **every** third-party `uses:` in `.github/workflows/` (leave `./local-action` and SHA-pinned ones alone). Then turn on Dependabot's `github-actions` ecosystem so it proposes reviewed SHA bumps for you:
>    ```yaml
>    # .github/dependabot.yml
>    version: 2
>    updates:
>      - package-ecosystem: "github-actions"
>        directory: "/"
>        schedule: { interval: "weekly" }
>    ```
> 4. While you're in there: scope job permissions down (`permissions: { contents: read }` at the top of the workflow, widen only where needed) so a compromised step has less to steal.
> 5. Verify: re-run `grep -rEn 'uses:\s*[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+@' .github/workflows/ | grep -vE '@[0-9a-f]{40}\b' | grep -vEi 'uses:\s*\./'` — it should print nothing.

For a `curl | bash` finding, the "fix tonight" is Pattern 2's download-verify-run snippet. For an auto-update finding, it's enabling code signing + an HTTPS, signature-verified update feed (Pattern 3).

## What NOT to flag

- **First-party / local actions.** `uses: ./.github/actions/my-action` or `uses: ./` runs code *from your own repo* — there's no external tag to hijack. Never flag these.
- **Already SHA-pinned steps.** `uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683` is the *fix*, not a finding — even with a trailing `# v4.2.2` comment. Don't flag a 40-hex pin.
- **Reusable workflows / Actions in the SAME repo or same org pinned by policy.** `uses: my-org/shared/.github/workflows/ci.yml@v1` inside `my-org`'s own repos is internal code under your control. If the org enforces SHA-pinning via an Action allowlist / org ruleset elsewhere, a tag here is policy-covered — note as INFO at most.
- **Versioned package installs inside a step are *not* this check.** `npm ci`, `pip install -r requirements.txt`, `go build`, `bundle install` lean on lockfiles + the `dependencies.md` check. Don't double-report them here.
- **`curl | bash` in a throwaway/ephemeral context with no secrets and no persistence** — e.g. a local one-off in a README "try it" snippet, or a sandboxed job that holds no credentials. Lower the severity; flag the *production deploy* and *secret-bearing* pipelines hard.
- **Auto-update that already verifies a signature.** Electron with code signing + notarization enabled, Sparkle with `SUPublicEDKey` set, or any updater that checks a detached signature against a pinned key over HTTPS — that's the correct pattern. Confirm the key is pinned and the feed is `https://` before clearing it, but don't flag a properly-signed updater.
- **Container base images / language toolchains pinned by tag** (`FROM node:20`, `runs-on: ubuntu-latest`) — different surface, owned by `dependencies.md` / infra hardening, not this module. (`FROM node:20@sha256:...` digest-pinning is the gold standard, but a bare tag here is a nit, not a high-sev pipeline-integrity finding.)
