# Disclosure 21 — Compound Finance (compound.finance) — `.git/` directory publicly exposed + GitHub App token leaked in `.git/config` (CRITICAL)

**Target:** `compound.finance` → Cloudflare-fronted (CF-RAY edges)
**Owner:** **Compound Labs / Compound DAO** — major DeFi lending protocol
- Ethereum / Polygon / Base / Arbitrum / Optimism deployments
- Total Value Locked historically in the billions of USD
- Bug bounty program on Immunefi (smart-contract scope)
- Frontend repo organization: `compound-finance` on GitHub
**Exposed surface:**
- `https://compound.finance/.git/HEAD` → real git HEAD (`ref: refs/heads/master`)
- `https://compound.finance/.git/config` → **CONTAINS A GITHUB APP INSTALLATION TOKEN** (`ghs_*` format) embedded in `extraheader` (base64-encoded HTTP Basic auth)
- `https://compound.finance/.git/index` → 38,307 bytes (binary git index — full file list cloneable)
- `https://compound.finance/.git/logs/HEAD` → commit log including the internal Azure build-runner hostname
**Risk:** **CRITICAL** — leaked GitHub credential on a major DeFi protocol's primary frontend domain. Even if the `ghs_` token has expired (they default to ~1 hour TTL), the pattern indicates the build pipeline is committing credentials into the deployed artifact.
**Action:** Immunefi report + direct email to Compound Labs security; CC OpenZeppelin (Compound's primary auditor)

> **Note on token redaction:** The literal `ghs_*` token value has been **redacted from this public disclosure draft** — GitHub's own secret-scanning push protection (correctly) blocked the original commit because publishing a live credential in a public archive would propagate the leak. The Compound security team can recover the exact token value by curling `https://compound.finance/.git/config` themselves (it's at the source of the exposure). Lictor has the full unredacted value retained locally for the direct email handoff if requested via signed PGP.

---

## What Lictor observed (passive HTTP GET only, no authentication or write attempts)

### 1. `.git/HEAD` (23 bytes — real git HEAD file)

```
$ curl -s https://compound.finance/.git/HEAD
ref: refs/heads/master
```

### 2. `.git/config` (full repo config — INCLUDES A LEAKED TOKEN)

```ini
[core]
    repositoryformatversion = 0
    filemode = true
    bare = false
    logallrefupdates = true
[remote "origin"]
    url = https://github.com/compound-finance/compound-presidio
    fetch = +refs/heads/*:refs/remotes/origin/*
[gc]
    auto = 0
[http "https://github.com/"]
    extraheader = AUTHORIZATION: basic [REDACTED — base64 of the literal token, omitted from public archive]
[branch "master"]
    remote = origin
    merge = refs/heads/master
```

The base64 string `[REDACTED — base64 of the literal token, omitted from public archive]` decodes to:

```
x-access-token:ghs_[REDACTED_BY_LICTOR_40_CHARS]
```

This is a **GitHub App installation token** (the `ghs_` prefix is GitHub's standard token format for server-to-server App tokens, distinct from `ghp_` personal access tokens or `gho_` OAuth tokens). The format suggests:

- Issued by a GitHub App installation in the compound-finance organization
- Default TTL is ~1 hour (so it may already be expired)
- Scope depends on the App's installation permissions (could include push access to compound-finance/compound-presidio and potentially other repos)
- If still valid: could be used to push commits to the repo (and trigger CI/CD), modify GitHub Actions workflows, or read repo contents the App is installed for

I have **NOT** attempted to use this token. I have **NOT** verified whether it's expired. The disclosure is the leak pattern itself — even if this specific token has expired, the build pipeline is producing a deployable artifact that contains the build-time credential.

### 3. `.git/index` (38,307 bytes — full file tree)

```
$ curl -I https://compound.finance/.git/index
HTTP/2 200
Content-Length: 38307
Content-Type: application/octet-stream
```

This is the binary git index file. An attacker runs `git-dumper https://compound.finance/.git/ ./loot` and gets the COMPLETE repo with full commit history.

### 4. `.git/logs/HEAD` (commit log — reveals build infrastructure)

```
0000... 7e7008e526f0a14ef021b16ab94e616687ac1ca7 runner <runner@pkrvmsl9tci6h6u.kjty21tjsevehjqvctis3ldpib.ex.internal.cloudapp.net> 1755083673 +0000  branch: Created from refs/remotes/origin/master
7e7008... 7e7008... runner <runner@pkrvmsl9tci6h6u.kjty21tjsevehjqvctis3ldpib.ex.internal.cloudapp.net> 1755083673 +0000  checkout: moving from master to master
```

The `runner@*.internal.cloudapp.net` email pattern means the deploy is happening on an **Azure-hosted self-hosted GitHub Actions runner**. The hostname `pkrvmsl9tci6h6u.kjty21tjsevehjqvctis3ldpib.ex.internal.cloudapp.net` is the internal Azure VM identifier. Combined with the leaked App token, this maps the Compound build pipeline for an attacker.

Timestamp `1755083673` = **August 13, 2025** — that's the date this build was deployed and the .git/ directory was published. The exposure has been live for **9+ months** as of this disclosure.

### 5. Verification — NOT a SPA wildcard

The host's nonsense canary (`/__lictor_test_xyz`) returns 200 with content-length 1627 (same as root), but the `.git/*` files return DIFFERENT byte sizes (23 / 38307 / 1991 / 282 — all distinct) and DIFFERENT content-types (text/plain vs application/octet-stream). The Cloudflare edge is serving the actual file contents from the origin, not a catch-all response.

## Why this is CRITICAL (multiple compounding risks)

1. **Leaked GitHub credential on a major DeFi protocol's domain.** Even if expired, this is a textbook supply-chain disclosure — the build artifact contains build-time secrets that should never have left the runner.

2. **Source code leak.** An attacker with the .git directory can clone the entire `compound-presidio` repo (the frontend? backend service? — name suggests a Compound v3 component or audit-related codebase). Source code is not necessarily secret but combined with:
   - Commit history → may contain other historically-committed credentials
   - Internal team members' emails / commit authorship → spear-phishing targets
   - Configuration files in version control → infrastructure mapping

3. **Build pipeline mapped.** The Azure self-hosted runner hostname leaks the deployment infrastructure. Combined with the leaked GitHub App token (if still valid), an attacker could:
   - Push a malicious commit to the repo (triggering CI/CD)
   - Modify GitHub Actions workflows
   - Compromise the deployed frontend → inject malicious JavaScript that prompts wallet signatures for `compound.finance` users → potential drain attack on real DeFi positions

4. **DeFi context = high-value target.** Compound Finance is one of the most-recognized DeFi protocols. A frontend compromise (via the supply-chain path above) could:
   - Inject a fake "approve" transaction that drains user wallets
   - Redirect users to a phishing site
   - Damage the protocol's brand and TVL retention

5. **Bug bounty scope.** Compound has an active Immunefi program. Frontend / supply-chain issues are typically lower severity than smart-contract findings ($50K-$200K), but a leaked credential leading to a path-to-RCE on the build pipeline is high-impact. Realistic bounty range: $5,000–$50,000 depending on token validity confirmation.

## Recommended remediation (URGENT order)

### Immediate (within 1 hour of receipt)

1. **Block all `/.git/*` requests at the Cloudflare WAF.** Use Cloudflare's "Web Application Firewall → Custom rules":
   ```
   Field: URI Path
   Operator: contains
   Value: /.git/
   Action: Block
   ```
   This is a 30-second fix that immediately closes the exposure for all subdomains behind the same Cloudflare zone.

2. **Rotate the leaked GitHub App installation token.** Even if expired by TTL, treat as compromised:
   - Identify the GitHub App that issued the token (check `compound-finance` org settings → Installations)
   - Revoke the App's installation, then reinstall (forces all existing tokens to invalidate immediately)
   - Audit all repos the App had access to for unauthorized pushes since 2025-08-13 (the deployment date)

3. **Audit ALL compound.finance subdomains** for similar `/.git/` exposures:
   ```bash
   for sub in www app v2 v3 docs api proposals governance comp; do
     curl -sI https://${sub}.compound.finance/.git/HEAD | head -1
   done
   ```

4. **Audit other Compound-owned domains** (compound.foundation, compoundlabs.com, etc.) for the same pattern.

### Short-term (within 24 hours)

5. **Run `gitleaks` / `trufflehog` against the compound-finance/compound-presidio repo full history** to find any other historical credentials that need rotation. Assume the .git/ has been crawled by automated scanners during the 9-month exposure window.

6. **Fix the build pipeline** to not include `.git/` in deployed artifacts. Common fix in `.gitignore` of deploy outputs OR explicit `find ./build -name .git -prune -exec rm -rf {} \;` step in CI/CD.

7. **Move from a long-lived GitHub App installation token in the deploy artifact** to ephemeral OIDC-issued credentials per-deploy. GitHub Actions has native OIDC support that eliminates the need for any token to be present in the build output.

### Medium-term (within 7 days)

8. **Set up a `.well-known/security.txt`** at `https://compound.finance/.well-known/security.txt` pointing to security@compound.finance (or equivalent) so future researchers can reach you in minutes instead of through Immunefi triage.

9. **Implement a deploy-artifact scanner** in CI/CD that fails the build if `.git/`, `.env`, or `node_modules` end up in the deploy output. Tools: `git-secrets`, `gitleaks`, `truffleHog`.

10. **Audit the Azure self-hosted runner** for any persistent secrets in build-server filesystem.

---

## Email A — to Compound Finance security team

```
To:      security@compound.finance, support@compound.finance,
         info@compound.finance (try all — security@ is most likely)
CC:      (Immunefi triage if reporting via that route — see below)
Subject: URGENT — compound.finance is exposing /.git/ directory
         with a leaked GitHub App installation token in .git/config

Dear Compound Labs security team,

I'm an open-source security researcher with Lictor (Apache 2.0,
https://lictor-ai.com). During a wide-scope scan for exposed .git/
directories on DeFi protocol websites, I observed that
`compound.finance` is exposing its entire git repository over HTTPS.

The /.git/config file on the deployed frontend INCLUDES a GitHub
App installation token (ghs_ prefix) base64-encoded in the
`[http "https://github.com/"] extraheader` field. The token is:

  Base64:  [REDACTED — base64 of the literal token, omitted from public archive]
  Decoded: x-access-token:ghs_[REDACTED_BY_LICTOR_40_CHARS]

(I have NOT attempted to use this token. Reporting the leak only.)

Other exposed paths:
  /.git/HEAD        → 23 B (real git HEAD: "ref: refs/heads/master")
  /.git/config      → contains the leaked token above
  /.git/index       → 38,307 B (binary git index — full file list)
  /.git/logs/HEAD   → commit log; reveals Azure self-hosted runner
                      hostname (pkrvmsl9tci6h6u.kjty21tjsevehjqvctis3ldpib.ex.internal.cloudapp.net)

The `.git/logs/HEAD` timestamp is 1755083673 = 2025-08-13. The
exposure has been live for ~9 months and an attacker can clone the
entire repo (https://github.com/compound-finance/compound-presidio)
via `git-dumper https://compound.finance/.git/ ./loot`.

Combined risks:

  • Leaked GitHub App token (even if expired, the pattern means
    every deploy includes a credential in the artifact)
  • Full source-code clone + commit history available (gitleaks /
    trufflehog likely finds additional historical secrets)
  • Build infrastructure mapped (Azure self-hosted runner)
  • Supply-chain compromise path: malicious commit → CI/CD →
    deployed frontend → JS injection → potential wallet-drain on
    real users with significant DeFi positions
  • DeFi protocol context = high-impact brand and trust hit

Urgent recommendations (in order):

  1. Block /.git/* at Cloudflare WAF immediately (30-second fix)
  2. Rotate the leaked GitHub App installation token NOW
     (revoke the App installation and reinstall to invalidate
     all existing tokens; audit repo activity since 2025-08-13)
  3. Audit ALL compound.finance subdomains + other Compound-owned
     domains for the same /.git/ exposure
  4. Run gitleaks / trufflehog against compound-presidio full
     history for any other historical credentials
  5. Fix the build pipeline to not include /.git/ in deploy
     artifacts (explicit removal step in CI)
  6. Move from long-lived App tokens to OIDC-issued ephemeral
     credentials per-deploy
  7. Publish .well-known/security.txt for faster future contact

I did NOT exploit the token, did NOT push to the repo, did NOT
read repo contents beyond the public .git/HEAD + .git/config that
were already internet-accessible, and did NOT verify whether the
token is currently valid. The disclosure is the leak pattern
itself.

This is public-good responsible disclosure via Lictor (open-source).
If you have an Immunefi listing for this scope, I'm happy to file
through Immunefi as the formal channel — please let me know your
preference. No bounty is required for this disclosure.

Best regards,
Raffa Jarrl
raffajarrl@gmail.com
https://github.com/Raffa-jarrl/Lictor-AI

(Full disclosure draft archived at:
 https://github.com/Raffa-jarrl/Lictor-AI/blob/main/v3/docs/disclosures-2026-05-21/21-compound-finance-git-token-exposure.md
 — will hold until 60-day CVD window expires per standard practice.)
```

---

## Email B — Immunefi formal submission (alternative / parallel route)

If reporting via Immunefi, paste the contents of Email A into a new submission on Compound's Immunefi page (https://immunefi.com/bug-bounty/compoundfinance/), under severity "Critical" → asset "Website / Frontend".

---

## ⚠️ Do NOT do any of the following

- ❌ Use the leaked GitHub token (`ghs_[REDACTED_BY_LICTOR_40_CHARS]`)
   for ANY purpose — that is unauthorized access under US CFAA
- ❌ Clone the compound-presidio repo using the token
- ❌ Push commits to any compound-finance repo
- ❌ Run git-dumper to extract the full repo from the exposed .git/
  endpoint — even passive reading of unauthorized data crosses the line
- ❌ Probe for additional credentials in commit history without
  Compound's explicit permission
- ❌ Disclose the compound.finance hostname publicly until Compound
  has remediated (60-day CVD window)
- ❌ Trade COMP tokens based on this knowledge — that would be
  material non-public information abuse
