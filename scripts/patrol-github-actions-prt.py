#!/usr/bin/env python3
"""
patrol-github-actions-prt — scanner #71.

Hunts the `pull_request_target` exploitation class in public GitHub Actions
workflows. This is one of the highest-payout vulnerability classes on
HackerOne / Bugcrowd in 2024-2026 because almost every F500 org has
dozens of public OSS repos with at least one workflow that gets it wrong.

The vulnerability chain:
  1. `pull_request_target` runs in the context of the BASE repo with full
     secrets access (unlike `pull_request` which runs in fork context)
  2. If the workflow checks out the PR's HEAD code (via `actions/checkout`
     with `ref: ${{ github.event.pull_request.head.* }}`) it now has
     attacker-controlled code on disk with secrets in env vars
  3. If the workflow then RUNS that code — npm install (postinstall),
     pip install, make, bundle install, ANY build command — it's RCE
     with full repo secrets including GITHUB_TOKEN, npm tokens, AWS keys,
     deployment credentials.
  4. Often results in repo-level compromise: attacker can push commits,
     publish malicious packages, modify releases.

Famous incidents:
  - GitHub-2022 multiple programs paid $5k-$30k each
  - Mozilla-2023 multiple repos
  - Hundreds of small/medium incidents documented at
    https://securitylab.github.com/research/

Detection (passive, ethical — never opens a PR, never executes any code):
  1. Enumerate repos in target org via public GitHub API
  2. Fetch .github/workflows/*.yml from default branch
  3. Pattern-match for the vulnerable combination
  4. Severity score based on what risky pattern combination matches
  5. Output structured findings

Usage:
  patrol-github-actions-prt.py --orgs cloudflare,coinbase,reddit
  # or
  patrol-github-actions-prt.py --org-file orgs.txt

Requires GITHUB_TOKEN env var (60 req/hr unauthenticated is too slow;
this scanner needs at least 1000 req/hr authenticated).
"""
from __future__ import annotations
import argparse, json, os, re, time, urllib.request, urllib.parse, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from pathlib import Path

UA = "Lictor-GitHubActionsPRT/0.1 (+https://lictor-ai.com)"

# Risky patterns to look for in workflow YAML
TRIGGER_PRT_RX = re.compile(
    r'(?:^|\s)on:\s*(?:\n\s+pull_request_target|[\[\(](?:[^\]\)]*,\s*)?pull_request_target)',
    re.MULTILINE | re.IGNORECASE)

# More liberal: any "pull_request_target" appearance in trigger context
TRIGGER_PRT_LOOSE_RX = re.compile(r'pull_request_target', re.IGNORECASE)

# Risky checkout of attacker-controlled code
RISKY_CHECKOUT_RX = re.compile(
    r'uses:\s*actions/checkout@[^\n]*(?:\n[^\n]*)*?'
    r'with:[^\n]*(?:\n[^\n]*)*?'
    r'ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(?:sha|ref)\s*\}\}',
    re.IGNORECASE)

# Code-execution patterns after checkout
EXEC_AFTER_CHECKOUT_PATTERNS = [
    (re.compile(r'(?:^|\n)\s*(?:run|script):.*(?:npm|yarn|pnpm)\s+(?:install|i|ci|build|test)',
                re.IGNORECASE | re.MULTILINE),
     "npm/yarn/pnpm install or build — runs postinstall from attacker package.json"),
    (re.compile(r'(?:^|\n)\s*(?:run|script):.*pip\s+install',
                re.IGNORECASE | re.MULTILINE),
     "pip install — runs setup.py from attacker code"),
    (re.compile(r'(?:^|\n)\s*(?:run|script):.*(?:bundle|gem)\s+(?:install|build|exec)',
                re.IGNORECASE | re.MULTILINE),
     "bundle/gem install/exec — runs Ruby code from attacker"),
    (re.compile(r'(?:^|\n)\s*(?:run|script):.*(?:go\s+(?:run|build|test)|cargo\s+(?:build|run|test))',
                re.IGNORECASE | re.MULTILINE),
     "go/cargo build — may execute build.rs or generate.go"),
    (re.compile(r'(?:^|\n)\s*(?:run|script):.*make(?:\s|$)',
                re.IGNORECASE | re.MULTILINE),
     "make — executes Makefile from attacker"),
    (re.compile(r'(?:^|\n)\s*(?:run|script):.*(?:node|python|ruby|sh|bash)\s+(?:\./|\w+/)',
                re.IGNORECASE | re.MULTILINE),
     "executes attacker script directly (node/python/sh)"),
    (re.compile(r'uses:\s*\./\s*(?:\n|$)',
                re.IGNORECASE | re.MULTILINE),
     "uses ./ composite action from PR — full RCE"),
]

# Shell injection: ${{ github.event.pull_request.* }} in run: blocks
SHELL_INJECTION_RX = re.compile(
    r'(?:^|\n)\s*(?:run|script):[^\n]*(?:[\'"`]|\s)\$\{\{\s*github\.event\.(?:pull_request|issue|comment|review)\.[^\}]*\}\}',
    re.MULTILINE | re.IGNORECASE)

# Permissions check: workflows with broad write perms are higher impact
PERM_WRITE_RX = re.compile(
    r'permissions:[^\n]*(?:\n\s+\w+:\s*write)+', re.IGNORECASE)

@dataclass
class GhaFinding:
    org: str
    repo: str
    workflow_path: str
    workflow_url: str
    triggers_prt: bool = False
    risky_checkout: bool = False
    exec_patterns: list = field(default_factory=list)
    shell_injection: bool = False
    has_write_perms: bool = False
    severity: str = "INFO"
    notes: str = ""

def gh_api(url: str, token: str | None, accept: str = "application/vnd.github.v3+json",
           timeout: int = 20) -> bytes | None:
    headers = {"Accept": accept, "User-Agent": UA}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read(2_000_000)
    except urllib.error.HTTPError as e:
        if e.code == 403:
            # Rate limited — back off
            reset = e.headers.get('X-RateLimit-Reset', '0')
            print(f"[!] GH 403 (rate limit) — sleeping 60s (reset: {reset})")
            time.sleep(60)
        elif e.code == 404:
            return None  # Common, don't log
        else:
            print(f"[!] GH HTTPError {e.code}: {url[:80]}")
        return None
    except Exception as e:
        print(f"[!] gh_api error: {e}")
        return None

def list_org_repos(org: str, token: str | None, max_repos: int = 100) -> list[dict]:
    """List public repos for an org (paginated)."""
    repos = []
    per_page = 100
    page = 1
    while len(repos) < max_repos:
        url = (f"https://api.github.com/orgs/{org}/repos?"
               f"type=public&sort=updated&per_page={per_page}&page={page}")
        body = gh_api(url, token)
        if not body: break
        try:
            data = json.loads(body)
        except Exception:
            break
        if not data: break
        repos.extend(data)
        if len(data) < per_page: break
        page += 1
        time.sleep(0.5)
    return repos[:max_repos]

def list_workflow_files(org: str, repo: str, default_branch: str,
                        token: str | None) -> list[str]:
    """List .github/workflows/*.yml paths in a repo."""
    url = (f"https://api.github.com/repos/{org}/{repo}/contents/.github/workflows"
           f"?ref={default_branch}")
    body = gh_api(url, token)
    if not body: return []
    try:
        items = json.loads(body)
    except Exception:
        return []
    if not isinstance(items, list): return []
    return [item['path'] for item in items
            if item.get('type') == 'file' and
            item.get('name', '').lower().endswith(('.yml', '.yaml'))]

def fetch_workflow_raw(org: str, repo: str, default_branch: str,
                       path: str) -> str:
    """Fetch raw workflow file (no auth needed for public)."""
    url = f"https://raw.githubusercontent.com/{org}/{repo}/{default_branch}/{path}"
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.read(200_000).decode("utf-8", "replace")
    except Exception:
        return ""

def analyze_workflow(org: str, repo: str, path: str, content: str,
                     workflow_url: str) -> GhaFinding | None:
    finding = GhaFinding(
        org=org, repo=repo, workflow_path=path, workflow_url=workflow_url
    )
    # Triger check
    if not TRIGGER_PRT_LOOSE_RX.search(content):
        return None  # No PRT trigger — not relevant
    finding.triggers_prt = True

    # Risky checkout
    if RISKY_CHECKOUT_RX.search(content):
        finding.risky_checkout = True

    # Code-execution after checkout
    for rx, name in EXEC_AFTER_CHECKOUT_PATTERNS:
        if rx.search(content):
            finding.exec_patterns.append(name)
    finding.exec_patterns = sorted(set(finding.exec_patterns))[:8]

    # Shell injection
    if SHELL_INJECTION_RX.search(content):
        finding.shell_injection = True

    # Write permissions
    if PERM_WRITE_RX.search(content):
        finding.has_write_perms = True

    # Severity scoring — strict gates to avoid FPs
    # PRT alone is NOT a vuln (could be label-only or comment-only)
    risk_signals = 0
    if finding.risky_checkout: risk_signals += 2
    if finding.exec_patterns: risk_signals += len(finding.exec_patterns)
    if finding.shell_injection: risk_signals += 2

    if risk_signals == 0:
        finding.severity = "INFO"
        finding.notes = ("uses pull_request_target but no risky pattern detected "
                        "(likely safe — labels/comments only)")
    elif finding.risky_checkout and finding.exec_patterns:
        finding.severity = "CRITICAL"
        finding.notes = ("PRT + risky-checkout + code-execution = RCE in PR "
                        "context with secrets access. ")
        if finding.has_write_perms:
            finding.notes += "Also has write permissions — repo compromise risk."
    elif finding.risky_checkout:
        finding.severity = "HIGH"
        finding.notes = ("PRT + risky-checkout (no exec pattern detected — but "
                        "even reading files from PR with secrets is sensitive)")
    elif finding.shell_injection:
        finding.severity = "CRITICAL"
        finding.notes = ("PRT + shell-injection via github.event.pull_request.* "
                        "in run: block — direct command injection")
    elif finding.exec_patterns:
        finding.severity = "MEDIUM"
        finding.notes = ("PRT + exec patterns but no risky checkout detected — "
                        "still review manually (may use PR data via env vars)")
    else:
        finding.severity = "LOW"
        finding.notes = "PRT trigger present but vuln-pattern not detected"

    return finding

def scan_repo(org: str, repo_data: dict, token: str | None) -> list[GhaFinding]:
    repo = repo_data['name']
    default_branch = repo_data.get('default_branch', 'main')
    findings: list[GhaFinding] = []
    workflow_paths = list_workflow_files(org, repo, default_branch, token)
    for path in workflow_paths:
        content = fetch_workflow_raw(org, repo, default_branch, path)
        time.sleep(0.2)
        if not content: continue
        url = f"https://github.com/{org}/{repo}/blob/{default_branch}/{path}"
        f = analyze_workflow(org, repo, path, content, url)
        if f and f.severity != "INFO":
            findings.append(f)
    return findings

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--orgs", help="comma-separated org names")
    ap.add_argument("--org-file", help="file with one org per line")
    ap.add_argument("--max-repos-per-org", type=int, default=50)
    ap.add_argument("--threads", type=int, default=3)
    ap.add_argument("--gh-token-env", default="GITHUB_TOKEN")
    ap.add_argument("--ledger",
                    default="/Users/raffa/Lictor/v3/ledgers/github-actions-prt.jsonl")
    args = ap.parse_args()

    if args.orgs:
        orgs = [o.strip() for o in args.orgs.split(',') if o.strip()]
    elif args.org_file:
        orgs = [l.strip() for l in Path(args.org_file).read_text().splitlines() if l.strip()]
    else:
        ap.error("provide --orgs or --org-file")

    token = os.environ.get(args.gh_token_env, "").strip() or None
    if not token:
        print(f"[!] No GITHUB_TOKEN — falling back to unauthenticated 60/hr rate limit")
        print(f"[!] Set: export {args.gh_token_env}=ghp_...")
        print(f"[!] Recommended scope: 'public_repo' (read-only)")

    print(f"[+] GitHub Actions PRT hunt: {len(orgs)} orgs × up to {args.max_repos_per_org} repos each")
    Path(args.ledger).parent.mkdir(parents=True, exist_ok=True)

    n_crit = n_high = n_med = n_low = 0
    with open(args.ledger, "a") as ledger:
        for org_idx, org in enumerate(orgs, 1):
            print(f"\n[+] [{org_idx}/{len(orgs)}] Enumerating {org}...")
            repos = list_org_repos(org, token, args.max_repos_per_org)
            print(f"    → {len(repos)} repos")
            with ThreadPoolExecutor(max_workers=args.threads) as pool:
                futures = {pool.submit(scan_repo, org, r, token): r for r in repos}
                for fut in as_completed(futures):
                    repo_data = futures[fut]
                    try:
                        findings = fut.result()
                    except Exception as e:
                        print(f"  EXC {repo_data['name']}: {e}")
                        continue
                    for f in findings:
                        ledger.write(json.dumps(asdict(f)) + "\n")
                        ledger.flush()
                        tag = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡",
                               "LOW":"⚪","INFO":"."}.get(f.severity, "?")
                        print(f"    {tag} {f.org}/{f.repo} :: {f.workflow_path}  {f.severity}")
                        print(f"        {f.notes[:100]}")
                        if f.severity == "CRITICAL": n_crit += 1
                        elif f.severity == "HIGH": n_high += 1
                        elif f.severity == "MEDIUM": n_med += 1
                        else: n_low += 1
    print(f"\n[+] Done. CRITICAL={n_crit} HIGH={n_high} MEDIUM={n_med} LOW={n_low}")
    print(f"[+] 🔴 CRITICAL = open a PR with malicious npm-scripts/etc to verify.")
    print(f"[+]              DO NOT actually open the PR — disclose with the workflow")
    print(f"[+]              evidence + show the attack chain in the report.")

if __name__ == "__main__":
    main()
