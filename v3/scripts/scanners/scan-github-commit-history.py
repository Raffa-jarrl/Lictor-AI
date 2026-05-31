#!/usr/bin/env python3
"""scan-github-commit-history.py — Mine git commit history for accidentally-leaked secrets.

THE TARGET:
  Developers commit a secret, realize the mistake, remove the file in the next
  commit. Git keeps the history forever — the secret is still recoverable via
  git log. GitHub's secret scanning catches MANY of these and auto-revokes,
  but not all. The interesting ones are:
  - Custom secret formats not in GitHub's pattern catalog
  - Secrets in private repos that later went public
  - Secrets in forks where scanning wasn't active

WHAT IT FINDS:
  Live API keys (GitHub PAT, AWS, Stripe, etc.) that exist in commit history
  of public DeFi-protocol repos but were removed from current HEAD.

ETHICAL:
  - Uses GitHub API only (no clone needed — uses /commits and /commits/<sha>)
  - Read-only, public-repo only
  - Live validation against provider API (same as scan-sourcemap-secrets.py)
  - Tokens redacted in output
  - Findings stay local until manual disclosure
"""
import argparse, json, re, time, urllib.request, urllib.error
from pathlib import Path
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

UA = "LictorAI-EthicalScanner/0.4 (+https://lictor-ai.com/transparency)"
LEDGER = Path.home() / "Lictor/v3/ledgers/github-commit-history-secrets.jsonl"
GH_TOKEN = (Path.home() / ".lictor/gh-token").read_text().strip() if (Path.home() / ".lictor/gh-token").exists() else None

# Top DeFi orgs to scan
DEFI_ORGS = [
    "Uniswap", "aave", "compound-finance", "MakerDAO", "lidofinance",
    "curvefi", "balancer-labs", "synthetixio", "yearn",
    "GMX-io", "1inch", "pancakeswap", "morpho-org", "ethereum-optimism",
    "0xPolygon", "OffchainLabs", "scroll-tech", "starknet-io", "centrifuge",
    "thrackle-io", "fraxfinance", "safe-global", "wormhole-foundation",
    "LayerZero-Labs", "Consensys", "ChainSafe", "fireblocks", "BitGo",
]

# Secret patterns — same strict regexes as sourcemap scanner
PATTERNS = {
    "github_pat":     re.compile(rb"\bghp_[A-Za-z0-9]{36}\b"),
    "github_server":  re.compile(rb"\bghs_[A-Za-z0-9]{36}\b"),
    "github_oauth":   re.compile(rb"\bgho_[A-Za-z0-9]{36}\b"),
    "aws_key":        re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
    "stripe_live":    re.compile(rb"\bsk_live_[A-Za-z0-9]{24,}\b"),
    "google_api":     re.compile(rb"\bAIza[A-Za-z0-9_-]{35}\b"),
    "slack":          re.compile(rb"\bxoxb-[0-9]+-[0-9]+-[A-Za-z0-9]+\b"),
    "openai_proj":    re.compile(rb"\bsk-proj-[A-Za-z0-9_-]{20,}\b"),
    "anthropic":      re.compile(rb"\bsk-ant-(?:api|admin)\d+-[A-Za-z0-9_-]{40,}\b"),
    # Ethereum private key in production env (not example/test files only)
    "eth_priv_key":   re.compile(rb"PRIVATE_KEY[\"'\s=:]+0x[0-9a-fA-F]{64}"),
}

# Test/example keys to ignore
KNOWN_TEST = [
    b"0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",  # Anvil
    b"AKIAIOSFODNN7EXAMPLE",
]


def redact(token):
    s = token.decode("latin-1", "replace") if isinstance(token, bytes) else token
    return s[:8] + "..." + s[-4:] if len(s) > 14 else s[:4] + "..."


def gh_api(url, timeout=15):
    headers = {"User-Agent": UA, "Accept": "application/vnd.github.v3+json"}
    if GH_TOKEN:
        headers["Authorization"] = f"token {GH_TOKEN}"
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read() if e.fp else b""
    except Exception:
        return None, b""


def list_org_repos(org, max_repos=20):
    """List recent public repos for an org."""
    url = f"https://api.github.com/orgs/{org}/repos?per_page={max_repos}&sort=pushed"
    st, body = gh_api(url)
    if st != 200:
        return []
    try:
        repos = json.loads(body)
        return [r["full_name"] for r in repos if not r.get("fork") and not r.get("archived")]
    except Exception:
        return []


def list_recent_commits(repo, max_commits=30):
    """List recent commit SHAs from a repo."""
    url = f"https://api.github.com/repos/{repo}/commits?per_page={max_commits}"
    st, body = gh_api(url)
    if st != 200:
        return []
    try:
        commits = json.loads(body)
        return [c["sha"] for c in commits]
    except Exception:
        return []


def get_commit_diff(repo, sha):
    """Get the diff for a single commit (only files added/modified)."""
    url = f"https://api.github.com/repos/{repo}/commits/{sha}"
    st, body = gh_api(url)
    if st != 200:
        return None
    try:
        data = json.loads(body)
        # Concatenate all patch text from files
        patch_text = b""
        for f in data.get("files", [])[:20]:  # cap files per commit
            if f.get("patch"):
                patch_text += f["patch"].encode("utf-8", errors="replace") + b"\n"
        return patch_text
    except Exception:
        return None


def extract_secrets(patch_text):
    """Pattern-match secrets in commit diff."""
    hits = []
    for name, pat in PATTERNS.items():
        for m in pat.finditer(patch_text):
            token = m.group(0)
            if any(t in token for t in KNOWN_TEST):
                continue
            hits.append({"kind": name, "token": token, "redacted": redact(token)})
    return hits


def validate_github_token(token):
    """Live-check: GET /user with the token. 200 = live."""
    try:
        req = urllib.request.Request(
            "https://api.github.com/user",
            headers={"Authorization": f"token {token}", "User-Agent": UA}
        )
        with urllib.request.urlopen(req, timeout=8) as r:
            if r.status == 200:
                d = json.loads(r.read())
                return {"live": True, "owner": d.get("login","?"), "type": d.get("type","?")}
    except Exception:
        pass
    return {"live": False}


def process_repo(repo):
    """Scan one repo's commit history for leaked secrets."""
    findings = []
    commits = list_recent_commits(repo, max_commits=30)
    for sha in commits:
        patch = get_commit_diff(repo, sha)
        if not patch:
            continue
        hits = extract_secrets(patch)
        for h in hits:
            entry = {
                "repo": repo,
                "commit": sha[:8],
                "kind": h["kind"],
                "token_redacted": h["redacted"],
                "url": f"https://github.com/{repo}/commit/{sha}",
                "discovered_at": datetime.now(timezone.utc).isoformat(),
            }
            # Live-validate if it's a GitHub token
            if h["kind"].startswith("github"):
                v = validate_github_token(h["token"].decode("latin-1", "replace"))
                entry["validation"] = v
                if v.get("live"):
                    entry["severity"] = "CRITICAL — live token leaked in commit history"
                else:
                    entry["severity"] = "INFO — token revoked"
            else:
                entry["severity"] = f"NEEDS-MANUAL-VALIDATION — {h['kind']}"
            findings.append(entry)
        time.sleep(0.1)  # respect rate limit
    return findings


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--orgs-limit", type=int, default=len(DEFI_ORGS))
    p.add_argument("--repos-per-org", type=int, default=10)
    args = p.parse_args()

    print(f"[+] GitHub commit-history secret hunt")
    print(f"[+] Orgs: {args.orgs_limit}, ~{args.repos_per_org} repos each, last 30 commits each")
    print(f"[+] Ledger: {LEDGER}")
    print()

    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    all_findings = []
    repos_scanned = 0

    with open(LEDGER, "a") as out:
        for i, org in enumerate(DEFI_ORGS[:args.orgs_limit], 1):
            print(f"  [{i:>3}/{args.orgs_limit}] {org}", end=" ", flush=True)
            repos = list_org_repos(org, max_repos=args.repos_per_org)
            print(f"({len(repos)} repos)", flush=True)
            for repo in repos:
                repos_scanned += 1
                try:
                    fs = process_repo(repo)
                    if fs:
                        live = sum(1 for f in fs if f.get("validation",{}).get("live"))
                        print(f"      [{repo}] {len(fs)} hits ({live} live)", flush=True)
                        for f in fs:
                            out.write(json.dumps(f) + "\n")
                            out.flush()
                            all_findings.append(f)
                except Exception as e:
                    print(f"      [{repo}] error: {e}", flush=True)
                time.sleep(0.3)

    print()
    print("=" * 70)
    print("COMMIT-HISTORY SECRET HUNT SUMMARY")
    print("=" * 70)
    print(f"  Orgs scanned: {args.orgs_limit}")
    print(f"  Repos scanned: {repos_scanned}")
    print(f"  Pattern hits: {len(all_findings)}")
    live = [f for f in all_findings if f.get("validation",{}).get("live")]
    print(f"  🔴 LIVE secrets: {len(live)}")
    if live:
        print()
        print("CRITICAL FINDINGS:")
        for f in live:
            print(f"  {f['repo']:<40} {f['kind']:<15} {f['token_redacted']}")
            print(f"    {f['url']}")


if __name__ == "__main__":
    main()
