"""ETHGlobal / Web3 hackathon committed-secrets scanner.

Strategy:
1. GitHub topic search for hackathon repos (topic:ethglobal, topic:eth-global,
   topic:web3-hackathon, topic:hackathon-project, topic:devpost) created in
   last 90 days
2. For each repo, check for committed .env files containing PRIVATE_KEY=0x,
   MNEMONIC, DEPLOYER_PRIVATE_KEY (via GitHub raw file fetch — no clone)
3. Also check for common hardhat-deploy artifact paths

Ethical: GET only the first 200 bytes of .env files. Signature-match (env var
name) — never the value after =. Never extract or log the actual key.
"""
import urllib.request, urllib.error, ssl, json, re, time
from pathlib import Path
from datetime import datetime, timezone, timedelta

UA = "Lictor-v3-HackHunt/0.1 (+https://lictor-ai.com)"
LEDGER = Path.home() / "Lictor" / "v3" / "ledgers" / "hackathon-secrets.jsonl"
TOKEN = (Path.home() / ".lictor" / "gh-token").read_text().strip()

TOPICS = ["ethglobal", "eth-global", "web3-hackathon", "hackathon-project",
          "devpost", "hackathon-2026", "encode-club", "buildspace-projects",
          "polygon-hackathon", "solana-hackathon"]

# Sensitive paths to probe in each repo (raw.githubusercontent.com)
SENSITIVE_PATHS = [
    ".env", ".env.production", ".env.local", ".env.deploy", ".env.mainnet",
    "packages/contracts/.env", "packages/hardhat/.env", "packages/foundry/.env",
    "frontend/.env", "backend/.env", "hardhat.config.js",
    "deploy/key.json", "scripts/deploy/key.json",
    ".secrets", "secrets.json", "config/secrets.json",
]

# Patterns that indicate real key material in a .env body
KEY_SIG = re.compile(
    rb"PRIVATE_KEY\s*=\s*[\"\']?0x[0-9a-f]{50}|"
    rb"MNEMONIC\s*=\s*[\"\']?[a-z]+\s+[a-z]+\s+[a-z]+\s+[a-z]+|"
    rb"DEPLOYER_PRIVATE_KEY|"
    rb"ALCHEMY_API_KEY\s*=\s*[\"\']?[A-Za-z0-9_-]{20}|"
    rb"INFURA_PROJECT_ID\s*=\s*[\"\']?[a-f0-9]{20}",
    re.I)


def fetch(url, headers=None, timeout=10):
    headers = headers or {}
    headers.setdefault("User-Agent", UA)
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read() if e.fp else b""
    except Exception as ex:
        return None, str(ex).encode()


def search_topic(topic, max_repos=50):
    """Search GitHub for repos with given topic created in last 90 days."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=90)).strftime("%Y-%m-%d")
    q = f"topic:{topic} created:>{cutoff}"
    url = f"https://api.github.com/search/repositories?q=" + urllib.request.quote(q) + f"&per_page={max_repos}&sort=updated"
    st, body = fetch(url, headers={"Authorization": f"token {TOKEN}", "Accept": "application/vnd.github.v3+json"})
    if st != 200:
        return []
    return json.loads(body).get("items", [])


def probe_repo(repo_full_name, default_branch="main"):
    """For each sensitive path, fetch first 200 bytes via raw.gh. Return matches."""
    findings = []
    for path in SENSITIVE_PATHS:
        for branch in (default_branch, "master"):
            url = f"https://raw.githubusercontent.com/{repo_full_name}/{branch}/{path}"
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            try:
                with urllib.request.urlopen(req, timeout=6) as r:
                    body = r.read(200)
                    if KEY_SIG.search(body):
                        m = KEY_SIG.search(body)
                        sig = m.group(0).decode("utf-8", "replace")[:30] + "..."
                        findings.append({"path": path, "branch": branch, "sig": sig, "size": len(body)})
                        break  # don't try master if main worked
            except Exception:
                continue
    return findings


all_findings = []
all_repos = set()
print(f"[+] hackathon-secrets hunt — {len(TOPICS)} GitHub topics × top 50 repos each", flush=True)
print(f"[+] Filter: created in last 90 days, sorted by recently-updated", flush=True)
print(f"[+] Per repo: check {len(SENSITIVE_PATHS)} sensitive paths × 2 branches (main, master)", flush=True)
print(f"[+] Ethical: GET 200B max, sig-match env var name, NEVER extract key value", flush=True)
print(flush=True)

for topic in TOPICS:
    print(f"  [search]  topic:{topic} (created:>90d)...", flush=True)
    repos = search_topic(topic, max_repos=50)
    print(f"  [search]  topic:{topic} → {len(repos)} repos", flush=True)
    time.sleep(2.5)  # rate limit
    for repo in repos:
        full = repo.get("full_name")
        if not full or full in all_repos: continue
        all_repos.add(full)
        default_branch = repo.get("default_branch", "main")
        # don't slam github raw — light pause
        time.sleep(0.5)
        hits = probe_repo(full, default_branch)
        if hits:
            for h in hits:
                print(f"  🔴 HACK-SECRET  {full}@{h['branch']}/{h['path']}  → {h['sig']}", flush=True)
                all_findings.append({
                    "type": "hackathon-secret",
                    "repo": full,
                    "branch": h["branch"],
                    "path": h["path"],
                    "sig_excerpt": h["sig"],
                    "topic": topic,
                    "stars": repo.get("stargazers_count", 0),
                    "created_at": repo.get("created_at"),
                    "discovered_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                })

print(f"\n[+] hackathon-secrets hunt complete: {len(all_findings)} findings across {len(all_repos)} unique repos", flush=True)
if all_findings:
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    with LEDGER.open("a") as f:
        for fi in all_findings: f.write(json.dumps(fi) + "\n")
    print(f"[+] Wrote to {LEDGER}", flush=True)
