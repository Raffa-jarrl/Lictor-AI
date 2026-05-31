#!/usr/bin/env python3
"""
orchestrate-f500-deep-scan — runs a deep-scan battery against 500+ bounty-active
programs in parallel batches.

Pattern: sliding-window concurrency. 50 worker processes active at any time.
Each worker:
  1. Pulls next company from queue
  2. Downloads its chaos.projectdiscovery.io subdomain zip
  3. Filters to ~500 leak-likely subdomains (admin/api/dev/staging/etc)
  4. Runs scanner battery (sourcemap, terraform-state, cicd-panels,
     web-exposed-files, cors-credentials)
  5. Writes per-company findings to v3/ledgers/f500/<company>/
  6. Picks the next company

Total estimated runtime: 1-4 hours for 577 companies with 50 workers.

Resume-safe: writes per-company state file; can be killed + restarted.

Usage:
  orchestrate-f500-deep-scan.py
"""
from __future__ import annotations
import argparse, json, os, re, subprocess, time, tempfile, zipfile, io
import urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path("/Users/raffa/Lictor")
LEDGER_DIR = ROOT / "v3" / "ledgers" / "f500"
STATE_FILE = ROOT / "v3" / "ledgers" / "f500" / "_orchestrator-state.json"
UA = "Lictor-F500Orchestrator/0.1 (+https://lictor-ai.com)"

# Telegram notify helper
import sys as _sys
_sys.path.insert(0, str(ROOT / "v3" / "scripts"))
try:
    from notify_telegram import notify as _tg_notify
except Exception:
    def _tg_notify(msg, **kw): return False

def tg(msg: str) -> None:
    """Fire-and-forget Telegram notification."""
    try: _tg_notify(msg)
    except Exception: pass

# Filter subdomains to leak-likely patterns
LEAK_LIKELY_PREFIXES = (
    "admin", "api", "auth", "dev", "stage", "staging", "test", "uat", "qa",
    "internal", "intranet", "beta", "preview", "sandbox", "console",
    "dashboard", "docs", "developer", "github", "gitlab", "ci",
    "jenkins", "metrics", "grafana", "kibana", "sso", "login", "oauth",
    "id", "accounts", "my", "support", "help", "status", "monitor",
    "portal", "registry", "git", "bamboo", "drone", "argo", "tekton",
    "vault", "secret", "key", "credentials", "config", "deploy",
)

SCANNERS_PER_COMPANY = [
    # Faster per-scanner: smaller batches, higher parallelism, shorter timeouts
    {
        "name": "terraform-state",
        "script": "scripts/patrol-terraform-state-exposure.py",
        "args": ["--hosts", "{hosts_file}", "--max-hosts", "100", "--threads", "10"],
        "ledger": "terraform-state.jsonl",
        "timeout": 300,  # 5 min
    },
    {
        "name": "cicd-panels",
        "script": "scripts/patrol-cicd-admin-panels.py",
        # Limited port set + higher threads + fail-fast probe added in scanner
        "args": ["--hosts", "{hosts_file}", "--max-hosts", "60", "--threads", "20",
                 "--ports", "80,443,8080,8443"],
        "ledger": "cicd-panels.jsonl",
        "timeout": 600,  # 10 min — port-alive check makes most ports skip fast
    },
    {
        "name": "sourcemap",
        "script": "scripts/patrol-sourcemap-leak.py",
        # Sourcemap now accepts --ledger (added in v2). Reads --corpus as host list.
        "args": ["--corpus", "{hosts_file}", "--max-domains", "100", "--workers", "20"],
        "ledger": "sourcemap.jsonl",
        "timeout": 300,
    },
    {
        "name": "cors",
        "script": "scripts/patrol-cors-credentials-reflected.py",
        "args": ["--hosts", "{hosts_file}", "--max-hosts", "100", "--threads", "8",
                 "--paths-per-host", "4"],
        "ledger": "cors.jsonl",
        "timeout": 300,
    },
]

def http_get(url, timeout=30, max_bytes=200_000_000):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read(max_bytes)
    except Exception as e:
        return None

def load_programs() -> list[dict]:
    """Load the chaos program index."""
    body = http_get("https://chaos-data.projectdiscovery.io/index.json")
    if not body:
        # fallback: cached
        cache = Path("/tmp/lictor-f500-programs.json")
        if cache.exists():
            return json.loads(cache.read_text())
        return []
    progs = json.loads(body)
    return [p for p in progs if p.get("platform") and p.get("URL")]

def load_state() -> dict:
    state = {"completed": [], "failed": [], "skipped": []}
    if STATE_FILE.exists():
        try: state = json.loads(STATE_FILE.read_text())
        except: pass
    # Also infer completed from on-disk summary.json files (resume safety)
    if LEDGER_DIR.exists():
        existing = set(state.get("completed", []))
        for sub in LEDGER_DIR.iterdir():
            summ = sub / "summary.json"
            if summ.exists():
                try:
                    s = json.loads(summ.read_text())
                    name = s.get("name")
                    if name and name not in existing:
                        state.setdefault("completed", []).append(name)
                        existing.add(name)
                except Exception:
                    pass
    return state

def save_state(state: dict):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2))

def safe_name(name: str) -> str:
    """Normalize a program name into a filesystem-safe folder name."""
    return re.sub(r'[^a-z0-9._-]', '_', name.lower())[:60]

def fetch_subdomains_for_program(prog: dict, work_dir: Path) -> list[str]:
    """Download + extract chaos zip; return filtered subdomain list."""
    zip_url = prog["URL"]
    zip_bytes = http_get(zip_url, timeout=60, max_bytes=100_000_000)
    if not zip_bytes: return []
    subdomains = set()
    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes), 'r') as zf:
            for name in zf.namelist():
                if not name.endswith(".txt"): continue
                with zf.open(name) as f:
                    for line in f.read().decode("utf-8", "replace").splitlines():
                        line = line.strip().lower()
                        if line and "." in line and " " not in line:
                            subdomains.add(line)
    except Exception:
        return []

    # Filter to leak-likely
    filtered = set()
    for sub in subdomains:
        # Always include the apex
        # Otherwise must match a leak-likely prefix
        host_label = sub.split(".")[0]
        if (any(host_label.startswith(p) for p in LEAK_LIKELY_PREFIXES) or
            any(f".{p}." in sub for p in LEAK_LIKELY_PREFIXES)):
            filtered.add(sub)
        if len(filtered) >= 500: break

    # If no filter matches, sample first 200
    if not filtered:
        return sorted(subdomains)[:200]
    return sorted(filtered)[:500]

def run_scanner(scanner: dict, hosts_file: Path, output_ledger: Path,
                timeout: int = None) -> dict:
    if timeout is None:
        timeout = scanner.get("timeout", 300)
    """Run a single scanner; return result summary."""
    args = [a.replace("{hosts_file}", str(hosts_file)) for a in scanner["args"]]
    # Add ledger override
    args += ["--ledger", str(output_ledger)]
    cmd = ["/usr/bin/python3", str(ROOT / scanner["script"])] + args
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        # Count findings
        finding_count = 0
        if output_ledger.exists():
            with open(output_ledger) as f:
                finding_count = sum(1 for _ in f)
        return {
            "name": scanner["name"], "status": "ok" if result.returncode == 0 else "error",
            "findings": finding_count, "exit_code": result.returncode,
            "stderr_tail": result.stderr[-500:] if result.stderr else "",
        }
    except subprocess.TimeoutExpired:
        return {"name": scanner["name"], "status": "timeout", "findings": 0}
    except Exception as e:
        return {"name": scanner["name"], "status": "exception", "findings": 0,
                "error": str(e)[:200]}

def scan_one_company(prog: dict) -> dict:
    """Full deep-scan battery for one company. Returns summary."""
    name = prog["name"]
    safe = safe_name(name)
    out_dir = LEDGER_DIR / safe
    out_dir.mkdir(parents=True, exist_ok=True)

    summary = {
        "name": name, "platform": prog.get("platform"),
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scanners": [],
        "total_findings": 0,
    }

    # Fetch + filter subdomains
    hosts = fetch_subdomains_for_program(prog, out_dir)
    if not hosts:
        summary["status"] = "no_subdomains"
        (out_dir / "summary.json").write_text(json.dumps(summary, indent=2))
        return summary
    summary["subdomain_count"] = len(hosts)

    # Write hosts file for scanners
    hosts_file = out_dir / "hosts.txt"
    hosts_file.write_text("\n".join(hosts) + "\n")

    # Run each scanner
    for scanner in SCANNERS_PER_COMPANY:
        out_ledger = out_dir / scanner["ledger"]
        result = run_scanner(scanner, hosts_file, out_ledger)
        summary["scanners"].append(result)
        summary["total_findings"] += result.get("findings", 0)

    summary["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    summary["status"] = "complete"
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2))

    # NO per-company Telegram. A separate verify-and-notify daemon scans summary.json
    # files, runs strict verification against the new FP rules, and ONLY notifies when
    # a finding survives the verification gate. See verify-f500-findings.py.
    return summary

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-programs", type=int, default=500)
    ap.add_argument("--workers", type=int, default=50)
    ap.add_argument("--resume", action="store_true",
                    help="Skip already-completed programs from state file")
    args = ap.parse_args()

    LEDGER_DIR.mkdir(parents=True, exist_ok=True)
    programs = load_programs()[:args.max_programs]
    print(f"[+] Loaded {len(programs)} bounty-active programs")

    state = load_state() if args.resume else {"completed": [], "failed": [], "skipped": []}
    pending = [p for p in programs if p["name"] not in state["completed"]]
    print(f"[+] {len(pending)} pending ({len(state['completed'])} already done)")
    print(f"[+] Running {args.workers} concurrent workers")
    print(f"[+] Per-company timeout: 15 min per scanner × 4 scanners = ~1 hour max\n")

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(scan_one_company, p): p for p in pending}
        done = 0
        for fut in as_completed(futures):
            done += 1
            prog = futures[fut]
            try:
                summary = fut.result()
                state["completed"].append(prog["name"])
                save_state(state)
                tag = "🔴" if summary.get("total_findings", 0) > 0 else "."
                print(f"  [{done}/{len(pending)}] {tag} {prog['name']:35s}  "
                      f"subs={summary.get('subdomain_count',0):4d}  "
                      f"findings={summary.get('total_findings',0):3d}  "
                      f"status={summary.get('status','?')}")
            except Exception as e:
                state["failed"].append({"name": prog["name"], "error": str(e)[:200]})
                save_state(state)
                print(f"  [{done}/{len(pending)}] ❌ {prog['name']}  EXC: {str(e)[:80]}")

    print(f"\n[+] Done. completed={len(state['completed'])} failed={len(state['failed'])}")
    print(f"[+] Per-company results in {LEDGER_DIR}/<company>/")
    print(f"[+] Aggregate via: cat {LEDGER_DIR}/*/summary.json | jq '...'")

if __name__ == "__main__":
    main()
