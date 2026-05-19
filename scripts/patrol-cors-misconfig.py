#!/usr/bin/env python3
"""
patrol-cors-misconfig — scanner #22.

Hunts CORS misconfigurations that allow attacker-origin to read credentialed
API responses. Two dangerous patterns:
  1. ACAO reflects Origin header + ACAC: true → universal CSRF on auth APIs
  2. ACAO: null + ACAC: true → exploitable via sandboxed iframe
Bounty payouts: $500-$2K typical when found on a bounty-program endpoint.
"""
from __future__ import annotations
import argparse, json, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-CORSPatrol/0.1"
LEDGER = Path.home() / ".lictor" / "cors-ledger.jsonl"

PROBES = [
    ("/", "GET"),
    ("/api/", "GET"),
    ("/api/v1/", "GET"),
    ("/api/v1/users/me", "GET"),
    ("/api/account", "GET"),
    ("/api/profile", "GET"),
    ("/api/me", "GET"),
    ("/api/user", "GET"),
    ("/.well-known/openid-configuration", "GET"),
    ("/graphql", "POST"),
]
PREFIXES = ["", "api.", "app.", "admin.", "internal.", "auth.", "id.", "account.", "dashboard."]

@dataclass
class CORSFinding:
    host: str; path: str; method: str
    pattern: str  # "reflect-origin-with-creds" | "null-origin-with-creds"
    acao: str; acac: str; payout: int
    found_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))


def probe(host, path, method="GET", origin="https://attacker.example.com", timeout=6):
    url = f"https://{host}{path}"
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": UA,
            "Origin": origin,
            "Accept": "*/*",
        }, method=method)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")
            return r.status, acao, acac
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Access-Control-Allow-Origin", ""), e.headers.get("Access-Control-Allow-Credentials", "")
    except Exception:
        return 0, "", ""


def check_one(host_path):
    host, (path, method) = host_path
    # Probe 1: attacker origin reflection
    status, acao, acac = probe(host, path, method, origin="https://attacker.example.com")
    if status == 0: return None
    if acac.lower() == "true":
        if acao == "https://attacker.example.com":
            return CORSFinding(host=host, path=path, method=method,
                pattern="reflect-attacker-origin-with-creds",
                acao=acao, acac=acac, payout=2000)
        if acao == "null":
            return CORSFinding(host=host, path=path, method=method,
                pattern="null-origin-with-creds",
                acao=acao, acac=acac, payout=1000)
        if acao == "*":
            # ACAO:* + ACAC:true is invalid per spec but some browsers honor it
            return CORSFinding(host=host, path=path, method=method,
                pattern="wildcard-with-creds-INVALID",
                acao=acao, acac=acac, payout=300)
    return None


def append_ledger(f):
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    with LEDGER.open("a") as fp:
        fp.write(json.dumps(asdict(f)) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default=str(Path.home() / ".lictor" / "bounty-corpus-priority.txt"))
    ap.add_argument("--max-domains", type=int, default=300)
    ap.add_argument("--workers", type=int, default=80)
    args = ap.parse_args()

    domains = [l.strip() for l in Path(args.corpus).expanduser().read_text().splitlines() if l.strip()][:args.max_domains]
    print(f"[+] cors patrol — {len(domains)} apex × {len(PREFIXES)} prefixes × {len(PROBES)} probes", flush=True)

    tasks = []
    for apex in domains:
        for prefix in PREFIXES:
            host = f"{prefix}{apex}"
            for p in PROBES:
                tasks.append((host, p))
    print(f"[+] total probes: {len(tasks)}", flush=True)

    hits = []
    completed = 0
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(check_one, t): t for t in tasks}
        for fut in as_completed(futures):
            completed += 1
            if completed % 500 == 0:
                print(f"  [{completed}/{len(tasks)}] {len(hits)} hits", flush=True)
            try: r = fut.result(timeout=10)
            except: r = None
            if r:
                print(f"  🔴🔴 CORS-MISCONFIG  {r.pattern:<35} https://{r.host}{r.path}  (${r.payout})", flush=True)
                append_ledger(r); hits.append(r)
    print(f"\n[+] scan complete: {len(hits)} CORS misconfigs found")


if __name__ == "__main__": main()
