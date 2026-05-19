#!/usr/bin/env python3
"""
patrol-dns-axfr — scanner #20.

Hunts misconfigured DNS servers that allow zone transfer (AXFR) to anyone.
A successful AXFR dumps the entire zone — every subdomain, every internal
service, every CNAME pointing at staging infra. Massive recon win for an
attacker; clear $1K-$5K bounty when found on a bounty program.

Method:
  1. For each apex domain, get its NS records via `dig +short NS`
  2. For each NS, attempt AXFR: `dig AXFR @ns.example.com example.com +time=5`
  3. If the response includes more than the SOA record, the zone is leaking

Why this works:
  - DNS admins occasionally forget to restrict AXFR
  - bind/PowerDNS default-deny but customer setups vary
  - Often the ONLY proof needed is the AXFR response itself
"""
from __future__ import annotations
import argparse, json, subprocess, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path

LEDGER = Path.home() / ".lictor" / "axfr-ledger.jsonl"
OUT = Path.home() / "Lictor" / "docs" / "launch" / f"axfr-{datetime.now().strftime('%Y-%m-%d')}-private.md"


@dataclass
class AxfrLeak:
    domain: str
    nameserver: str
    record_count: int
    sample_records: list
    found_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))


def get_nameservers(domain, timeout=5):
    try:
        out = subprocess.check_output(["dig", "+short", "NS", domain, f"+time={timeout}"],
                                       stderr=subprocess.DEVNULL, timeout=timeout+2)
        return [ns.strip(".") for ns in out.decode().strip().splitlines() if ns.strip()]
    except Exception:
        return []


def try_axfr(domain, nameserver, timeout=6):
    """Returns list of records if AXFR works (and has >1 record), else None."""
    try:
        out = subprocess.check_output(
            ["dig", f"@{nameserver}", "AXFR", domain, f"+time={timeout}", "+nostats", "+nocomments"],
            stderr=subprocess.DEVNULL, timeout=timeout+2)
        text = out.decode("utf-8", "replace")
        records = [l for l in text.splitlines() if l.strip() and not l.startswith(";")]
        # Need to see more than just SOA (1 line) to count as leak — real zones have many records
        if len(records) > 5:
            return records
    except Exception:
        pass
    return None


def load_ledger():
    if not LEDGER.exists(): return set()
    seen = set()
    for l in LEDGER.read_text().splitlines():
        if l.strip():
            try:
                d = json.loads(l)
                seen.add(d["domain"])
            except: pass
    return seen


def append_ledger(leak):
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    with LEDGER.open("a") as f:
        f.write(json.dumps(asdict(leak)) + "\n")


def check_domain(domain):
    """For one apex, try AXFR against each of its nameservers."""
    nss = get_nameservers(domain)
    if not nss: return None
    for ns in nss[:5]:  # cap nameservers per domain
        records = try_axfr(domain, ns)
        if records:
            return AxfrLeak(
                domain=domain, nameserver=ns,
                record_count=len(records),
                sample_records=records[:10],
            )
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default=str(Path.home() / ".lictor" / "bounty-corpus-priority.txt"))
    ap.add_argument("--max-domains", type=int, default=500)
    ap.add_argument("--workers", type=int, default=50)
    args = ap.parse_args()

    seen = load_ledger()
    print(f"[+] dns-axfr patrol — {len(seen)} prior hits in ledger", flush=True)

    domains = [l.strip() for l in Path(args.corpus).expanduser().read_text().splitlines()
               if l.strip() and l.strip() not in seen][:args.max_domains]
    print(f"[+] scanning {len(domains)} domains for AXFR leaks ({args.workers} workers)", flush=True)

    hits = []
    completed = 0
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(check_domain, d): d for d in domains}
        for fut in as_completed(futures):
            d = futures[fut]
            completed += 1
            if completed % 50 == 0:
                print(f"  [{completed}/{len(domains)}] scanned, {len(hits)} hits", flush=True)
            try: result = fut.result(timeout=20)
            except Exception: result = None
            if result:
                print(f"  🔴🔴 AXFR-LEAK  {result.domain}  via {result.nameserver}  ({result.record_count} records)", flush=True)
                append_ledger(result)
                hits.append(result)

    print(f"\n[+] scan complete: {len(hits)} AXFR leaks found")
    if hits:
        OUT.parent.mkdir(parents=True, exist_ok=True)
        with OUT.open("w") as f:
            f.write(f"# DNS AXFR leaks — {datetime.now().strftime('%Y-%m-%d')} (PRIVATE)\n\n")
            f.write(f"**Domains scanned:** {len(domains)}\n**Leaks confirmed:** {len(hits)}\n\n")
            f.write("| Domain | Nameserver | Records | Sample |\n|---|---|---|---|\n")
            for h in hits:
                sample = " // ".join(h.sample_records[:3])[:200]
                f.write(f"| `{h.domain}` | `{h.nameserver}` | {h.record_count} | `{sample}` |\n")
        print(f"    → {OUT}")


if __name__ == "__main__":
    main()
