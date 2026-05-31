#!/usr/bin/env python3
"""
passive-recon — discover subdomains WITHOUT touching the targets (Option 3).

Pulls names from certificate-transparency logs (crt.sh) — a passive, public
data source. We query crt.sh, not the target's servers, so this generates
effectively zero traffic to anyone we're researching. Ideal to run from a
residential line: invisible to the targets and their ISPs.

    python3 scripts/passive-recon.py                       # IL apexes by default
    python3 scripts/passive-recon.py --apex FILE --out FILE

Output: newline-separated subdomains, opt-out-filtered. Feed it to the gentle
runner for a throttled, identifiable active pass when you choose to.
"""
from __future__ import annotations
import argparse, json, sys, time, urllib.request, urllib.error
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from scan_ethics import USER_AGENT, filter_hosts  # noqa: E402

HOME = Path.home()
DEF_APEX = HOME / ".lictor" / "il-recon" / "il-apex.txt"
DEF_OUT = HOME / ".lictor" / "il-recon" / "il-passive-subs.txt"


def crtsh(domain: str, timeout: float = 40.0, retries: int = 3) -> set[str]:
    """Certificate-transparency names for a domain, via crt.sh. Passive.

    crt.sh is frequently slow on the first hit (cold query) — we retry with
    backoff rather than silently returning empty.
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    names: set[str] = set()
    data = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT,
                                                       "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                data = json.loads(r.read().decode("utf-8", "replace"))
            break
        except urllib.error.HTTPError as e:
            if e.code == 429:               # crt.sh throttle — wait it out, don't hammer
                time.sleep(30 + 20 * attempt)
            else:
                time.sleep(3 * (attempt + 1))
        except Exception:
            time.sleep(3 * (attempt + 1))   # timeout/cold-query backoff: 3s, 6s, …
    if not data:
        return names
    for row in data:
        for field in ("name_value", "common_name"):
            val = row.get(field) or ""
            for n in val.split("\n"):
                n = n.strip().lower().lstrip("*.").rstrip(".")
                if n.endswith("." + domain) or n == domain:
                    if " " not in n and "@" not in n:
                        names.add(n)
    return names


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apex", default=str(DEF_APEX), help="file of apex domains")
    ap.add_argument("--out", default=str(DEF_OUT))
    ap.add_argument("--sleep", type=float, default=1.5, help="polite gap between crt.sh queries")
    args = ap.parse_args()

    apex_file = Path(args.apex)
    if not apex_file.exists():
        print(f"apex file not found: {apex_file}", file=sys.stderr)
        return 1
    apexes = [a.strip() for a in apex_file.read_text().splitlines() if a.strip() and not a.startswith("#")]
    print(f"[passive-recon] {len(apexes)} apexes via crt.sh (passive — zero target traffic)", flush=True)

    all_subs: set[str] = set()
    for i, apex in enumerate(apexes, 1):
        found = crtsh(apex)
        all_subs |= found
        if i % 10 == 0 or found:
            print(f"  [{i}/{len(apexes)}] {apex}: +{len(found)}  (total {len(all_subs)})", flush=True)
        time.sleep(args.sleep)  # be gentle to crt.sh, a free shared service

    # honor opt-out, fold in apexes themselves, sort
    final = sorted(set(filter_hosts(sorted(all_subs))) | set(apexes))
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text("\n".join(final) + "\n")
    print(f"[passive-recon] {len(final)} unique names (opt-out filtered) → {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
