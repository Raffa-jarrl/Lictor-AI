#!/usr/bin/env python3
"""
scan_ethics — shared good-netizen helpers for every Lictor scanner.

One place for: our identifiable User-Agent, the opt-out exclusion list, and
gentle default rates. Import this instead of hard-coding a UA or re-reading
the opt-out file in each scanner.

    from scan_ethics import USER_AGENT, filter_hosts, is_optout, GENTLE

    hosts = filter_hosts(hosts)          # drop anyone who opted out
    headers = {"User-Agent": USER_AGENT} # identifiable, points to our policy
"""
from __future__ import annotations
from pathlib import Path

# Identifiable UA — points anyone who looks straight to the policy + abuse box.
USER_AGENT = "Lictor-Patrol/1.0 (+https://lictorai.com/scan-policy; abuse@lictorai.com)"
POLICY_URL = "https://lictorai.com/scan-policy"
ABUSE_EMAIL = "abuse@lictorai.com"

OPTOUT_FILE = Path.home() / ".lictor" / "opt-out.txt"

# Gentle defaults for the single-lane runner (Option 2: throttled + transparent).
GENTLE = {
    "threads": 8,        # was 20-50 across the swarm — now one lane, low width
    "rate_limit": 40,    # requests/sec ceiling
    "sleep": 0.4,        # polite gap between hosts
    "timeout": 8,
}


def load_optout() -> set[str]:
    """Set of opted-out apex/host names (lowercased)."""
    out: set[str] = set()
    try:
        for line in OPTOUT_FILE.read_text().splitlines():
            s = line.strip().lower()
            if s and not s.startswith("#"):
                out.add(s.lstrip("*."))
    except FileNotFoundError:
        pass
    return out


def is_optout(host: str, optout: set[str] | None = None) -> bool:
    """True if host, or any parent domain of it, is on the opt-out list."""
    optout = load_optout() if optout is None else optout
    if not optout:
        return False
    h = host.strip().lower().rstrip(".")
    parts = h.split(".")
    # check the full host and every parent suffix (sub.a.co.il → a.co.il → co.il)
    for i in range(len(parts) - 1):
        if ".".join(parts[i:]) in optout:
            return True
    return h in optout


def filter_hosts(hosts) -> list[str]:
    """Drop every host covered by the opt-out list. Logs how many were removed."""
    optout = load_optout()
    if not optout:
        return list(hosts)
    kept, dropped = [], 0
    for h in hosts:
        if is_optout(h, optout):
            dropped += 1
        else:
            kept.append(h)
    if dropped:
        import sys
        print(f"[scan_ethics] opt-out: excluded {dropped} host(s)", file=sys.stderr)
    return kept


if __name__ == "__main__":
    # quick self-test / status
    o = load_optout()
    print(f"opt-out entries: {len(o)}")
    print(f"User-Agent: {USER_AGENT}")
    for t in ("example.co.il", "sub.example.co.il", "safe.org.il"):
        print(f"  is_optout({t}) = {is_optout(t, o)}")
