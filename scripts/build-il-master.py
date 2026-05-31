#!/usr/bin/env python3
"""
build-il-master — consolidate every Israeli target list into one clean master.

Israel is our first-priority zone. Many IL host lists have accumulated
(il-corpus, the il-parties-* family, MENA, plus .il hosts hiding inside the
big global corpora). This dedupes them all into:

  ~/.lictor/il-master.txt        — one host per line, sorted, deduped
  /tmp/il-discovery/scan-pool.txt — rank<TAB>host (the format scan-il-verified wants)

Run standalone or let the daily IL patrol call it first so the master stays
fresh as corpora grow. Hosts only — no scheme/path/port/wildcard. Draft-only;
touches nothing on the network.
"""
from __future__ import annotations
import re, sys
from pathlib import Path

HOME = Path.home()
LIC = HOME / ".lictor"
OUT_MASTER = LIC / "il-master.txt"
POOL_DIR = Path("/tmp/il-discovery")
OUT_POOL = POOL_DIR / "scan-pool.txt"

# IL-specific corpora — every host here is in-scope as-is.
IL_LISTS = [
    "il-corpus.txt", "il-parties-clean.txt", "il-parties-corpus.txt",
    "il-parties-expanded.txt", "il-parties-extended.txt",
]
# Mixed corpora — pull ONLY the .il hosts out of these.
MIXED_LISTS = [
    "day3-mena-corpus.txt", "bounty-corpus.txt", "bounty-corpus-paid.txt",
    "global-mega-corpus.txt", "crypto-deep-corpus.txt",
]

# Israeli second-level / TLD suffixes that mark a host as in-scope.
IL_SUFFIXES = (".co.il", ".org.il", ".gov.il", ".muni.il", ".ac.il",
               ".net.il", ".k12.il", ".idf.il", ".health.gov.il", ".il")


def clean_host(raw: str) -> str | None:
    """Normalise a corpus line to a bare hostname, or None if unusable."""
    s = raw.strip()
    if not s or s.startswith("#"):
        return None
    s = re.sub(r"^[a-zA-Z]+://", "", s)        # strip scheme
    s = s.split("/")[0].split("?")[0]          # strip path/query
    s = s.split("@")[-1]                        # strip any user@ part
    s = s.split(":")[0]                         # strip port
    s = s.strip().strip(".").lower()
    if s.startswith("*."):                      # drop wildcards — not a probe target
        return None
    if not s or " " in s or "." not in s:
        return None
    if not re.match(r"^[a-z0-9.\-]+$", s):
        return None
    return s


def is_il(host: str) -> bool:
    return host.endswith(IL_SUFFIXES)


def read_lines(name: str) -> list[str]:
    p = LIC / name
    if not p.exists():
        return []
    return p.read_text(errors="ignore").splitlines()


def main() -> int:
    hosts: set[str] = set()
    src_counts: dict[str, int] = {}

    for name in IL_LISTS:
        n = 0
        for line in read_lines(name):
            h = clean_host(line)
            if h:
                hosts.add(h); n += 1
        src_counts[name] = n

    for name in MIXED_LISTS:
        n = 0
        for line in read_lines(name):
            h = clean_host(line)
            if h and is_il(h):
                hosts.add(h); n += 1
        src_counts[name] = n  # count = IL hosts harvested from this mixed list

    # Final guard: keep only plausibly-Israeli hosts in the master.
    il_hosts = sorted(h for h in hosts if is_il(h))

    OUT_MASTER.parent.mkdir(parents=True, exist_ok=True)
    OUT_MASTER.write_text("\n".join(il_hosts) + "\n")

    POOL_DIR.mkdir(parents=True, exist_ok=True)
    with OUT_POOL.open("w") as fh:
        for i, h in enumerate(il_hosts, 1):
            fh.write(f"{i}\t{h}\n")

    print(f"[build-il-master] {len(il_hosts)} unique IL hosts → {OUT_MASTER}")
    print(f"[build-il-master] scan pool (rank<TAB>host) → {OUT_POOL}")
    for name, n in src_counts.items():
        tag = "IL-only" if name in MIXED_LISTS else "all"
        print(f"   {name:<26} {n:>5} hosts ({tag})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
