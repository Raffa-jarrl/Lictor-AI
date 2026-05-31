#!/usr/bin/env python3
"""
build-expanded-corpus — adds lower-tier targets to the unified F500 host corpus.

Sources:
  1. DefiLlama protocols (5074 DeFi projects, many on Immunefi) — pull project URLs
  2. Chaos VDP-only programs (270 unscanned) — download zips, extract subdomains
  3. Government VDPs — pull CISA list via API
  4. HuntrDev OSS bounties — fetch huntr.com listings

Writes to v3/ledgers/all-bounty-hosts.txt (replaces f500-all-hosts.txt as default).
"""
from __future__ import annotations
import io, json, urllib.parse, urllib.request, zipfile
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

ROOT = Path("/Users/raffa/Lictor")
CHAOS_PROGRAMS = Path("/tmp/chaos-programs.json")
F500_CORPUS = ROOT / "v3" / "ledgers" / "f500-all-hosts.txt"
EXPANDED = ROOT / "v3" / "ledgers" / "all-bounty-hosts.txt"

UA = "Lictor-CorpusBuilder/0.1"

# Filter to leak-likely prefixes (same as F500 orchestrator)
LEAK_LIKELY = ("admin", "api", "auth", "dev", "stage", "staging", "test", "uat", "qa",
               "internal", "intranet", "beta", "preview", "sandbox", "console",
               "dashboard", "docs", "developer", "github", "gitlab", "ci",
               "jenkins", "metrics", "grafana", "kibana", "sso", "login", "oauth",
               "id", "accounts", "my", "support", "help", "status", "monitor",
               "portal", "registry", "git", "bamboo", "drone", "argo", "tekton",
               "vault", "secret", "key", "credentials", "config", "deploy",
               "billing", "pay", "wallet", "rpc", "node", "bridge", "swap")

# Social/CDN domains to exclude
EXCLUDE_DOMAINS = ("twitter.com", "discord.gg", "discord.com", "telegram.org",
                   "t.me", "facebook.com", "github.com", "medium.com", "youtube.com",
                   "linkedin.com", "instagram.com", "reddit.com", "tiktok.com",
                   "google.com", "googleapis.com", "cloudflare.com", "cloudfront.net",
                   "amazonaws.com", "akamaihd.net", "fastly.net")


def fetch_defi_llama() -> set[str]:
    """Pull defi-llama protocol URLs, extract hostnames."""
    print("[1] Fetching DefiLlama protocols...")
    try:
        req = urllib.request.Request("https://api.llama.fi/protocols",
                                      headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=60) as r:
            protocols = json.loads(r.read())
    except Exception as e:
        print(f"  error: {e}")
        return set()
    hosts = set()
    for p in protocols:
        url = p.get("url") or ""
        if not url: continue
        try:
            parsed = urllib.parse.urlparse(url if "://" in url else "https://" + url)
            host = (parsed.hostname or "").lower()
        except Exception:
            continue
        if not host or "." not in host: continue
        if any(host.endswith(ex) or host == ex for ex in EXCLUDE_DOMAINS): continue
        hosts.add(host)
        # Also add common subdomains
        if not host.startswith("www."):
            for pref in ("app", "api", "docs", "dapp", "swap", "bridge"):
                hosts.add(f"{pref}.{host}")
    print(f"  ✓ DefiLlama: {len(hosts)} hosts added")
    return hosts


def fetch_vdp_chaos_zip(prog: dict) -> set[str]:
    """Download one chaos zip + extract leak-likely subdomains."""
    url = prog.get("URL")
    if not url: return set()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=60) as r:
            data = r.read(50_000_000)  # cap 50MB
    except Exception:
        return set()
    subs = set()
    try:
        with zipfile.ZipFile(io.BytesIO(data), 'r') as zf:
            for name in zf.namelist():
                if not name.endswith(".txt"): continue
                with zf.open(name) as f:
                    for line in f.read().decode("utf-8", "replace").splitlines():
                        line = line.strip().lower()
                        if not line or "." not in line or " " in line: continue
                        host_label = line.split(".")[0]
                        if any(host_label.startswith(p) for p in LEAK_LIKELY):
                            subs.add(line)
                        if len(subs) >= 300: return subs  # cap per VDP
    except Exception:
        return set()
    return subs


def fetch_vdp_programs() -> set[str]:
    """Pull all VDP-only programs from chaos, download zips in parallel."""
    print("[2] Fetching VDP-only programs (top 100 by smallest count)...")
    if not CHAOS_PROGRAMS.exists():
        print("  no chaos data — skipping")
        return set()
    progs = json.loads(CHAOS_PROGRAMS.read_text())
    vdp = [p for p in progs if not p.get("bounty") and p.get("URL")]
    # Prefer SMALLER subdomain counts (more focused targets, less catchall noise)
    vdp.sort(key=lambda p: p.get("count", 0))
    sample = vdp[:100]  # top 100 smallest VDPs
    print(f"  Downloading {len(sample)} VDP chaos zips in parallel...")
    all_hosts = set()
    with ThreadPoolExecutor(max_workers=15) as pool:
        futures = {pool.submit(fetch_vdp_chaos_zip, p): p for p in sample}
        for i, fut in enumerate(as_completed(futures), 1):
            try:
                subs = fut.result(timeout=70)
                all_hosts.update(subs)
            except Exception: pass
            if i % 20 == 0:
                print(f"    [{i}/{len(sample)}] VDPs processed, total hosts: {len(all_hosts)}")
    print(f"  ✓ VDP corpus: {len(all_hosts)} hosts added")
    return all_hosts


def fetch_huntr_targets() -> set[str]:
    """Try to pull HuntrDev OSS bounty target list."""
    print("[3] HuntrDev OSS — best-effort scrape...")
    # HuntrDev is mostly OSS package bounties (npm/pypi/go modules)
    # Their hosts are mostly the project's main GitHub repo, not testable via HTTP scanner
    # Skip for now — different scan model needed (static code analysis)
    print("  ⚠ HuntrDev is package-based (npm/pypi), not URL-scannable. Skipping.")
    return set()


def fetch_us_gov_vdps() -> set[str]:
    """Pull CISA's list of US government VDP programs."""
    print("[4] US gov VDPs (CISA list)...")
    # CISA maintains a public list of agency VDPs at https://github.com/cisagov/vdp-implementation-guide
    # but the actual program scopes are scattered across .gov sites
    # Pragmatic: scan common .gov subdomains where research indicates real bugs
    # Skip for now — needs separate enumeration
    print("  ⚠ Needs per-agency enumeration. Skipping for now.")
    return set()


def main():
    all_hosts = set()
    # Load existing F500 corpus
    if F500_CORPUS.exists():
        existing = set(l.strip() for l in F500_CORPUS.read_text().splitlines() if l.strip())
        print(f"[0] Existing F500 corpus: {len(existing)} hosts")
        all_hosts.update(existing)

    # Add new sources
    all_hosts.update(fetch_defi_llama())
    all_hosts.update(fetch_vdp_programs())
    # all_hosts.update(fetch_huntr_targets())  # skipped
    # all_hosts.update(fetch_us_gov_vdps())   # skipped

    # Final sanitization: dedupe, lowercase, valid host shape
    sanitized = set()
    for h in all_hosts:
        h = h.strip().lower()
        if not h or "." not in h: continue
        if " " in h or "/" in h or ":" in h: continue
        if h.startswith(".") or h.endswith("."): continue
        sanitized.add(h)

    EXPANDED.write_text("\n".join(sorted(sanitized)))
    print(f"\n[+] Done. Wrote {len(sanitized)} unique hosts to {EXPANDED}")


if __name__ == "__main__":
    main()
