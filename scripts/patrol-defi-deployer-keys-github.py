#!/usr/bin/env python3
"""
patrol-defi-deployer-keys-github — scanner #52 (Web3 pivot).

Hunts leaked deployer / hot-wallet private keys and seed phrases in DeFi org
GitHub repos. A leaked deployer key on a DeFi protocol with admin privileges
= full protocol takeover = $1M-$10M+ Immunefi bounty.

Discovery patterns:
  - DEPLOYER_PRIVATE_KEY=0x... in .env files
  - MNEMONIC="12-or-24-word phrase" in .env / hardhat.config.js
  - privateKey: '0x...' in deploy scripts
  - secrets.json with private_key field
  - .secret files with raw 64-hex strings

Method (ETHICAL):
  1. GitHub Code Search for high-signal patterns scoped to DeFi orgs
  2. Pull raw file content
  3. Validate with regex (40-char hex for ETH PK, BIP39 wordlist for mnemonic)
  4. Filter false positives (.example, test_*, sample fixtures, docs)
  5. Check the on-chain address derived from the key:
     - If balance > 0 ETH or any admin role on a known contract = CRITICAL
     - We do NOT derive the address ourselves — only record the leak metadata
       and let the affected protocol's security team confirm impact.

We never use the leaked keys for anything. We report.

Usage:
  patrol-defi-deployer-keys-github.py --orgs defi-orgs.txt --ledger defi-deployer-keys.jsonl
"""
from __future__ import annotations
import argparse, base64, json, re, subprocess, time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

# Detection regexes
ETH_PK_RX = re.compile(r'\b(?:0x)?([a-fA-F0-9]{64})\b')  # 64 hex chars
# BIP39 mnemonics: 12, 15, 18, 21, or 24 lowercase words separated by single spaces
MNEMONIC_RX = re.compile(r'\b((?:[a-z]+ ){11,23}[a-z]+)\b')

# Pattern-context: assignment / KV pairs
SECRET_KEY_CONTEXT = re.compile(
    r'(DEPLOYER_PRIVATE_KEY|PRIVATE_KEY|PRIV_KEY|MNEMONIC|SEED_PHRASE|SECRET_KEY|HOT_WALLET_KEY)\s*[=:]\s*["\']?([^\s"\']+)',
    re.IGNORECASE)

# False-positive paths / contexts
FP_PATH = re.compile(r'(\.example|\.template|\.sample|test[/_]|fixture|docs?/|\.md$|README)', re.IGNORECASE)
FP_VALUE = re.compile(r'(0x0+$|0xdeadbeef|0xabcdef|0x1{10,}|0x[0-9a-f]{4,8}$|placeholder|change[-_ ]?me|your[-_ ]?key|insert[-_ ]?here|<.*>|\$\{)', re.IGNORECASE)

# BIP39 first words sanity check (common ones — full list omitted for brevity)
BIP39_COMMON = {"abandon", "ability", "able", "about", "above", "absent", "absorb",
                "abstract", "absurd", "abuse", "access", "accident", "account",
                "accuse", "achieve", "acid", "acoustic", "acquire", "across",
                "act", "action", "actor", "actress", "actual", "adapt", "add",
                "address", "adjust", "admit", "adult", "advance", "advice",
                "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
                "agree", "ahead", "aim", "air", "airport", "aisle", "alarm",
                "album", "alcohol", "alert", "alien", "all", "alley", "allow",
                "almost", "alone", "alpha", "already", "also", "alter", "always"}

@dataclass
class KeyLeak:
    org: str
    repo: str
    path: str
    url: str
    kind: str        # "eth_private_key" / "mnemonic"
    key_redacted: str
    context: str
    stars: int = 0
    pushed_at: str = ""

def gh_search(query: str, max_pages: int = 2) -> list:
    results, seen = [], set()
    for page in range(1, max_pages + 1):
        try:
            out = subprocess.check_output(
                ["gh", "api", "-X", "GET", "search/code",
                 "-f", f"q={query}", "-f", "per_page=100", "-f", f"page={page}",
                 "--jq", ".items"], stderr=subprocess.DEVNULL, timeout=30)
            items = json.loads(out)
        except Exception:
            break
        if not items: break
        for it in items:
            key = (it["repository"]["full_name"], it["path"])
            if key in seen: continue
            seen.add(key)
            results.append(it)
        time.sleep(2.5)
    return results

def gh_raw_file(repo: str, path: str) -> str | None:
    try:
        out = subprocess.check_output(
            ["gh", "api", f"repos/{repo}/contents/{path}", "-q", ".content"],
            stderr=subprocess.DEVNULL, timeout=15)
        return base64.b64decode(out.decode().strip().replace("\n","")).decode("utf-8","replace")
    except Exception:
        return None

def gh_repo_meta(repo: str) -> dict:
    try:
        out = subprocess.check_output(
            ["gh", "api", f"repos/{repo}", "--jq",
             '{stars: .stargazers_count, pushed_at: .pushed_at, archived: .archived}'],
            stderr=subprocess.DEVNULL, timeout=10)
        return json.loads(out)
    except Exception:
        return {}

def looks_real_eth_pk(hex_str: str, surrounding_ctx: str) -> bool:
    if len(hex_str) != 64: return False
    if FP_VALUE.search(hex_str) or FP_VALUE.search(surrounding_ctx): return False
    # All-same-char keys are placeholders
    if len(set(hex_str.lower())) < 8: return False
    return True

def looks_real_mnemonic(phrase: str) -> bool:
    words = phrase.lower().split()
    if len(words) not in (12, 15, 18, 21, 24): return False
    # At least one common BIP39 word + all lowercase + reasonable length per word
    if not any(w in BIP39_COMMON for w in words): return False
    if not all(2 <= len(w) <= 8 for w in words): return False
    if FP_VALUE.search(phrase): return False
    return True

def context_around(text: str, start: int, window: int = 100) -> str:
    return text[max(0, start - window):min(len(text), start + window)]

def verify_file(item: dict, org: str) -> list[KeyLeak]:
    repo = item["repository"]["full_name"]
    path = item["path"]
    if FP_PATH.search(path):
        return []
    content = gh_raw_file(repo, path)
    if not content: return []
    if FP_PATH.search(content[:200]):  # docstring saying "this is example"
        return []

    leaks = []
    meta = gh_repo_meta(repo)
    if meta.get("archived"): return []

    # First pass: KV context match (highest signal)
    for m in SECRET_KEY_CONTEXT.finditer(content):
        key_name, val = m.group(1), m.group(2)
        ctx = context_around(content, m.start())
        if FP_VALUE.search(val) or FP_VALUE.search(ctx): continue
        # Determine kind
        if re.match(r'^(0x)?[a-fA-F0-9]{64}$', val):
            if looks_real_eth_pk(val.lstrip('0x'), ctx):
                leaks.append(KeyLeak(org=org, repo=repo, path=path, url=item["html_url"],
                                      kind="eth_private_key",
                                      key_redacted=val[:6] + "..." + val[-4:],
                                      context=ctx.replace("\n", " ")[:150],
                                      stars=meta.get("stars", 0),
                                      pushed_at=meta.get("pushed_at", "")[:10]))
        elif " " in val and looks_real_mnemonic(val):
            leaks.append(KeyLeak(org=org, repo=repo, path=path, url=item["html_url"],
                                  kind="mnemonic",
                                  key_redacted=" ".join(val.split()[:2]) + " ...",
                                  context=ctx.replace("\n", " ")[:150],
                                  stars=meta.get("stars", 0),
                                  pushed_at=meta.get("pushed_at", "")[:10]))

    # Second pass: bare 64-hex outside KV (lower signal, but still worth flagging)
    if not leaks:
        for m in ETH_PK_RX.finditer(content):
            hex_val = m.group(1)
            ctx = context_around(content, m.start())
            if looks_real_eth_pk(hex_val, ctx):
                leaks.append(KeyLeak(org=org, repo=repo, path=path, url=item["html_url"],
                                      kind="eth_private_key_bare",
                                      key_redacted=hex_val[:6] + "..." + hex_val[-4:],
                                      context=ctx.replace("\n", " ")[:150],
                                      stars=meta.get("stars", 0),
                                      pushed_at=meta.get("pushed_at", "")[:10]))
                break  # one per file is enough signal
    return leaks

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--orgs", required=True)
    ap.add_argument("--ledger", default="/Users/raffa/Lictor/v3/ledgers/defi-deployer-keys.jsonl")
    ap.add_argument("--per-org-max", type=int, default=30)
    args = ap.parse_args()

    orgs = [o.strip() for o in Path(args.orgs).read_text().splitlines() if o.strip()]
    print(f"[+] Hunting deployer/hot-wallet keys across {len(orgs)} DeFi orgs")
    print(f"[+] ETHICS: only DETECT + REPORT. Never derive address. Never use key.")
    Path(args.ledger).parent.mkdir(parents=True, exist_ok=True)

    n_total = 0
    with open(args.ledger, "a") as ledger:
        for oi, org in enumerate(orgs, 1):
            print(f"\n[+] [{oi}/{len(orgs)}] Org: {org}")
            queries = [
                f'org:{org} DEPLOYER_PRIVATE_KEY',
                f'org:{org} "PRIVATE_KEY=0x"',
                f'org:{org} MNEMONIC filename:.env',
                f'org:{org} privateKey filename:hardhat.config',
            ]
            candidates = []
            for q in queries:
                items = gh_search(q, max_pages=1)
                for it in items:
                    candidates.append(it)
                    if len(candidates) >= args.per_org_max: break
                if len(candidates) >= args.per_org_max: break
            print(f"    {len(candidates)} candidate files")
            for ci, it in enumerate(candidates, 1):
                try:
                    leaks = verify_file(it, org)
                except Exception as e:
                    print(f"    [{ci}/{len(candidates)}] EXC: {e}")
                    continue
                for k in leaks:
                    ledger.write(json.dumps(asdict(k)) + "\n")
                    ledger.flush()
                    n_total += 1
                    print(f"    🔴 LEAK  {k.kind}  {k.repo}/{k.path}  {k.key_redacted}  ★{k.stars}")
                time.sleep(0.8)

    print(f"\n[+] Done. {n_total} key leaks discovered → {args.ledger}")
    print(f"[+] Disclose IMMEDIATELY — DeFi key leaks are time-sensitive.")
    print(f"[+] Report via Immunefi if the org has a program, else security@{{org}}.")

if __name__ == "__main__":
    main()
