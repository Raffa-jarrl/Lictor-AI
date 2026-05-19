#!/usr/bin/env python3
"""
patrol-huggingface-leaks — scanner #18.

Hugging Face is a high-value bounty target:
  - They DO have a security program
  - Their model/space/dataset repos contain enormous amounts of code
  - Their devs are ML researchers, less security training than backend SWE
  - hf_* tokens, OpenAI/Anthropic keys, AWS creds frequently leaked
  - Less commonly scanned than GitHub corpora

Strategy:
  1. Pull recent public Spaces from HF API (newest first — most likely to have fresh leaks)
  2. For each Space, fetch the file tree
  3. For each text file, grep for secret patterns
  4. Report verified leaks

API: https://huggingface.co/api/spaces?sort=lastModified&direction=-1&limit=100
"""
from __future__ import annotations
import argparse, json, re, time, urllib.request, urllib.error
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-HFPatrol/0.1 (+https://lictor-ai.com)"
LEDGER = Path.home() / ".lictor" / "hf-leak-ledger.jsonl"
OUT = Path.home() / "Lictor" / "docs" / "launch" / f"hf-leaks-{datetime.now().strftime('%Y-%m-%d')}-private.md"

PATTERNS = {
    "hf_token":      re.compile(r'\bhf_[A-Za-z0-9]{30,40}\b'),
    "openai_key":    re.compile(r'\bsk-[A-Za-z0-9_-]{32,}\b'),
    "anthropic_key": re.compile(r'\bsk-ant-api\d{2}-[A-Za-z0-9_-]{50,200}\b'),
    "aws_akid":      re.compile(r'\bAKIA[A-Z0-9]{16}\b'),
    "stripe_live":   re.compile(r'\bsk_live_[A-Za-z0-9]{24,99}\b'),
    "github_pat":    re.compile(r'\bghp_[A-Za-z0-9]{36,40}\b'),
    "github_oauth":  re.compile(r'\bgho_[A-Za-z0-9]{36,40}\b'),
    "google_api":    re.compile(r'\bAIza[A-Za-z0-9_-]{35}\b'),
    "slack_token":   re.compile(r'\bxox[baprs]-[A-Za-z0-9-]{10,200}\b'),
    "private_key":   re.compile(r'-----BEGIN (RSA |OPENSSH |EC |PGP )?PRIVATE KEY-----'),
}
PLACEHOLDER_RX = re.compile(r'(example|sample|placeholder|XXX+|TODO|FAKE|your_|YOUR_|<[^>]{1,30}>|test_|sk-test|sk_test|hf_test)', re.I)


@dataclass
class Leak:
    space: str
    file: str
    pattern: str
    redacted: str
    snippet: str
    found_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))


def http_get(url, timeout=15):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return f"__HTTP{e.code}__"
    except Exception:
        return ""


def list_spaces(limit=200):
    """Recently-modified public Spaces."""
    url = f"https://huggingface.co/api/spaces?sort=lastModified&direction=-1&limit={limit}"
    body = http_get(url, 25)
    try:
        data = json.loads(body)
        return [s["id"] for s in data]
    except Exception:
        return []


def list_models(limit=200):
    """Recently-modified public Models."""
    url = f"https://huggingface.co/api/models?sort=lastModified&direction=-1&limit={limit}"
    body = http_get(url, 25)
    try:
        data = json.loads(body)
        return [m["id"] for m in data]
    except Exception:
        return []


def list_files(repo_id, repo_type="spaces"):
    """List text-ish files in an HF repo."""
    url = f"https://huggingface.co/api/{repo_type}/{repo_id}/tree/main"
    body = http_get(url, 15)
    try:
        data = json.loads(body)
        files = []
        for item in data:
            if item.get("type") != "file": continue
            path = item.get("path", "")
            # Only scan text-ish files
            if re.search(r'\.(py|js|ts|env|yml|yaml|json|md|sh|bash|conf|cfg|ini|toml|txt|properties)$|^\.env|^Dockerfile|^requirements', path, re.I):
                files.append(path)
        return files[:50]  # cap per repo
    except Exception:
        return []


def fetch_file(repo_id, path, repo_type="spaces"):
    url = f"https://huggingface.co/{repo_id}/raw/main/{path}"
    body = http_get(url, 15)
    if body.startswith("__HTTP"): return None
    if len(body) > 200000: body = body[:200000]  # cap
    return body


def scan_content(content):
    """Return list of (pattern_name, match, snippet)."""
    hits = []
    for pname, rx in PATTERNS.items():
        for m in rx.finditer(content):
            matched = m.group(0)
            # Context check
            ctx = content[max(0, m.start()-100):m.end()+150]
            if PLACEHOLDER_RX.search(ctx): continue
            # Length sanity for some patterns
            if pname == "openai_key" and len(matched) < 32: continue
            # Snippet for display
            snippet = ctx.replace("\n", " ")[:250]
            hits.append((pname, matched, snippet))
    return hits


def load_ledger():
    if not LEDGER.exists(): return set()
    seen = set()
    for line in LEDGER.read_text().splitlines():
        if line.strip():
            try:
                d = json.loads(line)
                seen.add(f"{d['space']}|{d['file']}|{d['pattern']}")
            except: pass
    return seen


def append_ledger(leak: Leak):
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    with LEDGER.open("a") as f:
        f.write(json.dumps(asdict(leak)) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--spaces", type=int, default=100, help="how many recent Spaces to scan")
    ap.add_argument("--models", type=int, default=0,   help="how many recent Models to scan")
    args = ap.parse_args()

    seen = load_ledger()
    print(f"[+] HF leak patrol — ledger has {len(seen)} prior leak IDs", flush=True)

    targets = []
    if args.spaces > 0:
        sp = list_spaces(args.spaces)
        print(f"[+] pulled {len(sp)} recent Spaces", flush=True)
        targets += [(s, "spaces") for s in sp]
    if args.models > 0:
        md = list_models(args.models)
        print(f"[+] pulled {len(md)} recent Models", flush=True)
        targets += [(m, "models") for m in md]

    confirmed = []
    for i, (rid, rtype) in enumerate(targets, 1):
        files = list_files(rid, rtype)
        time.sleep(0.3)
        if not files:
            print(f"  [{i}/{len(targets)}] {rtype}/{rid:<50}  ⚪ no files", flush=True)
            continue
        leaks_here = 0
        for fname in files:
            content = fetch_file(rid, fname, rtype)
            time.sleep(0.2)
            if not content: continue
            hits = scan_content(content)
            for pname, matched, snippet in hits:
                key = f"{rid}|{fname}|{pname}"
                if key in seen: continue
                seen.add(key)
                redacted = matched[:8] + "…" + matched[-4:] if len(matched) > 16 else matched
                leak = Leak(space=rid, file=fname, pattern=pname,
                            redacted=redacted, snippet=snippet)
                append_ledger(leak)
                confirmed.append(leak)
                leaks_here += 1
        tag = f"🔴 {leaks_here}" if leaks_here else "⚪"
        print(f"  [{i}/{len(targets)}] {rtype}/{rid:<50}  {tag}", flush=True)
        time.sleep(0.5)

    print(f"\n[+] scan complete: {len(confirmed)} NEW leaks across {len(targets)} HF repos", flush=True)

    if confirmed:
        OUT.parent.mkdir(parents=True, exist_ok=True)
        with OUT.open("w") as f:
            f.write(f"# HF leak patrol — {datetime.now().strftime('%Y-%m-%d %H:%M')} (PRIVATE)\n\n")
            f.write(f"**Repos scanned:** {len(targets)}\n")
            f.write(f"**New leaks:** {len(confirmed)}\n\n")
            f.write("| Pattern | Repo | File | Redacted | Snippet |\n")
            f.write("|---|---|---|---|---|\n")
            for l in confirmed:
                f.write(f"| **{l.pattern}** | `{l.space}` | `{l.file}` | `{l.redacted}` | `{l.snippet[:100]}` |\n")
        print(f"    → {OUT}")


if __name__ == "__main__":
    main()
