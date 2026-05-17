#!/usr/bin/env python3
"""
patrol-npm — hunt hardcoded API keys in recently-published npm packages.

Why this is a great target:
  - npm registry is a separate corpus from GitHub Code Search
  - Many AI-built CLI tools / wrappers publish with bundled keys in dist/
  - Public tarballs, no auth needed
  - The publisher is "the owner" — clear disclosure target

Detection:
  - Recent packages from npm registry-replicate stream (--all + last 24h)
  - Download tarball, stream-extract files matching /\.(js|ts|mjs|cjs|json)$/
  - Apply same key patterns as patrol-huggingface
  - Skip packages where keys live in test/ or example/
"""
from __future__ import annotations
import argparse, json, re, sys, time, tarfile, io, urllib.request, urllib.error
from dataclasses import dataclass
from pathlib import Path
from datetime import datetime, timezone, timedelta

UA = "Lictor-Patrol-NPM/0.1 (+https://lictorai.com)"
TIMEOUT = 15

KEY_PATTERNS = {
    "openai":     re.compile(r'(sk-(?:proj-)?[A-Za-z0-9_-]{40,})'),
    "anthropic":  re.compile(r'(sk-ant-api03-[A-Za-z0-9_-]{90,})'),
    "huggingface":re.compile(r'(hf_[A-Za-z0-9]{32,})'),
    "google-ai":  re.compile(r'(AIza[A-Za-z0-9_-]{35})'),
    "groq":       re.compile(r'(gsk_[A-Za-z0-9]{30,})'),
    "stripe-live":re.compile(r'(sk_live_[A-Za-z0-9]{24,})'),
    "stripe-restricted": re.compile(r'(rk_live_[A-Za-z0-9]{24,})'),
    "github-pat": re.compile(r'(ghp_[A-Za-z0-9]{36,})'),
    "github-server": re.compile(r'(ghs_[A-Za-z0-9]{36,})'),
    "aws-key":    re.compile(r'(AKIA[A-Z0-9]{16})'),
    "slack-bot":  re.compile(r'(xoxb-\d+-\d+-[A-Za-z0-9]{24,})'),
    "replicate":  re.compile(r'(r8_[A-Za-z0-9]{30,})'),
    "supabase-sr":re.compile(r'(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]*service_role[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)'),
}

PLACEHOLDER = re.compile(r'(your|example|placeholder|xxxx+|fake|test|demo|sample|here|todo|insert|replace|<.*>|process\.env|\\$\\{)', re.IGNORECASE)
SKIP_PATH = re.compile(r'(?:^|/)(test|tests|__tests__|spec|specs|example|examples|docs?|fixtures?|node_modules)/', re.IGNORECASE)

@dataclass
class Hit:
    package: str
    version: str
    path: str
    kind: str
    redacted: str
    homepage: str = ""
    author: str = ""

def http_get_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return json.loads(r.read())
    except Exception:
        return None

def http_get_bytes(url, max_bytes=10_000_000):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.read(max_bytes)
    except Exception:
        return None

def list_recent_packages(limit=300, days=7):
    """Use the npm registry search API for recently-modified packages."""
    seen = 0
    page_size = 50
    skip = 0
    while seen < limit:
        # Sort by recently modified
        url = f"https://registry.npmjs.org/-/v1/search?text=&size={page_size}&from={skip}&popularity=0.1&quality=0.0&maintenance=0.0"
        # Better: a search for "ai" or "openai" keyword to seed AI-relevant packages
        url = f"https://registry.npmjs.org/-/v1/search?text=keywords:ai+keywords:llm&size={page_size}&from={skip}"
        data = http_get_json(url)
        if not data or "objects" not in data: break
        objs = data["objects"]
        if not objs: break
        for o in objs:
            pkg = o.get("package", {})
            yield pkg
            seen += 1
            if seen >= limit: return
        skip += page_size
        time.sleep(0.5)

def scan_tarball(tarball_bytes):
    """Stream-scan a .tgz, yield (path, kind, raw, redacted)."""
    out = []
    try:
        bio = io.BytesIO(tarball_bytes)
        with tarfile.open(fileobj=bio, mode="r:gz") as tar:
            for member in tar.getmembers():
                if not member.isfile(): continue
                if member.size > 500_000: continue  # skip very large
                if SKIP_PATH.search(member.name): continue
                if not re.search(r'\.(js|ts|mjs|cjs|json|env)$', member.name): continue
                f = tar.extractfile(member)
                if not f: continue
                try:
                    text = f.read().decode("utf-8", "replace")
                except: continue
                seen = set()
                for kind, rx in KEY_PATTERNS.items():
                    for m in rx.finditer(text):
                        val = m.group(1) if m.lastindex else m.group(0)
                        if (kind, val) in seen: continue
                        seen.add((kind, val))
                        start = m.start()
                        ctx = text[max(0, start-60):min(len(text), start+60)]
                        if PLACEHOLDER.search(ctx): continue
                        red = val[:8] + "…" + val[-4:] if len(val) > 14 else val
                        out.append((member.name, kind, val, red))
    except Exception as e:
        print(f"    tarball err: {e}", flush=True)
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max", type=int, default=200)
    ap.add_argument("--private", default=f"docs/launch/patrol-npm-{datetime.now().strftime('%Y-%m-%d')}-private.md")
    args = ap.parse_args()

    print(f"[+] Listing up to {args.max} AI-keyword npm packages (recent)...", flush=True)
    packages = list(list_recent_packages(args.max))
    print(f"[+] Got {len(packages)} packages. Scanning tarballs...", flush=True)

    hits = []
    for i, pkg in enumerate(packages, 1):
        name = pkg.get("name", "?")
        version = pkg.get("version", "?")
        homepage = pkg.get("links", {}).get("homepage", "")
        author = pkg.get("author", {}).get("name", "") if isinstance(pkg.get("author"), dict) else str(pkg.get("author",""))

        # Get tarball URL from registry detail
        meta = http_get_json(f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@/')}")
        if not meta:
            print(f"  [{i}/{len(packages)}] {name}  ⚪ meta fetch failed", flush=True)
            continue
        latest = meta.get("dist-tags", {}).get("latest", version)
        tarball_url = meta.get("versions", {}).get(latest, {}).get("dist", {}).get("tarball")
        if not tarball_url:
            print(f"  [{i}/{len(packages)}] {name}  ⚪ no tarball", flush=True)
            continue

        print(f"  [{i}/{len(packages)}] {name}@{latest}", end="", flush=True)
        tb = http_get_bytes(tarball_url)
        if not tb:
            print("  ⚪ tarball fetch failed", flush=True)
            continue

        found = scan_tarball(tb)
        if not found:
            print(f"  ⚪ {len(tb)//1024}KB clean", flush=True)
        else:
            print(f"  🔴 {len(found)} hit(s)", flush=True)
            for path, kind, val, red in found:
                hits.append(Hit(package=name, version=latest, path=path,
                                kind=kind, redacted=red, homepage=homepage, author=author))
                print(f"     {kind} {red}  {path}", flush=True)
        time.sleep(0.6)

    md = [f"# Patrol — npm package secret exposure (PRIVATE)\n",
          f"**Scanned at:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
          f"**Packages inspected:** {len(packages)}",
          f"**Confirmed exposures:** {len(hits)}\n",
          "| Package | Version | Kind | Redacted | Path | Author | Homepage |",
          "|---|---|---|---|---|---|---|"]
    for h in sorted(hits, key=lambda x: x.package):
        md.append(f"| `{h.package}` | {h.version} | {h.kind} | `{h.redacted}` | `{h.path}` | {h.author} | {h.homepage} |")
    Path(args.private).write_text("\n".join(md))
    print(f"\n[+] Done. {len(hits)} confirmed npm packages with exposed keys.")
    print(f"[+] Private: {args.private}")

if __name__ == "__main__":
    main()

# Make urllib.parse available
import urllib.parse
