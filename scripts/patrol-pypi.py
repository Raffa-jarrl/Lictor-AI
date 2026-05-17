#!/usr/bin/env python3
"""
patrol-pypi — hunt hardcoded API keys in recently-published PyPI packages.

PyPI is a fresh corpus separate from GitHub Code Search. Many AI-built CLI
tools / wrappers publish with bundled keys directly in .py files. Public
tarballs (sdist) and wheels, no auth needed.

Detection: same 13 key kinds as patrol-npm (OpenAI/Anthropic/HF/Google-AI/
Groq/Stripe/GH PAT/AWS/Slack/Replicate/Supabase-service-role).
"""
from __future__ import annotations
import argparse, json, re, sys, time, tarfile, zipfile, io
import urllib.request, urllib.error, urllib.parse
from dataclasses import dataclass
from pathlib import Path
from datetime import datetime, timezone

UA = "Lictor-Patrol-PyPI/0.1 (+https://lictorai.com)"
TIMEOUT = 15

KEY_PATTERNS = {
    "openai":     re.compile(r'(sk-(?:proj-)?[A-Za-z0-9_-]{40,})'),
    "anthropic":  re.compile(r'(sk-ant-api03-[A-Za-z0-9_-]{90,})'),
    "huggingface":re.compile(r'(hf_[A-Za-z0-9]{32,})'),
    "google-ai":  re.compile(r'(AIza[A-Za-z0-9_-]{35})'),
    "groq":       re.compile(r'(gsk_[A-Za-z0-9]{30,})'),
    "stripe-live":re.compile(r'(sk_live_[A-Za-z0-9]{24,})'),
    "stripe-rk":  re.compile(r'(rk_live_[A-Za-z0-9]{24,})'),
    "github-pat": re.compile(r'(ghp_[A-Za-z0-9]{36,})'),
    "aws-key":    re.compile(r'(AKIA[A-Z0-9]{16})'),
    "slack-bot":  re.compile(r'(xoxb-\d+-\d+-[A-Za-z0-9]{24,})'),
    "replicate":  re.compile(r'(r8_[A-Za-z0-9]{30,})'),
    "supabase-sr":re.compile(r'(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]*service_role[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)'),
    "twilio-token":re.compile(r'\b(AC[a-f0-9]{32})\b'),
    "sendgrid":   re.compile(r'(SG\.[A-Za-z0-9_-]{20,30}\.[A-Za-z0-9_-]{40,50})'),
}

PLACEHOLDER = re.compile(r'(your|example|placeholder|xxxx+|fake|test|demo|sample|here|todo|insert|replace|<.*>|os\.environ|os\.getenv|\$\{)', re.IGNORECASE)
SKIP_PATH = re.compile(r'(?:^|/)(test|tests|__tests__|spec|specs|example|examples|docs?|fixtures?|\.tox|\.git)/', re.IGNORECASE)

@dataclass
class Hit:
    package: str
    version: str
    path: str
    kind: str
    redacted: str
    author: str = ""
    project_url: str = ""

def http_get_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return json.loads(r.read())
    except Exception: return None

def http_get_bytes(url, max_bytes=10_000_000):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.read(max_bytes)
    except Exception: return None

def list_ai_packages(limit=200):
    """Search PyPI for AI-keyword packages using their JSON search API."""
    # PyPI doesn't have a great search API; use simple keyword endpoint
    queries = ["llm", "openai-client", "anthropic-client", "chatbot", "ai-agent", "rag", "embedding", "vector"]
    seen = set()
    out = []
    for q in queries:
        url = f"https://pypi.org/search/?q={urllib.parse.quote(q)}&format=json"
        # Fallback: scrape the search page since their search JSON endpoint is gone
        data = http_get_json(url)
        if not data:
            # Use libraries.io as fallback for popularity-sorted recent
            continue
        for p in (data.get("results") or [])[:30]:
            name = p.get("name")
            if name and name not in seen:
                seen.add(name); out.append(name)
                if len(out) >= limit: return out
        time.sleep(0.5)
    # PyPI's "Simple" index gives all packages; sample recent ones
    if len(out) < limit:
        url = "https://pypi.org/simple/"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/vnd.pypi.simple.v1+json"})
            with urllib.request.urlopen(req, timeout=30) as r:
                data = json.loads(r.read())
                # Take a random-ish sample from end (newer at end usually)
                projects = [p["name"] for p in data.get("projects", [])][-5000:]
                # Filter for AI-relevant words
                ai_words = re.compile(r'(ai|llm|gpt|openai|anthropic|claude|gemini|llama|rag|agent|chat|embed)', re.IGNORECASE)
                for n in reversed(projects):
                    if ai_words.search(n) and n not in seen:
                        seen.add(n); out.append(n)
                        if len(out) >= limit: break
        except Exception as e:
            print(f"  simple index err: {e}", flush=True)
    return out[:limit]

def get_package_meta(name):
    return http_get_json(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json")

def scan_archive(archive_bytes, name):
    """Stream-scan a sdist .tar.gz or wheel .whl (zip). Yield hits."""
    out = []
    # Try tarball first
    try:
        bio = io.BytesIO(archive_bytes)
        with tarfile.open(fileobj=bio, mode="r:gz") as tar:
            for m in tar.getmembers():
                if not m.isfile() or m.size > 500_000: continue
                if SKIP_PATH.search(m.name): continue
                if not re.search(r'\.(py|env|yaml|yml|json|cfg|ini|toml)$', m.name): continue
                f = tar.extractfile(m)
                if not f: continue
                try: text = f.read().decode("utf-8","replace")
                except: continue
                seen = set()
                for kind, rx in KEY_PATTERNS.items():
                    for mt in rx.finditer(text):
                        val = mt.group(1) if mt.lastindex else mt.group(0)
                        if (kind, val) in seen: continue
                        seen.add((kind, val))
                        ctx = text[max(0,mt.start()-60):min(len(text),mt.start()+60)]
                        if PLACEHOLDER.search(ctx): continue
                        red = val[:8] + "…" + val[-4:] if len(val) > 14 else val
                        out.append((m.name, kind, val, red))
        return out
    except (tarfile.TarError, OSError, EOFError):
        pass
    # Try as wheel/zip
    try:
        bio = io.BytesIO(archive_bytes)
        with zipfile.ZipFile(bio, "r") as zf:
            for info in zf.infolist():
                if info.file_size > 500_000: continue
                if SKIP_PATH.search(info.filename): continue
                if not re.search(r'\.(py|env|yaml|yml|json|cfg|ini|toml)$', info.filename): continue
                try: text = zf.read(info).decode("utf-8","replace")
                except: continue
                seen = set()
                for kind, rx in KEY_PATTERNS.items():
                    for mt in rx.finditer(text):
                        val = mt.group(1) if mt.lastindex else mt.group(0)
                        if (kind, val) in seen: continue
                        seen.add((kind, val))
                        ctx = text[max(0,mt.start()-60):min(len(text),mt.start()+60)]
                        if PLACEHOLDER.search(ctx): continue
                        red = val[:8] + "…" + val[-4:] if len(val) > 14 else val
                        out.append((info.filename, kind, val, red))
    except Exception:
        pass
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max", type=int, default=200)
    ap.add_argument("--private", default=f"docs/launch/patrol-pypi-{datetime.now().strftime('%Y-%m-%d')}-private.md")
    args = ap.parse_args()

    print(f"[+] discovering up to {args.max} AI-keyword PyPI packages...", flush=True)
    names = list_ai_packages(args.max)
    print(f"[+] {len(names)} packages to scan", flush=True)

    hits = []
    for i, name in enumerate(names, 1):
        meta = get_package_meta(name)
        if not meta:
            print(f"  [{i}/{len(names)}] {name}  ⚪ no meta", flush=True)
            continue
        version = meta.get("info",{}).get("version","?")
        author = meta.get("info",{}).get("author","")
        project_url = meta.get("info",{}).get("project_url","") or meta.get("info",{}).get("home_page","")
        # Pick latest release file (prefer wheel, fall back to sdist)
        urls = meta.get("urls", [])
        archive_url = None
        for u in urls:
            if u.get("packagetype") == "bdist_wheel":
                archive_url = u.get("url"); break
        if not archive_url:
            for u in urls:
                if u.get("packagetype") == "sdist":
                    archive_url = u.get("url"); break
        if not archive_url:
            print(f"  [{i}/{len(names)}] {name}@{version}  ⚪ no archive", flush=True)
            continue

        print(f"  [{i}/{len(names)}] {name}@{version}", end="", flush=True)
        ab = http_get_bytes(archive_url)
        if not ab:
            print("  ⚪ fetch failed", flush=True); continue
        found = scan_archive(ab, name)
        if not found:
            print(f"  ⚪ {len(ab)//1024}KB clean", flush=True)
        else:
            print(f"  🔴 {len(found)} hit(s)", flush=True)
            for path, kind, val, red in found:
                hits.append(Hit(package=name, version=version, path=path,
                                kind=kind, redacted=red, author=author, project_url=project_url))
                print(f"     {kind} {red}  {path}", flush=True)
        time.sleep(0.6)

    md = [f"# Patrol — PyPI package secret exposure (PRIVATE)\n",
          f"**Scanned at:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
          f"**Packages inspected:** {len(names)}",
          f"**Confirmed exposures:** {len(hits)}\n",
          "| Package | Version | Kind | Redacted | Path | Author | Project URL |",
          "|---|---|---|---|---|---|---|"]
    for h in sorted(hits, key=lambda x: x.package):
        md.append(f"| `{h.package}` | {h.version} | {h.kind} | `{h.redacted}` | `{h.path}` | {h.author} | {h.project_url} |")
    Path(args.private).write_text("\n".join(md))
    print(f"\n[+] Done. {len(hits)} confirmed PyPI exposures.")
    print(f"[+] Private: {args.private}")

if __name__ == "__main__":
    main()
