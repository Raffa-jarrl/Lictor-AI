#!/usr/bin/env python3
"""
patrol-huggingface — hunt hardcoded API keys in public HuggingFace Spaces.

Why this is a great target:
  - HF Spaces are public Python apps (literally vibe-coded ML demos)
  - Source is fetchable without auth (raw/main/app.py)
  - Audience is exactly Lictor's: people building AI things who didn't write the code
  - Fresh corpus — separate from GitHub Code Search, no overlap

Detection:
  - OpenAI key: sk-proj-..., sk-...
  - Anthropic key: sk-ant-api03-...
  - HuggingFace token: hf_...
  - Replicate token: r8_...
  - Pinecone key: long base64 + index_name pattern
  - Cohere key: long hex string + cohere.Client
"""
from __future__ import annotations
import argparse, json, re, sys, time, urllib.request, urllib.error, urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime, timezone

UA = "Lictor-Patrol-HF/0.1 (+https://lictorai.com)"
TIMEOUT = 10

KEY_PATTERNS = {
    "openai":     re.compile(r'(sk-(?:proj-)?[A-Za-z0-9_-]{32,})'),
    "anthropic":  re.compile(r'(sk-ant-api03-[A-Za-z0-9_-]{90,})'),
    "huggingface":re.compile(r'(hf_[A-Za-z0-9]{32,})'),
    "replicate":  re.compile(r'(r8_[A-Za-z0-9]{30,})'),
    "google-ai":  re.compile(r'(AIza[A-Za-z0-9_-]{35})'),
    "cohere":     re.compile(r'cohere[^a-z]*([a-z0-9]{32,40})', re.IGNORECASE),
    "pinecone":   re.compile(r'pinecone[^a-z]*api[_-]?key[^a-z]*[\'"]([A-Za-z0-9_-]{30,})', re.IGNORECASE),
    "groq":       re.compile(r'(gsk_[A-Za-z0-9]{30,})'),
    "together":   re.compile(r'(tgp_v1_[A-Za-z0-9_-]{40,})'),
    "fireworks":  re.compile(r'(fw_[A-Za-z0-9]{40,})'),
}

# Filter out obvious placeholders/examples
PLACEHOLDER = re.compile(r'(your|example|placeholder|xxxx+|fake|test|demo|sample|here|todo|insert|replace|<.*>|getenv|environ|secrets\.)', re.IGNORECASE)

@dataclass
class Hit:
    space_id: str
    url: str
    kind: str
    redacted: str
    likes: int = 0
    last_modified: str = ""

def http_get_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return json.loads(r.read())
    except Exception:
        return None

def http_get_text(url, max_bytes=200_000):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.read(max_bytes).decode("utf-8", "replace")
    except Exception:
        return None

def list_spaces(limit_total=1000, sort="lastModified"):
    """Yield space metadata dicts from HF API."""
    seen = 0; offset = 0; page_size = 100
    while seen < limit_total:
        url = f"https://huggingface.co/api/spaces?sort={sort}&direction=-1&limit={page_size}&offset={offset}"
        data = http_get_json(url)
        if not data: break
        if not isinstance(data, list) or not data: break
        for s in data:
            yield s
            seen += 1
            if seen >= limit_total: return
        offset += page_size
        time.sleep(0.5)

def list_space_files(space_id):
    """Use HF tree API to list all files in the Space."""
    url = f"https://huggingface.co/api/spaces/{space_id}/tree/main?recursive=true"
    data = http_get_json(url)
    if not data or not isinstance(data, list): return []
    return [f["path"] for f in data if f.get("type") == "file"]

def fetch_app_source(space_id):
    """Fetch any source-y file in the Space. Returns (filename, text) per file."""
    paths = list_space_files(space_id)
    scan_extensions = ('.py','.js','.ts','.jsx','.tsx','.env','.json','.yaml','.yml','.sh','.dockerfile','Dockerfile','.html','.cjs','.mjs')
    out = []
    for p in paths[:25]:  # cap per-Space to 25 files
        if not (p.endswith(scan_extensions) or 'env' in p.lower() or p == 'Dockerfile'): continue
        url = f"https://huggingface.co/spaces/{space_id}/raw/main/{urllib.parse.quote(p)}"
        text = http_get_text(url, max_bytes=300_000)
        if text and len(text) > 30:
            out.append((p, text))
    return out

def scan_text(text):
    """Yield (kind, raw_match, redacted) per real-looking key."""
    seen = set()
    for kind, rx in KEY_PATTERNS.items():
        for m in rx.finditer(text):
            val = m.group(1) if m.lastindex else m.group(0)
            if (kind, val) in seen: continue
            seen.add((kind, val))
            # Context check — is it in a comment/placeholder zone?
            start = m.start()
            ctx = text[max(0, start-60):min(len(text), start+60)]
            if PLACEHOLDER.search(ctx): continue
            # Real-looking length minimums
            if kind == "openai" and len(val) < 40: continue
            if kind == "huggingface" and len(val) < 35: continue
            red = val[:8] + "…" + val[-4:] if len(val) > 14 else val
            yield (kind, val, red)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max", type=int, default=500, help="Max spaces to scan")
    ap.add_argument("--sort", default="lastModified", choices=["lastModified","likes","trendingScore"])
    ap.add_argument("--private", default=f"docs/launch/patrol-hf-{datetime.now().strftime('%Y-%m-%d')}-private.md")
    ap.add_argument("--public",  default=f"docs/launch/patrol-hf-{datetime.now().strftime('%Y-%m-%d')}-aggregate.md")
    args = ap.parse_args()

    print(f"[+] Listing up to {args.max} HF Spaces (sort={args.sort})...", flush=True)
    spaces = list(list_spaces(args.max, args.sort))
    print(f"[+] Got {len(spaces)} spaces. Scanning each for hardcoded keys...", flush=True)

    hits = []
    seen_keys = set()  # dedup at (space, kind, redacted) granularity
    for i, s in enumerate(spaces, 1):
        sid = s.get("id") or f"{s.get('author','?')}/{s.get('cardData',{}).get('id','?')}"
        likes = s.get("likes", 0)
        lm = s.get("lastModified", "")[:10]
        print(f"  [{i}/{len(spaces)}] {sid}", end="", flush=True)
        try:
            files = fetch_app_source(sid)
            if not files:
                print("  ⚪ no source files")
                continue
            local_hits = 0
            for fn, text in files:
                for kind, val, red in scan_text(text):
                    key = (sid, kind, val)
                    if key in seen_keys: continue
                    seen_keys.add(key)
                    h = Hit(space_id=sid,
                            url=f"https://huggingface.co/spaces/{sid}/blob/main/{fn}",
                            kind=kind, redacted=red,
                            likes=likes, last_modified=lm)
                    hits.append(h)
                    local_hits += 1
                    print(f"\n   🔴 {kind} {red}  ★{likes}  {fn}", end="")
            if local_hits == 0:
                print(f"  ⚪ scanned {len(files)} files, no keys")
            else:
                print()
        except Exception as e:
            print(f"  EXC {e}")
        time.sleep(0.4)

    # Reports
    md = [f"# Patrol — HuggingFace Spaces secret exposure (PRIVATE)\n",
          f"**Scanned at:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
          f"**Spaces inspected:** {len(spaces)}",
          f"**Confirmed exposures:** {len(hits)}\n",
          "| Space | Kind | Key (redacted) | ♥ | Last Modified | File |",
          "|---|---|---|---|---|---|"]
    for h in sorted(hits, key=lambda x: -x.likes):
        md.append(f"| `{h.space_id}` | {h.kind} | `{h.redacted}` | {h.likes} | {h.last_modified} | [link]({h.url}) |")
    Path(args.private).write_text("\n".join(md))

    pm = [f"# Patrol — HF Spaces aggregate\n",
          f"**Run:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
          f"- Spaces inspected: **{len(spaces)}**",
          f"- Confirmed secret exposures: **{len(hits)}**"]
    Path(args.public).write_text("\n".join(pm))

    print(f"\n[+] Done. {len(hits)} confirmed HF Spaces with exposed keys.")
    print(f"[+] Private: {args.private}")

if __name__ == "__main__":
    main()
