#!/usr/bin/env python3
"""
patrol-postman — hunt API keys in public Postman workspaces.

Postman doesn't expose a public search API, but their public workspace +
collection pages are publicly fetchable + indexed. We use their published
workspace JSON endpoints:
  - https://www.postman.com/_api/ws/proxy/search-all  (search)
  - https://www.postman.com/_api/workspace/<id>/api/... (workspace detail)
  - https://www.postman.com/<owner>/workspace/<name>/collection/<id>.json (raw collection)

Each Postman collection JSON contains every saved request — including
Authorization headers, Bearer tokens, API keys in URLs/body. Bots scrape
these constantly. This catches the same exposures pre-bot.
"""
from __future__ import annotations
import argparse, json, re, time, urllib.request, urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-Patrol-Postman/0.1 (+https://lictorai.com)"
TIMEOUT = 15

PATTERNS = {
    "openai":       re.compile(r'(sk-(?:proj-)?[A-Za-z0-9_-]{40,})'),
    "anthropic":    re.compile(r'(sk-ant-api03-[A-Za-z0-9_-]{90,})'),
    "google-ai":    re.compile(r'(AIza[A-Za-z0-9_-]{35})'),
    "huggingface":  re.compile(r'(hf_[A-Za-z0-9]{32,})'),
    "groq":         re.compile(r'(gsk_[A-Za-z0-9]{30,})'),
    "stripe-live":  re.compile(r'(sk_live_[A-Za-z0-9]{24,})'),
    "github-pat":   re.compile(r'(ghp_[A-Za-z0-9]{36,})'),
    "aws-key":      re.compile(r'(AKIA[A-Z0-9]{16})'),
    "slack-bot":    re.compile(r'(xoxb-\d+-\d+-[A-Za-z0-9]{24,})'),
    "supabase-sr":  re.compile(r'(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]*service_role[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)'),
    "twilio-sid":   re.compile(r'\b(AC[a-f0-9]{32})\b'),
    "sendgrid":     re.compile(r'(SG\.[A-Za-z0-9_-]{20,30}\.[A-Za-z0-9_-]{40,50})'),
    "mailchimp":    re.compile(r'\b([0-9a-f]{32}-us\d{1,3})\b'),
}

PLACEHOLDER = re.compile(r'(your|example|placeholder|<.*>|test|demo|sample|fake|xxxx+|0{8,})', re.IGNORECASE)


@dataclass
class Hit:
    kind: str
    workspace: str
    collection: str
    url: str
    redacted: str


def http_get_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return json.loads(r.read())
    except Exception:
        return None


def search_workspaces(query, page=0):
    """Hit Postman's public search-all endpoint."""
    url = "https://www.postman.com/_api/ws/proxy/search-all"
    body = json.dumps({
        "service": "search",
        "method": "POST",
        "path": "/search-all",
        "body": {
            "queryIndices": ["collaboration.workspace"],
            "queryText": query,
            "size": 50,
            "from": page * 50,
            "clientTraceId": f"lictor-{int(time.time())}",
        },
    }).encode()
    req = urllib.request.Request(url, data=body, method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json", "User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            data = json.loads(r.read())
            results = []
            for entity in (data.get("data") or []):
                doc = entity.get("document") or {}
                results.append({
                    "id": doc.get("publishedId") or doc.get("id"),
                    "name": doc.get("name", "?"),
                    "slug": doc.get("slug", ""),
                    "owner": doc.get("publisherHandle") or (doc.get("publisher") or {}).get("name", ""),
                    "raw": doc,
                })
            return results
    except Exception as e:
        print(f"  search err: {e}", flush=True)
        return []


def scan_text(text, source_label):
    out = []
    seen = set()
    for kind, rx in PATTERNS.items():
        for m in rx.finditer(text):
            val = m.group(1) if m.lastindex else m.group(0)
            if (kind, val) in seen: continue
            seen.add((kind, val))
            ctx = text[max(0, m.start()-60):min(len(text), m.start()+60)]
            if PLACEHOLDER.search(ctx): continue
            red = val[:8] + "…" + val[-4:] if len(val) > 14 else val
            out.append((kind, val, red))
    return out


def scan_workspace_text(ws_id):
    """Fetch the full workspace JSON tree and grep for secrets."""
    url = f"https://www.postman.com/_api/workspace/{ws_id}"
    data = http_get_json(url)
    if not data: return []
    text = json.dumps(data)  # entire blob as text
    return scan_text(text, ws_id)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--queries", nargs="+", default=[
        "openai", "firebase", "supabase", "stripe", "twilio", "sendgrid",
        "anthropic", "claude", "groq", "huggingface", "mailchimp"
    ])
    ap.add_argument("--max-workspaces", type=int, default=200)
    ap.add_argument("--private", default=f"docs/launch/patrol-postman-{datetime.now().strftime('%Y-%m-%d')}-private.md")
    args = ap.parse_args()

    print(f"[+] postman patrol — queries={args.queries}", flush=True)

    workspaces = {}
    for q in args.queries:
        results = search_workspaces(q, page=0)
        for r in results:
            wid = r.get("id")
            if wid and wid not in workspaces:
                workspaces[wid] = r
        time.sleep(1)
        if len(workspaces) >= args.max_workspaces: break

    candidates = list(workspaces.values())[:args.max_workspaces]
    print(f"[+] discovered {len(candidates)} workspaces", flush=True)

    hits = []
    for i, ws in enumerate(candidates, 1):
        wid = ws["id"]
        name = ws.get("name", "?")
        owner = ws.get("owner", "?")
        print(f"  [{i}/{len(candidates)}] {owner}/{name}", end="", flush=True)
        try:
            ws_hits = scan_workspace_text(wid)
            if ws_hits:
                print(f"  🔴 {len(ws_hits)} hit(s)", flush=True)
                for kind, val, red in ws_hits:
                    hits.append(Hit(kind=kind, workspace=name, collection=wid,
                                    url=f"https://www.postman.com/{owner}/workspace/{ws.get('slug','')}",
                                    redacted=red))
                    print(f"     {kind} {red}", flush=True)
            else:
                print("  ⚪", flush=True)
        except Exception as e:
            print(f"  EXC: {e}", flush=True)
        time.sleep(0.5)

    md = [f"# Patrol — Postman public workspace exposure (PRIVATE)\n",
          f"**Scanned at:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
          f"**Workspaces inspected:** {len(candidates)}",
          f"**Confirmed exposures:** {len(hits)}\n",
          "| Kind | Workspace | Redacted | URL |",
          "|---|---|---|---|"]
    for h in hits:
        md.append(f"| {h.kind} | `{h.workspace}` | `{h.redacted}` | [link]({h.url}) |")
    Path(args.private).write_text("\n".join(md))
    print(f"\n[+] Done. {len(hits)} verified Postman exposures.")


if __name__ == "__main__":
    main()
