#!/usr/bin/env python3
"""
patrol-gists — hunt secrets in public GitHub Gists.

WHY THIS IS A FRESH CORPUS:
- Gists are stored separately from repos. GitHub Code Search indexes them
  separately, and our existing patrol-* scanners only hit repo code.
- People paste casual snippets to gists ALL THE TIME — including config
  files, debug snippets, README examples — without thinking about it as
  "publishing code."
- The "throwaway" mindset around gists means less self-censoring of secrets.

Architecture:
- GH /gists/public endpoint returns latest public gists, paginated
- For each gist: walk its files, regex for secret patterns
- Same 17-pattern library as lictor-local
- Output: docs/launch/patrol-gists-YYYY-MM-DD-private.md

Note: gists don't have "stars" or "is archived" — every active gist is fair
game. The author IS the owner (always a single user), so disclosure goes
through GitHub's gist-comment thread or DM.
"""
from __future__ import annotations
import argparse, json, re, sys, time, urllib.request, urllib.error
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from pathlib import Path

TOKEN = open(Path.home() / ".lictor" / "gh-token").read().strip()
UA = "Lictor-Patrol-Gists/0.1 (+https://lictorai.com)"
TIMEOUT = 12

PATTERNS = {
    "openai":       re.compile(r'(sk-(?:proj-)?(?=[A-Za-z0-9_-]*[0-9])(?=[A-Za-z0-9_-]*[A-Z])[A-Za-z0-9_-]{40,})'),
    "anthropic":    re.compile(r'(sk-ant-api03-[A-Za-z0-9_-]{90,})'),
    "google-ai":    re.compile(r'(AIza[A-Za-z0-9_-]{35})'),
    "huggingface":  re.compile(r'(hf_[A-Za-z0-9]{32,})'),
    "groq":         re.compile(r'(gsk_[A-Za-z0-9]{30,})'),
    "stripe-live":  re.compile(r'(sk_live_[A-Za-z0-9]{24,})'),
    "stripe-restricted": re.compile(r'(rk_live_[A-Za-z0-9]{24,})'),
    "stripe-webhook":re.compile(r'(whsec_[A-Za-z0-9]{32,})'),
    "github-pat":   re.compile(r'(ghp_[A-Za-z0-9]{36,})'),
    "github-server":re.compile(r'(ghs_[A-Za-z0-9]{36,})'),
    "aws-key":      re.compile(r'(AKIA[A-Z0-9]{16})'),
    "slack-bot":    re.compile(r'(xoxb-\d+-\d+-[A-Za-z0-9]{24,})'),
    "slack-user":   re.compile(r'(xoxp-\d+-\d+-\d+-[A-Za-z0-9]{32,})'),
    "twilio-sid":   re.compile(r'\b(AC[a-f0-9]{32})\b'),
    "sendgrid":     re.compile(r'(SG\.[A-Za-z0-9_-]{20,30}\.[A-Za-z0-9_-]{40,})'),
    "mailchimp":    re.compile(r'\b([0-9a-f]{32}-us\d{1,3})\b'),
    "supabase-sr":  re.compile(r'(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]*service_role[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)'),
    "firebase-sa":  re.compile(r'"private_key_id"\s*:\s*"[a-f0-9]{20,}"'),
    "sentry-dsn":   re.compile(r'https://[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io/\d+'),
    "ngrok":        re.compile(r'(ngrok_[A-Za-z0-9_-]{30,})'),
    "discord-token":re.compile(r'\b([MNO][A-Za-z0-9_-]{22,26}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,})\b'),
}

PLACEHOLDER = re.compile(r'(your|example|placeholder|XXXX+|TODO|REPLACE|FAKE|<.{1,30}>|0{8,}|x{8,}|getenv|os\.environ|process\.env)', re.IGNORECASE)


@dataclass
class GistHit:
    gist_id: str
    gist_url: str
    owner: str
    filename: str
    kind: str
    redacted: str
    description: str = ""
    updated_at: str = ""


def gh_json(url, timeout=TIMEOUT):
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {TOKEN}",
        "Accept": "application/vnd.github+json",
        "User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return {"_err": f"HTTP {e.code}"}
    except Exception as e:
        return {"_err": str(e)}


def list_public_gists(pages=10, since=None):
    """Yield gist metadata from /gists/public. Each page is 30 gists max."""
    for page in range(1, pages + 1):
        url = f"https://api.github.com/gists/public?per_page=30&page={page}"
        if since:
            url += f"&since={since}"
        data = gh_json(url)
        if not isinstance(data, list): break
        for g in data:
            yield g
        time.sleep(0.5)


def scan_text(text, label=""):
    """Yield (kind, val, redacted) for each match in text."""
    seen = set()
    for kind, rx in PATTERNS.items():
        for m in rx.finditer(text):
            val = m.group(1) if m.lastindex else m.group(0)
            if (kind, val) in seen: continue
            seen.add((kind, val))
            ctx = text[max(0, m.start()-80):min(len(text), m.start()+80)]
            if PLACEHOLDER.search(ctx): continue
            red = val[:8] + "…" + val[-4:] if len(val) > 14 else val[:6] + "…"
            yield (kind, val, red)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pages", type=int, default=10, help="Gist API pages to walk (30 gists/page)")
    ap.add_argument("--max-age-days", type=int, default=90)
    ap.add_argument("--private", default=f"docs/launch/patrol-gists-{datetime.now().strftime('%Y-%m-%d')}-private.md")
    args = ap.parse_args()

    since = (datetime.now(timezone.utc) - timedelta(days=args.max_age_days)).isoformat(timespec="seconds")
    print(f"[+] walking up to {args.pages * 30} public gists since {since[:10]}...", flush=True)

    hits = []
    n_inspected = 0
    for g in list_public_gists(pages=args.pages, since=since):
        n_inspected += 1
        gist_id = g.get("id", "?")
        owner = (g.get("owner") or {}).get("login", "?")
        gist_url = g.get("html_url", "")
        desc = g.get("description") or ""
        updated = g.get("updated_at", "")[:10]
        files = g.get("files") or {}

        if n_inspected % 10 == 0:
            print(f"  [{n_inspected}] gists walked, {len(hits)} hits so far", flush=True)

        for fname, fmeta in files.items():
            # Fetch raw content (for files > 1MB, fmeta.content might be truncated)
            raw_url = fmeta.get("raw_url") or ""
            content = fmeta.get("content") or ""
            if fmeta.get("truncated") and raw_url:
                # Fetch full content
                try:
                    req = urllib.request.Request(raw_url, headers={"User-Agent": UA})
                    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                        content = r.read(200_000).decode("utf-8", "replace")
                except Exception:
                    pass

            for kind, val, red in scan_text(content):
                hits.append(GistHit(
                    gist_id=gist_id, gist_url=gist_url, owner=owner,
                    filename=fname, kind=kind, redacted=red,
                    description=desc[:80], updated_at=updated))
                print(f"  🔴 {kind:18s} {red:24s} in {owner}/{fname[:40]}", flush=True)

    print(f"\n[+] inspected: {n_inspected} gists, {len(hits)} verified hits", flush=True)

    md = [f"# Patrol — Public GitHub Gists secret exposure (PRIVATE)\n",
          f"**Scanned at:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
          f"**Gists inspected:** {n_inspected}",
          f"**Confirmed exposures:** {len(hits)}\n",
          "| Kind | Owner | Filename | Redacted | Updated | URL |",
          "|---|---|---|---|---|---|"]
    for h in sorted(hits, key=lambda x: x.updated_at, reverse=True):
        md.append(f"| {h.kind} | `{h.owner}` | `{h.filename}` | `{h.redacted}` | {h.updated_at} | [link]({h.gist_url}) |")
    Path(args.private).write_text("\n".join(md))
    print(f"[+] Done. Private: {args.private}")


if __name__ == "__main__":
    main()
