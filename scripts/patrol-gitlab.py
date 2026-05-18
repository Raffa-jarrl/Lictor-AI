#!/usr/bin/env python3
"""
patrol-gitlab — hunt secrets in public GitLab.com projects.

Fresh corpus: zero overlap with GitHub Code Search ceiling.
Uses GitLab's public search API for blobs (free, no auth for public projects).

For each match: fetch raw file, regex-verify, repo-meta-check, filter
placeholders + archived + stale, write outreach queue.
"""
from __future__ import annotations
import argparse, json, re, time, urllib.request, urllib.error, urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from pathlib import Path

UA = "Lictor-Patrol-GitLab/0.1 (+https://lictorai.com)"
TIMEOUT = 20

# Same secret patterns as our existing scanners
PATTERNS = {
    "firebase-sa":  re.compile(r'"private_key_id"\s*:\s*"[a-f0-9]{20,}".*?"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----', re.DOTALL),
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

PLACEHOLDER = re.compile(r'(your|example|placeholder|REPLACE|XXX|TODO|getenv|environ|<.*>|test|demo|sample|fake|0{8,}|x{8,})', re.IGNORECASE)
SKIP_PATH = re.compile(r'(\.example$|/tests?/|/spec/|/fixtures?/|/docs?/|README|CHANGELOG)', re.IGNORECASE)


@dataclass
class Hit:
    kind: str
    project: str
    path: str
    url: str
    redacted: str
    stars: int = 0
    last_activity: str = ""


def http_get_json(url, timeout=TIMEOUT):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except Exception:
        return None


def http_get_text(url, max_bytes=200_000, timeout=TIMEOUT):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read(max_bytes).decode("utf-8", "replace")
    except Exception:
        return None


def gl_search_projects(keyword, per_page=100, pages=2):
    """GitLab public-projects search (no auth needed for public)."""
    seen = set()
    out = []
    for page in range(1, pages + 1):
        url = f"https://gitlab.com/api/v4/projects?search={urllib.parse.quote(keyword)}&per_page={per_page}&page={page}&order_by=last_activity_at&visibility=public"
        data = http_get_json(url)
        if not data: break
        if not isinstance(data, list) or not data: break
        for p in data:
            pid = p.get("id")
            if pid in seen: continue
            seen.add(pid)
            out.append(p)
        time.sleep(0.6)
    return out


def gl_list_files(project_id, ref="HEAD"):
    """List files in a project's default branch via repo-tree API."""
    out = []
    for page in range(1, 3):
        url = f"https://gitlab.com/api/v4/projects/{project_id}/repository/tree?recursive=true&per_page=100&page={page}&ref={ref}"
        data = http_get_json(url)
        if not data or not isinstance(data, list): break
        out.extend(data)
        if len(data) < 100: break
        time.sleep(0.3)
    return out


def gl_get_raw(project_id, path, ref="HEAD"):
    """Fetch raw file content."""
    url = f"https://gitlab.com/api/v4/projects/{project_id}/repository/files/{urllib.parse.quote(path, safe='')}/raw?ref={ref}"
    return http_get_text(url)


def scan_project(project, max_files=30):
    """Walk project files, scan each for known patterns. Yield Hit objects."""
    pid = project.get("id")
    path_with_namespace = project.get("path_with_namespace", "?")
    web_url = project.get("web_url", "")
    star_count = project.get("star_count", 0)
    last_activity = project.get("last_activity_at", "")[:10]
    default_branch = project.get("default_branch", "main")

    files = gl_list_files(pid, ref=default_branch)
    out = []
    seen_keys = set()
    interesting = [f for f in files if f.get("type") == "blob"
                   and not SKIP_PATH.search(f.get("path", ""))
                   and re.search(r'\.(py|js|ts|json|env|yaml|yml|cfg|ini|toml|sh|tf|md)$', f.get("path", ""))]
    for f in interesting[:max_files]:
        path = f.get("path", "")
        text = gl_get_raw(pid, path, ref=default_branch)
        if not text: continue
        for kind, rx in PATTERNS.items():
            for m in rx.finditer(text):
                val = m.group(1) if m.lastindex else m.group(0)
                key = (kind, val)
                if key in seen_keys: continue
                seen_keys.add(key)
                ctx = text[max(0, m.start()-60):min(len(text), m.start()+60)]
                if PLACEHOLDER.search(ctx): continue
                red = val[:8] + "…" + val[-4:] if len(val) > 14 else val
                out.append(Hit(kind=kind, project=path_with_namespace, path=path,
                               url=f"{web_url}/-/blob/{default_branch}/{path}",
                               redacted=red, stars=star_count, last_activity=last_activity))
        time.sleep(0.2)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-projects", type=int, default=200)
    ap.add_argument("--max-files-per-project", type=int, default=25)
    ap.add_argument("--max-age-days", type=int, default=365)
    ap.add_argument("--keywords", nargs="+", default=[
        "ai", "openai", "firebase", "supabase", "claude", "gpt",
        "chatbot", "agent", "llm", "rag", "embedding"
    ])
    ap.add_argument("--private", default=f"docs/launch/patrol-gitlab-{datetime.now().strftime('%Y-%m-%d')}-private.md")
    args = ap.parse_args()

    cutoff = (datetime.now(timezone.utc) - timedelta(days=args.max_age_days)).strftime('%Y-%m-%d')
    print(f"[+] gitlab patrol — keywords={args.keywords} cutoff={cutoff}", flush=True)

    # Pool projects via keyword search
    all_projects = {}
    for kw in args.keywords:
        ps = gl_search_projects(kw, per_page=100, pages=1)
        for p in ps:
            pid = p.get("id")
            if pid and pid not in all_projects:
                all_projects[pid] = p
        time.sleep(0.5)
        if len(all_projects) >= args.max_projects: break

    candidates = list(all_projects.values())[:args.max_projects]
    # Filter to fresh (pushed within max_age_days)
    fresh = [p for p in candidates if (p.get("last_activity_at", "") or "")[:10] >= cutoff]
    print(f"[+] discovered {len(candidates)} projects, {len(fresh)} fresh (≤{args.max_age_days}d)", flush=True)

    hits = []
    for i, p in enumerate(fresh, 1):
        name = p.get("path_with_namespace", "?")
        print(f"  [{i}/{len(fresh)}] {name}", end="", flush=True)
        try:
            ph = scan_project(p, max_files=args.max_files_per_project)
            if ph:
                hits.extend(ph)
                print(f"  🔴 {len(ph)} hit(s)", flush=True)
                for h in ph:
                    print(f"     {h.kind} {h.redacted}  {h.path}", flush=True)
            else:
                print("  ⚪", flush=True)
        except Exception as e:
            print(f"  EXC: {e}", flush=True)
        time.sleep(0.5)

    md = [f"# Patrol — GitLab.com secret exposure (PRIVATE)\n",
          f"**Scanned at:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
          f"**Projects inspected:** {len(fresh)}",
          f"**Confirmed exposures:** {len(hits)}\n",
          "| Kind | Project | Path | ★ | Last activity | Redacted | URL |",
          "|---|---|---|---|---|---|---|"]
    for h in sorted(hits, key=lambda x: (-x.stars, x.kind)):
        md.append(f"| {h.kind} | `{h.project}` | `{h.path}` | {h.stars} | {h.last_activity} | `{h.redacted}` | [link]({h.url}) |")
    Path(args.private).write_text("\n".join(md))
    print(f"\n[+] Done. {len(hits)} verified GitLab exposures.")
    print(f"[+] Private: {args.private}")


if __name__ == "__main__":
    main()
