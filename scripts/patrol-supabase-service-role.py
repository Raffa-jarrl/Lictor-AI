#!/usr/bin/env python3
"""
Patrol — target the `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY` mistake.

This is one specific high-confidence finding pattern: putting the
Supabase service-role key behind a NEXT_PUBLIC_* prefix (or VITE_*,
or any client-exposed prefix) means it ends up in the JS bundle. Anyone
opening devtools then has bypass-RLS write access to the whole DB.

For each candidate:
  1. Fetch the file via GitHub raw URL
  2. Extract any JWT-shaped string near the env var name
  3. Base64-decode the JWT's middle segment
  4. If the payload has "role":"service_role", we've confirmed the bug

Output:
  - public-aggregate.md   — counts only, safe to publish
  - private-outreach.md   — owner, file URL, JWT fingerprint (NOT raw key);
                             gitignored; for Bridge / Raffa eyes only

Disclosure window: 30 days private before any public scorecard.
"""
from __future__ import annotations
import argparse, base64, json, re, subprocess, sys, time
from dataclasses import dataclass, field
from datetime import datetime, timezone

UA = "Lictor-Patrol/0.1 (+https://lictor-ai.com/scan; raffa@lictor-ai.com)"

# JWT shaped: header.payload.signature, base64url segments
JWT_RX = re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,}')

def gh_code_search(query, per_page=100, max_pages=5):
    """Iterate GitHub code search results."""
    results = []
    for page in range(1, max_pages + 1):
        try:
            out = subprocess.check_output(
                ["gh", "api", "-X", "GET", "search/code",
                 "-f", f"q={query}", "-f", f"per_page={per_page}", "-f", f"page={page}",
                 "--jq", ".items"],
                stderr=subprocess.DEVNULL, timeout=30)
            items = json.loads(out)
        except Exception:
            break
        if not items: break
        results.extend(items)
        time.sleep(2)  # respect rate limits
    return results

def gh_raw_file(repo, ref, path):
    """Download a file's raw content via the GitHub contents API."""
    try:
        out = subprocess.check_output(
            ["gh", "api", f"repos/{repo}/contents/{path}", "-q", ".content"],
            stderr=subprocess.DEVNULL, timeout=15)
        b64 = out.decode("utf-8").strip().replace("\n", "")
        return base64.b64decode(b64).decode("utf-8", "replace")
    except Exception:
        return None

def gh_repo_meta(repo):
    try:
        out = subprocess.check_output(
            ["gh", "api", f"repos/{repo}", "-q",
             "{html_url: .html_url, homepage: .homepage, description: .description, "
             "pushed_at: .pushed_at, created_at: .created_at, stars: .stargazers_count, "
             "owner_login: .owner.login, owner_type: .owner.type, owner_email: .owner.email}"],
            stderr=subprocess.DEVNULL, timeout=10)
        # gh's --jq returns text not JSON for object syntax; rerun without --jq
        out = subprocess.check_output(
            ["gh", "api", f"repos/{repo}"], stderr=subprocess.DEVNULL, timeout=10)
        d = json.loads(out)
        return {
            "html_url": d.get("html_url"), "homepage": d.get("homepage"),
            "description": d.get("description"), "pushed_at": d.get("pushed_at"),
            "created_at": d.get("created_at"), "stars": d.get("stargazers_count"),
            "owner": d.get("owner", {}).get("login"), "owner_type": d.get("owner", {}).get("type"),
        }
    except Exception:
        return {}

def decode_jwt_payload(jwt):
    try:
        parts = jwt.split(".")
        if len(parts) < 2: return None
        pad = "=" * (-len(parts[1]) % 4)
        raw = base64.urlsafe_b64decode(parts[1] + pad)
        return json.loads(raw)
    except Exception:
        return None

def jwt_fingerprint(jwt):
    """Short non-recoverable identifier — for tracking same key seen across repos."""
    import hashlib
    return hashlib.sha256(jwt.encode()).hexdigest()[:12]

# --- Categorization ---------------------------------------------------------

CLIENT_PATHS = (
    "src/components/", "src/app/", "src/pages/", "app/", "pages/", "components/",
    "client/", "frontend/", "ui/", "web/", "lib/supabase",
)
SERVER_PATHS = (
    "scripts/", "server/", "api/", "backend/", "tools/", "ops/", "migrations/",
)

def path_risk(path):
    p = path.lower()
    if any(p.startswith(s) or "/" + s.rstrip("/") + "/" in p for s in SERVER_PATHS):
        return "server"
    if any(p.startswith(s) or "/" + s.rstrip("/") + "/" in p for s in CLIENT_PATHS):
        return "client"
    if p.startswith(".env") or p.endswith(".env"): return "env-file"
    return "ambiguous"

@dataclass
class Candidate:
    repo: str
    path: str
    file_url: str
    path_risk: str
    file_content_excerpt: str = ""
    found_jwt: bool = False
    jwt_role: str = ""
    jwt_fingerprint: str = ""
    repo_meta: dict = field(default_factory=dict)

def triage_one(item, age_max_days):
    repo = item["repository"]["full_name"]
    path = item["path"]
    file_url = item["html_url"]
    pr = path_risk(path)

    cand = Candidate(repo=repo, path=path, file_url=file_url, path_risk=pr)
    cand.repo_meta = gh_repo_meta(repo)
    # Filter on recency
    pushed = cand.repo_meta.get("pushed_at", "")
    try:
        pushed_dt = datetime.fromisoformat(pushed.replace("Z","+00:00"))
        age_days = (datetime.now(timezone.utc) - pushed_dt).days
        cand.repo_meta["age_days"] = age_days
        if age_days > age_max_days:
            return None
    except Exception:
        return None

    content = gh_raw_file(repo, "HEAD", path)
    if not content: return cand
    # Find the surrounding line
    m = re.search(r'NEXT_PUBLIC_[A-Z_]*SERVICE_ROLE[^\n]*', content)
    if m:
        cand.file_content_excerpt = m.group(0)[:200]
    # Look for an adjacent JWT
    for jm in JWT_RX.finditer(content):
        payload = decode_jwt_payload(jm.group(0))
        if payload and payload.get("role") == "service_role":
            cand.found_jwt = True
            cand.jwt_role = "service_role"
            cand.jwt_fingerprint = jwt_fingerprint(jm.group(0))
            break
    return cand

def render_reports(cands, public_path, private_path):
    actionable = [c for c in cands if c.found_jwt and c.path_risk in ("client", "env-file", "ambiguous")]
    server_only = [c for c in cands if c.found_jwt and c.path_risk == "server"]

    # --- private outreach queue (NOT for public commit) ---
    md = ["# Patrol — Supabase service-role exposure (PRIVATE)\n"]
    md.append(f"**Scanned at:** {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}")
    md.append(f"**Disclosure status:** PRIVATE — 30-day window starts at first outreach.\n")
    md.append(f"## Confirmed service_role JWT in client-likely path ({len(actionable)})\n")
    md.append("Bridge: draft personalized outreach for each. Open file, verify it's actually exposed (not in a server-only context that just happens to live under src/), then send. Use the standard template from docs/launch/lictor-scan-and-patrol-v0.1.md.\n")
    md.append("| Repo | Path | Risk | Owner | Stars | Pushed | File |\n|---|---|---|---|---|---|---|\n")
    for c in sorted(actionable, key=lambda x: -(x.repo_meta.get("stars") or 0)):
        md.append(f"| `{c.repo}` | `{c.path}` | **{c.path_risk}** | "
                  f"{c.repo_meta.get('owner','?')} ({c.repo_meta.get('owner_type','?')}) | "
                  f"{c.repo_meta.get('stars',0)} | {c.repo_meta.get('pushed_at','?')[:10]} | "
                  f"[link]({c.file_url}) |")
    md.append("\n## Server-only context (no outreach needed)\n")
    for c in server_only:
        md.append(f"- `{c.repo}` / `{c.path}` — server path, legitimate use")
    open(private_path, "w").write("\n".join(md))

    # --- public aggregate (counts only) ---
    pm = ["# Patrol — service-role exposure scan (aggregate stats)\n"]
    pm.append(f"**Run:** {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}")
    pm.append(f"**Method:** GitHub Code Search for `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY` in TypeScript files, filtered to repos pushed in the last N days, with file fetched and JWT verified by decoding payload role.\n")
    pm.append("## Findings\n")
    pm.append(f"- Total candidate files inspected: **{len(cands)}**")
    pm.append(f"- Files with a confirmed `service_role` JWT decoded: **{sum(1 for c in cands if c.found_jwt)}**")
    pm.append(f"- Of those, in client-likely paths (the actual bug): **{len(actionable)}**")
    pm.append(f"- In server-only paths (legitimate use, no concern): **{len(server_only)}**\n")
    pm.append("## Methodology + ethics\n")
    pm.append("- Individual repos are not named in this aggregate report.")
    pm.append("- Each owner with a likely-exposed key is contacted privately within 24h.")
    pm.append("- 30-day private disclosure window before any individual scorecard goes public.")
    pm.append("- One-click opt-out at the founder's request, no questions.")
    pm.append("- Full methodology: [`docs/launch/lictor-scan-and-patrol-v0.1.md`](./lictor-scan-and-patrol-v0.1.md)")
    open(public_path, "w").write("\n".join(pm))
    return len(actionable), len(server_only), len(cands)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-candidates", type=int, default=30,
                    help="Cap on how many code-search hits to triage this run")
    ap.add_argument("--max-age-days", type=int, default=30,
                    help="Only consider repos pushed within this many days")
    ap.add_argument("--public", default="docs/launch/patrol-aggregate-2026-05-16.md")
    ap.add_argument("--private", default="docs/launch/patrol-outreach-private-2026-05-16.md")
    args = ap.parse_args()

    queries = [
        '"NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY" extension:ts',
        '"NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY" extension:tsx',
        '"NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY" extension:js',
        '"VITE_SUPABASE_SERVICE_ROLE_KEY" extension:ts',
    ]
    print("[+] Running GitHub code searches...")
    raw = []
    seen = set()
    for q in queries:
        items = gh_code_search(q, per_page=30, max_pages=1)
        for it in items:
            key = (it["repository"]["full_name"], it["path"])
            if key in seen: continue
            seen.add(key)
            raw.append(it)
            if len(raw) >= args.max_candidates: break
        if len(raw) >= args.max_candidates: break
    print(f"[+] {len(raw)} unique candidate files")

    cands = []
    for i, it in enumerate(raw, 1):
        repo = it["repository"]["full_name"]
        path = it["path"]
        print(f"  [{i}/{len(raw)}] {repo}/{path}", end="", flush=True)
        try:
            c = triage_one(it, args.max_age_days)
            if c is None:
                print("  too old, skip")
                continue
            cands.append(c)
            mark = "🔴" if c.found_jwt and c.path_risk != "server" else "⚪"
            print(f"  {mark} path_risk={c.path_risk} jwt={c.found_jwt} fp={c.jwt_fingerprint}")
        except Exception as e:
            print(f"  ERR: {e}")
        time.sleep(1.5)

    n_act, n_srv, n_total = render_reports(cands, args.public, args.private)
    print(f"\n[+] Done. Inspected {n_total}. {n_act} actionable. {n_srv} legitimate.")
    print(f"[+] Public aggregate: {args.public}")
    print(f"[+] Private outreach queue: {args.private}")

if __name__ == "__main__":
    main()
