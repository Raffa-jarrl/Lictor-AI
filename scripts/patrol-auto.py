#!/usr/bin/env python3
"""
patrol-auto — Lictor's continuous Patrol pipeline.

Runs in the shadow (cron, every 6h), serves the light (transparent aggregate
stats published monthly; individual disclosures sent privately under
responsible 30-day disclosure window).

Pipeline:
  1. DISCOVER  — query GitHub for new MCP / vibe-coded repos (since last run)
  2. CLONE     — shallow-clone candidates into /tmp/patrol-cache
  3. SCAN      — run lictor-multi.py against each
  4. TRIAGE    — for actionable findings (CRITICAL/HIGH in client-likely paths),
                 generate a draft disclosure file in disclosures/queue/
  5. NOTIFY    — macOS notification when queue gets new items
  6. STATS     — append aggregate counts to output/patrol-aggregate.jsonl

What it does NOT do:
  - Send anything. Every disclosure draft sits in the queue until Raffa
    reviews + submits manually. The Submit click is the irreversible human
    step. Patrol does everything up to that line.

Cron line:
  0 */6 * * * cd ~/Lictor && python3 scripts/patrol-auto.py --max 30 >> ~/.lictor/patrol-auto.log 2>&1

State file:
  ~/.lictor/patrol-state.json — tracks last-scanned timestamp, repo
  history (to avoid re-scanning), queue size, disclosure status.
"""
from __future__ import annotations
import argparse, hashlib, json, os, subprocess, sys, time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

LICTOR_ROOT = Path(os.environ.get("LICTOR_ROOT", Path.home() / "Lictor"))
STATE_DIR = Path(os.environ.get("LICTOR_STATE", Path.home() / ".lictor"))
STATE_DIR.mkdir(exist_ok=True)
STATE_FILE = STATE_DIR / "patrol-state.json"
CACHE_DIR = Path("/tmp/patrol-cache")
CACHE_DIR.mkdir(exist_ok=True)
QUEUE_DIR = LICTOR_ROOT / "disclosures" / "queue"
QUEUE_DIR.mkdir(parents=True, exist_ok=True)
AGGREGATE_FILE = LICTOR_ROOT / "output" / "patrol-aggregate.jsonl"
AGGREGATE_FILE.parent.mkdir(parents=True, exist_ok=True)

# ----- State management -----

def load_state() -> dict:
    if STATE_FILE.exists():
        try: return json.loads(STATE_FILE.read_text())
        except Exception: pass
    return {"last_run": None, "seen_repos": {}, "queue_count": 0, "total_disclosed": 0}

def save_state(state: dict):
    STATE_FILE.write_text(json.dumps(state, indent=2))

# ----- Discovery -----

DISCOVERY_QUERIES = [
    # MCP ecosystem (our wedge — highest leverage)
    '"modelcontextprotocol" language:python pushed:>{since}',
    '"@modelcontextprotocol/sdk" language:typescript pushed:>{since}',
    'topic:mcp-server pushed:>{since}',
    # Vibe-coder ecosystem
    'lovable created:>{since}',
    '"bolt.new" OR "bolt-new" created:>{since}',
    '"v0.dev" created:>{since}',
    # Browser extensions
    'topic:chrome-extension created:>{since}',
    # CI/CD configs (every GH Action repo update)
    '"pull_request_target" extension:yml pushed:>{since}',
]

def discover(since_days: int) -> list[dict]:
    """Query GitHub for fresh candidates. Returns a list of {full_name, html_url, pushed_at}."""
    since = (datetime.now(timezone.utc) - timedelta(days=since_days)).strftime("%Y-%m-%d")
    seen, results = set(), []
    for q in DISCOVERY_QUERIES:
        query = q.format(since=since)
        try:
            out = subprocess.check_output(
                ["gh", "api", "-X", "GET", "search/repositories",
                 "-f", f"q={query}", "-f", "per_page=50", "--jq", ".items"],
                stderr=subprocess.DEVNULL, timeout=30)
            items = json.loads(out)
        except Exception:
            continue
        for it in items:
            key = it.get("full_name")
            if not key or key in seen: continue
            seen.add(key)
            results.append({
                "repo": key, "html_url": it["html_url"],
                "pushed_at": it.get("pushed_at"),
                "stars": it.get("stargazers_count", 0),
            })
        time.sleep(2)  # rate-limit politely
    return results

# ----- Cloning -----

def shallow_clone(repo: str) -> Path | None:
    safe = repo.replace("/", "-")
    dest = CACHE_DIR / safe
    if dest.exists():
        # Update if older than 7 days
        if (time.time() - dest.stat().st_mtime) < 7 * 24 * 3600:
            return dest
        subprocess.run(["rm", "-rf", str(dest)], stderr=subprocess.DEVNULL)
    try:
        subprocess.check_call(
            ["git", "clone", "--depth=1", "--quiet", f"https://github.com/{repo}", str(dest)],
            stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL, timeout=60)
        return dest
    except Exception:
        return None

# ----- Scan -----

def scan(repo_path: Path) -> dict:
    """Invoke lictor-multi.py on the path, return parsed JSON."""
    try:
        out = subprocess.check_output(
            ["python3", str(LICTOR_ROOT / "scripts" / "lictor-multi.py"), str(repo_path), "--json"],
            stderr=subprocess.DEVNULL, timeout=120)
        return json.loads(out)
    except Exception as e:
        return {"shape": {}, "findings": [], "error": str(e)}

# ----- Triage -----

OUTREACH_SEVERITIES = ("critical", "high")

def is_actionable(finding: dict) -> bool:
    """A finding is worth outreach if severity is CRITICAL/HIGH and not in a known-false-positive path."""
    if finding.get("severity") not in OUTREACH_SEVERITIES: return False
    path = finding.get("path", "")
    # Skip false-positive paths
    SKIP = ("vendor/", "third_party/", "node_modules/", ".venv/", "site-packages/", "test/", "tests/")
    if any(s in path for s in SKIP): return False
    return True

def queue_disclosure(repo: dict, findings: list[dict]):
    """Write a disclosure draft to disclosures/queue/<safe-name>.md. Always overwrite."""
    safe = repo["repo"].replace("/", "_")
    out = QUEUE_DIR / f"{safe}.md"
    actionable = [f for f in findings if is_actionable(f)]
    if not actionable: return None

    md = [f"# Draft disclosure — `{repo['repo']}`\n"]
    md.append(f"**Discovered:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    md.append(f"**Repo URL:** {repo['html_url']}")
    md.append(f"**Stars:** {repo.get('stars', 0)}  ·  **Last pushed:** {repo.get('pushed_at','?')}")
    md.append(f"**Actionable findings:** {len(actionable)}\n")
    md.append("---\n## What to do\n")
    md.append("1. **Verify** each finding manually (open the file, confirm it's a real exposure, not a false positive)")
    md.append("2. **Check PVR**: visit `https://github.com/" + repo['repo'] + "/security/advisories/new` — does the form load?")
    md.append("    - YES → use this draft as the basis for your private security advisory")
    md.append("    - NO  → open a public issue saying 'I have a security finding, contact me at raffa@lictorai.com'")
    md.append("3. **30-day disclosure window** starts at the moment you contact the maintainer")
    md.append("4. **Update** `~/.lictor/patrol-state.json` with the advisory ID + outcome\n")
    md.append("---\n## Findings\n")
    for f in actionable:
        emoji = {"critical": "🔴", "high": "🟠"}.get(f["severity"], "")
        md.append(f"### {emoji} **{f['severity'].upper()}** — {f['title']}")
        md.append(f"- Surface: `{f['surface']}`  ·  Check: `{f['check']}`")
        if f.get("path"): md.append(f"- Path: `{f['path']}`" + (f":{f['line']}" if f.get('line') else ''))
        if f.get("evidence"): md.append(f"- Evidence: `{f['evidence']}`")
        if f.get("fix"): md.append(f"- Suggested fix: {f['fix']}")
        md.append("")
    out.write_text("\n".join(md))
    return out

# ----- Aggregate stats (the public-facing artifact) -----

def append_aggregate(timestamp: str, scanned_n: int, findings_by_severity: dict, findings_by_surface: dict):
    """Append one row to the aggregate JSONL. Goes public on lictorai.com/in-the-wild."""
    row = {
        "timestamp": timestamp,
        "scanned_n": scanned_n,
        "by_severity": findings_by_severity,
        "by_surface": findings_by_surface,
    }
    with AGGREGATE_FILE.open("a") as f:
        f.write(json.dumps(row) + "\n")

# ----- macOS notification -----

def notify(title: str, message: str):
    try:
        subprocess.run(["osascript", "-e",
            f'display notification "{message}" with title "{title}" sound name "Glass"'],
            stderr=subprocess.DEVNULL, timeout=5)
    except Exception:
        pass

# ----- Main -----

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--since-days", type=int, default=2, help="Days back to discover")
    ap.add_argument("--max", type=int, default=30, help="Cap on repos to process this run")
    ap.add_argument("--dry-run", action="store_true", help="Discover + report only; don't clone/scan")
    args = ap.parse_args()

    print(f"[{datetime.now().isoformat(timespec='seconds')}] Patrol auto starting...")
    state = load_state()

    candidates = discover(args.since_days)
    new_candidates = [c for c in candidates if c["repo"] not in state["seen_repos"]][:args.max]
    print(f"  Discovered: {len(candidates)} repos · New (not seen before): {len(new_candidates)}")

    if args.dry_run:
        for c in new_candidates:
            print(f"  would scan: {c['repo']}")
        return

    queued_this_run = 0
    sev_counts = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
    surface_counts = {}
    for c in new_candidates:
        path = shallow_clone(c["repo"])
        if not path:
            print(f"  [skip] clone failed: {c['repo']}")
            state["seen_repos"][c["repo"]] = {"status": "clone-failed", "ts": datetime.now(timezone.utc).isoformat()}
            continue
        result = scan(path)
        for f in result.get("findings", []):
            sev_counts[f.get("severity", "info")] = sev_counts.get(f.get("severity"), 0) + 1
            surface = f.get("surface", "?")
            surface_counts[surface] = surface_counts.get(surface, 0) + 1
        draft = queue_disclosure(c, result.get("findings", []))
        if draft:
            queued_this_run += 1
            print(f"  [queue] {c['repo']} → {draft.name} ({sum(1 for f in result['findings'] if is_actionable(f))} actionable)")
        state["seen_repos"][c["repo"]] = {
            "status": "scanned",
            "ts": datetime.now(timezone.utc).isoformat(),
            "findings_n": len(result.get("findings", [])),
            "queued": bool(draft),
        }

    append_aggregate(datetime.now(timezone.utc).isoformat(), len(new_candidates), sev_counts, surface_counts)
    state["last_run"] = datetime.now(timezone.utc).isoformat()
    state["queue_count"] += queued_this_run
    save_state(state)

    print(f"  Aggregate: scanned={len(new_candidates)}, critical+high={sev_counts['critical']+sev_counts['high']}, queued={queued_this_run}")
    if queued_this_run:
        notify("Lictor Patrol — new disclosures queued", f"{queued_this_run} new draft(s). Review at disclosures/queue/")

if __name__ == "__main__":
    main()
