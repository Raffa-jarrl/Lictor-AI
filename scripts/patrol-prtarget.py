#!/usr/bin/env python3
"""
patrol-prtarget — hunt the `pull_request_target` + checkout-PR-head RCE class.

GitHub Code Search has a known cap (~1000 results per query) so we paginate
across narrower queries to surface as many real candidates as possible.
For each candidate workflow file:
  1. Fetch raw content
  2. Verify both `pull_request_target` AND a checkout step referencing PR head
  3. Score severity: HIGH if the checkout uses ${{ github.event.pull_request.head.* }}
                     CRITICAL if it ALSO has `with: ref:` set to head AND runs build/test steps after
  4. Filter to repos with ≥10 stars (impact gating)
  5. Write outreach queue + aggregate stats

Disclosure ethics same as Patrol: privately notify each maintainer with the
30-day responsible window. Aggregate count goes public via the monthly
transparency report.
"""
from __future__ import annotations
import argparse, base64, json, re, subprocess, sys, time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path

CHECKOUT_HEAD_RX = re.compile(r'ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(sha|ref)', re.IGNORECASE)
PR_TARGET_RX = re.compile(r'^\s*on:\s*(\n[\s-]*[\w-]+:.*)*\n\s*pull_request_target\b', re.MULTILINE)
PR_TARGET_SIMPLE_RX = re.compile(r'\bpull_request_target\b')
USES_CHECKOUT_RX = re.compile(r'uses:\s*actions/checkout@')

@dataclass
class Hit:
    repo: str
    path: str
    url: str
    severity: str
    stars: int = 0
    pushed_at: str = ""
    evidence_lines: list[str] = field(default_factory=list)

def gh_code_search_paginated(query, per_page=100, max_pages=10):
    seen, results = set(), []
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
        for it in items:
            key = (it["repository"]["full_name"], it["path"])
            if key in seen: continue
            seen.add(key)
            results.append(it)
        time.sleep(2)  # rate-limit politely
    return results

def gh_repo_meta(repo):
    try:
        out = subprocess.check_output(
            ["gh", "api", f"repos/{repo}", "--jq",
             '{stars: .stargazers_count, pushed_at: .pushed_at, archived: .archived}'],
            stderr=subprocess.DEVNULL, timeout=10)
        return json.loads(out)
    except Exception:
        return {}

def gh_raw_file(repo, path):
    try:
        out = subprocess.check_output(
            ["gh", "api", f"repos/{repo}/contents/{path}", "-q", ".content"],
            stderr=subprocess.DEVNULL, timeout=15)
        return base64.b64decode(out.decode("utf-8").strip().replace("\n", "")).decode("utf-8", "replace")
    except Exception:
        return None

def verify_hit(repo: str, path: str, url: str) -> Hit | None:
    content = gh_raw_file(repo, path)
    if not content: return None

    has_pr_target = bool(PR_TARGET_SIMPLE_RX.search(content))
    has_checkout = bool(USES_CHECKOUT_RX.search(content))
    if not (has_pr_target and has_checkout):
        return None

    # Try to find checkout-of-PR-head
    head_match = CHECKOUT_HEAD_RX.search(content)
    # Severity scoring
    severity = "medium"  # default: has both but no obvious head-checkout
    evidence_lines = []
    if head_match:
        severity = "high"
        line_no = content[:head_match.start()].count("\n") + 1
        ev_line = content.split("\n")[line_no - 1].strip()[:120]
        evidence_lines.append(f"line {line_no}: {ev_line}")
        # Critical: head checkout + run/test/build step after
        after = "\n".join(content.split("\n")[line_no:line_no + 30])
        if re.search(r'run:\s*(npm|yarn|pnpm|python|pip|cargo|go|make|sh)\s+', after):
            severity = "critical"
            evidence_lines.append("→ runs build/install/test commands after PR-head checkout")

    # PR target found but checkout might be benign (no head ref)
    if not head_match:
        # If the workflow just has both but uses defaults — still elevated risk
        # but lower confidence. Skip to keep signal-to-noise high.
        return None

    meta = gh_repo_meta(repo)
    if meta.get("archived"): return None  # don't disclose to archived repos

    return Hit(
        repo=repo, path=path, url=url,
        severity=severity,
        stars=meta.get("stars", 0),
        pushed_at=meta.get("pushed_at", ""),
        evidence_lines=evidence_lines,
    )

def render_reports(hits, public_path, private_path):
    actionable = [h for h in hits if h.severity in ("critical", "high") and h.stars >= 10]

    md = ["# Patrol — pull_request_target + checkout-head RCE class (PRIVATE — gitignored)\n"]
    md.append(f"**Scanned at:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    md.append(f"**Method:** GitHub Code Search for `pull_request_target` in YAML workflow files, then raw-file fetch + AST regex confirmation that the workflow checks out the PR's head SHA.")
    md.append(f"**Disclosure status:** PRIVATE — 30-day responsible window starts at first outreach per repo.\n")
    md.append(f"## Confirmed exposures (severity ≥ HIGH, stars ≥ 10): {len(actionable)}\n")
    md.append("| Repo | Stars | Severity | File | Last pushed |")
    md.append("|---|---|---|---|---|")
    for h in sorted(actionable, key=lambda x: (-x.stars, x.severity)):
        md.append(f"| `{h.repo}` | {h.stars} | **{h.severity.upper()}** | `{h.path}` | {h.pushed_at[:10]} |")
    md.append("\n## Outreach playbook\n")
    md.append("Per repo:")
    md.append("1. Check if PVR is enabled: navigate to `https://github.com/<repo>/security/advisories/new`")
    md.append("2. If PVR works: use the punkpeye-style draft (see `disclosures/2026-05-17/02-punkpeye-mcp-servers.md` as template)")
    md.append("3. If PVR is off: open a public issue with 'I have a security finding, contact me at raffa@lictorai.com' — NO details in public")
    md.append("4. Mark disclosure-sent timestamp in `~/.lictor/patrol-state.json`")
    Path(private_path).write_text("\n".join(md))

    # Aggregate report (public-safe)
    pm = ["# Patrol — pull_request_target attack-class scan (aggregate)\n"]
    pm.append(f"**Run:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    pm.append(f"**Method:** GitHub Code Search for `pull_request_target` in workflow YAML, raw-file content verification of checkout-PR-head pattern.\n")
    pm.append("## Aggregate counts\n")
    pm.append(f"- Candidate workflow files searched: **{len(hits)}**")
    pm.append(f"- Confirmed checkout-PR-head pattern: **{sum(1 for h in hits if h.severity in ('critical','high'))}**")
    pm.append(f"- High severity (PR head checked out, no build step yet): **{sum(1 for h in hits if h.severity == 'high')}**")
    pm.append(f"- Critical severity (PR head checked out + runs build/test): **{sum(1 for h in hits if h.severity == 'critical')}**")
    pm.append(f"- Outreach-eligible (above + ≥10 stars + not archived): **{len(actionable)}**")
    Path(public_path).write_text("\n".join(pm))

    return len(actionable), len(hits)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max", type=int, default=200, help="Cap on candidates inspected")
    ap.add_argument("--public", default="docs/launch/patrol-prtarget-aggregate-2026-05-17.md")
    ap.add_argument("--private", default="docs/launch/patrol-prtarget-private-2026-05-17.md")
    args = ap.parse_args()

    queries = [
        '"pull_request_target" extension:yml path:.github/workflows',
        '"pull_request_target" extension:yaml path:.github/workflows',
    ]
    print("[+] Searching GitHub Code Search for pull_request_target...")
    raw = []
    seen = set()
    for q in queries:
        items = gh_code_search_paginated(q, per_page=100, max_pages=5)
        for it in items:
            key = (it["repository"]["full_name"], it["path"])
            if key in seen: continue
            seen.add(key)
            raw.append(it)
            if len(raw) >= args.max: break
        if len(raw) >= args.max: break
    print(f"[+] {len(raw)} candidate workflow files")

    hits = []
    for i, it in enumerate(raw, 1):
        repo = it["repository"]["full_name"]
        path = it["path"]
        url = it["html_url"]
        print(f"  [{i}/{len(raw)}] {repo}/{path}", end="", flush=True)
        try:
            h = verify_hit(repo, path, url)
            if h:
                hits.append(h)
                mark = "🔴" if h.severity == "critical" else "🟠" if h.severity == "high" else "⚪"
                print(f"  {mark} {h.severity} (★{h.stars})")
            else:
                print("  ⚪ no head-checkout / benign")
        except Exception as e:
            print(f"  EXC: {e}")
        time.sleep(1.2)

    n_act, n_total = render_reports(hits, args.public, args.private)
    print(f"\n[+] Done. {n_total} hits, {n_act} actionable. Private: {args.private}")

if __name__ == "__main__":
    main()
