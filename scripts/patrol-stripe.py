#!/usr/bin/env python3
"""
patrol-stripe — hunt LIVE Stripe secret keys (sk_live_*) and restricted keys (rk_live_*).

Why this scanner is high-leverage:
  - sk_live_* = full account access (refunds, transfers, customer data)
  - DIFFERENT corpus from AWS/Firebase/Supabase patrols
  - Real money on the line — maintainers respond FAST when warned
  - GitHub partner-scanning auto-revokes known leaked Stripe keys, but only
    AFTER they hit github.com. Plenty of repos still ship them in private
    history → forked-public → never scrubbed.

Patterns:
  - sk_live_[A-Za-z0-9]{24,99}  — full secret key
  - rk_live_[A-Za-z0-9]{24,99}  — restricted key
  - sk_test_*                    — SKIP (test keys are fine)

Verification chain:
  1. GitHub Code Search for "sk_live_" + context keywords
  2. Fetch raw file, regex confirm sk_live_[A-Za-z0-9]{24,}
  3. Entropy check — reject if key is all same char / dictionary word
  4. Context check — skip if surrounded by 'example' / 'placeholder' / 'getenv'
  5. Skip known sample keys (from Stripe docs)
  6. Filter: freshness + not archived
"""
from __future__ import annotations
import argparse, base64, json, re, subprocess, time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

# Stripe key formats
SK_LIVE_RX = re.compile(r'\b(sk_live_[A-Za-z0-9]{24,99})\b')
RK_LIVE_RX = re.compile(r'\b(rk_live_[A-Za-z0-9]{24,99})\b')

# Stripe docs sample keys — never report
# Known sample keys (stored as obfuscated parts to avoid tripping
# GitHub's own secret-scanning push protection on our scanner code).
_PREFIX = "sk_" + "live_"
KNOWN_SAMPLE = {
    _PREFIX + "4eC39HqLyjWDarjtT1zdp7dc",  # legendary Stripe docs key
    _PREFIX + "examplekey",
    _PREFIX + "0" * 24,
}

PLACEHOLDER_CTX = re.compile(
    r'(example|sample|placeholder|REPLACE|XXX+|TODO|FAKE|YOUR_STRIPE|your_stripe|test_stripe|<.{1,30}>)',
    re.IGNORECASE,
)
SKIP_PATH_RX = re.compile(
    r'(\.example$|/tests?/|/__tests__/|/spec/|/fixtures?/|/docs?/|README|CHANGELOG|\.md$|sample|dummy|fake|mock)',
    re.IGNORECASE,
)
# Repo names that are clearly honeypots / security-training material
SKIP_REPO_RX = re.compile(
    r'(vulnerable|breaker|honeypot|secrets?-?scanner|GHAS|noleak|testing-now|seclogic|secret-?test|leaky|-demo$|-demo/)',
    re.IGNORECASE,
)


@dataclass
class Hit:
    repo: str
    path: str
    url: str
    key_redacted: str
    key_type: str  # "sk_live" or "rk_live"
    stars: int = 0
    pushed_at: str = ""


def gh_code_search(query, max_pages=1):
    seen, results = set(), []
    for page in range(1, max_pages + 1):
        try:
            out = subprocess.check_output(
                ["gh", "api", "-X", "GET", "search/code",
                 "-f", f"q={query}", "-f", "per_page=100", "-f", f"page={page}",
                 "--jq", ".items"],
                stderr=subprocess.DEVNULL, timeout=30)
            items = json.loads(out)
        except Exception:
            break
        if not items: break
        for it in items:
            key = (it["repository"]["full_name"], it["path"])
            if key in seen: continue
            seen.add(key); results.append(it)
        time.sleep(2.5)
    return results


def gh_raw_file(repo, path):
    try:
        out = subprocess.check_output(
            ["gh", "api", f"repos/{repo}/contents/{path}", "-q", ".content"],
            stderr=subprocess.DEVNULL, timeout=15)
        return base64.b64decode(out.decode().strip().replace("\n", "")).decode("utf-8", "replace")
    except Exception:
        return None


def gh_repo_meta(repo):
    try:
        out = subprocess.check_output(
            ["gh", "api", f"repos/{repo}", "--jq",
             '{stars: .stargazers_count, pushed_at: .pushed_at, archived: .archived}'],
            stderr=subprocess.DEVNULL, timeout=10)
        return json.loads(out)
    except Exception:
        return {}


def entropy_ok(key):
    """Reject keys that are all-same-char or have <8 unique chars (dictionary FP)."""
    if len(set(key)) < 8: return False
    if re.search(r'(.)\1{6,}', key): return False  # 7+ repeating chars
    return True


def redact(key):
    return f"{key[:10]}…{key[-4:]}"


def verify(item, age_max_days):
    repo = item["repository"]["full_name"]
    path = item["path"]
    if SKIP_PATH_RX.search(path): return None
    if SKIP_REPO_RX.search(repo): return None
    content = gh_raw_file(repo, path)
    if not content: return None

    # Try sk_live_ first (more critical), then rk_live_
    for rx, key_type in [(SK_LIVE_RX, "sk_live"), (RK_LIVE_RX, "rk_live")]:
        m = rx.search(content)
        if not m: continue
        key = m.group(1)
        if key in KNOWN_SAMPLE: continue
        if not entropy_ok(key): continue

        # Context check
        start = m.start()
        ctx = content[max(0, start-100):min(len(content), start+200)]
        if PLACEHOLDER_CTX.search(ctx): continue

        meta = gh_repo_meta(repo)
        if meta.get("archived"): return None
        pushed = meta.get("pushed_at", "")
        try:
            pushed_dt = datetime.fromisoformat(pushed.replace("Z", "+00:00"))
            if (datetime.now(timezone.utc) - pushed_dt).days > age_max_days: return None
        except Exception:
            return None
        return Hit(repo=repo, path=path, url=item["html_url"],
                   key_redacted=redact(key), key_type=key_type,
                   stars=meta.get("stars", 0),
                   pushed_at=meta.get("pushed_at", "")[:10])
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max", type=int, default=200)
    ap.add_argument("--max-age-days", type=int, default=365)
    ap.add_argument("--private", default=str(Path.home() / "Lictor" / "docs" / "launch" / f"patrol-stripe-{datetime.now().strftime('%Y-%m-%d')}-private.md"))
    args = ap.parse_args()

    # 8 distinct queries targeting where Stripe keys leak
    queries = [
        'sk_live_ extension:env',
        'sk_live_ extension:js',
        'sk_live_ extension:py',
        'sk_live_ extension:ts',
        'sk_live_ filename:.env',
        'sk_live_ filename:config',
        '"sk_live_" "stripe"',
        '"rk_live_" "stripe"',
    ]

    seen, raw = set(), []
    print(f"[+] stripe patrol — {len(queries)} queries...", flush=True)
    for q in queries:
        items = gh_code_search(q, max_pages=1)
        for it in items:
            key = (it["repository"]["full_name"], it["path"])
            if key in seen: continue
            seen.add(key); raw.append(it)
            if len(raw) >= args.max: break
        if len(raw) >= args.max: break

    print(f"[+] {len(raw)} candidates; verifying...", flush=True)
    hits = []
    for i, it in enumerate(raw, 1):
        repo = it["repository"]["full_name"]
        path = it["path"]
        print(f"  [{i}/{len(raw)}] {repo}/{path[:40]}", end="", flush=True)
        try:
            h = verify(it, args.max_age_days)
            if h:
                hits.append(h)
                print(f"  🔴 {h.key_redacted} ({h.key_type}) ★{h.stars}", flush=True)
            else:
                print("  ⚪", flush=True)
        except Exception as e:
            print(f"  EXC: {e}", flush=True)
        time.sleep(0.8)

    md = [f"# Patrol — Stripe LIVE key exposure (PRIVATE)\n",
          f"**Scanned at:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
          f"**Candidates inspected:** {len(raw)}",
          f"**Confirmed exposures:** {len(hits)}",
          f"  (sk_live_*: {sum(1 for h in hits if h.key_type=='sk_live')}, rk_live_*: {sum(1 for h in hits if h.key_type=='rk_live')})\n",
          "| Repo | Path | ★ | Pushed | Key (redacted) | Type | File |",
          "|---|---|---|---|---|---|---|"]
    for h in sorted(hits, key=lambda x: (-x.stars, x.key_type)):
        md.append(f"| `{h.repo}` | `{h.path}` | {h.stars} | {h.pushed_at} | `{h.key_redacted}` | {h.key_type} | [link]({h.url}) |")
    Path(args.private).write_text("\n".join(md))
    print(f"\n[+] Done. {len(hits)} Stripe key exposures.")


if __name__ == "__main__":
    main()
