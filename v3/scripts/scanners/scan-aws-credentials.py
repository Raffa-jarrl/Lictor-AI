#!/usr/bin/env python3
"""scan-aws-credentials.py — Find AWS access key + secret pairs in public content.

THE TARGET:
  AWS credentials that escape into public artifacts: sourcemaps, exposed
  .git/, public buckets, build logs. Live AWS access keys with admin
  privileges are the highest-payout single bounty class — Coinbase paid
  $250K for one, Capital One paid $200K for one. Even an IAM user with
  S3:ListBucket scope can be $5K-$25K.

ETHICAL GUARANTEES:
  - GET only on public web content
  - NEVER calls AWS STS / IAM (would require running their secret)
  - Outputs the AKIA ID + a redacted secret + safe manual-validate command
  - The user runs validation themselves with their own decision to act

WHAT IT FINDS:
  Paired AKIA + 40-char-secret in the same nearby context (within 200 chars
  of each other in the file). This minimizes FP from random AKIA-like
  strings that aren't actual AWS keys.

LIVE VALIDATION (manual, for the user to run):
  $ AWS_ACCESS_KEY_ID=AKIA... AWS_SECRET_ACCESS_KEY=... \\
    aws sts get-caller-identity
  Returns the principal ARN if live, AccessDenied if revoked.
  This is read-only and reveals only the identity, not data.
"""
import argparse
import json
import re
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime, timezone

USER_AGENT = "LictorAI-EthicalScanner/0.3 (+https://lictor-ai.com/transparency)"
LEDGER = Path.home() / "Lictor/v3/ledgers/aws-credentials.jsonl"
DEFAULT_SOURCEMAP_LEDGER = Path.home() / "Lictor/v3/ledgers/sourcemap-exposure.jsonl"

# Patterns — STRICT to minimize FP
AKIA_RE   = re.compile(rb"\b(AKIA[0-9A-Z]{16})\b")
ASIA_RE   = re.compile(rb"\b(ASIA[0-9A-Z]{16})\b")   # temp creds
# Secret: 40 char base64-ish, but be careful — many other strings match this
SECRET_RE = re.compile(rb"\b([A-Za-z0-9/+=]{40})\b")

# Strong context indicators that an adjacent 40-char string IS the secret
SECRET_CONTEXT = re.compile(rb"(SECRET|secret_access_key|aws_secret|awsSecret|"
                            rb"AWS_SECRET_ACCESS_KEY|secretAccessKey)",
                            re.I)

# Known docs/example AWS keys — IGNORE
KNOWN_EXAMPLE_KEYS = {
    b"AKIAIOSFODNN7EXAMPLE",   # AWS official example
    b"AKIAI44QH8DHBEXAMPLE",
}


def redact_secret(s):
    """Show first 4 + last 4 chars only."""
    if isinstance(s, bytes):
        s = s.decode("latin-1", "replace")
    if len(s) <= 10:
        return s[:2] + "..." + s[-2:]
    return s[:4] + "..." + s[-4:]


def fetch_url(url, max_bytes=5 * 1024 * 1024):
    """GET public content, cap at max_bytes."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=20) as r:
            if r.status != 200:
                return None
            return r.read(max_bytes)
    except Exception:
        return None


def find_aws_pairs(body):
    """Find paired AKIA + secret in proximity. Returns list of pairs."""
    if not body:
        return []
    pairs = []
    # First pass: find all AKIA matches
    akia_hits = []
    for pat in (AKIA_RE, ASIA_RE):
        for m in pat.finditer(body):
            key = m.group(0)
            if key in KNOWN_EXAMPLE_KEYS:
                continue
            akia_hits.append({"key": key, "pos": m.start()})

    # For each AKIA, look for a secret-like string within 200 chars
    seen_keys = set()
    for hit in akia_hits:
        key = hit["key"]
        if key in seen_keys:
            continue
        seen_keys.add(key)
        pos = hit["pos"]
        # Window: 200 chars before and after
        window_start = max(0, pos - 200)
        window_end = min(len(body), pos + 200)
        window = body[window_start:window_end]

        # If the SECRET_CONTEXT hint is in the window, increase confidence
        has_context = bool(SECRET_CONTEXT.search(window))

        # Find 40-char base64-ish strings in window (excluding the AKIA itself)
        candidates = []
        for m in SECRET_RE.finditer(window):
            cand = m.group(0)
            if cand == key:
                continue
            # Filter out things that are obviously NOT AWS secrets
            # (AWS secrets are 40 chars, alphanumeric + /+ =, never just hex)
            if re.fullmatch(rb"[0-9a-fA-F]+", cand):
                continue  # pure hex = likely hash, not aws secret
            if cand.startswith((b"sha", b"md5", b"base64", b"data")):
                continue
            candidates.append(cand)

        if candidates:
            pairs.append({
                "akia": key.decode("latin-1"),
                "secret_candidates": [c.decode("latin-1") for c in candidates[:3]],
                "secret_redacted": [redact_secret(c) for c in candidates[:3]],
                "has_context_hint": has_context,
                "confidence": "HIGH" if has_context else "MEDIUM",
            })
        else:
            # AKIA alone with no nearby secret = still worth noting
            pairs.append({
                "akia": key.decode("latin-1"),
                "secret_candidates": [],
                "secret_redacted": [],
                "has_context_hint": False,
                "confidence": "LOW (AKIA alone, no paired secret nearby)",
            })

    return pairs


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--ledger", type=str, default=str(DEFAULT_SOURCEMAP_LEDGER),
                   help="Sourcemap-exposure ledger to scan (default: sourcemap-exposure.jsonl)")
    p.add_argument("--limit", type=int, default=292,
                   help="Max entries to scan (default 292 = all)")
    args = p.parse_args()

    in_path = Path(args.ledger)
    if not in_path.exists():
        print(f"[FAIL] ledger not found: {in_path}")
        sys.exit(1)

    print(f"[+] AWS credential pair hunt on {in_path}")
    print(f"[+] Output: {LEDGER}")
    print()

    stats = {"scanned": 0, "fetched": 0, "akia_found": 0,
             "with_secret": 0, "with_context": 0}
    all_findings = []

    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    with open(in_path) as f, open(LEDGER, "a") as out:
        for i, line in enumerate(f):
            if i >= args.limit:
                break
            try:
                entry = json.loads(line)
            except Exception:
                continue

            url = entry.get("url", "") or entry.get("matched-at", "")
            if not url or not url.startswith("http"):
                continue

            stats["scanned"] += 1
            body = fetch_url(url)
            if body is None:
                continue
            stats["fetched"] += 1

            pairs = find_aws_pairs(body)
            if not pairs:
                continue

            for p_ in pairs:
                stats["akia_found"] += 1
                if p_["secret_candidates"]:
                    stats["with_secret"] += 1
                if p_["has_context_hint"]:
                    stats["with_context"] += 1

                print(f"  [{i+1}] {url[:60]}")
                print(f"      AKIA: {p_['akia'][:8]}...{p_['akia'][-4:]}")
                print(f"      confidence: {p_['confidence']}")
                if p_["secret_redacted"]:
                    print(f"      paired secret candidates: {p_['secret_redacted']}")
                    print(f"      → MANUAL VALIDATE: AWS_ACCESS_KEY_ID={p_['akia']} \\")
                    print(f"                         AWS_SECRET_ACCESS_KEY=<SECRET> \\")
                    print(f"                         aws sts get-caller-identity")

                finding = {
                    "source_url": url,
                    "akia_id": p_["akia"],
                    "secret_redacted": p_["secret_redacted"],
                    "confidence": p_["confidence"],
                    "has_context_hint": p_["has_context_hint"],
                    "discovered_at": datetime.now(timezone.utc).isoformat(),
                    "validation_status": "PENDING_MANUAL",
                    "validation_command": f"AWS_ACCESS_KEY_ID={p_['akia']} AWS_SECRET_ACCESS_KEY=<secret> aws sts get-caller-identity",
                }
                out.write(json.dumps(finding) + "\n")
                out.flush()
                all_findings.append(finding)

    print()
    print("=" * 70)
    print("AWS CREDENTIAL HUNT SUMMARY")
    print("=" * 70)
    print(f"  Entries scanned:        {stats['scanned']}")
    print(f"  Fetched:                {stats['fetched']}")
    print(f"  AKIA IDs found:         {stats['akia_found']}")
    print(f"  With paired secret:     {stats['with_secret']}")
    print(f"  With context hint:      {stats['with_context']}")
    print()
    print(f"[+] Ledger: {LEDGER}")
    if all_findings:
        print(f"[+] {len(all_findings)} candidate(s) need MANUAL validation via aws CLI")


if __name__ == "__main__":
    main()
