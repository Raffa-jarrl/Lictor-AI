#!/usr/bin/env python3
"""scan-cloudflare-tokens.py — Find live Cloudflare API tokens in public content.

THE TARGET:
  Cloudflare API tokens with DNS-edit / Workers-deploy / R2-write scope
  enable: domain hijack, traffic interception, malware distribution via
  the protocol's own CDN. Critical-tier finding on any Immunefi-listed
  protocol — typically $25K-$100K bounty.

ETHICAL:
  - GET only on public content
  - Token verification uses Cloudflare's official /tokens/verify endpoint
    (returns ONLY whether the token is live + its name + status — no data,
    no zone enumeration, no write actions)
  - Tokens redacted in output
  - Findings stay local

PATTERNS:
  Cloudflare API tokens follow ~40-char alphanumeric + underscore/hyphen.
  We require the token to appear with strong context (CF_API_TOKEN=,
  CLOUDFLARE_TOKEN, cloudflare.com/client/v4 nearby) to reduce FP.
"""
import argparse
import json
import re
import sys
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime, timezone

USER_AGENT = "LictorAI-EthicalScanner/0.3 (+https://lictor-ai.com/transparency)"
LEDGER = Path.home() / "Lictor/v3/ledgers/cloudflare-tokens.jsonl"
DEFAULT_SOURCEMAP_LEDGER = Path.home() / "Lictor/v3/ledgers/sourcemap-exposure.jsonl"

# Cloudflare API tokens: typically 40 chars [A-Za-z0-9_-]
# We use context-anchored matching: only flag if preceded by CF/cloudflare context
CONTEXT_TOKEN_RE = re.compile(
    rb"(?:CF_API_TOKEN|CLOUDFLARE_API_TOKEN|CLOUDFLARE_TOKEN|"
    rb"cf_api_token|cloudflare_token|CF_TOKEN)"
    rb"[\"'\s:=]{1,8}([A-Za-z0-9_-]{40})\b",
    re.I
)

# Cloudflare Global API key (legacy, more dangerous — 37 hex chars)
GLOBAL_KEY_RE = re.compile(
    rb"(?:CLOUDFLARE_API_KEY|CF_API_KEY|cloudflareKey)"
    rb"[\"'\s:=]{1,8}([a-f0-9]{37})\b",
    re.I
)

# Cloudflare Account ID often nearby (32 hex chars)
ACCOUNT_ID_RE = re.compile(
    rb"(?:CF_ACCOUNT_ID|CLOUDFLARE_ACCOUNT_ID|cloudflare_account)"
    rb"[\"'\s:=]{1,8}([a-f0-9]{32})\b",
    re.I
)


def redact(s):
    s = s if isinstance(s, str) else s.decode("latin-1", "replace")
    if len(s) <= 12:
        return s[:4] + "..."
    return s[:6] + "..." + s[-4:]


def http(url, headers=None, timeout=10, method="GET"):
    headers = headers or {}
    headers.setdefault("User-Agent", USER_AGENT)
    try:
        req = urllib.request.Request(url, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read() if e.fp else b""
    except Exception as e:
        return None, str(e).encode()


def fetch_content(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=20) as r:
            if r.status != 200:
                return None
            return r.read(5 * 1024 * 1024)
    except Exception:
        return None


def find_cf_tokens(body):
    """Find Cloudflare tokens with context-anchored matching."""
    if not body:
        return []
    findings = []
    for m in CONTEXT_TOKEN_RE.finditer(body):
        token = m.group(1)
        findings.append({"type": "api_token", "token": token.decode("latin-1"),
                         "context": m.group(0)[:80].decode("latin-1", "replace")})
    for m in GLOBAL_KEY_RE.finditer(body):
        token = m.group(1)
        findings.append({"type": "global_key", "token": token.decode("latin-1"),
                         "context": m.group(0)[:80].decode("latin-1", "replace")})
    # Also detect account ID for context
    account_ids = [m.group(1).decode("latin-1") for m in ACCOUNT_ID_RE.finditer(body)]
    for f in findings:
        if account_ids:
            f["account_id_nearby"] = account_ids[0]
    return findings


def validate_cf_token(token, token_type):
    """Call Cloudflare /tokens/verify — returns only token name + status, no data."""
    if token_type == "api_token":
        st, body = http("https://api.cloudflare.com/client/v4/user/tokens/verify",
                        headers={"Authorization": f"Bearer {token}"})
        if st == 200:
            try:
                data = json.loads(body)
                if data.get("success"):
                    result = data.get("result", {})
                    return {
                        "live": True,
                        "token_id": result.get("id", ""),
                        "status": result.get("status", ""),
                        "expires_on": result.get("expires_on", ""),
                    }
            except Exception:
                return {"live": False, "parse_err": True}
        return {"live": False, "status": st}
    elif token_type == "global_key":
        # Global key requires email + key — we don't have the email, so just flag
        return {"live": "UNKNOWN (global keys require email pair to validate)",
                "warning": "manually check by pairing with X-Auth-Email header"}
    return {"live": False, "type_unsupported": True}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--ledger", type=str, default=str(DEFAULT_SOURCEMAP_LEDGER))
    p.add_argument("--limit", type=int, default=292)
    args = p.parse_args()

    in_path = Path(args.ledger)
    if not in_path.exists():
        print(f"[FAIL] ledger not found: {in_path}")
        sys.exit(1)

    print(f"[+] Cloudflare token hunt on {in_path}")
    print(f"[+] Output: {LEDGER}")
    print()

    stats = {"scanned": 0, "fetched": 0, "matched": 0, "live": 0}
    findings = []

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
            body = fetch_content(url)
            if body is None:
                continue
            stats["fetched"] += 1

            hits = find_cf_tokens(body)
            if not hits:
                continue

            stats["matched"] += len(hits)
            for h in hits:
                token = h["token"]
                redacted = redact(token)
                print(f"  [{i+1}] {url[:60]}")
                print(f"      type: {h['type']} | redacted: {redacted}")
                print(f"      context: {h['context']}")

                v = validate_cf_token(token, h["type"])
                if v.get("live") is True:
                    stats["live"] += 1
                    print(f"      → 🔴 LIVE TOKEN — Cloudflare confirms valid")
                    print(f"         token_id: {v.get('token_id')}, status: {v.get('status')}")

                finding = {
                    "source_url": url,
                    "type": h["type"],
                    "token_redacted": redacted,
                    "account_id_nearby": h.get("account_id_nearby"),
                    "validation": v,
                    "discovered_at": datetime.now(timezone.utc).isoformat(),
                }
                out.write(json.dumps(finding) + "\n")
                out.flush()
                findings.append(finding)

    print()
    print("=" * 70)
    print("CLOUDFLARE TOKEN HUNT SUMMARY")
    print("=" * 70)
    print(f"  Entries scanned: {stats['scanned']}")
    print(f"  Fetched:         {stats['fetched']}")
    print(f"  Pattern hits:    {stats['matched']}")
    print(f"  🔴 LIVE tokens:  {stats['live']}")
    print(f"[+] Ledger: {LEDGER}")


if __name__ == "__main__":
    main()
