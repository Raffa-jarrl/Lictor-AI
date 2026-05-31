#!/usr/bin/env python3
"""
patrol-cache-deception — web cache deception scanner.

Classic $5K-20K bug class: CDN caches authenticated-user responses against
attacker-crafted URLs. Mechanism:
  - Auth endpoint /api/profile (returns user's data)
  - CDN caches static assets like /api/profile/lictor-test.js (extension trick)
  - Attacker visits /api/profile/some-victim-id.css after victim
  - CDN serves cached victim data

Algorithm:
  1. Find auth-required endpoints on host (probes /api/profile, /api/users/me,
     /account, /api/account return 401/403 anonymously)
  2. Append cacheable suffix (.css/.js/.png/.jpg/.gif/.ico) to the auth path
  3. Check headers for Cache-Control: public OR proxy cache hit headers
     (X-Cache: HIT, CF-Cache-Status: HIT, Age: > 0)
  4. If cache hit + endpoint is identity-leaking, it's vulnerable

PASSIVE: This is detection only. We never inject malicious cache entries.

Usage:
  patrol-cache-deception.py --hosts hosts.txt --threads 25
"""
from __future__ import annotations
import argparse, json, ssl, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-CacheDeception/0.1 (+https://lictor-ai.com)"
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

AUTH_PATHS = [
    "/api/profile", "/api/users/me", "/api/account", "/api/me",
    "/account", "/profile", "/api/v1/profile", "/api/v1/users/me",
    "/api/v2/users/me", "/me", "/settings", "/api/settings",
]

CACHEABLE_EXTENSIONS = [".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".svg"]

# Attacker-controllable suffix
SUFFIX = "lictor_cd_test"

CACHE_HIT_INDICATORS = [
    ("x-cache", "hit"),
    ("cf-cache-status", "hit"),
    ("x-served-by-cache", "yes"),
    ("x-cache-hits", None),  # any value > 0
    ("cache-control", "public"),
    ("age", None),  # any non-zero value
]


@dataclass
class CacheDeception:
    host: str
    auth_path: str
    cacheable_url: str
    auth_status_baseline: int
    cacheable_status: int
    cache_indicators: dict
    severity: str
    notes: str
    found_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))


def http(url, headers=None, timeout=5):
    h = {"User-Agent": UA}
    if headers: h.update(headers)
    try:
        req = urllib.request.Request(url, headers=h)
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, dict(r.headers), r.read(5000)
    except urllib.error.HTTPError as e:
        try: body = e.read(5000)
        except: body = b""
        return e.code, dict(e.headers) if e.headers else {}, body
    except Exception:
        return 0, {}, b""


def is_cache_hit(headers: dict) -> tuple[bool, dict]:
    """Check headers for cache-hit indicators. Returns (is_hit, evidence_dict)."""
    lower = {k.lower(): v for k, v in headers.items()}
    hits = {}
    for key, want_val in CACHE_HIT_INDICATORS:
        v = lower.get(key, "")
        if not v: continue
        v_lower = v.lower()
        if want_val is None:
            # Just presence is enough (e.g. Age header)
            # For Age, check it's > 0
            if key == "age":
                try:
                    if int(v) > 0:
                        hits[key] = v
                except: pass
            else:
                hits[key] = v
        elif want_val in v_lower:
            hits[key] = v
    return (len(hits) > 0, hits)


def scan_host(host: str) -> list[CacheDeception]:
    findings = []
    # Find an auth-required endpoint
    for auth_path in AUTH_PATHS:
        url_auth = f"https://{host}{auth_path}"
        s_auth, _, _ = http(url_auth, timeout=4)
        if s_auth not in (401, 403):
            continue  # not auth-protected

        # Try cache deception with extension trick
        for ext in CACHEABLE_EXTENSIONS[:5]:  # cap to 5 ext per host
            url_decep = f"https://{host}{auth_path}/{SUFFIX}{ext}"
            s_decep, h_decep, _ = http(url_decep, timeout=4)
            if s_decep != 200:
                continue
            # Check cache headers
            is_hit, evidence = is_cache_hit(h_decep)
            if not is_hit:
                continue
            # Real finding: auth endpoint returns 401, but auth-path/random.css returns 200 cached
            findings.append(CacheDeception(
                host=host, auth_path=auth_path, cacheable_url=url_decep,
                auth_status_baseline=s_auth, cacheable_status=s_decep,
                cache_indicators=evidence,
                severity="HIGH",
                notes=f"Auth endpoint {auth_path} returns {s_auth}, but {auth_path}/X{ext} returns 200 with cache-hit headers. Cache deception possible.",
            ))
            return findings  # one per host
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", required=True)
    ap.add_argument("--max-hosts", type=int, default=3000)
    ap.add_argument("--threads", type=int, default=25)
    ap.add_argument("--ledger", default="/Users/raffa/Lictor/v3/ledgers/cache-deception.jsonl")
    args = ap.parse_args()
    hosts = [l.strip() for l in Path(args.hosts).read_text().splitlines() if l.strip()][:args.max_hosts]
    Path(args.ledger).parent.mkdir(parents=True, exist_ok=True)
    print(f"[+] cache-deception — {len(hosts)} hosts")
    n = 0
    with open(args.ledger, "a") as ledger, \
         ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(scan_host, h): h for h in hosts}
        for i, fut in enumerate(as_completed(futures), 1):
            try: results = fut.result(timeout=60)
            except: results = []
            for f in results:
                ledger.write(json.dumps(asdict(f)) + "\n")
                ledger.flush()
                n += 1
                print(f"  [{i}/{len(hosts)}] 🟠 {f.severity} {f.host} cache-deception via {f.auth_path}")
            if i % 500 == 0:
                print(f"  [{i}/{len(hosts)}] findings={n}")
    print(f"\n[+] Done. findings={n}")


if __name__ == "__main__":
    main()
