#!/usr/bin/env python3
"""
Lictor v3 — SSRF auto-discovery scanner

The pitch: SSRF (Server-Side Request Forgery) bugs pay $1K-$50K on most
bug-bounty programs. The most common shape: an endpoint that takes a
`url=` / `image=` / `fetch=` / `proxy=` parameter and fetches it
server-side, then either returns the content or uses it (e.g. PDF
generator pulling a URL).

To find SSRF without authenticated access, this scanner:

1. For each target subdomain, probe common SSRF-vulnerable paths:
   - /api/proxy?url=X
   - /api/image?url=X
   - /api/fetch?url=X
   - /api/preview?url=X
   - /api/webhook/test?url=X
   - /api/pdf?url=X
   - /api/screenshot?url=X
   - /api/og?url=X (open graph image preview)
   - /thumbnail?url=X
   - /og-image?url=X

2. The SSRF probe URL is `https://lictor-ssrf-probe.dev/check` (a Lictor-controlled
   endpoint that logs requests for verification — to be set up). For initial
   v3-alpha, we use `https://example.com/` as a benign probe target and look
   for HTTP 200 / non-redirect responses indicating server-side fetch happened.

3. If the response indicates the server actually fetched the URL (200 OK + body
   matches example.com content), it's a strong SSRF signal. Owl reviews to
   confirm whether the response is from a server-side fetch (real SSRF) vs a
   client-side redirect (FP).

4. Output to ledgers/ssrf-candidates.jsonl for Owl to review.

This is intentionally CONSERVATIVE — we use a benign external probe target,
NOT an internal RFC1918 address. Demonstrating internal-network SSRF (which
is what makes SSRF Critical) requires authenticated testing, which Lictor
defers to Raffa's manual exploit phase. v3 surfaces the candidate; Raffa
performs the impact PoC.

Usage:
  python3 patrol-ssrf-discovery.py --corpus PATH --max-domains N
  python3 patrol-ssrf-discovery.py google.com  # single target
"""
from __future__ import annotations
import argparse, json, ssl, sys, urllib.parse, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-v3-SSRF/0.1 (+https://lictor-ai.com)"
LEDGER = Path.home() / "Lictor" / "v3" / "ledgers" / "ssrf-candidates.jsonl"

# Benign external probe target — non-sensitive, public, well-known content
SSRF_PROBE_TARGET = "https://example.com/"
SSRF_PROBE_BODY_MARKER = "Example Domain"  # confirms the server actually fetched

# Common SSRF-vulnerable path patterns
SSRF_PATHS = [
    "/api/proxy?url={target}",
    "/api/fetch?url={target}",
    "/api/image?url={target}",
    "/api/preview?url={target}",
    "/api/webhook/test?url={target}",
    "/api/pdf?url={target}",
    "/api/screenshot?url={target}",
    "/api/og?url={target}",
    "/api/og-image?url={target}",
    "/api/thumbnail?url={target}",
    "/api/url-preview?url={target}",
    "/api/link-preview?url={target}",
    "/proxy?url={target}",
    "/fetch?url={target}",
    "/image-proxy?url={target}",
    "/thumbnail?url={target}",
    "/og-image?url={target}",
    "/api/v1/proxy?url={target}",
    "/api/v1/preview?url={target}",
    "/api/v2/og?url={target}",
    "/render?url={target}",
    "/screenshot?url={target}",
    "/pdf?url={target}",
]


def _fetch(url: str, timeout: int = 8) -> dict:
    """Single HTTP fetch, return {status, headers, body_first_2k}."""
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read(2000).decode("utf-8", "replace")
            return {"status": r.status, "headers": {k.lower(): v for k, v in r.headers.items()}, "body": body}
    except urllib.error.HTTPError as e:
        try:
            body = e.read(2000).decode("utf-8", "replace")
        except Exception:
            body = ""
        return {"status": e.code, "headers": {k.lower(): v for k, v in (e.headers.items() if e.headers else [])}, "body": body}
    except Exception as ex:
        return {"status": 0, "headers": {}, "body": "", "error": str(ex)[:200]}


def _is_ssrf_signal(resp: dict) -> tuple[bool, str]:
    """Does the response indicate the server actually fetched example.com?

    Returns (is_signal, reason).

    Strong signals:
    - status 200 + body contains "Example Domain" (the example.com title)
    - status 200 + content-type text/html + body length similar to example.com (~1256 bytes)

    Weak signals:
    - status 302/301 redirect to example.com (client-side redirect, NOT SSRF)
    - status 200 but body doesn't contain example.com markers

    No signal:
    - 404 / 400 / 5xx
    - body is the application's own page (no example.com content)
    """
    status = resp.get("status", 0)
    body = resp.get("body", "")
    headers = resp.get("headers", {})

    if status != 200:
        return False, f"non-200 status ({status})"

    if SSRF_PROBE_BODY_MARKER in body:
        return True, "body contains 'Example Domain' — server-side fetch confirmed"

    # Heuristic: if the response is text/html and small (~1-3 KB), might be a fetched-and-rendered example.com
    ct = headers.get("content-type", "")
    if "text/html" in ct and 500 < len(body) < 3000:
        return True, f"text/html response, {len(body)}B body — possible server-side fetch (needs manual confirm)"

    return False, "200 but no example.com markers in body"


def probe_one_subdomain(host: str, paths: list[str], probe_target: str) -> list[dict]:
    """Probe all SSRF paths against one host. Returns list of finding dicts."""
    findings = []
    encoded_target = urllib.parse.quote(probe_target, safe="")
    for path_template in paths:
        url = f"https://{host}{path_template.format(target=encoded_target)}"
        resp = _fetch(url, timeout=5)
        is_signal, reason = _is_ssrf_signal(resp)
        if is_signal:
            findings.append({
                "host": host,
                "path": path_template.split("?")[0],
                "probed_url": url,
                "probe_target": probe_target,
                "status": resp.get("status"),
                "reason": reason,
                "body_snippet": resp.get("body", "")[:300],
                "discovered_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            })
            print(f"  🟡 SSRF-CANDIDATE  {host}{path_template.split('?')[0]}  →  {reason}", flush=True)
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", nargs="?", help="Single host to probe (e.g. example.com)")
    ap.add_argument("--corpus", help="Path to apex-domain corpus file (one domain per line)")
    ap.add_argument("--max-domains", type=int, default=50, help="Cap on domains from corpus")
    ap.add_argument("--workers", type=int, default=10)
    ap.add_argument("--probe-target", default=SSRF_PROBE_TARGET, help="The URL the SSRF candidate is asked to fetch (default: https://example.com/)")
    args = ap.parse_args()

    if args.target:
        targets = [args.target]
    elif args.corpus:
        p = Path(args.corpus).expanduser()
        if not p.exists():
            sys.exit(f"❌ Corpus file not found: {p}")
        targets = [l.strip() for l in p.read_text().splitlines() if l.strip()][:args.max_domains]
    else:
        ap.print_help()
        sys.exit(1)

    print(f"[+] SSRF discovery — {len(targets)} hosts × {len(SSRF_PATHS)} paths = {len(targets) * len(SSRF_PATHS)} probes", flush=True)
    print(f"[+] Probe target: {args.probe_target}", flush=True)
    print(f"[+] Looking for body marker: '{SSRF_PROBE_BODY_MARKER}'", flush=True)

    all_findings = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(probe_one_subdomain, host, SSRF_PATHS, args.probe_target): host for host in targets}
        for fut in as_completed(futures):
            try:
                hits = fut.result(timeout=300)
                all_findings.extend(hits)
            except Exception as e:
                print(f"  ⚠️  worker error: {e}", flush=True)

    print(f"\n[+] scan complete: {len(all_findings)} SSRF candidates found", flush=True)

    if all_findings:
        LEDGER.parent.mkdir(parents=True, exist_ok=True)
        with LEDGER.open("a") as f:
            for hit in all_findings:
                f.write(json.dumps(hit) + "\n")
        print(f"[+] Wrote {len(all_findings)} entries to {LEDGER}", flush=True)
        print(f"[+] Next: Owl reviews each candidate to confirm real SSRF vs FP", flush=True)
        print(f"[+] For each PASS: Raffa runs internal-network PoC (e.g., http://169.254.169.254/) to elevate severity", flush=True)


if __name__ == "__main__":
    main()
