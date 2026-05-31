#!/usr/bin/env python3
"""
verify-chaos-takeover-candidates — fast fingerprint-based takeover verifier.

Takes the chaos+dnsx output (4,206 source → target CNAME pairs across
takeover-class cloud providers) and identifies which sources are actually
claimable by matching the response body against documented no-app
fingerprints for each platform.

Strategy:
  - For each (source, target) pair, fetch https://<source>/
  - Match body against known fingerprints per provider
  - Tag claimable candidates with high/medium confidence
  - Skip live, normal apps quickly

Output: JSONL with verified takeover candidates
"""
from __future__ import annotations
import argparse, json, re, urllib.request, urllib.error, ssl, socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from pathlib import Path

UA = "Lictor-ChaosTakeoverVerify/0.1 (+https://lictor-ai.com)"

# Per-provider fingerprints. Each is (body_substring, http_status, confidence).
# Confidence: "HIGH" = unambiguous no-app; "MEDIUM" = needs human verification
FINGERPRINTS = {
    "herokudns.com": [
        ("There's nothing here, yet", 404, "HIGH"),
        ("No such app", 404, "HIGH"),
        ("Application Error", 503, "MEDIUM"),  # could be temporary
        ("herokucdn.com/error-pages/no-such-app", -1, "HIGH"),
    ],
    "herokuapp.com": [
        ("There's nothing here, yet", 404, "HIGH"),
        ("No such app", 404, "HIGH"),
        ("Application Error", 503, "MEDIUM"),
        ("herokucdn.com/error-pages/no-such-app", -1, "HIGH"),
    ],
    "github.io": [
        ("There isn't a GitHub Pages site here.", 404, "HIGH"),
        ("For root URLs (like http://example.com/) you must provide an index.html file", 404, "HIGH"),
    ],
    "netlify.app": [
        ("Not Found - Request ID:", 404, "HIGH"),
        ("Page Not Found - Looks like you've followed a broken link", 404, "MEDIUM"),
    ],
    "vercel.app": [
        ("The deployment could not be found on Vercel", 404, "HIGH"),
        ("DEPLOYMENT_NOT_FOUND", 404, "HIGH"),
    ],
    "azurewebsites.net": [
        ("Web App - Unavailable", 404, "MEDIUM"),
        ("404 Web Site not found", 404, "HIGH"),
        ("The resource you are looking for has been removed", 404, "MEDIUM"),
    ],
    "wpengine.com": [
        ("The site you were looking for couldn't be found", 404, "HIGH"),
    ],
    "elasticbeanstalk.com": [
        ("No application configured at this address", 404, "MEDIUM"),
        ("DNS_PROBE_FINISHED_NXDOMAIN", -1, "HIGH"),
    ],
    "squarespace.com": [
        ("No Such Account", 404, "HIGH"),
        ("This domain isn't yet connected to a website", 404, "HIGH"),
    ],
    "surge.sh": [
        ("project not found", 404, "HIGH"),
    ],
    "unbouncepages.com": [
        ("The requested URL was not found on this server", 404, "MEDIUM"),
    ],
    "fastly.net": [
        ("Fastly error: unknown domain", 500, "MEDIUM"),  # can be FP
    ],
    "cloudapp.net": [
        # Azure cloud services — older platform, rarely claimable now
    ],
    "cloudfront.net": [
        # CloudFront — usually a wrapper, takeover requires distribution removal
    ],
    "s3.amazonaws.com": [
        ("NoSuchBucket", 404, "HIGH"),
        ("The specified bucket does not exist", 404, "HIGH"),
    ],
    "sendgrid.net": [],   # rarely takeover-able directly
}

@dataclass
class TakeoverFinding:
    source: str
    target: str
    provider: str
    status_code: int = 0
    body_snippet: str = ""
    fingerprint_matched: str = ""
    confidence: str = ""    # HIGH / MEDIUM / NONE
    notes: str = ""

def provider_from_target(target: str) -> str:
    for prov in FINGERPRINTS:
        if target.endswith("." + prov) or target.endswith(prov):
            return prov
    return ""

def check_one(source: str, target: str, timeout: int = 8) -> TakeoverFinding | None:
    provider = provider_from_target(target)
    if not provider:
        return None
    finding = TakeoverFinding(source=source, target=target, provider=provider)

    url = f"https://{source}/"
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            finding.status_code = r.status
            body = r.read(50_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        finding.status_code = e.code
        try: body = e.read(50_000).decode("utf-8", "replace")
        except: body = ""
    except (socket.timeout, socket.gaierror) as e:
        finding.notes = f"resolve/timeout: {type(e).__name__}"
        return None
    except Exception as e:
        finding.notes = f"error: {type(e).__name__}: {str(e)[:60]}"
        return None

    # Match against fingerprints for this provider
    for fp_substr, expected_status, conf in FINGERPRINTS.get(provider, []):
        # If status code matters, gate on it (-1 = wildcard)
        if expected_status != -1 and finding.status_code != expected_status:
            continue
        if fp_substr.lower() in body.lower():
            finding.fingerprint_matched = fp_substr
            finding.confidence = conf
            finding.body_snippet = body[:200].replace('\n', ' ')
            return finding

    # No fingerprint matched — likely a live, legit app
    return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--candidates", default="/tmp/lictor-chaos-takeover-candidates.txt",
                    help="Space-separated source→target per line")
    ap.add_argument("--threads", type=int, default=12)
    ap.add_argument("--max", type=int, default=5000)
    ap.add_argument("--ledger",
                    default="/Users/raffa/Lictor/v3/ledgers/chaos-takeover-verified.jsonl")
    args = ap.parse_args()

    pairs = []
    for line in Path(args.candidates).read_text().splitlines():
        parts = line.split()
        if len(parts) >= 2:
            pairs.append((parts[0].lower(), parts[1].lower()))
    pairs = pairs[:args.max]
    print(f"[+] Verifying {len(pairs)} chaos takeover candidates with {args.threads} threads")
    Path(args.ledger).parent.mkdir(parents=True, exist_ok=True)

    n_high = n_med = 0
    n_checked = 0
    with open(args.ledger, "a") as ledger, \
         ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(check_one, s, t): (s, t) for s, t in pairs}
        for fut in as_completed(futures):
            n_checked += 1
            try:
                f = fut.result()
            except Exception:
                continue
            if not f: continue
            ledger.write(json.dumps(asdict(f)) + "\n")
            ledger.flush()
            tag = {"HIGH": "🔴", "MEDIUM": "🟡"}.get(f.confidence, "?")
            print(f"  [{n_checked}/{len(pairs)}] {tag} {f.source}  ({f.provider}, {f.confidence})  → {f.fingerprint_matched[:40]}")
            if f.confidence == "HIGH": n_high += 1
            elif f.confidence == "MEDIUM": n_med += 1
            # Print progress every 200
            if n_checked % 200 == 0:
                print(f"  [progress] {n_checked}/{len(pairs)} checked — {n_high} HIGH + {n_med} MEDIUM so far")
    print(f"\n[+] Done. HIGH={n_high} MEDIUM={n_med} (out of {len(pairs)} checked)")
    print(f"[+] HIGH = unambiguous takeover candidate (high-confidence fingerprint match)")
    print(f"[+] MEDIUM = needs human verification (could be transient error)")

if __name__ == "__main__":
    main()
