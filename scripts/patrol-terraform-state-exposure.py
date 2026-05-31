#!/usr/bin/env python3
"""
patrol-terraform-state-exposure — scanner #75.

Hunts publicly-exposed Terraform state files (`*.tfstate`, `terraform.tfstate.backup`)
on web servers and S3 buckets. State files routinely contain plaintext AWS access
keys, database passwords, API tokens, and full cloud infrastructure topology.

Why $50K+ class:
  - Terraform state often contains AWS/GCP access keys in plaintext
  - Database passwords, third-party API tokens, SSH private keys
  - Full cloud topology disclosure → targeted attack planning
  - Real precedent: every quarter someone gets a 5-figure bounty for tfstate exposure

Strategy (passive, ethical):
  1. For each host, probe common Terraform state paths
  2. Probe predictable S3/GCS/Azure bucket names ('*-tfstate', '*-terraform', etc.)
  3. For each 200 OK with JSON content, validate it's a Terraform state structure
  4. Surface evidence WITHOUT downloading the full state file
  5. NEVER extract or use credentials found

We do NOT download full state files. HEAD-only + small sample to verify shape.

Usage:
  patrol-terraform-state-exposure.py --hosts hosts.txt
"""
from __future__ import annotations
import argparse, json, urllib.request, urllib.error, ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from pathlib import Path

UA = "Lictor-TerraformStatePatrol/0.1 (+https://lictor-ai.com)"

# Common Terraform state paths on web servers
TFSTATE_PATHS = [
    "/terraform.tfstate",
    "/terraform.tfstate.backup",
    "/.terraform/terraform.tfstate",
    "/.terraform/",
    "/state/terraform.tfstate",
    "/states/terraform.tfstate",
    "/infrastructure/terraform.tfstate",
    "/infra/terraform.tfstate",
    "/iac/terraform.tfstate",
    "/iac/state/terraform.tfstate",
    "/deployment/terraform.tfstate",
    "/deploy/terraform.tfstate",
    "/ops/terraform.tfstate",
    "/devops/terraform.tfstate",
    "/cdk.out/",
    "/cdk.out/cdk.json",
    "/.aws/credentials",
    "/.aws/config",
    "/aws-credentials.json",
    "/credentials.json",
]

# S3/GCS bucket name patterns to probe (will check each as <prefix>-<suffix>.s3.amazonaws.com)
TFSTATE_BUCKET_PATTERNS = [
    "tfstate", "terraform", "terraform-state", "tf-state",
    "state", "iac", "infrastructure", "infra",
]

@dataclass
class TfStateFinding:
    host: str
    url: str
    method: str           # "direct" or "s3-bucket"
    status_code: int
    content_type: str
    content_length: int
    is_valid_tfstate: bool = False
    tfstate_evidence: list = field(default_factory=list)
    sensitive_indicators: list = field(default_factory=list)
    severity: str = "INFO"
    notes: str = ""

def http_head_with_partial_get(url: str, max_bytes: int = 5000, timeout: int = 8) -> dict | None:
    """HEAD first; if 200, do a partial GET (Range: bytes=0-N) to inspect body shape."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # First: HEAD
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            head_status = r.status
            head_headers = dict(r.headers)
    except urllib.error.HTTPError as e:
        return {"status": e.code, "body": "", "ct": "", "size": 0, "headers": dict(e.headers) if e.headers else {}}
    except Exception:
        return None
    if head_status != 200:
        return {"status": head_status, "body": "", "ct": head_headers.get("Content-Type", ""), "size": 0, "headers": head_headers}
    # GET with Range header (partial body)
    req2 = urllib.request.Request(url, headers={
        "User-Agent": UA,
        "Range": f"bytes=0-{max_bytes-1}",
    })
    try:
        with urllib.request.urlopen(req2, timeout=timeout, context=ctx) as r:
            body = r.read(max_bytes).decode("utf-8", "replace")
            return {"status": r.status, "body": body,
                    "ct": r.headers.get("Content-Type", ""),
                    "size": int(r.headers.get("Content-Length", 0)),
                    "headers": dict(r.headers)}
    except Exception:
        return None

def is_valid_tfstate(body: str) -> tuple[bool, list]:
    """Return (is_valid, evidence_list). Heuristic check for Terraform state JSON shape."""
    evidence = []
    # Terraform state v4 markers
    markers = [
        ('"version":', "version field"),
        ('"terraform_version":', "terraform_version field"),
        ('"serial":', "serial field"),
        ('"lineage":', "lineage field"),
        ('"resources":', "resources array"),
        ('"outputs":', "outputs"),
    ]
    for m, label in markers:
        if m in body:
            evidence.append(label)
    return len(evidence) >= 2, evidence

def find_sensitive_indicators(body: str) -> list:
    """Look for credential / secret patterns in the body sample."""
    indicators = []
    patterns = [
        ('"access_key"', "AWS access_key field"),
        ('"secret_key"', "AWS secret_key field"),
        ('AKIA', "AWS access key prefix"),
        ('"aws_access_key_id"', "aws_access_key_id field"),
        ('"aws_secret_access_key"', "aws_secret_access_key field"),
        ('"password"', "password field"),
        ('"private_key"', "private_key field"),
        ('"connection_string"', "connection_string"),
        ('"db_password"', "db_password"),
        ('"api_key"', "api_key field"),
        ('"jwt_secret"', "jwt_secret"),
        ('-----BEGIN', "PEM key material"),
    ]
    for p, label in patterns:
        if p in body:
            indicators.append(label)
    return indicators

def check_direct_path(host: str, path: str) -> TfStateFinding | None:
    url = f"https://{host}{path}"
    result = http_head_with_partial_get(url)
    if not result or result["status"] != 200: return None
    body = result["body"]
    is_tfstate, evidence = is_valid_tfstate(body)
    if not is_tfstate: return None  # Not a real tfstate
    sensitive = find_sensitive_indicators(body)
    severity = "CRITICAL" if sensitive else "HIGH"
    notes = ("Terraform state file publicly accessible" +
             (f" — contains: {', '.join(sensitive)}" if sensitive else ""))
    return TfStateFinding(
        host=host, url=url, method="direct",
        status_code=200, content_type=result["ct"], content_length=result["size"],
        is_valid_tfstate=True, tfstate_evidence=evidence,
        sensitive_indicators=sensitive, severity=severity, notes=notes)

def check_s3_bucket(org: str, pattern: str) -> TfStateFinding | None:
    """Check if a bucket like 'companyname-tfstate' is publicly listable + contains tfstate."""
    bucket = f"{org}-{pattern}"
    url = f"https://{bucket}.s3.amazonaws.com/"
    result = http_head_with_partial_get(url)
    if not result or result["status"] != 200: return None
    body = result["body"]
    # S3 bucket listing has <ListBucketResult> XML
    if "<ListBucketResult" not in body and "ListBucketResult" not in body:
        return None
    # Look for .tfstate file listing inside
    if ".tfstate" not in body.lower():
        return None
    return TfStateFinding(
        host=bucket + ".s3.amazonaws.com", url=url, method="s3-bucket",
        status_code=200, content_type=result["ct"], content_length=result["size"],
        is_valid_tfstate=False,
        tfstate_evidence=["S3 bucket lists .tfstate files"],
        severity="HIGH",
        notes=f"Public S3 bucket '{bucket}' lists Terraform state files")

def scan_host(host: str) -> list[TfStateFinding]:
    host = host.strip().lower().replace("https://", "").replace("http://", "").rstrip("/").split("/")[0]
    findings = []
    # Direct path probes
    for path in TFSTATE_PATHS:
        f = check_direct_path(host, path)
        if f: findings.append(f)
    # S3 bucket probes (derived from host prefix)
    apex = host.split(".")[0] if "." in host else host
    for pattern in TFSTATE_BUCKET_PATTERNS:
        f = check_s3_bucket(apex, pattern)
        if f: findings.append(f)
    return findings

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", required=True)
    ap.add_argument("--threads", type=int, default=8)
    ap.add_argument("--max-hosts", type=int, default=1000)
    ap.add_argument("--ledger",
                    default="/Users/raffa/Lictor/v3/ledgers/terraform-state-exposure.jsonl")
    args = ap.parse_args()

    hosts = [h.strip() for h in Path(args.hosts).read_text().splitlines()
             if h.strip() and not h.startswith('#')][:args.max_hosts]
    print(f"[+] Terraform state exposure hunt: {len(hosts)} hosts × {len(TFSTATE_PATHS)} paths + S3 bucket guesses")
    Path(args.ledger).parent.mkdir(parents=True, exist_ok=True)

    n_crit = n_high = 0
    with open(args.ledger, "a") as ledger, \
         ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(scan_host, h): h for h in hosts}
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
                print(f"  [{done}/{len(hosts)}] {tag} {f.host}{f.url.split(f.host,1)[1] if f.host in f.url else ''}  "
                      f"{f.severity} — {f.notes[:80]}")
                if f.severity == "CRITICAL": n_crit += 1
                elif f.severity == "HIGH": n_high += 1
            if done % 100 == 0:
                print(f"  [progress] {done}/{len(hosts)}")
    print(f"\n[+] Done. CRITICAL={n_crit} HIGH={n_high}")
    print(f"[+] 🔴 CRITICAL = tfstate file with credential indicators")

if __name__ == "__main__":
    main()
