#!/usr/bin/env python3
"""
patrol-cicd-admin-panels — scanner #73.

Hunts publicly-exposed CI/CD admin panels (Jenkins, GitLab, Bamboo, TeamCity,
Drone, Concourse, Argo CD, Tekton). When these are reachable without auth or
with weak auth, the impact is typically pre-auth RCE via script console,
build-pipeline injection, or credential extraction.

Why $50K+ class:
  - Jenkins Script Console (no auth) = full RCE on the Jenkins host
  - GitLab API without auth = repo content + token extraction
  - TeamCity/Bamboo build script injection = code execution
  - Drone CI tokens = supply-chain pivot
  - Real precedent: $25K-$100K per finding on Bugcrowd/HackerOne F500 targets

Strategy (passive, ethical):
  1. For each host, probe common CI/CD ports (8080, 8081, 8090, 50000, 8443)
  2. Fetch known unauthenticated endpoints per platform
  3. Fingerprint by HTTP headers + body markers
  4. For each detected platform, run safe auth-check probes:
     - Jenkins: GET /api/json → 200 = readable; /scriptText → 200 = RCE
     - GitLab: GET /api/v4/version → 200 = version disclosure
     - TeamCity: GET /app/rest/server → 200 = server info
     - Drone: GET /api/user → 200 = user info
  5. NEVER actually execute scripts / submit builds / extract credentials

We do NOT exploit. We confirm fingerprint + reachable-without-auth status only.

Usage:
  patrol-cicd-admin-panels.py --hosts hosts.txt
"""
from __future__ import annotations
import argparse, json, re, urllib.request, urllib.error, ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from pathlib import Path

UA = "Lictor-CICDPanelPatrol/0.1 (+https://lictor-ai.com)"

# Per-platform fingerprints. Format:
#   { platform_name: [(probe_path, body_marker, header_marker), ...] }
PLATFORM_FINGERPRINTS = {
    # FP-Class fix: only platform-NAME-specific markers (or platform-specific headers).
    # Removed loose markers like 'version', 'items', 'login' which match countless other systems.
    "Jenkins": [
        ("/", "Jenkins", "X-Jenkins"),
        ("/login", "Jenkins", "X-Jenkins"),
        # /api/json must contain 'hudson.model' (real Jenkins JSON), not just '_class' which
        # matches every HTML class attribute (Next.js, React, etc.) and is a massive FP source
        ("/api/json", "hudson.model", None),
    ],
    "GitLab": [
        ("/", "GitLab", "X-GitLab"),
        ("/users/sign_in", "GitLab", None),
        ("/api/v4/version", "gitlab", None),
    ],
    "TeamCity": [
        ("/", "TeamCity", None),
        ("/login.html", "TeamCity", None),
        ("/app/rest/server", "teamcity", None),
    ],
    "Bamboo": [
        ("/", "Atlassian Bamboo", None),
        ("/userlogin!default.action", "Bamboo", None),
    ],
    "Drone": [
        ("/", "drone-ci", None),  # tighter than just 'drone'
        ("/api/user", "drone", None),
    ],
    "ArgoCD": [
        ("/", "Argo CD", None),
        ("/api/version", "argo", None),
    ],
    "Concourse": [
        ("/", "Concourse", None),
        ("/api/v1/info", "concourse", None),
    ],
    "Tekton": [
        ("/", "Tekton", None),
        ("/api/v1/namespaces", "tekton.dev", None),  # K8s API group, Tekton-specific
    ],
    "BuildKite": [
        ("/", "Buildkite", None),
    ],
    "GitHubActionsRunner": [
        ("/", "GitHub Actions Runner", None),
    ],
}

# Probe ports
CICD_PORTS = [80, 443, 8080, 8081, 8443, 8090, 50000, 8084, 9000, 7990, 7080, 8085]

# Severity-elevating endpoints — if these return 200, it's a real RCE/disclosure
RCE_PROBES = {
    "Jenkins": [
        ("/script", "Groovy script console"),
        ("/scriptText", "Groovy script execution endpoint"),
        ("/computer", "Slave/agent listing"),
        ("/asynchPeople/", "User enumeration"),
    ],
    "GitLab": [
        ("/api/v4/users", "User listing"),
        ("/api/v4/projects", "Project listing"),
    ],
    "TeamCity": [
        ("/app/rest/users", "User listing"),
        ("/admin/admin.html", "Admin panel"),
    ],
    "ArgoCD": [
        ("/api/v1/applications", "Application listing"),
        ("/api/v1/clusters", "Cluster listing"),
    ],
}

@dataclass
class CICDFinding:
    host: str
    port: int
    scheme: str
    platform: str
    fingerprint_evidence: str
    rce_probes: list = field(default_factory=list)
    severity: str = "INFO"
    notes: str = ""

def http_get(url: str, timeout: int = 8) -> tuple[int, str, dict] | None:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read(50_000).decode("utf-8", "replace")
            return r.status, body, dict(r.headers)
    except urllib.error.HTTPError as e:
        try:
            body = e.read(50_000).decode("utf-8", "replace")
        except Exception:
            body = ""
        return e.code, body, dict(e.headers) if e.headers else {}
    except Exception:
        return None

def port_alive(host: str, port: int, scheme: str, timeout: int = 3) -> bool:
    """Quick check: does this port respond AT ALL? Returns False if dead/timeout."""
    url = f"{scheme}://{host}:{port}/"
    result = http_get(url, timeout=timeout)
    return result is not None and result[0] != 0

# Negative-corpus to suppress fingerprint FPs (e.g. cfp_time Swagger matched 'version')
PLATFORM_ANTIMARKERS = {
    "GitLab": ["swagger", "redoc", "openapi", "<title>Swagger"],
}

def fingerprint_platform(host: str, port: int, scheme: str) -> tuple[str, str] | None:
    """Return (platform_name, evidence) if a known CI/CD platform is detected.
    Fail-fast: if the port doesn't respond at all on root path, skip all probes."""
    if not port_alive(host, port, scheme, timeout=3):
        return None
    for platform, probes in PLATFORM_FINGERPRINTS.items():
        antimarkers = PLATFORM_ANTIMARKERS.get(platform, [])
        for path, body_marker, header_marker in probes:
            url = f"{scheme}://{host}:{port}{path}"
            result = http_get(url, timeout=4)
            if not result: continue
            status, body, headers = result
            if status == 0: continue
            body_lower = body.lower()
            # Skip if body contains a known anti-marker (e.g. Swagger != GitLab)
            if any(am.lower() in body_lower for am in antimarkers):
                continue
            # Body marker check
            body_match = body_marker.lower() in body_lower if body_marker else False
            # Header marker check
            header_match = any(header_marker.lower() in k.lower() for k in headers) if header_marker else False
            if body_match or header_match:
                evidence_parts = []
                if body_match: evidence_parts.append(f"body contains '{body_marker}'")
                if header_match: evidence_parts.append(f"header contains '{header_marker}'")
                return platform, " + ".join(evidence_parts) + f" (HTTP {status})"
    return None

def check_rce_probes(host: str, port: int, scheme: str, platform: str) -> list[dict]:
    """For platforms with known sensitive endpoints, check if they're reachable.
    NEVER execute, never extract — just check the endpoint responds."""
    hits = []
    probes = RCE_PROBES.get(platform, [])
    for path, description in probes:
        url = f"{scheme}://{host}:{port}{path}"
        result = http_get(url, timeout=6)
        if not result: continue
        status, body, _ = result
        if status == 200 and len(body) > 20:
            hits.append({
                "path": path,
                "description": description,
                "status": status,
                "body_size": len(body),
                "body_snippet": body[:150].replace('\n', ' ')
            })
        elif status in (401, 403):
            # Auth required — good (not vulnerable)
            pass
    return hits

def scan_host(host: str, ports: list[int]) -> list[CICDFinding]:
    findings = []
    # Strip protocol if present
    host_clean = host.replace("https://", "").replace("http://", "").rstrip("/").split("/")[0]
    for port in ports:
        for scheme in ("https", "http"):
            # Skip https on plain-http ports + vice versa for efficiency
            if scheme == "https" and port in (8081, 8090, 50000): continue
            if scheme == "http" and port in (443, 8443): continue
            result = fingerprint_platform(host_clean, port, scheme)
            if not result: continue
            platform, evidence = result
            rce_hits = check_rce_probes(host_clean, port, scheme, platform)
            # Severity scoring
            if rce_hits and platform == "Jenkins":
                # Check if Script Console is accessible
                for h in rce_hits:
                    if "/script" in h["path"]:
                        severity = "CRITICAL"
                        notes = "Jenkins Script Console reachable → pre-auth RCE"
                        break
                else:
                    severity = "HIGH"
                    notes = "Jenkins API accessible without auth"
            elif rce_hits:
                severity = "HIGH"
                notes = f"{platform} sensitive endpoints accessible: {', '.join(h['path'] for h in rce_hits)}"
            else:
                severity = "MEDIUM"
                notes = f"{platform} detected but no obvious auth-bypass — manual review"
            findings.append(CICDFinding(
                host=host_clean, port=port, scheme=scheme, platform=platform,
                fingerprint_evidence=evidence, rce_probes=rce_hits,
                severity=severity, notes=notes))
    return findings

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", required=True)
    ap.add_argument("--threads", type=int, default=8)
    ap.add_argument("--max-hosts", type=int, default=1000)
    ap.add_argument("--ports", default=",".join(str(p) for p in CICD_PORTS))
    ap.add_argument("--ledger",
                    default="/Users/raffa/Lictor/v3/ledgers/cicd-admin-panels.jsonl")
    args = ap.parse_args()

    hosts = [h.strip() for h in Path(args.hosts).read_text().splitlines()
             if h.strip() and not h.startswith('#')][:args.max_hosts]
    ports = [int(p) for p in args.ports.split(",")]
    print(f"[+] CI/CD admin panel hunt: {len(hosts)} hosts × {len(ports)} ports each")
    Path(args.ledger).parent.mkdir(parents=True, exist_ok=True)

    n_crit = n_high = n_med = 0
    with open(args.ledger, "a") as ledger, \
         ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(scan_host, h, ports): h for h in hosts}
        done = 0
        for fut in as_completed(futures):
            done += 1
            host = futures[fut]
            try:
                hits = fut.result()
            except Exception as e:
                print(f"  [{done}/{len(hosts)}] {host} EXC: {e}")
                continue
            for f in hits:
                ledger.write(json.dumps(asdict(f)) + "\n")
                ledger.flush()
                tag = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡"}.get(f.severity, "?")
                print(f"  [{done}/{len(hosts)}] {tag} {f.host}:{f.port} ({f.scheme}) → {f.platform}  {f.severity}")
                print(f"      {f.notes[:120]}")
                if f.severity == "CRITICAL": n_crit += 1
                elif f.severity == "HIGH": n_high += 1
                else: n_med += 1
    print(f"\n[+] Done. CRITICAL={n_crit} HIGH={n_high} MEDIUM={n_med}")
    print(f"[+] 🔴 CRITICAL = Jenkins Script Console reachable (pre-auth RCE)")
    print(f"[+] 🟠 HIGH = CI/CD API accessible without auth")

if __name__ == "__main__":
    main()
