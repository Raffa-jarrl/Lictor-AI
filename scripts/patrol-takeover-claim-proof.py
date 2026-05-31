#!/usr/bin/env python3
"""
patrol-takeover-claim-proof — subdomain takeover with active claim-ability proof.

Floqast lesson: fingerprint alone ("NoSuchBucket" / "404 Not Found Github Pages")
is INSUFFICIENT for takeover. Bounty programs require demonstration that the
underlying resource is ACTUALLY claimable (the name is free on the target service).

For each F500 subdomain:
  1. Resolve CNAME chain.
  2. If final CNAME matches a known takeover pattern (heroku, s3, github.io,
     azurewebsites, fastly, surge.sh, ngrok, netlify, etc.) AND the actual
     HTTP probe returns a service-specific "this resource doesn't exist"
     fingerprint, attempt the claim-ability check.
  3. Claim-ability check: query the target service's name API or attempt a
     no-op claim request to see if the name is actually free.
     - S3: HEAD https://{bucket}.s3.amazonaws.com/ → 404 NoSuchBucket
     - GitHub Pages: GET https://{user}.github.io/ → 404 + GitHub fingerprint
     - Heroku: GET https://{name}.herokuapp.com/ → herokucdn no app
     - Azure: nslookup {name}.azurewebsites.net → NXDOMAIN
     - Netlify: GET {name}.netlify.app → 404 + Netlify branding
     - Fastly: requires manual check (no public API)

PASSIVE ONLY — we never actually claim. We confirm the name is free, that's all.

Usage:
  patrol-takeover-claim-proof.py --hosts hosts.txt --threads 30
"""
from __future__ import annotations
import argparse, json, re, socket, ssl, subprocess, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-TakeoverClaimProof/0.1 (+https://lictor-ai.com)"
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

# =============================================================================
# 2026-05-27 — Coca-Cola lesson (Lennaert, Bugcrowd):
# "Are you able to actually take over any of these subdomains? Without an actual
#  takeover the issue remains theoretical."
#
# Most 2018-era takeover vendors have fixed self-signup. What remains as
# "dangling CNAME" is mostly account-gated, B2B, or domain-verified. Submitting
# these as takeover findings burns triager goodwill without being exploitable.
#
# Two layers of FP suppression:
#
#  1. TAKEOVER_FP_PATTERNS — CNAME substrings that ALWAYS suppress regardless
#     of fingerprint match. These are vendors where dangling CNAMEs are
#     theoretical (B2B accounts, domain verification, etc.).
#
#  2. KNOWN_EXPLOITABLE_TIER1 — rule names where takeover is STILL ACTUALLY
#     exploitable in 2026. Findings outside this set get demoted to "INFO"
#     severity even if the rule matches, so they don't reach the submission
#     queue downstream.
# =============================================================================

TAKEOVER_FP_PATTERNS = [
    # Magento Cloud on Fastly — account-gated B2B with domain verification.
    # Coca-Cola N/A 2026-05-27.
    "magentocloud.map.fastly.net",
    # AWS / Azure CDN — account-bound, can't re-register the same name.
    "cloudfront.net",
    "azureedge.net",
    "azurefd.net",
    "trafficmanager.net",
    # WPEngine / Shopify Plus / Vercel — domain-verified or account-bound.
    "wpengine.com",
    "wpenginepowered.com",
    "shopifycloud.com",
    "myshopify.com",
    "vercel.app",
    # AWS PaaS — account-bound.
    "elasticbeanstalk.com",
    "amplifyapp.com",
    # GitHub user pages confirmed-exists are filtered later in scan_host via
    # the api.github.com/users/{name} check (don't pattern-suppress here).
]

# Vendors with public self-signup, no domain verification, and actually
# claimable in 2026. Only THESE produce HIGH/CRITICAL severity output.
# Everything else gets demoted to INFO.
KNOWN_EXPLOITABLE_TIER1 = {
    "AWS_S3",         # bucket-name claim still works (cert layer complicates serving but pays for some programs)
    "GitHub_Pages",   # confirmed when api.github.com/users/{name} returns 404
    "Heroku",         # abandoned app names still re-registerable
    "Surge",          # self-signup, no verification
    "Webflow",        # free-tier still self-signup
    "Cargo",          # self-signup, no verification (manual_review for now)
    "Azure_WebApp",   # NXDOMAIN-confirmed cases only
    "Netlify",        # account-claimable when verified marker matches
    # NOT in tier 1 (auto-demoted to INFO):
    #   Fastly — most cases are Magento/CDN tenancy
    #   Tumblr — vendor fixed verification ~2018
}

# (cname_marker, takeover_fingerprint_in_body, claim_service, name_extract_re, claim_check)
TAKEOVER_RULES = [
    # AWS S3
    {
        "name": "AWS_S3",
        "cname_match": re.compile(r"s3[\.-]"),
        "body_fingerprint": [b"NoSuchBucket", b"The specified bucket does not exist"],
        "extract_name": re.compile(r"^([a-z0-9.\-]+)\.s3[.-]"),
        "claim_check_url": lambda name: f"https://{name}.s3.amazonaws.com/",
        "claim_check_marker": b"NoSuchBucket",
        "severity": "CRITICAL",
    },
    # GitHub Pages
    {
        "name": "GitHub_Pages",
        "cname_match": re.compile(r"\.github\.io$"),
        "body_fingerprint": [b"There isn't a GitHub Pages site here", b"404 \xe2\x80\x94 File not found"],
        "extract_name": re.compile(r"^([a-z0-9-]+)\.github\.io$"),
        "claim_check_url": lambda name: f"https://{name}.github.io/",
        "claim_check_marker": b"There isn't a GitHub Pages site here",
        "severity": "HIGH",
    },
    # Heroku
    {
        "name": "Heroku",
        "cname_match": re.compile(r"\.(herokuapp|herokussl)\.com$"),
        "body_fingerprint": [b"No such app", b"herokucdn.com/error-pages/no-such-app.html"],
        "extract_name": re.compile(r"^([a-z0-9-]+)\.herokuapp\.com$"),
        "claim_check_url": lambda name: f"https://{name}.herokuapp.com/",
        "claim_check_marker": b"No such app",
        "severity": "CRITICAL",
    },
    # Azure WebApps
    {
        "name": "Azure_WebApp",
        "cname_match": re.compile(r"\.(azurewebsites|cloudapp)\.net$"),
        "body_fingerprint": [b"404 Web Site not found", b"web app is stopped"],
        "extract_name": re.compile(r"^([a-z0-9-]+)\.azurewebsites\.net$"),
        "claim_check_url": None,  # azure uses DNS-only check
        "claim_check_marker": None,
        "severity": "CRITICAL",
        "dns_only": True,
    },
    # Netlify
    {
        "name": "Netlify",
        "cname_match": re.compile(r"\.netlify\.(app|com)$"),
        "body_fingerprint": [b"Not Found - Request ID", b"Looks like you've followed a broken link"],
        "extract_name": re.compile(r"^([a-z0-9-]+)\.netlify\.(?:app|com)$"),
        "claim_check_url": lambda name: f"https://{name}.netlify.app/",
        "claim_check_marker": b"Not Found",
        "severity": "HIGH",
    },
    # Fastly
    {
        "name": "Fastly",
        "cname_match": re.compile(r"\.(fastly\.net|fastlylb\.net)$"),
        "body_fingerprint": [b"Fastly error: unknown domain", b"Request could not be processed by Fastly"],
        "extract_name": None,  # Fastly takeover requires customer account, can't auto-verify claim-ability
        "claim_check_url": None,
        "claim_check_marker": None,
        "severity": "HIGH",
        "manual_review": True,
    },
    # Surge
    {
        "name": "Surge",
        "cname_match": re.compile(r"\.surge\.sh$"),
        "body_fingerprint": [b"project not found"],
        "extract_name": re.compile(r"^([a-z0-9-]+)\.surge\.sh$"),
        "claim_check_url": lambda name: f"https://{name}.surge.sh/",
        "claim_check_marker": b"project not found",
        "severity": "CRITICAL",
    },
    # Cargo Collective
    {
        "name": "Cargo",
        "cname_match": re.compile(r"\.cargocollective\.com$"),
        "body_fingerprint": [b"404 Not Found"],
        "extract_name": None,
        "claim_check_url": None, "claim_check_marker": None,
        "severity": "HIGH", "manual_review": True,
    },
    # Webflow
    {
        "name": "Webflow",
        "cname_match": re.compile(r"\.webflow\.io$"),
        "body_fingerprint": [b"The page you are looking for doesn't exist"],
        "extract_name": re.compile(r"^([a-z0-9-]+)\.webflow\.io$"),
        "claim_check_url": lambda name: f"https://{name}.webflow.io/",
        "claim_check_marker": b"The page you are looking for doesn't exist",
        "severity": "HIGH",
    },
    # Tumblr
    {
        "name": "Tumblr",
        "cname_match": re.compile(r"\.domains\.tumblr\.com$"),
        "body_fingerprint": [b"There's nothing here"],
        "extract_name": None,
        "claim_check_url": None, "claim_check_marker": None,
        "severity": "HIGH", "manual_review": True,
    },
]

@dataclass
class TakeoverLead:
    host: str
    cname_chain: list
    service: str
    fingerprint_evidence: str
    claim_status: str   # "verified_claimable", "manual_review", "claim_not_verifiable"
    claim_evidence: str
    severity: str
    notes: str
    found_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))


def resolve_cname_chain(host: str, max_depth: int = 6) -> list[str]:
    """Resolve full CNAME chain. Returns list of names (host first, final target last)."""
    chain = [host]
    cur = host
    for _ in range(max_depth):
        try:
            r = subprocess.run(["host", "-t", "CNAME", cur], capture_output=True, text=True, timeout=5)
            line = r.stdout.strip()
            m = re.search(r"is an alias for\s+([a-z0-9.\-]+)\.?", line)
            if not m: break
            next_name = m.group(1).rstrip(".")
            if next_name in chain: break  # loop
            chain.append(next_name)
            cur = next_name
        except Exception:
            break
    return chain


def dns_resolves(host: str) -> bool:
    """Does the host resolve to any A/AAAA?"""
    try:
        socket.getaddrinfo(host, None)
        return True
    except socket.gaierror:
        return False


def http_get(url: str, timeout: int = 5) -> tuple[int, bytes]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read(8000)
    except urllib.error.HTTPError as e:
        try: return e.code, e.read(8000)
        except: return e.code, b""
    except Exception:
        return 0, b""


def _apply_tier_demotion(lead: TakeoverLead, rule_name: str) -> TakeoverLead:
    """Demote severity to INFO if the rule is not in KNOWN_EXPLOITABLE_TIER1.
    This stops Tier-2/3 findings from reaching the submission queue downstream
    while keeping them visible in the ledger for visibility/research."""
    if rule_name not in KNOWN_EXPLOITABLE_TIER1:
        lead.severity = "INFO"
        lead.notes = f"[TIER2-INFO — not auto-submitted] {lead.notes}"
    return lead


def scan_host(host: str) -> TakeoverLead | None:
    chain = resolve_cname_chain(host)
    if len(chain) < 2:
        return None  # no CNAME, not a takeover candidate
    final_cname = chain[-1]
    # FP pattern suppression — vendors where dangling CNAMEs are theoretical
    # (account-gated, B2B, domain-verified). Return None to skip entirely.
    for fp_pattern in TAKEOVER_FP_PATTERNS:
        if fp_pattern in final_cname:
            return None
    # Check against each rule
    for rule in TAKEOVER_RULES:
        if not rule["cname_match"].search(final_cname): continue
        # Fetch the host and look for fingerprint
        status, body = http_get(f"https://{host}/")
        if not body:
            status, body = http_get(f"http://{host}/")
        fingerprint_matched = any(fp in body for fp in rule["body_fingerprint"])
        if not fingerprint_matched: continue
        # Found takeover fingerprint. Now do claim-ability check.
        if rule.get("dns_only"):
            # For Azure: check if NXDOMAIN
            target = chain[-1]
            if not dns_resolves(target):
                return _apply_tier_demotion(TakeoverLead(
                    host=host, cname_chain=chain, service=rule["name"],
                    fingerprint_evidence=body[:200].decode("utf-8", "replace"),
                    claim_status="verified_claimable",
                    claim_evidence=f"DNS NXDOMAIN for {target}",
                    severity=rule["severity"],
                    notes=f"Subdomain takeover: CNAME points to {target} (NXDOMAIN, claimable on {rule['name']})",
                ), rule["name"])
            continue
        if rule.get("manual_review"):
            return _apply_tier_demotion(TakeoverLead(
                host=host, cname_chain=chain, service=rule["name"],
                fingerprint_evidence=body[:200].decode("utf-8", "replace"),
                claim_status="manual_review",
                claim_evidence="Service requires account-level verification",
                severity=rule["severity"],
                notes=f"Probable takeover: {rule['name']} fingerprint matched. Manual claim verification required.",
            ), rule["name"])
        if rule.get("extract_name") and rule.get("claim_check_url"):
            m = rule["extract_name"].search(final_cname)
            if not m: continue
            name = m.group(1)
            check_url = rule["claim_check_url"](name)
            _, check_body = http_get(check_url)
            if rule["claim_check_marker"] in check_body:
                # Additional check for GitHub Pages: verify the user/org is actually FREE
                # If the user/org exists, the username is taken — not claimable.
                if rule["name"] == "GitHub_Pages":
                    user_check_url = f"https://api.github.com/users/{name}"
                    user_status, _ = http_get(user_check_url)
                    if user_status == 200:
                        # User/org exists — they own the name; can't be taken over
                        continue
                    if user_status != 404:
                        # Unknown status — be safe, mark for manual review
                        return _apply_tier_demotion(TakeoverLead(
                            host=host, cname_chain=chain, service=rule["name"],
                            fingerprint_evidence=body[:200].decode("utf-8", "replace"),
                            claim_status="manual_review",
                            claim_evidence=f"GitHub Pages 'no site' marker matched but user-check returned {user_status}",
                            severity=rule["severity"],
                            notes=f"GitHub Pages fingerprint matched but cannot confirm user '{name}' is free",
                        ), rule["name"])
                return _apply_tier_demotion(TakeoverLead(
                    host=host, cname_chain=chain, service=rule["name"],
                    fingerprint_evidence=body[:200].decode("utf-8", "replace"),
                    claim_status="verified_claimable",
                    claim_evidence=f"Direct probe {check_url} returns marker '{rule['claim_check_marker'][:50].decode()}'",
                    severity=rule["severity"],
                    notes=f"VERIFIED takeover: {rule['name']} name '{name}' is free + can be claimed",
                ), rule["name"])
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", required=True)
    ap.add_argument("--max-hosts", type=int, default=10000)
    ap.add_argument("--threads", type=int, default=30)
    ap.add_argument("--ledger", default="/Users/raffa/Lictor/v3/ledgers/takeover-claim-proof.jsonl")
    args = ap.parse_args()
    hosts = [l.strip() for l in Path(args.hosts).read_text().splitlines() if l.strip()][:args.max_hosts]
    Path(args.ledger).parent.mkdir(parents=True, exist_ok=True)
    print(f"[+] takeover-claim-proof — {len(hosts)} hosts")
    n_crit = n_high = n_review = 0
    with open(args.ledger, "a") as ledger, \
         ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(scan_host, h): h for h in hosts}
        for i, fut in enumerate(as_completed(futures), 1):
            try: result = fut.result(timeout=30)
            except: result = None
            if result:
                ledger.write(json.dumps(asdict(result)) + "\n")
                ledger.flush()
                if result.severity == "CRITICAL": n_crit += 1
                elif result.severity == "HIGH": n_high += 1
                if result.claim_status == "manual_review": n_review += 1
                tag = "🔴" if result.severity == "CRITICAL" else "🟠"
                print(f"  [{i}/{len(hosts)}] {tag} {result.severity:8s} {result.host} → {result.service} ({result.claim_status})")
            if i % 500 == 0:
                print(f"  [{i}/{len(hosts)}] crit={n_crit} high={n_high} manual_review={n_review}")
    print(f"\n[+] Done. CRITICAL={n_crit} HIGH={n_high} (manual_review={n_review})")


if __name__ == "__main__":
    main()
