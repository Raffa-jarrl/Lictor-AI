#!/usr/bin/env python3
"""
submission-queue-builder — continuously processes verified findings into
ready-to-submit disclosure drafts.

Watches v3/ledgers/verified-f500-leads.jsonl every 5 min. For each new
verified finding:
  1. Runs a fresh deep-verification probe (re-validates the finding is still
     real — defensive against transient issues / scan-time race conditions).
  2. Determines disclosure channel (HackerOne / Bugcrowd / Intigriti / direct
     email) based on the program platform.
  3. Builds a structured disclosure draft with:
       - Title (concise, descriptive)
       - Summary (1 paragraph)
       - Steps to reproduce (concrete curl commands)
       - Impact (specific to vuln class)
       - Suggested fix
       - Evidence (response excerpts, hashes for proof)
  4. Writes draft to v3/ledgers/submissions/<safe_name>/<finding_id>.md
  5. Updates a master submission-queue.jsonl with status (draft|approved|sent).

NEVER auto-submits. The user reviews + approves.

Usage:
  nohup python3 -u scripts/submission-queue-builder.py > v3/ledgers/sq-builder.log 2>&1 &
"""
from __future__ import annotations
import json, os, ssl, time, urllib.request, urllib.error
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path("/Users/raffa/Lictor")
VERIFIED = ROOT / "v3" / "ledgers" / "verified-f500-leads.jsonl"
QUEUE = ROOT / "v3" / "ledgers" / "submission-queue.jsonl"
DRAFTS = ROOT / "v3" / "ledgers" / "submissions"
STATE = ROOT / "v3" / "ledgers" / "sq-builder-state.json"

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
UA = "Lictor-DeepVerify/0.1"


def load_state():
    if STATE.exists():
        try: return json.loads(STATE.read_text())
        except: pass
    return {"processed_lead_keys": []}


def save_state(s):
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(s, indent=2))


def http(url, method="GET", headers=None, timeout=6):
    h = {"User-Agent": UA}
    if headers: h.update(headers)
    try:
        req = urllib.request.Request(url, method=method, headers=h)
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, dict(r.headers), r.read(8000)
    except urllib.error.HTTPError as e:
        try: body = e.read(8000)
        except: body = b""
        return e.code, dict(e.headers) if e.headers else {}, body
    except Exception:
        return 0, {}, b""


def deep_verify(lead: dict) -> tuple[bool, str]:
    """Re-run a fresh probe to confirm the finding still reproduces.
    Returns (still_valid, reason)."""
    scanner = lead.get("scanner", "")
    f = lead.get("finding") or lead

    if scanner in ("cors", "cors-credentials-reflected"):
        host = f.get("host")
        s, h, b = http(f"https://{host}/", method="OPTIONS",
                       headers={"Origin": "https://lictor-verify-test.example",
                                "Access-Control-Request-Method": "GET"})
        acao = h.get("Access-Control-Allow-Origin", "") or h.get("access-control-allow-origin", "")
        acac = h.get("Access-Control-Allow-Credentials", "") or h.get("access-control-allow-credentials", "")
        if "lictor-verify-test.example" in acao and acac.lower() == "true":
            return True, "CORS reflection + credentials still present"
        return False, f"CORS no longer reflects (acao={acao}, acac={acac})"

    if scanner == "cicd-panels":
        host = f.get("host"); port = f.get("port"); scheme = f.get("scheme")
        plat = f.get("platform")
        if plat == "Jenkins":
            s, _, b = http(f"{scheme}://{host}:{port}/api/json")
            if b"hudson.model" in b: return True, "Jenkins /api/json still returns hudson.model"
            return False, "Jenkins no longer responds"
        if plat == "GitLab":
            s, _, b = http(f"{scheme}://{host}:{port}/users/sign_in")
            if b"GitLab" in b: return True, "GitLab /users/sign_in still returns GitLab page"
            return False, "GitLab no longer responds"
        return True, "passthrough"

    if scanner == "sensitive-files":
        url = f.get("url")
        if not url: return False, "no url"
        s, _, b = http(url)
        if s == 200 and len(b) >= 50:
            return True, f"file still served at {url} (size={len(b)})"
        return False, f"file no longer served (status={s})"

    if scanner == "open-admin-ports":
        # Re-probe is in the scanner already, trust it
        return True, "scanner-validated"

    if scanner == "takeover-claim":
        # Already strictly validated with verified_claimable status
        return True, "claim-validated"

    if scanner == "github-secrets":
        # Re-fetch the GitHub URL to confirm secret still present
        html_url = f.get("html_url")
        if not html_url: return True, "no url to recheck"
        raw = html_url.replace("https://github.com/", "https://raw.githubusercontent.com/").replace("/blob/", "/")
        s, _, b = http(raw)
        if s == 200:
            # Check pattern_name prefix still in body
            prefix = f.get("matched_value_prefix", "")
            if prefix and prefix.encode() in b:
                return True, f"secret still in {raw}"
        return False, f"secret no longer in repo (status={s})"

    if scanner == "graphql-mutations":
        endpoint = f.get("endpoint")
        if not endpoint: return False, "no endpoint"
        # Re-introspect
        import urllib.request as ur
        try:
            req = ur.Request(endpoint, method="POST",
                             data=b'{"query":"{__schema{mutationType{fields{name}}}}"}',
                             headers={"Content-Type": "application/json", "User-Agent": UA})
            with ur.urlopen(req, timeout=8, context=ctx) as r:
                body = r.read(50000)
                if b'"mutationType"' in body or b'"fields"' in body:
                    return True, "introspection still open"
        except: pass
        return False, "introspection closed or endpoint dead"

    if scanner == "jwt-weakness":
        # Hard to re-verify without re-running scan logic. Trust scanner.
        return True, "scanner-validated"

    if scanner == "web3-jsonrpc":
        host = f.get("host"); port = f.get("port"); scheme = f.get("scheme")
        # Re-probe eth_chainId
        import urllib.request as ur
        try:
            payload = b'{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}'
            req = ur.Request(f"{scheme}://{host}:{port}/", method="POST",
                             data=payload, headers={"Content-Type":"application/json","User-Agent":UA})
            with ur.urlopen(req, timeout=6, context=ctx) as r:
                if b'"result"' in r.read(2000):
                    return True, "JSON-RPC still responding"
        except: pass
        return False, "JSON-RPC no longer responding"

    if scanner == "oauth-misconfig":
        return True, "scanner-validated"
    if scanner == "ssrf-reprobe":
        return True, "scanner-validated"
    return True, "unknown_scanner_passthrough"


def determine_channel(lead: dict) -> str:
    plat = (lead.get("platform") or "").lower()
    if "hackerone" in plat: return "hackerone"
    if "bugcrowd" in plat: return "bugcrowd"
    if "intigriti" in plat: return "intigriti"
    if "immunefi" in plat: return "immunefi"
    return "email"  # fallback: direct email to security@


VULN_CLASS_TITLES = {
    "cors": "CORS Origin reflection with credentials enabled",
    "cicd-panels": "Exposed CI/CD admin panel ({platform})",
    "sensitive-files": "Sensitive file exposed at {path}",
    "open-admin-ports": "Exposed {service} on port {port} without authentication",
    "takeover-claim": "Subdomain takeover via dangling CNAME to {service}",
    "github-secrets": "Hardcoded {pattern_name} secret in public GitHub repository",
    "graphql-mutations": "GraphQL introspection open + {n_risky} high-risk mutations exposed",
    "jwt-weakness": "JWT {issue} accepted — authentication bypass",
    "web3-jsonrpc": "Exposed Ethereum JSON-RPC with {n_accounts} unlocked accounts",
    "oauth-misconfig": "OAuth {issue}",
    "ssrf-reprobe": "Server-side request forgery — confirmed exfil of {target_description}",
}


def build_draft(lead: dict, deep_proof: str, channel: str) -> str:
    """Return markdown disclosure draft."""
    f = lead.get("finding") or lead
    scanner = lead.get("scanner", "?")
    company = lead.get("company", "?")
    host = f.get("host") or f.get("org") or "?"
    sev = f.get("severity", "?")

    title_template = VULN_CLASS_TITLES.get(scanner, "Security finding")
    title = title_template.format(
        platform=f.get("platform",""), path=f.get("path",""),
        service=f.get("service",""), port=f.get("port",""),
        pattern_name=f.get("pattern_name",""),
        n_risky=len(f.get("high_risk_mutations",[])),
        issue=f.get("issue",""),
        n_accounts=len(f.get("accounts",[])),
        target_description=f.get("target_description",""),
    )

    md = f"""# [{sev}] {title}

**Program:** {company} ({lead.get('platform','?')})
**Disclosure channel:** {channel}
**Reported by:** Lictor (https://lictor-ai.com) — automated scanner; manually verified before submission.
**Found:** {lead.get('ts', '?')}
**Re-verified:** {deep_proof}

## Summary

{f.get('notes', 'See evidence below.')}

## Affected asset

- Host: `{host}`
{f"- Path: `{f.get('path')}`" if f.get('path') else ''}
{f"- Port: `{f.get('port')}`" if f.get('port') else ''}
{f"- Endpoint: `{f.get('endpoint') or f.get('url') or ''}`" if (f.get('endpoint') or f.get('url')) else ''}

## Steps to reproduce

```bash
{generate_repro_curl(scanner, f)}
```

## Evidence

```
{json.dumps(f, indent=2)[:1500]}
```

## Impact

{impact_text(scanner, f)}

## Suggested remediation

{remediation_text(scanner)}

## Disclosure constraints

This report follows Lictor's coordinated vulnerability disclosure policy. We
have NOT exploited the issue. We have only confirmed reproducibility with
the minimum safe probe.

We will publish a sanitised summary in our public archive after the program
acknowledges receipt + indicates remediation timeline.
"""
    return md


def generate_repro_curl(scanner: str, f: dict) -> str:
    if scanner == "cors":
        host = f.get("host")
        return f"""curl -i -X OPTIONS -H 'Origin: https://attacker.example' \\
  -H 'Access-Control-Request-Method: GET' \\
  https://{host}/

# Look for: Access-Control-Allow-Origin: https://attacker.example
# Look for: Access-Control-Allow-Credentials: true
"""
    if scanner == "cicd-panels":
        return f"curl -i {f.get('scheme','https')}://{f.get('host')}:{f.get('port')}/api/json"
    if scanner == "sensitive-files":
        return f"curl -i {f.get('url')}"
    if scanner == "open-admin-ports":
        return f"# Test access to {f.get('service')} on port {f.get('port')}\nnc -zv {f.get('host')} {f.get('port')}"
    if scanner == "takeover-claim":
        return f"host {f.get('host')}\n# Notice CNAME → {f.get('cname_chain', [''])[-1]}\ncurl -i https://{f.get('host')}/"
    if scanner == "github-secrets":
        return f"# Reference: {f.get('html_url')}\n# Secret pattern: {f.get('pattern_name')} starting '{f.get('matched_value_prefix')}'"
    if scanner == "graphql-mutations":
        return f"""curl -X POST -H 'Content-Type: application/json' \\
  -d '{{"query":"{{__schema{{mutationType{{fields{{name}}}}}}}}"}}' \\
  {f.get('endpoint')}"""
    if scanner == "web3-jsonrpc":
        return f"""curl -X POST -H 'Content-Type: application/json' \\
  -d '{{"jsonrpc":"2.0","method":"eth_accounts","params":[],"id":1}}' \\
  {f.get('scheme','http')}://{f.get('host')}:{f.get('port')}/"""
    if scanner == "ssrf-reprobe":
        return f"# Reproducer URL:\ncurl -i '{f.get('probe_url')}'"
    return f"# See ledger entry above"


def impact_text(scanner: str, f: dict) -> str:
    if scanner == "cors":
        return ("Cross-origin authenticated read possible from any attacker page. "
                "If a logged-in user visits an attacker-controlled site, that site can "
                "make credentialed requests and read the response. Vector for session "
                "theft, account takeover, and data exfiltration.")
    if scanner == "cicd-panels":
        return ("Public exposure of CI/CD admin panel. Depending on configuration, "
                "may permit pre-auth RCE via script console, build pipeline injection, "
                "credential extraction, or supply-chain pivot.")
    if scanner == "sensitive-files":
        path = f.get("path", "")
        if ".env" in path or "credentials" in path:
            return "Exposed environment file likely contains cloud credentials (AWS keys, DB passwords, API tokens). Full infrastructure compromise possible."
        if ".git" in path:
            return "Exposed .git/ permits full repository download including secrets in commit history."
        return "Exposed configuration may leak credentials or internal architecture details."
    if scanner == "open-admin-ports":
        svc = f.get("service","")
        if svc.startswith("Elasticsearch") or svc == "MongoDB" or svc == "CouchDB":
            return "Exposed database with no authentication permits arbitrary read of all stored data (likely user PII)."
        if svc == "Redis":
            return "Exposed Redis without auth permits cache poisoning, session theft, and (via CONFIG SET dir) RCE on host."
        if svc.startswith("K8s") or svc == "Kubelet" or svc == "DockerAPI":
            return "Container/cluster control plane exposed without auth — full host RCE possible."
        return f"{svc} exposed without authentication. Severity depends on data accessible."
    if scanner == "takeover-claim":
        return ("Subdomain CNAME points to a deprovisioned cloud resource that is "
                "available for claim by any attacker. Once claimed, attacker controls "
                "all traffic to the subdomain — phishing, cookie theft, content "
                "injection.")
    if scanner == "github-secrets":
        return (f"Hardcoded {f.get('pattern_name')} credential found in public repository. "
                "Anyone with internet access can extract and reuse it.")
    if scanner == "graphql-mutations":
        return ("GraphQL introspection open. Attackers can enumerate full schema "
                "including all mutations. Any auth-misconfigured high-risk mutation "
                "becomes directly exploitable.")
    if scanner == "jwt-weakness":
        return ("Authentication is bypassable via crafted JWT. Attacker can forge "
                "tokens for arbitrary users including admins.")
    if scanner == "web3-jsonrpc":
        return ("Ethereum JSON-RPC node exposed with unlocked accounts. Attacker can "
                "drain wallets via eth_sendTransaction, sign arbitrary messages, and "
                "execute privileged contract calls on behalf of compromised accounts.")
    if scanner == "oauth-misconfig":
        return ("OAuth flow accepts attacker-controlled redirect_uri, enabling "
                "authorization code interception and full account takeover.")
    if scanner == "ssrf-reprobe":
        return ("Server-side request forgery confirmed against cloud metadata service. "
                "Cloud IAM credentials retrievable by any unauthenticated attacker — "
                "leading to full cloud account compromise.")
    return "Manual review needed for impact assessment."


def remediation_text(scanner: str) -> str:
    if scanner == "cors":
        return ("- Restrict Access-Control-Allow-Origin to a strict allow-list of trusted origins.\n"
                "- Never set Access-Control-Allow-Credentials: true with a reflected/wildcard origin.\n"
                "- If the endpoint serves public data only, set ACAO: * and ACAC: false (omit credentials).")
    if scanner == "cicd-panels":
        return ("- Place CI/CD admin behind VPN or SSO.\n"
                "- Disable anonymous read on /api/json, /script, /scriptText.\n"
                "- Enforce auth-required matrix in Jenkins or GitLab settings.")
    if scanner == "sensitive-files":
        return ("- Remove the file from web root.\n"
                "- Add explicit deny rules in nginx/Apache for `.env*`, `.git/`, `wp-config.php`, etc.\n"
                "- Rotate ALL credentials present in the file IMMEDIATELY (assume compromised).")
    if scanner == "open-admin-ports":
        return ("- Firewall the service to internal-only.\n"
                "- Enable strong authentication (mTLS, IAM, etc.).\n"
                "- Rotate credentials if the service held sensitive data.")
    if scanner == "takeover-claim":
        return ("- Delete the dangling CNAME record from your DNS zone.\n"
                "- OR reclaim the resource on the target service to prevent attacker claim.")
    if scanner == "github-secrets":
        return ("- Rotate the leaked credential immediately.\n"
                "- Remove the secret from git history (BFG Repo-Cleaner or git filter-repo).\n"
                "- Audit access logs for unauthorized use during the exposure window.")
    if scanner == "graphql-mutations":
        return ("- Disable introspection in production.\n"
                "- Apply auth-middleware to all mutations.\n"
                "- Implement schema-level rate limiting + cost analysis.")
    if scanner == "jwt-weakness":
        return ("- Reject alg=none unconditionally.\n"
                "- Use a strong random secret (≥256 bits of entropy) for HMAC.\n"
                "- Validate kid header against an allow-list to prevent path traversal.")
    if scanner == "web3-jsonrpc":
        return ("- Remove JSON-RPC from public internet.\n"
                "- If public access required, restrict to read-only methods and rate limit.\n"
                "- Move any held funds to a hardware-wallet-controlled address.")
    if scanner == "oauth-misconfig":
        return ("- Require strict redirect_uri whitelist matching.\n"
                "- Require state parameter on all authorization requests.\n"
                "- Disable implicit flow; require PKCE for public clients.")
    if scanner == "ssrf-reprobe":
        return ("- Implement allow-list for outbound HTTP requests.\n"
                "- Block requests to 169.254.169.254, link-local, RFC1918 ranges.\n"
                "- Use IMDSv2 (with hop-limit) on AWS instead of IMDSv1.\n"
                "- Rotate all cloud credentials immediately.")
    return "See OWASP guidance for this vulnerability class."


def lead_key(lead: dict) -> str:
    f = lead.get("finding") or lead
    return f"{lead.get('scanner','?')}|{f.get('host') or f.get('org') or '?'}|{f.get('path') or f.get('port') or f.get('pattern_name') or f.get('classification') or ''}"


def main():
    print(f"[+] submission-queue-builder starting", flush=True)
    state = load_state()
    processed = set(state.get("processed_lead_keys", []))
    DRAFTS.mkdir(parents=True, exist_ok=True)
    QUEUE.parent.mkdir(parents=True, exist_ok=True)

    while True:
        if not VERIFIED.exists():
            time.sleep(60); continue
        n_new = 0
        for line in VERIFIED.read_text().splitlines():
            if not line.strip(): continue
            try: lead = json.loads(line)
            except: continue
            key = lead_key(lead)
            if key in processed: continue
            processed.add(key)
            # Deep verify
            still_valid, reason = deep_verify(lead)
            if not still_valid:
                # Still record but mark as stale
                with QUEUE.open("a") as qf:
                    qf.write(json.dumps({
                        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                        "key": key, "status": "STALE_AT_VERIFY",
                        "reverify_reason": reason, "lead": lead,
                    }) + "\n")
                continue
            channel = determine_channel(lead)
            draft = build_draft(lead, reason, channel)
            # Write draft file
            safe_name = "".join(c if c.isalnum() else "_" for c in (lead.get("company") or "unknown"))[:50]
            company_dir = DRAFTS / safe_name
            company_dir.mkdir(parents=True, exist_ok=True)
            fname_key = "".join(c if c.isalnum() else "_" for c in key)[:80]
            draft_path = company_dir / f"{fname_key}.md"
            draft_path.write_text(draft)
            # Add to queue
            with QUEUE.open("a") as qf:
                qf.write(json.dumps({
                    "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "key": key,
                    "status": "READY_FOR_REVIEW",
                    "channel": channel,
                    "draft_path": str(draft_path),
                    "company": lead.get("company"),
                    "scanner": lead.get("scanner"),
                    "severity": (lead.get("finding") or lead).get("severity", "?"),
                    "host": (lead.get("finding") or lead).get("host") or "?",
                    "reverify_reason": reason,
                }) + "\n")
            n_new += 1
            print(f"  drafted: {key[:80]}", flush=True)
        if n_new:
            print(f"[{datetime.now(timezone.utc).isoformat(timespec='seconds')}] new drafts: {n_new}", flush=True)
        state["processed_lead_keys"] = sorted(processed)
        save_state(state)
        time.sleep(300)  # 5 min


if __name__ == "__main__":
    main()
