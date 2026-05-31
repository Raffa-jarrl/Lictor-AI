#!/usr/bin/env python3
"""
generate-misc-disclosures — produce disclosure MDs for host-header-injection
and defi-rpc-leak findings (the clean, verified ones).

Reads from verified-cleaned.jsonl, groups by host + finding-type, generates one
MD per (host, finding-type) bundle.
"""
from __future__ import annotations
import argparse, json
from collections import defaultdict
from pathlib import Path
from datetime import datetime, timezone

PROGRAMS = {
    "myharmony.com":      ("Direct",     "security@logitech.com",    "Logitech Harmony — pay range $500-$5K via Logitech disclosure"),
    "alternativa.film":   ("Direct",     "security@alternativa.film","direct disclosure (no public bounty)"),
    "visainfinite.ca":    ("HackerOne",  "https://hackerone.com/visa","Visa — pay range $500-$15K"),
    "etherscan.io":       ("Direct",     "security@etherscan.io",    "Etherscan — Web3 infra, $500-$5K typical"),
    "app.ribbon.finance": ("Immunefi",   "https://immunefi.com/bug-bounty/ribbon-finance","Ribbon Finance — DeFi protocol, $500-$10K typical for info-disclosure"),
}

def md_host_header(host: str, findings: list[dict]) -> str:
    program, channel, payout = PROGRAMS.get(host, ("Direct", f"security@{host}", "$500-$5K typical"))
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    md = []
    md.append(f"# Host-header injection on {host} — password-reset hijack risk\n")
    md.append(f"**Submit to:** {program} — {channel}")
    md.append(f"**Estimated bounty tier:** {payout}")
    md.append(f"**Disclosed under:** Lictor CVD policy (https://lictor-ai.com/transparency) — standard 60-day window")
    md.append(f"**Generated:** {today}\n")
    md.append("---\n")

    md.append("## TITLE\n```")
    md.append(f"Host-header injection on {host} — X-Forwarded-Host reflected in {'Set-Cookie' if 'header' in (findings[0].get('verification_notes','') or '') else 'response body'} on auth/reset endpoints")
    md.append("```\n")

    md.append("## SEVERITY\n")
    sev = "HIGH" if any(f.get("confidence") == "HIGH" for f in findings) else "MEDIUM"
    md.append(f"**{sev}** — Host-header reflection on password-reset endpoints is the classic vector for "
              "password-reset poisoning: attacker triggers a reset for a victim's email, but the email "
              f"contains a reset URL pointing to attacker-controlled host. Victim clicks → attacker captures the token.\n")

    md.append("## SUMMARY\n")
    md.append(f"A Lictor `patrol-host-header-injection` scan identified that `{host}` reflects "
              "attacker-controlled `X-Forwarded-Host` (and related headers) into the response — "
              "either in the body or in cookies — on the following authentication-related endpoints:\n")
    for f in findings:
        orig = f.get("original", {}) or {}
        md.append(f"- `{orig.get('path','')}` — reflected via `{orig.get('injection_method','x_forwarded_host')}`, "
                  f"found in {f.get('verification_notes','').replace('reflected in ', '')}")
    md.append("")

    md.append("## STEPS TO REPRODUCE\n")
    md.append("For each endpoint above, the verification is:\n")
    md.append("```bash")
    md.append(f'curl -i -H "X-Forwarded-Host: attacker.example.com" \\')
    md.append(f"     'https://{host}{findings[0].get('original',{}).get('path','/')}'")
    md.append("```")
    md.append("Look for `attacker.example.com` in the response body or any response headers "
              "(Location, Set-Cookie, etc.). Where reflected = injection candidate.\n")

    md.append("## IMPACT\n")
    md.append("1. **Password-reset poisoning** — if your password-reset email generation uses Host or "
              "X-Forwarded-Host to construct the reset URL, an attacker can send victims a poisoned "
              "reset email pointing to attacker-controlled domain. Victim clicks → attacker captures token.")
    md.append("2. **Session fixation / cache poisoning** — if Set-Cookie reflects the injected host, "
              "browsers may scope cookies to attacker.example.com, enabling session hijacking.")
    md.append("3. **Phishing leverage** — emails from your domain pointing to attacker-controlled URLs "
              "have very high click-through rates because they appear legitimately from your service.\n")

    md.append("## SUGGESTED REMEDIATION\n")
    md.append("1. **Disable Host-header-based URL generation in emails** — use a hard-coded `APP_BASE_URL` "
              "config value, not the incoming request's Host header.")
    md.append("2. **Reject untrusted X-Forwarded-Host** at the reverse-proxy / load-balancer layer — only "
              "your own infrastructure should set this header.")
    md.append("3. **Validate Host against an allowlist** of canonical domains before using it in any "
              "response generation (email links, Set-Cookie domain, etc.).\n")

    md.append("## WHAT I DID NOT DO (audit trail)\n")
    md.append("- Did NOT trigger any actual password reset for any account")
    md.append("- Did NOT enumerate users or accounts on the system")
    md.append("- Did NOT attempt to capture any tokens or session material")
    md.append(f"- Did NOT send phishing emails or test the chain against real users")
    md.append("- Reproduction stopped at confirming the Host-header reflection. The chain-to-ATO step "
              "is a known consequence that your team can evaluate.")
    md.append(f"- Disclosure governed by Lictor CVD policy at https://lictor-ai.com/transparency\n")

    md.append("## REPORTER\n")
    md.append("Raffa — founder, Lictor (open-source ethical security scanner)")
    md.append("- Email: raffajarrl@gmail.com")
    md.append("- Site: https://lictor-ai.com")
    md.append("- Open source: https://github.com/Raffa-jarrl/Lictor-AI")
    return "\n".join(md)

def md_defi_rpc(host: str, findings: list[dict]) -> str:
    program, channel, payout = PROGRAMS.get(host, ("Direct", f"security@{host.replace('app.','')}", "$500-$5K typical"))
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    md = []
    md.append(f"# DeFi RPC API-key leak on {host}\n")
    md.append(f"**Submit to:** {program} — {channel}")
    md.append(f"**Estimated bounty tier:** {payout}")
    md.append(f"**Disclosed under:** Lictor CVD policy (https://lictor-ai.com/transparency) — standard 60-day window")
    md.append(f"**Generated:** {today}\n")
    md.append("---\n")

    md.append("## TITLE\n```")
    providers = sorted(set((f.get("original",{}) or {}).get("provider","") for f in findings))
    md.append(f"{', '.join(providers)} API key(s) hardcoded in client-side JavaScript on {host}")
    md.append("```\n")

    md.append("## SEVERITY\n")
    md.append("**MEDIUM** — Hardcoded RPC provider keys in client-side JS are extractable by any user "
              "with browser developer tools. The keys grant the holder paid-tier RPC access on the affected "
              "provider account — leading to unauthorized usage that costs the project money, plus "
              "denial-of-service if the rate limit is exhausted.\n")

    md.append("## SUMMARY\n")
    md.append(f"A Lictor `patrol-defi-rpc-leak` scan identified that the production front-end of `{host}` "
              "contains hardcoded RPC provider API keys embedded in its compiled JavaScript bundles. "
              "Verification: keys were re-fetched at verification time and confirmed still present.\n")
    md.append("Specific findings:")
    for f in findings:
        orig = f.get("original", {}) or {}
        md.append(f"- **{orig.get('provider','')}** key `{orig.get('key_redacted','')}` "
                  f"in `{orig.get('js_source_url','')[:120]}`")
    md.append("")

    md.append("## STEPS TO REPRODUCE\n")
    md.append("1. Open browser devtools on `https://" + host + "/`")
    md.append("2. Inspect Network → JS bundles (the `js_source_url` listed above)")
    md.append("3. Search the bundle for the provider's URL pattern, e.g.:")
    md.append("   - Alchemy: `eth-mainnet.g.alchemy.com/v2/<KEY>`")
    md.append("   - Infura: `mainnet.infura.io/v3/<KEY>`")
    md.append("4. The full key value will be visible in the source.\n")

    md.append("## IMPACT\n")
    md.append("1. **Cost-shifting attack** — attacker uses your paid RPC tier for their own queries; "
              "you receive the bill. For archive-node tier providers, this is real $.")
    md.append("2. **Rate-limit exhaustion** — attacker can DoS your application by saturating the "
              "RPC quota, causing transactions to fail for real users.")
    md.append("3. **Inference of monitored addresses** — query patterns reveal which wallets / contracts "
              "your protocol monitors. Useful intel for sophisticated attackers.")
    md.append("4. **If higher-tier features** (websocket, debug_traceTransaction, eth_subscribe, etc.) "
              "are unlocked on the leaked key, attacker can perform expensive ops you didn't authorize.\n")

    md.append("## SUGGESTED REMEDIATION\n")
    md.append("1. **Immediate**: rotate the leaked key with the RPC provider's dashboard.")
    md.append("2. **Architecture**: move the RPC key to your backend. Have the client proxy through "
              "your own API rather than calling the third-party RPC directly. This adds rate-limiting "
              "and protects the key from public exposure.")
    md.append("3. **Alternative**: use a public RPC tier with no key (free, no abuse vector), or "
              "use a JWT-based authentication scheme with short-lived signed tokens issued by your backend.\n")

    md.append("## WHAT I DID NOT DO (audit trail)\n")
    md.append("- Did NOT use the leaked key to make any RPC calls")
    md.append("- Did NOT enumerate the rate limit or quota usage")
    md.append("- Did NOT attempt to access any higher-tier features the key may have unlocked")
    md.append("- Did NOT share the key with any third party")
    md.append("- Reproduction stopped at confirming the key is present in the JS bundle")
    md.append(f"- Disclosure governed by Lictor CVD policy at https://lictor-ai.com/transparency\n")

    md.append("## REPORTER\n")
    md.append("Raffa — founder, Lictor (open-source ethical security scanner)")
    md.append("- Email: raffajarrl@gmail.com")
    md.append("- Site: https://lictor-ai.com")
    md.append("- Open source: https://github.com/Raffa-jarrl/Lictor-AI")
    return "\n".join(md)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--verified", default="/Users/raffa/Lictor/v3/ledgers/verified-cleaned.jsonl")
    ap.add_argument("--out-base", default="/Users/raffa/Lictor/disclosures")
    args = ap.parse_args()

    with open(args.verified) as f:
        findings = [json.loads(line) for line in f if line.strip()]

    by_host_hh: dict[str, list[dict]] = defaultdict(list)
    by_host_rpc: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        ft = f.get("finding_type", "")
        h = f.get("host", "")
        if ft == "host_header_injection":
            by_host_hh[h].append(f)
        elif ft == "defi_rpc_leak":
            by_host_rpc[h].append(f)

    out_hh = Path(args.out_base, "2026-05-24-host-header")
    out_rpc = Path(args.out_base, "2026-05-24-defi-rpc-leak")
    out_hh.mkdir(parents=True, exist_ok=True)
    out_rpc.mkdir(parents=True, exist_ok=True)

    print(f"[+] Host-header-injection: {len(by_host_hh)} unique hosts")
    for host, fs in by_host_hh.items():
        md = md_host_header(host, fs)
        out_file = out_hh / f"{host}-host-header.md"
        out_file.write_text(md)
        print(f"  ✓ {host}: {len(fs)} findings → {out_file.name}")

    print(f"\n[+] DeFi-RPC-leak: {len(by_host_rpc)} unique hosts")
    for host, fs in by_host_rpc.items():
        md = md_defi_rpc(host, fs)
        out_file = out_rpc / f"{host}-defi-rpc.md"
        out_file.write_text(md)
        print(f"  ✓ {host}: {len(fs)} findings → {out_file.name}")

if __name__ == "__main__":
    main()
