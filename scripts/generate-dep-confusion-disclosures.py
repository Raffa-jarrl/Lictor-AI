#!/usr/bin/env python3
"""
generate-dep-confusion-disclosures — produce HackerOne/Bugcrowd-ready MD files
for the verified dep-confusion findings.

Groups findings by org → ONE markdown per org bundling all that org's
dep-confusion candidates.

Each MD includes:
  - Title formatted for the program's submission form
  - Severity, asset, summary
  - Steps to reproduce (per package)
  - Impact analysis
  - Suggested remediation
  - "What I did NOT do" audit trail
  - Reporter block

Usage:
  generate-dep-confusion-disclosures.py --verified verified-cleaned.jsonl
                                          --out-dir disclosures/2026-05-24-dep-confusion/
"""
from __future__ import annotations
import argparse, json, re
from collections import defaultdict
from pathlib import Path
from datetime import datetime, timezone

# Org → bug bounty program info
PROGRAM_LOOKUP = {
    "github":        ("HackerOne",  "https://hackerone.com/github",     "$500-$30K (Bug Bounty tier)"),
    "spotify":       ("HackerOne",  "https://hackerone.com/spotify",    "$500-$25K"),
    "reddit":        ("HackerOne",  "https://hackerone.com/reddit",     "$500-$15K"),
    "atlassian":     ("Bugcrowd",   "https://bugcrowd.com/atlassian",   "$500-$15K"),
    "cloudflare":    ("HackerOne",  "https://hackerone.com/cloudflare", "$500-$20K"),
    "docker":        ("Direct",     "security@docker.com",              "discretionary"),
    "salesforce":    ("HackerOne",  "https://hackerone.com/salesforce", "$500-$20K"),
    "coinbase":      ("HackerOne",  "https://hackerone.com/coinbase",   "$500-$50K"),
    "hashicorp":     ("HackerOne",  "https://hackerone.com/hashicorp",  "$500-$10K"),
    "linkedin":      ("HackerOne",  "https://hackerone.com/linkedin",   "$500-$15K"),
    "okta":          ("Bugcrowd",   "https://bugcrowd.com/okta",        "$500-$15K"),
    "plaid":         ("Direct",     "security@plaid.com",               "discretionary"),
}

# Skip findings with these package-name prefixes — they're monorepo-internal,
# not real npm dep-confusion candidates (resolved via workspaces, not npm)
SKIP_PACKAGE_PREFIXES = ("@repo/", "@apps/", "@workspace/", "@local/")

def md_for_org(org: str, findings: list[dict]) -> str | None:
    program, url, payout = PROGRAM_LOOKUP.get(org, ("Unknown", "security@" + org + ".com", "TBD"))
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # Filter findings: skip @repo/* etc.
    real = [f for f in findings if not any(
        (f.get("original", {}) or {}).get("package_name", "").startswith(p)
        for p in SKIP_PACKAGE_PREFIXES
    )]
    if not real:
        return None

    md = []
    md.append(f"# Dep-confusion bulk disclosure — {org} ({len(real)} packages)\n")
    md.append(f"**Submit to:** {program} — {url}")
    md.append(f"**Estimated bounty tier:** {payout}")
    md.append(f"**Disclosed under:** Lictor CVD policy (https://lictor-ai.com/transparency) — standard 60-day window")
    md.append(f"**Generated:** {today}\n")
    md.append("---\n")

    md.append("## TITLE (for submission form)\n")
    md.append("```")
    md.append(f"Dependency confusion — {len(real)} unclaimed internal-scope npm packages referenced in public {org} repos")
    md.append("```\n")

    md.append("## SEVERITY\n")
    md.append("**HIGH** — Each unclaimed package, when registered by an attacker, gets pulled at "
              "`npm install` time on any system following the manifest. Reference: PayPal-CVE-2021 ($30K), Uber-2021 ($9K).\n")

    md.append("## ASSET / IN-SCOPE\n")
    md.append(f"`*.{org}` GitHub organization repositories that reference unpublished `@{org}/*` "
              f"and `@{org}-internal/*` scope packages in their published manifests.\n")

    md.append("## SUMMARY\n")
    md.append(f"A Lictor `patrol-dependency-confusion` scan on `{today}` identified {len(real)} npm packages "
              f"referenced in public {org} GitHub repositories whose package names are **NOT registered** "
              f"on the public npm registry as of verification time.\n")
    md.append("If an attacker registers these names on public npm with a higher version number, then any "
              "system that runs `npm install` against an affected manifest (without proper npm scope-mapping "
              f"to a private registry) will resolve to the attacker-controlled package — granting "
              f"arbitrary code execution on the build/test/CI system.\n")
    md.append("This is the PayPal-2021 / Uber-2021 / Microsoft-2021 dependency-confusion pattern, well-"
              "documented at https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610.\n")

    md.append("## STEPS TO REPRODUCE\n")
    md.append("For each package below, the verification:\n")
    md.append("```bash")
    md.append("# Confirm the package is referenced in the public repo")
    md.append("gh api repos/{repo}/contents/{path} | jq -r .content | base64 -d | grep '{pkg}'")
    md.append("")
    md.append("# Confirm the package is NOT registered on public npm (returns 404)")
    md.append("curl -s -o /dev/null -w '%{http_code}\\n' https://registry.npmjs.org/{pkg}")
    md.append("# → 404 = unclaimed, squat-able")
    md.append("```\n")

    md.append(f"## THE {len(real)} UNCLAIMED PACKAGES\n")
    md.append("| # | Package | Public manifest | Verified-unclaimed |")
    md.append("|---|---------|-----------------|--------------------|")
    for i, f in enumerate(real, 1):
        orig = f.get("original", {}) or {}
        pkg = orig.get("package_name", "")
        repo = orig.get("repo", "")
        path = orig.get("manifest_path", "")
        url_l = orig.get("manifest_url", "")
        manifest_link = f"[`{repo}/{path}`]({url_l})" if url_l else f"`{repo}/{path}`"
        md.append(f"| {i} | `{pkg}` | {manifest_link} | ✓ (registry returned 404 at re-verification time) |")
    md.append("")

    md.append("## IMPACT\n")
    md.append("Per-package, the consequence of an attacker registering a malicious squat:\n")
    md.append("1. **Build-time RCE on any CI runner** that installs the affected manifest. This includes "
              f"all of {org}'s public CI workflows (GitHub Actions, CircleCI, etc.) plus any downstream "
              "fork that hasn't pinned its npm scope to an internal registry.")
    md.append("2. **Build-time RCE on developer machines** when developers clone the repo and run `npm install`.")
    md.append("3. **Supply-chain pivot** — once the attacker controls the package, all future installs across "
              "every consumer pull the malicious payload. Equivalent to source-code commit access in practical impact.")
    md.append("")

    md.append("## SUGGESTED REMEDIATION\n")
    md.append("**Immediate** (per package — fastest fix):")
    md.append("1. For each package above: register the name on public npm as a placeholder owned by your org, "
              f"with a high version (`99.99.99`) that prints `console.error('Defensive placeholder by {org}')` on require.")
    md.append("2. Add the namespace to your private-registry scope-mapping in `.npmrc` so internal builds "
              "resolve via your internal registry, not public npm.\n")
    md.append("**Long-term:**")
    md.append("- Audit all repos under `github.com/{org}/*` for similar unclaimed-name references")
    md.append("- Enforce `--registry=` flag in CI to pin npm resolution")
    md.append("- Consider the `npm scope-registry` policy at organization level\n")

    md.append("## WHAT I DID NOT DO (audit trail)\n")
    md.append("- Did NOT register any of the squat candidate package names — would constitute malicious action")
    md.append("- Did NOT publish any payload — Lictor's role is detection + responsible disclosure only")
    md.append("- Did NOT clone the affected repos to a private location")
    md.append("- Did NOT inspect contributor/maintainer information beyond the public manifest")
    md.append(f"- Disclosure governed by Lictor CVD policy at https://lictor-ai.com/transparency")
    md.append("- Standard 60-day window before any public discussion\n")

    md.append("## REPORTER\n")
    md.append("Raffa — founder, Lictor (open-source ethical security scanner)")
    md.append("- Email: raffajarrl@gmail.com")
    md.append("- Site: https://lictor-ai.com")
    md.append("- Open source: https://github.com/Raffa-jarrl/Lictor-AI")

    return "\n".join(md)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--verified", default="/Users/raffa/Lictor/v3/ledgers/verified-cleaned.jsonl")
    ap.add_argument("--out-dir",
                     default="/Users/raffa/Lictor/disclosures/2026-05-24-dep-confusion")
    args = ap.parse_args()

    findings = []
    with open(args.verified) as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                j = json.loads(line)
                if j.get("finding_type") == "dep_confusion" and j.get("classification") == "confirmed":
                    findings.append(j)
            except: pass
    print(f"[+] {len(findings)} confirmed dep-confusion findings to group")

    by_org: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        orig = f.get("original", {}) or {}
        org = (orig.get("org") or orig.get("repo", "").split("/")[0]).lower()
        if not org: continue
        # Dedupe by (org, package_name) — sometimes same finding appears twice
        by_org[org].append(f)
    # Dedupe within each org
    for org in by_org:
        seen = set()
        out = []
        for f in by_org[org]:
            pkg = (f.get("original", {}) or {}).get("package_name", "")
            if pkg in seen: continue
            seen.add(pkg)
            out.append(f)
        by_org[org] = out

    Path(args.out_dir).mkdir(parents=True, exist_ok=True)

    n_files = 0
    n_skipped = 0
    for org, fs in sorted(by_org.items()):
        md = md_for_org(org, fs)
        if md is None:
            print(f"  - {org}: SKIPPED ({len(fs)} findings, all monorepo-internal)")
            n_skipped += 1
            continue
        out_file = Path(args.out_dir) / f"{org}-dep-confusion.md"
        out_file.write_text(md)
        print(f"  ✓ {org}: {len(fs)} findings → {out_file.name}")
        n_files += 1

    print(f"\n[+] {n_files} disclosure MD files written → {args.out_dir}")
    print(f"[+] {n_skipped} orgs skipped (all monorepo-internal pattern)")

    # Build an INDEX file
    index_lines = [
        f"# Dep-confusion disclosure index — generated {datetime.now(timezone.utc).strftime('%Y-%m-%d')}\n",
        f"## Submissions ready to file\n",
    ]
    for org in sorted(by_org.keys()):
        if md_for_org(org, by_org[org]) is None: continue
        program, url, payout = PROGRAM_LOOKUP.get(org, ("Unknown", "?", "?"))
        n = len([f for f in by_org[org] if not any(
            (f.get("original", {}) or {}).get("package_name", "").startswith(p)
            for p in SKIP_PACKAGE_PREFIXES)])
        index_lines.append(f"- **{org}** ({n} packages) — `{org}-dep-confusion.md` → {program} ({url}) — est. {payout}")
    Path(args.out_dir, "INDEX.md").write_text("\n".join(index_lines))
    print(f"[+] INDEX written → {args.out_dir}/INDEX.md")

if __name__ == "__main__":
    main()
