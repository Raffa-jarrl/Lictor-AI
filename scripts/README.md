# Lictor multi-surface scanner — coverage status

These Python scripts ship Patrol v0.2 — working scans for every surface
documented on lictorai.com/patterns. They will be ported to Rust in
lictor-core for Patrol v0.3 (the Cloudflare Worker behind /scan).

## Scripts

| Script | What it does |
|---|---|
| `lictor-multi.py <path>` | Auto-detect project type + run every applicable check |
| `patrol-pilot.py` | URL-based surface scan (web, headers, exposed-file probes, bundle JWT decode) |
| `patrol-supabase-service-role.py` | GitHub Code Search for hardcoded service-role JWTs |
| `patrol-pilot.py --mode mature` | GitHub-cohort scan of mature custom-domain apps |
| `patrol-pilot.py --mode showcase` | Showcase-page scraping (deferred — needs Chrome MCP) |
| `wait-for-dns.sh` | DNS watcher for new domain registrations |

## Surface coverage — what's actually scanned today

| Surface | /patterns categories | Status |
|---|---|---|
| **Web** (HTTP-fetchable) | 10 patterns | ✅ via `patrol-pilot.py` (headers, exposed files, JWT decode in bundles, API endpoint probes) |
| **Web** (source-code) | 10 patterns | ✅ via `core/` Rust crate (7 checks: secrets, RLS hints, auth, cors, ai-agent, webhooks, hallucinated_packages) |
| **MCP servers** | 5 patterns | ✅ via `lictor-multi.py --only mcp` (tool-desc dynamic content, exec-tool sandbox-less, raw-network-to-LLM) |
| **CI/CD pipelines** | 4 patterns | ✅ via `lictor-multi.py --only ci-cd` (pull_request_target+checkout-PR, tag-pinned actions, echo-secret, default-token-perms) |
| **Browser extensions** | 4 patterns | ✅ via `lictor-multi.py --only browser-ext` (all_urls, unsafe-eval, WAR scope, dangerous permissions) |
| **CLI scripts** | 4 patterns | ✅ via `lictor-multi.py --only cli-scripts` (shell=True, os.system, secrets in argv, eval, bash unquoted) |
| **Desktop apps (Electron/Tauri)** | 3 patterns | ✅ via `lictor-multi.py --only desktop` (nodeIntegration, contextIsolation, tauri allowlist) |
| **Mobile (iOS/Android)** | 8 patterns | 🚧 v0.3 — needs `.ipa`/`.apk` static analysis |
| **AI features inside apps** | 5 patterns | 🚧 v0.3 — needs runtime-trace + LLM-call interception (Sentinel does some of this) |
| **APIs & serverless** | 4 patterns | 🚧 v0.3 — overlap with web checks; IAM/billing alarms need cloud API access |
| **Cross-cutting** | 4 patterns | ⚪ Partial — OAuth scopes / log retention need manual review or platform integration |

## How to run

Single project, all surfaces:
```bash
python3 scripts/lictor-multi.py /path/to/your/project
```

Single surface (e.g. just MCP):
```bash
python3 scripts/lictor-multi.py /path/to/your/mcp-server --only mcp
```

JSON output (for piping into other tools):
```bash
python3 scripts/lictor-multi.py /path --json | jq '.findings[] | select(.severity == "critical")'
```

URL scan (live deployed sites):
```bash
python3 scripts/patrol-pilot.py --mode fresh --max 50
```

## Roadmap

- **v0.2** (now) — Python scripts work end-to-end on real projects
- **v0.3** (Jul 6) — Rust crate `lictor-core` ports these checks for the Cloudflare Worker at `scan-api.lictorai.com`
- **v0.4** (Aug 15) — Mobile (.ipa/.apk) static analysis via dedicated parser
- **v1.0** (Oct 6) — Public hard launch with all surfaces covered

False-negative reports against these scripts are the highest-value
contributions we accept. File at
github.com/Raffa-jarrl/Lictor-AI/issues/new?template=false-negative.md
