# lictor-core

The shared security check engine. Compiles to native (used by Sentinel + Guardian) and WASM (used by Shield).

## What's in here

| Module | Status | Description |
|---|---|---|
| `finding` | scaffolded | The `Finding` type — severity, category, evidence, remediation |
| `checks::secrets` | TODO (port from audit.py) | API keys, JWTs, exposed `.env` / `.git/config` |
| `checks::database` | TODO | Supabase RLS off, Firebase open, `/api/users` without auth |
| `checks::auth` | TODO | Admin paths returning 200 instead of redirecting |
| `checks::cors` | TODO | `Access-Control-Allow-Origin: *` + `credentials: true` |
| `checks::ai_agent` | TODO | Chat widget / agent surface detection |
| `http` | TODO (native only) | Polite, rate-limited HTTP client |

## Build

```bash
# Native build (default)
cargo build --release -p lictor-core

# WASM build (for Shield)
cargo build --release -p lictor-core --target wasm32-unknown-unknown --no-default-features --features wasm
```

For the Shield extension we'll use `wasm-pack` to produce a JS-friendly bundle:

```bash
wasm-pack build --target web --out-dir ../shield/wasm
```

## API

The public surface is intentionally small. Each check returns a `Vec<Finding>`. The Shield/Sentinel/Guardian wrappers decide what to do with findings.

```rust
use lictor_core::{Finding, Severity, run_all_checks};

let findings = run_all_checks("https://example.com").await?;
for f in findings.iter().filter(|f| f.severity == Severity::Critical) {
    println!("{}: {}", f.title, f.where_found);
}
```

## Where the rules come from

The initial check rules are ported from [`audit.py`](https://github.com/generationai/genai-audit-toolkit) — a single-file Python CLI built and hardened against real AI-built apps in early 2026. Porting to Rust gives us:

1. Speed (~50x faster on bulk audits)
2. WASM compatibility (run in browser)
3. Type-safe finding model
4. Cargo as a real distribution mechanism

## Status

Pre-alpha. The skeleton compiles. Real checks land in commits over Phase 1 of the build plan (~weeks 1–4).
