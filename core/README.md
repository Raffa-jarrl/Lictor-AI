# lictor-core

The shared security check engine. Compiles to native (used by Sentinel + Guardian) and WASM (used by Shield).

## Status

**Phase 1 ported.** All 5 checks have full pattern parity with `audit.py`.

| Module | Status |
|---|---|
| `finding` | ✅ done |
| `http` (native) | ✅ done — `Fetch` trait, `UreqFetch`, `MockFetch`, rate limiter, manual same-host redirect handling |
| `checks::secrets` | ✅ ported (15 patterns + `.env` / `.git/config` / `wp-config.php` probes) |
| `checks::database` | ✅ ported (Supabase RLS, Firebase, 7 unauth API paths) |
| `checks::auth` | ✅ ported (login surface detect + 4 admin path probes) |
| `checks::cors` | ✅ ported (4 API paths × CORS header analysis) |
| `checks::ai_agent` | ✅ ported (7 strong fingerprints) |
| `report` | ✅ markdown writer with score |
| WASM bridge | ⏳ next: wire `wasm-pack` for Shield to consume |

**Tests: 30/30 pass.**

## Build

```bash
# Native build:
cargo build --release -p lictor-core

# Run all tests:
cargo test -p lictor-core

# WASM build (Phase 1 next step):
cargo build --release -p lictor-core --target wasm32-unknown-unknown \
    --no-default-features --features wasm
```

## Try it

A working CLI ships as a Cargo example:

```bash
cargo run --release --example audit -- https://your-vibe-coded-app.com -o report.md
```

The audit is read-only and rate-limited to 1 req/sec/host. Outputs a markdown report grouped by severity.

## API

Provide a `Fetch` impl, call any individual check or `run_all_checks`:

```rust
use lictor_core::{run_all_checks, http::UreqFetch};

let fetcher = UreqFetch::new();
let findings = run_all_checks("https://example.com", &fetcher);
for f in findings.iter().filter(|f| f.severity >= lictor_core::Severity::High) {
    println!("[{:?}] {} — {}", f.severity, f.title, f.where_found);
}
```

For tests / WASM / mocking, swap in `MockFetch`:

```rust
use lictor_core::http::{MockFetch, Method};

let fetcher = MockFetch::new()
    .with_html("https://x.test/", "<script>const k = \"sk-AAAAAAAAAAAAAAAAAAAA\"</script>");
let findings = lictor_core::checks::secrets::run("https://x.test/", &fetcher);
```

## Where the rules come from

The check rules are ported from [`audit.py`](https://github.com/generationai/genai-audit-toolkit) — the single-file Python CLI built and hardened against real AI-built apps in early 2026. Porting to Rust gives us:

1. Speed (~50× faster on bulk audits)
2. WASM compatibility (run in browser)
3. Type-safe finding model
4. Cargo distribution

When you add a pattern in one, add it in the other. The test suites mirror.

## License

MIT.
