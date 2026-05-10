# Contributing to Lictor AI

Lictor is in active pre-alpha development. The API surface is changing daily; we are not yet accepting feature contributions.

If you've found a real bug or a real false-positive in one of the audit checks, **please open an issue** — that's exactly what we want to hear. PRs that fix a typo, a doc error, or a clear bug are also welcome.

## What we are NOT taking right now

- New checks (the rule set is still being calibrated against the Phase 1 baseline)
- Refactors of `lictor-core`'s public API
- New SDK targets for Sentinel beyond TypeScript + Python (Phase 2)
- Anything that changes the `Fetch` trait shape or the WASM binding layer
- Stylistic changes that aren't backed by a measurable improvement

## Before opening a PR

1. **Open an issue first.** Describe the problem before sending code. Saves you (and us) time when the answer is "we already shipped that on `main` yesterday."
2. **Run the full local check set** — these mirror exactly what CI runs:
   ```bash
   cargo fmt --all
   cargo clippy -p lictor-core -- -D warnings
   cargo clippy -p lictor-core --no-default-features --features wasm \
       --target wasm32-unknown-unknown -- -D warnings
   cargo test -p lictor-core --all-features
   cd shield && pnpm typecheck && pnpm build
   ```
3. **Don't add a dependency without a paragraph of justification.** Every dep is a future supply-chain attack surface. Lictor is a security tool — we treat dependencies the way a security tool should.
4. **Match the test shape of the surrounding code.** Each check has both static-analysis tests (with hand-crafted strings) and integration tests (with `MockFetch`). Add both for new behaviour.

## Patterns we use

- `Fetch` trait abstracts I/O across native (`UreqFetch`), WASM (browser fetch), and tests (`MockFetch`). Don't inline `ureq::*` in a check.
- Static-analysis functions (`analyze_text`, `classify_*`, `detect_*`) take primitive inputs, return `Vec<Finding>` or a classification enum, do no I/O. They're the WASM-safe surface. The full `run<F: Fetch>(...)` pipeline composes them with the fetcher.
- Patterns live in `static SECRET_PATTERNS: Lazy<Vec<Pattern>>` style — compiled once, shared everywhere.
- Findings dedupe by exact matched value, not by redacted form. The first pattern in `SECRET_PATTERNS` to match a given value wins.

## Disclosure policy

If you found a security vulnerability in **Lictor itself** (not in a site Lictor scans), see [`SECURITY.md`](./SECURITY.md). Don't open a public issue.

## Code of conduct

Be useful, be specific, be calm. Don't waste anyone's time.

## License

By submitting a contribution, you agree that your work will be licensed under the same terms as the surrounding code (MIT for `core/` / `shield/` / `sentinel/`; source-available-not-redistributable for `guardian/`).
