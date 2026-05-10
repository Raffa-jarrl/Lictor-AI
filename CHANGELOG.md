# Changelog

All notable changes to Lictor are recorded here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versioning follows [SemVer](https://semver.org/) once we hit `0.1.0` (the first published release).

## [Unreleased] — 2026-05 (positioning + governance round)

### Added

- **`docs/compliance.md`** — Lictor's products mapped onto SOC 2 (CC6/7/8/9), GDPR Article 32, EU AI Act (Articles 9, 12, 14, 26, 50), NIST AI RMF, ISO/IEC 42001. The lictor.ai/compliance landing page is generated from this doc. Removes the #1 blocker in enterprise procurement.
- **`docs/specs/multi-tenant-plan.md`** — explicit migration recipe to flip Guardian from single-tenant to multi-tenant. Schema is already shaped for it; this doc is the runbook for when an enterprise customer triggers the flip (~Q1 2027).
- **`NOTICE`** — Apache 2.0-required NOTICE file, with attribution for bundled third-party software.
- **`guardian/LICENSE`** — explicit source-available terms for Guardian (read/study/contribute permitted; host-as-a-service forbidden; self-hosting agreements available on request).

### Changed

- **License pivot: MIT → Apache 2.0** for all OSS components (lictor-core, Lictor Shield, @lictor/sentinel, lictor-sentinel). Apache's patent grant is what enterprise legal teams require; MIT was unblocking nothing. Guardian stays source-available under separate terms.
- **Updated `package.json` / `pyproject.toml` / `Cargo.toml`** for the four OSS packages to declare Apache-2.0 in their metadata.
- **Strategic positioning: "AI security tool" → "safety infrastructure for the AI agent era".** Captured in `STRATEGY.md` §13.0 (in the GenerationAI repo). The launch-day narrative anchor is now: *"AI agents are starting to take real-world actions. The infrastructure to make that safe doesn't exist yet. We're building it."* This frame pulls Lictor out of feature-comparison with incumbents and into category-creation territory.

## [Earlier] — 2026-05 (initial polish round)

### Added

- **Brand assets.** SVG sources for the primary mark (Praetorian helmet with circuit-detail crest), the fasces secondary mark, the lockup, and a favicon-optimized variant. Pre-rendered PNGs at 16/32/48/128/256/512. See [`brand/README.md`](./brand/README.md).
- **CI** via GitHub Actions. Runs `cargo fmt --check`, `cargo clippy -D warnings` against both native and `wasm32-unknown-unknown`, the full test suite (`--all-features`), the native CLI build, and the Shield extension end-to-end build. Uploads the unpacked extension as a downloadable artifact.
- **`CONTRIBUTING.md`**, **`SECURITY.md`**, this file.
- **`examples/vulnerable-demo/`** — static HTML fixture with intentional vulnerabilities, used to validate the engine catches the 6 expected findings against real HTTP.
- **`core/examples/audit.rs`** — native CLI binary. `cargo run --release --example audit -- <URL> -o report.md`.
- **`core/src/wasm.rs`** — 21 wasm-bindgen exports of the static-analysis surface.
- **`shield/src/audit-engine.ts`** — orchestrates the full Shield audit. Loads `lictor-core` as WASM, dispatches HTML/JS/probes via `chrome.runtime`-context fetches, passes bytes/headers to WASM for pattern matching.

### Changed

- **`core/checks/secrets.rs`**: dedup is now by exact matched value, not by `(label, redacted_form)`. Same secret matching multiple patterns (e.g. an Anthropic key matched by the broader `sk-` pattern) now produces one finding under the more specific label, not two.
- **`core/checks/secrets.rs`**: OpenAI pattern is now `sk-(?:proj-)?[A-Za-z0-9_-]{20,}`. Catches OpenAI's 2024+ project-scoped keys (the upstream `audit.py` pattern missed them).
- **All check modules** refactored to expose a pure-static-analysis surface (`analyze_text`, `classify_*`, `detect_signals`, etc.) alongside the full `run<F: Fetch>` pipeline. WASM only links the pure layer; native links both.
- **Shield**: stub content-script replaced with real WASM-dispatched audit. Background service worker maintains per-tab state and updates the toolbar badge by top severity. Popup polls for findings and renders them with severity-coloured pills.

### Fixed

- **`core/checks/database.rs`**: `finding_firebase_open` had a duplicate `.with_detail()` call (second clobbered the first). Coalesced into one detail string with both the probe URL and the project host.
- **`core/finding.rs`**: `Severity` ordering. Original `derive(PartialOrd, Ord)` was driven by variant declaration order, which put `Critical` *first* (smallest). Replaced with a manual `Ord` impl that ranks by domain semantics (`Critical > High > Medium > Low > Info`).

### Internal

- `cargo fmt --all` clean. `cargo clippy -D warnings` clean on native + `wasm32-unknown-unknown`. 39 tests passing.
- `wasm-opt` size pass disabled in `core/Cargo.toml` due to a known incompatibility between the bundled `wasm-opt` and Rust's bulk-memory output. WASM bundle is 960 KB (will drop to ~280 KB once we wire a newer `wasm-opt`). Tracked.
- Repo now structured as a Cargo + npm workspace dual: `Cargo.toml` declares the Rust workspace, `package.json` declares the JS workspace.

---

## How this file is maintained

- One section per release tag (`## [0.1.0] — YYYY-MM-DD`).
- The current development cycle lives under `## [Unreleased]`.
- Subsections in order: **Added**, **Changed**, **Fixed**, **Removed**, **Security**, **Internal**.
- Don't include refactors, formatting changes, or test-only changes unless they materially shift the public API or a measurable like binary size or test coverage.
