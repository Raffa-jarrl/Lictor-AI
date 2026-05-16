# Changelog

All notable changes to Lictor are recorded here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versioning follows [SemVer](https://semver.org/) once we hit `0.1.0` (the first published release).

## [Unreleased] — 2026-05 (W5–W10: Phase 1 Sentinel feature-frozen)

### Added

- **`pii-leak` check** (postflight). 11 patterns × 7 categories with Luhn-validated credit cards. Catches emails, phones (US + international), SSNs (rejects invalid prefixes), IBANs, IPv4/IPv6, formatted US addresses.
- **`secrets-in-input` check** (preflight). 15 patterns ported from `lictor-core` SECRET_PATTERNS. Catches Google/Anthropic/OpenAI/Stripe/GitHub/Slack/AWS keys, private key blocks, JWTs, MongoDB/Postgres/Redis connection strings.
- **Sentinel telemetry sender hardened**. 5xx + network errors retry up to 3 times with exponential backoff (200/400/800ms ± 20% jitter); 4xx are permanent; queue capped at 100 in-flight. Pluggable fetch for testability.
- **Python sister package: `lictor-sentinel` (PyPI).** Feature parity with `@lictor/sentinel`: real `wrap()` via recursive `__getattr__` proxy, same Check interface, all three check catalogs mirrored character-for-character, same telemetry wire format. urllib-based (zero runtime deps). 11 E2E tests pass.
- **End-to-end Guardian integration test** (`sentinel/tests/e2e-guardian.test.ts`). Stands up a real HTTP server, wraps a fake OpenAI client, fires adversarial input, verifies the envelope lands at Guardian with the correct shape, bearer auth, AND the privacy invariant (no raw user content in the wire format).

### Status

- **`@lictor/sentinel`** v0.1.0-alpha.0 — feature-frozen, 159/159 tests pass, `pnpm pack` produces clean tarball with all three checks bundled
- **`lictor-sentinel`** v0.1.0a0 — feature-frozen, 11/11 tests pass, `python -m build` produces clean wheel that installs and works in a fresh venv

Both packages publishable to their registries (`pnpm publish` / `twine upload`) when the launch infrastructure sprint (W19) opens.

## [Earlier] — 2026-05 (W4: prompt-injection check)

### Added

- **`@lictor/sentinel` — real `prompt-injection` check.** Auto-registered on module import. 32 curated patterns across 7 attack families:
  - `direct-override` — "ignore previous instructions" and variants
  - `authority-impersonation` — fake `System:` / `[ADMIN]` role markers, "developer mode enabled", "bypass safety filters"
  - `jailbreak` — DAN-style personas, "act as evil AI", "unrestricted version"
  - `system-prompt-extraction` — "repeat your system prompt", "base64-encode your instructions"
  - `delimiter-injection` (CRITICAL) — model-control tokens (`<|im_start|>`, `[INST]`, `<|eot_id|>`, fake `Assistant:` turn boundaries)
  - `goal-hijacking` — "instead of that, do this"
  - `suspicious-encoding` — long base64 strings, hex-escape soup, zero-width character runs
- 84 tests covering positive (real adversarial input MUST trip) and negative (similar-looking legitimate input MUST NOT trip) cases. Every pattern in the catalog has at least one positive AND one negative test — that's the addition discipline going forward.
- End-to-end integration tests in `sentinel/tests/integration.test.ts` proving the real check fires through `wrap()` for OpenAI-shaped clients.
- Documented in `sentinel/README.md` and `docs/specs/sentinel-api.md` §8.

### Internal

- New `sentinel/src/checks/` directory with `index.ts` as the built-in registry. Side-effect import auto-registers `BUILTIN_CHECKS` on `@lictor/sentinel` load.
- `Check` interface (unchanged) is now the stable contract — W5 PII-leak and secrets-in-input checks plug in with no further wiring.

## [Earlier] — 2026-05 (positioning + governance round)

### Added

- **`docs/compliance.md`** — Lictor's products mapped onto SOC 2 (CC6/7/8/9), GDPR Article 32, EU AI Act (Articles 9, 12, 14, 26, 50), NIST AI RMF, ISO/IEC 42001. The lictorai.com/compliance landing page is generated from this doc. Removes the #1 blocker in enterprise procurement.
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
