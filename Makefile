# Lictor — repo-wide developer entry point.
#
# Run `make help` for everything available.
# Designed to work on a fresh clone (after running `bash scripts/setup.sh`).

.DEFAULT_GOAL := help
SHELL := /bin/bash

# ── Help ─────────────────────────────────────────────────────────────────

.PHONY: help
help: ## Show this help
	@echo "Lictor — developer entry point"
	@echo ""
	@echo "Common targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""
	@echo "First-time setup: bash scripts/setup.sh"

# ── Setup + verification ────────────────────────────────────────────────

.PHONY: setup
setup: ## First-time clone setup (idempotent)
	bash scripts/setup.sh

.PHONY: check
check: check-rust check-ts ## Run all compile/type checks
	@echo "✓ All checks passed"

.PHONY: check-rust
check-rust: ## Cargo check the workspace
	cargo check --workspace --features native

.PHONY: check-ts
check-ts: ## TypeScript typecheck the Studio frontend
	cd studio && pnpm typecheck

# ── Tests ────────────────────────────────────────────────────────────────

.PHONY: test
test: test-rust ## Run all tests
	@echo "✓ All tests passed"

.PHONY: test-rust
test-rust: ## Run lictor-core test suite
	cargo test -p lictor-core --features native

.PHONY: test-watch
test-watch: ## Re-run Rust tests on file change (requires cargo-watch)
	cargo watch -x 'test -p lictor-core --features native'

# ── Studio (Tauri desktop app) ──────────────────────────────────────────

.PHONY: studio-dev
studio-dev: ## Launch Studio in dev mode (hot reload)
	cd studio && pnpm tauri:dev

.PHONY: studio-build
studio-build: ## Build Studio release .dmg (macOS)
	cd studio && pnpm tauri:build

.PHONY: studio-typecheck
studio-typecheck: ## TS typecheck only
	cd studio && pnpm typecheck

# ── Brand + landing ─────────────────────────────────────────────────────

.PHONY: brand
brand: ## Render all brand assets from SVG sources
	bash scripts/render-brand-assets.sh

.PHONY: brand-check
brand-check: ## Verify all brand assets present
	bash scripts/render-brand-assets.sh --check

.PHONY: landing-serve
landing-serve: ## Serve landing/ on http://localhost:8000
	cd landing && python3 -m http.server 8000

# ── Metrics + ops ───────────────────────────────────────────────────────

.PHONY: metrics
metrics: ## Generate this month's metrics report
	python3 scripts/generate-monthly-metrics.py

.PHONY: metrics-dry
metrics-dry: ## Preview the metrics report (no writes)
	python3 scripts/generate-monthly-metrics.py --dry-run

# ── Repo health ─────────────────────────────────────────────────────────

.PHONY: format
format: ## Format Rust + TS code
	cargo fmt --all
	cd studio && pnpm exec prettier --write 'src/**/*.{ts,tsx,css}' 2>/dev/null || true

.PHONY: lint
lint: ## Lint Rust + TS
	cargo clippy --workspace --features native -- -D warnings 2>&1 || true
	cd studio && pnpm exec tsc --noEmit

.PHONY: clean
clean: ## Remove all build artifacts
	cargo clean
	rm -rf studio/node_modules studio/dist studio/src-tauri/target
	rm -rf landing/.cache

.PHONY: doctor
doctor: ## Diagnose the local dev environment
	@echo "═══ Lictor developer environment ═══"
	@echo ""
	@echo "Rust toolchain:"
	@command -v rustc >/dev/null && rustc --version || echo "  ✗ rustc not found — run 'rustup default stable'"
	@command -v cargo >/dev/null && cargo --version || echo "  ✗ cargo not found"
	@echo ""
	@echo "Node toolchain:"
	@command -v node >/dev/null && echo "  ✓ node $$(node --version)" || echo "  ✗ node not found"
	@command -v pnpm >/dev/null && echo "  ✓ pnpm $$(pnpm --version)" || echo "  ✗ pnpm not found (npm i -g pnpm)"
	@echo ""
	@echo "Brand asset tools:"
	@command -v rsvg-convert >/dev/null && echo "  ✓ rsvg-convert" || echo "  ✗ rsvg-convert (brew install librsvg)"
	@command -v iconutil >/dev/null && echo "  ✓ iconutil (built-in)" || echo "  ✗ iconutil (macOS only)"
	@echo ""
	@echo "Repo state:"
	@if [ -f studio/node_modules/.modules.yaml ]; then echo "  ✓ studio deps installed"; else echo "  ⚠ studio/node_modules missing — run 'make setup'"; fi
	@if [ -d brand ] && [ -f brand/icon-512.png ]; then echo "  ✓ brand assets rendered"; else echo "  ⚠ brand assets missing — run 'make brand'"; fi
