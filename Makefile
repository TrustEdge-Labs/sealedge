# Copyright (c) 2025 TRUSTEDGE LABS LLC
# MPL-2.0: https://mozilla.org/MPL/2.0/
# Project: sealedge — Privacy and trust at the edge.

.PHONY: help copyright-check fix-copyright install-hooks build test clean

help: ## Show this help message
	@echo "TrustEdge Development Commands:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

copyright-check: ## Check all files for copyright headers
	@./scripts/fix-copyright.sh

fix-copyright: ## Add copyright headers to files that are missing them
	@./scripts/fix-copyright.sh

install-hooks: ## Install git pre-commit hooks
	@echo "Installing pre-commit hook..."
	@cp scripts/pre-commit.sh .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@echo "✅ Pre-commit hook installed"

build: ## Build all workspace crates
	@cargo build --workspace

build-with-audio: ## Build the project with audio features
	@cd crates/core && cargo build --release --features audio

test: ## Run workspace tests
	@cargo test --workspace

test-with-audio: ## Run tests with audio features
	@cd crates/core && cargo test --features audio

demo: ## Produce a sample cam.video archive and verify it
	@cargo run -p trst-cli -- wrap --profile cam.video --in ./examples/cam.video/sample.bin --out ./examples/cam.video/sample.trst
	@cargo run -p trst-cli -- verify ./examples/cam.video/sample.trst --device-pub $$(cat device.pub)

clippy: ## Run clippy linting
	@cd crates/core && cargo clippy -- -D warnings

fmt: ## Format code
	@cd crates/core && cargo fmt

fmt-check: ## Check code formatting
	@cd crates/core && cargo fmt --check

audit: ## Run security audit
	@cd crates/core && cargo audit

clean: ## Clean build artifacts
	@cd crates/core && cargo clean

full-check: copyright-check clippy fmt-check test audit ## Run all quality checks

test-wasm: ## Run WASM tests in Chrome
	@echo "Running WASM tests..."
	@cd crates/wasm && wasm-pack test --chrome --headless
	@cd crates/trst-wasm && wasm-pack test --chrome --headless
	@echo "✅ All WASM tests passed"

test-wasm-all: ## Run WASM tests in all browsers
	@echo "Running WASM tests in all browsers..."
	@cd crates/wasm && wasm-pack test --chrome --headless && wasm-pack test --firefox --headless
	@cd crates/trst-wasm && wasm-pack test --chrome --headless && wasm-pack test --firefox --headless
	@echo "✅ All cross-browser WASM tests passed"

test-wasm-dev: ## Run WASM tests with visible browser (for debugging)
	@echo "Running WASM tests in development mode..."
	@cd crates/wasm && wasm-pack test --chrome

ci-check: ## Run the same checks as CI
	@echo "Running CI checks..."
	@$(MAKE) copyright-check
	@$(MAKE) fmt-check
	@$(MAKE) clippy
	@$(MAKE) test
	@$(MAKE) audit
	@echo "✅ All CI checks passed"

ci-check-full: ## Run CI checks including WASM tests
	@echo "Running full CI checks including WASM..."
	@$(MAKE) ci-check
	@$(MAKE) test-wasm
	@echo "✅ All CI checks including WASM passed"

dev-setup: install-hooks ## Set up development environment
	@echo "Setting up development environment..."
	@cd crates/core && rustup component add clippy rustfmt
	@cd crates/core && cargo install cargo-audit || true
	@$(MAKE) install-hooks
	@echo "✅ Development environment ready"
