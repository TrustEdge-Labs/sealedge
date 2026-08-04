<!--
Copyright (c) 2025 TRUSTEDGE LABS LLC
MPL-2.0: https://mozilla.org/MPL/2.0/
Project: sealedge — Privacy and trust at the edge.
GitHub: https://github.com/TrustEdge-Labs/sealedge
-->

# Sealedge Scripts

Utility scripts for Sealedge development, testing, documentation, and demos.

## 📁 Directory Structure

```
scripts/
├── ci-check.sh            # Pre-commit CI validation (mirrors GitHub CI)
├── pre-commit.sh          # Git pre-commit hook checks
├── fast-bench.sh          # Fast local performance benchmarks
├── fix-copyright.sh       # Copyright header maintenance
├── build-wasm-demo.sh     # Build the seal-wasm module for the web/demo verifier
├── demo.sh                # End-to-end demo (keygen, wrap, verify; supports --local)
├── demo-attestation.sh    # End-to-end SBOM attestation demo
├── generate-types.sh      # Generate web/dashboard TypeScript types from JSON Schema
├── consolidate-docs.sh    # Documentation consolidation helper
├── test-inventory.sh      # Generate a per-crate/per-module test inventory baseline
├── validate-v6.sh         # Full v6.0 validation gate (feature matrix + WASM/dashboard/e2e)
└── project/               # Project maintenance utilities
    ├── add-copyright.sh   # Add copyright headers to source files
    └── check-docs.sh      # Documentation status/consistency check
```

## 🚀 Quick Start

All scripts should be run from the project root directory:

```bash
# Run pre-commit CI checks (prevents GitHub CI failures)
./scripts/ci-check.sh

# End-to-end demo (add --local to skip server verification)
./scripts/demo.sh --local

# Build the WASM verifier demo
./scripts/build-wasm-demo.sh

# Fast local benchmarks
./scripts/fast-bench.sh

# Documentation status check
./scripts/project/check-docs.sh
```

## 📋 Script Categories

### Core Development
Scripts for daily development workflows:

- **ci-check.sh**: Pre-commit CI validation that runs the same checks as GitHub CI to prevent failures
- **pre-commit.sh**: Git pre-commit hook checks for code quality
- **fast-bench.sh**: Fast performance benchmarks for local development (local-only, no CI integration)
- **fix-copyright.sh**: Automated copyright header maintenance
- **validate-v6.sh**: Full v6.0 validation gate mirroring the CI feature matrix plus WASM, dashboard build, docker-compose e2e, and demo roundtrip

### Demos
- **demo.sh**: End-to-end demo — keygen, wrap, local verify, and optional server verify. Supports `--local` (skip server) and `--docker`
- **demo-attestation.sh**: End-to-end SBOM attestation demo — keygen, SBOM generation (syft), attest, and local/remote verification

### Build & Codegen
- **build-wasm-demo.sh**: Build the `seal-wasm` module into `web/demo/pkg` for the browser verifier
- **generate-types.sh**: Generate TypeScript interfaces (`web/dashboard/src/lib/types.ts`) from the `sealedge-types` JSON Schema fixtures

### Documentation & Inventory
- **consolidate-docs.sh**: Documentation consolidation helper
- **test-inventory.sh**: Generate a test inventory with per-crate and per-module granularity for baseline diffing
- **project/add-copyright.sh**: Add consistent copyright headers to all source files
- **project/check-docs.sh**: Validate documentation status and consistency

## 🚀 Performance Benchmarking

### fast-bench.sh

Quick performance benchmarks for local development (no CI integration).

**Usage:**
```bash
# From project root
./scripts/fast-bench.sh [crypto|network|all]

# Examples
./scripts/fast-bench.sh              # All benchmarks (default)
./scripts/fast-bench.sh crypto       # Crypto benchmarks only
./scripts/fast-bench.sh network      # Network benchmarks only
```

**Features:**
- **Fast execution** (quick checks, not statistically rigorous)
- **Local development only** (never runs in CI)
- **Automatic environment setup** (sets `BENCH_FAST=1`)

For full statistical accuracy, use `cargo bench` in the `crates/core/` directory.

## 🔧 Requirements

- **Bash** shell environment
- **Cargo/Rust** toolchain for building and testing
- **OpenSSL** for cryptographic operations in demos
- **wasm-pack** for `build-wasm-demo.sh`
- **Node.js/npx** for `generate-types.sh`
- **syft** for `demo-attestation.sh`

## 📝 Contributing

When adding new scripts:

1. **Use kebab-case naming** (`new-script.sh`)
2. **Make executable** (`chmod +x`)
3. **Add a description** to this README
4. **Include usage examples** in the script header

## 📚 Documentation

For detailed usage and examples, see:

- [CONTRIBUTING.md](../CONTRIBUTING.md) - Contribution guidelines
