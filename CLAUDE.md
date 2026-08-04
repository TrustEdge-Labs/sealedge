<!--
Copyright (c) 2025 TRUSTEDGE LABS LLC
MPL-2.0: https://mozilla.org/MPL/2.0/
Project: sealedge — Privacy and trust at the edge.
GitHub: https://github.com/TrustEdge-Labs/sealedge
-->


# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
# Full CI validation (run before committing)
./scripts/ci-check.sh

# Build workspace
cargo build --workspace --release

# Test entire workspace (471 tests)
cargo test --workspace

# Test specific crates
cargo test -p sealedge-types                     # Shared wire types (12 tests)
cargo test -p sealedge-core --lib                # Core cryptography + attestation (199 tests)
cargo test -p sealedge-seal-cli --test acceptance # Archive + attestation validation (36 tests)
cargo test -p sealedge-platform --lib            # Platform unit tests (18 tests)
cargo test -p sealedge-platform --test verify_integration           # Verify integration (9 tests)
cargo test -p sealedge-platform --test verify_integration --features http  # All verify integration (27 tests)

# Run a single test
cargo test -p sealedge-core test_name -- --nocapture

# Build/test with optional features
cargo build -p sealedge-cli --features audio                        # Live audio capture CLI
cargo build -p sealedge-core --features yubikey                     # YubiKey hardware support
cargo build -p sealedge-platform --features "http,postgres,ca"      # Full platform service
cargo test --features yubikey --test yubikey_integration
```

### Dashboard (web/dashboard/)

```bash
# Install dependencies
cd web/dashboard && npm install

# Development server
cd web/dashboard && npm run dev

# Production build
cd web/dashboard && npm run build

# Type checking
cd web/dashboard && npm run check
```

The dashboard is a SvelteKit app that provides a web UI for managing devices and viewing verification receipts. It connects to the platform server API at the URL configured in `.env.local` (defaults to `http://localhost:3001`).

## Architecture Overview

Sealedge is a Cargo workspace with 9 crates under `crates/` (plus `examples/cam.video`):

**Core Platform:**
- `sealedge-types` - Shared wire types for platform services (verification, receipts, policies); re-exported from sealedge-core
- `sealedge-core` - Core cryptographic library: envelope encryption (AES-256-GCM), Universal Backend system, network client/server, auth, receipts, attestation; re-exports sealedge-types
- `sealedge-platform` - Consolidated verification and CA service: BLAKE3+Ed25519 verify engine, JWKS key manager, Axum HTTP layer, PostgreSQL multi-tenant backend; feature flags: `http`, `postgres`, `ca`, `yubikey`, `openapi`
- `sealedge-platform-server` - Standalone HTTP server binary (Axum + clap CLI)
- `sealedge-cli` - Main CLI for envelope encryption (binary: `sealedge`)
- `sealedge-wasm` - WebAssembly bindings for browser integration

**Archive System (.seal format):**
- `sealedge-seal-protocols` - Canonical cam.video manifest types (WASM-compatible, minimal dependencies)
- `sealedge-seal-cli` - CLI tool (binary: `seal`) for wrap/verify operations
- `sealedge-seal-wasm` - Browser verification (imports manifest types from seal-protocols)

**Experimental Crates:**
- Experimental community crates (`sealedge-pubky`, `sealedge-pubky-advanced`) live in `crates/experimental/` as a separate standalone workspace. They are not part of the root workspace or CI pipeline.

**Web Dashboard:**
- `web/dashboard/` - SvelteKit admin dashboard for device management and receipt viewing

### Key Modules in `crates/core/src/`

| Module | Purpose |
|--------|---------|
| `backends/` | Universal Backend system - pluggable crypto ops (Software HSM, Keyring, YubiKey) |
| `transport/` | Network transport abstraction (TCP with framing, QUIC with TLS) |
| `envelope.rs` | **Core envelope format** - Ed25519 signed, AES-256-GCM encrypted chunks (used by receipts, attestation) |
| `crypto.rs` | XChaCha20-Poly1305 encryption, Ed25519 signing |
| `chain.rs` | BLAKE3-based continuity chain with genesis seed |
| `archive.rs` | .seal archive read/write and validation |
| `auth.rs` | Ed25519 mutual authentication with X25519 ECDH session key derivation |
| `point_attestation.rs` | **Point attestation format** - Ed25519 signed, BLAKE3 hashed binding of two artifacts (`.se-attestation.json`) |
| `audio.rs` | Live audio capture (feature-gated) |
| `hybrid.rs` | RSA hybrid encryption (asymmetric operations) |

### Data Flow

1. Input → `InputReader` trait (file, audio stream)
2. Chunking (default 4KB)
3. Per-chunk AES-256-GCM encryption
4. Envelope creation with metadata manifest
5. Transport (local file or network)

### GitHub Organization

The TrustEdge-Labs GitHub org contains 3 repos:
- **sealedge** — This monorepo: Rust workspace + SvelteKit dashboard
- **trustedgelabs-website** — Product website
- **shipsecure** — Separate product

## Code Standards

- **Formatting**: `cargo fmt` and `cargo clippy -- -D warnings` must pass
- **No emoji in code**: Use UTF-8 symbols for terminal output: ✔ ✖ ⚠ ● ♪ ■
- **Error handling**: `anyhow` for CLIs, `thiserror` for libraries; no `unwrap()` in production
- **Security**: Use `zeroize` for key material, constant-time comparisons for sensitive data
- **Copyright headers**: All `.rs` files need the MPL-2.0 header (run `./scripts/fix-copyright.sh`)

### Rust Copyright Header

```rust
//
// Copyright (c) 2025 TRUSTEDGE LABS LLC
// This source code is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Project: sealedge — Privacy and trust at the edge.
//
```

## Key Patterns

### Universal Backend Pattern

All crypto operations use capability-based dispatch:

```rust
// Check capability before use
if backend.supports_operation(&operation) {
    let result = backend.perform_operation(key_id, operation)?;
}
```

### .seal Archive Structure (`trst_version` 0.2.0, C4)

```
clip-<id>.seal/
├── manifest.json           # Canonical manifest (0.2.0) incl. device.key_agreement_public
│                           #   and an `encryption` block (per-archive CEK wrapped to
│                           #   recipients via HPKE); absent for --sign-only archives
├── signatures/
│   └── manifest.sig        # Detached Ed25519 signature (covers the encryption block)
└── chunks/
    ├── 00000.bin           # Zero-padded chunk files; [nonce:24][ciphertext] when encrypted,
    └── ...                 #   plaintext when --sign-only
```

Content is encrypted under a per-archive random CEK (never derived from the signing
key); the CEK is HPKE-wrapped to one or more recipients. Verifiers only need public
keys and reject non-`0.2.0` archives. See `docs/designs/c4-content-encryption-redesign.md`.

### Encrypted Key Files (SEALEDGE-KEY-V2)

A device has an Ed25519 **signing** key and an independent X25519 **key-agreement**
key, stored together as a `SEALEDGE-KEY-V2` bundle encrypted at rest with
PBKDF2-HMAC-SHA256 (600k iterations) + AES-256-GCM (passphrase prompted via
`rpassword`). The `.pub` file carries both public keys, one per line
(`ed25519:...` then `x25519:...`). The Ed25519 key is used only for signing;
confidentiality rides on the X25519 key. (Pre-C4 `SEALEDGE-KEY-V1` single-key
files are rejected — re-run `seal keygen`.)

For CI/automation where interactive prompts are not possible, use `--unencrypted`:
- `seal keygen --unencrypted` — generates a plaintext key bundle
- `seal wrap --unencrypted` — reads key bundle without passphrase prompt
- `seal unwrap --unencrypted` — reads key bundle without passphrase prompt

Production devices should always use encrypted key files. The `--unencrypted` flag is an
explicit escape hatch and is never the default.

### Working with Point Attestations

```bash
# Generate a signing key (unencrypted for CI, encrypted by default for interactive use)
cargo run -p sealedge-seal-cli -- keygen --out-key build.key --out-pub build.pub --unencrypted

# Create SBOM attestation (binds SBOM to binary with Ed25519 signature)
cargo run -p sealedge-seal-cli -- attest-sbom --binary target/release/seal --sbom bom.cdx.json \
  --device-key build.key --device-pub build.pub --out attestation.se-attestation.json

# Verify attestation locally
cargo run -p sealedge-seal-cli -- verify-attestation attestation.se-attestation.json \
  --device-pub "$(cat build.pub)"

# Verify with file hash checking (confirms binary and SBOM match attestation)
cargo run -p sealedge-seal-cli -- verify-attestation attestation.se-attestation.json \
  --device-pub "$(cat build.pub)" --binary target/release/seal --sbom bom.cdx.json

# Submit to platform server for verification receipt
curl -X POST http://localhost:3001/v1/verify-attestation \
  -H "Content-Type: application/json" \
  -d @attestation.se-attestation.json
```

### Working with Archives

```bash
# Generate device keypair (encrypted at rest — passphrase prompted)
cargo run -p sealedge-seal-cli -- keygen --out-key device.key --out-pub device.pub

# For CI/automation (unencrypted key file — no passphrase)
cargo run -p sealedge-seal-cli -- keygen --out-key device.key --out-pub device.pub --unencrypted

# Create archive (generic profile; encrypted to the device key by default)
cargo run -p sealedge-seal-cli -- wrap --in sample.bin --out archive.seal --device-key device.key

# Create archive also readable by an auditor (extra HPKE recipient; repeatable)
cargo run -p sealedge-seal-cli -- wrap --in sample.bin --out archive.seal --device-key device.key --recipient "x25519:<auditor-pub>"

# Create a signed-but-unencrypted archive (plaintext chunks, no CEK)
cargo run -p sealedge-seal-cli -- wrap --sign-only --in sample.bin --out archive.seal --device-key device.key

# Create archive (sensor profile with geo)
cargo run -p sealedge-seal-cli -- wrap --profile sensor --in data.csv --out archive.seal --sample-rate 100 --unit celsius --sensor-model DHT22 --latitude 40.7 --longitude=-74.0 --device-key device.key

# Verify archive locally (public-key only; use the ed25519 line from device.pub)
cargo run -p sealedge-seal-cli -- verify archive.seal --device-pub "ed25519:..."

# Decrypt and recover original data (any recipient uses its OWN key bundle)
cargo run -p sealedge-seal-cli -- unwrap archive.seal --device-key device.key --out recovered.bin

# Sign with YubiKey hardware (requires yubikey feature; --sign-only only)
cargo run -p sealedge-seal-cli --features yubikey -- wrap --backend yubikey --sign-only --in data.bin --out archive.seal --device-key device.key

# Submit to platform server for verification
cargo run -p sealedge-seal-cli -- emit-request --archive archive.seal --device-pub device.pub --out request.json --post http://localhost:3001/v1/verify
```

### Running the Demo

```bash
# Full demo (requires docker-compose stack running)
./scripts/demo.sh

# Local-only demo (no docker needed)
./scripts/demo.sh --local
```

## Feature Flags

### sealedge-core

| Feature | Purpose | Dependencies |
|---------|---------|--------------|
| `audio` | Live microphone capture | cpal (ALSA/CoreAudio/WASAPI) |
| `yubikey` | Hardware security keys | yubikey, x509-cert, rcgen, der, spki, signature |
| `git-attestation` | Git repository state attestation | git2 |
| `keyring` | OS keyring integration for key storage | keyring |
| `insecure-tls` | Skip TLS certificate verification (development only) | (no new deps) |

### sealedge-platform

| Feature | Purpose | Dependencies |
|---------|---------|--------------|
| `http` | Axum HTTP layer (verify, jwks, health endpoints) | axum, tower, tower-http, tokio |
| `postgres` | PostgreSQL multi-tenant backend (devices, receipts, orgs) | sqlx, bcrypt |
| `ca` | Certificate Authority service via UniversalBackend | sealedge-core, x509-parser |
| `openapi` | OpenAPI schema generation | utoipa |
| `yubikey` | YubiKey-backed CA operations | sealedge-core/yubikey |
| `test-utils` | Exports `create_test_app` for integration tests | (no new deps) |

Default build has no features enabled for fast CI and maximum portability.

## Platform Environment Variables

The `sealedge-platform-server` binary reads configuration from environment variables (or a `.env` file via `dotenvy`):

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3001` | HTTP server port. Must be a valid port number (0–65535); fails fast with error if invalid. |
| `RECEIPT_TTL_SECS` | `3600` | Verification receipt TTL in seconds (1 hour). Must be a valid integer. |
| `JWT_AUDIENCE` | `sealedge-platform` | Expected JWT audience claim for verification tokens. |
| `DATABASE_URL` | (required in release) | PostgreSQL connection URL. Required in release builds; defaults to localhost in debug. Requires `postgres` feature. |

See `deploy/.env.example` for the full template with all variables documented.

## CLI Binaries

| Binary | Source | Purpose |
|--------|--------|---------|
| `sealedge` | `crates/cli/src/main.rs` | Main envelope encryption CLI |
| `sealedge-server` | `crates/core/src/bin/sealedge-server.rs` | Network server (TCP/QUIC transport) |
| `sealedge-client` | `crates/core/src/bin/sealedge-client.rs` | Network client |
| `sealedge-platform-server` | `crates/platform-server/src/main.rs` | Platform HTTP server (verify, verify-attestation, JWKS, health, verify page) |
| `seal` | `crates/seal-cli/src/main.rs` | Archive + attestation CLI (keygen/wrap/verify/unwrap/emit-request/attest-sbom/verify-attestation) |

## Common Tasks

### Adding Crypto Operations

1. Add to Universal Backend trait in `crates/core/src/backends/universal.rs`
2. Implement in relevant backends (`software_hsm.rs`, `yubikey.rs`)
3. Add tests including security scenarios
4. Update capability discovery

### Network Testing

```bash
# With authentication (ECDH-derived session key - no --key-hex needed):
# Terminal 1: Server
./target/release/sealedge-server --listen 127.0.0.1:8080 --require-auth --decrypt

# Terminal 2: Client
./target/release/sealedge-client --server 127.0.0.1:8080 --input test.txt --enable-auth --server-cert server.cert

# Without authentication (manual key sharing):
# Terminal 1: Server
./target/release/sealedge-server --listen 127.0.0.1:8080 --decrypt --key-hex $(openssl rand -hex 32)

# Terminal 2: Client
./target/release/sealedge-client --server 127.0.0.1:8080 --input test.txt --key-hex $(cat shared.key)
```

### Debugging

```bash
RUST_LOG=debug cargo test failing_test -- --nocapture
```

## Skill routing

When the user's request matches an available skill, ALWAYS invoke it using the Skill
tool as your FIRST action. Do NOT answer directly, do NOT use other tools first.
The skill has specialized workflows that produce better results than ad-hoc answers.

Key routing rules:
- Product ideas, "is this worth building", brainstorming → invoke office-hours
- Bugs, errors, "why is this broken", 500 errors → invoke investigate
- Ship, deploy, push, create PR → invoke ship
- QA, test the site, find bugs → invoke qa
- Code review, check my diff → invoke review
- Update docs after shipping → invoke document-release
- Weekly retro → invoke retro
- Design system, brand → invoke design-consultation
- Visual audit, design polish → invoke design-review
- Architecture review → invoke plan-eng-review
- Save progress, checkpoint, resume → invoke checkpoint
- Code quality, health check → invoke health
