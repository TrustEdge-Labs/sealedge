<!--
Copyright (c) 2025 TRUSTEDGE LABS LLC
MPL-2.0: https://mozilla.org/MPL/2.0/
Project: sealedge — Privacy and trust at the edge.
GitHub: https://github.com/TrustEdge-Labs/sealedge
-->

# Sealedge Architecture

This document covers Sealedge's internal architecture, crate organization, core systems, and testing infrastructure. For quick start and usage, see the [root README](../README.md).

---

## Project Structure

Sealedge is organized as a Cargo workspace with specialized crates:

```
sealedge/
├── crates/
│   ├── core/                     # Core cryptographic library (sealedge-core)
│   ├── types/                    # Shared wire types (sealedge-types)
│   ├── platform/                 # Verification and CA service (sealedge-platform)
│   ├── platform-server/          # Standalone HTTP server binary
│   ├── sealedge-cli/            # Main envelope encryption CLI (binary: sealedge)
│   ├── seal-cli/                 # .seal archive CLI tool (sealedge-seal-cli, binary: seal)
│   ├── seal-protocols/           # Canonical cam.video manifest types (WASM-compatible)
│   ├── seal-wasm/                # .seal verification WebAssembly bindings
│   ├── wasm/                     # Core WebAssembly bindings
│   └── experimental/             # Separate workspace for community/experimental crates
│       ├── pubky/                # Pubky network adapter
│       └── pubky-advanced/       # Advanced Pubky integration
├── examples/                     # Example implementations and demos
└── docs/                         # Documentation and guides
```

> **Experimental crates** (`sealedge-pubky`, `sealedge-pubky-advanced`) live in `crates/experimental/` as a separate Cargo workspace. They are not part of the root workspace build or CI pipeline.

### Crate Overview

| Crate | Purpose | Documentation |
|-------|---------|---------------|
| **sealedge-types** | Shared wire types for platform services (verification, receipts, policies) | [Types Documentation](../crates/types/) |
| **sealedge-core** | Core cryptographic library with envelope encryption | [Core Documentation](../crates/core/) |
| **sealedge-platform** | Consolidated verification and CA service (feature-gated: http, postgres, ca, yubikey) | [Platform Documentation](../crates/platform/) |
| **sealedge-platform-server** | Standalone HTTP server binary | [Server Documentation](../crates/platform-server/) |
| **sealedge-cli** | Main CLI for envelope encryption (binary: `sealedge`) | [CLI Documentation](../crates/sealedge-cli/) |
| **sealedge-seal-cli** | CLI for .seal archive creation and verification (binary: `seal`) | [Archive CLI Documentation](../crates/seal-cli/) |
| **sealedge-seal-protocols** | Canonical cam.video manifest types (WASM-compatible) | [Archive Format Documentation](../crates/seal-protocols/) |
| **sealedge-seal-wasm** | .seal archive verification in the browser | [Archive WASM Documentation](../crates/seal-wasm/) |
| **sealedge-wasm** | WebAssembly bindings for browser/Node.js integration | [WASM Documentation](../crates/wasm/) |

---

## Technology Stack

- **Language**: Rust (stable) for memory safety and performance
- **Cryptography**: AES-256-GCM, Ed25519, X25519 ECDH, HKDF-SHA256, RSA OAEP-SHA256, BLAKE3 with algorithm agility
- **Key Files**: SEALEDGE-KEY-V2 format (Ed25519 signing key + independent X25519 key-agreement key) — PBKDF2-HMAC-SHA256 (600k iterations) + AES-256-GCM encryption at rest
- **Audio**: Cross-platform support (Linux/ALSA, Windows/WASAPI, macOS/CoreAudio)
- **Hardware**: YubiKey PIV operations via `yubikey` crate and PCSC
- **Network**: Ed25519-based mutual authentication with X25519 ECDH session key derivation

---

## Data Flow

1. Input via `InputReader` trait (file, audio stream)
2. Chunking (default 4KB for envelope encryption, 1MB for .seal archives)
3. Per-chunk AES-256-GCM encryption
4. Envelope creation with metadata manifest
5. Transport (local file or network)

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
| `audio.rs` | Live audio capture (feature-gated) |
| `hybrid.rs` | RSA hybrid encryption (asymmetric operations) |

---

## Core Systems

### Universal Backend System

Sealedge features a **capability-based Universal Backend system** that provides pluggable cryptographic operations across different hardware and software backends.

**Supported Backends:**
- **Keyring Backend**: OS keyring integration for key derivation and storage
- **YubiKey Backend**: Hardware PIV operations (ECDSA P-256, RSA-2048) via `yubikey` crate
- **Software HSM**: In-memory cryptographic operations for development
- **TPM Backend**: Planned for future milestone

All crypto operations use capability-based dispatch:

```rust
// Check capability before use
if backend.supports_operation(&operation) {
    let result = backend.perform_operation(key_id, operation)?;
}
```

**For detailed backend documentation, see [docs/technical/universal-backend.md](technical/universal-backend.md).**

### Digital Receipt System

Sealedge includes a **production-ready digital receipt system** that enables cryptographically secure ownership transfer of digital assets with comprehensive security testing.

**Key Properties:**
- Cryptographic ownership chains with hash binding
- Ed25519 signatures for authenticity and non-repudiation
- Attack resistance against tampering, replay, and forgery
- 23 comprehensive security tests covering all attack scenarios

**For complete receipt system documentation, see [crates/core/](../crates/core/).**

### Network Operations

Sealedge supports secure client-server communication with **Mutual Authentication** using Ed25519 digital signatures and **automated X25519 ECDH key exchange** for session encryption.

**Security Features:**
- Mutual authentication between clients and servers
- Automated session encryption key derivation via X25519 ECDH (no out-of-band key sharing needed)
- Session isolation with time-limited cryptographic sessions
- Replay protection through challenge-response protocols with BLAKE3 domain-separated KDF
- Forward security with automatic session expiration

**For authentication setup and network security, see [docs/user/authentication.md](user/authentication.md).**

---

## .seal Archive Format

The `.seal` archive specification (`trst_version` 0.2.0, C4) includes:

- **Manifest Canonicalization**: Fixed-order JSON fields with signature exclusion
- **BLAKE3 Continuity Chain**: Genesis seed `blake3("sealedge:genesis")` with segment linking over the stored (ciphertext) bytes
- **Content Encryption**: Per-archive random Content-Encryption Key (CEK) encrypts chunks with XChaCha20-Poly1305; the CEK is HPKE-wrapped (RFC 9180) to one or more recipients (recipient #0 = the device's X25519 key). A sign-only mode omits the `encryption` block and stores plaintext chunks.
- **Ed25519 Signatures**: Device key signing with "ed25519:BASE64" format, covering the `encryption` block
- **Dual Device Keys**: Ed25519 signing key plus an optional X25519 `key_agreement_public` key
- **Profiles**: `generic` (default), `cam.video`, `sensor`, `audio`, `log`
- **Archive Layout**: `clip-<id>.seal/` directory with manifest, signatures, and chunks

### Archive Directory Structure

```
clip-<id>.seal/
├── manifest.json           # Canonical 0.2.0 manifest (incl. optional encryption block)
├── signatures/
│   └── manifest.sig        # Detached Ed25519 signature
└── chunks/
    ├── 00000.bin           # Zero-padded chunk files ([nonce:24][ciphertext] when encrypted)
    └── ...
```

### Working with Archives

```bash
# Generate device keypair (passphrase prompted for encrypted key file)
cargo run -p sealedge-seal-cli -- keygen --out-key device.key --out-pub device.pub

# For CI/automation (unencrypted key — no passphrase)
cargo run -p sealedge-seal-cli -- keygen --out-key device.key --out-pub device.pub --unencrypted

# Create archive (cam.video profile)
cargo run -p sealedge-seal-cli -- wrap --profile cam.video --in sample.bin --out archive.seal --device-key device.key --device-pub device.pub

# Verify archive
cargo run -p sealedge-seal-cli -- verify archive.seal --device-pub "ed25519:..."

# Recover original data
cargo run -p sealedge-seal-cli -- unwrap archive.seal --device-key device.key --out recovered.bin
```

---

## Testing and Quality Assurance

Sealedge includes a comprehensive test suite across 9 workspace crates:

- **160+ Core Tests**: Envelope encryption, Universal Backend system, receipts, attestation, transport layer (includes 18 YubiKey simulation tests)
- **4+ Auth Integration Tests**: Mutual authentication, session management, ECDH session key derivation, key uniqueness
- **9 Hardware Integration Tests**: YubiKey PIV operations (require physical device, run manually)
- **7 Archive Tests**: .seal format wrap/verify, cryptographic validation, CLI integration (sealedge-seal-cli acceptance)
- **19+ Platform Tests**: Verification engine, HTTP round-trip, CORS, router parity
- **18 Type Tests**: Shared wire type validation (sealedge-types)
- **45+ Security Tests**: Timestamp validation, error handling, permissions, cryptographic correctness (v2.3–v2.4)

```bash
# Run complete test suite
./scripts/ci-check.sh

# Run tests by crate
cargo test -p sealedge-core --lib                # Core cryptography tests
cargo test -p sealedge-types                     # Type tests (18)
cargo test -p sealedge-seal-cli --test acceptance # Archive validation (7)
cargo test -p sealedge-platform --lib            # Platform unit tests
cargo test --features yubikey --test yubikey_integration  # Hardware tests (need YubiKey)
```

**For detailed testing procedures, see [docs/developer/testing.md](developer/testing.md).**

---

## Documentation Index

### User Guides
- **[CLI Reference](user/cli.md)** - Complete command-line interface documentation
- **[Examples](user/examples/README.md)** - Real-world usage examples and workflows
- **[Authentication Guide](user/authentication.md)** - Network security setup
- **[Troubleshooting](user/troubleshooting.md)** - Common issues and solutions

### Technical Reference
- **[Universal Backend](technical/universal-backend.md)** - Backend system architecture
- **[Binary Format](technical/format.md)** - File format specification
- **[Network Protocol](technical/protocol.md)** - Communication protocol details
- **[Security Model](../SECURITY.md)** - Security architecture and threat model

### Development
- **[Contributing](../CONTRIBUTING.md)** - How to contribute to Sealedge
- **[Development Guide](developer/development.md)** - Development setup and workflows
- **[Testing Guide](developer/testing.md)** - Test procedures and validation
- **[Coding Standards](developer/coding-standards.md)** - Code style and conventions
