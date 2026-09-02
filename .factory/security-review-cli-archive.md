<!--
Copyright (c) 2025 TRUSTEDGE LABS LLC
MPL-2.0: https://mozilla.org/MPL/2.0/
Project: sealedge — Privacy and trust at the edge.
GitHub: https://github.com/TrustEdge-Labs/sealedge
-->


# Security Review: CLI Binaries & .trst Archive System

**Date:** 2026-03-22  
**Scope:** `trustedge-cli`, `trustedge-trst-cli`, `trustedge-trst-protocols`, `trustedge-core` (archive/crypto modules)  
**Reviewer:** Automated security analysis

---

## 1. Architecture Summary

### trustedge-cli (`trustedge` binary)
- Envelope encryption CLI using AES-256-GCM with per-chunk Ed25519 signed manifests.
- Supports file and live-audio input. Per-chunk encryption with nonce = `[4-byte prefix || 8-byte seq counter]`.
- Outputs `.trst` envelope format (bincode-serialized `StreamHeader` + `Record` frames).
- Supports pluggable key backends (keyring, TPM, HSM stubs) via `BackendRegistry`.

### trustedge-trst-cli (`trst` binary)
- Archive CLI for `.trst` directory-based archives.
- **Subcommands:** `keygen`, `wrap`, `verify`, `unwrap`, `emit-request`.
- Signing: Ed25519 (software default) or ECDSA P-256 (YubiKey hardware).
- Chunk encryption: XChaCha20-Poly1305 with HKDF-SHA256-derived chunk key from the device Ed25519 secret.
- Continuity chain: BLAKE3-based hash chain with genesis seed.

### trustedge-trst-protocols
- WASM-compatible manifest types (zero crypto dependencies).
- `TrstManifest` with profile-agnostic metadata (`generic`, `cam.video`, `sensor`, `audio`, `log`).
- Deterministic canonical JSON serialization for signing.

### Encrypted Key Format (TRUSTEDGE-KEY-V1)
- PBKDF2-HMAC-SHA256 (600,000 iterations) + AES-256-GCM.
- 32-byte random salt, 12-byte random nonce. Format: `header\nJSON-metadata\nciphertext`.

---

## 2. Security Findings

### MEDIUM Severity

#### M-1: AES-256 Key Printed to stderr in Demo Mode (trustedge-cli)
**File:** `crates/trustedge-cli/src/main.rs`, line ~376  
**Code:** `eprintln!("NOTE (demo): AES-256 key (hex) = {}", hex::encode(kb));`  
**Issue:** When no `--key-out` and no `--key-hex` is provided in encrypt mode, the randomly generated AES-256 key is printed to stderr in plaintext hex. While annotated as "demo only", this is a production binary. Keys in terminal output can be captured by shell history, process monitoring, or screen recordings.  
**Recommendation:** Remove the fallback eprintln in non-demo builds, or gate it behind an explicit `--show-key` flag, or require `--key-out` always.

#### M-2: No Minimum Iteration Count Enforcement on Import (trustedge-core)
**File:** `crates/core/src/crypto.rs`, line ~233  
**Issue:** `import_secret_encrypted()` reads the `iterations` field from the JSON metadata and uses it directly. An attacker who obtains a key file could reduce iterations (e.g., to 1) and re-encrypt with a guessed passphrase. There is no minimum-iteration check on import.  
**Recommendation:** Enforce `iterations >= PBKDF2_MIN_ITERATIONS` during import, or at minimum log a warning.

#### M-3: Auto-Generated Key Files Lack Permission Restrictions (trst-cli, wrap path)
**File:** `crates/trst-cli/src/main.rs`, `load_or_generate_keypair()` function  
**Issue:** When `wrap` auto-generates a keypair (no `--device-key` provided), the secret key file is written via `fs::write()` with default permissions (typically 0644 on Unix). The `keygen` subcommand correctly sets 0600 permissions, but the auto-generation path in `load_or_generate_keypair()` does not.  
**Recommendation:** Apply `chmod 0600` after writing the auto-generated `device.key` in `load_or_generate_keypair()`, matching the `keygen` behavior.

#### M-4: No `--unencrypted` Flag Warning in trst-cli
**File:** `crates/trst-cli/src/main.rs`  
**Issue:** The `--unencrypted` flag allows writing plaintext key files and reading them without passphrase prompts, intended for CI/automation. However, no warning is emitted when this flag is used. Users may not realize they are operating without key encryption.  
**Recommendation:** Print a warning to stderr when `--unencrypted` is used in interactive contexts (e.g., `eprintln!("⚠ Warning: Using unencrypted key file (insecure for production use)")`).

#### M-5: trustedge-cli Key File Has No Permission Restrictions
**File:** `crates/trustedge-cli/src/main.rs`, line ~374  
**Issue:** When `--key-out` is used, the AES key hex is written via `std::fs::write()` with default permissions. No `chmod 0600` is applied.  
**Recommendation:** Set restrictive file permissions on key output files.

### LOW Severity

#### L-1: Signing Key Generated Per-Session in trustedge-cli (Demo Pattern)
**File:** `crates/trustedge-cli/src/main.rs`, line ~509  
**Code:** `let signing = SigningKey::generate(&mut OsRng); // demo only`  
**Issue:** The trustedge-cli generates an ephemeral Ed25519 signing key per invocation. This key is never persisted or communicated to a verifier. For production use, the signing key should be tied to a device identity. Annotated as "demo only" — not a vulnerability per se, but a production gap.  

#### L-2: No Chunk Size Upper Bound Validation in trst-cli Wrap
**File:** `crates/trst-cli/src/main.rs`  
**Issue:** The `--chunk-size` argument (default 1MB) has no explicit upper bound check. An extremely large chunk size (e.g., `u64::MAX`) would cause `fs::read()` to attempt to read the full file into a single chunk, potentially causing OOM. The trustedge-cli envelope format has `MAX_CHUNK_SIZE` validation but trst-cli does not.  
**Recommendation:** Add a reasonable upper bound check on `chunk_size` (e.g., 256 MB).

#### L-3: AAD JSON Key Ordering Not Guaranteed Across serde_json Versions
**File:** `crates/core/src/crypto.rs`, `generate_aad()` function  
**Issue:** `generate_aad()` uses `serde_json::json!()` macro to build the AAD value. While serde_json currently preserves insertion order, this is not a guaranteed contract. A future serde_json version could change key ordering, breaking AAD compatibility across versions.  
**Recommendation:** Use a canonical or explicit ordering for AAD construction, or use `BTreeMap` as done in the manifest canonical serialization.

#### L-4: `process::exit()` in Error Paths Bypasses RAII Cleanup (trst-cli)
**File:** `crates/trst-cli/src/main.rs`, multiple locations  
**Issue:** Several error paths in `handle_verify` and `handle_unwrap` call `process::exit(10)`, `process::exit(11)`, or `process::exit(12)`. These bypass Rust's RAII drop handlers, meaning any `zeroize`-on-drop key material in scope won't be zeroed. In practice, the OS reclaims memory immediately on exit, but for defense-in-depth this is suboptimal.  
**Recommendation:** Return distinct error types and handle exit codes in `main()`.

#### L-5: Device ID Derived From First 6 Bytes of Public Key
**File:** `crates/trst-cli/src/main.rs`, `pub_key_to_device_id()`  
**Issue:** The device ID is derived from only the first 6 bytes of the raw public key bytes, producing `te:cam:<12-hex-chars>`. With 2^48 possible values, collision probability is non-negligible at scale (~50% at ~17M devices via birthday paradox). This is not a security vulnerability but a correctness concern for large deployments.  

### INFO

#### I-1: `#![forbid(unsafe_code)]` Present in trustedge-cli ✓
The trustedge-cli binary forbids unsafe code. Good practice.

#### I-2: Path Traversal in Archive Extraction — MITIGATED
The `read_archive()` function in `archive.rs` does NOT use `segment.chunk_file` from the manifest to construct file paths. Instead, it generates chunk filenames deterministically as `format!("{:05}.bin", expected_index)` and validates that `segment.chunk_file == chunk_filename`. A malicious manifest with `chunk_file: "../../etc/passwd"` would fail the validation check and return `ArchiveError::InvalidChunkIndex`. **This is correctly mitigated.**

#### I-3: Signature Verified Before Decryption in Unwrap ✓
`handle_unwrap()` correctly verifies the Ed25519 signature and continuity chain before any decryption occurs. This prevents oracle attacks.

#### I-4: Key Material Zeroization ✓
`DeviceKeypair` implements `Drop` with `zeroize()` on the secret key bytes. The PBKDF2-derived key in `export_secret_encrypted` and `import_secret_encrypted` is also zeroized after use. The trustedge-cli also zeroizes `key_bytes` after use.

#### I-5: No Zip-Slip / Archive Extraction Vulnerability ✓
The .trst archive format uses a flat directory structure with numerically-indexed chunks. There is no decompression step, no recursive extraction, and filenames are validated against expected patterns. Zip-slip is not applicable.

#### I-6: TOCTOU — Low Risk
File operations use standard `fs::read`, `fs::write`, `File::open`, `File::create`. There are no check-then-act patterns with separate existence checks followed by opens. The `keygen` command checks for existing files before writing, which is a minor TOCTOU window but acceptable for a CLI tool.

#### I-7: Error Messages — No Sensitive Data Leakage ✓
Error messages do not include key material, passphrases, or decrypted content. Crypto errors use generic messages like "Wrong passphrase or corrupted key file" and "AES-GCM decrypt/verify failed".

---

## 3. Code Quality Issues

### CQ-1: Inconsistent Error Handling Between CLIs
- `trustedge-cli` uses `anyhow::Result` throughout with `?` propagation.
- `trst-cli` mixes `anyhow::Result` with `process::exit()` in several handlers.
- Recommendation: Standardize on returning Result types and mapping to exit codes at the top level.

### CQ-2: Seed Mode Disables Nonce Randomness (By Design, Documented)
The `--seed` flag uses `ChaCha20Rng::seed_from_u64()` for deterministic nonces. This is correctly documented as "for testing/CI, not cryptographically secure" in the CLI help text.

### CQ-3: reqwest 0.11 (Not Latest)
The `trst-cli` depends on `reqwest = "0.11"`. Current stable is 0.12+. Not a security issue but worth tracking for dependency freshness.

---

## 4. Test Coverage Assessment

### trustedge-trst-cli Tests (Excellent Coverage)
| Test File | Tests | Coverage Area |
|-----------|-------|---------------|
| `acceptance.rs` | 26 tests | Happy-path wrap/verify/unwrap for all profiles, keygen, ECDSA P-256, backends, emit-request |
| `security_archive_integrity.rs` | 7 tests | SEC-01 through SEC-04: chunk mutation, injection, reordering, manifest forgery |
| `security_nonce_key_derivation.rs` | 7 tests | SEC-05 through SEC-07: nonce uniqueness, cross-archive uniqueness, HKDF binding |
| `security_key_file_protection.rs` | 16 tests | SEC-08 through SEC-12: truncated files, corrupted JSON, wrong passphrase, boundary conditions |
| `security_error_paths.rs` | 4 tests | SEC-13: sensor profile validation |
| `integration_tests.rs` | 12 tests | End-to-end workflows, error handling, deterministic output |

**Total: ~72 tests** covering the trst-cli crate alone.

### trustedge-core Crypto Tests (Good Coverage)
The `crypto.rs` module has 16 unit tests covering:
- Keypair generation, import/export
- Sign/verify round-trip (Ed25519 and ECDSA P-256)
- AEAD encrypt/decrypt round-trip
- Wrong-data verification
- Encrypted key file round-trip, wrong passphrase, format validation
- HKDF determinism and entropy

### trustedge-trst-protocols Tests (Good Coverage)
The `manifest.rs` module has 24 unit tests covering:
- Canonical serialization for all profile types
- Round-trip serialization/deserialization
- Validation for all profiles
- Key ordering determinism
- Untagged enum discrimination

### Coverage Gaps
1. **trustedge-cli has no dedicated test files** — its functionality is partially tested through the core library tests, but there are no acceptance tests for the `trustedge` binary itself.
2. **No fuzz tests** — BLAKE3 hash inputs, bincode deserialization, and canonical JSON are potential fuzzing targets.
3. **No tests for extremely large archives** — DoS limits are checked in trustedge-cli decrypt but not in trst-cli.

---

## 5. Summary

The codebase demonstrates strong security engineering:

**Strengths:**
- Signature-before-decryption pattern correctly implemented
- Path traversal fully mitigated via deterministic filename generation
- PBKDF2 at 600K iterations per OWASP guidelines
- Key material zeroization via `Drop` trait
- Comprehensive security test suite (SEC-01 through SEC-13)
- `#![forbid(unsafe_code)]` in CLI binary
- AAD binding for encryption prevents cross-context attacks

**Areas for Improvement:**
- M-1: Remove key printing to stderr in production builds
- M-2: Enforce minimum PBKDF2 iterations on import
- M-3: Set 0600 permissions on auto-generated key files in wrap path
- M-4/M-5: Add warnings for `--unencrypted` flag and set permissions on key-out files
- Add acceptance tests for `trustedge` binary
- Consider fuzzing for bincode deserialization and canonical JSON parsing
