<!--
Copyright (c) 2025 TRUSTEDGE LABS LLC
MPL-2.0: https://mozilla.org/MPL/2.0/
Project: sealedge — Privacy and trust at the edge.
GitHub: https://github.com/TrustEdge-Labs/sealedge
-->

# Sealedge Migration Guide

This guide documents breaking changes for users upgrading across major versions of Sealedge (formerly trustedge). Migration sections are listed newest-first. The v6.0 section below covers the trustedge → sealedge rebrand.

## v6.0: trustedge → sealedge rebrand — clean break

v6.0 is a trademark-driven rename from "trustedge" to "sealedge". **There is no backward-compatibility path.** Existing `.trst` archives, `.te-attestation.json` files, `TRUSTEDGE-KEY-V1` encrypted key files, and active TCP/QUIC sessions fail cleanly under the new magic bytes and domain-separation constants.

### What renamed

| Surface | Before (v5.x) | After (v6.0) |
|---|---|---|
| Workspace crate prefix | `trustedge-*` | `sealedge-*` |
| Main CLI binary | `trustedge` | `sealedge` |
| Archive CLI binary | `trst` | `seal` |
| Archive inspector binary | `inspect-trst` | `inspect-seal` |
| Network server binary | `trustedge-server` | `sealedge-server` |
| Network client binary | `trustedge-client` | `sealedge-client` |
| Platform HTTP server binary | `trustedge-platform-server` | `sealedge-platform-server` |
| Archive file extension | `.trst` | `.seal` |
| Attestation file extension | `.te-attestation.json` | `.se-attestation.json` |
| Env-var prefix | `TRUSTEDGE_*` | `SEALEDGE_*` |
| Encrypted-key header | `TRUSTEDGE-KEY-V1` | `SEALEDGE-KEY-V2` |
| Envelope domain | `TRUSTEDGE_ENVELOPE_V1` | `SEALEDGE_ENVELOPE_V1` |
| Chunk-key domain | `TRUSTEDGE_SEAL_CHUNK_KEY` | `SEALEDGE_SEAL_CHUNK_KEY` |
| Session-key domain | `TRUSTEDGE_SESSION_KEY_V1` | `SEALEDGE_SESSION_KEY_V1` |
| Genesis seed | `trustedge:genesis` | `sealedge:genesis` |
| Manifest domain | `trustedge.manifest.v1` | `sealedge.manifest.v1` |
| Archive magic bytes | `TRST` | `SEAL` |
| X25519 derivation (experimental) | `TRUSTEDGE_X25519_DERIVATION` | `SEALEDGE_X25519_DERIVATION` |
| V2 session key (experimental) | `TRUSTEDGE_V2_SESSION_KEY` | `SEALEDGE_V2_SESSION_KEY` |
| V2 audio domain (experimental) | `TRUSTEDGE_AUDIO_V2` | `SEALEDGE_AUDIO_V2` |
| GitHub repo URL | `TrustEdge-Labs/trustedge` | `TrustEdge-Labs/sealedge` |
| GitHub Action | `TrustEdge-Labs/attest-sbom-action@v1` | `TrustEdge-Labs/sealedge-attest-sbom-action@v2` |

Preserved unchanged:
- `TrustEdge-Labs` (GitHub organization name)
- `TRUSTEDGE LABS LLC` (legal entity in copyright lines)
- `trustedgelabs.com` (company domain)

### Clean-break behavior (no silent migration)

Under v6.0, the following inputs fail cleanly instead of being silently upgraded:

- A `.trst` archive read by `seal verify` fails with a clear magic-byte error — there is no shim that accepts `TRST` magic and rewrites it as `SEAL`.
- A `TRUSTEDGE-KEY-V1` encrypted key file read by v6.0 tooling fails with a header-mismatch error.
- An envelope using the v5.x HKDF domain `TRUSTEDGE_ENVELOPE_V1` decrypts to different OKM under v6.0's `SEALEDGE_ENVELOPE_V1` domain — tags will fail to verify.
- Networking sessions using the v5.x session-key domain fail handshake under v6.0 peers.

This is intentional. The solo-dev threshold here is: no production users depend on cross-version decrypt, and keeping dual code paths forever is worse than requiring a re-wrap.

### How to upgrade

Any data you want to carry forward must be re-wrapped under v6.0:

1. **Regenerate device keys** under the new encrypted-key header:
   ```bash
   # Interactive (passphrase prompted)
   cargo run -p sealedge-seal-cli -- keygen --out-key device.key --out-pub device.pub

   # CI / automation (unencrypted key file)
   cargo run -p sealedge-seal-cli -- keygen --out-key device.key --out-pub device.pub --unencrypted
   ```

2. **Re-wrap existing plaintext source data** into `.seal` archives:
   ```bash
   cargo run -p sealedge-seal-cli -- wrap \
     --in source.bin \
     --out archive.seal \
     --device-key device.key \
     --device-pub device.pub
   ```

   If the only copy you have is an old `.trst` archive, unwrap it with the v5.x `trst` binary on the old branch first, then re-wrap the recovered plaintext with the v6.0 `seal` binary.

3. **Re-attest SBOMs** so `.se-attestation.json` files are produced under the new Ed25519 key:
   ```bash
   cargo run -p sealedge-seal-cli -- attest-sbom \
     --binary target/release/seal \
     --sbom bom.cdx.json \
     --device-key build.key \
     --device-pub build.pub \
     --out attestation.se-attestation.json
   ```

4. **Update env-var exports** in shell profiles, systemd units, Docker compose files, and CI workflows:
   ```bash
   # Before
   export TRUSTEDGE_DEVICE_ID=…
   export TRUSTEDGE_SALT=…

   # After
   export SEALEDGE_DEVICE_ID=…
   export SEALEDGE_SALT=…
   ```

5. **Update Cargo.toml dependencies** in any consumer crate:
   ```toml
   # Before
   [dependencies]
   trustedge-core = { version = "0.5", features = ["audio"] }

   # After
   [dependencies]
   sealedge-core = { version = "0.6", features = ["audio"] }
   ```

6. **Update repository URL** if you have a local clone:
   ```bash
   git remote set-url origin https://github.com/TrustEdge-Labs/sealedge.git
   ```
   (GitHub's automatic redirect continues to resolve the old URL during the transition, but the canonical URL now points at `sealedge`.)

### If you hit a verification failure after upgrade

The following errors are all the expected clean-break signal:

- `verify failed: archive magic mismatch — expected SEAL, got TRST`
- `key file header mismatch — expected SEALEDGE-KEY-V2`
- `AEAD tag verification failed` on an envelope that decrypts under the old domain
- `handshake failed: peer session-key domain mismatch`

These are not bugs. Regenerate keys and re-wrap your data under v6.0.

## Migrating from 0.2.x to 0.3.x: Crate Consolidation

### Overview

As part of the TrustEdge workspace consolidation project (Phases 4-7), all receipts and attestation functionality was merged into `trustedge-core`. The standalone `trustedge-receipts` and `trustedge-attestation` crates served as deprecated re-export facades.

**As of v1.7 (February 2026), these facade crates have been removed from the workspace entirely.** They were never published to crates.io, so no yanking was needed. Git history preserves the removed code.

**Why this change:**
- **Single source of truth**: Core cryptographic operations centralized in one place
- **Reduced compilation units**: Faster builds with fewer dependency edges
- **Better maintainability**: One codebase for all applications-layer functionality
- **Identical APIs**: All function signatures and behaviors remain unchanged

**Timeline:**

| Version | Date | Status |
|---------|------|--------|
| 0.2.0 | January 2026 | Facades active, no warnings |
| 0.3.0 | February 2026 | Facades deprecated, compiler warnings issued |
| 0.4.0 / v1.7 | February 2026 | Facades **removed** from workspace (complete) |

Migration is required. Use `trustedge-core` directly.

---

## Migration Steps

### Step 1: Update Cargo.toml Dependencies

**Before (using facade crates):**
```toml
[dependencies]
trustedge-receipts = "0.2.0"
trustedge-attestation = "0.2.0"
```

**After (using consolidated core):**
```toml
[dependencies]
trustedge-core = "0.2.0"
```

If you're using both receipts and attestation, you only need to add `trustedge-core` once.

### Step 2: Update Import Statements

All type names and function signatures remain identical. Only the module path changes.

#### Receipts Migration

**Before:**
```rust
use trustedge_receipts::{
    Receipt,
    create_receipt,
    assign_receipt,
    extract_receipt,
    verify_receipt_chain,
};
```

**After:**
```rust
use trustedge_core::{
    Receipt,
    create_receipt,
    assign_receipt,
    extract_receipt,
    verify_receipt_chain,
};
```

#### Attestation Migration

**Before:**
```rust
use trustedge_attestation::{
    Attestation,
    AttestationConfig,
    AttestationResult,
    OutputFormat,
    KeySource,
    VerificationConfig,
    VerificationResult,
    VerificationDetails,
    VerificationInfo,
    create_signed_attestation,
    verify_attestation,
};
```

**After:**
```rust
use trustedge_core::{
    Attestation,
    AttestationConfig,
    AttestationResult,
    OutputFormat,
    KeySource,
    VerificationConfig,
    VerificationResult,
    VerificationDetails,
    VerificationInfo,
    create_signed_attestation,
    verify_attestation,
};
```

### Step 3: Verify Compilation

After updating dependencies and imports, verify everything still works:

```bash
# Clean build to ensure no stale artifacts
cargo clean

# Check for compilation errors
cargo check

# Run your test suite
cargo test

# If you have clippy enabled, ensure no new warnings
cargo clippy -- -D warnings
```

---

## API Compatibility

**Important: There are NO breaking changes to function signatures or behavior.**

- All type names remain identical (`Receipt`, `Attestation`, etc.)
- All function names remain identical (`create_receipt`, `verify_attestation`, etc.)
- All function signatures remain identical (same parameters, same return types)
- All runtime behavior remains identical (same cryptographic operations)

**Only import paths have changed.** This is why the migration window exists — you need time to update imports, but your code logic requires no changes.

---

## Troubleshooting

### "Cannot find type `Receipt` in this scope"

**Cause:** You're still importing from `trustedge_receipts`, but the crate is deprecated.

**Solution:**
1. Update your `Cargo.toml` to include `trustedge-core = "0.2.0"`
2. Change `use trustedge_receipts::Receipt;` to `use trustedge_core::Receipt;`

### "Cannot find type `Attestation` in this scope"

**Cause:** You're still importing from `trustedge_attestation`, but the crate is deprecated.

**Solution:**
1. Update your `Cargo.toml` to include `trustedge-core = "0.2.0"`
2. Change `use trustedge_attestation::Attestation;` to `use trustedge_core::Attestation;`

### "Multiple versions of `trustedge-core` in dependency tree"

**Cause:** Some of your dependencies still use the old facade crates, which themselves depend on `trustedge-core`.

**Solution:**
1. Run `cargo tree` to identify which dependencies are using old facades
2. Check if those dependencies have newer versions that use `trustedge-core` directly
3. Update those dependencies in your `Cargo.toml`
4. If upstream dependencies haven't migrated yet, you may need to wait or contact the maintainers

### Shell crates (CLIs, WASM) fail to build after migration

**Cause:** This should NOT happen. All TrustEdge shell crates (CLI tools, WASM bindings) already use `trustedge-core` directly.

**Solution:**
- If you encounter this, it's a bug. Please report it: https://github.com/TrustEdge-Labs/trustedge/issues
- Include your `Cargo.toml`, error message, and Rust version in the report

---

## Need Help?

If you encounter issues not covered in this guide:

- **Check the CHANGELOG**: See [CHANGELOG.md](CHANGELOG.md) for deprecation notices and version history
- **Open an issue**: https://github.com/TrustEdge-Labs/trustedge/issues

---

## For Library Maintainers

If you maintain a library that depends on `trustedge-receipts` or `trustedge-attestation`:

1. **Update your dependencies** to use `trustedge-core` as soon as possible
2. **Publish a new version** of your library with the updated dependency
3. **Document the change** in your CHANGELOG so your users know to upgrade
4. **Consider SemVer impact**:
   - If you re-export TrustEdge types in your public API, this is a breaking change (requires major version bump)
   - If TrustEdge is only an internal dependency, this is a non-breaking change (patch or minor version bump)

---

## Migration Complete

The facade crates (`trustedge-receipts`, `trustedge-attestation`) have been removed as of v1.7. All TrustEdge shell crates already use `trustedge-core` directly. External projects that referenced these crates (which were never published to crates.io) should use `trustedge-core` directly.
