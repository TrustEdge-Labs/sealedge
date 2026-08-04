<!--
Copyright (c) 2025 TRUSTEDGE LABS LLC
MPL-2.0: https://mozilla.org/MPL/2.0/
Project: sealedge — Privacy and trust at the edge.
GitHub: https://github.com/TrustEdge-Labs/sealedge
-->

# cam.video Archive Demo

This directory contains an end-to-end demonstration of the Sealedge `.seal`
archive format (`trst_version` 0.2.0, C4) using the `cam.video` profile. It shows
cryptographic signatures, BLAKE3 continuity chains, and per-archive content
encryption.

## 🚀 5-Minute Quick Start

### 1) Build the workspace
```bash
cargo build --workspace
```

### 2) Create sample input data

**On Linux/macOS:**
```bash
head -c 32M </dev/urandom > examples/cam.video/sample.bin
```

**On Windows (PowerShell):**
```powershell
$bytes = New-Object byte[] (32 * 1024 * 1024)
(New-Object System.Random).NextBytes($bytes)
[System.IO.File]::WriteAllBytes("examples/cam.video/sample.bin", $bytes)
```

**Alternative (cross-platform with openssl):**
```bash
openssl rand 33554432 > examples/cam.video/sample.bin
```

### 3) Generate a device keypair

`wrap` needs a signing key. Generate a `SEALEDGE-KEY-V2` bundle first. The
`--unencrypted` flag keeps the demo non-interactive; drop it (and answer the
passphrase prompt) for an encrypted-at-rest key.

```bash
cargo run -p sealedge-seal-cli -- keygen --out-key device.key --out-pub device.pub --unencrypted
```

### 4) Wrap using the CLI
```bash
cargo run -p sealedge-seal-cli -- wrap --profile cam.video \
  --in examples/cam.video/sample.bin --out ./clip.seal \
  --device-key device.key --unencrypted
```

The archive is encrypted to the device key by default. Add `--sign-only` for
plaintext chunks, or `--recipient x25519:<base64>` to let an extra recipient
decrypt it.

### 5) Verify using the CLI

`device.pub` has two lines (`ed25519:` then `x25519:`); pass the signing line:

```bash
cargo run -p sealedge-seal-cli -- verify ./clip.seal --device-pub "$(grep '^ed25519:' device.pub)"
```

## 📋 Expected Output

### Wrap Command Output:
```
Archive: ./clip.seal
Signature: ed25519:A1B2C3D4E5F6...
Segments: 32
```

(`Generated device key`/`Generated device pub` lines appear only when you omit
`--device-key` and let `wrap` auto-generate a keypair.)

### Verify Command Output:
```
Signature: PASS
Continuity: PASS
Segments: 32  Duration(s): 64.0  Chunk(s): 2.0
```

## 🔧 Library Examples

This directory also includes two Rust examples that demonstrate direct use of the
core library APIs:

### `record_and_wrap.rs` - Programmatic Archive Creation
```bash
cargo run -p sealedge-cam-video-examples --bin record_and_wrap
```

This example shows how to:
- Generate device keypairs using the core crypto module
- Read input data and split into fixed-size chunks
- Encrypt each chunk with XChaCha20-Poly1305
- Build BLAKE3 continuity chains
- Create and sign cam.video manifests
- Write complete .seal archive structures

> **Note:** this example illustrates the low-level pipeline against the pre-C4
> (`0.1.0`) manifest shape. Its output is **not** accepted by the current
> `seal verify`, which requires `trst_version` 0.2.0. Use the CLI quick start
> above to produce verifiable archives.

### `verify_cli.rs` - Programmatic Archive Verification
```bash
cargo run -p sealedge-cam-video-examples --bin verify_cli [archive_path] [device_pub_path]
```

This example demonstrates:
- Reading .seal archive structures
- Verifying Ed25519 signatures against canonical manifest bytes
- Validating BLAKE3 continuity chain integrity
- Checking chunk file hash consistency
- Comprehensive verification reporting

## 📁 Archive Structure

The generated `.seal` archives follow this structure:
```
clip.seal/
├── manifest.json          # Signed cam.video manifest (0.2.0); includes an
│                          #   `encryption` block + device.key_agreement_public
├── signatures/
│   └── manifest.sig        # Detached Ed25519 signature over the canonical manifest
└── chunks/
    ├── 00000.bin           # [nonce:24][ciphertext] when encrypted; plaintext under --sign-only
    ├── 00001.bin
    └── ...                 # Additional chunks
```

## 🔐 Security Features (C4 / 0.2.0)

- **Ed25519 Signatures**: Each manifest is cryptographically signed with the device key
- **Per-archive random CEK**: Content is encrypted with a random content-encryption key (never derived from the signing key), using XChaCha20-Poly1305; each chunk stores `[nonce:24][ciphertext]`
- **HPKE-wrapped recipients**: The CEK is HPKE-wrapped (RFC 9180 base mode) to one or more recipients; recipient #0 is the device, and `--recipient` adds more
- **Sign-only mode**: `--sign-only` produces plaintext chunks with no `encryption` block
- **BLAKE3 Continuity Chains**: Tamper-evident chain linking all segments
- **Canonical Serialization**: Deterministic manifest ordering for consistent signatures

## 🎯 Profile Specification

The `cam.video` profile implements:
- **Chunk-based storage**: Fixed-size segments with timing metadata
- **Device identity**: Cryptographic device fingerprinting
- **Capture metadata**: Timestamp, resolution, codec, and frame rate information
- **Claims system**: Extensible metadata for location, source verification, etc.
- **Chain continuity**: Genesis-rooted hash chain for segment ordering

## 🧪 Testing & Validation

Run the integration tests to validate archive behavior:
```bash
cargo test -p sealedge-seal-cli
```

## 📚 Further Documentation

- **[C4 content-encryption design](../../docs/designs/c4-content-encryption-redesign.md)** - The 0.2.0 content-encryption model
- **[Core module source](../../crates/core/src/)** - Low-level API reference
- **[seal CLI](../../crates/seal-cli/)** - Command-line interface guide

---

*This example demonstrates the C4 (`trst_version` 0.2.0) implementation of the
Sealedge .seal specification using the cam.video profile.*
