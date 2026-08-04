<!--
Copyright (c) 2025 TRUSTEDGE LABS LLC
MPL-2.0: https://mozilla.org/MPL/2.0/
Project: sealedge — Privacy and trust at the edge.
GitHub: https://github.com/TrustEdge-Labs/sealedge
-->

# Sealedge CLI Reference

Complete command-line interface documentation for Sealedge, covering both the core encryption system and the .seal archive format.

## Table of Contents
- [Overview](#overview)
- [Point Attestation (.se-attestation.json)](#point-attestation-te-attestationjson)
  - [seal attest-sbom - Create SBOM Attestation](#seal-attest-sbom---create-sbom-attestation)
  - [seal verify-attestation - Verify Attestation](#seal-verify-attestation---verify-attestation)
- [Archive System (.seal)](#archive-system-trst)
  - [seal keygen - Generate Key Pair](#seal-keygen---generate-key-pair)
  - [seal wrap - Create Archives](#seal-wrap---create-archives)
  - [seal verify - Verify Archives](#seal-verify---verify-archives)
  - [seal unwrap - Decrypt Archives](#seal-unwrap---decrypt-archives)
  - [seal emit-request - Submit for Verification](#seal-emit-request---submit-for-verification)
- [Encrypted Key Files](#encrypted-key-files)
- [Core Encryption System](#core-encryption-system)
  - [sealedge - Envelope Encryption](#sealedge---envelope-encryption)
  - [Network Operations](#network-operations)
- [Complete Workflows](#complete-workflows)
- [Error Handling](#error-handling)

---

## Overview

Sealedge provides two complementary CLI tools:

1. **`seal`** - Archive + attestation CLI (keygen, wrap, verify, unwrap, emit-request, attest-sbom, verify-attestation)
2. **`sealedge`** - Core envelope encryption and network operations

Both tools are built after running `cargo build --workspace --release`.

---

## Point Attestation (.se-attestation.json)

Point attestation creates a lightweight JSON document that cryptographically binds two artifacts together (e.g., an SBOM and a binary). The attestation is self-contained: it includes the Ed25519 signature, BLAKE3 hashes, a random nonce, and the signer's public key. Any third party can verify it without access to Sealedge infrastructure.

### seal attest-sbom - Create SBOM Attestation

Bind a CycloneDX SBOM to a binary artifact and sign the binding with an Ed25519 key.

```bash
seal attest-sbom --binary <path> --sbom <path> \
  --device-key <key-path> --device-pub <pub-path> \
  --out <output-path>
```

**Arguments:**

| Flag | Required | Description |
|------|----------|-------------|
| `--binary` | Yes | Path to the binary artifact (the subject) |
| `--sbom` | Yes | Path to the CycloneDX JSON SBOM (the evidence) |
| `--device-key` | Yes | Path to Ed25519 private key file |
| `--device-pub` | Yes | Path to Ed25519 public key file |
| `--out` | No | Output path (default: `attestation.se-attestation.json`) |
| `--unencrypted` | No | Read key without passphrase prompt (for CI/automation) |

**Input validation:**
- Binary must not be empty (0 bytes)
- Binary must not exceed 256 MB
- SBOM must be valid JSON
- Key file must exist and be readable

**Output:** A `.se-attestation.json` file containing:
- `format`: `"te-point-attestation-v1"`
- `subject`: BLAKE3 hash, filename, and label ("binary") of the binary artifact
- `evidence`: BLAKE3 hash, filename, and label ("sbom") of the SBOM
- `signature`: Ed25519 signature over canonical JSON (signature field excluded)
- `nonce`: 16 random bytes (hex-encoded) for replay prevention
- `timestamp`: ISO 8601 timestamp
- `public_key`: The signer's public key (embedded for self-contained verification)

**Example:**

```bash
seal attest-sbom --binary target/release/myapp --sbom bom.cdx.json \
  --device-key build.key --device-pub build.pub
# Output: attestation.se-attestation.json
```

### seal verify-attestation - Verify Attestation

Verify an attestation document's Ed25519 signature, with optional file hash checking.

```bash
seal verify-attestation <attestation-path> --device-pub <pub-key>
```

**Arguments:**

| Flag | Required | Description |
|------|----------|-------------|
| `<attestation-path>` | Yes | Path to `.se-attestation.json` file |
| `--device-pub` | Yes | Public key string (`ed25519:...`) or path to `.pub` file |
| `--binary` | No | Path to binary file for hash verification |
| `--sbom` | No | Path to SBOM file for hash verification |

**Exit codes:**
- `0` - Verification passed
- `1` - General error (IO, JSON parsing, bad input)
- `10` - Verification failed (invalid signature or hash mismatch)

**Example:**

```bash
# Signature verification only (pass the .pub file path, or an inline ed25519: key)
seal verify-attestation attestation.se-attestation.json \
  --device-pub build.pub

# Signature + file hash verification
seal verify-attestation attestation.se-attestation.json \
  --device-pub build.pub \
  --binary target/release/myapp --sbom bom.cdx.json
```

---

## Archive System (.seal)

The `seal` command provides secure archival capabilities with Ed25519 digital signatures and cryptographic chunk verification.

### seal keygen - Generate Key Pair

Generate a device key **bundle** (`SEALEDGE-KEY-V2`): an Ed25519 signing key plus
an independent X25519 key-agreement key, used for signing and content encryption
respectively. The `.pub` file carries both public keys, one per line
(`ed25519:...` then `x25519:...`).

```bash
seal keygen --out-key <KEY_PATH> --out-pub <PUB_PATH> [--unencrypted]
```

| Option | Description |
|--------|-------------|
| `--out-key <PATH>` | Output path for the private key bundle |
| `--out-pub <PATH>` | Output path for the public key file (two lines: ed25519 + x25519) |
| `--unencrypted` | Generate plaintext key bundle (no passphrase). CI/automation only — see [Encrypted Key Files](#encrypted-key-files) |

```bash
# Generate encrypted key (passphrase prompted)
seal keygen --out-key device.key --out-pub device.pub

# Generate unencrypted key for CI/automation
seal keygen --out-key device.key --out-pub device.pub --unencrypted
```

### seal wrap - Create Archives

Create a signed .seal archive from input data. Archives are **encrypted by
default** (per-archive random content key, XChaCha20-Poly1305, HPKE-wrapped to
recipients). The default profile is `generic`. If `--device-key` is omitted,
`wrap` auto-generates `device.key` + `device.pub`.

The device `id` is derived from the signing public key; `model`, `firmware`, and
the cam.video `resolution`/`codec` are fixed defaults in the manifest — there are
no flags to set them, and there is no archive-chaining flag.

```bash
seal wrap --in <INPUT> --out <OUTPUT> [OPTIONS]
```

#### Required Arguments

| Option | Description | Example |
|--------|-------------|---------|
| `--in <PATH>` | Input file | `--in video.bin` |
| `--out <PATH>` | Output .seal archive directory (must end in `.seal`) | `--out recording.seal` |

#### Common Options

| Option | Default | Description | Example |
|--------|---------|-------------|---------|
| `--profile <PROFILE>` | `generic` | Profile: `generic`, `cam.video`, `sensor`, `audio`, `log` | `--profile cam.video` |
| `--device-key <PATH>` | (generated) | Existing device key bundle; auto-generates if omitted | `--device-key device.key` |
| `--chunk-size <SIZE>` | `1048576` | Chunk size in bytes (1MB; max 256MB) | `--chunk-size 4096` |
| `--recipient <X25519_PUB>` | - | Additional HPKE recipient (`x25519:<base64>`); repeatable | `--recipient "x25519:..."` |
| `--sign-only` | - | Plaintext chunks, no encryption (cannot combine with `--recipient`) | `--sign-only` |
| `--unencrypted` | - | Read a plaintext key bundle without a passphrase prompt (CI only) | `--unencrypted` |
| `--backend <BACKEND>` | `software` | Signing backend: `software` or `yubikey` (yubikey requires `--sign-only`) | `--backend yubikey` |
| `--slot <SLOT>` | `9c` | YubiKey PIV slot (yubikey backend) | `--slot 9c` |
| `--seed <U64>` | - | Seed the RNG for deterministic output (testing/CI; not secure) | `--seed 42` |

#### Profile-specific flags

| Profile | Flags |
|---------|-------|
| `cam.video` | `--fps` (default 30), `--chunk-seconds` (default 2.0) |
| `sensor` | `--sample-rate`, `--unit`, `--sensor-model` (required); `--latitude`, `--longitude`, `--altitude` (optional) |
| `audio` | `--sample-rate`, `--bit-depth`, `--channels`, `--codec` (all required) |
| `log` | `--application`, `--host`, `--log-level`, `--log-format` (all required) |
| `generic` | `--data-type`, `--source`, `--description`, `--mime-type` (all optional) |

#### Example Usage

```bash
# Basic archive (generic profile; auto-generates device.key + device.pub; encrypted)
seal wrap --in recording.bin --out recording.seal --device-key device.key

# Security camera archive
seal wrap \
  --in security_feed.bin \
  --out evidence.seal \
  --profile cam.video \
  --fps 60 \
  --chunk-seconds 2.0 \
  --device-key device.key

# Also readable by an auditor (extra HPKE recipient)
seal wrap \
  --in recording.bin \
  --out recording.seal \
  --device-key device.key \
  --recipient "x25519:<auditor-pub>"

# Signed-but-unencrypted archive (plaintext chunks)
seal wrap --sign-only --in recording.bin --out recording.seal --device-key device.key

# Sensor archive with geo metadata
seal wrap \
  --in data.csv \
  --out sensor.seal \
  --profile sensor \
  --sample-rate 100 \
  --unit celsius \
  --sensor-model DHT22 \
  --latitude 40.7 --longitude=-74.0 \
  --device-key device.key
```

### seal verify - Verify Archives

Verify the cryptographic integrity of a .seal archive. Verification is
**public-key only** and rejects any archive that is not `trst_version` 0.2.0.

```bash
seal verify <ARCHIVE> --device-pub <PUBLIC_KEY> [--json] [--emit-receipt <PATH>]
```

#### Arguments

| Argument | Description | Example |
|----------|-------------|---------|
| `<ARCHIVE>` | Path to .seal archive directory | `recording.seal` |
| `--device-pub <KEY>` | Signer public key: `ed25519:<base64>` or `ecdsa-p256:<base64>` (a bare key is treated as ed25519) | `--device-pub "ed25519:GAUp..."` |
| `--json` | Emit the verification report as JSON to stdout | `--json` |
| `--emit-receipt <PATH>` | Write a JSON verification receipt to a file | `--emit-receipt receipt.json` |

A V2 `.pub` file has two lines, so pass the Ed25519 line explicitly rather than
`$(cat device.pub)`.

#### Verification Process

1. **Version check** - Reject non-`0.2.0` archives
2. **Signature Verification** - Ed25519/ECDSA-P256 signature validation against the canonical manifest
3. **Continuity + Integrity** - BLAKE3 chunk hashes and continuity chain validation

#### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Verification passed |
| `10` | Signature verification failed |
| `11` | Continuity chain verification failed |
| `12` | Integrity / schema / IO error (bad archive, missing chunk, unsupported version) |
| `14` | Internal canonicalization error |
| `1` | General error |

#### Example Usage

```bash
# Basic verification (pass the ed25519 line from the two-line .pub)
seal verify recording.seal --device-pub "$(grep '^ed25519:' device.pub)"

# JSON output plus a written receipt
seal verify evidence.seal \
  --device-pub "$(grep '^ed25519:' device.pub)" \
  --json --emit-receipt receipt.json
```

#### Verification Output

```
Signature: PASS
Continuity: PASS
Segments: 16  Duration(s): 32.0  Chunk(s): 2.0
```

### seal unwrap - Decrypt Archives

Decrypt a .seal archive and recover the original data. **Any recipient** of the
archive decrypts with its own key bundle (the device owner, or an auditor added
via `--recipient` at wrap time). The signature is always verified against the
manifest's embedded `device.public_key`; `--device-pub` optionally pins which
signer you expect.

```bash
seal unwrap <ARCHIVE> --device-key <KEY_PATH> --out <OUTPUT> [--device-pub <KEY>] [--unencrypted]
```

| Argument | Description |
|----------|-------------|
| `<ARCHIVE>` | Path to .seal archive directory |
| `--device-key <PATH>` | Path to the recipient's own key bundle (device owner or auditor) |
| `--out <PATH>` | Output path for recovered data |
| `--device-pub <KEY>` | Optional expected signer (`ed25519:<base64>`); fails if it differs from the manifest's signer |
| `--unencrypted` | Read a plaintext key bundle without a passphrase prompt (CI/automation only) |

```bash
# Recover data from an archive (passphrase prompted if the key bundle is encrypted)
seal unwrap recording.seal --device-key device.key --out recovered.bin

# Recover and pin the expected signer
seal unwrap recording.seal \
  --device-key device.key \
  --device-pub "$(grep '^ed25519:' device.pub)" \
  --out recovered.bin

# Recover with an unencrypted key bundle (CI)
seal unwrap recording.seal --device-key device.key --out recovered.bin --unencrypted
```

### seal emit-request - Submit for Verification

Submit an archive to a Sealedge platform server for remote verification.

```bash
seal emit-request --archive <PATH> --device-pub <PUB_FILE> --out <PATH> [--post <URL>]
```

| Option | Description |
|--------|-------------|
| `--archive <PATH>` | Path to .seal archive directory |
| `--device-pub <PATH>` | Path to the device `.pub` file (the Ed25519 line is selected) |
| `--out <PATH>` | Output path for the JSON verification request |
| `--post <URL>` | POST the request to this platform endpoint |

```bash
# Write request to file
seal emit-request --archive archive.seal --device-pub device.pub --out request.json

# Submit directly to platform server
seal emit-request --archive archive.seal --device-pub device.pub --out request.json --post http://localhost:3001/v1/verify
```

---

## Encrypted Key Files

A device key **bundle** — an Ed25519 signing key plus an independent X25519
key-agreement key — is stored together as a `SEALEDGE-KEY-V2` file, encrypted at
rest using PBKDF2-HMAC-SHA256 (600k iterations) + AES-256-GCM. A passphrase is
prompted at runtime. (Legacy single-key `SEALEDGE-KEY-V1` files are rejected —
re-run `seal keygen`.)

For CI/automation where interactive prompts are not possible, use `--unencrypted`:
- `seal keygen --unencrypted` — generates a plaintext key bundle
- `seal wrap --unencrypted` — reads a plaintext key bundle without a passphrase prompt
- `seal unwrap --unencrypted` — reads a plaintext key bundle without a passphrase prompt

**Production devices should always use encrypted key files.** The `--unencrypted` flag is an explicit escape hatch.

---

## Core Encryption System

The `sealedge` command provides envelope encryption, key management, and network operations.

### sealedge - Envelope Encryption

Encrypt and decrypt files using AES-256-GCM with metadata preservation.

```bash
sealedge [OPTIONS]
```

#### Core Operations

| Option | Description | Example |
|--------|-------------|---------|
| `-i, --input <INPUT>` | Input file (any binary data) | `--input document.pdf` |
| `-o, --out <OUT>` | Output file path. **Required in both modes** — in encrypt mode it receives a round-trip plaintext copy (use `/dev/null` to discard) | `--out decrypted.pdf` |
| `--envelope <ENVELOPE>` | Write the encrypted envelope (a `.trst` file) to this path | `--envelope encrypted.trst` |
| `--decrypt` | Decrypt mode (read from --input, write to --out) | `--decrypt` |

#### Chunk Configuration

| Option | Default | Description | Example |
|--------|---------|-------------|---------|
| `--chunk <SIZE>` | `4096` | Chunk size in bytes | `--chunk 8192` |
| `--no-plaintext` | - | Skip plaintext output (encrypt only) | `--no-plaintext` |

#### Key Management

| Option | Description | Example |
|--------|-------------|---------|
| `--key-hex <KEY>` | 64 hex chars (32 bytes) AES-256 key | `--key-hex 0123456789abcdef...` |
| `--key-out <PATH>` | Save generated key to file | `--key-out mykey.hex` |
| `--set-passphrase <PASS>` | Store passphrase in OS keyring | `--set-passphrase "secure_phrase"` |
| `--salt-hex <SALT>` | 32 hex chars (16 bytes) for key derivation | `--salt-hex "abcdef..."` |
| `--use-keyring` | Use keyring passphrase + salt for key | `--use-keyring` |

#### Format Options

| Option | Description | Example |
|--------|-------------|---------|
| `--inspect` | Show metadata without decryption | `--inspect` |
| `--force-raw` | Force raw output regardless of detected type | `--force-raw` |
| `--verbose` | Enable verbose format details | `--verbose` |

#### Example Usage

```bash
# Basic file encryption (--out receives a round-trip copy; /dev/null discards it)
sealedge --input document.pdf --out /dev/null --envelope encrypted.trst --key-out mykey.hex

# Decrypt file
sealedge --decrypt --input encrypted.trst --out recovered.pdf --key-hex $(cat mykey.hex)

# Encrypt with keyring
sealedge --set-passphrase "my_secure_passphrase"
sealedge --input file.txt --out /dev/null --envelope file.trst --use-keyring --salt-hex "abcdef1234567890abcdef1234567890"

# Inspect without decryption
sealedge --input encrypted.trst --inspect
```

### Network Operations

Sealedge supports secure client-server communication with mutual authentication.

#### Server Mode

```bash
sealedge-server --listen <ADDRESS> [OPTIONS]
```

| Option | Description | Example |
|--------|-------------|---------|
| `--listen <ADDR>` | Server bind address | `--listen 127.0.0.1:8080` |
| `--require-auth` | Enable mutual authentication | `--require-auth` |
| `--decrypt` | Auto-decrypt received files | `--decrypt` |
| `--key-hex <KEY>` | Shared encryption key | `--key-hex $(openssl rand -hex 32)` |

#### Client Mode

```bash
sealedge-client --server <ADDRESS> [OPTIONS]
```

| Option | Description | Example |
|--------|-------------|---------|
| `--server <ADDR>` | Server address | `--server 127.0.0.1:8080` |
| `--file <FILE>` | File to send | `--file document.txt` |
| `--enable-auth` | Use mutual authentication (server enables it with `--require-auth`) | `--enable-auth` |
| `--server-cert <PATH>` | Trusted server certificate (for auth) | `--server-cert server.cert` |
| `--key-hex <KEY>` | Shared encryption key (no-auth mode only) | `--key-hex $(cat shared.key)` |

With authentication the session key is derived via X25519 ECDH, so `--key-hex` is
only needed in the no-auth mode.

#### Network Example

```bash
# Authenticated: server requires auth, client enables it (no shared key needed)
sealedge-server --listen 127.0.0.1:8080 --require-auth --decrypt
sealedge-client --server 127.0.0.1:8080 --file file.txt --enable-auth --server-cert sealedge-server.cert

# No-auth: both sides share the same AES-256 key
sealedge-server --listen 127.0.0.1:8080 --decrypt --key-hex $(openssl rand -hex 32)
sealedge-client --server 127.0.0.1:8080 --file file.txt --key-hex $(cat shared.key)
```

---

## Complete Workflows

### Signed Evidence Archives with a Shared Device Key

Sign multiple evidence archives with one device key so they all verify against
the same public key. (There is no archive-chaining flag; each archive is
independently signed and verified.)

```bash
# Generate one device key bundle for the source device
seal keygen --out-key device.key --out-pub device.pub

# Wrap each piece of evidence with that key
seal wrap --in evidence_001.bin --out evidence_001.seal --device-key device.key
seal wrap --in evidence_002.bin --out evidence_002.seal --device-key device.key

# Verify each archive (pass the ed25519 line from the two-line .pub)
seal verify evidence_001.seal --device-pub "$(grep '^ed25519:' device.pub)"
seal verify evidence_002.seal --device-pub "$(grep '^ed25519:' device.pub)"
```

### Hybrid Encryption + Archive

Combine envelope encryption with the archive format:

```bash
# Encrypt sensitive data into an envelope (--out discards the round-trip copy)
sealedge --input sensitive.pdf --out /dev/null --envelope encrypted.trst --key-out secret.key

# Archive the encrypted envelope (default generic profile; sign-only keeps it as-is)
seal wrap --sign-only --in encrypted.trst --out archived.seal --device-key device.key

# Verify archive integrity
seal verify archived.seal --device-pub "$(grep '^ed25519:' device.pub)"

# Recover the envelope, then decrypt it
seal unwrap archived.seal --device-key device.key --out encrypted.trst
sealedge --decrypt --input encrypted.trst --out recovered.pdf --key-hex $(cat secret.key)
```

### Network + Archive Pipeline

Stream data over the network, then archive it:

```bash
# Server: receive and decrypt into a directory
sealedge-server --listen 127.0.0.1:8080 --decrypt --key-hex $(cat shared.key) --output-dir received/ &
SERVER_PID=$!

# Client: send data
sealedge-client --server 127.0.0.1:8080 --file data.bin --key-hex $(cat shared.key)

# Archive the received data
seal wrap --in received/data.bin --out network_archive.seal --device-key device.key

# Cleanup
kill $SERVER_PID
```

---

## Error Handling

### Archive Verification Errors

| Error Type | Description | Solution |
|------------|-------------|----------|
| `signature error` | Ed25519 signature validation failed | Check device public key, verify archive integrity |
| `missing chunk` | Required chunk file not found | Check archive completeness, file permissions |
| `hash mismatch` | Chunk content doesn't match expected hash | Archive corrupted, re-create from source |
| `unexpected end` | Archive truncated or malformed | Check for incomplete transfers, storage issues |

### Encryption Errors

| Error Type | Description | Solution |
|------------|-------------|----------|
| `Invalid key length` | AES key not 32 bytes (64 hex chars) | Verify key format and length |
| `Decryption failed` | Wrong key or corrupted data | Check key correctness, file integrity |
| `Format error` | Unrecognized envelope format | Verify file is Sealedge format |

### Network Errors

| Error Type | Description | Solution |
|------------|-------------|----------|
| `Connection refused` | Server not reachable | Check server status, network connectivity |
| `Authentication failed` | Mutual auth rejected | Verify certificates, key compatibility |
| `Protocol error` | Communication protocol mismatch | Ensure compatible Sealedge versions |

### Debugging Commands

```bash
# Run with debug logging
RUST_LOG=debug sealedge --input file.txt --out /dev/null --envelope test.trst --key-out test.key 2>&1 | head -20

# Test archive validation
cargo test -p sealedge-seal-cli --test acceptance -- --nocapture

# Check network connectivity
telnet 127.0.0.1 8080

# Verify YubiKey hardware
ykman piv info
```

---

## Performance Notes

- **Chunk Size**: Larger chunks (1MB+) improve throughput, smaller chunks (4KB) reduce memory usage
- **Network**: Use authentication for production, skip for high-throughput scenarios
- **Archive**: Ed25519 signing adds ~1ms per archive, BLAKE3 hashing is very fast
- **Memory**: Streaming design maintains <50MB RAM regardless of file size

For additional examples and advanced usage, see [Examples Index](examples/README.md).

---

*This document is part of the Sealedge project documentation.*

**📖 Links:**
- **[Sealedge Home](https://github.com/TrustEdge-Labs/sealedge)** - Main repository
- **[Sealedge Labs](https://github.com/TrustEdge-Labs)** - Organization profile
- **[Documentation](https://github.com/TrustEdge-Labs/sealedge/tree/main/docs)** - Complete docs
- **[Issues](https://github.com/TrustEdge-Labs/sealedge/issues)** - Bug reports & features

**⚖️ Legal:**
- **Copyright**: © 2025 Sealedge Labs LLC
- **License**: Mozilla Public License 2.0 ([MPL-2.0](https://mozilla.org/MPL/2.0/))
- **Commercial**: [Enterprise licensing available](mailto:enterprise@trustedgelabs.com)