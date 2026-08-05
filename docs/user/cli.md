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
  - [seal verify-chronicle - Verify Device Chronicle](#seal-verify-chronicle---verify-device-chronicle)
  - [seal witness - Request a Witness Receipt](#seal-witness---request-a-witness-receipt)
  - [seal rekey - Rotate Signing Identity](#seal-rekey---rotate-signing-identity)
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

1. **`seal`** - Archive + attestation CLI (keygen, wrap, verify, verify-chronicle, witness, rekey, unwrap, emit-request, attest-sbom, verify-attestation)
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

#### Chronicle options (linking archives over time)

By default each archive is a standalone island. These flags instead make an
archive an entry in a device **chronicle** — an append-only, hash-linked,
sequence-numbered chain — so deletion and reordering across archives become
detectable (see [`seal verify-chronicle`](#seal-verify-chronicle---verify-device-chronicle)).

| Option | Description |
|--------|-------------|
| `--chronicle <PATH>` | Read and advance a chronicle state file (the device's head pointer). An absent file starts a new chronicle at sequence 0 (genesis). After writing, the state is atomically updated to the new tip |
| `--prev-archive <PATH>` | Link onto a specific previous `.seal` (derives its digest and `sequence + 1`) |
| `--prev-hash <B3>` | Explicit previous archive digest (`b3:<hex>`); requires `--prev-seq` |
| `--prev-seq <N>` | Sequence of the previous archive (used with `--prev-hash`); the new archive is `seq N+1` |

A chronicle archive carries `sequence` and `prev_archive_hash` in its signed
manifest, plus `device.key_epoch` — the monotonic per-identity key epoch (`0` at
genesis, incremented by [`seal rekey`](#seal-rekey---rotate-signing-identity)).

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

A chronicle archive additionally carries `sequence`, `prev_archive_hash`, and
`device.key_epoch` (the monotonic per-identity key epoch — `0` at genesis,
incremented by [`seal rekey`](#seal-rekey---rotate-signing-identity)).
Single-archive `verify` reports the archive's chronicle position but **cannot**
prove linkage; use
[`seal verify-chronicle`](#seal-verify-chronicle---verify-device-chronicle) with
the full chain for that.

#### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Verification passed |
| `10` | Signature verification failed |
| `11` | Continuity chain verification failed |
| `12` | Integrity / schema / IO error (bad archive, missing chunk, unsupported version) |
| `13` | Chronicle linkage / contiguity / epoch / authorization failure ([`verify-chronicle`](#seal-verify-chronicle---verify-device-chronicle) only) |
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

### seal verify-chronicle - Verify Device Chronicle

`seal verify` proves that a single archive is authentic, but it cannot prove how
a device's archives relate to one another. `seal verify-chronicle` verifies a
**chronicle** — the per-device, append-only, hash-linked, sequence-numbered chain
of archives (and rotation entries) produced by
[`seal wrap --chronicle`](#seal-wrap---create-archives) and
[`seal rekey`](#seal-rekey---rotate-signing-identity). It detects mid-chain
deletion, reordering, and forks **offline**, and — with a witness receipt — tail
deletion.

```bash
seal verify-chronicle <PATHS...> --device-pub <ed25519:...> \
  [--witness <RECEIPT>] [--witness-jwks <URL|PATH>] [--json]
```

#### Arguments

| Argument | Description |
|----------|-------------|
| `<PATHS...>` | One or more `.seal` archives, or a directory containing them (rotation entries are picked up automatically) |
| `--device-pub <KEY>` | Expected **genesis** signer (`ed25519:<base64>`) — the identity at sequence 0. The active signer is walked forward across rotation entries, so pin the genesis key, **not** the current one |
| `--witness <PATH>` | Platform witness receipt (JWS) to cross-check the local tip against (detects tail deletion). Requires `--witness-jwks` |
| `--witness-jwks <URL\|PATH>` | Platform JWKS (URL or file path) used to verify the witness receipt |
| `--json` | Emit the report as JSON to stdout |

#### What It Checks

1. **Per-entry signature + continuity** — every archive passes the same signature
   and intra-archive continuity checks as `seal verify`.
2. **Contiguity** — sequences run `0, 1, 2, …, N` with no gaps (a gap means a
   mid-chain entry was deleted) and no duplicates (a duplicate `sequence` with a
   different digest is a fork).
3. **Hash linkage** — each entry's `prev_archive_hash` equals the BLAKE3 archive
   digest of its predecessor.
4. **Active-identity walk** — the chain begins under the genesis key; each
   dual-signed rotation entry advances the active signer and `key_epoch` (the old
   key authorizes, the new key proves possession). Every content archive must be
   signed by the active identity for its position and carry the matching
   `device.key_epoch`.
5. **Witness cross-check (optional)** — verifies the receipt against the JWKS,
   then requires the local tip to be at least as advanced as the witnessed tip. A
   local chain that is **behind** the witnessed tip means the tail was deleted.

#### Exit Codes

Same scheme as [`seal verify`](#seal-verify---verify-archives), with `13` added
for chronicle failures:

| Code | Meaning |
|------|---------|
| `0` | Chronicle verified |
| `10` | Signature verification failed |
| `11` | Continuity chain verification failed |
| `12` | Archive read / schema / IO error |
| `13` | Chronicle linkage, contiguity, epoch, or rotation-authorization failure |
| `14` | Internal canonicalization error |
| `1` | General error |

#### Example Usage

```bash
# Verify a whole chronicle directory, pinning the genesis identity
seal verify-chronicle ./chronicle/ --device-pub "$(grep '^ed25519:' genesis.pub)"

# Explicit archives, JSON report
seal verify-chronicle clip-000.seal clip-001.seal clip-002.seal \
  --device-pub "$(grep '^ed25519:' genesis.pub)" --json

# Cross-check the local tip against a platform witness receipt (detects tail deletion)
seal verify-chronicle ./chronicle/ \
  --device-pub "$(grep '^ed25519:' genesis.pub)" \
  --witness receipt.json \
  --witness-jwks http://localhost:3001/.well-known/jwks.json
```

### seal witness - Request a Witness Receipt

Submit the chronicle tip to a platform for a signed, timestamped **witness
receipt** — a JWS asserting "at `observed_at` I saw this device at
`(sequence, tip)`, consistent with my append-only record." The receipt's
**trusted timestamp** is what makes tail deletion and "when did this exist?"
answerable; witness early and often, since detection only begins at the first
witnessed tip.

```bash
seal witness --chronicle <STATE> --device-key <KEY> \
  [--rotation <DIR>] [--post <URL>] [--out <PATH>] [--unencrypted]
```

| Option | Description |
|--------|-------------|
| `--chronicle <PATH>` | Chronicle state file whose tip to witness |
| `--device-key <PATH>` | Device key bundle that signs the witness request |
| `--rotation <DIR>` | Rotation entry directory to attach when the tip being witnessed is a rotation (see [`seal rekey`](#seal-rekey---rotate-signing-identity)) — lets the platform verify it and record the device's `old → new` key lineage |
| `--post <URL>` | Platform `/v1/witness` endpoint to submit to |
| `--out <PATH>` | With `--post`: write the returned receipt. Without `--post`: write the signed request for offline submission (mirrors `emit-request`) |
| `--unencrypted` | Read a plaintext key bundle without a passphrase prompt (CI/automation only) |

```bash
# Submit the current tip and save the returned receipt
seal witness --chronicle device.chronicle --device-key device.key \
  --post http://localhost:3001/v1/witness --out receipt.json

# Emit a signed request only (no network), for offline submission
seal witness --chronicle device.chronicle --device-key device.key --out request.json

# Witness a chronicle whose tip is a rotation entry, so the platform records lineage
seal witness --chronicle device.chronicle --device-key device2.key \
  --rotation rotation-001.seal \
  --post http://localhost:3001/v1/witness --out receipt.json
```

### seal rekey - Rotate Signing Identity

Rotate a chronicle to a new signing identity. `rekey` appends a **rotation
entry** — a dedicated chronicle entry, co-signed by the old key (which authorizes
the successor) and the new key (which proves possession) — that advances the
active identity and increments `device.key_epoch`. Later
[`seal wrap --chronicle`](#seal-wrap---create-archives) archives are signed by the
new key and stamped with the incremented epoch, and
[`seal verify-chronicle`](#seal-verify-chronicle---verify-device-chronicle)
follows the rotation without trusting any platform.

```bash
seal rekey --chronicle <STATE> --old-key <OLD> --new-key <NEW> --out <DIR.seal> [--unencrypted]
```

| Option | Description |
|--------|-------------|
| `--chronicle <PATH>` | Chronicle state file to rotate and advance. Must already exist — run `seal wrap --chronicle` first (there is nothing to rotate on an empty chronicle) |
| `--old-key <PATH>` | Current device key bundle; its signing key must match the chronicle's active signer. Authorizes the successor |
| `--new-key <PATH>` | Pre-generated new `SEALEDGE-KEY-V2` bundle (run `seal keygen` first). Proves possession — `rekey` does **not** generate it |
| `--out <PATH>` | Output directory for the rotation entry (contains `rotation.json`); place it in the chronicle alongside the `.seal` archives |
| `--unencrypted` | Read plaintext key bundles without a passphrase prompt (CI/automation only) |

The new key's epoch is always `old.key_epoch + 1`.

```bash
# 1. Generate the successor identity up front
seal keygen --out-key device2.key --out-pub device2.pub

# 2. Rotate the chronicle onto it (dual-signed rotation entry)
seal rekey --chronicle device.chronicle \
  --old-key device.key --new-key device2.key \
  --out rotation-001.seal

# 3. Subsequent archives are signed by the new key (key_epoch = 1)
seal wrap --in next.bin --out clip-008.seal \
  --device-key device2.key --chronicle device.chronicle

# 4. Verify the whole chain — still pinned to the GENESIS key
seal verify-chronicle ./chronicle/ --device-pub "$(grep '^ed25519:' device.pub)"
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