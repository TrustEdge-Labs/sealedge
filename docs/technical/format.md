<!--
Copyright (c) 2025 TRUSTEDGE LABS LLC
MPL-2.0: https://mozilla.org/MPL/2.0/
Project: sealedge — Privacy and trust at the edge.
GitHub: https://github.com/TrustEdge-Labs/sealedge
-->

# Sealedge Format Specification v2.0

**Version:** 2.0
**Date:** March 2026
**Status:** Stable

> **Related Documentation**: For security considerations and vulnerability reporting, see [`SECURITY.md`](../../SECURITY.md)

## Overview

This document defines the binary format for Sealedge `.seal` envelope files. The format provides authenticated encryption with provenance for chunked data streams, designed for privacy-preserving edge computing.

**Version 2.0 Changes:**
- **Algorithm Agility**: Header expanded from 58 to 66 bytes with dedicated algorithm fields
- **Forward Compatibility**: Automatic V1→V2 migration with default algorithm mapping
- **Parse-time Validation**: Reject unknown/unsupported algorithm IDs at parse time

---

## 1. File Structure

A `.seal` file consists of:

```
[Preamble] [StreamHeader] [Record]* 
```

- **Preamble**: Magic bytes and version (5 bytes)
- **StreamHeader**: Session metadata (variable length, bincode-encoded)  
- **Record**: Zero or more encrypted data records (variable length each, bincode-encoded)

---

## 2. Preamble (5 bytes)

```
Offset | Size | Field   | Description
-------|------|---------|----------------------------------
0      | 4    | MAGIC   | Magic bytes: "SEAL" (0x5345414C)
4      | 1    | VERSION | Format version: 0x02 (0x01 legacy)
```

**Byte Order**: Fixed bytes, no endianness concerns.

**Validation**:
- MAGIC must exactly match `[0x53, 0x45, 0x41, 0x4C]` ("SEAL")
- VERSION must be `0x01` (legacy) or `0x02` (current) for this specification

**Failure Modes**:
- **Invalid Magic**: Not a Sealedge file, abort parsing
- **Unsupported Version**: Future/unknown format, abort parsing

**Version Migration**:
- V1 files (58-byte headers) automatically migrate to V2 (66-byte headers) with default algorithms

---

## 3. StreamHeader (Variable Length)

The StreamHeader is bincode-encoded with the following structure:

```rust
struct StreamHeader {
    v: u8,                   // Stream format version (0x02, 0x01 legacy)
    header: Vec<u8>,         // File header bytes (66 bytes V2, 58 bytes V1)
    header_hash: [u8; 32],   // BLAKE3 hash of header bytes
}
```

### 3.1. Embedded FileHeader (66 bytes V2, 58 bytes V1)

The `header` field contains a FileHeader with **algorithm agility**:

**V2 Format (66 bytes) - Current:**
```
Offset | Size | Field         | Description
-------|------|---------------|--------------------------------
0      | 1    | version       | File format version (0x02)
1      | 1    | aead_alg      | AEAD algorithm ID (1=AES-256-GCM, 2=ChaCha20-Poly1305, 3=AES-256-SIV)
2      | 1    | sig_alg       | Signature algorithm ID (1=Ed25519, 2=ECDSA-P256, 3=ECDSA-P384, 4=RSA-PSS-2048, 5=RSA-PSS-4096, 6=Dilithium3, 7=Falcon512)
3      | 1    | hash_alg      | Hash algorithm ID (1=BLAKE3, 2=SHA-256, 3=SHA-384, 4=SHA-512, 5=SHA3-256, 6=SHA3-512)
4      | 1    | kdf_alg       | KDF algorithm ID (1=PBKDF2-SHA256, 2=Argon2id, 3=Scrypt, 4=HKDF)
5      | 3    | reserved      | Reserved for future use (must be zero)
8      | 16   | key_id        | Key identifier
24     | 32   | device_id_hash| BLAKE3(device_id || salt)
56     | 4    | nonce_prefix  | Random nonce prefix for session
60     | 4    | chunk_size    | Chunk size in bytes (big-endian)
```

**V1 Format (58 bytes) - Legacy:**
```
Offset | Size | Field         | Description
-------|------|---------------|--------------------------------
0      | 1    | version       | File format version (0x01)
1      | 1    | alg           | Algorithm ID (0x01 = AES-256-GCM only)
2      | 16   | key_id        | Key identifier
18     | 32   | device_id_hash| BLAKE3(device_id || salt)
50     | 4    | nonce_prefix  | Random nonce prefix for session
54     | 4    | chunk_size    | Chunk size in bytes (big-endian)
```

**Byte Order**: All multi-byte fields are **big-endian** except where noted.

**Validation**:
- V2: `header` must be exactly 66 bytes, V1: `header` must be exactly 58 bytes
- `header_hash` must equal `BLAKE3(header)`
- FileHeader fields must pass individual validation (see below)
- Algorithm IDs must be supported (parse-time validation)

**Failure Modes**:
- **Wrong Header Length**: Not 66 bytes (V2) or 58 bytes (V1), abort parsing
- **Hash Mismatch**: Header corrupted or tampered, abort parsing
- **Unsupported Algorithm**: Unknown algorithm ID, abort parsing

**Algorithm Migration**:
- V1 files automatically upgrade to V2 with: AEAD=AES-256-GCM, Signature=Ed25519, Hash=BLAKE3, KDF=PBKDF2-SHA256

---

## 4. Record (Variable Length)

Each Record is bincode-encoded with this structure:

```rust
struct Record {
    seq: u64,                    // Sequence number (starts at 1)
    nonce: [u8; 12],            // AES-GCM nonce: prefix(4) || counter(8)
    sm: SignedManifest,         // Signed manifest
    ct: Vec<u8>,                // AES-GCM ciphertext + tag
}
```

### 4.1. SignedManifest

```rust
struct SignedManifest {
    manifest: Vec<u8>,          // bincode(Manifest)
    sig: Vec<u8>,              // Ed25519 signature (64 bytes, domain-separated)
    pubkey: Vec<u8>,           // Ed25519 public key (32 bytes)
}
```

**Signature Domain Separation**: The Ed25519 signature is computed with domain separation to prevent cross-context signature reuse:

```
signature_input = b"sealedge.manifest.v1" || manifest_bytes
signature = Ed25519.sign(signature_input)
```

This ensures signatures are cryptographically bound to Sealedge manifest context and cannot be reused in other protocols or systems.

### 4.2. Manifest

```rust
struct Manifest {
    v: u8,                     // Manifest version (0x01)
    ts_ms: u64,               // Timestamp (milliseconds since UNIX epoch)
    seq: u64,                 // Sequence number (must match Record.seq)
    header_hash: [u8; 32],    // Must match StreamHeader.header_hash
    pt_hash: [u8; 32],        // BLAKE3 hash of plaintext chunk
    key_id: [u8; 16],         // Must match FileHeader.key_id
    ai_used: bool,            // AI processing flag (placeholder)
    model_ids: Vec<String>,   // Model identifiers (placeholder)
    data_type: DataType,      // Data type and format metadata
    chunk_len: u32,           // Expected plaintext length (cryptographically bound via AAD)
}
```

**Security Enhancement**: The `chunk_len` field is cryptographically bound to the ciphertext via AAD, preventing length manipulation attacks and enabling early bounds checking before decryption.

**Byte Order**: 
- `seq`, `ts_ms`, `chunk_len`: Little-endian (bincode default)
- Nonce counter (last 8 bytes): **Big-endian** to match sequence

---

## 5. Cryptographic Layout

### 5.1. Nonce Construction

```
nonce = nonce_prefix(4) || sequence_be(8)
```

- `nonce_prefix`: From FileHeader, fixed per session
- `sequence_be`: Record sequence as 8-byte big-endian integer

**Constraints**:
- Nonce must be unique per key
- Sequence numbers must be contiguous starting from 1
- All records in a stream must use the same nonce_prefix

### 5.2. AAD (Additional Authenticated Data)

```
AAD = header_hash(32) || seq_be(8) || nonce(12) || manifest_hash(32) || chunk_len_be(4)
```

Total length: 88 bytes

**Construction**:
1. `header_hash`: StreamHeader.header_hash (32 bytes)
2. `seq_be`: Record sequence as big-endian u64 (8 bytes)  
3. `nonce`: Full 12-byte nonce (4 bytes prefix + 8 bytes counter)
4. `manifest_hash`: BLAKE3(SignedManifest.manifest) (32 bytes)
5. `chunk_len_be`: Expected plaintext length as big-endian u32 (4 bytes)

**Security Properties**:
- Cryptographically binds chunk length to prevent manipulation
- Enables pre-decryption validation of expected plaintext size
- Provides early detection of malformed or oversized chunks

### 5.3. AES-GCM Encryption

```
ciphertext = AES256-GCM.encrypt(
    key: [u8; 32],
    nonce: [u8; 12], 
    plaintext: chunk_data,
    aad: AAD
)
```

The resulting ciphertext includes the authentication tag (16 bytes appended).

---

## 6. Validation Rules

### 6.1. Stream-Level Invariants

1. **Magic and Version**: Must match expected values (VERSION=0x02 current, 0x01 legacy)
2. **Header Hash**: StreamHeader.header_hash must equal BLAKE3(StreamHeader.header)
3. **Header Length**: FileHeader must be exactly 66 bytes (V2) or 58 bytes (V1)
4. **Algorithm Validation**: All algorithm IDs must be supported (parse-time validation)
5. **Sequence Contiguity**: Record sequences must start at 1 and increment by 1
6. **Chunk Size Bounds**: FileHeader.chunk_size must be > 0 and ≤ 128MB
7. **Stream Size Limits**: Total stream size must not exceed 10GB
8. **Record Count Limits**: Maximum 1,000,000 records per stream

### 6.2. Algorithm Validation

**AEAD Algorithms (aead_alg field):**
- 1 = AES-256-GCM (default)
- 2 = ChaCha20-Poly1305  
- 3 = AES-256-SIV (future quantum resistance)
- Others = Unsupported, abort parsing

**Signature Algorithms (sig_alg field):**
- 1 = Ed25519 (default)
- 2 = ECDSA-P256
- 3 = ECDSA-P384  
- 4 = RSA-PSS-2048
- 5 = RSA-PSS-4096
- 6 = Dilithium3 (post-quantum)
- 7 = Falcon512 (post-quantum)
- Others = Unsupported, abort parsing

**Hash Algorithms (hash_alg field):**
- 1 = BLAKE3 (default)
- 2 = SHA-256
- 3 = SHA-384
- 4 = SHA-512
- 5 = SHA3-256
- 6 = SHA3-512
- Others = Unsupported, abort parsing

**KDF Algorithms (kdf_alg field):**
- 1 = PBKDF2-SHA256 (default)
- 2 = Argon2id
- 3 = Scrypt
- 4 = HKDF
- Others = Unsupported, abort parsing

### 6.3. Record-Level Invariants

1. **Nonce Prefix**: Record.nonce[0..4] must equal FileHeader.nonce_prefix
2. **Nonce Counter**: Record.nonce[4..12] must equal Record.seq (big-endian)
3. **Manifest Sequence**: Manifest.seq must equal Record.seq
4. **Header Hash Binding**: Manifest.header_hash must equal StreamHeader.header_hash
5. **Key ID Binding**: Manifest.key_id must equal FileHeader.key_id
6. **Domain-Separated Signature**: Ed25519 signature must verify over domain-separated message:
   ```
   verify_input = b"sealedge.manifest.v1" || manifest_bytes
   Ed25519.verify(verify_input, signature, public_key) == valid
   ```
7. **Public Key**: Must be valid Ed25519 public key (32 bytes)
8. **Plaintext Hash**: After decryption, BLAKE3(plaintext) must equal Manifest.pt_hash
9. **Chunk Length Bounds**: Manifest.chunk_len must be > 0 and ≤ FileHeader.chunk_size
10. **Ciphertext Size Bounds**: Record.ct.len() must be ≤ chunk_size + 16 (AES-GCM tag)
11. **Decrypted Length Validation**: len(decrypted_plaintext) must equal Manifest.chunk_len

### 6.3. Cryptographic Invariants

1. **AES-GCM**: Must decrypt and authenticate successfully
2. **AAD Construction**: Must be built correctly from components
3. **Nonce Uniqueness**: No nonce reuse within a key's lifetime

---

## 7. Error Handling

### 7.1. Parse Errors

| Error | Cause | Action |
|-------|-------|--------|
| `BadMagic` | MAGIC ≠ "SEAL" | Abort, not a Sealedge file |
| `UnsupportedVersion` | VERSION ∉ {0x01, 0x02} | Abort, format not supported |
| `HeaderLengthMismatch` | Header ≠ 66 bytes (V2) or 58 bytes (V1) | Abort, corrupted stream |
| `HeaderHashMismatch` | Hash verification failed | Abort, corrupted/tampered |
| `UnsupportedAlgorithm` | Unknown algorithm ID | Abort, algorithm not supported |
| `BincodeError` | Deserialization failed | Abort, corrupted data |

### 7.2. Validation Errors

| Error | Cause | Action |
|-------|-------|--------|
| `NoncePrefix Mismatch` | Record prefix ≠ header prefix | Reject record |
| `NonceCounterMismatch` | Nonce counter ≠ sequence | Reject record |
| `SequenceMismatch` | Manifest.seq ≠ Record.seq | Reject record |
| `HeaderHashMismatch` | Manifest binding failed | Reject record |
| `KeyIdMismatch` | Manifest.key_id ≠ FileHeader.key_id | Reject record |
| `SignatureFailure` | Ed25519 verification failed | Reject record |
| `DecryptionFailure` | AES-GCM decrypt/auth failed | Reject record |
| `PlaintextHashMismatch` | Decrypted hash ≠ manifest | Reject record |
| `SequenceGap` | Non-contiguous sequence | Reject record |
| `ChunkSizeExceeded` | chunk_size > MAX_CHUNK_SIZE | Reject stream |
| `ChunkLengthInvalid` | chunk_len > chunk_size or = 0 | Reject record |
| `CiphertextOversized` | ct.len() > chunk_size + 16 | Reject record |
| `LengthMismatch` | decrypted_len ≠ chunk_len | Reject record |
| `StreamSizeExceeded` | Total size > 10GB | Reject stream |
| `RecordCountExceeded` | Records > 1,000,000 | Reject stream |

### 7.3. Failure Semantics

- **Parse Errors**: Entire file is invalid, stop processing
- **Validation Errors**: Reject individual record, may continue with next
- **Security Policy**: Fail-closed, reject on any cryptographic failure

---

## 8. Test Vectors

### 8.1. Deterministic Test Vector

Sealedge includes deterministic test vectors to validate format compliance:

**Test Parameters:**
- **AES-256 Key**: `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f` (hex)
- **Ed25519 Seed**: `4242424242424242424242424242424224242424242424242424242424242424` (hex)
- **Nonce Prefix**: `aabbccdd` (hex)
- **Key ID**: `TEST_KEY_ID_16B!` (ASCII)
- **Input Size**: 32,768 bytes (deterministic pseudo-random)
- **Chunk Size**: 4,096 bytes

**Golden Hash:**
```
BLAKE3(.seal) = 8ecc3b2fcb0887dfd6ff3513c0caa3febb2150a920213fa5b622243ad530f34c
```

**Usage:**
- Run `cargo test vectors::tests::golden_trst_digest_is_stable` to verify format compliance
- Any intentional format changes require updating the golden hash
- External implementations can use these vectors for validation

### 8.2. Integration Testing

The implementation includes comprehensive integration tests:

1. **Round-trip Test**: Encrypt → envelope → decrypt with known keys
2. **Tamper Detection**: Verify corrupted envelopes fail validation  
3. **CLI Testing**: End-to-end testing via command-line interface

**Test Location**: [`src/vectors.rs`](sealedge-core/src/vectors.rs) and [`tests/roundtrip_integration.rs`](sealedge-core/tests/roundtrip_integration.rs)

---

## 9. Implementation Notes

### 8.1. Bincode Encoding

- Uses bincode's default configuration (little-endian integers)
- Length-prefixed for variable-length fields (strings, vectors)
- No custom serialization logic required

### 8.2. BLAKE3 Hashing

- Standard BLAKE3 with 256-bit (32-byte) output
- No custom parameters or salt
- Used for header hash, manifest hash, and plaintext hash

### 8.3. Ed25519 Signatures

- Standard Ed25519 as per RFC 8032
- 64-byte signatures, 32-byte public keys
- Signs over the raw bincode(Manifest) bytes

### 8.4. Memory Considerations

- Records can be processed streaming (one at a time)
- No requirement to buffer entire file in memory
- Chunk size limits maximum single-record memory usage

---

## 10. Test Vectors

See Section 8 for the deterministic test vector and golden hash used to validate format compliance.

---

## 11. Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-08-25 | Initial specification |
| 2.0 | February 2026 | HKDF-SHA256 KDF, versioned envelope format, encrypted key files, algorithm agility |

Encrypted key files are now `SEALEDGE-KEY-V2` (an Ed25519 signing key plus an independent X25519 key-agreement key, encrypted at rest with PBKDF2-HMAC-SHA256 + AES-256-GCM); the earlier single-key `SEALEDGE-KEY-V1` bundle is rejected.

---

## 12. References

- [BLAKE3 Specification](https://github.com/BLAKE3-team/BLAKE3-specs)
- [Ed25519 - RFC 8032](https://tools.ietf.org/html/rfc8032)
- [AES-GCM - NIST SP 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [Bincode Documentation](https://docs.rs/bincode/)

---

**See Also:**
- [`src/format.rs`](sealedge-core/src/format.rs) - Reference implementation
- [protocol.md](protocol.md) - Network protocol specification
- [threat-model.md](threat-model.md) - Security analysis

---

## Legal & Attribution

**Copyright** © 2025 TRUSTEDGE LABS LLC. All rights reserved.

**License**: This specification is licensed under the [Mozilla Public License 2.0 (MPL-2.0)](https://mozilla.org/MPL/2.0/).

**Project**: [Sealedge](https://github.com/TrustEdge-Labs/sealedge) — Privacy and trust at the edge.

**Standards Compliance**: This format specification implements [BLAKE3](https://github.com/BLAKE3-team/BLAKE3-specs), [Ed25519 RFC 8032](https://tools.ietf.org/html/rfc8032), [AES-GCM NIST SP 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final), and [Bincode](https://docs.rs/bincode/) serialization.
