<!--
Copyright (c) 2025 TRUSTEDGE LABS LLC
MPL-2.0: https://mozilla.org/MPL/2.0/
Project: sealedge — Privacy and trust at the edge.
GitHub: https://github.com/TrustEdge-Labs/sealedge
-->

# Sealedge Protocol Specification

**Version:** 1.0 (Stable)
**Date:** August 28, 2025

> **Related Documentation**: For security policies and vulnerability reporting, see [`SECURITY.md`](../../SECURITY.md)

## Overview

This document describes the wire format and network protocol for chunk transfer between Sealedge clients and servers. The protocol provides privacy-preserving, authenticated, and integrity-checked streaming of data with comprehensive validation and tamper detection.

**Key Features:**
- **TCP-based transport** with QUIC/TLS support (webpki-roots, secure-by-default)
- **Length-prefixed message framing** for reliable parsing
- **Comprehensive validation** with strict security invariants
- **Real-time processing** with ACK/response flow
- **Complete tamper detection** preventing replay and reordering attacks
- **Automated key exchange** via X25519 ECDH during authentication handshake

---

## 1. Transport Layer

- **Primary:** TCP with comprehensive validation and error handling
- **QUIC/TLS:** Implemented with webpki-roots for production TLS; `insecure-tls` feature flag for development
- **Connection Management:** Configurable timeouts, automatic retry logic, and graceful shutdown
- **Message Framing:** Length-prefixed (u32, little-endian) followed by bincode-encoded payload
- **Flow Control:** ACK/response protocol with error reporting

### 1.1. Connection Resilience

**Client Connection Features:**
- **Connection Timeouts:** Configurable connection establishment timeout (default: 10 seconds)
- **Retry Logic:** Automatic retry with exponential backoff (default: 3 attempts)
- **Operation Timeouts:** Chunk send timeout (30s) and ACK read timeout (10s)
- **Error Recovery:** Comprehensive error context and recovery guidance

**Server Connection Features:**
- **Graceful Shutdown:** SIGINT/SIGTERM handling with connection completion
- **Connection Tracking:** Per-connection state management and cleanup
- **Resource Management:** Proper cleanup of active connections during shutdown

---

## 2. Message Types

### 2.1. NetworkChunk

Each chunk sent over the wire is serialized as a `NetworkChunk` struct (bincode encoding):

```rust
struct NetworkChunk {
    sequence: u64,           // Chunk sequence number (starting from 1)
    data: Vec<u8>,           // Encrypted chunk data (AES-GCM)
    manifest: Vec<u8>,       // bincode-encoded, signed manifest
    nonce: [u8; 12],         // Nonce used for AES-GCM (prefix + counter)
    timestamp: u64,          // Seconds since UNIX epoch
}
```

**Transport Encoding:**
- **Serialization:** bincode (efficient binary format)
- **Frame Format:** `[u32 length][bincode(NetworkChunk)]`
- **Validation:** Each chunk undergoes comprehensive validation on receipt

**Chunk Validation:**
- Data and manifest must not be empty
- Timestamp must not be more than 5 minutes in the future
- Sequence numbers must be contiguous (no gaps or duplicates)
- Nonce prefix must match session header prefix
- Chunk length must be ≤ declared chunk_size and > 0
- Ciphertext size must be ≤ chunk_size + 16 bytes (AES-GCM tag)
- Stream limits: max 1,000,000 records, 10GB total size
- All cryptographic validation must pass

### 2.1.1. Envelope File Format

The `.seal` envelope file is a binary format containing:

- **StreamHeader**: version, header bytes (66 bytes V2, 58 bytes V1), header hash (BLAKE3)
- **Record(s)**: sequence number, nonce (12 bytes: 4-byte prefix + 8-byte counter), signed manifest (with Ed25519 signature), ciphertext (AES-GCM)

All fields are bincode-encoded for compactness and speed.

**Envelope Integrity Invariants:**
- Each record's nonce prefix (first 4 bytes) must match the stream header's nonce prefix.
- The nonce counter (last 8 bytes) must equal the record's sequence number.
- The manifest's `seq` field must match the record's `seq` field.
These invariants are strictly enforced during decryption and help prevent record tampering, replay, or mixing between streams. If any validation fails (e.g., signature, nonce prefix, nonce counter, manifest sequence, hash), the record is rejected and an error is reported.

### 2.2. Manifest

The manifest is a bincode-encoded struct, signed with Ed25519 using **domain separation**:

```
struct Manifest {
    v: u8,                   // Manifest version
    ts_ms: u64,              // Millisecond timestamp
    seq: u64,                // Chunk sequence
    header_hash: [u8; 32],   // BLAKE3 hash of file/session header
    pt_hash: [u8; 32],       // BLAKE3 hash of plaintext chunk
    key_id: [u8; 16],        // Key identifier for rotation support
    ai_used: bool,           // Placeholder for AI usage
    model_ids: Vec<String>,  // Placeholder for model IDs
    data_type: DataType,     // Data type and format metadata
    chunk_len: u32,          // Expected plaintext length (cryptographically bound)
}

struct SignedManifest {
    manifest: Vec<u8>,       // bincode(Manifest)
    sig: Vec<u8>,            // Ed25519 signature (domain-separated)
    pubkey: Vec<u8>,         // Ed25519 public key
}
```

**Domain Separation**: Manifest signatures use domain separation to prevent signature reuse across different contexts. The signature is computed over:
```
signature = Ed25519.sign(b"sealedge.manifest.v1" || manifest_bytes)
```

This prevents cross-protocol signature attacks and ensures signatures are cryptographically bound to the Sealedge manifest context.

struct FileHeader {
    version: u8,             // File format version
    alg: u8,                 // Algorithm identifier (1 = AES-256-GCM)
    key_id: [u8; 16],        // Key identifier (matches manifest.key_id)
    device_id_hash: [u8; 32], // BLAKE3 hash of device ID + salt
    nonce_prefix: [u8; 4],   // Random nonce prefix for session
    chunk_size: u32,         // Chunk size in bytes (big-endian)
}
```


### 2.2. Fields and AAD recipe

- **AAD** = BLAKE3(header) || seq_be(8) || nonce(12) || BLAKE3(manifest_bytes) || chunk_len_be(4)
- **Nonce** = nonce_prefix(4) || seq_be(8) (unique per key/session)
- **Record** = seq, nonce, signed_manifest { manifest_bytes, ed25519_sig, pubkey }, ct

**Security Enhancements**:
- Chunk length cryptographically bound via AAD prevents manipulation
- Pre-decryption bounds checking (chunk_len ≤ chunk_size, ct.len() ≤ chunk_size + 16)
- Post-decryption length validation (decrypted_len = chunk_len)
- DoS protection: max 128MB chunks, 1M records, 10GB total per stream

**Integrity check:** See above: nonce prefix, nonce counter, and manifest sequence integrity are enforced for every record.

---


## 3. Protocol Flow

### 3.1. Connection and Session Setup

1. **Connection Establishment:**
   - Client connects to server via TCP with configurable timeout
   - Automatic retry logic with exponential backoff for failed connections
   - Server allocates per-connection state and session tracking
   - Connection ID assigned for logging and debugging

2. **Session Initialization:**
   - First valid chunk establishes session parameters
   - Header hash, nonce prefix, and key ID locked for session
   - Sequence tracking initialized (expecting sequence 1)

3. **Connection Management:**
   - Client operations include timeout handling for chunk transmission and ACK reception
   - Server supports graceful shutdown with active connection completion
   - Connection state tracking enables proper resource cleanup

### 3.2. Chunk Processing Pipeline

1. **Chunk Reception:**
   - Server reads length-prefixed NetworkChunk from socket
   - Basic structure validation (non-empty data/manifest, timestamp bounds)

2. **Cryptographic Validation:**
   - Manifest signature verification (Ed25519)
   - Key ID validation against configured keys
   - Nonce prefix and counter validation
   - Sequence number continuity check

3. **Decryption and Integrity:**
   - AES-GCM decryption with AAD binding
   - Plaintext hash verification against manifest
   - Header consistency validation

4. **Processing and Storage:**
   - Optional plaintext storage to output directory
   - Session state update (next expected sequence)
   - ACK response to client (future enhancement)

### 3.3. Validation Enforcement

**Critical Security Invariants (strictly enforced):**
- Record nonce prefix must match stream header nonce prefix
- Nonce counter (last 8 bytes) must equal record sequence number
- Manifest sequence must match record sequence number
- Manifest header hash must match stream header hash
- Manifest key ID must match file header key ID
- Sequence numbers must be strictly contiguous (no gaps or reuse)

**Failure Response:**
- Any validation failure immediately rejects the chunk
- Detailed error logging for debugging and monitoring
- Connection may be terminated for security violations

---


## 4. Security Considerations

- **Confidentiality:** AES-256-GCM per chunk, with session keys derived via X25519 ECDH when auth is active
- **Integrity:** Ed25519 signatures on manifests, AES-GCM tags, and nonce prefix integrity
- **Key Exchange:** Automated X25519 ECDH during auth handshake with BLAKE3 domain-separated KDF
- **Replay Protection:** Sequence numbers, timestamps, and random challenge bytes mixed into session key KDF
- **Memory Safety:** Key material protected with `Secret<T>` wrapper and zeroize-on-drop
- **Extensibility:** Protocol is versioned and designed for future upgrades (chunk reordering, error handling)

### Key Selection & Backend Architecture

**Key Selection Priority (client):**

When authentication is enabled (`--enable-auth`), the session encryption key is derived automatically via X25519 ECDH during the auth handshake — no manual key sharing required. The priority order:

1. **Auth-derived key** (ECDH session key from authentication handshake)
2. **`--key-hex`** (64-char hex, manual key)
3. **`--use-keyring`** + `--salt-hex` (keyring-derived via PBKDF2)
4. **Random key** (generated and printed for encrypt-only mode)

**ECDH Session Key Derivation:**

During the auth handshake, both client and server independently derive the same 256-bit session key:

1. Ed25519 keys are converted to X25519 (`SigningKey::to_scalar_bytes()` / `VerifyingKey::to_montgomery()`)
2. Standard X25519 Diffie-Hellman produces a shared secret
3. BLAKE3 `derive_key` with domain `"SEALEDGE_SESSION_KEY_V1"` mixes: shared secret + challenge bytes + both public keys (deterministically ordered)
4. Low-order point rejection prevents invalid curve attacks

No additional wire messages are needed — the session key is a side-effect of the existing challenge-response handshake.

**Universal Backend System (Implemented):**

The key management system uses pluggable backends via the `UniversalBackend` trait:

- **Software HSM** — In-memory cryptographic operations with key persistence
- **Keyring Backend** — OS keyring integration with PBKDF2 key derivation (feature-gated: `keyring`)
- **YubiKey Backend** — Hardware PIV operations with ECDSA P-256 and RSA-2048 (feature-gated: `yubikey`)
- **TPM Backend** — Planned for future milestone

**Mutual Exclusivity:** Backend selection flags are mutually exclusive. Only one backend may be specified per operation.

**PBKDF2 Parameters:**
- PBKDF2 with SHA-256
- 600,000 iterations
- 16-byte (32 hex char) salt (required with `--use-keyring`)

### Connection Management Options

**Client Connection Resilience (sealedge-client):**
```bash
# Configure connection timeouts and retry behavior
--connect-timeout <SECONDS>    # Connection establishment timeout (default: 10)
--retry-attempts <COUNT>       # Number of retry attempts (default: 3)
--retry-delay <SECONDS>        # Delay between retries (default: 2)

# Example: Aggressive retry for unstable networks
sealedge-client --server 10.0.1.100:8080 \
  --file data.wav \
  --connect-timeout 5 \
  --retry-attempts 5 \
  --retry-delay 1 \
  --verbose

# Example: Conservative settings for reliable networks
sealedge-client --server server.example.com:8080 \
  --file data.wav \
  --connect-timeout 30 \
  --retry-attempts 1
```

**Server Connection Management (sealedge-server):**
```bash
# Graceful shutdown via SIGINT/SIGTERM
# Server will complete active connections before shutdown
kill -INT <server_pid>

# Example: Server with verbose connection tracking
sealedge-server --listen 0.0.0.0:8080 \
  --verbose \
  --decrypt \
  --output-dir ./received_data
```

---

## 5. Example Message (Hex Dump)

```
[00 00 01 2A] [bincode(NetworkChunk...)]
// 4-byte length prefix, then bincode-encoded struct
```

---

## 6. Future Extensions & Planned Features

### 6.1 Live Audio Streaming Protocol
**Status:** Planned for Phase 3

- **Real-time chunk processing** with configurable latency targets
- **Audio-specific metadata** in manifest (sample rate, channels, format)
- **Temporal synchronization** for live playback scenarios
- **Buffer management** for network jitter and packet loss recovery

**Planned Message Extensions:**
```rust
struct AudioChunk {
    chunk: NetworkChunk,         // Standard encrypted chunk
    sample_rate: u32,            // Audio sample rate (Hz)
    channels: u8,                // Number of audio channels
    format: AudioFormat,         // PCM format specification
    duration_ms: u32,            // Chunk duration in milliseconds
}

struct LiveStreamMetadata {
    session_id: [u8; 16],        // Unique session identifier
    device_id: Vec<u8>,          // Audio capture device identifier
    start_timestamp: u64,        // Session start time (Unix epoch)
    expected_duration: Option<u64>, // Expected session duration (ms)
}
```

### 6.2 Matter Device Integration Protocol
**Status:** Planned for Phase 4

- **Certificate-based device authentication** using Matter credentials
- **Device onboarding workflow** with local test CA simulation
- **Matter device ID mapping** to Sealedge envelope manifests
- **Commissioning protocol integration** for seamless device addition

**Planned Extensions:**
```rust
struct MatterDeviceManifest {
    matter_device_id: [u8; 8],   // Matter 64-bit device identifier
    fabric_id: [u8; 8],          // Matter fabric identifier
    certificate_chain: Vec<Vec<u8>>, // X.509 certificate chain
    commissioning_data: Vec<u8>, // Device commissioning information
}

struct DeviceAttestationData {
    attestation_nonce: [u8; 32], // Attestation challenge nonce
    device_signature: Vec<u8>,   // Device-signed attestation
    timestamp: u64,              // Attestation timestamp
}
```

### 6.3 Enhanced Key Management Protocol
**Status:** Partially implemented

- ✅ **Multi-backend key derivation** — Universal Backend system with Software HSM, Keyring, YubiKey
- ✅ **X25519 ECDH session keys** — Automatic key exchange during auth handshake
- **Key rotation protocol** with backward compatibility (planned)
- **Distributed key management** for multi-device scenarios (planned)

### 6.4 Advanced Transport Features
**Status:** Partially implemented

- ✅ **QUIC transport layer** — Implemented with webpki-roots TLS; `insecure-tls` feature flag
- ✅ **Mutual authentication** — Ed25519 challenge-response with X25519 ECDH key exchange
- **Connection pooling** and multiplexing for high-throughput scenarios (planned)
- **Chunk retransmission** and error recovery protocols (planned)

### 6.5 Audit and Compliance Extensions
**Status:** Planned for Phase 5

- **Comprehensive audit logging** with structured JSON output
- **Compliance report generation** for regulatory requirements
- **Chain of custody tracking** for forensic applications
- **Tamper evidence reporting** with detailed failure analysis

---

## 8. Test Vectors and Validation

### 8.1. Deterministic Test Vectors

Sealedge provides deterministic test vectors to verify protocol compliance:

**Test Configuration:**
- **32KB input data**: Deterministic pseudo-random bytes via LCG
- **4KB chunks**: Standard chunking for realistic testing
- **Fixed cryptographic material**: Known AES-256 and Ed25519 keys
- **Golden envelope hash**: `8ecc3b2fcb0887dfd6ff3513c0caa3febb2150a920213fa5b622243ad530f34c`

**Validation Tests:**
1. **Format compliance**: `cargo test vectors::tests::golden_trst_digest_is_stable`
2. **Round-trip integrity**: `cargo test golden_envelope_roundtrip`  
3. **Tamper detection**: `cargo test tamper_fails_on_manifest_change`

### 8.2. Integration Testing

The implementation includes end-to-end protocol testing:

- **CLI-based testing**: Real binary execution via command line
- **File-based round-trips**: Input → encrypt → envelope → decrypt → verify
- **Network protocol testing**: Client/server chunk transfer validation
- **Error injection**: Corruption detection and failure modes

**Test Execution:**
```bash
cargo test                     # All tests
cargo test --test vectors      # Integration tests only
cargo test golden_trst         # Format compliance only
```

---

## 9. Error Handling

If any validation fails during decryption (e.g., manifest signature, nonce prefix, nonce counter, manifest sequence, key ID mismatch, header hash, or plaintext hash), the record is rejected and an error is reported or logged. This ensures that tampered, out-of-sequence, replayed, or incorrectly keyed records cannot be decrypted or accepted.

---

**See also:**
- [`src/format.rs`](sealedge-core/src/format.rs) — Centralized format definitions and constants
- [`src/lib.rs`](sealedge-core/src/lib.rs) for struct definitions
- [`src/main.rs`](sealedge-core/src/main.rs) for CLI and envelope logic
- `sealedge-client` and `sealedge-server` for protocol usage
- [threat-model.md](threat-model.md) for security rationale

---

**Protocol Versioning:**
The protocol is versioned (see StreamHeader and file preamble). Future changes will increment the version and document compatibility requirements.

---

## Legal & Attribution

**Copyright** © 2025 TRUSTEDGE LABS LLC. All rights reserved.

**License**: This specification is licensed under the [Mozilla Public License 2.0 (MPL-2.0)](https://mozilla.org/MPL/2.0/).

**Project**: [Sealedge](https://github.com/TrustEdge-Labs/sealedge) — Privacy and trust at the edge.

**Standards**: This specification references [BLAKE3](https://github.com/BLAKE3-team/BLAKE3-specs), [Ed25519 RFC 8032](https://tools.ietf.org/html/rfc8032), and [AES-GCM NIST SP 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final).
