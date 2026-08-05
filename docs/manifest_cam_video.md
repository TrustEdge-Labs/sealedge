<!--
Copyright (c) 2025 TRUSTEDGE LABS LLC
MPL-2.0: https://mozilla.org/MPL/2.0/
Project: sealedge — Privacy and trust at the edge.
GitHub: https://github.com/johnzilla/sealedge
-->


# .seal Archive Manifest Specification

The `.seal` archive manifest is a profile-agnostic, signed JSON document that
describes a trusted capture archive. It is defined by the `TrstManifest` type in
`crates/seal-protocols/src/archive/manifest.rs`. The `cam.video` profile is one
of several profiles (`generic`, `cam.video`, `sensor`, `audio`, `log`) selected
via the `metadata` field.

> **Version:** `trst_version` is `"0.2.0"` (the C4 clean break). Verifiers reject
> `0.1.0` and any unknown version. The historical `capture` / `CaptureInfo` names
> survive only as backward-compatible type aliases for `metadata` /
> `CamVideoMetadata`.

## Schema Fields and Types

```rust
pub struct TrstManifest {
    pub trst_version: String,               // Protocol version — "0.2.0"
    pub profile: String,                    // "generic" | "cam.video" | "sensor" | "audio" | "log"
    pub device: DeviceInfo,                 // Device identification and keys
    pub metadata: ProfileMetadata,          // Profile-specific capture metadata (enum)
    pub chunk: ChunkInfo,                    // Chunking configuration
    pub segments: Vec<SegmentInfo>,          // Per-segment verification data
    pub claims: Vec<String>,                 // Additional claims (e.g. "location:unknown")
    pub encryption: Option<EncryptionBlock>, // Content-encryption metadata; None = sign-only
    pub sequence: Option<u64>,               // Chronicle position (H1); 0 = genesis, absent = standalone
    pub prev_archive_hash: Option<String>,   // b3:<hex> of the previous archive (H1); absent at genesis
    pub signature: Option<String>,           // Ed25519 signature (excluded from canonical bytes)
}

pub struct DeviceInfo {
    pub id: String,                          // Device identifier (e.g. "te:cam:a1b2c3")
    pub model: String,                       // Device model name
    pub firmware_version: String,            // Firmware version
    pub public_key: String,                  // Ed25519 signing key ("ed25519:BASE64")
    pub key_agreement_public: Option<String>,// X25519 key-agreement key ("x25519:BASE64"), 0.2.0
}

// metadata is a `#[serde(untagged)]` enum. The `cam.video` variant:
pub struct CamVideoMetadata {
    pub started_at: String,                  // RFC3339 timestamp
    pub ended_at: String,                    // RFC3339 timestamp
    pub timezone: String,                    // Timezone (e.g. "UTC")
    pub fps: f64,                            // Frames per second
    pub resolution: String,                  // Resolution (e.g. "1920x1080")
    pub codec: String,                       // Codec (e.g. "raw", "h264")
}

pub struct ChunkInfo {
    pub size_bytes: u64,                     // Target chunk size in bytes
    pub duration_seconds: f64,               // Target chunk duration
}

pub struct SegmentInfo {
    pub chunk_file: String,                  // Chunk filename (e.g. "00000.bin")
    pub blake3_hash: String,                 // BLAKE3 of the stored chunk bytes (bare hex, no prefix)
    pub start_time: String,                  // Segment start time
    pub duration_seconds: f64,               // Segment duration
    pub continuity_hash: String,             // Continuity chain state (bare hex, no prefix)
}
```

Other profiles supply their own `metadata` variant (`GenericMetadata`,
`SensorMetadata`, `AudioMetadata`, `LogMetadata`); all variants require
`started_at` and `ended_at`. The `metadata` object always serializes under the
`"metadata"` key regardless of profile.

### Profile metadata variants

| Profile | Distinguishing required fields | Metadata type |
|---------|--------------------------------|---------------|
| `cam.video` | `timezone`, `fps`, `resolution`, `codec` | `CamVideoMetadata` |
| `sensor` | `sample_rate_hz`, `unit`, `sensor_model` (+ optional `latitude`/`longitude`/`altitude`/`labels`) | `SensorMetadata` |
| `audio` | `sample_rate_hz`, `bit_depth`, `channels`, `codec` | `AudioMetadata` |
| `log` | `application`, `host`, `log_level`, `log_format` | `LogMetadata` |
| `generic` (default) | none — all content fields optional (`data_type`, `source`, `description`, `mime_type`, `labels`) | `GenericMetadata` |

## Content Encryption (C4)

Archive content is encrypted under a per-archive **random** Content-Encryption
Key (CEK) — never derived from the signing key. Chunks are encrypted with
XChaCha20-Poly1305, and on disk each chunk is `[nonce:24][ciphertext]` (the
24-byte nonce is prepended to the ciphertext; there is no `xchacha20:NONCE`
manifest field). The CEK is then HPKE-wrapped (RFC 9180 base mode;
`DHKEM(X25519,HKDF-SHA256)` / `HKDF-SHA256` / `ChaCha20Poly1305`) to one or more
recipients. Recipient #0 is conventionally the device's own X25519 key.

The optional `encryption` block records this:

```rust
pub struct EncryptionBlock {
    pub content_aead: String,          // e.g. "XChaCha20Poly1305"
    pub hpke: HpkeSuite,               // { kem, kdf, aead }
    pub recipients: Vec<RecipientEntry>,
}

pub struct RecipientEntry {
    pub recipient_id: String,          // selection hint: "b3:<hex>" over the recipient X25519 key
    pub recipient_pub: String,         // recipient X25519 public key ("x25519:BASE64")
    pub enc: String,                   // HPKE encapsulated ephemeral key (base64)
    pub wrapped_cek: String,           // HPKE-sealed CEK (base64)
}
```

- **Encrypted archive:** `encryption` is present with a non-empty `recipients`
  list; chunks are ciphertext.
- **Sign-only archive:** `encryption` is absent (`None`); chunks are plaintext.
- **Empty `recipients`:** a hard validation error — an encryption block with zero
  recipients is rejected (use sign-only mode to store plaintext).

## Canonicalization Rules

The manifest is canonicalized before signing to guarantee byte-identical
verification. See `TrstManifest::to_canonical_bytes` / `serialize_canonical`.

### 1. Fixed Object Key Order (NOT alphabetical)

Canonical JSON emits keys in a **fixed declaration order**, not alphabetical
order:

```
trst_version, profile, device, metadata, chunk, segments, claims,
encryption?, sequence?, prev_archive_hash?
```

Within nested objects the order is also fixed:

- `device`: `id, model, firmware_version, public_key, key_agreement_public?`
- `metadata` (cam.video): `started_at, ended_at, timezone, fps, resolution, codec`
- `chunk`: `size_bytes, duration_seconds`
- each segment: `chunk_file, blake3_hash, start_time, duration_seconds, continuity_hash`
- `encryption`: `content_aead, hpke{kem, kdf, aead}, recipients[...]`
- each recipient: `recipient_id, recipient_pub, enc, wrapped_cek`

Recipients and segments serialize in array order.

### 2. Optional Fields Emitted Only When Present

`key_agreement_public`, `encryption`, `sequence`, and `prev_archive_hash` are
written only when set. Sign-only / key-agreement-less / non-chronicle manifests
therefore canonicalize without those keys. A chronicle archive carries a
monotonic `sequence` (0 = genesis, no `prev_archive_hash`); later archives set
`prev_archive_hash` to `b3:<hex>` of the previous manifest's canonical bytes. Within metadata, `labels` are emitted as a sorted map
(keys are sorted) and are omitted when empty.

### 3. Segment Hashes Are Bare Hex

`blake3_hash` and `continuity_hash` are lowercase hex strings with **no**
prefix. (The `b3:` prefix appears elsewhere — on point-attestation artifact
hashes and on `emit-request` segment references — but never on archive
segments.)

### 4. UTF-8 Encoding

All strings are valid UTF-8 without a byte order mark (BOM). Canonical bytes are
compact (no insignificant whitespace).

### 5. Signature Exclusion

The `signature` field is excluded from the canonical bytes used for signing.

## Signature Format

### Ed25519 Signatures
- Algorithm: Ed25519 digital signatures
- Format: `"ed25519:BASE64"`
- Input: canonical JSON bytes (UTF-8), which include the `encryption` block when present
- Verification: public key from `device.public_key`

Example:
```json
{
  "signature": "ed25519:MEUCIQDx1234...base64signature...5678=="
}
```

## Continuity Chain

The continuity chain cryptographically links segments to detect tampering or
reordering.

### Genesis State
```rust
genesis = blake3("sealedge:genesis")
```

### Chain Progression
```rust
chain_i = chain_next(chain_{i-1}, hash_i)
where hash_i = blake3(stored_chunk_bytes_i)
```

`stored_chunk_bytes` are the bytes actually on disk: for an encrypted archive
that is `[nonce:24][ciphertext]`; for a sign-only archive it is the plaintext
chunk. The per-segment `blake3_hash` covers the same stored bytes.

## Example Manifest (cam.video, encrypted)

Shown pretty-printed for readability; the canonical bytes are compact and use
the fixed key order above.

```json
{
  "trst_version": "0.2.0",
  "profile": "cam.video",
  "device": {
    "id": "te:cam:a1b2c3",
    "model": "TrustEdgeRefCam",
    "firmware_version": "1.0.0",
    "public_key": "ed25519:GAUpGXoor5gP...",
    "key_agreement_public": "x25519:9Qm3s0k1..."
  },
  "metadata": {
    "started_at": "2025-01-15T10:30:00Z",
    "ended_at": "2025-01-15T10:32:00Z",
    "timezone": "UTC",
    "fps": 30.0,
    "resolution": "1920x1080",
    "codec": "raw"
  },
  "chunk": {
    "size_bytes": 1048576,
    "duration_seconds": 2.0
  },
  "segments": [
    {
      "chunk_file": "00000.bin",
      "blake3_hash": "abc123...",
      "start_time": "2025-01-15T10:30:00Z",
      "duration_seconds": 2.0,
      "continuity_hash": "def456..."
    },
    {
      "chunk_file": "00001.bin",
      "blake3_hash": "ghi789...",
      "start_time": "2025-01-15T10:30:02Z",
      "duration_seconds": 2.0,
      "continuity_hash": "jkl012..."
    }
  ],
  "claims": ["location:unknown"],
  "encryption": {
    "content_aead": "XChaCha20Poly1305",
    "hpke": {
      "kem": "DHKEM(X25519,HKDF-SHA256)",
      "kdf": "HKDF-SHA256",
      "aead": "ChaCha20Poly1305"
    },
    "recipients": [
      {
        "recipient_id": "b3:aaaa...",
        "recipient_pub": "x25519:9Qm3s0k1...",
        "enc": "ZW5jMA==",
        "wrapped_cek": "d3JhcDA="
      }
    ]
  },
  "signature": "ed25519:MEUCIQDx1234..."
}
```

For a **sign-only** archive, drop the `encryption` block (and optionally
`key_agreement_public`); the chunks under `chunks/` are plaintext.

## Verification Order of Operations

### 1. Parse
- Parse `manifest.json`
- Confirm `trst_version` is `"0.2.0"` (reject `0.1.0`/unknown)
- Validate required fields and that data types match the schema

### 2. Canonicalize
- Rebuild the fixed-order canonical JSON bytes
- Exclude the `signature` field

### 3. Signature Verification
- Verify the Ed25519 signature over the canonical bytes using `device.public_key`

### 4. Continuity Verification
- Load the stored chunk files referenced in `segments`
- Compute BLAKE3 over each stored chunk (ciphertext incl. nonce when encrypted)
- Verify the continuity chain from genesis through all segments
- Ensure no gaps, reordering, or tampering

### Exit Codes
- **0**: All verifications pass
- **10**: Signature verification failed
- **11**: Continuity chain verification failed
- **12**: IO error or malformed archive
- **13**: Invalid CLI arguments
- **14**: Internal error

## Related Documentation

- [CLI Reference](../README.md#p0-golden-path-2-minutes)
- [Acceptance Tests](../crates/seal-cli/tests/acceptance.rs)
- [C4 Content-Encryption Design](designs/c4-content-encryption-redesign.md)
</content>
</invoke>
