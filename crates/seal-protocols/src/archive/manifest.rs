//
// Copyright (c) 2025 TRUSTEDGE LABS LLC
// This source code is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Project: sealedge — Privacy and trust at the edge.
//

//! Profile-agnostic manifest types for .trst archives.
//!
//! `TrstManifest` is the unified manifest type supporting both `generic` and
//! `cam.video` profiles via the `ProfileMetadata` enum.  The `CamVideoManifest`
//! and `CaptureInfo` names remain as type aliases for backward compatibility.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ManifestFormatError {
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Invalid field value: {0}")]
    InvalidField(String),
}

// ─── Profile metadata variants ───────────────────────────────────────────────

/// Metadata for the `generic` profile.  All content-specific fields are
/// optional; `started_at` and `ended_at` are the only required timestamps.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GenericMetadata {
    pub started_at: String,
    pub ended_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    /// Free-form key/value labels.  BTreeMap ensures sorted keys in canonical output.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
}

/// Metadata for the `cam.video` profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CamVideoMetadata {
    pub started_at: String,
    pub ended_at: String,
    pub timezone: String,
    pub fps: f64,
    pub resolution: String,
    pub codec: String,
}

/// Metadata for the `sensor` profile.
///
/// The `unit` and `sensor_model` fields are required and unambiguously
/// distinguish this variant from `Generic` during untagged deserialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensorMetadata {
    pub started_at: String,
    pub ended_at: String,
    pub sample_rate_hz: f64,
    pub unit: String,
    pub sensor_model: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latitude: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub longitude: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub altitude: Option<f64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
}

/// Metadata for the `audio` profile.
///
/// The `bit_depth` and `channels` fields are required and unambiguously
/// distinguish this variant from `Generic` during untagged deserialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AudioMetadata {
    pub started_at: String,
    pub ended_at: String,
    pub sample_rate_hz: u32,
    pub bit_depth: u16,
    pub channels: u8,
    pub codec: String,
}

/// Metadata for the `log` profile.
///
/// The `application` and `host` fields are required and unambiguously
/// distinguish this variant from `Generic` during untagged deserialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogMetadata {
    pub started_at: String,
    pub ended_at: String,
    pub application: String,
    pub host: String,
    pub log_level: String,
    pub log_format: String,
}

/// Union of all profile-specific metadata.
///
/// `#[serde(untagged)]` means serde tries each variant in declaration order.
/// Variant order matters: each variant must have at least one required field
/// not present in `Generic` for unambiguous deserialization.
/// - `CamVideo`: `timezone`, `fps`, `resolution`
/// - `Sensor`: `unit`, `sensor_model`
/// - `Audio`: `bit_depth`, `channels`
/// - `Log`: `application`, `host`
/// - `Generic`: catch-all with all optional fields
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ProfileMetadata {
    CamVideo(CamVideoMetadata),
    Sensor(SensorMetadata),
    Audio(AudioMetadata),
    Log(LogMetadata),
    Generic(GenericMetadata),
}

// ─── Supporting structs (unchanged) ──────────────────────────────────────────

/// Device information embedded in the manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub id: String,
    pub model: String,
    pub firmware_version: String,
    /// Ed25519 signing/identity key, `ed25519:<base64>` (C3 cross-check applies).
    pub public_key: String,
    /// X25519 key-agreement key, `x25519:<base64>` (C4, `0.2.0`). Independent of
    /// `public_key`; absent in `0.1.0` / sign-only construction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_agreement_public: Option<String>,
}

/// Chunk configuration for the archive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkInfo {
    pub size_bytes: u64,
    pub duration_seconds: f64,
}

/// Individual segment information within the archive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentInfo {
    pub chunk_file: String,
    pub blake3_hash: String,
    pub start_time: String,
    pub duration_seconds: f64,
    pub continuity_hash: String,
}

// ─── Content-encryption block (trst_version 0.2.0, C4) ────────────────────────

/// HPKE ciphersuite identifiers (RFC 9180) used to wrap the per-archive CEK.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HpkeSuite {
    /// KEM identifier, e.g. `"DHKEM(X25519,HKDF-SHA256)"`.
    pub kem: String,
    /// KDF identifier, e.g. `"HKDF-SHA256"`.
    pub kdf: String,
    /// AEAD identifier, e.g. `"ChaCha20Poly1305"`.
    pub aead: String,
}

/// One recipient's wrapped copy of the per-archive Content-Encryption Key (CEK).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecipientEntry {
    /// Non-authoritative selection hint: `b3:<hex>` over the recipient X25519 key.
    pub recipient_id: String,
    /// Recipient X25519 public key, `x25519:<base64>`.
    pub recipient_pub: String,
    /// HPKE encapsulated (ephemeral) key, base64.
    pub enc: String,
    /// HPKE-sealed CEK (ciphertext||tag), base64.
    pub wrapped_cek: String,
}

/// Content-encryption metadata for `trst_version` `0.2.0` archives.
///
/// Absent (`TrstManifest.encryption == None`) denotes a signed-but-unencrypted
/// ("sign-only") archive. When present, `recipients` MUST be non-empty (an empty
/// list is a hard error, never "intended unreadable").
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptionBlock {
    /// Content AEAD for chunk encryption, e.g. `"XChaCha20Poly1305"`.
    pub content_aead: String,
    /// HPKE suite used to wrap the CEK to each recipient.
    pub hpke: HpkeSuite,
    /// Per-recipient wrapped CEKs (recipient #0 is conventionally the device).
    pub recipients: Vec<RecipientEntry>,
}

// ─── Main manifest type ───────────────────────────────────────────────────────

/// Profile-agnostic manifest for a `.trst` archive.
///
/// Supports `"generic"` and `"cam.video"` profiles via the `metadata` field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrstManifest {
    pub trst_version: String,
    pub profile: String,
    pub device: DeviceInfo,
    pub metadata: ProfileMetadata,
    pub chunk: ChunkInfo,
    pub segments: Vec<SegmentInfo>,
    pub claims: Vec<String>,
    /// Content-encryption metadata (C4, `0.2.0`). `None` = signed-but-unencrypted
    /// ("sign-only"); `Some` carries the per-recipient wrapped CEKs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<EncryptionBlock>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_archive_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

// ─── Backward-compatibility aliases ──────────────────────────────────────────

/// Backward-compatible alias for `TrstManifest`.
pub type CamVideoManifest = TrstManifest;

/// Backward-compatible alias for `CamVideoMetadata` (the old `CaptureInfo` struct).
pub type CaptureInfo = CamVideoMetadata;

// ─── TrstManifest implementation ──────────────────────────────────────────────

impl TrstManifest {
    /// Create a new manifest with the `generic` profile and empty metadata.
    pub fn new() -> Self {
        Self {
            trst_version: "0.1.0".to_string(),
            profile: "generic".to_string(),
            device: DeviceInfo {
                id: String::new(),
                model: "TrustEdgeRefCam".to_string(),
                firmware_version: "1.0.0".to_string(),
                public_key: String::new(),
                key_agreement_public: None,
            },
            metadata: ProfileMetadata::Generic(GenericMetadata::default()),
            chunk: ChunkInfo {
                size_bytes: 1_048_576, // 1 MB default
                duration_seconds: 2.0,
            },
            segments: Vec::new(),
            claims: Vec::new(),
            encryption: None,
            prev_archive_hash: None,
            signature: None,
        }
    }

    /// Create a new manifest pre-configured for the `cam.video` profile.
    pub fn new_cam_video() -> Self {
        Self {
            trst_version: "0.1.0".to_string(),
            profile: "cam.video".to_string(),
            device: DeviceInfo {
                id: String::new(),
                model: "TrustEdgeRefCam".to_string(),
                firmware_version: "1.0.0".to_string(),
                public_key: String::new(),
                key_agreement_public: None,
            },
            metadata: ProfileMetadata::CamVideo(CamVideoMetadata {
                started_at: String::new(),
                ended_at: String::new(),
                timezone: "UTC".to_string(),
                fps: 30.0,
                resolution: "1920x1080".to_string(),
                codec: "raw".to_string(),
            }),
            chunk: ChunkInfo {
                size_bytes: 1_048_576,
                duration_seconds: 2.0,
            },
            segments: Vec::new(),
            claims: Vec::new(),
            encryption: None,
            prev_archive_hash: None,
            signature: None,
        }
    }

    /// Convert manifest to canonical bytes for signing/verification.
    /// The `signature` field is excluded from canonicalization.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, ManifestFormatError> {
        let mut canonical = self.clone();
        canonical.signature = None;
        let json_string = Self::serialize_canonical(&canonical)?;
        Ok(json_string.into_bytes())
    }

    /// Build a deterministically-ordered JSON string for a manifest.
    fn serialize_canonical(manifest: &TrstManifest) -> Result<String, ManifestFormatError> {
        let mut result = String::from("{");

        result.push_str(&format!(
            "\"trst_version\":{}",
            serde_json::to_string(&manifest.trst_version)?
        ));
        result.push_str(&format!(
            ",\"profile\":{}",
            serde_json::to_string(&manifest.profile)?
        ));

        // Device — ordered fields
        result.push_str(",\"device\":{");
        result.push_str(&format!(
            "\"id\":{}",
            serde_json::to_string(&manifest.device.id)?
        ));
        result.push_str(&format!(
            ",\"model\":{}",
            serde_json::to_string(&manifest.device.model)?
        ));
        result.push_str(&format!(
            ",\"firmware_version\":{}",
            serde_json::to_string(&manifest.device.firmware_version)?
        ));
        result.push_str(&format!(
            ",\"public_key\":{}",
            serde_json::to_string(&manifest.device.public_key)?
        ));
        // C4 (0.2.0): device X25519 key-agreement key, emitted only when present so
        // 0.1.0 / sign-only manifests canonicalize byte-identically to before.
        if let Some(ref ka) = manifest.device.key_agreement_public {
            result.push_str(&format!(
                ",\"key_agreement_public\":{}",
                serde_json::to_string(ka)?
            ));
        }
        result.push('}');

        // Metadata — dispatch on variant
        match &manifest.metadata {
            ProfileMetadata::CamVideo(m) => {
                result.push_str(",\"metadata\":{");
                result.push_str(&format!(
                    "\"started_at\":{}",
                    serde_json::to_string(&m.started_at)?
                ));
                result.push_str(&format!(
                    ",\"ended_at\":{}",
                    serde_json::to_string(&m.ended_at)?
                ));
                result.push_str(&format!(
                    ",\"timezone\":{}",
                    serde_json::to_string(&m.timezone)?
                ));
                result.push_str(&format!(",\"fps\":{}", m.fps));
                result.push_str(&format!(
                    ",\"resolution\":{}",
                    serde_json::to_string(&m.resolution)?
                ));
                result.push_str(&format!(",\"codec\":{}", serde_json::to_string(&m.codec)?));
                result.push('}');
            }
            ProfileMetadata::Sensor(m) => {
                result.push_str(",\"metadata\":{");
                result.push_str(&format!(
                    "\"started_at\":{}",
                    serde_json::to_string(&m.started_at)?
                ));
                result.push_str(&format!(
                    ",\"ended_at\":{}",
                    serde_json::to_string(&m.ended_at)?
                ));
                result.push_str(&format!(",\"sample_rate_hz\":{}", m.sample_rate_hz));
                result.push_str(&format!(",\"unit\":{}", serde_json::to_string(&m.unit)?));
                result.push_str(&format!(
                    ",\"sensor_model\":{}",
                    serde_json::to_string(&m.sensor_model)?
                ));
                if let Some(lat) = m.latitude {
                    result.push_str(&format!(",\"latitude\":{lat}"));
                }
                if let Some(lon) = m.longitude {
                    result.push_str(&format!(",\"longitude\":{lon}"));
                }
                if let Some(alt) = m.altitude {
                    result.push_str(&format!(",\"altitude\":{alt}"));
                }
                if !m.labels.is_empty() {
                    // BTreeMap guarantees sorted keys
                    result.push_str(",\"labels\":{");
                    let mut first = true;
                    for (k, v) in &m.labels {
                        if !first {
                            result.push(',');
                        }
                        first = false;
                        result.push_str(&format!(
                            "{}:{}",
                            serde_json::to_string(k)?,
                            serde_json::to_string(v)?
                        ));
                    }
                    result.push('}');
                }
                result.push('}');
            }
            ProfileMetadata::Audio(m) => {
                result.push_str(",\"metadata\":{");
                result.push_str(&format!(
                    "\"started_at\":{}",
                    serde_json::to_string(&m.started_at)?
                ));
                result.push_str(&format!(
                    ",\"ended_at\":{}",
                    serde_json::to_string(&m.ended_at)?
                ));
                result.push_str(&format!(",\"sample_rate_hz\":{}", m.sample_rate_hz));
                result.push_str(&format!(",\"bit_depth\":{}", m.bit_depth));
                result.push_str(&format!(",\"channels\":{}", m.channels));
                result.push_str(&format!(",\"codec\":{}", serde_json::to_string(&m.codec)?));
                result.push('}');
            }
            ProfileMetadata::Log(m) => {
                result.push_str(",\"metadata\":{");
                result.push_str(&format!(
                    "\"started_at\":{}",
                    serde_json::to_string(&m.started_at)?
                ));
                result.push_str(&format!(
                    ",\"ended_at\":{}",
                    serde_json::to_string(&m.ended_at)?
                ));
                result.push_str(&format!(
                    ",\"application\":{}",
                    serde_json::to_string(&m.application)?
                ));
                result.push_str(&format!(",\"host\":{}", serde_json::to_string(&m.host)?));
                result.push_str(&format!(
                    ",\"log_level\":{}",
                    serde_json::to_string(&m.log_level)?
                ));
                result.push_str(&format!(
                    ",\"log_format\":{}",
                    serde_json::to_string(&m.log_format)?
                ));
                result.push('}');
            }
            ProfileMetadata::Generic(m) => {
                result.push_str(",\"metadata\":{");
                result.push_str(&format!(
                    "\"started_at\":{}",
                    serde_json::to_string(&m.started_at)?
                ));
                result.push_str(&format!(
                    ",\"ended_at\":{}",
                    serde_json::to_string(&m.ended_at)?
                ));
                if let Some(ref v) = m.data_type {
                    result.push_str(&format!(",\"data_type\":{}", serde_json::to_string(v)?));
                }
                if let Some(ref v) = m.source {
                    result.push_str(&format!(",\"source\":{}", serde_json::to_string(v)?));
                }
                if let Some(ref v) = m.description {
                    result.push_str(&format!(",\"description\":{}", serde_json::to_string(v)?));
                }
                if let Some(ref v) = m.mime_type {
                    result.push_str(&format!(",\"mime_type\":{}", serde_json::to_string(v)?));
                }
                if !m.labels.is_empty() {
                    // BTreeMap guarantees sorted keys
                    result.push_str(",\"labels\":{");
                    let mut first = true;
                    for (k, v) in &m.labels {
                        if !first {
                            result.push(',');
                        }
                        first = false;
                        result.push_str(&format!(
                            "{}:{}",
                            serde_json::to_string(k)?,
                            serde_json::to_string(v)?
                        ));
                    }
                    result.push('}');
                }
                result.push('}');
            }
        }

        // Chunk
        result.push_str(",\"chunk\":{");
        result.push_str(&format!("\"size_bytes\":{}", manifest.chunk.size_bytes));
        result.push_str(&format!(
            ",\"duration_seconds\":{}",
            manifest.chunk.duration_seconds
        ));
        result.push('}');

        // Segments
        result.push_str(",\"segments\":[");
        for (i, segment) in manifest.segments.iter().enumerate() {
            if i > 0 {
                result.push(',');
            }
            result.push('{');
            result.push_str(&format!(
                "\"chunk_file\":{}",
                serde_json::to_string(&segment.chunk_file)?
            ));
            result.push_str(&format!(
                ",\"blake3_hash\":{}",
                serde_json::to_string(&segment.blake3_hash)?
            ));
            result.push_str(&format!(
                ",\"start_time\":{}",
                serde_json::to_string(&segment.start_time)?
            ));
            result.push_str(&format!(
                ",\"duration_seconds\":{}",
                segment.duration_seconds
            ));
            result.push_str(&format!(
                ",\"continuity_hash\":{}",
                serde_json::to_string(&segment.continuity_hash)?
            ));
            result.push('}');
        }
        result.push(']');

        // Claims
        result.push_str(&format!(
            ",\"claims\":{}",
            serde_json::to_string(&manifest.claims)?
        ));

        // C4 (0.2.0): content-encryption block, emitted only when present. Fixed
        // field order; recipients serialized in array order (wrap emits a
        // deterministic order). Absent ⇒ signed-but-unencrypted, bytes unchanged.
        if let Some(ref enc) = manifest.encryption {
            result.push_str(",\"encryption\":{");
            result.push_str(&format!(
                "\"content_aead\":{}",
                serde_json::to_string(&enc.content_aead)?
            ));
            result.push_str(",\"hpke\":{");
            result.push_str(&format!(
                "\"kem\":{}",
                serde_json::to_string(&enc.hpke.kem)?
            ));
            result.push_str(&format!(
                ",\"kdf\":{}",
                serde_json::to_string(&enc.hpke.kdf)?
            ));
            result.push_str(&format!(
                ",\"aead\":{}",
                serde_json::to_string(&enc.hpke.aead)?
            ));
            result.push('}');
            result.push_str(",\"recipients\":[");
            for (i, r) in enc.recipients.iter().enumerate() {
                if i > 0 {
                    result.push(',');
                }
                result.push('{');
                result.push_str(&format!(
                    "\"recipient_id\":{}",
                    serde_json::to_string(&r.recipient_id)?
                ));
                result.push_str(&format!(
                    ",\"recipient_pub\":{}",
                    serde_json::to_string(&r.recipient_pub)?
                ));
                result.push_str(&format!(",\"enc\":{}", serde_json::to_string(&r.enc)?));
                result.push_str(&format!(
                    ",\"wrapped_cek\":{}",
                    serde_json::to_string(&r.wrapped_cek)?
                ));
                result.push('}');
            }
            result.push(']');
            result.push('}');
        }

        // Optional prev_archive_hash
        if let Some(ref prev_hash) = manifest.prev_archive_hash {
            result.push_str(&format!(
                ",\"prev_archive_hash\":{}",
                serde_json::to_string(prev_hash)?
            ));
        }

        // Note: signature is explicitly excluded from canonicalization

        result.push('}');
        Ok(result)
    }

    /// Create a new manifest pre-configured for the `sensor` profile.
    pub fn new_sensor() -> Self {
        Self {
            trst_version: "0.1.0".to_string(),
            profile: "sensor".to_string(),
            device: DeviceInfo {
                id: String::new(),
                model: "TrustEdgeRefSensor".to_string(),
                firmware_version: "1.0.0".to_string(),
                public_key: String::new(),
                key_agreement_public: None,
            },
            metadata: ProfileMetadata::Sensor(SensorMetadata {
                started_at: String::new(),
                ended_at: String::new(),
                sample_rate_hz: 100.0,
                unit: String::new(),
                sensor_model: String::new(),
                latitude: None,
                longitude: None,
                altitude: None,
                labels: BTreeMap::new(),
            }),
            chunk: ChunkInfo {
                size_bytes: 1_048_576,
                duration_seconds: 2.0,
            },
            segments: Vec::new(),
            claims: Vec::new(),
            encryption: None,
            prev_archive_hash: None,
            signature: None,
        }
    }

    /// Create a new manifest pre-configured for the `audio` profile.
    pub fn new_audio() -> Self {
        Self {
            trst_version: "0.1.0".to_string(),
            profile: "audio".to_string(),
            device: DeviceInfo {
                id: String::new(),
                model: "TrustEdgeRefAudio".to_string(),
                firmware_version: "1.0.0".to_string(),
                public_key: String::new(),
                key_agreement_public: None,
            },
            metadata: ProfileMetadata::Audio(AudioMetadata {
                started_at: String::new(),
                ended_at: String::new(),
                sample_rate_hz: 44100,
                bit_depth: 16,
                channels: 2,
                codec: "pcm".to_string(),
            }),
            chunk: ChunkInfo {
                size_bytes: 1_048_576,
                duration_seconds: 2.0,
            },
            segments: Vec::new(),
            claims: Vec::new(),
            encryption: None,
            prev_archive_hash: None,
            signature: None,
        }
    }

    /// Create a new manifest pre-configured for the `log` profile.
    pub fn new_log() -> Self {
        Self {
            trst_version: "0.1.0".to_string(),
            profile: "log".to_string(),
            device: DeviceInfo {
                id: String::new(),
                model: "TrustEdgeRefLog".to_string(),
                firmware_version: "1.0.0".to_string(),
                public_key: String::new(),
                key_agreement_public: None,
            },
            metadata: ProfileMetadata::Log(LogMetadata {
                started_at: String::new(),
                ended_at: String::new(),
                application: String::new(),
                host: String::new(),
                log_level: "info".to_string(),
                log_format: "json".to_string(),
            }),
            chunk: ChunkInfo {
                size_bytes: 1_048_576,
                duration_seconds: 2.0,
            },
            segments: Vec::new(),
            claims: Vec::new(),
            encryption: None,
            prev_archive_hash: None,
            signature: None,
        }
    }

    /// Set the detached signature on this manifest.
    pub fn set_signature(&mut self, signature: String) {
        self.signature = Some(signature);
    }

    /// Validate manifest structure and required fields.
    pub fn validate(&self) -> Result<(), ManifestFormatError> {
        if self.trst_version.is_empty() {
            return Err(ManifestFormatError::InvalidField(
                "trst_version cannot be empty".to_string(),
            ));
        }

        // Accept "generic", "cam.video", "sensor", "audio", "log"
        if !["generic", "cam.video", "sensor", "audio", "log"].contains(&self.profile.as_str()) {
            return Err(ManifestFormatError::InvalidField(format!(
                "profile must be 'generic', 'cam.video', 'sensor', 'audio', or 'log', got '{}'",
                self.profile
            )));
        }

        if self.device.id.is_empty() {
            return Err(ManifestFormatError::InvalidField(
                "device.id cannot be empty".to_string(),
            ));
        }

        if self.device.public_key.is_empty() {
            return Err(ManifestFormatError::InvalidField(
                "device.public_key cannot be empty".to_string(),
            ));
        }

        // Validate metadata timestamps and required fields based on variant
        match &self.metadata {
            ProfileMetadata::CamVideo(m) => {
                if m.started_at.is_empty() {
                    return Err(ManifestFormatError::InvalidField(
                        "metadata.started_at cannot be empty".to_string(),
                    ));
                }
                if m.ended_at.is_empty() {
                    return Err(ManifestFormatError::InvalidField(
                        "metadata.ended_at cannot be empty".to_string(),
                    ));
                }
            }
            ProfileMetadata::Sensor(m) => {
                if m.started_at.is_empty() {
                    return Err(ManifestFormatError::InvalidField(
                        "metadata.started_at cannot be empty".to_string(),
                    ));
                }
                if m.ended_at.is_empty() {
                    return Err(ManifestFormatError::InvalidField(
                        "metadata.ended_at cannot be empty".to_string(),
                    ));
                }
                if m.sample_rate_hz <= 0.0 {
                    return Err(ManifestFormatError::InvalidField(
                        "metadata.sample_rate_hz must be > 0".to_string(),
                    ));
                }
                if m.unit.is_empty() {
                    return Err(ManifestFormatError::InvalidField(
                        "metadata.unit cannot be empty".to_string(),
                    ));
                }
                if m.sensor_model.is_empty() {
                    return Err(ManifestFormatError::InvalidField(
                        "metadata.sensor_model cannot be empty".to_string(),
                    ));
                }
            }
            ProfileMetadata::Audio(m) => {
                if m.started_at.is_empty() {
                    return Err(ManifestFormatError::InvalidField(
                        "metadata.started_at cannot be empty".to_string(),
                    ));
                }
                if m.ended_at.is_empty() {
                    return Err(ManifestFormatError::InvalidField(
                        "metadata.ended_at cannot be empty".to_string(),
                    ));
                }
                if m.sample_rate_hz == 0 {
                    return Err(ManifestFormatError::InvalidField(
                        "metadata.sample_rate_hz must be > 0".to_string(),
                    ));
                }
                if m.bit_depth == 0 {
                    return Err(ManifestFormatError::InvalidField(
                        "metadata.bit_depth must be > 0".to_string(),
                    ));
                }
                if m.channels == 0 {
                    return Err(ManifestFormatError::InvalidField(
                        "metadata.channels must be > 0".to_string(),
                    ));
                }
                if m.codec.is_empty() {
                    return Err(ManifestFormatError::InvalidField(
                        "metadata.codec cannot be empty".to_string(),
                    ));
                }
            }
            ProfileMetadata::Log(m) => {
                if m.started_at.is_empty() {
                    return Err(ManifestFormatError::InvalidField(
                        "metadata.started_at cannot be empty".to_string(),
                    ));
                }
                if m.ended_at.is_empty() {
                    return Err(ManifestFormatError::InvalidField(
                        "metadata.ended_at cannot be empty".to_string(),
                    ));
                }
                if m.application.is_empty() {
                    return Err(ManifestFormatError::InvalidField(
                        "metadata.application cannot be empty".to_string(),
                    ));
                }
                if m.host.is_empty() {
                    return Err(ManifestFormatError::InvalidField(
                        "metadata.host cannot be empty".to_string(),
                    ));
                }
                if m.log_level.is_empty() {
                    return Err(ManifestFormatError::InvalidField(
                        "metadata.log_level cannot be empty".to_string(),
                    ));
                }
                if m.log_format.is_empty() {
                    return Err(ManifestFormatError::InvalidField(
                        "metadata.log_format cannot be empty".to_string(),
                    ));
                }
            }
            ProfileMetadata::Generic(m) => {
                if m.started_at.is_empty() {
                    return Err(ManifestFormatError::InvalidField(
                        "metadata.started_at cannot be empty".to_string(),
                    ));
                }
                if m.ended_at.is_empty() {
                    return Err(ManifestFormatError::InvalidField(
                        "metadata.ended_at cannot be empty".to_string(),
                    ));
                }
            }
        }

        if self.segments.is_empty() {
            return Err(ManifestFormatError::InvalidField(
                "segments cannot be empty".to_string(),
            ));
        }

        for (i, segment) in self.segments.iter().enumerate() {
            if segment.chunk_file.is_empty() {
                return Err(ManifestFormatError::InvalidField(format!(
                    "segment[{}].chunk_file cannot be empty",
                    i
                )));
            }
            if segment.blake3_hash.is_empty() {
                return Err(ManifestFormatError::InvalidField(format!(
                    "segment[{}].blake3_hash cannot be empty",
                    i
                )));
            }
            if segment.continuity_hash.is_empty() {
                return Err(ManifestFormatError::InvalidField(format!(
                    "segment[{}].continuity_hash cannot be empty",
                    i
                )));
            }
        }

        // C4 (0.2.0): an encryption block with no recipients is a hard error —
        // it is ambiguous between "mistake" and "intentionally unreadable".
        // Sign-only archives use `encryption: None` instead (see the design doc).
        if let Some(ref enc) = self.encryption {
            if enc.recipients.is_empty() {
                return Err(ManifestFormatError::InvalidField(
                    "encryption.recipients cannot be empty (use sign-only mode for no encryption)"
                        .to_string(),
                ));
            }
        }

        Ok(())
    }
}

impl Default for TrstManifest {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn cam_video_manifest() -> TrstManifest {
        let mut m = TrstManifest::new_cam_video();
        m.device.id = "TEST001".to_string();
        m.device.public_key = "ed25519:test_key".to_string();
        if let ProfileMetadata::CamVideo(ref mut meta) = m.metadata {
            meta.started_at = "2025-01-15T10:30:00Z".to_string();
            meta.ended_at = "2025-01-15T10:30:02Z".to_string();
        }
        m.segments.push(SegmentInfo {
            chunk_file: "00000.bin".to_string(),
            blake3_hash: "abc123".to_string(),
            start_time: "2025-01-15T10:30:00Z".to_string(),
            duration_seconds: 2.0,
            continuity_hash: "def456".to_string(),
        });
        m
    }

    fn generic_manifest() -> TrstManifest {
        let mut m = TrstManifest::new();
        m.device.id = "GENERIC001".to_string();
        m.device.public_key = "ed25519:generic_key".to_string();
        if let ProfileMetadata::Generic(ref mut meta) = m.metadata {
            meta.started_at = "2025-01-15T10:30:00Z".to_string();
            meta.ended_at = "2025-01-15T10:30:02Z".to_string();
        }
        m.segments.push(SegmentInfo {
            chunk_file: "00000.bin".to_string(),
            blake3_hash: "abc123".to_string(),
            start_time: "2025-01-15T10:30:00Z".to_string(),
            duration_seconds: 2.0,
            continuity_hash: "def456".to_string(),
        });
        m
    }

    // ── New profile-agnostic tests ──

    #[test]
    fn test_generic_metadata_canonical_serialization() {
        let mut m = TrstManifest::new();
        m.device.id = "G001".to_string();
        m.device.public_key = "ed25519:k".to_string();
        if let ProfileMetadata::Generic(ref mut meta) = m.metadata {
            meta.started_at = "2025-01-15T10:00:00Z".to_string();
            meta.ended_at = "2025-01-15T10:00:10Z".to_string();
            meta.data_type = Some("sensor".to_string());
            meta.source = Some("drone-cam-01".to_string());
            meta.description = Some("Test capture".to_string());
            meta.mime_type = Some("application/octet-stream".to_string());
            meta.labels.insert("env".to_string(), "prod".to_string());
            meta.labels
                .insert("camera".to_string(), "front".to_string());
        }
        m.segments.push(SegmentInfo {
            chunk_file: "00000.bin".to_string(),
            blake3_hash: "abc".to_string(),
            start_time: "2025-01-15T10:00:00Z".to_string(),
            duration_seconds: 10.0,
            continuity_hash: "def".to_string(),
        });

        let bytes = m.to_canonical_bytes().unwrap();
        let json = String::from_utf8(bytes).unwrap();

        // Must contain metadata section
        assert!(json.contains("\"metadata\""));
        assert!(json.contains("\"data_type\""));
        assert!(json.contains("\"source\""));
        // Labels must be sorted: "camera" before "env"
        let camera_pos = json.find("\"camera\"").unwrap();
        let env_pos = json.find("\"env\"").unwrap();
        assert!(camera_pos < env_pos, "labels must have sorted keys");
    }

    #[test]
    fn test_cam_video_metadata_canonical_serialization() {
        let m = cam_video_manifest();
        let bytes = m.to_canonical_bytes().unwrap();
        let json = String::from_utf8(bytes).unwrap();

        assert!(json.contains("\"metadata\""));
        assert!(json.contains("\"fps\""));
        assert!(json.contains("\"resolution\""));
        assert!(json.contains("\"codec\""));
        assert!(json.contains("\"timezone\""));
    }

    #[test]
    fn test_generic_metadata_round_trip() {
        let mut m = TrstManifest::new();
        if let ProfileMetadata::Generic(ref mut meta) = m.metadata {
            meta.started_at = "2025-01-15T10:00:00Z".to_string();
            meta.ended_at = "2025-01-15T10:00:10Z".to_string();
            meta.data_type = Some("video".to_string());
            meta.source = Some("cam-01".to_string());
            meta.labels
                .insert("region".to_string(), "us-east".to_string());
        }

        let json = serde_json::to_string(&m).unwrap();
        let decoded: TrstManifest = serde_json::from_str(&json).unwrap();

        if let ProfileMetadata::Generic(meta) = decoded.metadata {
            assert_eq!(meta.data_type, Some("video".to_string()));
            assert_eq!(meta.source, Some("cam-01".to_string()));
            assert_eq!(meta.labels.get("region"), Some(&"us-east".to_string()));
        } else {
            panic!("Expected Generic variant");
        }
    }

    #[test]
    fn test_generic_metadata_minimal_round_trip() {
        // All optional fields absent
        let mut m = TrstManifest::new();
        if let ProfileMetadata::Generic(ref mut meta) = m.metadata {
            meta.started_at = "2025-01-15T10:00:00Z".to_string();
            meta.ended_at = "2025-01-15T10:00:10Z".to_string();
        }

        let json = serde_json::to_string(&m).unwrap();
        let decoded: TrstManifest = serde_json::from_str(&json).unwrap();

        if let ProfileMetadata::Generic(meta) = decoded.metadata {
            assert!(meta.data_type.is_none());
            assert!(meta.source.is_none());
            assert!(meta.labels.is_empty());
        } else {
            panic!("Expected Generic variant");
        }
    }

    #[test]
    fn test_validation_accepts_generic_profile() {
        let m = generic_manifest();
        assert!(
            m.validate().is_ok(),
            "validate() must accept profile='generic'"
        );
    }

    #[test]
    fn test_validation_accepts_cam_video_profile() {
        let m = cam_video_manifest();
        assert!(
            m.validate().is_ok(),
            "validate() must accept profile='cam.video'"
        );
    }

    #[test]
    fn test_validation_rejects_unknown_profile() {
        let mut m = TrstManifest::new();
        m.profile = "unknown".to_string();
        m.device.id = "X".to_string();
        m.device.public_key = "ed25519:k".to_string();
        if let ProfileMetadata::Generic(ref mut meta) = m.metadata {
            meta.started_at = "2025-01-15T10:00:00Z".to_string();
            meta.ended_at = "2025-01-15T10:00:01Z".to_string();
        }
        m.segments.push(SegmentInfo {
            chunk_file: "00000.bin".to_string(),
            blake3_hash: "h".to_string(),
            start_time: "t".to_string(),
            duration_seconds: 1.0,
            continuity_hash: "c".to_string(),
        });
        assert!(m.validate().is_err());
    }

    #[test]
    fn test_validation_rejects_empty_trst_version() {
        let mut m = generic_manifest();
        m.trst_version = String::new();
        assert!(m.validate().is_err());
    }

    #[test]
    fn test_validation_rejects_empty_device_id() {
        let mut m = generic_manifest();
        m.device.id = String::new();
        assert!(m.validate().is_err());
    }

    #[test]
    fn test_validation_rejects_empty_public_key() {
        let mut m = generic_manifest();
        m.device.public_key = String::new();
        assert!(m.validate().is_err());
    }

    #[test]
    fn test_cam_video_manifest_alias_compiles() {
        // CamVideoManifest is a type alias for TrstManifest — this must compile
        let m: CamVideoManifest = TrstManifest::new_cam_video();
        assert_eq!(m.profile, "cam.video");
    }

    #[test]
    fn test_labels_sorted_in_canonical_output() {
        let mut m = TrstManifest::new();
        m.device.id = "X".to_string();
        m.device.public_key = "ed25519:k".to_string();
        if let ProfileMetadata::Generic(ref mut meta) = m.metadata {
            meta.started_at = "t".to_string();
            meta.ended_at = "t".to_string();
            meta.labels.insert("z-key".to_string(), "1".to_string());
            meta.labels.insert("a-key".to_string(), "2".to_string());
            meta.labels.insert("m-key".to_string(), "3".to_string());
        }
        m.segments.push(SegmentInfo {
            chunk_file: "00000.bin".to_string(),
            blake3_hash: "h".to_string(),
            start_time: "t".to_string(),
            duration_seconds: 1.0,
            continuity_hash: "c".to_string(),
        });

        let bytes = m.to_canonical_bytes().unwrap();
        let json = String::from_utf8(bytes).unwrap();

        let a_pos = json.find("\"a-key\"").unwrap();
        let m_pos = json.find("\"m-key\"").unwrap();
        let z_pos = json.find("\"z-key\"").unwrap();
        assert!(a_pos < m_pos && m_pos < z_pos, "labels must be sorted");
    }

    // ── Retained tests (updated for new API) ──

    #[test]
    fn test_manifest_creation() {
        let manifest = TrstManifest::new_cam_video();
        assert_eq!(manifest.trst_version, "0.1.0");
        assert_eq!(manifest.profile, "cam.video");
        assert_eq!(manifest.device.model, "TrustEdgeRefCam");
        if let ProfileMetadata::CamVideo(m) = &manifest.metadata {
            assert_eq!(m.fps, 30.0);
        } else {
            panic!("Expected CamVideo variant");
        }
    }

    #[test]
    fn test_canonical_bytes_excludes_signature() {
        let mut manifest = cam_video_manifest();

        let bytes_without_sig = manifest.to_canonical_bytes().unwrap();
        let json_str = String::from_utf8(bytes_without_sig.clone()).unwrap();
        assert!(!json_str.contains("signature"));

        manifest.set_signature("test_signature".to_string());
        let bytes_with_sig = manifest.to_canonical_bytes().unwrap();

        assert_eq!(bytes_without_sig, bytes_with_sig);
    }

    #[test]
    fn test_key_ordering() {
        let manifest = cam_video_manifest();
        let canonical_bytes = manifest.to_canonical_bytes().unwrap();
        let json_str = String::from_utf8(canonical_bytes).unwrap();

        let trst_pos = json_str.find("\"trst_version\"").unwrap();
        let profile_pos = json_str.find("\"profile\"").unwrap();
        let device_pos = json_str.find("\"device\"").unwrap();
        let metadata_pos = json_str.find("\"metadata\"").unwrap();
        let chunk_pos = json_str.find("\"chunk\"").unwrap();
        let segments_pos = json_str.find("\"segments\"").unwrap();
        let claims_pos = json_str.find("\"claims\"").unwrap();

        assert!(trst_pos < profile_pos);
        assert!(profile_pos < device_pos);
        assert!(device_pos < metadata_pos);
        assert!(metadata_pos < chunk_pos);
        assert!(chunk_pos < segments_pos);
        assert!(segments_pos < claims_pos);
    }

    #[test]
    fn test_validation() {
        let manifest = cam_video_manifest();
        assert!(manifest.validate().is_ok());
    }

    #[test]
    fn test_stable_canonicalization() {
        let manifest = cam_video_manifest();

        let bytes1 = manifest.to_canonical_bytes().unwrap();
        let bytes2 = manifest.to_canonical_bytes().unwrap();
        let bytes3 = manifest.to_canonical_bytes().unwrap();

        assert_eq!(bytes1, bytes2);
        assert_eq!(bytes2, bytes3);
    }

    // ── New sensor/audio/log profile tests ──

    fn make_segment() -> SegmentInfo {
        SegmentInfo {
            chunk_file: "00000.bin".to_string(),
            blake3_hash: "abc123".to_string(),
            start_time: "2025-06-01T00:00:00Z".to_string(),
            duration_seconds: 1.0,
            continuity_hash: "def456".to_string(),
        }
    }

    #[test]
    fn test_sensor_metadata_round_trip() {
        let mut m = TrstManifest::new_sensor();
        m.device.id = "SENSOR001".to_string();
        m.device.public_key = "ed25519:sensor_key".to_string();
        if let ProfileMetadata::Sensor(ref mut meta) = m.metadata {
            meta.started_at = "2025-06-01T00:00:00Z".to_string();
            meta.ended_at = "2025-06-01T00:01:00Z".to_string();
            meta.sample_rate_hz = 1000.0;
            meta.unit = "celsius".to_string();
            meta.sensor_model = "BME280".to_string();
            meta.latitude = Some(37.7749);
            meta.longitude = Some(-122.4194);
            meta.altitude = Some(16.0);
            meta.labels
                .insert("zone".to_string(), "outdoor".to_string());
        }
        m.segments.push(make_segment());

        let json = serde_json::to_string(&m).unwrap();
        let decoded: TrstManifest = serde_json::from_str(&json).unwrap();

        if let ProfileMetadata::Sensor(meta) = decoded.metadata {
            assert_eq!(meta.unit, "celsius");
            assert_eq!(meta.sensor_model, "BME280");
            assert_eq!(meta.sample_rate_hz, 1000.0);
            assert_eq!(meta.latitude, Some(37.7749));
            assert_eq!(meta.longitude, Some(-122.4194));
            assert_eq!(meta.altitude, Some(16.0));
            assert_eq!(meta.labels.get("zone"), Some(&"outdoor".to_string()));
        } else {
            panic!("Expected Sensor variant, got something else");
        }
    }

    #[test]
    fn test_audio_metadata_round_trip() {
        let mut m = TrstManifest::new_audio();
        m.device.id = "AUDIO001".to_string();
        m.device.public_key = "ed25519:audio_key".to_string();
        if let ProfileMetadata::Audio(ref mut meta) = m.metadata {
            meta.started_at = "2025-06-01T00:00:00Z".to_string();
            meta.ended_at = "2025-06-01T00:01:00Z".to_string();
            meta.sample_rate_hz = 48000;
            meta.bit_depth = 24;
            meta.channels = 1;
            meta.codec = "flac".to_string();
        }
        m.segments.push(make_segment());

        let json = serde_json::to_string(&m).unwrap();
        let decoded: TrstManifest = serde_json::from_str(&json).unwrap();

        if let ProfileMetadata::Audio(meta) = decoded.metadata {
            assert_eq!(meta.sample_rate_hz, 48000);
            assert_eq!(meta.bit_depth, 24);
            assert_eq!(meta.channels, 1);
            assert_eq!(meta.codec, "flac");
        } else {
            panic!("Expected Audio variant, got something else");
        }
    }

    #[test]
    fn test_log_metadata_round_trip() {
        let mut m = TrstManifest::new_log();
        m.device.id = "LOG001".to_string();
        m.device.public_key = "ed25519:log_key".to_string();
        if let ProfileMetadata::Log(ref mut meta) = m.metadata {
            meta.started_at = "2025-06-01T00:00:00Z".to_string();
            meta.ended_at = "2025-06-01T00:01:00Z".to_string();
            meta.application = "sealedge-agent".to_string();
            meta.host = "edge-node-01".to_string();
            meta.log_level = "warn".to_string();
            meta.log_format = "json".to_string();
        }
        m.segments.push(make_segment());

        let json = serde_json::to_string(&m).unwrap();
        let decoded: TrstManifest = serde_json::from_str(&json).unwrap();

        if let ProfileMetadata::Log(meta) = decoded.metadata {
            assert_eq!(meta.application, "sealedge-agent");
            assert_eq!(meta.host, "edge-node-01");
            assert_eq!(meta.log_level, "warn");
            assert_eq!(meta.log_format, "json");
        } else {
            panic!("Expected Log variant, got something else");
        }
    }

    #[test]
    fn test_sensor_canonical_serialization() {
        let mut m = TrstManifest::new_sensor();
        m.device.id = "S001".to_string();
        m.device.public_key = "ed25519:k".to_string();
        if let ProfileMetadata::Sensor(ref mut meta) = m.metadata {
            meta.started_at = "2025-06-01T00:00:00Z".to_string();
            meta.ended_at = "2025-06-01T00:01:00Z".to_string();
            meta.sample_rate_hz = 100.0;
            meta.unit = "celsius".to_string();
            meta.sensor_model = "BME280".to_string();
            meta.latitude = Some(37.7749);
            meta.longitude = Some(-122.4194);
            meta.altitude = Some(16.0);
            meta.labels.insert("z-key".to_string(), "1".to_string());
            meta.labels.insert("a-key".to_string(), "2".to_string());
        }
        m.segments.push(make_segment());

        let bytes = m.to_canonical_bytes().unwrap();
        let json = String::from_utf8(bytes).unwrap();

        // Key ordering
        let started_pos = json.find("\"started_at\"").unwrap();
        let ended_pos = json.find("\"ended_at\"").unwrap();
        let rate_pos = json.find("\"sample_rate_hz\"").unwrap();
        let unit_pos = json.find("\"unit\"").unwrap();
        let model_pos = json.find("\"sensor_model\"").unwrap();
        let lat_pos = json.find("\"latitude\"").unwrap();
        let lon_pos = json.find("\"longitude\"").unwrap();
        let alt_pos = json.find("\"altitude\"").unwrap();

        assert!(started_pos < ended_pos);
        assert!(ended_pos < rate_pos);
        assert!(rate_pos < unit_pos);
        assert!(unit_pos < model_pos);
        assert!(model_pos < lat_pos);
        assert!(lat_pos < lon_pos);
        assert!(lon_pos < alt_pos);

        // Labels sorted
        let a_pos = json.find("\"a-key\"").unwrap();
        let z_pos = json.find("\"z-key\"").unwrap();
        assert!(a_pos < z_pos, "labels must be sorted");
    }

    #[test]
    fn test_audio_canonical_serialization() {
        let mut m = TrstManifest::new_audio();
        m.device.id = "A001".to_string();
        m.device.public_key = "ed25519:k".to_string();
        if let ProfileMetadata::Audio(ref mut meta) = m.metadata {
            meta.started_at = "2025-06-01T00:00:00Z".to_string();
            meta.ended_at = "2025-06-01T00:01:00Z".to_string();
            meta.sample_rate_hz = 44100;
            meta.bit_depth = 16;
            meta.channels = 2;
            meta.codec = "pcm".to_string();
        }
        m.segments.push(make_segment());

        let bytes = m.to_canonical_bytes().unwrap();
        let json = String::from_utf8(bytes).unwrap();

        let started_pos = json.find("\"started_at\"").unwrap();
        let ended_pos = json.find("\"ended_at\"").unwrap();
        let rate_pos = json.find("\"sample_rate_hz\"").unwrap();
        let depth_pos = json.find("\"bit_depth\"").unwrap();
        let chan_pos = json.find("\"channels\"").unwrap();
        let codec_pos = json.find("\"codec\"").unwrap();

        assert!(started_pos < ended_pos);
        assert!(ended_pos < rate_pos);
        assert!(rate_pos < depth_pos);
        assert!(depth_pos < chan_pos);
        assert!(chan_pos < codec_pos);
    }

    #[test]
    fn test_log_canonical_serialization() {
        let mut m = TrstManifest::new_log();
        m.device.id = "L001".to_string();
        m.device.public_key = "ed25519:k".to_string();
        if let ProfileMetadata::Log(ref mut meta) = m.metadata {
            meta.started_at = "2025-06-01T00:00:00Z".to_string();
            meta.ended_at = "2025-06-01T00:01:00Z".to_string();
            meta.application = "agent".to_string();
            meta.host = "node-01".to_string();
            meta.log_level = "info".to_string();
            meta.log_format = "json".to_string();
        }
        m.segments.push(make_segment());

        let bytes = m.to_canonical_bytes().unwrap();
        let json = String::from_utf8(bytes).unwrap();

        let started_pos = json.find("\"started_at\"").unwrap();
        let ended_pos = json.find("\"ended_at\"").unwrap();
        let app_pos = json.find("\"application\"").unwrap();
        let host_pos = json.find("\"host\"").unwrap();
        let level_pos = json.find("\"log_level\"").unwrap();
        let format_pos = json.find("\"log_format\"").unwrap();

        assert!(started_pos < ended_pos);
        assert!(ended_pos < app_pos);
        assert!(app_pos < host_pos);
        assert!(host_pos < level_pos);
        assert!(level_pos < format_pos);
    }

    #[test]
    fn test_validation_accepts_sensor_profile() {
        let mut m = TrstManifest::new_sensor();
        m.device.id = "S001".to_string();
        m.device.public_key = "ed25519:k".to_string();
        if let ProfileMetadata::Sensor(ref mut meta) = m.metadata {
            meta.started_at = "2025-06-01T00:00:00Z".to_string();
            meta.ended_at = "2025-06-01T00:01:00Z".to_string();
            meta.unit = "celsius".to_string();
            meta.sensor_model = "BME280".to_string();
        }
        m.segments.push(make_segment());
        assert!(
            m.validate().is_ok(),
            "validate() must accept profile='sensor'"
        );
    }

    #[test]
    fn test_validation_accepts_audio_profile() {
        let mut m = TrstManifest::new_audio();
        m.device.id = "A001".to_string();
        m.device.public_key = "ed25519:k".to_string();
        if let ProfileMetadata::Audio(ref mut meta) = m.metadata {
            meta.started_at = "2025-06-01T00:00:00Z".to_string();
            meta.ended_at = "2025-06-01T00:01:00Z".to_string();
        }
        m.segments.push(make_segment());
        assert!(
            m.validate().is_ok(),
            "validate() must accept profile='audio'"
        );
    }

    #[test]
    fn test_validation_accepts_log_profile() {
        let mut m = TrstManifest::new_log();
        m.device.id = "L001".to_string();
        m.device.public_key = "ed25519:k".to_string();
        if let ProfileMetadata::Log(ref mut meta) = m.metadata {
            meta.started_at = "2025-06-01T00:00:00Z".to_string();
            meta.ended_at = "2025-06-01T00:01:00Z".to_string();
            meta.application = "agent".to_string();
            meta.host = "node-01".to_string();
        }
        m.segments.push(make_segment());
        assert!(m.validate().is_ok(), "validate() must accept profile='log'");
    }

    #[test]
    fn test_untagged_sensor_discrimination() {
        // JSON with unit+sensor_model should deserialize as Sensor, not Generic
        let json = r#"{
            "started_at": "2025-06-01T00:00:00Z",
            "ended_at": "2025-06-01T00:01:00Z",
            "sample_rate_hz": 100.0,
            "unit": "celsius",
            "sensor_model": "BME280"
        }"#;
        let meta: ProfileMetadata = serde_json::from_str(json).unwrap();
        assert!(
            matches!(meta, ProfileMetadata::Sensor(_)),
            "Expected Sensor variant but got a different variant"
        );
    }

    #[test]
    fn test_untagged_audio_discrimination() {
        // JSON with bit_depth+channels should deserialize as Audio, not Generic
        let json = r#"{
            "started_at": "2025-06-01T00:00:00Z",
            "ended_at": "2025-06-01T00:01:00Z",
            "sample_rate_hz": 44100,
            "bit_depth": 16,
            "channels": 2,
            "codec": "pcm"
        }"#;
        let meta: ProfileMetadata = serde_json::from_str(json).unwrap();
        assert!(
            matches!(meta, ProfileMetadata::Audio(_)),
            "Expected Audio variant but got a different variant"
        );
    }

    #[test]
    fn test_untagged_log_discrimination() {
        // JSON with application+host should deserialize as Log, not Generic
        let json = r#"{
            "started_at": "2025-06-01T00:00:00Z",
            "ended_at": "2025-06-01T00:01:00Z",
            "application": "sealedge-agent",
            "host": "edge-node-01",
            "log_level": "info",
            "log_format": "json"
        }"#;
        let meta: ProfileMetadata = serde_json::from_str(json).unwrap();
        assert!(
            matches!(meta, ProfileMetadata::Log(_)),
            "Expected Log variant but got a different variant"
        );
    }

    #[test]
    fn test_decimal_precision() {
        let mut manifest = TrstManifest::new_cam_video();
        manifest.device.id = "TEST001".to_string();
        manifest.device.public_key = "ed25519:test_key".to_string();
        if let ProfileMetadata::CamVideo(ref mut m) = manifest.metadata {
            m.fps = 29.97;
            m.started_at = "2025-01-15T10:30:00Z".to_string();
            m.ended_at = "2025-01-15T10:30:02Z".to_string();
        }
        manifest.segments.push(SegmentInfo {
            chunk_file: "00000.bin".to_string(),
            blake3_hash: "abc123".to_string(),
            start_time: "2025-01-15T10:30:00Z".to_string(),
            duration_seconds: 2.0,
            continuity_hash: "def456".to_string(),
        });

        let canonical_bytes = manifest.to_canonical_bytes().unwrap();
        let json_str = String::from_utf8(canonical_bytes).unwrap();
        assert!(json_str.contains("29.97"));
    }

    // ── C4 (0.2.0) content-encryption block ──

    fn encryption_block() -> EncryptionBlock {
        EncryptionBlock {
            content_aead: "XChaCha20Poly1305".to_string(),
            hpke: HpkeSuite {
                kem: "DHKEM(X25519,HKDF-SHA256)".to_string(),
                kdf: "HKDF-SHA256".to_string(),
                aead: "ChaCha20Poly1305".to_string(),
            },
            recipients: vec![
                RecipientEntry {
                    recipient_id: "b3:aaaa".to_string(),
                    recipient_pub: "x25519:AAAA".to_string(),
                    enc: "ZW5jMA==".to_string(),
                    wrapped_cek: "d3JhcDA=".to_string(),
                },
                RecipientEntry {
                    recipient_id: "b3:bbbb".to_string(),
                    recipient_pub: "x25519:BBBB".to_string(),
                    enc: "ZW5jMQ==".to_string(),
                    wrapped_cek: "d3JhcDE=".to_string(),
                },
            ],
        }
    }

    #[test]
    fn test_absent_encryption_bytes_unchanged() {
        // A default (0.1.0-shaped) manifest must canonicalize with NO new fields —
        // this is what keeps the C1/C2 golden vectors valid after the type change.
        let m = generic_manifest();
        let json = String::from_utf8(m.to_canonical_bytes().unwrap()).unwrap();
        assert!(!json.contains("encryption"));
        assert!(!json.contains("key_agreement_public"));
    }

    #[test]
    fn test_sign_only_serializes_without_encryption_key() {
        // encryption: None (sign-only) must not emit an "encryption" key at all
        // (distinct from an encrypted archive with an empty recipient list).
        let m = generic_manifest();
        let json = serde_json::to_string(&m).unwrap();
        assert!(!json.contains("\"encryption\""));
        let round: TrstManifest = serde_json::from_str(&json).unwrap();
        assert!(round.encryption.is_none());
    }

    #[test]
    fn test_encryption_canonical_field_order() {
        let mut m = generic_manifest();
        m.device.key_agreement_public = Some("x25519:DEVKA".to_string());
        m.encryption = Some(encryption_block());

        let json = String::from_utf8(m.to_canonical_bytes().unwrap()).unwrap();

        // key_agreement_public comes right after public_key, inside device.
        let pub_pos = json.find("\"public_key\"").unwrap();
        let ka_pos = json.find("\"key_agreement_public\"").unwrap();
        let meta_pos = json.find("\"metadata\"").unwrap();
        assert!(pub_pos < ka_pos && ka_pos < meta_pos);

        // encryption block comes after claims (and before prev_archive_hash, absent here).
        let claims_pos = json.find("\"claims\"").unwrap();
        let enc_pos = json.find("\"encryption\"").unwrap();
        assert!(claims_pos < enc_pos);

        // hpke sub-order kem < kdf < aead.
        let kem = json.find("\"kem\"").unwrap();
        let kdf = json.find("\"kdf\"").unwrap();
        let aead = json.find("\"aead\"").unwrap();
        assert!(kem < kdf && kdf < aead);

        // Recipients preserve array order (recipient 0 before recipient 1).
        let r0 = json.find("b3:aaaa").unwrap();
        let r1 = json.find("b3:bbbb").unwrap();
        assert!(r0 < r1, "recipients must serialize in array order");

        // Per-recipient field order.
        let rid = json.find("\"recipient_id\"").unwrap();
        let rpub = json.find("\"recipient_pub\"").unwrap();
        let renc = json.find("\"enc\"").unwrap();
        let rwrap = json.find("\"wrapped_cek\"").unwrap();
        assert!(rid < rpub && rpub < renc && renc < rwrap);
    }

    #[test]
    fn test_encryption_stable_and_signature_excluded() {
        let mut m = generic_manifest();
        m.device.key_agreement_public = Some("x25519:DEVKA".to_string());
        m.encryption = Some(encryption_block());

        let b1 = m.to_canonical_bytes().unwrap();
        m.set_signature("ed25519:whatever".to_string());
        let b2 = m.to_canonical_bytes().unwrap();
        assert_eq!(
            b1, b2,
            "signature must remain excluded from canonical bytes"
        );
    }

    #[test]
    fn test_validate_rejects_empty_recipients() {
        // C4/N4: encryption present with zero recipients must be rejected.
        let mut m = generic_manifest();
        let mut enc = encryption_block();
        enc.recipients.clear();
        m.encryption = Some(enc);
        let err = m.validate().unwrap_err();
        assert!(
            format!("{err}").contains("encryption.recipients cannot be empty"),
            "expected empty-recipients rejection, got: {err}"
        );

        // With recipients present, the same manifest validates.
        m.encryption = Some(encryption_block());
        assert!(m.validate().is_ok());
    }

    #[test]
    fn test_encryption_round_trip() {
        let mut m = generic_manifest();
        m.device.key_agreement_public = Some("x25519:DEVKA".to_string());
        m.encryption = Some(encryption_block());

        let json = serde_json::to_string(&m).unwrap();
        let round: TrstManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(
            round.device.key_agreement_public.as_deref(),
            Some("x25519:DEVKA")
        );
        let enc = round.encryption.expect("encryption present");
        assert_eq!(enc.content_aead, "XChaCha20Poly1305");
        assert_eq!(enc.recipients.len(), 2);
        assert_eq!(enc.recipients[1].recipient_id, "b3:bbbb");
    }
}
