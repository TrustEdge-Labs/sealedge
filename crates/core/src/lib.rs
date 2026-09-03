//
// Copyright (c) 2025 TRUSTEDGE LABS LLC
// This source code is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Project: sealedge — Privacy and trust at the edge.
//

#![cfg_attr(docsrs, feature(doc_cfg))]

//! # Sealedge Core
//!
//! Core cryptographic library and CLI tools for privacy-preserving edge computing.
//!
//! Sealedge Core provides production-ready cryptographic primitives, universal backend systems,
//! and secure network operations for data-agnostic encryption at the edge.
//!
//! ## Key Features
//!
//! - **Production Cryptography**: AES-256-GCM encryption with PBKDF2 key derivation
//! - **Universal Backend System**: Pluggable crypto operations (Software HSM, Keyring, YubiKey)
//! - **Live Audio Capture**: Real-time microphone input with configurable quality
//! - **Network Operations**: Secure client-server communication with mutual authentication
//! - **Hardware Integration**: YubiKey PIV support (experimental, v1.1 rewrite in progress)
//! - **Algorithm Agility**: Configurable cryptographic algorithms with forward compatibility
//! - **Memory Safety**: Proper key material cleanup with zeroization
//!
//! ## Quick Start
//!
//! ```rust
//! use sealedge_core::Envelope;
//! use ed25519_dalek::SigningKey;
//! use rand_core::OsRng;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Generate key pairs
//! let sender_key = SigningKey::generate(&mut OsRng);
//! let recipient_key = SigningKey::generate(&mut OsRng);
//!
//! // Encrypt data
//! let data = b"Secret message";
//! let envelope = Envelope::seal(data, &sender_key, &recipient_key.verifying_key())?;
//!
//! // Decrypt data
//! let decrypted = envelope.unseal(&recipient_key)?;
//! assert_eq!(decrypted, data);
//! # Ok(())
//! # }
//! ```
//!
//! ## Architecture
//!
//! Sealedge Core is organized into several key modules:
//!
//! - [`envelope`] - Cryptographic envelope format for secure data packaging
//! - [`backends`] - Universal Backend system for pluggable crypto operations
//! - [`audio`] - Live audio capture functionality (requires `audio` feature)
//! - [`auth`] - Network authentication and session management
//! - [`transport`] - Network transport layer for secure communication
//! - [`asymmetric`] - Public key cryptography operations
//! - [`format`] - Data format handling and MIME type detection
//!
//! ## Feature Flags
//!
//! Sealedge Core uses `default = []` (no features enabled) for fast CI and maximum portability.
//! Enable features as needed for your deployment:
//!
//! ### Backend Features
//!
//! Hardware and storage integrations:
//!
//! - **`yubikey`** — YubiKey PIV support (experimental, v1.1 rewrite in progress).
//!   Requires PCSC libraries (`libpcsclite-dev` on Linux, built-in on macOS). Implementation removed pending rewrite.
//!
//! ### Platform Features
//!
//! I/O and system capabilities:
//!
//! - **`audio`** — Live audio capture from microphones via cpal.
//!   Requires audio libraries (`libasound2-dev` on Linux, CoreAudio on macOS, WASAPI on Windows).
//!
//! ### Usage
//!
//! ```toml
//! [dependencies]
//! sealedge-core = { version = "0.2", features = ["audio"] }
//! ```

use serde::{Deserialize, Serialize};

/// The length of the nonce used for AES-GCM encryption (12 bytes).
pub const NONCE_LEN: usize = 12;

pub mod archive;
pub mod asymmetric;
pub mod audio;
pub mod auth;
pub mod backends;
pub mod chain;
pub mod chronicle;
pub mod crypto;
pub mod envelope;
pub mod error;
pub mod format;
pub mod hybrid;
pub mod keywrap;
pub mod point_attestation;
pub mod secret;
pub mod transport;
pub mod vectors;

// Layer hierarchy (Phase 1 scaffolding -- populated in later phases)
pub mod applications;
pub mod io;
pub mod primitives;
pub mod protocols;
pub mod secure_file;

pub use archive::{
    archive_dir_name, read_manifest, validate_archive, write_archive, ArchiveError, ArchiveWriter,
    ChunkOutcome, MANIFEST_MAX_BYTES, MAX_CHUNK_SIZE_BYTES, MAX_STORED_CHUNK_BYTES, SIG_MAX_BYTES,
};
// Retained compat re-export; read_archive is deprecated (loads all chunks — N3/H3).
#[allow(deprecated)]
pub use archive::read_archive;
pub use asymmetric::{
    decrypt_key_asymmetric, encrypt_key_asymmetric, key_exchange, AsymmetricError, KeyPair,
    PrivateKey, PublicKey,
};
#[cfg(feature = "audio")]
#[cfg_attr(docsrs, doc(cfg(feature = "audio")))]
pub use audio::AudioCapture;
pub use audio::{AudioChunk, AudioConfig};
pub use auth::{
    client_authenticate, server_authenticate, AuthChallenge, AuthMessage, AuthMessageType,
    ClientAuthResponse, ClientAuthResult, ServerAuthConfirm, ServerCertificate, SessionInfo,
    SessionManager, SESSION_ID_SIZE, SESSION_TIMEOUT,
};
pub use backends::{
    AsymmetricAlgorithm,
    BackendCapabilities,
    BackendInfo,
    BackendPreferences,
    BackendRegistry,
    CryptoOperation,
    CryptoResult,
    HashAlgorithm,
    KeyBackend,
    KeyContext,
    KeyDerivationContext,
    KeyMetadata,
    SignatureAlgorithm,
    SymmetricAlgorithm,
    // Universal backend system (new)
    UniversalBackend,
    UniversalBackendRegistry,
};
#[cfg(feature = "keyring")]
#[cfg_attr(docsrs, doc(cfg(feature = "keyring")))]
pub use backends::{KeyringBackend, UniversalKeyringBackend};
pub use chain::{
    blake3_hex_or_b64, chain_next, genesis, segment_hash, validate_chain, ChainError, ChainSegment,
};
pub use chronicle::{
    archive_digest, format_archive_id, ChronicleState, RotationNew, RotationOld, RotationRecord,
    WitnessRequest, ROTATION_KIND,
};
pub use crypto::{
    decrypt_segment, derive_chunk_key, encrypt_segment, format_nonce, generate_aad,
    generate_nonce24, is_encrypted_key_file, parse_nonce, sign_manifest, verify_manifest,
    CryptoError, DeviceKeypair,
};
pub use secret::Secret;
pub use secure_file::write_secure;
// Ed25519 types re-exported for downstream crates (JWKS, key management)
pub use ed25519_dalek::{SigningKey, VerifyingKey};
pub use envelope::{Envelope, EnvelopeMetadata};
pub use error::ManifestError; // ManifestError is re-exported from error.rs (which aliases ManifestFormatError)
pub use error::{BackendError, TransportError, TrustEdgeError};
pub use format::*;
pub use hybrid::{open_envelope, seal_for_recipient, HybridEncryptionError, SymmetricKey};
pub use keywrap::{
    cek_wrap_info, chunk_aad_v2, hpke_open_cek, hpke_seal_cek, hpke_seal_cek_with_rng, open_secret,
    parse_x25519_public, recipient_id, seal_secret, seeded_test_rng, ContentKey, DeviceBundle,
    KeyAgreementKeypair, CONTENT_AEAD_ID, HPKE_AEAD_ID, HPKE_KDF_ID, HPKE_KEM_ID,
    SEALED_SECRET_HEADER_V1,
};
pub use point_attestation::{ArtifactRef, PointAttestation, PointAttestationError};
pub use sealedge_seal_protocols::archive::manifest::{
    AudioMetadata, CamVideoManifest, CamVideoMetadata, CaptureInfo, ChunkInfo, DeviceInfo,
    EncryptionBlock, GenericMetadata, HpkeSuite, LogMetadata, ManifestFormatError, ProfileMetadata,
    RecipientEntry, SegmentInfo, SensorMetadata, TrstManifest,
};
pub use transport::{Transport, TransportConfig, TransportFactory};

// Shared wire types — re-exported from sealedge-types for downstream access
// Downstream crates can use `sealedge_core::sealedge_types::*` or the
// convenience re-exports `sealedge_core::Uuid` and `sealedge_core::DateTime`.
pub use sealedge_types;
pub use sealedge_types::{DateTime, Utc, Uuid};

// Receipt system re-exports (Layer 4 applications)
pub use applications::receipts::{
    assign_receipt, create_receipt, extract_receipt, verify_signature_chain, OwnershipReceipt,
};

// Attestation system re-exports (Layer 4 applications)
pub use applications::attestation::{
    create_signed_attestation, verify_attestation, Attestation, AttestationConfig,
    AttestationResult, KeySource, OutputFormat, VerificationConfig, VerificationDetails,
    VerificationInfo, VerificationResult,
};

/// Represents a chunk of data sent over the network, including encrypted data,
/// a signed manifest, the nonce used for encryption, and a timestamp.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetworkChunk {
    /// The sequence number of the chunk in the stream.
    pub sequence: u64,
    /// The encrypted data payload for this chunk.
    pub data: Vec<u8>,
    /// The serialized, signed manifest (bincode-encoded).
    pub manifest: Vec<u8>,
    /// The nonce used for AES-GCM encryption.
    pub nonce: [u8; NONCE_LEN],
    /// The timestamp (seconds since UNIX epoch) when the chunk was created.
    pub timestamp: u64,
}

impl NetworkChunk {
    /// Creates a new `NetworkChunk` with the given sequence number, encrypted data, manifest, and explicit nonce.
    ///
    /// Callers must supply a real nonce — there is no zero-nonce default.
    pub fn new(
        seq: u64,
        encrypted_data: Vec<u8>,
        manifest_bytes: Vec<u8>,
        nonce: [u8; NONCE_LEN],
    ) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            sequence: seq,
            data: encrypted_data,
            manifest: manifest_bytes,
            nonce,
            timestamp,
        }
    }

    /// Validates the `NetworkChunk`.
    ///
    /// Checks that the data and manifest are not empty, and that the timestamp is not more than 5 minutes in the future.
    /// Returns `Ok(())` if valid, or an error otherwise.
    pub fn validate(&self) -> Result<(), anyhow::Error> {
        if self.data.is_empty() {
            return Err(anyhow::anyhow!("Chunk data is empty"));
        }
        if self.manifest.is_empty() {
            return Err(anyhow::anyhow!("Manifest is empty"));
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| anyhow::anyhow!("Time error: {}", e))?
            .as_secs();

        if self.timestamp > now + 300 {
            // Not more than 5 minutes in future
            return Err(anyhow::anyhow!("Chunk timestamp is too far in the future"));
        }

        Ok(())
    }
}
