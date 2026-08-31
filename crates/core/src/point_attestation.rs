//
// Copyright (c) 2025 TRUSTEDGE LABS LLC
// This source code is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Project: sealedge — Privacy and trust at the edge.
//

//! Point attestation — lightweight JSON attestation documents.
//!
//! A `PointAttestation` cryptographically binds two artifacts (subject + evidence) with:
//! - Ed25519 signing (via `sign_manifest` / `verify_manifest`)
//! - BLAKE3 file hashing with `"b3:"` prefix
//! - Random 16-byte nonce for replay resistance
//! - ISO 8601 timestamp
//! - Deterministic canonical JSON serialization (signature excluded from signed bytes)
//!
//! This is the cryptographic foundation for the SBOM attestation wedge (Phases 76-78).

use std::path::Path;

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::crypto::{sign_manifest, verify_manifest, CryptoError, DeviceKeypair};

/// Format identifier for v1 point attestation documents.
pub const FORMAT_V1: &str = "te-point-attestation-v1";

/// Number of random nonce bytes (16 bytes = 128-bit security).
pub const NONCE_BYTES: usize = 16;

/// Errors that can occur during point attestation operations.
#[derive(Error, Debug)]
pub enum PointAttestationError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Cryptographic error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("Hash mismatch for {artifact}: expected {expected}, actual {actual}")]
    HashMismatch {
        artifact: String,
        expected: String,
        actual: String,
    },

    #[error("Attestation has no signature — sign before verifying")]
    MissingSignature,
}

/// A reference to a single artifact, including its BLAKE3 hash, filename, and label.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ArtifactRef {
    /// BLAKE3 hash in `"b3:<64-hex-chars>"` format.
    pub hash: String,
    /// Base filename (no directory component).
    pub filename: String,
    /// Freeform label, e.g. `"binary"` or `"sbom"`.
    pub label: String,
}

/// A signed point-in-time attestation binding two artifacts.
///
/// The canonical bytes used for signing are produced by [`PointAttestation::canonical_bytes`],
/// which serializes the struct to JSON with `signature` set to `None`.
///
/// # Examples
///
/// ```rust,no_run
/// # use sealedge_core::{PointAttestation, DeviceKeypair};
/// # use std::path::Path;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let keypair = DeviceKeypair::generate()?;
/// let attestation = PointAttestation::create(
///     Path::new("my-binary"),
///     "binary",
///     Path::new("sbom.json"),
///     "sbom",
///     &keypair,
/// )?;
/// let json = attestation.to_json()?;
/// let loaded = PointAttestation::from_json(&json)?;
/// let valid = loaded.verify_signature(&keypair.public)?;
/// assert!(valid);
/// # Ok(())
/// # }
/// ```
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PointAttestation {
    /// Format identifier — always `"te-point-attestation-v1"`.
    pub format: String,
    /// Crate version at signing time.
    pub sealedge_version: String,
    /// ISO 8601 timestamp with millisecond precision.
    pub timestamp: String,
    /// Hex-encoded 16 random bytes for replay resistance.
    pub nonce: String,
    /// Subject artifact (e.g., the binary being attested).
    pub subject: ArtifactRef,
    /// Evidence artifact (e.g., the SBOM).
    pub evidence: ArtifactRef,
    /// Signer's public key in `"ed25519:<base64>"` format.
    pub public_key: String,
    /// Ed25519 signature in `"ed25519:<base64>"` format, or `None` before signing.
    pub signature: Option<String>,
}

/// Hash a file with BLAKE3 and return `"b3:<64-hex-chars>"`.
///
/// Streams the file through a fixed 64 KiB buffer (H3) instead of reading it whole
/// — hashing a large binary/SBOM is bounded to the buffer, not the file size.
pub fn hash_file(path: &Path) -> Result<String, PointAttestationError> {
    use std::io::Read as _;
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("b3:{}", hasher.finalize().to_hex()))
}

impl PointAttestation {
    /// Create and sign a new point attestation.
    ///
    /// Hashes both files with BLAKE3, generates a random nonce, records a timestamp,
    /// builds the struct, signs it via `sign_manifest`, and returns the signed attestation.
    pub fn create(
        subject_path: &Path,
        subject_label: &str,
        evidence_path: &Path,
        evidence_label: &str,
        keypair: &DeviceKeypair,
    ) -> Result<Self, PointAttestationError> {
        let subject_hash = hash_file(subject_path)?;
        let evidence_hash = hash_file(evidence_path)?;

        let subject_filename = subject_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let evidence_filename = evidence_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();

        let mut nonce_bytes = [0u8; NONCE_BYTES];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = hex::encode(nonce_bytes);

        let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

        let mut attestation = PointAttestation {
            format: FORMAT_V1.to_string(),
            sealedge_version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp,
            nonce,
            subject: ArtifactRef {
                hash: subject_hash,
                filename: subject_filename,
                label: subject_label.to_string(),
            },
            evidence: ArtifactRef {
                hash: evidence_hash,
                filename: evidence_filename,
                label: evidence_label.to_string(),
            },
            public_key: keypair.public.clone(),
            signature: None,
        };

        let canonical = attestation.canonical_bytes()?;
        let sig = sign_manifest(keypair, &canonical)?;
        attestation.signature = Some(sig);

        Ok(attestation)
    }

    /// Produce the canonical bytes for signing/verification.
    ///
    /// Clones the struct, sets `signature` to `None`, then serializes to JSON bytes.
    /// Field order is determined by struct declaration order, which is stable.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PointAttestationError> {
        let mut canonical = self.clone();
        canonical.signature = None;
        let json_string = serde_json::to_string(&canonical)?;
        Ok(json_string.into_bytes())
    }

    /// Verify the Ed25519 signature against the given public key.
    ///
    /// Returns `Ok(true)` if valid, `Ok(false)` if the signature does not match,
    /// or `Err` if the signature is absent or the key/signature format is invalid.
    pub fn verify_signature(&self, device_public: &str) -> Result<bool, PointAttestationError> {
        let sig = self
            .signature
            .as_deref()
            .ok_or(PointAttestationError::MissingSignature)?;
        let canonical = self.canonical_bytes()?;
        let result = verify_manifest(device_public, &canonical, sig)?;
        Ok(result)
    }

    /// Verify BLAKE3 file hashes against stored artifact references.
    ///
    /// Only paths that are `Some` are checked. Returns `Ok(())` if all provided
    /// files match their recorded hashes, or `Err(HashMismatch)` on first failure.
    pub fn verify_file_hashes(
        &self,
        subject_path: Option<&Path>,
        evidence_path: Option<&Path>,
    ) -> Result<(), PointAttestationError> {
        if let Some(path) = subject_path {
            let actual = hash_file(path)?;
            if actual != self.subject.hash {
                return Err(PointAttestationError::HashMismatch {
                    artifact: self.subject.filename.clone(),
                    expected: self.subject.hash.clone(),
                    actual,
                });
            }
        }
        if let Some(path) = evidence_path {
            let actual = hash_file(path)?;
            if actual != self.evidence.hash {
                return Err(PointAttestationError::HashMismatch {
                    artifact: self.evidence.filename.clone(),
                    expected: self.evidence.hash.clone(),
                    actual,
                });
            }
        }
        Ok(())
    }

    /// Serialize to pretty-printed JSON for writing to a `.se-attestation.json` file.
    pub fn to_json(&self) -> Result<String, PointAttestationError> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Deserialize from JSON (compact or pretty).
    pub fn from_json(json: &str) -> Result<Self, PointAttestationError> {
        Ok(serde_json::from_str(json)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as IoWrite;
    use tempfile::NamedTempFile;

    fn make_temp_file(content: &[u8]) -> NamedTempFile {
        let mut f = NamedTempFile::new().expect("temp file");
        f.write_all(content).expect("write");
        f
    }

    fn gen_keypair() -> DeviceKeypair {
        DeviceKeypair::generate().expect("keypair")
    }

    #[test]
    fn test_create_produces_signature() {
        let keypair = gen_keypair();
        let subject = make_temp_file(b"subject content");
        let evidence = make_temp_file(b"evidence content");

        let attest =
            PointAttestation::create(subject.path(), "binary", evidence.path(), "sbom", &keypair)
                .expect("create");

        assert!(attest.signature.is_some());
        let sig = attest.signature.as_ref().unwrap();
        assert!(
            sig.starts_with("ed25519:"),
            "sig should start with ed25519:"
        );
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let keypair = gen_keypair();
        let subject = make_temp_file(b"hello world");
        let evidence = make_temp_file(b"sbom data");

        let attest =
            PointAttestation::create(subject.path(), "binary", evidence.path(), "sbom", &keypair)
                .expect("create");

        let json = attest.to_json().expect("to_json");
        let loaded = PointAttestation::from_json(&json).expect("from_json");
        let valid = loaded.verify_signature(&keypair.public).expect("verify");
        assert!(valid, "signature should verify");
    }

    #[test]
    fn test_verify_wrong_public_key() {
        let keypair = gen_keypair();
        let wrong_keypair = gen_keypair();
        let subject = make_temp_file(b"hello world");
        let evidence = make_temp_file(b"sbom data");

        let attest =
            PointAttestation::create(subject.path(), "binary", evidence.path(), "sbom", &keypair)
                .expect("create");

        let valid = attest
            .verify_signature(&wrong_keypair.public)
            .expect("verify with wrong key");
        assert!(!valid, "wrong key should not verify");
    }

    #[test]
    fn test_tamper_fails_verification() {
        let keypair = gen_keypair();
        let subject = make_temp_file(b"original");
        let evidence = make_temp_file(b"evidence");

        let mut attest =
            PointAttestation::create(subject.path(), "binary", evidence.path(), "sbom", &keypair)
                .expect("create");

        // Tamper with a field
        attest.subject.label = "tampered".to_string();

        let valid = attest.verify_signature(&keypair.public).expect("verify");
        assert!(!valid, "tampered attestation should fail verification");
    }

    #[test]
    fn test_canonical_bytes_deterministic() {
        let keypair = gen_keypair();
        let subject = make_temp_file(b"data");
        let evidence = make_temp_file(b"evidence");

        let attest =
            PointAttestation::create(subject.path(), "binary", evidence.path(), "sbom", &keypair)
                .expect("create");

        let bytes1 = attest.canonical_bytes().expect("canonical 1");
        let bytes2 = attest.canonical_bytes().expect("canonical 2");
        assert_eq!(bytes1, bytes2, "canonical bytes must be deterministic");
    }

    #[test]
    fn test_canonical_bytes_excludes_signature() {
        let keypair = gen_keypair();
        let subject = make_temp_file(b"data");
        let evidence = make_temp_file(b"evidence");

        let attest =
            PointAttestation::create(subject.path(), "binary", evidence.path(), "sbom", &keypair)
                .expect("create");

        let canonical = attest.canonical_bytes().expect("canonical");
        let canonical_str = std::str::from_utf8(&canonical).expect("utf8");

        // The canonical JSON should serialize signature as null (None -> null in JSON)
        // and should NOT contain the actual signature value
        let sig_val = attest.signature.as_ref().unwrap();
        assert!(
            !canonical_str.contains(sig_val),
            "canonical bytes must not contain the signature value"
        );

        // Deserialize to verify signature field is null
        let val: serde_json::Value = serde_json::from_str(canonical_str).expect("parse");
        assert!(
            val["signature"].is_null(),
            "signature must be null in canonical bytes"
        );
    }

    #[test]
    fn test_nonce_format() {
        let keypair = gen_keypair();
        let subject = make_temp_file(b"data");
        let evidence = make_temp_file(b"evidence");

        let attest =
            PointAttestation::create(subject.path(), "binary", evidence.path(), "sbom", &keypair)
                .expect("create");

        assert_eq!(
            attest.nonce.len(),
            32,
            "nonce should be 32 hex chars (16 bytes)"
        );
        assert!(
            attest.nonce.chars().all(|c| c.is_ascii_hexdigit()),
            "nonce should be hex"
        );
    }

    #[test]
    fn test_timestamp_format() {
        let keypair = gen_keypair();
        let subject = make_temp_file(b"data");
        let evidence = make_temp_file(b"evidence");

        let attest =
            PointAttestation::create(subject.path(), "binary", evidence.path(), "sbom", &keypair)
                .expect("create");

        // ISO 8601 with Z suffix
        assert!(
            attest.timestamp.ends_with('Z'),
            "timestamp should be UTC ISO 8601 ending in Z"
        );
        assert!(
            attest.timestamp.contains('T'),
            "timestamp should contain T separator"
        );
    }

    #[test]
    fn test_hash_format() {
        let subject = make_temp_file(b"content");
        let hash = hash_file(subject.path()).expect("hash");
        assert!(hash.starts_with("b3:"), "hash should start with b3:");
        // "b3:" + 64 hex chars
        assert_eq!(hash.len(), 3 + 64, "b3: prefix + 64 hex chars");
    }

    #[test]
    fn test_format_field() {
        let keypair = gen_keypair();
        let subject = make_temp_file(b"data");
        let evidence = make_temp_file(b"evidence");

        let attest =
            PointAttestation::create(subject.path(), "binary", evidence.path(), "sbom", &keypair)
                .expect("create");

        assert_eq!(attest.format, FORMAT_V1);
        assert_eq!(attest.format, "te-point-attestation-v1");
    }

    #[test]
    fn test_verify_file_hashes_correct_files_pass() {
        let keypair = gen_keypair();
        let subject = make_temp_file(b"subject bytes");
        let evidence = make_temp_file(b"evidence bytes");

        let attest =
            PointAttestation::create(subject.path(), "binary", evidence.path(), "sbom", &keypair)
                .expect("create");

        attest
            .verify_file_hashes(Some(subject.path()), Some(evidence.path()))
            .expect("file hashes should match");
    }

    #[test]
    fn test_verify_file_hashes_wrong_file_fails() {
        let keypair = gen_keypair();
        let subject = make_temp_file(b"subject bytes");
        let evidence = make_temp_file(b"evidence bytes");
        let wrong_file = make_temp_file(b"completely different content");

        let attest =
            PointAttestation::create(subject.path(), "binary", evidence.path(), "sbom", &keypair)
                .expect("create");

        let result = attest.verify_file_hashes(Some(wrong_file.path()), None);
        assert!(
            matches!(result, Err(PointAttestationError::HashMismatch { .. })),
            "wrong subject file should produce HashMismatch"
        );
    }

    #[test]
    fn test_verify_file_hashes_only_subject() {
        let keypair = gen_keypair();
        let subject = make_temp_file(b"subject only");
        let evidence = make_temp_file(b"evidence");

        let attest =
            PointAttestation::create(subject.path(), "binary", evidence.path(), "sbom", &keypair)
                .expect("create");

        // Only check subject, not evidence
        attest
            .verify_file_hashes(Some(subject.path()), None)
            .expect("subject only check should pass");
    }

    #[test]
    fn test_verify_file_hashes_only_evidence() {
        let keypair = gen_keypair();
        let subject = make_temp_file(b"subject");
        let evidence = make_temp_file(b"evidence only");

        let attest =
            PointAttestation::create(subject.path(), "binary", evidence.path(), "sbom", &keypair)
                .expect("create");

        // Only check evidence, not subject
        attest
            .verify_file_hashes(None, Some(evidence.path()))
            .expect("evidence only check should pass");
    }

    #[test]
    fn test_missing_signature_error() {
        let keypair = gen_keypair();
        let subject = make_temp_file(b"data");
        let evidence = make_temp_file(b"evidence");

        let mut attest =
            PointAttestation::create(subject.path(), "binary", evidence.path(), "sbom", &keypair)
                .expect("create");

        attest.signature = None;
        let result = attest.verify_signature(&keypair.public);
        assert!(
            matches!(result, Err(PointAttestationError::MissingSignature)),
            "should get MissingSignature error"
        );
    }
}
