//
// Copyright (c) 2025 TRUSTEDGE LABS LLC
// This source code is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Project: sealedge — Privacy and trust at the edge.
//

//! Verification engine — BLAKE3 continuity chaining and Ed25519 signature verification.
//!
//! All cryptographic operations delegate to sealedge_core's chain and crypto modules.
//! No direct blake3 or ed25519_dalek calls remain in this module.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

/// A segment reference (`{index, hash}`) as it appears on the wire.
///
/// This is the single canonical wire type re-exported from `sealedge-types`;
/// the CLI (`seal emit-request`) and this engine share the exact same
/// definition so the two sides cannot drift. The `SegmentDigest` name is
/// retained as an alias for readability within the verification engine.
pub use sealedge_types::verification::SegmentRef as SegmentDigest;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct VerifyReport {
    pub signature_verification: VerificationResult,
    pub continuity_verification: VerificationResult,
    pub metadata: VerificationMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct VerificationResult {
    pub passed: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct VerificationMetadata {
    pub total_segments: u32,
    pub verified_segments: u32,
    pub chain_tip: String,
    pub genesis_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ReceiptClaims {
    pub verification_id: String,
    pub device_id: String,
    pub manifest_digest: String,
    pub chain_tip: String,
    pub timestamp: String,
    pub kid: String,
    pub result: VerifyReport,
}

pub fn verify_to_report(
    manifest: &serde_json::Value,
    segments: &[SegmentDigest],
    device_pub: &str,
) -> Result<VerifyReport> {
    // Parse the wire manifest once into the canonical form. Both signature and
    // continuity verification operate on this — a malformed manifest is a hard
    // error, not a silent pass.
    let parsed: sealedge_core::TrstManifest = serde_json::from_value(manifest.clone())
        .map_err(|e| anyhow!("Manifest does not match the canonical .trst schema: {}", e))?;

    let signature_result = verify_signature(&parsed, device_pub)?;
    let continuity = verify_continuity(&parsed, segments);

    Ok(VerifyReport {
        signature_verification: signature_result,
        continuity_verification: continuity.result,
        metadata: VerificationMetadata {
            total_segments: parsed.segments.len() as u32,
            verified_segments: continuity.verified_segments,
            chain_tip: continuity.chain_tip,
            genesis_hash: format_b3(&sealedge_core::chain::genesis()),
        },
    })
}

pub fn receipt_from_report(
    report: &VerifyReport,
    manifest_digest: &str,
    device_id: &str,
    kid: &str,
    now_rfc3339: &str,
    chain_tip: &str,
) -> ReceiptClaims {
    ReceiptClaims {
        verification_id: format!("v_{}", uuid::Uuid::new_v4().simple()),
        device_id: device_id.to_string(),
        manifest_digest: manifest_digest.to_string(),
        chain_tip: chain_tip.to_string(),
        timestamp: now_rfc3339.to_string(),
        kid: kid.to_string(),
        result: report.clone(),
    }
}

/// Verify the manifest signature against the canonical `.trst` contract.
///
/// This is the single source of truth for the signing contract, and it MUST
/// stay byte-for-byte identical to what `seal wrap` signs:
///
/// - **Canonicalization**: the wire manifest is parsed into the canonical
///   [`sealedge_core::TrstManifest`] and re-serialized with
///   `to_canonical_bytes()` — the exact same function the CLI signs over.
///   We deliberately do NOT canonicalize the raw `serde_json::Value`, because
///   `serde_json::Value` objects are backed by a `BTreeMap` (keys re-serialize
///   alphabetically) which does not match the manifest's hand-ordered fields.
/// - **Signature format**: the `signature` field already carries its algorithm
///   prefix (`"ed25519:BASE64"` / `"ecdsa-p256:BASE64"`) and is passed straight
///   through to `verify_manifest`. We must NOT re-prepend a prefix here, or the
///   value becomes `"ed25519:ed25519:..."` and base64 decoding fails.
fn verify_signature(
    manifest: &sealedge_core::TrstManifest,
    device_pub: &str,
) -> Result<VerificationResult> {
    // device_pub must carry an algorithm prefix — core's verify_manifest
    // dispatches on the signature prefix and expects a matching key format.
    if !device_pub.starts_with("ed25519:") && !device_pub.starts_with("ecdsa-p256:") {
        return Err(anyhow!(
            "Device public key must have an algorithm prefix (ed25519: or ecdsa-p256:)"
        ));
    }

    // The signature travels inside the manifest, already algorithm-prefixed.
    let signature = manifest
        .signature
        .as_deref()
        .ok_or_else(|| anyhow!("Missing signature in manifest"))?;

    // `to_canonical_bytes()` excludes the signature field, matching the signer.
    let canonical_bytes = manifest
        .to_canonical_bytes()
        .map_err(|e| anyhow!("Failed to canonicalize manifest: {}", e))?;

    match sealedge_core::crypto::verify_manifest(device_pub, &canonical_bytes, signature) {
        Ok(true) => Ok(VerificationResult {
            passed: true,
            error: None,
        }),
        Ok(false) => Ok(VerificationResult {
            passed: false,
            error: Some("Signature verification failed".to_string()),
        }),
        Err(e) => Ok(VerificationResult {
            passed: false,
            error: Some(format!("Signature verification failed: {}", e)),
        }),
    }
}

/// Outcome of continuity verification.
struct ContinuityOutcome {
    result: VerificationResult,
    /// Number of segments actually verified (0 on any failure).
    verified_segments: u32,
    /// The chain tip reached ("b3:<hex>"). The genesis hash when nothing verified.
    chain_tip: String,
}

impl ContinuityOutcome {
    fn fail(msg: String) -> Self {
        Self {
            result: VerificationResult {
                passed: false,
                error: Some(msg),
            },
            verified_segments: 0,
            chain_tip: format_b3(&sealedge_core::chain::genesis()),
        }
    }
}

/// Verify segment continuity against the **signed** manifest.
///
/// The manifest signature already covers `manifest.segments` (each carries a
/// `blake3_hash` and a running `continuity_hash`). This function turns that into
/// a real, content-bound continuity check with two required parts:
///
/// 1. **Bind the client-submitted segments to the signed manifest.** The request
///    carries its own segment list (the CLI recomputes it by hashing the chunk
///    files). We require it to have the same length and sequential indices, and
///    each hash to equal the manifest's `blake3_hash` at that index. Without this
///    binding, arbitrary segment hashes could ride along on a legitimately-signed
///    manifest and still report `passed = true` (C2).
/// 2. **Validate the manifest's own continuity chain.** Delegated to
///    [`sealedge_core::chain::validate_chain`] — the same routine `seal verify`
///    uses — which recomputes `chain_next(prev, blake3_hash)` from genesis and
///    checks it against each stored `continuity_hash`. Hashes are hex-decoded
///    (the wire format the CLI writes), not base64.
fn verify_continuity(
    manifest: &sealedge_core::TrstManifest,
    client_segments: &[SegmentDigest],
) -> ContinuityOutcome {
    use sealedge_core::chain::ChainSegment;

    // Reconstruct the authoritative chain from the signed manifest.
    let mut chain_segments = Vec::with_capacity(manifest.segments.len());
    for (i, seg) in manifest.segments.iter().enumerate() {
        let stored_hash = match decode_b3_hex_32(&seg.blake3_hash) {
            Some(h) => h,
            None => {
                return ContinuityOutcome::fail(format!(
                    "segment[{}] blake3_hash is not 32-byte hex",
                    i
                ))
            }
        };
        let stored_continuity = match decode_b3_hex_32(&seg.continuity_hash) {
            Some(c) => c,
            None => {
                return ContinuityOutcome::fail(format!(
                    "segment[{}] continuity_hash is not 32-byte hex",
                    i
                ))
            }
        };
        chain_segments.push(ChainSegment {
            index: i,
            stored_hash,
            stored_continuity,
        });
    }

    // (1) Bind the client-submitted segments to the signed manifest.
    if client_segments.len() != manifest.segments.len() {
        return ContinuityOutcome::fail(format!(
            "submitted {} segments but signed manifest declares {}",
            client_segments.len(),
            manifest.segments.len()
        ));
    }
    let mut sorted = client_segments.to_vec();
    sorted.sort_by_key(|s| s.index);
    for (i, cs) in sorted.iter().enumerate() {
        if cs.index as usize != i {
            return ContinuityOutcome::fail(format!("missing segment at index {}", i));
        }
        // Client hashes are "b3:<hex>"; manifest stores bare "<hex>". Normalize both.
        let client_hash = cs
            .hash
            .strip_prefix("b3:")
            .unwrap_or(&cs.hash)
            .to_ascii_lowercase();
        let manifest_hash = manifest.segments[i].blake3_hash.to_ascii_lowercase();
        if client_hash != manifest_hash {
            return ContinuityOutcome::fail(format!(
                "segment[{}] hash does not match the signed manifest",
                i
            ));
        }
    }

    // (2) Validate the manifest's own continuity chain from genesis.
    match sealedge_core::chain::validate_chain(&chain_segments) {
        Ok(()) => {
            let chain_tip = chain_segments
                .last()
                .map(|s| format_b3(&s.stored_continuity))
                .unwrap_or_else(|| format_b3(&sealedge_core::chain::genesis()));
            ContinuityOutcome {
                result: VerificationResult {
                    passed: true,
                    error: None,
                },
                verified_segments: chain_segments.len() as u32,
                chain_tip,
            }
        }
        Err(e) => ContinuityOutcome::fail(format!("continuity chain invalid: {}", e)),
    }
}

/// Decode a `"b3:<hex>"` (or bare `"<hex>"`) string into 32 raw bytes.
///
/// Returns `None` if the hex is malformed or not exactly 32 bytes. Uses hex —
/// the encoding `seal wrap` writes for `blake3_hash`/`continuity_hash` — not
/// base64.
fn decode_b3_hex_32(value: &str) -> Option<[u8; 32]> {
    let hex_part = value.strip_prefix("b3:").unwrap_or(value);
    let bytes = hex::decode(hex_part).ok()?;
    bytes.try_into().ok()
}

/// Format a 32-byte hash as `"b3:<hex>"`, matching the archive/manifest encoding
/// (`hex::encode`) that `seal wrap` and `sealedge_core::chain` use.
fn format_b3(bytes: &[u8; 32]) -> String {
    format!("b3:{}", hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    use sealedge_core::{
        chain, ChunkInfo, DeviceInfo, GenericMetadata, ProfileMetadata, SegmentInfo, TrstManifest,
    };

    /// Build a manifest with a valid `n`-segment continuity chain, plus the
    /// matching client segment list (`b3:<hex>` of each segment hash) that a
    /// well-behaved client would submit.
    fn chained_manifest(n: usize) -> (TrstManifest, Vec<SegmentDigest>) {
        let mut seg_infos = Vec::new();
        let mut client = Vec::new();
        let mut prev = chain::genesis();
        for i in 0..n {
            let hash = chain::segment_hash(format!("chunk-{i}").as_bytes());
            let cont = chain::chain_next(&prev, &hash);
            prev = cont;
            seg_infos.push(SegmentInfo {
                chunk_file: format!("{i:05}.bin"),
                blake3_hash: hex::encode(hash),
                start_time: format!("segment-{i}"),
                duration_seconds: 1.0,
                continuity_hash: hex::encode(cont),
            });
            client.push(SegmentDigest {
                index: i as u32,
                hash: format!("b3:{}", hex::encode(hash)),
            });
        }
        let manifest = TrstManifest {
            trst_version: "0.1.0".to_string(),
            profile: "generic".to_string(),
            device: DeviceInfo {
                id: "TEST".to_string(),
                model: "m".to_string(),
                firmware_version: "1.0.0".to_string(),
                public_key: "ed25519:k".to_string(),
            },
            metadata: ProfileMetadata::Generic(GenericMetadata {
                started_at: "t0".to_string(),
                ended_at: "t1".to_string(),
                ..Default::default()
            }),
            chunk: ChunkInfo {
                size_bytes: 4096,
                duration_seconds: 1.0,
            },
            segments: seg_infos,
            claims: vec![],
            prev_archive_hash: None,
            signature: None,
        };
        (manifest, client)
    }

    #[test]
    fn test_format_and_decode_b3_roundtrip() {
        let bytes = chain::genesis();
        let formatted = format_b3(&bytes);
        assert!(formatted.starts_with("b3:"));
        assert_eq!(decode_b3_hex_32(&formatted), Some(bytes));
        // Bare hex (manifest form) also decodes.
        assert_eq!(decode_b3_hex_32(&hex::encode(bytes)), Some(bytes));
        // Base64 (the old, wrong encoding) must NOT decode as valid hex bytes.
        assert_eq!(decode_b3_hex_32("b3:not-hex!!"), None);
    }

    #[test]
    fn test_continuity_matches_signed_manifest() {
        let (manifest, client) = chained_manifest(3);
        let outcome = verify_continuity(&manifest, &client);
        assert!(outcome.result.passed);
        assert_eq!(outcome.verified_segments, 3);
        // chain_tip must be the manifest's last continuity_hash, not a function
        // of segment count alone.
        let expected_tip = format!("b3:{}", manifest.segments[2].continuity_hash);
        assert_eq!(outcome.chain_tip, expected_tip);
    }

    #[test]
    fn test_continuity_rejects_arbitrary_client_hashes() {
        // C2 exploit: attach arbitrary segment hashes to a signed manifest.
        let (manifest, mut client) = chained_manifest(2);
        client[1].hash =
            "b3:0000000000000000000000000000000000000000000000000000000000000000".to_string();
        let outcome = verify_continuity(&manifest, &client);
        assert!(
            !outcome.result.passed,
            "client hashes that differ from the signed manifest must fail"
        );
        assert_eq!(outcome.verified_segments, 0);
    }

    #[test]
    fn test_continuity_rejects_segment_count_mismatch() {
        let (manifest, client) = chained_manifest(3);
        let outcome = verify_continuity(&manifest, &client[..2]);
        assert!(!outcome.result.passed);
    }

    #[test]
    fn test_continuity_rejects_broken_manifest_chain() {
        // A signed manifest whose stored continuity_hash is wrong must fail.
        let (mut manifest, client) = chained_manifest(2);
        manifest.segments[1].continuity_hash =
            "1111111111111111111111111111111111111111111111111111111111111111".to_string();
        let outcome = verify_continuity(&manifest, &client);
        assert!(!outcome.result.passed);
    }

    #[test]
    fn test_continuity_empty_manifest_and_client() {
        let (manifest, client) = chained_manifest(0);
        let outcome = verify_continuity(&manifest, &client);
        assert!(outcome.result.passed);
        assert_eq!(outcome.verified_segments, 0);
        assert_eq!(outcome.chain_tip, format_b3(&chain::genesis()));
    }

    #[test]
    fn test_receipt_from_report() {
        let report = VerifyReport {
            signature_verification: VerificationResult {
                passed: true,
                error: None,
            },
            continuity_verification: VerificationResult {
                passed: true,
                error: None,
            },
            metadata: VerificationMetadata {
                total_segments: 0,
                verified_segments: 0,
                chain_tip: "b3:test".to_string(),
                genesis_hash: "b3:genesis".to_string(),
            },
        };

        let receipt = receipt_from_report(
            &report,
            "digest123",
            "device_abc",
            "key_001",
            "2026-02-21T00:00:00Z",
            "b3:test",
        );

        assert!(receipt.verification_id.starts_with("v_"));
        assert_eq!(receipt.device_id, "device_abc");
        assert_eq!(receipt.manifest_digest, "digest123");
        assert_eq!(receipt.kid, "key_001");
    }
}
