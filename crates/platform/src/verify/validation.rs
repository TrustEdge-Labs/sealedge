//
// Copyright (c) 2025 TRUSTEDGE LABS LLC
// This source code is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Project: sealedge — Privacy and trust at the edge.
//

//! Request validation for the verification service.

use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};
use tracing::warn;

use super::engine::{receipt_from_report, SegmentDigest, VerifyReport};
use super::jwks::KeyManager;
use super::signing::sign_receipt_jws;
use super::types::VerifyRequest;

#[derive(Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ValidationError {
    pub error: String,
    pub detail: String,
}

impl ValidationError {
    pub fn new(error: &str, detail: &str) -> Self {
        Self {
            error: error.to_string(),
            detail: detail.to_string(),
        }
    }
}

/// Validate a verify request — checks only segments and hash format.
///
/// Kept for backward compatibility. Callers that need full validation
/// (including `device_pub` and `manifest` checks) should use
/// [`validate_verify_request_full`] instead.
pub fn validate_verify_request(request: &VerifyRequest) -> Result<(), ValidationError> {
    // Validate segments are non-empty
    if request.segments.is_empty() {
        return Err(ValidationError::new(
            "invalid_segments",
            "segments array cannot be empty",
        ));
    }

    // Validate hash format for each segment
    validate_segment_hashes(&request.segments)?;

    // Note: Index validation is handled by continuity verification in the core library

    Ok(())
}

/// Validate a verify request — performs all four validation checks.
///
/// Checks are ordered and first-error-wins:
/// 1. Empty segments check
/// 2. Empty `device_pub` check
/// 3. Empty/null manifest check
/// 4. Hash format validation via [`validate_segment_hashes`]
pub fn validate_verify_request_full(request: &VerifyRequest) -> Result<(), ValidationError> {
    if request.segments.is_empty() {
        return Err(ValidationError::new(
            "invalid_segments",
            "segments array cannot be empty",
        ));
    }

    if request.device_pub.is_empty() {
        return Err(ValidationError::new(
            "invalid_device_pub",
            "device_pub cannot be empty",
        ));
    }

    if request.manifest.is_null()
        || request.manifest == serde_json::Value::Object(Default::default())
        || request.manifest.as_str() == Some("")
    {
        return Err(ValidationError::new(
            "invalid_manifest",
            "manifest cannot be empty",
        ));
    }

    validate_segment_hashes(&request.segments)?;

    Ok(())
}

static HASH_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^b3:[0-9a-f]{64}$").expect("HASH_REGEX compile"));

pub fn validate_segment_hashes(segments: &[SegmentDigest]) -> Result<(), ValidationError> {
    for (i, segment) in segments.iter().enumerate() {
        if !HASH_REGEX.is_match(&segment.hash) {
            return Err(ValidationError::new(
                "invalid_segments",
                &format!(
                    "segments[{}].hash must match ^b3:[0-9a-f]{{64}}$, got '{}'",
                    i, segment.hash
                ),
            ));
        }
    }

    Ok(())
}

/// Build a JWS receipt if the request options request one and verification passed.
///
/// Returns `Ok(Some(jws))` when a receipt was built and signed,
/// `Ok(None)` when the conditions for receipt issuance were not met,
/// or `Err(ValidationError)` if signing failed.
///
/// The `manifest_digest_fn` closure allows the caller to supply the appropriate
/// digest algorithm (e.g. BLAKE3 for the non-postgres handler) without this
/// function needing to know about feature flags.
pub async fn build_receipt_if_requested(
    request: &VerifyRequest,
    report: &VerifyReport,
    keys: &KeyManager,
    manifest_digest_fn: impl Fn(&serde_json::Value) -> String,
    receipt_ttl_secs: u64,
) -> Result<Option<String>, ValidationError> {
    let options = &request.options;

    if !options.return_receipt
        || !report.signature_verification.passed
        || !report.continuity_verification.passed
    {
        return Ok(None);
    }

    let device_id = options.device_id.as_deref().unwrap_or("unknown_device");
    let manifest_digest = manifest_digest_fn(&request.manifest);
    let now_rfc3339 = chrono::Utc::now().to_rfc3339();
    let kid = keys.current_kid();

    let receipt_obj = receipt_from_report(
        report,
        &manifest_digest,
        device_id,
        &kid,
        &now_rfc3339,
        &report.metadata.chain_tip,
    );

    match sign_receipt_jws(&receipt_obj, keys, receipt_ttl_secs).await {
        Ok(jws) => Ok(Some(jws)),
        Err(e) => {
            warn!("Failed to sign receipt: {}", e);
            Err(ValidationError::new(
                "receipt_signing_failed",
                "Receipt generation failed",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_segment(index: u32, hash: &str) -> SegmentDigest {
        SegmentDigest {
            index,
            hash: hash.to_string(),
        }
    }

    fn valid_hash() -> &'static str {
        "b3:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    }

    // -----------------------------------------------------------------------
    // Tests for the original validate_verify_request (backward compat)
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_empty_segments() {
        let request = VerifyRequest {
            device_pub: "ed25519:test".to_string(),
            manifest: serde_json::json!({}),
            segments: vec![],
            options: Default::default(),
        };

        let result = validate_verify_request(&request);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.error, "invalid_segments");
        assert!(err.detail.contains("cannot be empty"));
    }

    #[test]
    fn test_validate_invalid_hash_format() {
        let segments = vec![create_test_segment(0, "invalid_hash")];
        let request = VerifyRequest {
            device_pub: "ed25519:test".to_string(),
            manifest: serde_json::json!({}),
            segments,
            options: Default::default(),
        };

        let result = validate_verify_request(&request);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.error, "invalid_segments");
        assert!(err.detail.contains("must match ^b3:[0-9a-f]{64}$"));
    }

    #[test]
    fn test_validate_wrong_hash_length() {
        let segments = vec![create_test_segment(0, "b3:123")];
        let request = VerifyRequest {
            device_pub: "ed25519:test".to_string(),
            manifest: serde_json::json!({}),
            segments,
            options: Default::default(),
        };

        let result = validate_verify_request(&request);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.error, "invalid_segments");
        assert!(err.detail.contains("must match ^b3:[0-9a-f]{64}$"));
    }

    // Note: Index validation tests removed because index validation
    // is now handled by continuity verification in the core library

    #[test]
    fn test_validate_valid_request() {
        let segments = vec![
            create_test_segment(
                0,
                "b3:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            ),
            create_test_segment(
                1,
                "b3:fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321",
            ),
        ];
        let request = VerifyRequest {
            device_pub: "ed25519:test".to_string(),
            manifest: serde_json::json!({}),
            segments,
            options: Default::default(),
        };

        let result = validate_verify_request(&request);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_hash_with_uppercase() {
        let segments = vec![create_test_segment(
            0,
            "b3:1234567890ABCDEF1234567890abcdef1234567890abcdef1234567890abcdef",
        )];
        let request = VerifyRequest {
            device_pub: "ed25519:test".to_string(),
            manifest: serde_json::json!({}),
            segments,
            options: Default::default(),
        };

        let result = validate_verify_request(&request);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.error, "invalid_segments");
        assert!(err.detail.contains("must match ^b3:[0-9a-f]{64}$"));
    }

    // -----------------------------------------------------------------------
    // Tests for validate_verify_request_full (new)
    // -----------------------------------------------------------------------

    #[test]
    fn test_full_validate_empty_segments_returns_invalid_segments() {
        let request = VerifyRequest {
            device_pub: "ed25519:test".to_string(),
            manifest: serde_json::json!({"version": "1.0"}),
            segments: vec![],
            options: Default::default(),
        };

        let result = validate_verify_request_full(&request);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.error, "invalid_segments");
        assert!(err.detail.contains("cannot be empty"));
    }

    #[test]
    fn test_full_validate_empty_device_pub_returns_invalid_device_pub() {
        let request = VerifyRequest {
            device_pub: "".to_string(),
            manifest: serde_json::json!({"version": "1.0"}),
            segments: vec![create_test_segment(0, valid_hash())],
            options: Default::default(),
        };

        let result = validate_verify_request_full(&request);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.error, "invalid_device_pub");
        assert!(err.detail.contains("device_pub cannot be empty"));
    }

    #[test]
    fn test_full_validate_null_manifest_returns_invalid_manifest() {
        let request = VerifyRequest {
            device_pub: "ed25519:test".to_string(),
            manifest: serde_json::Value::Null,
            segments: vec![create_test_segment(0, valid_hash())],
            options: Default::default(),
        };

        let result = validate_verify_request_full(&request);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.error, "invalid_manifest");
        assert!(err.detail.contains("manifest cannot be empty"));
    }

    #[test]
    fn test_full_validate_empty_object_manifest_returns_invalid_manifest() {
        let request = VerifyRequest {
            device_pub: "ed25519:test".to_string(),
            manifest: serde_json::json!({}),
            segments: vec![create_test_segment(0, valid_hash())],
            options: Default::default(),
        };

        let result = validate_verify_request_full(&request);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.error, "invalid_manifest");
        assert!(err.detail.contains("manifest cannot be empty"));
    }

    #[test]
    fn test_full_validate_valid_request_passes() {
        let request = VerifyRequest {
            device_pub: "ed25519:test".to_string(),
            manifest: serde_json::json!({"version": "1.0", "device": "cam-01"}),
            segments: vec![
                create_test_segment(0, valid_hash()),
                create_test_segment(
                    1,
                    "b3:fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321",
                ),
            ],
            options: Default::default(),
        };

        let result = validate_verify_request_full(&request);
        assert!(result.is_ok());
    }

    #[test]
    fn test_full_validate_first_check_wins_segments_before_device_pub() {
        // Both segments empty AND device_pub empty — should return "invalid_segments" (first check)
        let request = VerifyRequest {
            device_pub: "".to_string(),
            manifest: serde_json::json!({"version": "1.0"}),
            segments: vec![],
            options: Default::default(),
        };

        let result = validate_verify_request_full(&request);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(
            err.error, "invalid_segments",
            "segments check must fire before device_pub check"
        );
    }
}
