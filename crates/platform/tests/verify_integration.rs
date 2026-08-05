//
// Copyright (c) 2025 TRUSTEDGE LABS LLC
// This source code is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Project: sealedge — Privacy and trust at the edge.
//

//! Integration tests for the consolidated verify module.
//!
//! Migrated from the v5.x trustedge-verify-core crate (merged into sealedge-platform in v6.0)/tests/integration_tests.rs.
//!
//! Test groupings:
//! - HTTP endpoint tests (feature = "http"): health, JWKS, CORS parity, verify round-trip
//! - Pure crypto tests (always available): happy path, tampered, wrong key, empty, key manager

use anyhow::Result;
use sealedge_platform::verify::engine::{verify_to_report, SegmentDigest};
use sealedge_platform::verify::jwks::KeyManager;

// ---------------------------------------------------------------------------
// Real-archive helpers — the ACTUAL product contract.
//
// These build a manifest exactly the way `seal wrap` does: a canonical
// `TrstManifest`, signed over `to_canonical_bytes()` with
// `crypto::sign_manifest`, with the algorithm-prefixed signature stored inside
// the manifest. Verifying such a manifest through `verify_to_report` is the
// end-to-end gate that C1 was missing — if either side's canonicalization or
// signature format drifts, these tests fail.
// ---------------------------------------------------------------------------

/// Build a real, canonically-signed `.trst` manifest for a freshly generated
/// device key. Returns `(manifest_json_value, device_pub)`.
fn build_real_signed_manifest(device_id: &str) -> (serde_json::Value, String) {
    let keypair = sealedge_core::DeviceKeypair::generate().unwrap();
    build_real_signed_manifest_with_key(&keypair, device_id)
}

/// Build a real, canonically-signed `.trst` manifest signed by `keypair`.
/// Returns `(manifest_json_value, device_pub)` where `device_pub` is the
/// keypair's public key (also embedded in the manifest).
fn build_real_signed_manifest_with_key(
    keypair: &sealedge_core::DeviceKeypair,
    device_id: &str,
) -> (serde_json::Value, String) {
    use sealedge_core::{
        chain, ChunkInfo, DeviceInfo, GenericMetadata, ProfileMetadata, SegmentInfo, TrstManifest,
    };

    // Build a real 2-segment continuity chain exactly as `seal wrap` does:
    // blake3_hash = hex(segment_hash(bytes)); continuity_hash = hex(chain_next(prev, hash)).
    let mut seg_infos = Vec::new();
    let mut prev = chain::genesis();
    for i in 0..2u32 {
        let hash = chain::segment_hash(format!("{device_id}-chunk-{i}").as_bytes());
        let cont = chain::chain_next(&prev, &hash);
        prev = cont;
        seg_infos.push(SegmentInfo {
            chunk_file: format!("{i:05}.bin"),
            blake3_hash: hex::encode(hash),
            start_time: format!("segment-{i}"),
            duration_seconds: 2.0,
            continuity_hash: hex::encode(cont),
        });
    }

    let mut manifest = TrstManifest {
        trst_version: "0.2.0".to_string(),
        profile: "generic".to_string(),
        device: DeviceInfo {
            id: device_id.to_string(),
            model: "TrustEdgeRefCam".to_string(),
            firmware_version: "1.0.0".to_string(),
            public_key: keypair.public.clone(),
            key_agreement_public: None,
        },
        metadata: ProfileMetadata::Generic(GenericMetadata {
            started_at: "2025-01-15T10:30:00Z".to_string(),
            ended_at: "2025-01-15T10:30:02Z".to_string(),
            ..Default::default()
        }),
        chunk: ChunkInfo {
            size_bytes: 4096,
            duration_seconds: 2.0,
        },
        segments: seg_infos,
        claims: vec!["location:unknown".to_string()],
        encryption: None,
        prev_archive_hash: None,
        signature: None,
    };

    let canonical = manifest.to_canonical_bytes().unwrap();
    let signature = sealedge_core::crypto::sign_manifest(keypair, &canonical).unwrap();
    manifest.set_signature(signature);

    let device_pub = keypair.public.clone();
    (serde_json::to_value(&manifest).unwrap(), device_pub)
}

/// Derive the client segment list (`b3:<hex>` per index) that a well-behaved
/// client submits — i.e. exactly the manifest's own `blake3_hash` values. This
/// is what `seal emit-request` produces by hashing the chunk files.
fn matching_segments(manifest: &serde_json::Value) -> Vec<SegmentDigest> {
    manifest["segments"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .map(|(i, seg)| SegmentDigest {
            index: i as u32,
            hash: format!("b3:{}", seg["blake3_hash"].as_str().unwrap()),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// HTTP endpoint tests (require `http` feature)
// ---------------------------------------------------------------------------

#[cfg(all(feature = "http", not(feature = "postgres")))]
mod http_tests {
    use super::*;
    use axum::{body::Body, http::header::CONTENT_TYPE, http::Request};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL;
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use ed25519_dalek::VerifyingKey as DalekVerifyingKey;
    use sealedge_platform::http::{create_router, AppState};
    use serde_json::json;
    use std::sync::Arc;
    use tokio::sync::{Mutex, RwLock};
    use tower::ServiceExt;

    /// Serializes tests that mutate process-global env vars (RATE_LIMIT_RPS,
    /// TRUSTED_PROXIES) to prevent races when cargo runs tests in parallel.
    static ENV_MUTEX: std::sync::LazyLock<Mutex<()>> = std::sync::LazyLock::new(|| Mutex::new(()));

    /// Build an independent test app state using the real consolidated router (no postgres).
    fn make_state() -> AppState {
        let key_manager = KeyManager::new().unwrap();
        AppState {
            keys: Arc::new(RwLock::new(key_manager)),
            receipt_ttl_secs: 3600,
        }
    }

    /// Build a test app using the real consolidated router (no postgres, stateless mode).
    async fn create_test_app() -> axum::Router {
        create_router(make_state())
    }

    // -----------------------------------------------------------------------
    // Helper: build a signed VerifyRequest JSON body
    // -----------------------------------------------------------------------

    /// Build a canonically signed manifest and return (signed_manifest, device_pub_string).
    ///
    /// Delegates to the crate-level [`build_real_signed_manifest`] so the HTTP
    /// round-trip exercises the exact product contract (`seal wrap` output).
    fn build_signed_manifest(device_id: &str) -> (serde_json::Value, String) {
        super::build_real_signed_manifest(device_id)
    }

    /// Build a valid VerifyRequest body as JSON bytes.
    ///
    /// Segments are derived from the manifest so they bind to the signed content
    /// (post-C2 the platform rejects segments that don't match the manifest).
    fn build_verify_body(
        signed_manifest: &serde_json::Value,
        device_pub: &str,
        return_receipt: bool,
    ) -> Vec<u8> {
        let segments: Vec<_> = super::matching_segments(signed_manifest)
            .into_iter()
            .map(|s| json!({ "index": s.index, "hash": s.hash }))
            .collect();
        let body = json!({
            "device_pub": device_pub,
            "manifest": signed_manifest,
            "segments": segments,
            "options": {
                "return_receipt": return_receipt,
                "device_id": "test-device"
            }
        });
        serde_json::to_vec(&body).unwrap()
    }

    // -----------------------------------------------------------------------
    // Test 1: Health endpoint
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_health_endpoint() -> Result<()> {
        let app = create_test_app().await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(body_json["status"], "OK");
        assert!(
            body_json.get("version").is_none(),
            "healthz must not expose version"
        );
        assert!(body_json.get("timestamp").is_some());

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Test 2: JWKS endpoint
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_jwks_endpoint() -> Result<()> {
        let app = create_test_app().await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/.well-known/jwks.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let jwks: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert!(jwks.get("keys").is_some());
        let keys = jwks["keys"].as_array().unwrap();
        assert!(!keys.is_empty());

        let key = &keys[0];
        assert_eq!(key["kty"], "OKP");
        assert_eq!(key["crv"], "Ed25519");
        assert_eq!(key["alg"], "EdDSA");
        assert!(key.get("kid").is_some());
        assert!(key.get("x").is_some());

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Test 3: CORS parity — two independently constructed routers produce
    //         identical CORS headers for the same OPTIONS preflight (TST-02).
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_cors_preflight_parity() -> Result<()> {
        // Build two independent routers from the same AppState (cloned).
        // Both go through build_base_router -> create_router, so their
        // CORS layer configuration must be identical.
        let state = make_state();
        let app1 = create_router(state.clone());
        let app2 = create_router(state);

        let make_preflight = || {
            Request::builder()
                .method("OPTIONS")
                .uri("/v1/verify")
                .header("Origin", "http://evil.example.com")
                .header("Access-Control-Request-Method", "POST")
                .body(Body::empty())
                .unwrap()
        };

        let resp1 = app1.oneshot(make_preflight()).await.unwrap();
        let resp2 = app2.oneshot(make_preflight()).await.unwrap();

        // Both routers must agree on all CORS response headers.
        assert_eq!(
            resp1.headers().get("access-control-allow-origin"),
            resp2.headers().get("access-control-allow-origin"),
            "CORS allow-origin headers must be identical between router instances"
        );
        assert_eq!(
            resp1.headers().get("access-control-allow-methods"),
            resp2.headers().get("access-control-allow-methods"),
            "CORS allow-methods headers must be identical between router instances"
        );
        assert_eq!(
            resp1.headers().get("access-control-allow-headers"),
            resp2.headers().get("access-control-allow-headers"),
            "CORS allow-headers headers must be identical between router instances"
        );

        // In verify-only builds, CorsLayer::new() denies all cross-origin requests —
        // no Access-Control-Allow-Origin header is present in either response.
        assert!(
            resp1.headers().get("access-control-allow-origin").is_none(),
            "verify-only build must deny cross-origin: Access-Control-Allow-Origin must be absent"
        );

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Test 4: Full verify round-trip — sign a payload, POST to /v1/verify,
    //         receive HTTP 200 with a JWS receipt (TST-03 happy path).
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_verify_round_trip() -> Result<()> {
        let app = create_test_app().await;

        let (signed_manifest, device_pub) = build_signed_manifest("test-device");
        let body_bytes = build_verify_body(&signed_manifest, &device_pub, true);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/verify")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(body_bytes))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "verify endpoint must return 200 for a valid signed payload"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let resp: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert!(
            resp["result"]["signature_verification"]["passed"]
                .as_bool()
                .unwrap_or(false),
            "signature_verification must pass for a correctly signed manifest"
        );
        assert!(
            resp["result"]["continuity_verification"]["passed"]
                .as_bool()
                .unwrap_or(false),
            "continuity_verification must pass for sequential segments"
        );
        assert!(
            resp["receipt"].is_string(),
            "receipt must be present when return_receipt=true and verification passed"
        );
        assert!(
            resp["verification_id"]
                .as_str()
                .unwrap_or("")
                .starts_with("v_"),
            "verification_id must start with 'v_'"
        );

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Test 5: Receipt JWS verified against JWKS (TST-03 full receipt check).
    //
    // Steps:
    //   1. POST /v1/verify with return_receipt=true → get JWS receipt
    //   2. GET /.well-known/jwks.json on a second router (same state) → get public key
    //   3. Verify the JWS Ed25519 signature using the JWKS public key
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_verify_receipt_matches_jwks() -> Result<()> {
        // Shared state so both routers have the same signing key.
        let state = make_state();
        let app_verify = create_router(state.clone());
        let app_jwks = create_router(state);

        // Step 1: POST /v1/verify → receive JWS receipt
        let (signed_manifest, device_pub) = build_signed_manifest("test-device");
        let body_bytes = build_verify_body(&signed_manifest, &device_pub, true);

        let verify_resp = app_verify
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/verify")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(body_bytes))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(verify_resp.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(verify_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let resp: serde_json::Value = serde_json::from_slice(&body).unwrap();

        let jws = resp["receipt"]
            .as_str()
            .expect("receipt must be a string in the response");

        // Step 2: GET /.well-known/jwks.json → extract Ed25519 public key
        let jwks_resp = app_jwks
            .oneshot(
                Request::builder()
                    .uri("/.well-known/jwks.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(jwks_resp.status(), axum::http::StatusCode::OK);
        let jwks_body = axum::body::to_bytes(jwks_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let jwks: serde_json::Value = serde_json::from_slice(&jwks_body).unwrap();

        let first_key = &jwks["keys"][0];
        assert_eq!(
            first_key["alg"], "EdDSA",
            "JWKS key algorithm must be EdDSA"
        );

        // The JWKS 'x' field is base64url-encoded without padding (RFC 8037 §2).
        let x_b64 = first_key["x"].as_str().expect("JWKS key must have 'x'");
        assert!(
            !x_b64.contains('=') && !x_b64.contains('+') && !x_b64.contains('/'),
            "JWKS 'x' must be base64url-no-pad per RFC 8037"
        );
        let pub_key_bytes: Vec<u8> = BASE64URL.decode(x_b64)?;
        assert_eq!(
            pub_key_bytes.len(),
            32,
            "Ed25519 public key must be 32 bytes"
        );

        let pub_key_arr: [u8; 32] = pub_key_bytes
            .try_into()
            .expect("Ed25519 public key must be 32 bytes");
        let verifying_key = DalekVerifyingKey::from_bytes(&pub_key_arr)?;

        // Step 3: Decode the JWS and verify the Ed25519 signature
        // JWS format: base64url(header).base64url(payload).base64url(signature)
        let parts: Vec<&str> = jws.split('.').collect();
        assert_eq!(parts.len(), 3, "JWS must have exactly 3 parts");

        // Parse header and verify alg
        let header_bytes = BASE64URL.decode(parts[0])?;
        let header: serde_json::Value = serde_json::from_slice(&header_bytes)?;
        assert_eq!(
            header["alg"], "EdDSA",
            "JWS header must specify EdDSA algorithm"
        );
        assert!(header.get("kid").is_some(), "JWS header must contain a kid");

        // Parse payload and check receipt fields
        let payload_bytes = BASE64URL.decode(parts[1])?;
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)?;

        // C3: the JWT subject must be the cryptographic signer (the verifying
        // public key), NOT the client-supplied device_id.
        assert_eq!(
            payload["sub"], device_pub,
            "JWS sub must be the signer public key, not the client device_id"
        );

        // The receipt is nested under the "receipt" field in JwsPayload
        let receipt_payload = &payload["receipt"];
        assert_eq!(
            receipt_payload["signer_pub"], device_pub,
            "receipt signer_pub must be the verification key"
        );
        assert_eq!(
            receipt_payload["device_registered"], false,
            "stateless verification must mark device_registered = false"
        );
        assert!(
            receipt_payload.get("device_id").is_some(),
            "JWS payload receipt must contain device_id"
        );
        assert!(
            receipt_payload.get("manifest_digest").is_some(),
            "JWS payload receipt must contain manifest_digest"
        );
        assert!(
            receipt_payload.get("chain_tip").is_some(),
            "JWS payload receipt must contain chain_tip"
        );

        // Verify Ed25519 signature: signing input = bytes of "header_b64.payload_b64"
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes = BASE64URL.decode(parts[2])?;
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .expect("Ed25519 signature must be 64 bytes");
        let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);

        verifying_key
            .verify_strict(signing_input.as_bytes(), &signature)
            .expect("JWS Ed25519 signature must verify against JWKS public key");

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Test 6: Wrong key returns HTTP 200 with signature_verification.passed=false
    //         and receipt=None (negative case).
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_verify_wrong_key_returns_failed_signature() -> Result<()> {
        let app = create_test_app().await;

        // Sign with one key, but present a DIFFERENT key as device_pub
        let (signed_manifest, _correct_pub) = build_signed_manifest("test-device");
        let wrong_key = sealedge_core::DeviceKeypair::generate().unwrap();
        let wrong_device_pub = wrong_key.public.clone();

        let body_bytes = build_verify_body(&signed_manifest, &wrong_device_pub, true);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/verify")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(body_bytes))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Server returns 200 (verification completed), not an error status
        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "wrong-key verification must return HTTP 200, not an error status"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let resp: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert!(
            !resp["result"]["signature_verification"]["passed"]
                .as_bool()
                .unwrap_or(true),
            "signature_verification must FAIL when device_pub does not match signing key"
        );
        assert!(
            resp["receipt"].is_null(),
            "receipt must be null when signature verification fails"
        );

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Test 6b: C3 cross-check — a device_pub that differs from the manifest's
    //          embedded device.public_key must fail signature and yield no
    //          receipt, even if that key is otherwise well-formed.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_verify_rejects_key_mismatch_with_manifest() -> Result<()> {
        let app = create_test_app().await;

        let (signed_manifest, _manifest_key) = build_signed_manifest("test-device");
        // A different, valid key presented as the verification key.
        let other = sealedge_core::DeviceKeypair::generate().unwrap();
        let body_bytes = build_verify_body(&signed_manifest, &other.public, true);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/verify")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(body_bytes))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let resp: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert!(
            !resp["result"]["signature_verification"]["passed"]
                .as_bool()
                .unwrap_or(true),
            "device_pub that does not match manifest.device.public_key must fail (C3)"
        );
        assert!(
            resp["receipt"].is_null(),
            "no receipt when the verification key does not match the manifest"
        );

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Test 7: SEC-11 — duplicate submission produces distinct receipts.
    //
    // Submitting the same archive twice must yield two receipts with different
    // verification_id values and different receipt verification_id claims.
    // This proves the system resists receipt replay attacks.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn sec_11_duplicate_submission_distinct_receipts() -> Result<()> {
        let (signed_manifest, device_pub) = build_signed_manifest("test-device");
        let body_bytes = build_verify_body(&signed_manifest, &device_pub, true);

        // Two separate app instances — oneshot consumes the router.
        let app1 = create_test_app().await;
        let app2 = create_test_app().await;

        let resp1 = app1
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/verify")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(body_bytes.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let resp2 = app2
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/verify")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(body_bytes))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp1.status(), axum::http::StatusCode::OK);
        assert_eq!(resp2.status(), axum::http::StatusCode::OK);

        let body1 = axum::body::to_bytes(resp1.into_body(), usize::MAX).await?;
        let body2 = axum::body::to_bytes(resp2.into_body(), usize::MAX).await?;

        let json1: serde_json::Value = serde_json::from_slice(&body1)?;
        let json2: serde_json::Value = serde_json::from_slice(&body2)?;

        let vid1 = json1["verification_id"].as_str().unwrap_or("");
        let vid2 = json2["verification_id"].as_str().unwrap_or("");

        assert_ne!(
            vid1, vid2,
            "SEC-11: duplicate submissions must produce different verification_id values (replay resistance)"
        );

        // Decode JWS receipts and compare inner receipt verification_id claims.
        let jws1 = json1["receipt"]
            .as_str()
            .expect("receipt must be present in response 1");
        let jws2 = json2["receipt"]
            .as_str()
            .expect("receipt must be present in response 2");

        let parts1: Vec<&str> = jws1.split('.').collect();
        let parts2: Vec<&str> = jws2.split('.').collect();

        assert_eq!(parts1.len(), 3, "JWS 1 must have exactly 3 parts");
        assert_eq!(parts2.len(), 3, "JWS 2 must have exactly 3 parts");

        let payload1_bytes = BASE64URL.decode(parts1[1])?;
        let payload2_bytes = BASE64URL.decode(parts2[1])?;

        let payload1: serde_json::Value = serde_json::from_slice(&payload1_bytes)?;
        let payload2: serde_json::Value = serde_json::from_slice(&payload2_bytes)?;

        let receipt_vid1 = &payload1["receipt"]["verification_id"];
        let receipt_vid2 = &payload2["receipt"]["verification_id"];

        assert_ne!(
            receipt_vid1, receipt_vid2,
            "SEC-11: receipt verification_id claims in JWS payloads must differ between duplicate submissions"
        );

        // Both receipts must have iat timestamps.
        assert!(
            payload1["iat"].is_number() || payload1["receipt"].get("iat").is_some(),
            "SEC-11: receipt 1 must contain an iat field"
        );
        assert!(
            payload2["iat"].is_number() || payload2["receipt"].get("iat").is_some(),
            "SEC-11: receipt 2 must contain an iat field"
        );

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Test 8: SEC-12a — different archive content produces different manifest_digest.
    //
    // Two different manifests must produce receipts with different manifest_digest
    // values. This proves the receipt is cryptographically bound to the specific
    // archive content that was submitted.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn sec_12_receipt_digest_bound_to_content() -> Result<()> {
        // Two real, canonically-signed manifests with different device_id values.
        let (signed_a, device_pub_a) = build_signed_manifest("device-alpha");
        let (signed_b, device_pub_b) = build_signed_manifest("device-beta");

        let body_a = build_verify_body(&signed_a, &device_pub_a, true);
        let body_b = build_verify_body(&signed_b, &device_pub_b, true);

        let app_a = create_test_app().await;
        let app_b = create_test_app().await;

        let resp_a = app_a
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/verify")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(body_a))
                    .unwrap(),
            )
            .await
            .unwrap();

        let resp_b = app_b
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/verify")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(body_b))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp_a.status(), axum::http::StatusCode::OK);
        assert_eq!(resp_b.status(), axum::http::StatusCode::OK);

        let body_bytes_a = axum::body::to_bytes(resp_a.into_body(), usize::MAX).await?;
        let body_bytes_b = axum::body::to_bytes(resp_b.into_body(), usize::MAX).await?;

        let json_a: serde_json::Value = serde_json::from_slice(&body_bytes_a)?;
        let json_b: serde_json::Value = serde_json::from_slice(&body_bytes_b)?;

        let jws_a = json_a["receipt"]
            .as_str()
            .expect("receipt must be present for manifest A");
        let jws_b = json_b["receipt"]
            .as_str()
            .expect("receipt must be present for manifest B");

        let parts_a: Vec<&str> = jws_a.split('.').collect();
        let parts_b: Vec<&str> = jws_b.split('.').collect();

        let payload_a: serde_json::Value = serde_json::from_slice(&BASE64URL.decode(parts_a[1])?)?;
        let payload_b: serde_json::Value = serde_json::from_slice(&BASE64URL.decode(parts_b[1])?)?;

        let digest_a = payload_a["receipt"]["manifest_digest"]
            .as_str()
            .expect("manifest_digest must be present in receipt A");
        let digest_b = payload_b["receipt"]["manifest_digest"]
            .as_str()
            .expect("manifest_digest must be present in receipt B");

        assert_ne!(
            digest_a, digest_b,
            "SEC-12: different archive content must produce different manifest_digest values"
        );

        assert!(
            digest_a.starts_with("b3:"),
            "SEC-12: manifest_digest must be prefixed with 'b3:' (BLAKE3)"
        );
        assert!(
            digest_b.starts_with("b3:"),
            "SEC-12: manifest_digest must be prefixed with 'b3:' (BLAKE3)"
        );

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Test 9: SEC-12b — same archive content produces identical manifest_digest.
    //
    // Two submissions of the same manifest must produce receipts with identical
    // manifest_digest values. This proves the digest is deterministically bound
    // to the archive content (not random or time-based).
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn sec_12_same_content_same_digest() -> Result<()> {
        let (signed_manifest, device_pub) = build_signed_manifest("test-device");
        let body_bytes = build_verify_body(&signed_manifest, &device_pub, true);

        let app1 = create_test_app().await;
        let app2 = create_test_app().await;

        let resp1 = app1
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/verify")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(body_bytes.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let resp2 = app2
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/verify")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(body_bytes))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp1.status(), axum::http::StatusCode::OK);
        assert_eq!(resp2.status(), axum::http::StatusCode::OK);

        let body1 = axum::body::to_bytes(resp1.into_body(), usize::MAX).await?;
        let body2 = axum::body::to_bytes(resp2.into_body(), usize::MAX).await?;

        let json1: serde_json::Value = serde_json::from_slice(&body1)?;
        let json2: serde_json::Value = serde_json::from_slice(&body2)?;

        let jws1 = json1["receipt"]
            .as_str()
            .expect("receipt must be present in response 1");
        let jws2 = json2["receipt"]
            .as_str()
            .expect("receipt must be present in response 2");

        let parts1: Vec<&str> = jws1.split('.').collect();
        let parts2: Vec<&str> = jws2.split('.').collect();

        let payload1: serde_json::Value = serde_json::from_slice(&BASE64URL.decode(parts1[1])?)?;
        let payload2: serde_json::Value = serde_json::from_slice(&BASE64URL.decode(parts2[1])?)?;

        let digest1 = payload1["receipt"]["manifest_digest"]
            .as_str()
            .expect("manifest_digest must be present in receipt 1");
        let digest2 = payload2["receipt"]["manifest_digest"]
            .as_str()
            .expect("manifest_digest must be present in receipt 2");

        assert_eq!(
            digest1, digest2,
            "SEC-12: same archive content must produce identical manifest_digest values (deterministic content binding)"
        );

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Test 10: Body limit — POST /v1/verify with >2 MB body returns 413.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_body_limit_413() {
        let app = create_test_app().await;
        // Build a body larger than the 2 MB RequestBodyLimitLayer
        let large_body = "x".repeat(3 * 1024 * 1024);
        let body = format!(
            r#"{{"manifest":{{"data":"{}"}}, "segments":[], "device_pub":"ed25519:test"}}"#,
            large_body
        );
        let req = Request::builder()
            .method("POST")
            .uri("/v1/verify")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            413,
            "oversized body (>2 MB) must return 413 Payload Too Large"
        );
    }

    // -----------------------------------------------------------------------
    // Test 11: Body under limit — POST /v1/verify with <2 MB body is not 413.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_body_under_limit_not_413() {
        let app = create_test_app().await;
        // Small valid-ish body — server will return 400 (bad payload) but NOT 413.
        let body = r#"{"manifest":{"data":"small"}, "segments":[], "device_pub":"ed25519:test"}"#;
        let req = Request::builder()
            .method("POST")
            .uri("/v1/verify")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_ne!(
            resp.status(),
            413,
            "normal-sized body (<2 MB) must not return 413"
        );
    }

    // -----------------------------------------------------------------------
    // Test 12: Rate limit — rapid calls to /v1/verify return 429.
    //
    // Sets RATE_LIMIT_RPS=2 so a burst of 20 requests should trigger 429.
    // The middleware falls back to 127.0.0.1 when ConnectInfo is absent
    // (oneshot test path), so all requests share the same bucket.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_rate_limit_429() {
        let _lock = ENV_MUTEX.lock().await;
        unsafe {
            std::env::set_var("RATE_LIMIT_RPS", "2");
        }
        let app = create_router(make_state());
        unsafe {
            std::env::remove_var("RATE_LIMIT_RPS");
        }

        let mut got_429 = false;
        for _ in 0..20 {
            let fresh_app = app.clone();
            let req = Request::builder()
                .method("POST")
                .uri("/v1/verify")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"manifest":{},"segments":[],"device_pub":"ed25519:x"}"#,
                ))
                .unwrap();
            let resp = fresh_app.oneshot(req).await.unwrap();
            if resp.status() == 429 {
                got_429 = true;
                break;
            }
        }
        assert!(
            got_429,
            "rapid calls to /v1/verify must eventually return 429 Too Many Requests"
        );
    }

    // -----------------------------------------------------------------------
    // Test 13: Healthz is never rate-limited.
    //
    // Sets RATE_LIMIT_RPS=1 and sends 20 GET /healthz requests.
    // All must return 200 — the rate limiter only applies to /v1/verify.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_healthz_not_rate_limited() {
        let _lock = ENV_MUTEX.lock().await;
        unsafe {
            std::env::set_var("RATE_LIMIT_RPS", "1");
        }
        let app = create_router(make_state());
        unsafe {
            std::env::remove_var("RATE_LIMIT_RPS");
        }

        for i in 0..20 {
            let fresh_app = app.clone();
            let req = Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap();
            let resp = fresh_app.oneshot(req).await.unwrap();
            assert_eq!(
                resp.status(),
                200,
                "GET /healthz request {} must not be rate-limited (expected 200, got {})",
                i + 1,
                resp.status()
            );
        }
    }

    // -----------------------------------------------------------------------
    // Test 14: SEC-ERRH — verify error response does not leak library detail.
    //
    // A manifest without a signature field triggers the verify_to_report Err
    // path (verify_signature returns Err when signature is missing). The
    // response body must contain only the generic category message and must NOT
    // contain any library error strings.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_verify_error_does_not_leak_library_detail() -> Result<()> {
        let app = create_test_app().await;

        // A manifest with no "signature" field at all triggers an Err return
        // from verify_signature (not just a passed=false result), which causes
        // the handler to return HTTP 400 with the generic error message.
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let verifying_key = signing_key.verifying_key();

        let manifest_no_sig = serde_json::json!({
            "version": "1.0",
            "segments": 1,
            "device_id": "test-device"
            // no "signature" field — triggers Err("Missing signature in manifest")
        });

        let device_pub = format!("ed25519:{}", BASE64.encode(verifying_key.as_bytes()));

        let body = serde_json::to_vec(&serde_json::json!({
            "device_pub": device_pub,
            "manifest": manifest_no_sig,
            "segments": [
                {
                    "index": 0,
                    "hash": "b3:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
                }
            ]
        }))
        .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/verify")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Must return a client error (400) — the verification error path.
        assert_eq!(
            response.status(),
            axum::http::StatusCode::BAD_REQUEST,
            "manifest missing signature field must return HTTP 400"
        );

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        // The detail field must contain only the generic category message, no
        // library internals like "Missing signature in manifest".
        assert_eq!(
            body_json["detail"], "Cryptographic verification failed",
            "error detail must be the exact generic message with no library internals"
        );

        // Convert body to string and assert no library error substrings are present.
        let body_str = std::str::from_utf8(&body_bytes).unwrap();
        for forbidden in &[
            "SignatureError",
            "InvalidSignature",
            "base64",
            "decode error",
            "verification equation",
            "invalid length",
            "Missing signature",
            "anyhow",
        ] {
            assert!(
                !body_str.contains(forbidden),
                "response body must not contain library detail substring '{}'",
                forbidden
            );
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Test 15: SEC-ERRH regression — success path is unaffected by sanitization.
    //
    // A valid signed manifest still returns HTTP 200 with
    // signature_verification.passed == true. Sanitization must not break the
    // success path.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_verify_success_unaffected_by_sanitization() -> Result<()> {
        let app = create_test_app().await;

        let (signed_manifest, device_pub) = build_signed_manifest("test-device");
        let body_bytes = build_verify_body(&signed_manifest, &device_pub, false);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/verify")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(body_bytes))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "success path must still return HTTP 200 after error sanitization"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let resp: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert!(
            resp["result"]["signature_verification"]["passed"]
                .as_bool()
                .unwrap_or(false),
            "signature_verification must pass for a correctly signed manifest"
        );

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Test 16: HTTP-02 — 429 response includes Retry-After: 1 header.
    //
    // Sets RATE_LIMIT_RPS=1 so the burst quota is exhausted quickly.
    // The first 429 response must carry `retry-after: 1`.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_rate_limit_retry_after() {
        let _lock = ENV_MUTEX.lock().await;
        unsafe {
            std::env::set_var("RATE_LIMIT_RPS", "1");
        }
        let app = create_router(make_state());
        unsafe {
            std::env::remove_var("RATE_LIMIT_RPS");
        }

        let mut retry_after_value: Option<String> = None;

        for _ in 0..20 {
            let fresh_app = app.clone();
            let req = Request::builder()
                .method("POST")
                .uri("/v1/verify")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"manifest":{},"segments":[],"device_pub":"ed25519:x"}"#,
                ))
                .unwrap();
            let resp = fresh_app.oneshot(req).await.unwrap();
            if resp.status() == 429 {
                retry_after_value = resp
                    .headers()
                    .get("retry-after")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                break;
            }
        }

        let value =
            retry_after_value.expect("rapid calls to /v1/verify must eventually return 429");
        assert_eq!(
            value, "1",
            "429 response must include Retry-After: 1 header (RFC 6585)"
        );
    }

    // -----------------------------------------------------------------------
    // Test 17: HTTP-01 — X-Forwarded-For is respected when peer is trusted.
    //
    // Sets TRUSTED_PROXIES="127.0.0.1/32" (oneshot tests appear as 127.0.0.1).
    // Rate limit is per-forwarded-IP, so two different XFF values have
    // independent buckets. First batch should 429; second batch with a
    // different forwarded IP should still 200.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_rate_limit_xff_trusted_proxy() {
        let _lock = ENV_MUTEX.lock().await;
        unsafe {
            std::env::set_var("RATE_LIMIT_RPS", "2");
            std::env::set_var("TRUSTED_PROXIES", "127.0.0.1/32");
        }
        let app = create_router(make_state());
        unsafe {
            std::env::remove_var("RATE_LIMIT_RPS");
            std::env::remove_var("TRUSTED_PROXIES");
        }

        // Exhaust the bucket for forwarded IP 10.99.99.1
        let mut got_429_for_first_ip = false;
        for _ in 0..20 {
            let req = Request::builder()
                .method("POST")
                .uri("/v1/verify")
                .header(CONTENT_TYPE, "application/json")
                .header("x-forwarded-for", "10.99.99.1")
                .body(Body::from(
                    r#"{"manifest":{},"segments":[],"device_pub":"ed25519:x"}"#,
                ))
                .unwrap();
            let resp = app.clone().oneshot(req).await.unwrap();
            if resp.status() == 429 {
                got_429_for_first_ip = true;
                break;
            }
        }
        assert!(
            got_429_for_first_ip,
            "forwarded IP 10.99.99.1 must eventually be rate-limited"
        );

        // A different forwarded IP (10.99.99.2) must have its own fresh bucket.
        let req = Request::builder()
            .method("POST")
            .uri("/v1/verify")
            .header(CONTENT_TYPE, "application/json")
            .header("x-forwarded-for", "10.99.99.2")
            .body(Body::from(
                r#"{"manifest":{},"segments":[],"device_pub":"ed25519:x"}"#,
            ))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_ne!(
            resp.status(),
            429,
            "forwarded IP 10.99.99.2 must not be rate-limited (independent bucket)"
        );
    }

    // -----------------------------------------------------------------------
    // Tests 19-23: POST /v1/verify-attestation — point attestation endpoint
    // -----------------------------------------------------------------------

    /// Build a signed PointAttestation JSON string for testing.
    fn build_test_attestation() -> String {
        let dir = tempfile::tempdir().unwrap();
        let binary_path = dir.path().join("test.bin");
        let sbom_path = dir.path().join("sbom.json");
        std::fs::write(&binary_path, b"test binary content").unwrap();
        std::fs::write(&sbom_path, r#"{"bomFormat":"CycloneDX","components":[]}"#).unwrap();

        let keypair = sealedge_core::DeviceKeypair::generate().unwrap();
        let attestation = sealedge_core::PointAttestation::create(
            &binary_path,
            "binary",
            &sbom_path,
            "sbom",
            &keypair,
        )
        .unwrap();
        attestation.to_json().unwrap()
    }

    #[tokio::test]
    async fn test_verify_attestation_valid() {
        let app = create_test_app().await;
        let body = build_test_attestation();
        let request = Request::builder()
            .method("POST")
            .uri("/v1/verify-attestation")
            .header(CONTENT_TYPE, "text/plain")
            .body(Body::from(body))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), 200, "valid attestation must return 200");
        let body_bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(json["status"], "verified", "status must be 'verified'");
        assert!(
            json["receipt"]
                .as_str()
                .map(|s| s.starts_with("ey"))
                .unwrap_or(false),
            "receipt must be a JWS token starting with 'ey'"
        );
    }

    #[tokio::test]
    async fn test_verify_attestation_bad_signature() {
        let app = create_test_app().await;
        let body = build_test_attestation();
        // Tamper with the nonce field by changing a character to break the signature
        let tampered = body.replacen(r#""nonce": ""#, r#""nonce": "x"#, 1);
        let request = Request::builder()
            .method("POST")
            .uri("/v1/verify-attestation")
            .header(CONTENT_TYPE, "text/plain")
            .body(Body::from(tampered))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            200,
            "tampered attestation must return 200 (not error)"
        );
        let body_bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(
            json["status"], "failed",
            "tampered attestation must have status 'failed'"
        );
    }

    #[tokio::test]
    async fn test_verify_attestation_malformed_json() {
        let app = create_test_app().await;
        let request = Request::builder()
            .method("POST")
            .uri("/v1/verify-attestation")
            .header(CONTENT_TYPE, "text/plain")
            .body(Body::from("not json at all"))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), 400, "malformed body must return 400");
        let body_bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(
            json["error"], "invalid_attestation",
            "malformed body error must be 'invalid_attestation'"
        );
    }

    #[tokio::test]
    async fn test_verify_attestation_wrong_format() {
        let app = create_test_app().await;
        // Build a minimal JSON that parses as PointAttestation but with wrong format
        let wrong_format_json = serde_json::json!({
            "format": "wrong-format-v99",
            "sealedge_version": "0.1.0",
            "timestamp": "2025-01-01T00:00:00.000Z",
            "nonce": "deadbeefdeadbeef",
            "subject": {
                "hash": "b3:0000000000000000000000000000000000000000000000000000000000000000",
                "filename": "test.bin",
                "label": "binary"
            },
            "evidence": {
                "hash": "b3:0000000000000000000000000000000000000000000000000000000000000000",
                "filename": "sbom.json",
                "label": "sbom"
            },
            "public_key": "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "signature": "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        });
        let request = Request::builder()
            .method("POST")
            .uri("/v1/verify-attestation")
            .header(CONTENT_TYPE, "text/plain")
            .body(Body::from(
                serde_json::to_string(&wrong_format_json).unwrap(),
            ))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), 400, "wrong format must return 400");
        let body_bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(
            json["error"], "invalid_format",
            "wrong format error must be 'invalid_format'"
        );
    }

    #[tokio::test]
    async fn test_verify_attestation_missing_signature() {
        let app = create_test_app().await;
        // Build valid attestation then remove the signature field
        let body = build_test_attestation();
        let mut parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        parsed["signature"] = serde_json::Value::Null;
        let request = Request::builder()
            .method("POST")
            .uri("/v1/verify-attestation")
            .header(CONTENT_TYPE, "text/plain")
            .body(Body::from(serde_json::to_string(&parsed).unwrap()))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), 400, "missing signature must return 400");
        let body_bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(
            json["error"], "missing_signature",
            "missing signature error must be 'missing_signature'"
        );
    }

    // -----------------------------------------------------------------------
    // Test 18: X-Forwarded-For is ignored when no trusted proxies are set.
    //
    // Sets TRUSTED_PROXIES="" (empty) and RATE_LIMIT_RPS=2.
    // All requests appear as 127.0.0.1 (oneshot fallback) regardless of the
    // X-Forwarded-For header, so they share the same bucket and 429 is hit.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_rate_limit_xff_untrusted_proxy() {
        let _lock = ENV_MUTEX.lock().await;
        unsafe {
            std::env::set_var("RATE_LIMIT_RPS", "2");
            std::env::set_var("TRUSTED_PROXIES", "");
        }
        let app = create_router(make_state());
        unsafe {
            std::env::remove_var("RATE_LIMIT_RPS");
            std::env::remove_var("TRUSTED_PROXIES");
        }

        // All requests share the 127.0.0.1 peer bucket (XFF is ignored)
        let mut got_429 = false;
        for _ in 0..20 {
            let req = Request::builder()
                .method("POST")
                .uri("/v1/verify")
                .header(CONTENT_TYPE, "application/json")
                .header("x-forwarded-for", "10.99.99.1")
                .body(Body::from(
                    r#"{"manifest":{},"segments":[],"device_pub":"ed25519:x"}"#,
                ))
                .unwrap();
            let resp = app.clone().oneshot(req).await.unwrap();
            if resp.status() == 429 {
                got_429 = true;
                break;
            }
        }
        assert!(
            got_429,
            "with no trusted proxies, peer IP 127.0.0.1 must be rate-limited regardless of XFF"
        );
    }
}

// ---------------------------------------------------------------------------
// Pure crypto tests (no feature gates required)
// ---------------------------------------------------------------------------

#[test]
fn test_happy_path_verification() -> Result<()> {
    let (signed_manifest, device_pub) = build_real_signed_manifest("test_device");
    let segments = matching_segments(&signed_manifest);

    let report = verify_to_report(&signed_manifest, &segments, &device_pub)?;

    assert!(report.signature_verification.passed);
    assert!(report.continuity_verification.passed);
    assert_eq!(report.metadata.total_segments, 2);
    assert_eq!(report.metadata.verified_segments, 2);
    // chain_tip must be the manifest's real last continuity_hash (C2), not a
    // function of segment count alone.
    let expected_tip = format!(
        "b3:{}",
        signed_manifest["segments"][1]["continuity_hash"]
            .as_str()
            .unwrap()
    );
    assert_eq!(report.metadata.chain_tip, expected_tip);

    Ok(())
}

#[test]
fn test_rejects_unsupported_version() -> Result<()> {
    // C4 §13.4 / M3: the platform verifier rejects non-0.2.0 archives outright.
    let (mut signed_manifest, device_pub) = build_real_signed_manifest("test_device");
    let segments = matching_segments(&signed_manifest);
    signed_manifest["trst_version"] = serde_json::json!("0.1.0");

    let err = verify_to_report(&signed_manifest, &segments, &device_pub).unwrap_err();
    assert!(
        err.to_string().contains("unsupported archive version"),
        "expected version rejection, got: {err}"
    );
    Ok(())
}

#[test]
fn test_tampered_manifest_fails_signature() -> Result<()> {
    // A canonically-signed manifest whose content is mutated after signing must
    // fail signature verification — the recomputed canonical bytes no longer
    // match the signature.
    let (mut signed_manifest, device_pub) = build_real_signed_manifest("test_device");
    let segments = matching_segments(&signed_manifest);
    signed_manifest["device"]["id"] = serde_json::json!("tampered-device");

    let report = verify_to_report(&signed_manifest, &segments, &device_pub)?;

    assert!(
        !report.signature_verification.passed,
        "tampering with a signed field must break signature verification"
    );
    assert!(report.signature_verification.error.is_some());

    Ok(())
}

#[test]
fn test_arbitrary_client_segments_fail_continuity() -> Result<()> {
    // C2 live exploit: attach arbitrary segment hashes to a legitimately-signed
    // manifest. The platform must NOT report continuity passed.
    let (signed_manifest, device_pub) = build_real_signed_manifest("test_device");
    let mut segments = matching_segments(&signed_manifest);
    segments[1].hash =
        "b3:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string();

    let report = verify_to_report(&signed_manifest, &segments, &device_pub)?;

    assert!(
        report.signature_verification.passed,
        "the manifest itself is validly signed"
    );
    assert!(
        !report.continuity_verification.passed,
        "segments that don't match the signed manifest must fail continuity (C2)"
    );
    assert_eq!(report.metadata.verified_segments, 0);

    Ok(())
}

#[test]
fn test_tampered_segment_verification() -> Result<()> {
    // A gap in the submitted segment indices must fail continuity.
    let (signed_manifest, device_pub) = build_real_signed_manifest("test_device");
    let mut segments = matching_segments(&signed_manifest);
    segments[1].index = 2; // gap at index 1

    let report = verify_to_report(&signed_manifest, &segments, &device_pub)?;

    assert!(report.signature_verification.passed);
    assert!(!report.continuity_verification.passed); // Should fail due to missing segment
    assert!(report.continuity_verification.error.is_some());

    Ok(())
}

#[test]
fn test_wrong_key_verification() -> Result<()> {
    // Manifest signed by one key, verified against a different public key.
    let (signed_manifest, _correct_pub) = build_real_signed_manifest("test_device");
    let segments = matching_segments(&signed_manifest);
    let wrong_key = sealedge_core::DeviceKeypair::generate().unwrap();

    let report = verify_to_report(&signed_manifest, &segments, &wrong_key.public)?;

    assert!(!report.signature_verification.passed); // Should fail with wrong key
    assert!(report.signature_verification.error.is_some());
    assert!(report.continuity_verification.passed); // Continuity should still pass

    Ok(())
}

#[test]
fn test_empty_segments_rejected() -> Result<()> {
    // Submitting no segments for a manifest that declares segments must fail
    // continuity (count mismatch) — post-C2 the client list must bind to the
    // signed manifest.
    let (signed_manifest, device_pub) = build_real_signed_manifest("test_device");

    let segments = vec![];

    let report = verify_to_report(&signed_manifest, &segments, &device_pub)?;

    assert!(report.signature_verification.passed);
    assert!(
        !report.continuity_verification.passed,
        "empty segments must not verify against a 2-segment signed manifest"
    );
    assert_eq!(report.metadata.total_segments, 2);
    assert_eq!(report.metadata.verified_segments, 0);

    Ok(())
}

#[test]
fn test_key_manager_creation_and_jwks() -> Result<()> {
    let key_manager = KeyManager::new()?;

    let kid = key_manager.current_kid();
    assert!(!kid.is_empty());
    assert!(kid.starts_with("key_"));

    let jwks = key_manager.to_jwks();
    let keys = jwks["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);

    let key = &keys[0];
    assert_eq!(key["kty"], "OKP");
    assert_eq!(key["crv"], "Ed25519");
    assert_eq!(key["alg"], "EdDSA");
    assert_eq!(key["kid"], kid);

    Ok(())
}

// ---------------------------------------------------------------------------
// JWKS key path configuration tests
// ---------------------------------------------------------------------------

#[test]
fn test_jwks_key_path_custom() -> Result<()> {
    // Create a unique temp directory for this test
    let dir = std::env::temp_dir().join(format!("sealedge_test_{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&dir)?;
    let key_path = dir.join("signing_key.json");

    let km = KeyManager::new_with_path(&key_path.to_string_lossy())?;

    // Signing key file must exist at the specified path
    assert!(
        key_path.exists(),
        "Signing key file must exist at the specified path"
    );

    // jwks.json must be co-located in the same directory
    let jwks_path = dir.join("jwks.json");
    assert!(
        jwks_path.exists(),
        "jwks.json must exist in the same directory as the signing key"
    );

    // KeyManager must load successfully (kid non-empty)
    assert!(!km.current_kid().is_empty(), "kid must be non-empty");

    // Cleanup
    std::fs::remove_dir_all(&dir).ok();

    Ok(())
}

#[test]
fn test_jwks_default_not_target_dev() -> Result<()> {
    // Clear JWKS_KEY_PATH to ensure default behavior
    std::env::remove_var("JWKS_KEY_PATH");

    // The default path must be in the system temp dir, not target/dev/
    let expected_default = std::env::temp_dir()
        .join("sealedge_signing_key.json")
        .to_string_lossy()
        .into_owned();

    let _km = KeyManager::new()?;

    // Verify the signing key was written to temp dir, not target/dev/
    assert!(
        std::path::Path::new(&expected_default).exists(),
        "Default signing key must be written to temp dir: {}",
        expected_default
    );

    // The default path must not contain "target/dev"
    assert!(
        !expected_default.contains("target/dev"),
        "Default key path must not contain target/dev, got: {}",
        expected_default
    );

    Ok(())
}

#[cfg(unix)]
#[test]
fn test_signing_key_permissions() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let dir = std::env::temp_dir().join(format!(
        "sealedge_perm_test_{}",
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(&dir)?;
    let key_path = dir.join("signing_key.json");

    let _km = KeyManager::new_with_path(&key_path.to_string_lossy())?;

    let metadata = std::fs::metadata(&key_path)?;
    let mode = metadata.permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "Signing key must have 0600 permissions, got {:o}",
        mode
    );

    // Cleanup
    std::fs::remove_dir_all(&dir).ok();

    Ok(())
}

#[test]
fn test_jwks_colocated_with_signing_key() -> Result<()> {
    let dir = std::env::temp_dir().join(format!(
        "sealedge_colocate_test_{}",
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(&dir)?;
    let key_path = dir.join("signing_key.json");

    let _km = KeyManager::new_with_path(&key_path.to_string_lossy())?;

    // jwks.json must be in the same directory as the signing key
    let expected_jwks = dir.join("jwks.json");
    assert!(
        expected_jwks.exists(),
        "jwks.json must be co-located with the signing key in the same directory"
    );

    // Verify that jwks.json is parseable JSON with a keys array
    let content = std::fs::read_to_string(&expected_jwks)?;
    let jwks: serde_json::Value = serde_json::from_str(&content)?;
    assert!(
        jwks.get("keys").is_some(),
        "jwks.json must contain a keys array"
    );

    // Cleanup
    std::fs::remove_dir_all(&dir).ok();

    Ok(())
}
