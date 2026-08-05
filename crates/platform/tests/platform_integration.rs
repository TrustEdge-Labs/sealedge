//
// Copyright (c) 2025 TRUSTEDGE LABS LLC
// This source code is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Project: sealedge — Privacy and trust at the edge.
//

//! Integration tests for the consolidated platform HTTP layer and database.
//!
//! Migrated from the v5.x trustedge-platform-api crate (renamed to sealedge-platform in v6.0)/platform-api/tests/integration_test.rs.
//!
//! ALL tests are marked `#[ignore]` — they require a running PostgreSQL instance.
//! Run with: `cargo test -p sealedge-platform --test platform_integration
//!            --features "http,postgres,test-utils" -- --include-ignored`
//!
//! Environment variable: TEST_DATABASE_URL (default: postgres://postgres:password@localhost:5432/sealedge_test)
//!
//! Behavioral changes from original platform-api tests:
//! - test_jwks_proxy: original expected 502 (proxy to verify-core). Now expects 200 (local JWKS).
//! - test_verify_valid_payload: original expected 502 (proxy to verify-core). Now expects 400
//!   (inline validation catches invalid segment hash format before verification).

#![cfg(all(feature = "http", feature = "postgres", feature = "test-utils"))]

use axum_test::TestServer;
use sealedge_platform::{
    database::{create_api_key, create_connection_pool, create_organization, run_migrations},
    http::{auth::generate_token, auth::hash_token_for_storage, handlers::create_test_app},
};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

async fn setup_test_db() -> (PgPool, Uuid, String) {
    let database_url = std::env::var("TEST_DATABASE_URL").unwrap_or_else(|_| {
        "postgres://postgres:password@localhost:5432/sealedge_test".to_string()
    });

    let pool = create_connection_pool(&database_url).await.unwrap();

    run_migrations(&pool).await.unwrap();

    let org_id = create_organization(&pool, "Test Org", "enterprise")
        .await
        .unwrap();

    let token = generate_token();
    let token_hash = hash_token_for_storage(&token);
    create_api_key(&pool, org_id, &token_hash).await.unwrap();

    (pool, org_id, token)
}

#[tokio::test]
#[ignore]
async fn test_auth_middleware() {
    let (pool, _org_id, token) = setup_test_db().await;

    let app = create_test_app(pool);
    let server = TestServer::new(app).unwrap();

    // Without token — should return 401
    let response = server
        .post("/v1/devices")
        .json(&json!({
            "device_id": "test-device",
            "device_pub": "test-pubkey",
            "label": "Test Device"
        }))
        .await;

    assert_eq!(response.status_code(), 401);

    // With valid token — should return 200
    let response = server
        .post("/v1/devices")
        .add_header(
            "Authorization".parse().unwrap(),
            format!("Bearer {}", token).parse().unwrap(),
        )
        .json(&json!({
            "device_id": "test-device",
            "device_pub": "test-pubkey",
            "label": "Test Device"
        }))
        .await;

    assert_eq!(response.status_code(), 200);
}

#[tokio::test]
#[ignore]
async fn test_device_registration() {
    let (pool, _org_id, token) = setup_test_db().await;

    let app = create_test_app(pool);
    let server = TestServer::new(app).unwrap();

    let response = server
        .post("/v1/devices")
        .add_header(
            "Authorization".parse().unwrap(),
            format!("Bearer {}", token).parse().unwrap(),
        )
        .json(&json!({
            "device_id": "test-device-001",
            "device_pub": "test-pubkey-data",
            "label": "Test Device"
        }))
        .await;

    assert_eq!(response.status_code(), 200);

    let body: serde_json::Value = response.json();
    assert_eq!(body["device_id"], "test-device-001");
    assert_eq!(body["device_pub"], "test-pubkey-data");
    assert_eq!(body["label"], "Test Device");
    assert_eq!(body["status"], "active");
}

#[tokio::test]
#[ignore]
async fn test_org_isolation() {
    let (pool, _org1_id, token1) = setup_test_db().await;

    let org2_id = create_organization(&pool, "Test Org 2", "free")
        .await
        .unwrap();
    let token2 = generate_token();
    let token2_hash = hash_token_for_storage(&token2);
    create_api_key(&pool, org2_id, &token2_hash).await.unwrap();

    let app = create_test_app(pool);
    let server = TestServer::new(app).unwrap();

    let response1 = server
        .post("/v1/devices")
        .add_header(
            "Authorization".parse().unwrap(),
            format!("Bearer {}", token1).parse().unwrap(),
        )
        .json(&json!({
            "device_id": "org1-device",
            "device_pub": "org1-pubkey",
            "label": "Org 1 Device"
        }))
        .await;

    assert_eq!(response1.status_code(), 200);

    let response2 = server
        .post("/v1/devices")
        .add_header(
            "Authorization".parse().unwrap(),
            format!("Bearer {}", token2).parse().unwrap(),
        )
        .json(&json!({
            "device_id": "org2-device",
            "device_pub": "org2-pubkey",
            "label": "Org 2 Device"
        }))
        .await;

    assert_eq!(response2.status_code(), 200);
}

/// Tests that JWKS endpoint returns local keys (not a 502 proxy error).
///
/// Behavioral change from original platform-api: previously proxied to verify-core (502 when
/// mock server not running). Now served from local KeyManager → 200 with valid JWKS structure.
#[tokio::test]
#[ignore]
async fn test_jwks_endpoint_returns_local_keys() {
    let (pool, _org_id, _token) = setup_test_db().await;

    let app = create_test_app(pool);
    let server = TestServer::new(app).unwrap();

    let response = server.get("/.well-known/jwks.json").await;

    assert_eq!(response.status_code(), 200);

    let body: serde_json::Value = response.json();
    assert!(body.get("keys").is_some());
    let keys = body["keys"].as_array().unwrap();
    assert!(!keys.is_empty());
    assert_eq!(keys[0]["kty"], "OKP");
    assert_eq!(keys[0]["crv"], "Ed25519");
    assert_eq!(keys[0]["alg"], "EdDSA");
}

#[tokio::test]
#[ignore]
async fn test_verify_invalid_payload_returns_400() {
    let (pool, _org_id, token) = setup_test_db().await;

    let app = create_test_app(pool);
    let server = TestServer::new(app).unwrap();

    let response = server
        .post("/v1/verify")
        .add_header(
            "Authorization".parse().unwrap(),
            format!("Bearer {}", token).parse().unwrap(),
        )
        .json(&json!({
            "device_pub": "",
            "manifest": "test manifest",
            "segments": []
        }))
        .await;

    assert_eq!(response.status_code(), 400);
    let body: serde_json::Value = response.json();
    assert_eq!(body["error"], "invalid_segments");
}

#[tokio::test]
#[ignore]
async fn test_verify_empty_device_pub_returns_400() {
    let (pool, _org_id, token) = setup_test_db().await;

    let app = create_test_app(pool);
    let server = TestServer::new(app).unwrap();

    let response = server
        .post("/v1/verify")
        .add_header(
            "Authorization".parse().unwrap(),
            format!("Bearer {}", token).parse().unwrap(),
        )
        .json(&json!({
            "device_pub": "",
            "manifest": "test manifest",
            "segments": [{"index": 0, "hash": "a".repeat(64)}]
        }))
        .await;

    assert_eq!(response.status_code(), 400);
    let body: serde_json::Value = response.json();
    assert_eq!(body["error"], "invalid_device_pub");
}

#[tokio::test]
#[ignore]
async fn test_verify_empty_manifest_returns_400() {
    let (pool, _org_id, token) = setup_test_db().await;

    let app = create_test_app(pool);
    let server = TestServer::new(app).unwrap();

    let response = server
        .post("/v1/verify")
        .add_header(
            "Authorization".parse().unwrap(),
            format!("Bearer {}", token).parse().unwrap(),
        )
        .json(&json!({
            "device_pub": "ed25519:test",
            "manifest": "",
            "segments": [{"index": 0, "hash": "a".repeat(64)}]
        }))
        .await;

    assert_eq!(response.status_code(), 400);
    let body: serde_json::Value = response.json();
    assert_eq!(body["error"], "invalid_manifest");
}

#[tokio::test]
#[ignore]
async fn test_verify_invalid_segments_returns_400() {
    let (pool, _org_id, token) = setup_test_db().await;

    let app = create_test_app(pool);
    let server = TestServer::new(app).unwrap();

    let response = server
        .post("/v1/verify")
        .add_header(
            "Authorization".parse().unwrap(),
            format!("Bearer {}", token).parse().unwrap(),
        )
        .json(&json!({
            "device_pub": "ed25519:test",
            "manifest": "test manifest",
            "segments": [{"index": 1, "hash": "invalid"}]
        }))
        .await;

    assert_eq!(response.status_code(), 400);
    let body: serde_json::Value = response.json();
    assert_eq!(body["error"], "invalid_segments");
}

/// Tests that a valid payload structure returns 400 due to invalid segment hash format.
///
/// Behavioral change from original platform-api: previously forwarded to verify-core via HTTP
/// (returning 502 when mock server not running). Now performs inline validation and verification.
/// The segment hash "a"*64 lacks the required "b3:" prefix, so validation fails with
/// `invalid_segments` before reaching the cryptographic verification step.
#[tokio::test]
#[ignore]
async fn test_verify_valid_payload_inline_verification() {
    let (pool, _org_id, token) = setup_test_db().await;

    let app = create_test_app(pool);
    let server = TestServer::new(app).unwrap();

    let response = server
        .post("/v1/verify")
        .add_header(
            "Authorization".parse().unwrap(),
            format!("Bearer {}", token).parse().unwrap(),
        )
        .json(&json!({
            "device_pub": "ed25519:test",
            "manifest": "test manifest",
            "segments": [{"index": 0, "hash": "a".repeat(64)}]
        }))
        .await;

    // Inline validation rejects the segment hash format (no "b3:" prefix)
    assert_eq!(response.status_code(), 400);
    let body: serde_json::Value = response.json();
    assert_eq!(body["error"], "invalid_segments");
}

#[tokio::test]
#[ignore]
async fn test_verify_malformed_json_returns_400() {
    let (pool, _org_id, token) = setup_test_db().await;

    let app = create_test_app(pool);
    let server = TestServer::new(app).unwrap();

    let response = server
        .post("/v1/verify")
        .add_header(
            "Authorization".parse().unwrap(),
            format!("Bearer {}", token).parse().unwrap(),
        )
        .add_header(
            "Content-Type".parse().unwrap(),
            "application/json".parse().unwrap(),
        )
        .text("{invalid json")
        .await;

    assert_eq!(response.status_code(), 400);
}

#[tokio::test]
#[ignore]
async fn test_verify_unknown_fields_returns_400() {
    let (pool, _org_id, token) = setup_test_db().await;

    let app = create_test_app(pool);
    let server = TestServer::new(app).unwrap();

    let response = server
        .post("/v1/verify")
        .add_header(
            "Authorization".parse().unwrap(),
            format!("Bearer {}", token).parse().unwrap(),
        )
        .json(&json!({
            "device_pub": "ed25519:test",
            "manifest": "test manifest",
            "segments": [{"index": 0, "hash": "a".repeat(64)}],
            "unknown_field": "should_cause_error"
        }))
        .await;

    assert_eq!(response.status_code(), 400);
}

// ─── H1 witness endpoint (POST /v1/witness) — require a live PostgreSQL ────────

/// Accept a genesis tip, idempotently replay it, and reject a fork at the same
/// sequence (409). Exercises the full handler: signature check, registry lookup,
/// monotonic ledger insert, and JWS issuance.
#[tokio::test]
#[ignore]
async fn test_witness_records_and_rejects_fork() {
    let (pool, _org_id, _token) = setup_test_db().await;
    let server = TestServer::new(create_test_app(pool)).unwrap();

    let kp = sealedge_core::DeviceKeypair::generate().unwrap();
    let signed_at = "2026-08-05T00:00:00Z";

    let r0 = sealedge_core::WitnessRequest::create_signed(&kp, 0, "b3:aaa", signed_at).unwrap();
    let resp = server.post("/v1/witness").json(&r0).await;
    assert_eq!(resp.status_code(), 200);
    assert!(resp.json::<serde_json::Value>()["jws"].as_str().is_some());

    // Exact replay is idempotent.
    let resp = server.post("/v1/witness").json(&r0).await;
    assert_eq!(resp.status_code(), 200);

    // Same sequence, different tip → fork.
    let fork = sealedge_core::WitnessRequest::create_signed(&kp, 0, "b3:bbb", signed_at).unwrap();
    let resp = server.post("/v1/witness").json(&fork).await;
    assert_eq!(resp.status_code(), 409);
}

/// Reject a sequence at or below the ledger max that isn't an exact replay
/// (rollback → 409). Gaps above the max are allowed.
#[tokio::test]
#[ignore]
async fn test_witness_rejects_rollback() {
    let (pool, _org_id, _token) = setup_test_db().await;
    let server = TestServer::new(create_test_app(pool)).unwrap();

    let kp = sealedge_core::DeviceKeypair::generate().unwrap();
    let signed_at = "2026-08-05T00:00:00Z";

    // Record sequence 2 (a gap above genesis is fine).
    let r2 = sealedge_core::WitnessRequest::create_signed(&kp, 2, "b3:ccc", signed_at).unwrap();
    assert_eq!(
        server.post("/v1/witness").json(&r2).await.status_code(),
        200
    );

    // Backfilling sequence 1 below the max is a rollback.
    let r1 = sealedge_core::WitnessRequest::create_signed(&kp, 1, "b3:bbb", signed_at).unwrap();
    assert_eq!(
        server.post("/v1/witness").json(&r1).await.status_code(),
        409
    );
}

/// A request whose signature does not match its contents is rejected (401).
#[tokio::test]
#[ignore]
async fn test_witness_rejects_bad_signature() {
    let (pool, _org_id, _token) = setup_test_db().await;
    let server = TestServer::new(create_test_app(pool)).unwrap();

    let kp = sealedge_core::DeviceKeypair::generate().unwrap();
    let mut req =
        sealedge_core::WitnessRequest::create_signed(&kp, 0, "b3:aaa", "2026-08-05T00:00:00Z")
            .unwrap();
    // Tamper the tip after signing — the signature no longer matches.
    req.tip = "b3:tampered".to_string();
    let resp = server.post("/v1/witness").json(&req).await;
    assert_eq!(resp.status_code(), 401);
}

// ─── H1 Phase 2: revocation & rotation lineage (POST /v1/devices/:id/revoke,
//     witness gates) — require a live PostgreSQL ─────────────────────────────

/// Register a device and return its UUID.
#[cfg(all(feature = "http", feature = "postgres", feature = "test-utils"))]
async fn register(server: &TestServer, token: &str, device_id: &str, device_pub: &str) -> Uuid {
    let resp = server
        .post("/v1/devices")
        .add_header(
            "Authorization".parse().unwrap(),
            format!("Bearer {token}").parse().unwrap(),
        )
        .json(&json!({ "device_id": device_id, "device_pub": device_pub }))
        .await;
    assert_eq!(resp.status_code(), 200);
    let body: serde_json::Value = resp.json();
    body["id"].as_str().unwrap().parse().unwrap()
}

/// Call the revoke endpoint and return the HTTP status.
#[cfg(all(feature = "http", feature = "postgres", feature = "test-utils"))]
async fn revoke(server: &TestServer, token: &str, id: Uuid, body: serde_json::Value) -> u16 {
    server
        .post(&format!("/v1/devices/{id}/revoke"))
        .add_header(
            "Authorization".parse().unwrap(),
            format!("Bearer {token}").parse().unwrap(),
        )
        .json(&body)
        .await
        .status_code()
        .as_u16()
}

/// PA4: revocation is monotonic — earlier-only for `revoked_at`, non-decreasing
/// for `min_epoch`; violations are 409.
#[tokio::test]
#[ignore]
async fn test_revoke_is_monotonic() {
    let (pool, _org_id, token) = setup_test_db().await;
    let server = TestServer::new(create_test_app(pool)).unwrap();
    let id = register(&server, &token, "dev-revoke", "ed25519:revoke-pub").await;

    // First revoke at a specific instant with a floor.
    assert_eq!(
        revoke(
            &server,
            &token,
            id,
            json!({ "revoked_at": "2026-08-05T00:00:00Z", "min_epoch": 2 })
        )
        .await,
        200
    );
    // Moving revoked_at LATER is rejected.
    assert_eq!(
        revoke(
            &server,
            &token,
            id,
            json!({ "revoked_at": "2026-08-09T00:00:00Z" })
        )
        .await,
        409
    );
    // Moving it EARLIER is allowed.
    assert_eq!(
        revoke(
            &server,
            &token,
            id,
            json!({ "revoked_at": "2026-08-01T00:00:00Z" })
        )
        .await,
        200
    );
    // Lowering min_epoch is rejected; raising it is allowed.
    assert_eq!(
        revoke(&server, &token, id, json!({ "min_epoch": 1 })).await,
        409
    );
    assert_eq!(
        revoke(&server, &token, id, json!({ "min_epoch": 5 })).await,
        200
    );
}

/// PA5: once revoked, a device is refused a NEW witness (403), but an
/// already-witnessed entry still replays (200).
#[tokio::test]
#[ignore]
async fn test_witness_refused_after_revoke() {
    let (pool, _org_id, token) = setup_test_db().await;
    let server = TestServer::new(create_test_app(pool)).unwrap();

    let kp = sealedge_core::DeviceKeypair::generate().unwrap();
    let id = register(&server, &token, "dev-w", &kp.public).await;

    // Witness genesis before revocation.
    let r0 = sealedge_core::WitnessRequest::create_signed(&kp, 0, "b3:aaa", "2026-08-05T00:00:00Z")
        .unwrap();
    assert_eq!(
        server.post("/v1/witness").json(&r0).await.status_code(),
        200
    );

    // Revoke the device.
    let resp = server
        .post(&format!("/v1/devices/{id}/revoke"))
        .add_header(
            "Authorization".parse().unwrap(),
            format!("Bearer {token}").parse().unwrap(),
        )
        .json(&json!({}))
        .await;
    assert_eq!(resp.status_code(), 200);

    // A NEW tip is refused (403); the already-witnessed genesis still replays.
    let r1 = sealedge_core::WitnessRequest::create_signed(&kp, 1, "b3:bbb", "2026-08-05T00:01:00Z")
        .unwrap();
    assert_eq!(
        server.post("/v1/witness").json(&r1).await.status_code(),
        403
    );
    assert_eq!(
        server.post("/v1/witness").json(&r0).await.status_code(),
        200
    );
}

/// PA1 + PA2: witnessing a rotation tip under the new key records lineage, after
/// which the old key's ledger is closed beyond the rotation point (409).
#[tokio::test]
#[ignore]
async fn test_rotation_lineage_closes_old_ledger() {
    let (pool, _org_id, _token) = setup_test_db().await;
    let server = TestServer::new(create_test_app(pool)).unwrap();

    let old = sealedge_core::DeviceKeypair::generate().unwrap();
    let new = sealedge_core::DeviceBundle::generate().unwrap();
    let ts = "2026-08-05T00:00:00Z";

    // Old key witnesses genesis (sequence 0).
    let g = sealedge_core::WitnessRequest::create_signed(&old, 0, "b3:genesis", ts).unwrap();
    assert_eq!(server.post("/v1/witness").json(&g).await.status_code(), 200);

    // Build a rotation entry at sequence 1 whose prev is the genesis tip.
    let rot = sealedge_core::RotationRecord::create_signed(
        &old,
        0,
        &new,
        1,
        "b3:genesis".to_string(),
        ts,
    )
    .unwrap();
    let rot_tip = sealedge_core::format_archive_id(&rot.archive_digest());

    // New key witnesses the rotation tip, attaching the rotation entry (PA1).
    let mut wreq =
        sealedge_core::WitnessRequest::create_signed(&new.signing, 1, &rot_tip, ts).unwrap();
    wreq.rotation = Some(rot);
    assert_eq!(
        server.post("/v1/witness").json(&wreq).await.status_code(),
        200
    );

    // PA2: the OLD key's ledger is now closed beyond the rotation — a new tip at
    // sequence 2 under the old key is refused as superseded (409).
    let old2 = sealedge_core::WitnessRequest::create_signed(&old, 2, "b3:evil", ts).unwrap();
    assert_eq!(
        server.post("/v1/witness").json(&old2).await.status_code(),
        409
    );

    // The NEW key continues normally.
    let new2 =
        sealedge_core::WitnessRequest::create_signed(&new.signing, 2, "b3:cont", ts).unwrap();
    assert_eq!(
        server.post("/v1/witness").json(&new2).await.status_code(),
        200
    );
}
