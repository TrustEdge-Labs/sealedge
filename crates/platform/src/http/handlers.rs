//
// Copyright (c) 2025 TRUSTEDGE LABS LLC
// This source code is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Project: sealedge — Privacy and trust at the edge.
//

//! HTTP endpoint handlers for the Sealedge Platform service.
//!
//! The key consolidation change: `verify_handler` now calls
//! `crate::verify::engine::verify_to_report()` directly instead of forwarding
//! to a separate verify-core service via HTTP.

use axum::{extract::State, http::StatusCode, response::Json};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::Utc;
use serde_json::Value;
use tracing::{info, warn};

use crate::verify::{
    engine::verify_to_report,
    types::{HealthResponse, VerifyRequest, VerifyResponse},
    validation::{validate_verify_request_full, ValidationError},
};

// The non-postgres handler uses the shared receipt builder from validation.rs.
#[cfg(not(feature = "postgres"))]
use crate::verify::validation::build_receipt_if_requested;

// receipt_from_report and sign_receipt_jws are only used in the postgres handler,
// which inlines receipt construction due to DB storage interleaving.
#[cfg(feature = "postgres")]
use crate::verify::{engine::receipt_from_report, signing::sign_receipt_jws};

// sign_receipt_jws is needed for the attestation handler (always available)
#[cfg(not(feature = "postgres"))]
use crate::verify::signing::sign_receipt_jws;

use sealedge_core::{point_attestation::FORMAT_V1, PointAttestation};

use super::state::AppState;

// ---------------------------------------------------------------------------
// Always-available handlers (no postgres required)
// ---------------------------------------------------------------------------

/// GET /.well-known/jwks.json — returns the local KeyManager's JWKS.
///
/// Serves keys from the local KeyManager. No proxy to an external service.
pub async fn jwks_handler(State(state): State<AppState>) -> Json<Value> {
    let keys = state.keys.read().await;
    Json(keys.to_jwks())
}

/// GET /healthz — returns service health status.
pub async fn health_handler() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "OK".to_string(),
        timestamp: Utc::now().to_rfc3339(),
    })
}

/// POST /v1/verify — inline verification (stateless, no DB storage).
///
/// Validates the request, calls `verify_to_report()` directly, and optionally
/// signs a JWS receipt. This handler does not require the `postgres` feature.
///
/// When the `postgres` feature is enabled, use `verify_handler` instead for
/// full multi-tenant operation with DB audit trail.
#[cfg(not(feature = "postgres"))]
pub async fn verify_handler(
    State(state): State<AppState>,
    Json(request): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, (StatusCode, Json<ValidationError>)> {
    info!(
        "Processing verification request for device: {}",
        request.device_pub
    );

    validate_verify_request_full(&request).map_err(|e| (StatusCode::BAD_REQUEST, Json(e)))?;

    let report = match verify_to_report(&request.manifest, &request.segments, &request.device_pub) {
        Ok(report) => report,
        Err(e) => {
            warn!("Verification failed: {}", e);
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ValidationError::new(
                    "verification_failed",
                    "Cryptographic verification failed",
                )),
            ));
        }
    };

    let verification_id = format!("v_{}", uuid::Uuid::new_v4().simple());

    let keys = state.keys.read().await;
    let receipt = build_receipt_if_requested(
        &request,
        &report,
        &keys,
        compute_manifest_digest_blake3,
        state.receipt_ttl_secs,
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(e)))?;

    Ok(Json(VerifyResponse {
        verification_id,
        result: report,
        receipt,
    }))
}

// ---------------------------------------------------------------------------
// Attestation verification response type (no feature gate — always available)
// ---------------------------------------------------------------------------

/// Response from POST /v1/verify-attestation.
#[derive(serde::Serialize)]
pub struct VerifyAttestationResponse {
    /// Verification outcome: `"verified"` or `"failed"`.
    pub status: String,
    /// JWS receipt token (only present when status is `"verified"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt: Option<String>,
    /// Additional details about the verification result.
    pub details: serde_json::Value,
}

/// POST /v1/verify-attestation — verify a point attestation document.
///
/// Accepts the attestation JSON document directly as the request body (per D-11).
/// Extracts the embedded public key, verifies the signature, and returns a JWS receipt
/// on success. No database interaction — works identically with or without postgres.
pub async fn verify_attestation_handler(
    State(state): State<AppState>,
    body: String,
) -> Result<Json<VerifyAttestationResponse>, (StatusCode, Json<ValidationError>)> {
    // Parse the attestation document
    let attestation = PointAttestation::from_json(&body).map_err(|e| {
        warn!("Failed to parse attestation document: {}", e);
        (
            StatusCode::BAD_REQUEST,
            Json(ValidationError::new(
                "invalid_attestation",
                "Failed to parse attestation document",
            )),
        )
    })?;

    // Validate format discriminant
    if attestation.format != FORMAT_V1 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ValidationError::new(
                "invalid_format",
                "Expected format te-point-attestation-v1",
            )),
        ));
    }

    // Require signature field to be present
    if attestation.signature.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ValidationError::new(
                "missing_signature",
                "Attestation document has no signature",
            )),
        ));
    }

    let device_pub = &attestation.public_key.clone();

    // Verify the Ed25519 signature using the embedded public key
    match attestation.verify_signature(device_pub) {
        Err(e) => {
            warn!("Attestation cryptographic verification error: {}", e);
            // Return 200 with "failed" — do not leak internal error details
            let details = serde_json::json!({
                "reason": "Cryptographic verification failed",
                "public_key": device_pub,
                "timestamp": attestation.timestamp,
            });
            Ok(Json(VerifyAttestationResponse {
                status: "failed".to_string(),
                receipt: None,
                details,
            }))
        }
        Ok(false) => {
            let details = serde_json::json!({
                "reason": "Signature verification failed",
                "public_key": device_pub,
                "timestamp": attestation.timestamp,
            });
            Ok(Json(VerifyAttestationResponse {
                status: "failed".to_string(),
                receipt: None,
                details,
            }))
        }
        Ok(true) => {
            // Signature valid — build JWS receipt
            let verification_id = format!("va_{}", uuid::Uuid::new_v4().simple());

            let manifest_digest = {
                let canonical = attestation.canonical_bytes().unwrap_or_default();
                let hash = sealedge_core::chain::segment_hash(&canonical);
                format!("b3:{}", BASE64.encode(hash))
            };

            let now_rfc3339 = Utc::now().to_rfc3339();

            let keys = state.keys.read().await;
            let kid = keys.current_kid();

            // Build ReceiptClaims minimally — point attestations don't have segments/chain.
            // Attestations are self-signed: the signer is the embedded public key,
            // and there is no device registry to bind it to (device_registered = false).
            // The receipt attests "this key signed this subject↔evidence binding",
            // not that the signer is a trusted/known device (C3).
            let receipt_claims = crate::verify::engine::ReceiptClaims {
                verification_id,
                signer_pub: device_pub.clone(),
                device_id: device_pub.clone(),
                device_registered: false,
                manifest_digest,
                chain_tip: "none".to_string(),
                timestamp: now_rfc3339,
                kid,
                result: crate::verify::engine::VerifyReport {
                    signature_verification: crate::verify::engine::VerificationResult {
                        passed: true,
                        error: None,
                    },
                    continuity_verification: crate::verify::engine::VerificationResult {
                        passed: true,
                        error: None,
                    },
                    metadata: crate::verify::engine::VerificationMetadata {
                        total_segments: 0,
                        verified_segments: 0,
                        chain_tip: "none".to_string(),
                        genesis_hash: "none".to_string(),
                    },
                },
            };

            match sign_receipt_jws(&receipt_claims, &keys, state.receipt_ttl_secs).await {
                Err(e) => {
                    warn!("Failed to sign attestation receipt: {}", e);
                    Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ValidationError::new(
                            "receipt_error",
                            "Failed to sign receipt",
                        )),
                    ))
                }
                Ok(jws_token) => {
                    let details = serde_json::json!({
                        "subject_hash": attestation.subject.hash,
                        "evidence_hash": attestation.evidence.hash,
                        "public_key": device_pub,
                        "timestamp": attestation.timestamp,
                        "format": attestation.format,
                        // Honest semantics (C3): this is a self-signed document. A
                        // "verified" status means the signature is well-formed and was
                        // produced by `public_key` — NOT that the signer is a trusted
                        // or registered identity.
                        "signer_registered": false,
                        "trust": "self-signed: signature valid for the embedded public key; signer identity not established",
                    });
                    Ok(Json(VerifyAttestationResponse {
                        status: "verified".to_string(),
                        receipt: Some(jws_token),
                        details,
                    }))
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Postgres-gated handlers (full multi-tenant with DB audit trail)
// ---------------------------------------------------------------------------

/// POST /v1/verify — inline verification with DB audit trail.
///
/// Consolidation change: calls `verify_to_report()` directly instead of
/// forwarding to a separate verify-core service via HTTP. Requires postgres.
#[cfg(feature = "postgres")]
pub async fn verify_handler(
    State(state): State<AppState>,
    org_ctx: Option<axum::extract::Extension<crate::http::auth::OrgContext>>,
    Json(request): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, (StatusCode, Json<ValidationError>)> {
    info!(
        "Processing verification request for device: {}",
        request.device_pub
    );

    if org_ctx.is_none() {
        tracing::debug!(
            "verify_handler: no OrgContext present — operating in tenant-agnostic mode"
        );
    }

    validate_verify_request_full(&request).map_err(|e| (StatusCode::BAD_REQUEST, Json(e)))?;

    // Registry binding (C3): if the request claims a device_id and we have a
    // tenant context, the device MUST be registered AND its stored key MUST
    // equal request.device_pub. We fail closed on an unknown device or a key
    // mismatch — otherwise device_id would be attacker-chosen identity attached
    // to an unrelated key. When bound, `device_registered` marks the receipt's
    // device_id as trustworthy.
    let mut device_id: Option<uuid::Uuid> = None;
    let mut device_registered = false;
    if let Some(ref device_id_str) = request.options.device_id {
        if let Some(ref ctx) = org_ctx {
            let record =
                crate::database::get_device_with_pub(&state.db_pool, ctx.org_id, device_id_str)
                    .await
                    .map_err(|_| {
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(ValidationError::new(
                                "database_error",
                                "Failed to query device",
                            )),
                        )
                    })?;

            match record {
                None => {
                    return Err((
                        StatusCode::FORBIDDEN,
                        Json(ValidationError::new(
                            "unknown_device",
                            "device_id is not registered for this organization",
                        )),
                    ));
                }
                Some((_, stored_pub)) if stored_pub != request.device_pub => {
                    return Err((
                        StatusCode::FORBIDDEN,
                        Json(ValidationError::new(
                            "device_key_mismatch",
                            "device_pub does not match the registered key for device_id",
                        )),
                    ));
                }
                Some((id, _)) => {
                    device_id = Some(id);
                    device_registered = true;
                }
            }
        }
        // No tenant context (tenant-agnostic mode): cannot bind, stays unregistered.
    }

    // H1 Phase 2: registry revocation enforcement (design §5.2). Look up the
    // signing key's revocation state (A2, org-agnostic registry binding) and fail
    // closed when the archive's key_epoch is below the device's min_epoch floor.
    // `revoked_at` itself is NOT a hard reject here — trusting an archive under a
    // revoked key is the verifier-side composition with the witness `observed_at`
    // (§5.3); we annotate `revoked_at`/`min_epoch` so the client can perform it.
    let mut revocation_annotation = serde_json::Value::Null;
    if let Some((_, rev)) =
        crate::database::get_device_revocation_by_pub(&state.db_pool, &request.device_pub)
            .await
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ValidationError::new(
                        "database_error",
                        "Failed to query device revocation",
                    )),
                )
            })?
    {
        // manifest is raw JSON here; absent key_epoch means epoch 0 (genesis).
        let archive_epoch = request
            .manifest
            .get("device")
            .and_then(|d| d.get("key_epoch"))
            .and_then(|e| e.as_u64())
            .unwrap_or(0) as u32;
        if !crate::revocation::epoch_allowed(rev.min_epoch, archive_epoch) {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ValidationError::new(
                    "epoch_below_min",
                    "archive key_epoch is below the device's min_epoch floor",
                )),
            ));
        }
        revocation_annotation = serde_json::json!({
            "revoked_at": rev.revoked_at,
            "min_epoch": rev.min_epoch,
        });
    }

    // Inline verification — direct call, no HTTP forwarding
    let report = match verify_to_report(&request.manifest, &request.segments, &request.device_pub) {
        Ok(report) => report,
        Err(e) => {
            warn!("Verification failed: {}", e);
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ValidationError::new(
                    "verification_failed",
                    "Cryptographic verification failed",
                )),
            ));
        }
    };

    // SHA-256 manifest digest for DB storage (compatibility with existing schema)
    let manifest_digest_sha256 = compute_manifest_digest_sha256(&request.manifest);

    let result_for_db = serde_json::json!({
        "signature_verification": {
            "passed": report.signature_verification.passed,
            "error": report.signature_verification.error,
        },
        "continuity_verification": {
            "passed": report.continuity_verification.passed,
            "error": report.continuity_verification.error,
        },
        "metadata": {
            "total_segments": report.metadata.total_segments,
            "verified_segments": report.metadata.verified_segments,
            "chain_tip": report.metadata.chain_tip,
            "genesis_hash": report.metadata.genesis_hash,
        },
        // H1 Phase 2: revocation annotation (null when the key is unregistered).
        "revocation": revocation_annotation,
    });

    let org_id_for_db = org_ctx
        .as_ref()
        .map(|e| e.org_id)
        .unwrap_or_else(uuid::Uuid::nil);

    let verification_id_uuid = crate::database::create_verification(
        &state.db_pool,
        org_id_for_db,
        device_id,
        &manifest_digest_sha256,
        &result_for_db,
    )
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ValidationError::new(
                "database_error",
                "Failed to create verification record",
            )),
        )
    })?;

    let verification_id = verification_id_uuid.to_string();
    let mut receipt = None;
    let mut receipt_id = None;

    // Receipt construction inlined here due to DB storage interleaving.
    {
        let options = &request.options;
        if options.return_receipt
            && report.signature_verification.passed
            && report.continuity_verification.passed
        {
            let device_id_str = options.device_id.as_deref().unwrap_or("unknown_device");

            // BLAKE3 digest for receipt construction (per verify-service convention)
            let manifest_digest_blake3 = compute_manifest_digest_blake3(&request.manifest);
            let now_rfc3339 = Utc::now().to_rfc3339();

            let keys = state.keys.read().await;
            let kid = keys.current_kid();

            let receipt_obj = receipt_from_report(
                &report,
                &manifest_digest_blake3,
                &request.device_pub,
                device_id_str,
                device_registered,
                &kid,
                &now_rfc3339,
                &report.metadata.chain_tip,
            );

            match sign_receipt_jws(&receipt_obj, &keys, state.receipt_ttl_secs).await {
                Ok(jws) => {
                    // Store receipt in DB
                    match crate::database::create_receipt(
                        &state.db_pool,
                        verification_id_uuid,
                        &jws,
                        &kid,
                    )
                    .await
                    {
                        Ok(rid) => {
                            receipt = Some(jws);
                            receipt_id = Some(rid.to_string());
                        }
                        Err(_) => {
                            warn!("Failed to store receipt in database");
                            // Non-fatal: return receipt without storing
                            receipt = Some(jws);
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to sign receipt: {}", e);
                    return Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ValidationError::new(
                            "receipt_signing_failed",
                            "Receipt generation failed",
                        )),
                    ));
                }
            }
        }
    }

    // Build response — include receipt_id in verification_id field for DB-backed mode
    let response_id = receipt_id
        .map(|rid| format!("{}/{}", verification_id, rid))
        .unwrap_or(verification_id);

    Ok(Json(VerifyResponse {
        verification_id: response_id,
        result: report,
        receipt,
    }))
}

/// POST /v1/devices — register a device for an organization.
#[cfg(feature = "postgres")]
pub async fn register_device_handler(
    State(state): State<AppState>,
    axum::extract::Extension(org_ctx): axum::extract::Extension<crate::http::auth::OrgContext>,
    Json(req): Json<DeviceRequest>,
) -> Result<Json<DeviceResponse>, StatusCode> {
    let device_uuid = crate::database::create_device(
        &state.db_pool,
        org_ctx.org_id,
        &req.device_id,
        &req.device_pub,
        req.label.as_deref(),
    )
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(DeviceResponse {
        id: device_uuid,
        device_id: req.device_id,
        device_pub: req.device_pub,
        label: req.label,
        status: "active".to_string(),
    }))
}

/// Body of a revoke request (H1 Phase 2). Both fields optional: an empty body
/// revokes as of now with no epoch floor.
#[cfg(feature = "postgres")]
#[derive(Debug, Default, serde::Deserialize)]
pub struct RevokeRequest {
    /// RFC 3339 instant the key is considered revoked from (defaults to now).
    pub revoked_at: Option<String>,
    /// Reject archives whose `key_epoch` is below this.
    pub min_epoch: Option<u32>,
}

/// Response to a revoke request: the applied (post-monotonicity) state.
#[cfg(feature = "postgres")]
#[derive(Debug, serde::Serialize)]
pub struct RevokeResponse {
    pub id: uuid::Uuid,
    pub revoked_at: String,
    pub min_epoch: Option<u32>,
}

/// POST /v1/devices/:id/revoke — revoke a device's signing key (H1 Phase 2,
/// design §5). Org-scoped (bearer-authenticated); only the owning org may revoke
/// its device. **Monotonic-only** (PA4): `revoked_at` may be moved earlier but
/// never later or cleared, and `min_epoch` is non-decreasing — a violation is a
/// `409`, so an admin cannot launder a post-compromise forgery.
#[cfg(feature = "postgres")]
pub async fn revoke_device_handler(
    State(state): State<AppState>,
    axum::extract::Extension(org_ctx): axum::extract::Extension<crate::http::auth::OrgContext>,
    axum::extract::Path(id): axum::extract::Path<uuid::Uuid>,
    Json(req): Json<RevokeRequest>,
) -> Result<Json<RevokeResponse>, (StatusCode, String)> {
    // Tenant-scoped load: an org sees (and revokes) only its own device.
    let (_device_pub, current) =
        crate::database::get_device_revocation(&state.db_pool, org_ctx.org_id, id)
            .await
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "device lookup failed".to_string(),
                )
            })?
            .ok_or((
                StatusCode::NOT_FOUND,
                "no such device in this organization".to_string(),
            ))?;

    let now = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let (revoked_at, min_epoch) = match crate::revocation::decide_revoke(
        &current,
        req.revoked_at.as_deref(),
        req.min_epoch,
        &now,
    ) {
        crate::revocation::RevokeOutcome::Reject(msg) => {
            return Err((StatusCode::CONFLICT, msg));
        }
        crate::revocation::RevokeOutcome::Apply {
            revoked_at,
            min_epoch,
        } => (revoked_at, min_epoch),
    };

    let updated = crate::database::set_device_revocation(
        &state.db_pool,
        org_ctx.org_id,
        id,
        &revoked_at,
        min_epoch,
    )
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "revoke update failed".to_string(),
        )
    })?;
    if !updated {
        return Err((
            StatusCode::NOT_FOUND,
            "no such device in this organization".to_string(),
        ));
    }

    Ok(Json(RevokeResponse {
        id,
        revoked_at,
        min_epoch,
    }))
}

/// Witness response: the signed JWS witness receipt.
#[cfg(feature = "postgres")]
#[derive(serde::Serialize)]
pub struct WitnessResponse {
    pub jws: String,
}

/// POST /v1/witness — record a device-signed chronicle tip in the append-only
/// ledger and return a signed witness receipt with a trusted timestamp (H1c).
///
/// No org bearer auth: the device's own Ed25519 signature over the request is the
/// authorization. Registry binding is by public key (A2); monotonicity, forks,
/// and rollbacks are decided by `witness::decide` and backstopped by the ledger
/// primary key.
#[cfg(feature = "postgres")]
pub async fn witness_handler(
    State(state): State<AppState>,
    Json(req): Json<sealedge_core::WitnessRequest>,
) -> Result<Json<WitnessResponse>, (StatusCode, String)> {
    // 1. The device signature IS the authorization.
    if !req.verify() {
        return Err((
            StatusCode::UNAUTHORIZED,
            "invalid witness request signature".to_string(),
        ));
    }

    // 2. Registry binding + revocation state by public key (A2). An unregistered
    // key is honest-public-witnessed and is never considered revoked.
    let (device_registered, revocation) =
        match crate::database::get_device_revocation_by_pub(&state.db_pool, &req.device_pub)
            .await
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "registry lookup failed".to_string(),
                )
            })? {
            Some((_, state)) => (true, state),
            None => (false, crate::revocation::RevocationState::default()),
        };

    // PA2: has this key been rotated away (superseded), and at what sequence?
    let superseded_seq = crate::database::lineage_rotation_seq(&state.db_pool, &req.device_pub)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "lineage lookup failed".to_string(),
            )
        })?;

    // 3. Load the device's ledger and decide (pure, unit-tested logic).
    let existing = crate::database::witness_entries(&state.db_pool, &req.device_pub)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "witness ledger read failed".to_string(),
            )
        })?;

    let decision = crate::witness::decide(&existing, req.sequence, &req.tip);

    // PA5: a revoked device is refused a NEW witness (already-witnessed entries
    // still replay below). The gate is on device state, not tip time.
    if crate::revocation::refuse_revoked_witness(
        crate::revocation::is_revoked(&revocation),
        &decision,
    ) {
        return Err((
            StatusCode::FORBIDDEN,
            "device key is revoked; new chronicle tips are refused".to_string(),
        ));
    }

    // PA2: the superseded old key's ledger is closed beyond the rotation point —
    // a stolen old key cannot fork a second platform-co-signed timeline.
    if crate::revocation::refuse_superseded(superseded_seq, req.sequence, &decision) {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "superseded: this key rotated away at sequence {}; new tips beyond it are refused",
                superseded_seq.unwrap_or_default()
            ),
        ));
    }

    let observed_now = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let (observed_at, prev) = match decision {
        crate::witness::WitnessDecision::Fork { existing_tip } => {
            return Err((
                StatusCode::CONFLICT,
                format!(
                    "fork: sequence {} already witnessed with a different tip ({existing_tip})",
                    req.sequence
                ),
            ));
        }
        crate::witness::WitnessDecision::Rollback { max_sequence } => {
            return Err((
                StatusCode::CONFLICT,
                format!(
                    "rollback: sequence {} is at or below the last witnessed sequence {max_sequence}",
                    req.sequence
                ),
            ));
        }
        // Idempotent replay: re-issue bearing the ORIGINAL trusted timestamp.
        crate::witness::WitnessDecision::Replay { existing, prev } => (existing.observed_at, prev),
        crate::witness::WitnessDecision::Record { prev } => {
            crate::database::witness_insert(
                &state.db_pool,
                &req.device_pub,
                req.sequence,
                &req.tip,
                &observed_now,
                device_registered,
                &req.signed_at,
            )
            .await
            .map_err(|e| {
                // A concurrent request may have taken this (device_pub, sequence)
                // first — the primary key rejects it as a fork.
                (
                    StatusCode::CONFLICT,
                    format!("witness ledger insert conflict: {e}"),
                )
            })?;
            (observed_now, prev)
        }
    };

    // PA1: if this witnesses a rotation tip, verify the rotation entry's
    // co-signatures + binding, then record device lineage (old -> new). The
    // insert is idempotent, so a replayed rotation witness is harmless.
    if let Some(rec) = req.rotation.as_ref() {
        match crate::revocation::verify_lineage_rotation(
            rec,
            &req.device_pub,
            req.sequence,
            &req.tip,
        ) {
            crate::revocation::LineageCheck::Reject(msg) => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("rotation lineage rejected: {msg}"),
                ));
            }
            crate::revocation::LineageCheck::Ok {
                old_pub,
                rotation_seq,
            } => {
                // (iv) defense-in-depth: if the old key witnessed its predecessor,
                // that entry's tip must match the rotation's prev_archive_hash.
                // Best-effort — witnessing is optional, so a missing predecessor
                // entry does not block lineage (the i-iii crypto checks stand).
                if rotation_seq > 0 {
                    if let Some(prev_entry) = crate::database::witness_entry_at(
                        &state.db_pool,
                        &old_pub,
                        rotation_seq - 1,
                    )
                    .await
                    .map_err(|_| {
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "lineage predecessor lookup failed".to_string(),
                        )
                    })? {
                        if prev_entry.tip != rec.prev_archive_hash {
                            return Err((
                                StatusCode::CONFLICT,
                                "rotation prev_archive_hash does not match the old key's witnessed chain".to_string(),
                            ));
                        }
                    }
                }
                crate::database::lineage_insert(
                    &state.db_pool,
                    &req.device_pub,
                    &old_pub,
                    rotation_seq,
                    &observed_at,
                )
                .await
                .map_err(|_| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "lineage insert failed".to_string(),
                    )
                })?;
            }
        }
    }

    let receipt = crate::witness::WitnessReceipt::build(
        &req.device_pub,
        device_registered,
        req.sequence,
        &req.tip,
        observed_at,
        prev.as_ref(),
        uuid::Uuid::new_v4().to_string(),
    );

    let keys = state.keys.read().await;
    let jws = crate::verify::signing::sign_witness_jws(&receipt, &keys).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to sign witness receipt: {e}"),
        )
    })?;

    Ok(Json(WitnessResponse { jws }))
}

/// POST /v1/witness without the `postgres` feature: refuse loudly rather than
/// issue a RAM-backed receipt implying durable, monotonic history (A5).
#[cfg(not(feature = "postgres"))]
pub async fn witness_unavailable_handler() -> StatusCode {
    StatusCode::SERVICE_UNAVAILABLE
}

/// GET /v1/receipts/:id — retrieve a verification receipt by ID.
#[cfg(feature = "postgres")]
pub async fn get_receipt_handler(
    State(state): State<AppState>,
    axum::extract::Extension(org_ctx): axum::extract::Extension<crate::http::auth::OrgContext>,
    axum::extract::Path(receipt_id): axum::extract::Path<uuid::Uuid>,
) -> Result<Json<ReceiptResponse>, StatusCode> {
    let (jws, kid) = crate::database::get_receipt(&state.db_pool, org_ctx.org_id, receipt_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let claims = parse_jws_claims(&jws).unwrap_or(Value::Null);

    Ok(Json(ReceiptResponse {
        id: receipt_id,
        jws,
        kid,
        claims,
    }))
}

// ---------------------------------------------------------------------------
// Request/response types (postgres-gated — DB-specific ops)
// ---------------------------------------------------------------------------

#[cfg(feature = "postgres")]
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct DeviceRequest {
    pub device_id: String,
    pub device_pub: String,
    pub label: Option<String>,
}

#[cfg(feature = "postgres")]
#[derive(Debug, serde::Serialize)]
pub struct DeviceResponse {
    pub id: uuid::Uuid,
    pub device_id: String,
    pub device_pub: String,
    pub label: Option<String>,
    pub status: String,
}

#[cfg(feature = "postgres")]
#[derive(Debug, serde::Serialize)]
pub struct ReceiptResponse {
    pub id: uuid::Uuid,
    pub jws: String,
    pub kid: String,
    pub claims: Value,
}

// ---------------------------------------------------------------------------
// Test utilities
// ---------------------------------------------------------------------------

#[cfg(all(any(test, feature = "test-utils"), feature = "postgres"))]
pub fn create_test_app(pool: sqlx::PgPool) -> axum::Router {
    let keys = std::sync::Arc::new(tokio::sync::RwLock::new(
        crate::verify::jwks::KeyManager::new().expect("KeyManager should initialize for test"),
    ));

    let state = AppState {
        db_pool: pool,
        keys,
        receipt_ttl_secs: 3600,
    };

    // Delegate to create_router so middleware stack is identical to production
    // (build_base_router -> create_router chain applies CORS, TraceLayer, auth).
    crate::http::create_router(state)
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Compute BLAKE3 manifest digest (for receipt construction).
pub(crate) fn compute_manifest_digest_blake3(manifest: &Value) -> String {
    let canonical = serde_json::to_string(manifest).unwrap_or_default();
    let hash = sealedge_core::chain::segment_hash(canonical.as_bytes());
    format!("b3:{}", BASE64.encode(hash))
}

/// Compute SHA-256 manifest digest (for DB storage — compatible with platform-api schema).
#[cfg(feature = "postgres")]
fn compute_manifest_digest_sha256(manifest: &Value) -> String {
    use sha2::{Digest, Sha256};
    let canonical = serde_json::to_string(manifest).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Parse JWS claims payload from a JWT string.
#[cfg(feature = "postgres")]
fn parse_jws_claims(jws: &str) -> Option<Value> {
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        return None;
    }

    let payload = parts[1];
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    serde_json::from_slice(&decoded).ok()
}
