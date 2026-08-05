//
// Copyright (c) 2025 TRUSTEDGE LABS LLC
// This source code is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Project: sealedge — Privacy and trust at the edge.
//

//! Axum router composition for the Sealedge Platform HTTP layer.
//!
//! Routes:
//!   POST  /v1/verify              — verify archive (always available)
//!   POST  /v1/verify-attestation  — verify point attestation (always available)
//!   POST  /v1/devices             — register device (postgres only)
//!   GET   /v1/receipts/:id        — get receipt (postgres only)
//!   GET   /.well-known/jwks.json  — local JWKS (no proxy)
//!   GET   /healthz                — health check
//!   GET   /verify                 — self-contained attestation verifier HTML page

use axum::{
    routing::{get, post},
    Router,
};
use tower_http::{cors::CorsLayer, limit::RequestBodyLimitLayer, trace::TraceLayer};

use super::{
    handlers::{health_handler, jwks_handler, verify_attestation_handler, verify_handler},
    rate_limit::{rate_limit_middleware, RateLimitState},
    state::AppState,
    static_files::verify_page_handler,
};

/// Build the base router with routes shared across all feature configurations.
///
/// The `/v1/verify` route is NOT included here — it is added in `create_router`
/// with rate limiting applied. All other routes (healthz, jwks) are public and
/// unthrottled.
///
/// Both `create_router` and `create_test_app` ultimately call this function,
/// ensuring a single source of truth for the route set (TST-02 parity).
pub fn build_base_router() -> Router<AppState> {
    let router = Router::new()
        .route("/.well-known/jwks.json", get(jwks_handler))
        .route("/healthz", get(health_handler))
        .route("/verify", get(verify_page_handler));

    // /v1/witness (H1c): public (the device signature is the auth). Requires a
    // durable ledger — with postgres it records + issues a receipt; without it
    // the endpoint refuses loudly with 503 (A5) rather than fake durability.
    #[cfg(feature = "postgres")]
    let router = router.route("/v1/witness", post(super::handlers::witness_handler));
    #[cfg(not(feature = "postgres"))]
    let router = router.route(
        "/v1/witness",
        post(super::handlers::witness_unavailable_handler),
    );

    router
}

/// Compose the full Axum router for the Sealedge Platform service.
///
/// Applies:
/// - `RequestBodyLimitLayer` (2 MB) on all routes to prevent body-flood DoS.
/// - Per-IP rate limiting on `/v1/verify` only (configurable via `RATE_LIMIT_RPS`,
///   default 10 req/sec) to protect the CPU-intensive verify endpoint.
///
/// When the `postgres` feature is enabled, the router includes device and
/// receipt endpoints protected by the Bearer token auth middleware.
pub fn create_router(state: AppState) -> Router {
    // Read rate limit RPS from environment, default to 10.
    let rps = std::env::var("RATE_LIMIT_RPS")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(10);
    let trusted_proxies: Vec<ipnet::IpNet> = std::env::var("TRUSTED_PROXIES")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse::<ipnet::IpNet>().ok())
        .collect();
    let rl_state = RateLimitState::new(rps, trusted_proxies);

    // Rate-limited verify sub-router — /v1/verify and /v1/verify-attestation are throttled.
    let verify_router = Router::new()
        .route("/v1/verify", post(verify_handler))
        .route("/v1/verify-attestation", post(verify_attestation_handler))
        .route_layer(axum::middleware::from_fn_with_state(
            rl_state,
            rate_limit_middleware,
        ));

    let base = build_base_router().merge(verify_router);

    #[cfg(feature = "postgres")]
    let base = {
        use super::auth::auth_middleware;
        use super::handlers::{get_receipt_handler, register_device_handler};
        use axum::middleware;

        // Read CORS allowed origins from CORS_ORIGINS env var (comma-separated).
        // Falls back to localhost:3000,localhost:8080 when not set (dev default).
        let cors_origins_raw = std::env::var("CORS_ORIGINS")
            .unwrap_or_else(|_| "http://localhost:3000,http://localhost:8080".to_string());

        let allowed_origins: Vec<axum::http::HeaderValue> = cors_origins_raw
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .filter_map(|s| {
                s.parse::<axum::http::HeaderValue>()
                    .map_err(|_| {
                        tracing::warn!("CORS_ORIGINS: skipping invalid entry {:?}", s);
                    })
                    .ok()
            })
            .collect();

        tracing::info!("CORS allowed origins: {:?}", allowed_origins);

        let cors = CorsLayer::new()
            .allow_origin(tower_http::cors::AllowOrigin::list(allowed_origins))
            .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
            .allow_headers([
                axum::http::header::CONTENT_TYPE,
                axum::http::header::AUTHORIZATION,
                axum::http::header::ACCEPT,
            ]);

        // Auth-protected routes (devices, receipts)
        let protected = Router::new()
            .route("/v1/devices", post(register_device_handler))
            .route("/v1/receipts/:id", get(get_receipt_handler))
            .layer(middleware::from_fn_with_state(
                state.db_pool.clone(),
                auth_middleware,
            ));

        // Merge: base routes (healthz, verify, jwks) are public, protected routes need auth
        base.merge(protected)
            .with_state(state)
            .layer(RequestBodyLimitLayer::new(2 * 1024 * 1024))
            .layer(cors)
            .layer(TraceLayer::new_for_http())
    };

    #[cfg(not(feature = "postgres"))]
    let base = base
        .with_state(state)
        .layer(RequestBodyLimitLayer::new(2 * 1024 * 1024))
        // Same-origin only — no cross-origin requests allowed for verify-only builds
        .layer(CorsLayer::new())
        .layer(TraceLayer::new_for_http());

    base
}
