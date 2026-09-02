<!--
Copyright (c) 2025 TRUSTEDGE LABS LLC
MPL-2.0: https://mozilla.org/MPL/2.0/
Project: sealedge — Privacy and trust at the edge.
GitHub: https://github.com/TrustEdge-Labs/sealedge
-->


# TrustEdge Platform — Post-Hardening Security Review

**Date:** 2026-03-24  
**Scope:** Platform crate, platform-server crate, deploy stack  
**Context:** Review after Phase 55 (HTTP hardening) and Phase 58 (platform fixes)

---

## 1. Status of Previously Identified Issues

### 1.1 Body size limit on `/v1/verify` — **FIXED** ✔

- `RequestBodyLimitLayer::new(2 * 1024 * 1024)` (2 MB) applied globally in `router.rs` for both `postgres` and non-postgres builds.
- Integration test `test_body_limit_413` confirms >2 MB payloads return HTTP 413.
- Integration test `test_body_under_limit_not_413` confirms normal payloads are not rejected.

### 1.2 Rate limiting added — **FIXED** ✔

- New `rate_limit.rs` module implements per-IP rate limiting using `governor` crate.
- Applied via `route_layer` only to `/v1/verify` (CPU-intensive endpoint).
- Configurable via `RATE_LIMIT_RPS` env var (default: 10 req/sec).
- `/healthz` and JWKS endpoints are correctly excluded from rate limiting.
- Integration tests `test_rate_limit_429` and `test_healthz_not_rate_limited` verify behavior.

### 1.3 `/v1/verify` fixed in postgres mode (Extension crash) — **FIXED** ✔

- In `handlers.rs` (postgres handler), `org_ctx` is now extracted as `Option<Extension<OrgContext>>` instead of a required `Extension<OrgContext>`.
- When `org_ctx.is_none()`, the handler operates in "tenant-agnostic mode" (debug log).
- DB writes use `Uuid::nil()` as `org_id` when no auth context is present.
- This prevents the crash that occurred when unauthenticated requests hit `/v1/verify` in postgres mode.

### 1.4 JWKS signing key path configurable / not plaintext in `target/dev/` — **FIXED** ✔

- `jwks.rs` `KeyManager::new()` reads `JWKS_KEY_PATH` env var; defaults to `std::env::temp_dir()` (e.g., `/tmp/trustedge_signing_key.json`), **not** `target/dev/`.
- On Unix, key file permissions are set to `0o600` (owner-only read/write).
- Integration tests verify: `test_jwks_default_not_target_dev`, `test_signing_key_permissions`, `test_jwks_colocated_with_signing_key`.
- `platform-server/main.rs` logs the resolved JWKS key path at startup.

### 1.5 CORS origins configurable via env var — **FIXED** ✔

- In `router.rs` (postgres build), `CORS_ORIGINS` env var is read (comma-separated).
- Falls back to `http://localhost:3000,http://localhost:8080` for dev.
- Invalid entries are logged and skipped.
- In non-postgres builds, `CorsLayer::new()` denies all cross-origin requests (secure default).
- Integration test `test_cors_preflight_parity` confirms CORS behavior consistency.

### 1.6 TLS configured in deploy stack — **FIXED** ✔

- New `nginx-ssl.conf.template` provides TLS 1.2/1.3 termination with strong ciphers (`HIGH:!aNULL:!MD5`).
- New `docker-entrypoint.sh` conditionally activates the TLS server block when `SSL_CERT_PATH` and `SSL_KEY_PATH` are set.
- `docker-compose.yml` exposes port 8443 for HTTPS and documents cert volume mount.
- `.env.example` documents TLS configuration variables.

### 1.7 `DATABASE_URL` required in production (no default fallback) — **NOT FIXED** ⚠

- `config.rs` still has a hardcoded fallback: `"postgres://postgres:password@localhost:5432/trustedge"`.
- In production, if `DATABASE_URL` is not set, the server will silently connect to this default URL with the password `password`. This is a security risk — the server should fail to start if `DATABASE_URL` is not explicitly set.
- **Severity:** Medium. The docker-compose.yml does set `DATABASE_URL`, so the Docker deployment is safe. But a bare-metal deployment without the env var would use the insecure default.

### 1.8 PostgreSQL port exposed to host — **NOT FIXED** ⚠

- `docker-compose.yml` still has `ports: - "5432:5432"` on the postgres service, exposing it directly to the host network.
- For production, the database should only be accessible from the internal Docker network (no `ports` mapping, or bind to `127.0.0.1:5432:5432`).
- **Severity:** Medium. Acceptable for dev/demo, risky for production.

### 1.9 Dashboard nginx runs as non-root — **NOT FIXED** ⚠

- `Dockerfile.dashboard` uses `nginx:alpine` as the runtime base, which runs as root by default.
- There is no `USER` directive in the dashboard Dockerfile's runtime stage.
- The platform server Dockerfile correctly creates and switches to a non-root `trustedge` user.
- **Severity:** Low-Medium. nginx:alpine typically drops privileges for worker processes, but the master process runs as root.

### 1.10 Input length validation added — **FIXED** ✔

- `validation.rs` `validate_verify_request_full()` checks:
  - Empty segments array
  - Empty `device_pub`
  - Null/empty manifest
  - Hash format regex (`^b3:[0-9a-f]{64}$`)
- Both `validate_verify_request` (backward compat) and `validate_verify_request_full` (new, used by handlers) exist.
- Comprehensive unit tests cover all validation paths including ordering guarantees.

### 1.11 Error messages now generic (no crypto internals) — **PARTIALLY FIXED** ⚠

- Validation errors use generic error codes (`invalid_segments`, `invalid_device_pub`, `invalid_manifest`).
- **However:** In `handlers.rs`, the verification failure error still includes the raw error message:
  ```rust
  &format!("Cryptographic verification failed: {}", e)
  ```
  And the receipt signing failure:
  ```rust
  &format!("Failed to sign receipt: {}", e)
  ```
  These could leak internal cryptographic details (e.g., key parsing errors, algorithm mismatches) to external callers.
- **Severity:** Low-Medium. The error messages may expose internal library error text to API consumers.

### 1.12 Regex compiled per-request — **NOT FIXED** ⚠

- In `validation.rs` `validate_segment_hashes()`:
  ```rust
  let hash_regex = Regex::new(r"^b3:[0-9a-f]{64}$").unwrap();
  ```
  This compiles the regex on every call to `validate_segment_hashes`, which is invoked once per verify request.
- Should use `lazy_static!`, `once_cell::sync::Lazy`, or `std::sync::LazyLock` to compile once.
- **Severity:** Low. Performance issue, not a security vulnerability. The regex is simple so compilation is fast, but it's wasteful under load.

### 1.13 JWS receipt TTL configurable — **NOT FIXED** ⚠

- In `signing.rs`:
  ```rust
  let exp = now + 3600; // 1 hour expiration
  ```
  The 1-hour TTL is hardcoded. There is no env var or configuration option to change it.
- **Severity:** Low. The current default is reasonable, but operators should be able to tune it.

### 1.14 CA default JWT secret still placeholder — **NOT FIXED** ⚠

- In `ca/mod.rs` `CAConfig::default()`:
  ```rust
  jwt_secret: Secret::new("your-secret-key".to_string()),
  ```
  The default secret is still the placeholder `"your-secret-key"`.
- **Mitigating factor:** The CA module is library-only (not wired into HTTP routes) and the builder pattern allows overriding. The Debug impl correctly redacts the secret. But if anyone uses `CAConfig::default()` without setting a real secret, they get a known-insecure value.
- **Severity:** Medium. The CA module is not exposed via HTTP yet, but the dangerous default persists.

### 1.15 Healthz exposes version — **NOT FIXED** ⚠

- In `handlers.rs`:
  ```rust
  version: env!("CARGO_PKG_VERSION").to_string(),
  ```
  The `/healthz` endpoint returns the exact crate version. This is information disclosure that helps attackers fingerprint the deployment.
- **Severity:** Low. Common practice in many services, but best practice is to omit or redact version info in production.

---

## 2. New Issues Introduced by Hardening Changes

### 2.1 `unsafe` in integration tests for env var manipulation — **LOW** ⚠

- `verify_integration.rs` uses `unsafe { std::env::set_var(...) }` and `unsafe { std::env::remove_var(...) }` in tests.
- These are unsafe because setting env vars is not thread-safe in Rust. Since tests may run in parallel, this could cause flaky test failures or undefined behavior.
- **Impact:** Test-only, no production risk. But should be documented or tests should use a test mutex.

### 2.2 Rate limiter fallback IP in test environments — **LOW**

- `rate_limit.rs` falls back to `127.0.0.1` when `ConnectInfo` is not available (e.g., tests or reverse proxy scenarios).
- If the platform is deployed behind a reverse proxy that doesn't pass `ConnectInfo`, ALL clients would be rate-limited as a single IP bucket. This effectively creates a global rate limit rather than per-client.
- **Mitigation needed:** Document that the server must be deployed with `into_make_service_with_connect_info::<SocketAddr>()` (which `main.rs` already does). Consider also reading `X-Forwarded-For` or `X-Real-IP` headers when behind a proxy.

### 2.3 No input length limits on string fields — **LOW**

- While manifest, segments, and device_pub are validated for format, there is no maximum length check on:
  - `device_pub` string (only checked for non-empty)
  - `manifest` JSON value (only checked for non-null/non-empty-object; could be arbitrarily deep)
  - `options.device_id` string
- The 2 MB body limit provides an implicit cap, but a single 2 MB `device_pub` string or deeply nested manifest could still waste processing time.
- **Severity:** Low. The body limit provides reasonable protection.

### 2.4 `Uuid::nil()` used as org_id for unauthenticated verify requests — **LOW-MEDIUM**

- In the postgres handler, when `org_ctx` is `None`, the code uses `Uuid::nil()` (all zeros) as the org_id for DB writes.
- If multiple unauthenticated requests are made, they all share `org_id = 00000000-0000-0000-0000-000000000000`.
- This means an unauthenticated user could query receipts for this nil org_id if they know a receipt UUID.
- **Mitigation:** The receipt endpoint (`/v1/receipts/:id`) requires auth middleware, so unauthenticated users can't retrieve receipts. This is adequately protected.

---

## 3. Rate Limit Implementation Review (`rate_limit.rs`)

### Soundness Assessment: **GOOD** ✔

- Uses `governor` crate's `DefaultKeyedRateLimiter<IpAddr>` — well-tested, production-ready.
- Quota is set via `Quota::per_second(NonZeroU32::new(rps))` — correct usage.
- `check_key()` returns `Err` for exceeded limits → maps to `StatusCode::TOO_MANY_REQUESTS` (429).
- Wrapped in `Arc` for safe concurrent sharing.
- Applied via `route_layer` only to the verify router sub-tree — does not affect healthz/jwks.
- Fallback to localhost IP when `ConnectInfo` is absent is reasonable for test ergonomics.

### Potential Improvements:
- No `Retry-After` header is sent on 429 responses. RFC 6585 recommends it.
- No burst capacity configuration separate from RPS (governor defaults burst = rps, which is reasonable).
- Memory growth: `DashMap` entries for IPs are never evicted. Under sustained attack from many unique IPs, memory could grow. Governor does handle expiry of rate-limit state internally via GCRA, but the DashMap keys persist.

---

## 4. Integration Test Assessment

### Coverage: **STRONG** ✔

The `verify_integration.rs` file adds ~500 lines of comprehensive tests:

| Test | Coverage |
|------|----------|
| `test_health_endpoint` | Healthz returns 200 with expected fields |
| `test_jwks_endpoint` | JWKS returns valid Ed25519 key structure |
| `test_cors_preflight_parity` | CORS consistency across router instances (TST-02) |
| `test_verify_round_trip` | Full sign→verify→receipt flow (TST-03) |
| `test_verify_receipt_matches_jwks` | JWS receipt signature verified against JWKS public key |
| `test_verify_wrong_key_returns_failed_signature` | Wrong key → signature fail, no receipt |
| `sec_11_duplicate_submission_distinct_receipts` | Replay resistance — unique verification IDs |
| `sec_12_receipt_digest_bound_to_content` | Different content → different digests |
| `sec_12_same_content_same_digest` | Same content → same digest (deterministic) |
| `test_body_limit_413` | 2 MB limit enforced |
| `test_body_under_limit_not_413` | Normal payload not rejected |
| `test_rate_limit_429` | Rate limiting works |
| `test_healthz_not_rate_limited` | Healthz exempt from rate limit |
| Pure crypto tests (5) | Happy path, tampered, wrong key, empty, key manager |
| JWKS path tests (4) | Custom path, default not target/dev, permissions, colocation |

**Strengths:**
- Security-focused tests (SEC-11 replay, SEC-12 content binding)
- End-to-end JWS verification against JWKS endpoint
- Both positive and negative test cases
- Body limit and rate limit tests

**Gaps:**
- No test for malformed JSON body (fuzzing)
- No test for extremely long `device_pub` or deeply nested manifest
- No test for `POST /v1/verify` with missing `Content-Type` header
- No postgres-mode integration test (all HTTP tests are `#[cfg(not(feature = "postgres"))]`)

---

## 5. Remaining Gaps Summary

| # | Issue | Severity | Status |
|---|-------|----------|--------|
| 1 | `DATABASE_URL` default fallback with `password` in config.rs | Medium | NOT FIXED |
| 2 | PostgreSQL port exposed to host in docker-compose | Medium | NOT FIXED |
| 3 | Dashboard nginx runs as root | Low-Medium | NOT FIXED |
| 4 | Error messages may leak crypto internals | Low-Medium | PARTIALLY FIXED |
| 5 | Regex compiled per-request in validation | Low | NOT FIXED |
| 6 | JWS receipt TTL hardcoded at 1 hour | Low | NOT FIXED |
| 7 | CA default JWT secret is placeholder | Medium | NOT FIXED |
| 8 | Healthz exposes exact version | Low | NOT FIXED |
| 9 | No `X-Forwarded-For` support for rate limiting behind proxy | Low | NEW |
| 10 | No `Retry-After` header on 429 responses | Low | NEW |

---

## 6. Overall Assessment

**The hardening changes (phases 55 and 58) are substantial and well-executed.** The critical issues — body size limits, rate limiting, JWKS key path security, CORS configuration, and the postgres-mode crash — have all been properly addressed with both code changes and integration tests.

The remaining gaps are primarily configuration hardening (DATABASE_URL default, postgres port, nginx user) and minor improvements (regex caching, TTL config, error message sanitization). None of them represent critical vulnerabilities in the current state.

The new integration test suite is thorough and covers important security properties (replay resistance, content binding, JWS verification). The rate limiter implementation using `governor` is sound and well-integrated.
