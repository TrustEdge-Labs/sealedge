<!--
Copyright (c) 2025 TRUSTEDGE LABS LLC
MPL-2.0: https://mozilla.org/MPL/2.0/
Project: sealedge — Privacy and trust at the edge.
GitHub: https://github.com/TrustEdge-Labs/sealedge
-->


# Sealedge Threat Model

**Version**: 2.2
**Date**: 2026-03-20
**Replaces**: August 2025 draft (obsolete — described a different system)

> For vulnerability reporting and security policies, see [`SECURITY.md`](../../SECURITY.md)

---

## System Overview

Sealedge is a cryptographic provenance system for edge device data. It proves that data — captured at an edge device — has not been tampered with from capture through to verification, using BLAKE3 continuity chains, Ed25519/ECDSA P-256 signatures, and verifiable receipts. The system provides encryption, attestation, and tamper-evidence for any data type (video, audio, sensor, logs). Device keys are passphrase-protected at rest; hardware-backed keys via YubiKey PIV are also supported.

---

## Architecture

```
[Edge Device / CLI (seal)]
    |-- keygen: SEALEDGE-KEY-V2 (PBKDF2-HMAC-SHA256 600k + AES-256-GCM, passphrase-protected)
    |-- wrap: chunk data -> XChaCha20-Poly1305 + BLAKE3 chain -> Ed25519/ECDSA P-256 sign
    |-- unwrap: verify signature + BLAKE3 chain -> HKDF key derivation -> decrypt chunks
         |
         v
[.seal Archive] ─── HTTP POST /v1/verify ───> [Platform Server (Axum)]
                                                     |-- JWT bearer auth (Secret<T>, ZeroizeOnDrop)
                                                     |-- BLAKE3 + Ed25519/ECDSA P-256 verify
                                                     |-- PostgreSQL (receipts, devices, orgs)
                                                     |-- JWKS endpoint
                                                     |-- CORS restricted (same-origin or header-limited)
                                                     v
                                              [Cryptographic Receipt (JWS)]
                                                     |
                                              [Dashboard (SvelteKit + nginx)]
                                              [Browser WASM (seal-wasm)]

[Network Transport (optional)]
    |-- TCP with framing (sealedge-core transport)
    |-- QUIC with TLS (webpki-roots trust store, secure-by-default)
         insecure-tls feature: compile-time blocked in release builds (build.rs guard)
```

### Docker Compose Stack

```
platform-server (Rust, Axum HTTP) <-> postgres (internal network, no external port)
                                  <-> dashboard (nginx static, port 3000)
```

---

## Assets Under Protection

| Asset | Protection Mechanism |
|-------|---------------------|
| Archive content (plaintext data) | XChaCha20-Poly1305 per-chunk encryption at rest and in transit |
| Device private keys | SEALEDGE-KEY-V2 (Ed25519 signing + independent X25519 key-agreement bundle): PBKDF2-HMAC-SHA256 (600k iterations, 32-byte salt) + AES-256-GCM |
| Verification receipts | JWS-signed by platform server |
| Platform JWT secret | Secret<T> wrapper with ZeroizeOnDrop; never serialized or logged |
| PostgreSQL credentials | Secret<T> wrapper with ZeroizeOnDrop |
| YubiKey PIV PIN | Secret<T> wrapper; prompted at runtime via rpassword; never stored |

---

## Cryptographic Primitives

| Primitive | Algorithm | Where Used | Notes |
|-----------|-----------|-----------|-------|
| Signing (software) | Ed25519 | Archive manifest signing, mutual auth | `ed25519-dalek`; "ed25519:BASE64" wire prefix |
| Signing (hardware) | ECDSA P-256 | YubiKey PIV slot 9c, YubiKey-generated X.509 certs | `yubikey` crate; "ecdsa-p256:BASE64" wire prefix |
| Symmetric encryption | AES-256-GCM | Per-chunk envelope encryption; SEALEDGE-KEY-V2 key-at-rest | Authenticated encryption with 128-bit tags |
| Symmetric encryption | XChaCha20-Poly1305 | .seal chunk encryption (crypto.rs) | Extended nonce variant, resistant to nonce misuse |
| Key derivation (envelope) | HKDF-SHA256 (RFC 5869) | v2 envelope key derivation | Single Extract+Expand, 40-byte OKM (32-byte AES key + 8-byte nonce prefix); info = "SEALEDGE_ENVELOPE_V1" |
| Key derivation (at rest) | PBKDF2-HMAC-SHA256 | SEALEDGE-KEY-V2 key-at-rest; Keyring backend | 600,000 iterations (OWASP 2023); 32-byte salt; min 300,000 enforced |
| Session key derivation | X25519 ECDH | Mutual-auth network transport session keys | BLAKE3 domain-separated KDF post-ECDH |
| Hash / chain | BLAKE3 | Continuity chain (genesis seed: blake3("sealedge:genesis")), segment linking, receipt binding | Non-cryptographic-signing usage; collision resistance only |
| Hybrid encryption | RSA-OAEP-SHA256 | Asymmetric encryption in hybrid.rs | Oaep::new::<sha2::Sha256>(); PKCS#1 v1.5 eliminated in v2.2 |

---

## Threat Categories

### T1: Data Tampering in Transit

**Description**: An adversary intercepts and modifies archive data or verification responses during network transmission.

**Attack Vectors**: Active network position (MITM), packet injection, TLS stripping.

**Status**: MITIGATED

**Mitigations**:
- AES-GCM authentication tags on each chunk — any modification is detected before decryption
- Ed25519 or ECDSA P-256 signature over the canonical manifest.json — signature verification is the first step in `seal verify` and `/v1/verify`
- BLAKE3 continuity chain — any missing, reordered, or substituted chunk breaks the chain from genesis seed
- `seal unwrap` enforces verify-then-decrypt: signature and chain must pass before any chunk is decrypted

---

### T2: Data Tampering at Rest

**Description**: An adversary modifies a .seal archive after it has been written to disk or object storage.

**Attack Vectors**: Direct filesystem access, storage layer manipulation, corrupt-and-replace.

**Status**: MITIGATED

**Mitigations**:
- .seal archives are tamper-evident read-only bundles: manifest.json + detached signature + encrypted chunks
- Ed25519/ECDSA P-256 signature over manifest.json; any manifest change invalidates the signature
- BLAKE3 continuity chain links all chunks back to the genesis seed — any chunk substitution or addition breaks the chain
- Chunk filenames are zero-padded indices; gaps or reordering are detected during verification

---

### T3: Key Compromise (Private Key at Rest)

**Description**: An adversary obtains a device's private signing key from disk storage.

**Attack Vectors**: Filesystem access, disk theft, memory dumps, backup exfiltration.

**Status**: MITIGATED (v2.2)

**Mitigations**:
- SEALEDGE-KEY-V2 bundle (C4): the Ed25519 signing key and the independent X25519 key-agreement key are encrypted together with AES-256-GCM; encryption key derived via PBKDF2-HMAC-SHA256 (600,000 iterations, 32-byte salt per OWASP 2023)
- **Key separation (C4)**: the signing key is used only for signatures. Compromise of the signing key permits forgery of new archives but does NOT expose the confidentiality of past content (content keys are never derived from it). See T13.
- Passphrase prompted at runtime via `rpassword` — never stored on disk or in environment variables
- `--unencrypted` flag available as explicit opt-in for CI/automation environments; requires conscious operator choice
- Hardware option: YubiKey PIV slot 9c — private key is generated on hardware and never extractable; software only holds the public certificate
- **Platform signing key (M2)**: the server's Ed25519 key — which signs JWKS verification receipts AND witness/timestamp receipts (the revocation root, see T14/T15) — is encrypted at rest with the same PBKDF2(600k)+AES-256-GCM scheme via `JWKS_KEY_PASSPHRASE`. In release builds the passphrase and an explicit `JWKS_KEY_PATH` are **required** (no `/tmp` default, no plaintext); the file is written atomically at `0600` (no write-then-chmod race) and transient key material is zeroized. Residual: the passphrase lives in the server's environment/process memory (standard for a headless signing service) — a full host compromise still exposes it; a hardware/KMS backend would close that, tracked as future work.

---

### T4: RSA Padding Oracle / Timing Side-Channel (RUSTSEC-2023-0071)

**Description**: An adversary exploits PKCS#1 v1.5 decryption timing variations to recover RSA private keys via the Marvin Attack.

**Attack Vectors**: Adaptive chosen-ciphertext attack, statistical timing measurement of decryption responses.

**Status**: MITIGATED (v2.2)

**Mitigations**:
- PKCS#1 v1.5 (`Pkcs1v15Encrypt` trait) completely eliminated from codebase in v2.2
- All RSA operations now use OAEP with SHA-256 (`Oaep::new::<sha2::Sha256>()`) — not vulnerable to RUSTSEC-2023-0071
- RUSTSEC-2023-0071 removed from `.cargo/audit.toml` ignore list; `cargo-audit` now passes with zero suppressed advisories

See **RSA Vulnerability History** section for full timeline.

---

### T5: Weak Key Derivation

**Description**: An adversary performs offline brute-force or dictionary attacks against stored key material, or exploits incorrect use of a KDF for its input type.

**Attack Vectors**: Offline dictionary attack against SEALEDGE-KEY-V2 files, rainbow tables, GPU brute-force.

**Status**: MITIGATED

**Mitigations**:
- `PBKDF2_MIN_ITERATIONS = 300_000` constant in `universal.rs`; enforced at builder level (assert!) and backend level (error return) — belt-and-suspenders
- Default iteration count: 600,000 (OWASP 2023 PBKDF2-HMAC-SHA256 recommendation)
- Envelope key derivation uses HKDF-SHA256 (RFC 5869): correct KDF for high-entropy input (ECDH shared secret) per NIST SP 800-56C; PBKDF2 is not appropriate for high-entropy seeds

---

### T6: Legacy Envelope Format

**Description**: An adversary or implementation bug exploits the weaker v1 envelope format (PBKDF2 per-chunk KDF, random nonces) that was present through v1.8.

**Attack Vectors**: Downgrade attack, tooling that re-introduces v1 handling, nonce collision in high-volume usage.

**Status**: MITIGATED (v2.2)

**Mitigations**:
- v1 envelope format removed entirely in v2.2 — no code path produces or consumes v1 envelopes
- Codebase is v2-only: single HKDF derivation per envelope, deterministic counter nonces (nonce_prefix[8] || chunk_index[3] || last_flag[1] = 12-byte nonce), no per-chunk re-derivation
- HKDF domain separation: info parameter = "SEALEDGE_ENVELOPE_V1" binds the derived key to Sealedge context

---

### T7: Insecure Transport

**Description**: An adversary intercepts network communications using weak or absent TLS, or exploits a debug/testing bypass left enabled in production.

**Attack Vectors**: TLS downgrade, self-signed cert acceptance in production, `insecure-tls` feature left enabled.

**Status**: MITIGATED

**Mitigations**:
- QUIC transport uses `webpki-roots` trust store by default — consistent cross-platform certificate validation
- `insecure-tls` is a compile-time feature flag; `build.rs` includes a compile-time guard that prevents release builds from enabling `insecure-tls` (uses `cfg!(not(debug_assertions))` check — not a runtime config)
- Docker Compose stack: platform-server and postgres communicate over Docker internal network; postgres port is not exposed externally; dashboard served via nginx with TLS termination upstream

---

### T8: Replay Attacks on Verification

**Description**: An adversary captures a valid verification request or receipt and replays it to obtain an additional receipt for content it does not control.

**Attack Vectors**: Network capture and replay of `/v1/verify` HTTP requests, re-submission of previously verified archives.

**Status**: PARTIAL

**Mitigations (implemented)**:
- Cryptographic receipts are bound to specific archive content via BLAKE3 digest — a receipt for archive A cannot be claimed as a receipt for archive B
- Per-chunk deterministic counter nonces prevent chunk-level replay (each chunk's nonce is unique by construction)
- Mutual auth challenge-response uses BLAKE3 domain-separated KDF with time-limited sessions — replaying a session handshake outside the session window fails

**Planned**:
- Sliding-window nonce validation for high-volume `/v1/verify` endpoints
- Request-level idempotency tokens with server-side deduplication

---

### T9: Dashboard / API Authentication Bypass

**Description**: An adversary gains access to the platform API or dashboard without valid credentials, or exploits CORS misconfigurations to make cross-origin requests on behalf of authenticated users.

**Attack Vectors**: Missing auth middleware, JWT algorithm confusion, CORS wildcard, credential theft via XSS.

**Status**: MITIGATED

**Mitigations**:
- JWT bearer tokens required for all platform endpoints except `/healthz` (excluded for Docker health checks)
- JWT secret stored in `Secret<T>` with `ZeroizeOnDrop` — never serialized, never logged, zeroed on drop
- `LoginRequest` password wrapped in `Secret<T>` at JSON parse boundary via private raw struct — no exposure window
- CORS: `CorsLayer::new()` (same-origin only) for verify-only builds; restricted to `Content-Type`, `Authorization`, `Accept` headers for postgres builds
- CI Step 23: grep-based check prevents regression of `#[derive(Serialize)]` on secret-holding structs

---

### T10: Secret Material in Memory

**Description**: Sensitive values (private keys, passphrases, PINs, JWT secrets, database passwords) remain in memory after use, accessible via memory dumps, core files, or debug logging.

**Attack Vectors**: Process memory inspection, crash dumps, debug logging of config structs.

**Status**: MITIGATED

**Mitigations**:
- `Secret<T>` wrapper type (in-house, using `zeroize` crate): implements `ZeroizeOnDrop` on all secret-holding fields
- Covered fields: YubiKey PIV PIN, passphrase (key-at-rest), JWT secret, database password
- `Debug` impl on `Secret<T>` outputs `[REDACTED]` — prevents accidental logging
- No `Display`, `Deref`, or `Serialize` derives on `Secret<T>` — prevents inadvertent exposure
- CI Step 23 enforces no regression: any `Serialize` derive added to a struct holding a `Secret<T>` field fails CI
- Rust memory safety prevents use-after-free of secret material

---

### T11: Supply Chain (Dependency Vulnerabilities)

**Description**: A vulnerability in a transitive Rust dependency introduces a security flaw, or a malicious package is introduced into the build.

**Attack Vectors**: Compromised crate on crates.io, unpinned dependencies drifting to vulnerable versions.

**Status**: MITIGATED

**Mitigations**:
- `cargo-audit` integrated as a blocking CI check — every build scans against the RustSec advisory database
- `Cargo.lock` tracked in git — audits run against exact pinned versions, not resolved-at-build-time versions
- RUSTSEC-2023-0071 (RSA Marvin Attack) was the only suppressed advisory; it is now resolved and removed from `.cargo/audit.toml`
- CI now passes with zero suppressed advisories

---

### T12: YubiKey Hardware Failure / Silent Fallback

**Description**: YubiKey hardware becomes unavailable and the system silently falls back to software key operations, defeating the hardware isolation guarantee.

**Attack Vectors**: YubiKey disconnect, PIV applet error, driver failure, supply chain substitution.

**Status**: MITIGATED

**Mitigations**:
- Fail-closed design: hardware unavailable = error returned to caller; no silent software fallback
- `ensure_connected()` is called at the start of every PIV operation — gates all hardware-backed operations
- 18 simulation tests + 9 hardware integration tests; all tests use real assertions, not placeholder values
- ECDSA P-256 signing via PIV slot 9c: private key is generated on hardware and is non-exportable by design

---

### T13: Content Confidentiality, Forward Secrecy & Recipient Access (C4)

**Description**: An adversary who later extracts a device key (e.g. flash readout of
a decommissioned board) attempts to decrypt all previously recorded archives; or a
provenance consumer (auditor/insurer) needs to read content without gaining the
power to forge.

**Attack Vectors**: Long-term key exfiltration, decommissioned-hardware readout,
key sharing for auditing.

**Status**: MITIGATED (C4, `.trst` 0.2.0)

**Mitigations**:
- **Per-archive random CEK**: chunk content is encrypted under a fresh Content-Encryption Key, never derived from any long-term key.
- **HPKE (RFC 9180) recipient wrapping with ephemeral sender keys**: the CEK is wrapped to each recipient's X25519 key using `DHKEM(X25519,HKDF-SHA256)`/`HKDF-SHA256`/`ChaCha20Poly1305`, base mode, with a fresh ephemeral per recipient. A later readout of a recipient's X25519 secret exposes only archives wrapped to that recipient, and only the CEKs — the ephemeral private keys are never stored (forward secrecy).
- **Recipient model**: an auditor decrypts with their own X25519 key and gains no signing/forgery capability. The device is simply recipient #0.
- **Manifest binding**: the Ed25519 signature covers the whole recipient set, and each HPKE `aad` binds the wrapped CEK to the manifest-without-encryption digest, so a wrapped CEK cannot be transplanted onto another manifest.
- **Full-identity chunk AAD (M1)**: `BLAKE3("sealedge/aad/v1" || device.public_key || profile || started_at)` — no longer the 48-bit truncated device id.

**Residual risk / out of scope here**:
- Compromise of a recipient's (incl. the device's) X25519 secret exposes archives wrapped to that key. Mitigation = rotation/revocation (Phase 2; manifest reserves room for a key-epoch).
- The network transport handshake (`auth.rs`) still uses static-static ECDH from the long-term key — tracked as a separate follow-up.
- Recipient public keys are visible in the manifest (who-can-read is not private). Acceptable for a provenance product.

---

### T14: Cross-Archive Integrity (Device Chronicle + Witness, H1)

**Threat**: `.seal` archives are independent files, so wholesale deletion,
reordering, or history-rewriting of a device's archives is invisible, and
capture timestamps are self-asserted.

**Mitigations**:
- **Chronicle linkage**: each archive carries a signed, monotonic `sequence` and
  a populated `prev_archive_hash` (BLAKE3 of the previous manifest's canonical
  bytes). `seal verify-chronicle` detects mid-chain deletion (sequence gaps),
  reordering, and tampering (broken links) offline, given the chain.
- **Witness receipt**: `POST /v1/witness` records a device-signed chronicle tip in
  an append-only, monotonic per-device ledger (primary key `(device_pub,
  sequence)`; forks and rollbacks are rejected `409`) and returns a JWS bearing a
  **trusted `observed_at`** timestamp. This answers "when did this exist?" and is
  the only way to detect **tail deletion** (dropping the newest archives):
  `verify-chronicle --witness` fails when the local tip is behind the witnessed
  tip. Without a durable (postgres) ledger the endpoint returns `503` rather than
  fabricate durability.

**Residual risk**:
- Detection begins at the **first witness**: history rewritten before any tip was
  ever witnessed is undetectable.
- The witness is a timestamp + monotonicity authority, not a content authority. A
  malicious platform can withhold service or shift its clock, and **cross-client
  equivocation** (showing different logs to different verifiers) is not prevented
  — that needs a Merkle transparency log with gossiped consistency proofs, which
  is explicitly out of scope (see `docs/designs/h1-device-chronicle.md` §9).

### T15: Key Lifecycle — Rotation & Revocation (H1 Phase 2)

**Threat**: A device's signing key is fixed for the life of its chronicle. It
cannot be rolled without abandoning history, and if it is compromised nothing
marks it invalid — a verifier can't tell a legitimate pre-compromise archive from
a post-compromise forgery.

**Mitigations**:
- **Rotation entry**: a dedicated, dual-signed chronicle entry links a new signing
  key to the old one. `sig_old` proves the current holder authorized the successor
  (only it can extend the chain); `sig_new` proves possession of the new key (no
  committing someone else's key). Every archive carries a monotonic `key_epoch`;
  `seal verify-chronicle` walks the active identity across rotations, verifying
  both co-signatures and the exact `+1` epoch bump at each switch.
- **Registry revocation**: `POST /v1/devices/:id/revoke` (org-admin, tenant-scoped)
  sets `revoked_at` / `min_epoch` on the device row. Revocation is **monotonic**
  (`revoked_at` earlier-only and never cleared; `min_epoch` non-decreasing), so an
  admin cannot retroactively bless a forgery. `/v1/verify` fails closed when an
  archive's `key_epoch` is below `min_epoch`.
- **Revocation × witness composition (the teeth)**: a signing key seen after
  compromise can forge archives with any self-asserted timestamp, so the only
  trusted time is the witness `observed_at`. An archive under a revoked key is
  trustworthy iff it was **witnessed before `revoked_at`** — a verifier-side
  composition of `verify-chronicle --witness` and the registry `revoked_at`.
- **Superseded-ledger rule**: once the platform records lineage `old → new` at the
  rotation sequence (after verifying the rotation entry carried on the witness
  request), the old key's witness ledger is **closed** beyond that point (`409`),
  so a stolen old key cannot fork a second platform-co-signed timeline. `/v1/witness`
  also refuses any **new** tip from a revoked key (`403`) while still replaying
  already-witnessed facts.

**Residual risk**:
- Archives witnessed **before** the compromise was noticed and revoked are trusted
  — inherent to "before revocation" and the reason the witnessed timestamp matters.
- Revocation is a registry fact; a malicious platform lying about `revoked_at` is
  the same equivocation residual as T14 (needs a transparency log).
- Device-signed self-revocation is not offered — revocation is registry/org-admin
  only (see `docs/designs/h1-phase2-rotation-revocation.md` §1 non-goals).

## RSA Vulnerability History

This section documents the full lifecycle of RUSTSEC-2023-0071 (Marvin Attack) in Sealedge.

**The advisory**: The `rsa` crate's PKCS#1 v1.5 decryption (`Pkcs1v15Encrypt`) is vulnerable to a timing side-channel attack (Marvin Attack) that enables adaptive chosen-ciphertext recovery of RSA private keys. Published 2023; CVE pending.

**v1.3 (2026-02-13) — Risk Accepted**

During cargo-audit integration, RUSTSEC-2023-0071 was identified against the `rsa` crate used in `hybrid.rs`. At the time, Sealedge's RSA usage was limited to `hybrid.rs`, which was used for non-production asymmetric encryption scenarios. The advisory was risk-accepted with documented rationale and added to `.cargo/audit.toml` ignore list.

Rationale: Sealedge's primary encryption path (AES-256-GCM) was unaffected. RSA in `hybrid.rs` was not used in the primary data lifecycle. Risk was acknowledged as a known limitation.

**v1.3 through v2.1 — Carried as Known Risk**

The advisory remained in `.cargo/audit.toml` with the risk-accepted rationale. Any use of `hybrid.rs` RSA decryption was potentially vulnerable to timing-based key recovery if an adversary could measure decryption response times.

**v2.2 Phase 45 (2026-03-19) — Fully Resolved**

`Pkcs1v15Encrypt` was replaced with `Oaep::new::<sha2::Sha256>()` in `asymmetric.rs` (`hybrid.rs`). OAEP does not have the timing side-channel vulnerability present in PKCS#1 v1.5 decryption.

RUSTSEC-2023-0071 was removed from `.cargo/audit.toml`. `cargo-audit` now passes with no suppressed advisories. The codebase contains no remaining PKCS#1 v1.5 decryption code.

---

## Mitigation Status Summary

| Threat | Status | Version Resolved |
|--------|--------|-----------------|
| T1: Data tampering in transit | MITIGATED | v1.0 |
| T2: Data tampering at rest | MITIGATED | v1.0 |
| T3: Key compromise at rest | MITIGATED | v2.2 |
| T4: RSA padding oracle (RUSTSEC-2023-0071) | MITIGATED | v2.2 |
| T5: Weak key derivation | MITIGATED | v1.8 / v2.2 |
| T6: Legacy envelope format | MITIGATED | v2.2 |
| T7: Insecure transport | MITIGATED | v1.4 / v2.2 |
| T8: Replay attacks on verification | PARTIAL | — |
| T9: API / dashboard auth bypass | MITIGATED | v1.7 |
| T10: Secret material in memory | MITIGATED | v1.7 |
| T11: Supply chain vulnerabilities | MITIGATED | v1.3 / v2.2 |
| T12: YubiKey hardware fallback | MITIGATED | v1.1 |
| T13: Content confidentiality & recipient access (C4) | MITIGATED | v6.x (C4) |
| T14: Cross-archive integrity (chronicle + witness, H1) | MITIGATED | v6.x (H1) |
| T15: Key lifecycle — rotation & revocation (H1 Phase 2) | MITIGATED | v6.x (H1 P2) |

---

## Out of Scope

The following are acknowledged but outside the current threat model:

- **TPM support** — planned for a future milestone; no hardware available to test against
- **Post-quantum cryptography** — research phase only; no production use case
- **Physical device security** — OS-level and environmental security are operator responsibilities
- **Regulatory compliance** — GDPR, CCPA, and sector-specific requirements are implementation-site concerns
- **Social engineering** — attacks against operators or administrators

---

## Document Maintenance

This document must be reviewed:
- Before each major release
- After any security incident
- When the cryptographic primitive set changes

Next scheduled review: before v2.3 or next major milestone.
