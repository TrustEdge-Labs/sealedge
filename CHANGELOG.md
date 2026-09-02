<!--
Copyright (c) 2025 TRUSTEDGE LABS LLC
MPL-2.0: https://mozilla.org/MPL/2.0/
Project: sealedge — Privacy and trust at the edge.
GitHub: https://github.com/TrustEdge-Labs/sealedge
-->

# Sealedge Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Note — Pre-v6.0 entries:** Entries below v6.0 describe the project under its former name, **trustedge**. Artifact names, binary names, extensions, and env-var prefixes in those entries refer to what shipped at the time. See `MIGRATION.md` §"v6.0" for the rename map. Entries from v6.0 onward use the current brand, **sealedge**.

## [Unreleased]

### Security — key-bundle zeroization & recovery integrity

- **Key-bundle zeroization close-out.** The device-key import/export path no
  longer leaves secret material in unzeroed heap copies. `DeviceBundle`'s
  plaintext form is now a dedicated `ZeroizeOnDrop` struct (replacing a
  `serde_json::Value` whose owned secret strings lingered); `to_plaintext`
  returns a `Zeroizing<String>`; `import_encrypted` wraps the decrypted buffer
  and validates UTF-8 by borrow (no owned copy). The single-key path
  (`DeviceKeypair::import_secret_encrypted`) wraps its decrypted raw key in
  `Zeroizing` too, and every CLI passphrase prompt is zeroized on drop. The final
  decoded-key copy on the import path (`DeviceKeypair::import_secret`) is now
  `Zeroizing` as well.
- **Owner-only key-file writes (no chmod race).** `seal keygen` and the rekey path
  now write secret key files through a shared core `write_secure` — a
  `0600`-at-creation temp file renamed over the target — instead of writing with
  the default umask then `chmod`-ing, which briefly left the key world-readable.
  This is the custody fix M2 applied to the JWKS key, now extracted to
  `sealedge-core::secure_file` so the platform and CLI share one implementation
  (Unix `rename(2)` semantics; a crash may leave an inert `.tmp.<pid>.<seq>` /
  `.seal-unwrap.<pid>.partial` sibling that is safe to delete).
- **Atomic `unwrap`.** `seal unwrap` recovers to a temp file and atomically
  renames it into place only on success; a mid-stream failure (I/O error, disk
  full, AEAD failure) now deletes the partial instead of leaving a
  silently-truncated plaintext that looked like a complete recovery. A failed
  unwrap also no longer truncates an existing output file — the previous output
  is untouched until the new recovery completes. Restores the pre-streaming
  all-or-nothing guarantee while keeping constant memory.
- **Key-file version validation.** `DeviceBundle::from_plaintext` and
  `open_secret` now reject an unexpected format version (bundle `!= 2`, sealed
  secret `!= 1`) before parsing the payload — closing a structural gap where a
  version mismatch was silently ignored.
- **Dependency.** Bumped `chacha20` 0.10.1 → 0.10.2 (0.10.1 was yanked upstream;
  pulled transitively via the QUIC stack).

### Security — archive read-path hardening

- **Chunk size cap + integrity.** Every chunk read path (`validate_archive`,
  `read_archive`, `unwrap`, `emit-request`) now rejects a stored chunk larger than
  `MAX_STORED_CHUNK_BYTES` — the 256 MiB `--chunk-size` producer cap plus AEAD
  overhead — sharing one core const with the `wrap` guard so producer and consumer
  can't drift (F10). `emit-request` also checks each segment's declared
  `chunk_file` name before hashing (F5), matching `validate_archive`/`read_archive`.
- **No exists()/open() TOCTOU.** `validate_archive` and `read_archive` open chunk
  files directly and map a missing file to `MissingChunk`, instead of an
  `exists()` precheck that could race with the open (F11).

### Changed — H3: streaming I/O (constant-memory wrap + bounded reads)

- **Streaming wrap.** `wrap` no longer holds the payload in memory: a new core
  `ArchiveWriter` streams one `chunk_size` buffer at a time (read → encrypt →
  write → segment), dropping peak RAM from ~2× payload to **O(chunk_size)** — the
  GB-scale edge-camera case now works. No format change; golden vectors and
  seeded output are byte-identical.
- **Bounded reads (DoS surface).** `validate_archive` stream-hashes each chunk;
  `read_manifest` reads the manifest+signature only (no chunk load); `unwrap` and
  `emit-request` stream one chunk at a time; `hash_file` streams. `verify` no
  longer double-reads the payload. No verify/ingest path loads a whole archive
  into memory.
- **Manifest/signature caps.** `manifest.json` (8 MiB) and the detached signature
  (4 KiB) are size-capped on read; the **same** `MANIFEST_MAX_BYTES` guards
  `ArchiveWriter::finalize`, so `wrap` can't emit a manifest a reader would reject
  (SA1). Threat model **T16** (resource exhaustion).

### Security — M2: platform signing-key custody

- **Encryption at rest.** The platform Ed25519 signing key (JWKS + the
  witness/timestamp root that backs revocation) is now encrypted at rest with
  PBKDF2-HMAC-SHA256 (600k) + AES-256-GCM via `JWKS_KEY_PASSPHRASE`, reusing the
  SEALEDGE-KEY-V2 scheme (new shared `seal_secret`/`open_secret` core primitive,
  `SEALEDGE-SEALED-V1` blob).
- **Fail closed in release.** `JWKS_KEY_PASSPHRASE` and an explicit `JWKS_KEY_PATH`
  are now **required** in release builds — no `/tmp` default, no plaintext key.
  Debug keeps a warned plaintext fallback for tests.
- **No write-then-chmod race.** The key file is written atomically to a `0600`
  temp sibling (mode set at creation) and renamed into place — closing the window
  where the key was briefly world-readable.
- **Zeroization.** Transient seed bytes, the base64 encoding, and the plaintext
  JSON are zeroized after use; the in-memory passphrase is zeroized on drop and
  never rendered by `Debug`. The live `SigningKey` itself is now
  `ZeroizeOnDrop` (enabled the `zeroize` feature on `ed25519-dalek`), with a
  compile-time guard test so the property can't silently regress (F1).
- **PBKDF2 iteration ceiling.** `open_secret` / bundle import now reject an
  above-ceiling iteration count (max 10M, symmetric with the 600k floor), so a
  corrupt or hostile key file can't stall decryption at boot (F2).

## [6.1.0] - 2026-08-05

### Added — H1 Phase 2: key rotation & revocation

- **Key rotation.** `seal rekey --chronicle <state> --old-key <old> --new-key <new>
  --out <dir>` emits a dedicated, dual-signed rotation entry (`rotation.json`) that
  links a new signing identity to the old one and advances the chronicle to the new
  key/epoch. `sig_old` authorizes the successor; `sig_new` proves possession.
- **Key epoch.** Every archive carries a monotonic `device.key_epoch` (H1 archives
  are epoch 0, emitted only when `> 0` so they stay byte-identical). `seal wrap
  --chronicle` stamps it from the chronicle state.
- **`verify-chronicle` walks rotations.** The one-signer rule is replaced by an
  active-identity walk: `--device-pub` pins the genesis identity, each rotation
  switches the active signer after verifying both co-signatures and the `+1` epoch
  bump. The `--witness` cross-check binds the receipt to the active signer at the
  witnessed sequence (works on rotated chains).
- **Registry revocation.** `POST /v1/devices/:id/revoke` (org-admin, tenant-scoped)
  sets `revoked_at` / `min_epoch`, **monotonic-only** (earlier-only, never cleared;
  non-decreasing). `/v1/verify` fails closed below `min_epoch` and annotates the
  result with the revocation state. Trusting an archive under a revoked key is the
  verifier-side composition `verify-chronicle --witness` + registry `revoked_at`.
- **Witness lineage & superseded ledger.** A rotation tip witnessed under the new
  key (`seal witness --rotation <dir>`) carries the rotation entry; the platform
  verifies its co-signatures and records `device_lineage`, then closes the old key's
  ledger beyond the rotation point (`409`) and refuses new tips from a revoked key
  (`403`, replays still succeed).
- Threat model **T15** (key lifecycle). Migration `004_revocation.sql`
  (`devices.revoked_at` / `min_epoch`, `device_lineage`).

### Added — H1 device chronicle (cross-archive continuity)

- **Chronicle linkage.** `.seal` archives can form a per-device, hash-linked,
  sequence-numbered chain: `seal wrap --chronicle <state>` populates the signed
  `sequence` + `prev_archive_hash` and advances a local head pointer (or use
  `--prev-archive` / `--prev-hash`+`--prev-seq`). Additive within `trst_version`
  0.2.0 — standalone archives are byte-identical to before.
- **`seal verify-chronicle`.** Verifies a device's chain: per-archive signature +
  continuity, single-signer, contiguity (detects gaps / reordering), and hash
  linkage. Exit code `13` on a chronicle failure.
- **Platform witness (`POST /v1/witness`) + `seal witness`.** A device submits its
  signed chronicle tip; the platform records it in an append-only, monotonic
  per-device ledger (forks / rollbacks → `409`) and returns a JWS witness receipt
  with a trusted timestamp. `seal verify-chronicle --witness` cross-checks the
  local tip against a receipt and detects **tail deletion**. Without the
  `postgres` feature the endpoint returns `503` rather than fake durability.
- Threat model **T14** (cross-archive integrity). Key rotation / revocation /
  key-epoch shipped in **H1 Phase 2** (above).

### Security (external review — Criticals C1–C4)

- **C1 — Platform `/v1/verify` now verifies real `.seal` archives.** Fixed a double
  `ed25519:` signature prefix and a canonicalization mismatch; the platform now
  verifies over `TrstManifest::to_canonical_bytes()` (the exact bytes the CLI signs),
  and the divergent `VerifyRequest` types are reconciled onto the shared
  `sealedge-types` definitions. Added end-to-end + golden-vector regression gates.
- **C2 — Continuity verification binds to the signed manifest.** Fixed an
  encoding bug that made `chain_tip` a function of segment count alone; the engine
  now validates the manifest's own BLAKE3 continuity chain and requires the
  submitted segments to match the signed manifest, and reports real
  `verified_segments`.
- **C3 — Honest receipt trust semantics.** JWS `sub` is now the cryptographic
  signer (`signer_pub`), not client-supplied `device_id`; the verification key
  must match `manifest.device.public_key`; postgres mode fails closed on unknown
  device / key mismatch; self-signed attestations are labeled as such.
- **C4 — Content-encryption redesign (breaking, `.trst` `0.2.0`).** The Ed25519
  key is now signing-only. Content is encrypted under a per-archive random CEK
  wrapped to one or more recipients via **HPKE (RFC 9180)** with ephemeral sender
  keys (forward secrecy). New independent X25519 device key and `SEALEDGE-KEY-V2`
  dual-key bundle. Auditors decrypt with their own key without gaining signing
  power. Chunk AAD binds the full device public key. Verifiers (CLI / platform /
  WASM) reject pre-C4 `0.1.0` archives. See
  `docs/designs/c4-content-encryption-redesign.md`.

### Changed (breaking)
- `.trst` archive format bumped to `0.2.0`; `0.1.0` archives are no longer produced
  or accepted. `seal keygen` now emits a `SEALEDGE-KEY-V2` bundle and a dual-line
  `.pub`. `seal wrap` gains `--recipient` and `--sign-only`. YubiKey wrap currently
  requires `--sign-only`.

## [6.0.0] - 2026-04-22

### Sealedge Rebrand

Trademark-driven clean-break rename from **trustedge** to **sealedge**. The project, workspace crates, binary names, file extensions, wire-format constants, and the published GitHub Action are all renamed. No backward-compatibility shims — data encrypted under old constants cannot be decrypted by v6.0 binaries. See [`MIGRATION.md`](MIGRATION.md) for the full rename map.

### Changed (breaking)
- **Crate rename**: every workspace crate renamed from `trustedge-*` to `sealedge-*`. Archive crates `trustedge-trst-*` renamed to `sealedge-seal-*`.
- **Binary rename**: `trustedge` → `sealedge`, `trst` → `seal`, `trustedge-server` → `sealedge-server`, `trustedge-client` → `sealedge-client`, `trustedge-platform-server` → `sealedge-platform-server`, `inspect-trst` → `inspect-seal`.
- **Archive file extension**: `.trst` → `.seal`.
- **Point attestation extension**: `.te-attestation.json` → `.se-attestation.json`.
- **Encrypted key file format**: `TRUSTEDGE-KEY-V1` → `SEALEDGE-KEY-V1` (clean break — v6.0 binaries cannot decrypt keys under the old header).
- **Wire-format constants**: all magic bytes and format strings rewritten to announce the product as sealedge; v2-only envelope format, no v1 decrypt path.
- **GitHub Action rename**: [`TrustEdge-Labs/attest-sbom-action@v1`](https://github.com/TrustEdge-Labs/attest-sbom-action) deprecated in favor of [`TrustEdge-Labs/sealedge-attest-sbom-action@v2`](https://github.com/TrustEdge-Labs/sealedge-attest-sbom-action). The old marketplace listing redirects.
- **Repository URL**: `TrustEdge-Labs/trustedge` → `TrustEdge-Labs/sealedge`. Old URL redirects via GitHub repo rename; local remotes and in-repo links updated.
- **Product references on trustedgelabs.com**: rebranded to Sealedge; live verifier links updated.

### Added
- **`MIGRATION.md`**: complete rename map across crates, binaries, extensions, constants, env vars, GitHub Action, and repository URL; includes a per-user migration checklist for upgrading callers.
- **`scripts/validate-v6.sh`**: reusable v6.0 validation-gate runner — wraps `ci-check.sh`, WASM cargo check + size floor, dashboard build/typecheck, docker compose health + `demo.sh` roundtrip, with a test-count floor (≥ 471) and `--allow-regression "<justification>"` escape hatch.
- **Platform migration `002_seed_anonymous_org.sql`**: seeds the nil-UUID organization so unauthenticated `/v1/verify` requests resolve against a real org row.
- **`RELEASE-NOTES-v6.0.0.md`** and v6.0.0 GitHub release with 5 self-attested assets (`seal`, `seal.sha256`, `seal-sbom.cdx.json`, `seal.se-attestation.json`, `ephemeral.pub`). Dogfoods `sealedge-attest-sbom-action@v2` end-to-end.

### Security
- **rustls-webpki**: bumped to 0.103.13 (RUSTSEC-2026-0104).

### Housekeeping
- `ci-check.sh` now excludes `.claude/` and `node_modules/` from the copyright-header scan.
- `validate-v6.sh` teardown uses `docker compose down -v` to clear the postgres volume between runs.
- Dashboard Sealedge-branded on home (`Sealedge Dashboard` heading + nav) and devices pages (`Registered Sealedge edge devices`).
- Full v6.0 validation gauntlet green: all 8 gates, 1052 tests across the feature matrix, both `workflow_dispatch` runs (`semver.yml`, `wasm-tests.yml`) and the tag-push CI run green on the rename-target repository.

---

## [5.0.0] - 2026-04-05

### Portfolio Polish

Hardened CI self-attestation and enhanced the published GitHub Action for marketplace readiness.

### Changed
- **CI self-attestation hardened**: Replaced unpinned `curl | sh` syft install with SHA-pinned `anchore/sbom-action@v0.24.0`. Added `continue-on-error: true` so attestation failures never block releases. Renamed `ephemeral.pub` to `build.pub` for clarity.
- **`build.pub` uploaded as release asset**: Verifiers can now independently check attestations using only the release assets (`trst.te-attestation.json` + `build.pub`), with no TrustEdge infrastructure needed.
- **GitHub Action enhanced**: `TrustEdge-Labs/attest-sbom-action@v1` now verifies the SHA256 checksum of the downloaded `trst` binary before executing. Graceful degradation when no checksum file is available. Added `branding` block for GitHub Marketplace listing.
- **Action README rewritten**: Two named usage examples (ephemeral key for CI, persistent key with GitHub Secret). "What you get" section clarifying the action produces a local `.te-attestation.json` file.

### Housekeeping
- Archived te-prove design doc (FOSS supply chain trust policy engine) to `.planning/ideas/` with context note. Parked pending demand evidence.

---

## [4.0.0] - 2026-04-03

### SBOM Attestation Wedge

First product feature: cryptographically bind SBOMs to binary artifacts using a lightweight point attestation format, independent of any CI provider.

### Added
- **Point attestation format** (`.te-attestation.json`): Ed25519 signature over BLAKE3 hashes of two artifacts (subject + evidence), random nonce, ISO 8601 timestamp. Generic `subject`/`evidence` schema works for any artifact pair.
- **`trst attest-sbom`**: CLI command to create attestation documents from a CycloneDX SBOM + binary artifact
- **`trst verify-attestation`**: CLI command to verify attestation documents locally, with optional binary/SBOM hash checking
- **`POST /v1/verify-attestation`**: Platform endpoint that verifies point attestations and returns JWS receipts
- **Static HTML verify page**: Browser-based attestation verification at `GET /verify`, served from the platform binary via `include_str!`
- **DigitalOcean App Platform deployment**: `deploy/digitalocean/` with Dockerfile (http-only, no postgres), app.yaml, and deployment guide
- **`scripts/demo-attestation.sh`**: End-to-end SBOM attestation demo (keygen, syft SBOM, attest, verify) in under 60 seconds
- **GitHub Action** (`actions/attest-sbom-action/`): Composite action for one-line CI integration, downloads pre-built `trst` binary
- **CI self-attestation**: Release workflow generates `.te-attestation.json` alongside release binaries using ephemeral keys
- **Product landing page content**: `docs/landing-page.md` with positioning, quick start, and differentiation
- **Third-party attestation guide**: `docs/third-party-attestation-guide.md` with manual and CI workflows
- `PointAttestation` and `ArtifactRef` types in `trustedge-core` (521 lines, 15 unit tests)
- 8 CLI acceptance tests for attest-sbom/verify-attestation
- 5 platform integration tests for /v1/verify-attestation
- `PointAttestationError` enum integrated into `TrustEdgeError`

### Changed
- Platform router serves static verify page at `GET /verify`
- CI workflow includes self-attestation job on release tags
- Test count: 406 -> 471 across 9 workspace crates

---

## [3.0.0] - 2026-03-27

### Official Signed Release

First official signed release. All security review findings resolved, documentation current, deployment hardened.

### Changed
- **Configurable receipt TTL**: JWS verification receipts now use `RECEIPT_TTL_SECS` env var (default 3600s) instead of hardcoded 1 hour
- **Strict PORT validation**: Invalid `PORT` env var now causes startup failure with clear error instead of silently defaulting to 3001
- **Envelope::hash() returns Result**: Serialization failures propagate instead of silently hashing empty input via `unwrap_or_default()`
- **generate_aad() uses .expect()**: Documents infallibility intent instead of bare `.unwrap()`
- **Docker Compose credentials**: Moved from inline plaintext to `env_file: deploy/.env` with `.env.example` template

### Security
- `/healthz` no longer exposes exact crate version (prevents version fingerprinting)
- nginx security headers (X-Content-Type-Options, X-Frame-Options, Referrer-Policy, CSP) now present in all location blocks, not just server level
- CSP `connect-src` includes API origin for dashboard API calls
- `deploy/.env` gitignored to prevent credential leaks

### Documentation
- README updated for v3.0 (version badge, Docker quick-start with `.env` step, security posture)
- CLAUDE.md updated (CLI binary table with `trustedge-platform-server`, feature flags including `git-attestation`/`keyring`/`insecure-tls`, Platform Environment Variables section, corrected test counts)
- docs/user/cli.md: all 5 `trst` subcommands documented including `keygen`, `unwrap`, `emit-request`; encrypted key files section added
- docs/architecture.md: corrected Key Modules table (`archive.rs` replaces nonexistent `manifest.rs`)
- docs/developer/testing.md: corrected test counts across all crates

### Added
- `deploy/.env.example` with all platform environment variables documented (PORT, RECEIPT_TTL_SECS, CORS_ORIGINS, JWKS_KEY_PATH, DATABASE_URL, POSTGRES_PASSWORD)

---

## [2.9.0] - 2026-03-26

### Security Review P2 Remediation

- Removed `impl Default` from `CAConfig` and `SoftwareHsmConfig` (placeholder credentials eliminated from production paths)
- Static `LazyLock<Regex>` in `validate_segment_hashes()` (zero per-request allocation)
- `--unencrypted` flag emits stderr security warning in all `trst` subcommands
- `wasm-tests.yml` has explicit `permissions: contents: read` (least-privilege CI)
- nginx security headers added at server level (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy)
- HSTS and HTTP-to-HTTPS redirect in `nginx-ssl.conf.template`

---

## [2.8.0] - 2026-03-26

### High Priority Hardening

- Proxy-aware per-client-IP rate limiting with `TRUSTED_PROXIES` CIDR config
- RFC 6585 `Retry-After: 1` header on 429 responses
- `NetworkChunk::new()` requires explicit nonce parameter (zero-nonce default eliminated)
- `process::exit()` replaced with `CliExitError` propagation (Zeroize Drop handlers run on key material)
- 256 MB ceiling on `--chunk-size`
- Dashboard nginx runs as non-root (`nginx-unprivileged`)
- CI bundle credential guard in GitHub Actions

---

## [2.7.0] - 2026-03-25

### CI & Config Security

- All GitHub Actions SHA-pinned to full commit SHAs
- `curl | sh` wasm-pack installer replaced with `cargo-binstall`
- `DATABASE_URL` fallback gated behind `debug_assertions`
- PostgreSQL port removed from docker-compose host binding
- `CAConfigBuilder::build()` rejects placeholder JWT secret outside tests
- Crypto error responses sanitized (generic messages to clients, full detail in server-side logs)

---

## [2.6.0] - 2026-03-24

### Security Hardening

- Zeroize-on-drop for `PrivateKey`, `ClientAuthResult`, `SessionInfo`, `SymmetricKey`
- 600k PBKDF2 minimum enforced at import boundary
- Optional `OrgContext` in postgres verify handler (tenant-agnostic fallback)
- CORS origins configurable via `CORS_ORIGINS` env var
- CLI requires `--key-out` or `--show-key` for encryption (no key leak to stderr)
- Conditional HTTPS termination in nginx via `SSL_CERT_PATH`/`SSL_KEY_PATH`
- `VITE_API_KEY` removed from dashboard bundle; CI guard prevents re-introduction

---

## [2.5.0] - 2026-03-23

### Critical Security Fixes

- QUIC `HardwareBackedVerifier` performs real TLS signature verification; `accept_any_hardware()` gated behind `insecure-tls`
- 2 MB `RequestBodyLimitLayer` on all platform HTTP routes
- Per-IP rate limiting on `/v1/verify` via `governor` (configurable `RATE_LIMIT_RPS`, default 10/sec)
- JWKS signing key path configurable via `JWKS_KEY_PATH` env var with 0600 permissions
- Fixed trst-wasm double-decrypt bug; crypto module wired into build

---

## [2.4.0] - 2026-03-22

### Security Review Remediation

- Custom base64 replaced with standard `base64` crate (23 call sites)
- Auth timestamp check: asymmetric (5s future / 300s past tolerance)
- `beneficiary()`/`issuer()` return `Result` instead of panicking
- Key files get 0600 Unix permissions on generation
- Encrypted key format includes `"version": 1` field
- Nonce construction guards against chunk index overflow (2^24 limit)
- 14 new error path tests

---

## [2.3.0] - 2026-03-21

### Security Testing

- 31 security tests across 4 threat model categories
- Archive integrity: byte mutation, chunk injection, reordering, manifest modification
- Nonce uniqueness and HKDF key-binding verification
- Encrypted key file protection: truncation, corruption, wrong passphrase
- Receipt binding and replay resistance tests

---

## [2.2.0] - 2026-03-19

### Security Remediation

- RSA OAEP-SHA256 replaces PKCS#1 v1.5 (RUSTSEC-2023-0071 fully resolved)
- v1 envelope format removed entirely
- PBKDF2 minimum 300k iterations enforced
- Device keys encrypted at rest: TRUSTEDGE-KEY-V1 format (PBKDF2-SHA256 600k + AES-256-GCM)
- `--unencrypted` escape hatch for CI/automation

---

## [2.1.0] - 2026-03-18

### Data Lifecycle & Hardware Integration

- `trst unwrap`: decrypt and recover original data (HKDF key derivation, verify-before-decrypt)
- `trst wrap --backend yubikey`: ECDSA P-256 hardware signing via PIV slot 9c
- Named archive profiles: sensor (with geo fields), audio, log
- Multi-algorithm verify dispatch: Ed25519 + ECDSA P-256 prefix-based

---

## [2.0.0] - 2026-03-16

### End-to-End Demo

- Data-agnostic archive profiles (generic default, cam.video preserved)
- Three-service Docker Compose stack (platform + postgres + dashboard) with auto-migration
- `trst keygen` subcommand for Ed25519 device key pair generation
- `scripts/demo.sh` showing full lifecycle (keygen, wrap, verify, receipt)
- README rewritten: problem statement, 3-command quick start, 4 use cases

### v1.1 through v1.8 (2026-02-11 to 2026-02-24)

- **v1.1**: YubiKey backend rewritten from scratch (fail-closed, 487 lines)
- **v1.2**: 2-tier crate classification, dependency audit, tiered CI
- **v1.3**: Feature-gated heavy deps (git2, keyring), cargo-audit CI
- **v1.4**: Secure-by-default QUIC TLS, dead code removal, TODO hygiene
- **v1.5**: Platform consolidation (types crate, platform merge, 5 repos archived)
- **v1.6**: Platform server binary, dashboard in monorepo, 11 repos deleted (3-repo org)
- **v1.7**: Secret\<T\> zeroize wrapper, CORS hardening, 16 integration tests
- **v1.8**: HKDF-SHA256 replaces PBKDF2 for envelope key derivation, versioned format

---

## [1.0.0] - 2026-02-11

### 🎉 v1.0 Consolidation Milestone

First major release. Workspace-wide architecture consolidation with zero API breaking changes.

### ⚠️ Deprecation Notices

**Facade crates deprecated:** `trustedge-receipts` and `trustedge-attestation`
are now deprecated facades. All functionality has been consolidated into
`trustedge-core`.

**Affected crates:**
- `trustedge-receipts` 0.3.0: Now a deprecated facade re-exporting from core
- `trustedge-attestation` 0.3.0: Now a deprecated facade re-exporting from core

**Timeline:**
- 1.0.0 (February 2026): Deprecation warnings issued
- Next major (August 2026): Facades will be removed from workspace

**Migration:** See [MIGRATION.md](MIGRATION.md) for upgrade instructions.
All functionality remains available through `trustedge-core` with identical APIs.

### 🏗️ Architecture Improvements

#### Workspace Consolidation
- **Receipts Consolidation**: Moved 1,281 LOC receipts implementation from standalone crate into trustedge-core applications layer
- **Attestation Consolidation**: Moved 826 LOC attestation implementation from standalone crate into trustedge-core applications layer
- **Facade Deprecation**: Created deprecated re-export facades for backward compatibility with 6-month migration window
- **Dependency Cleanup**: Removed 21 unused dependencies across workspace
- **Duplication Elimination**: ~2,500 LOC duplication removed

#### Code Quality
- **340+ Tests**: Up from 150+, including 160 core tests (receipts + attestation tests now in core)
- **Zero API Breaks**: 196 semver checks per crate, all passing
- **Security Fix**: Removed unmaintained wee_alloc dependency
- **Deprecation Fixes**: Updated all GenericArray::from_slice calls to use array conversion
- **Build Performance**: 45s clean release build with optimized dependency graph
- **WASM Compatibility**: Verified for trustedge-trst-protocols and browser verification crates
- **Copyright Headers**: MPL-2.0 headers on all .rs files

#### Previous Changes (included in v1.0)
- **CLI Extraction**: Extracted CLI from trustedge-core into dedicated trustedge-cli crate
- **Manifest Consolidation**: Unified CamVideoManifest types in trustedge-trst-protocols as canonical source
- **Pubky Marked Experimental**: trustedge-pubky and trustedge-pubky-advanced marked as community/experimental crates
- **Version Coordination**: Bumped core platform crates to 0.2.0, keeping Pubky at 0.1.0

### 🔧 YubiKey Improvements
- **GetPublicKey Operation**: Added support for retrieving public keys from YubiKey
- **Slot Validation**: Fixed yubikey_demo slot validation and custom PIN support

### 📚 Documentation
- **CLAUDE.md**: Refreshed architecture overview and crate descriptions
- **README**: Updated for v1.0 with current test counts and architecture
- **MIGRATION.md**: Added facade deprecation migration guide
- **Secure Node MVP**: Added hardware MVP specifications

---

## [0.3.0] - 2025-01-12

### 🎉 P0 Release: cam.video + verify

#### .trst Archive System
- **Locked Specification**: Finalized .trst archive format for cam.video profile
- **Ed25519 Signatures**: Device identity with detached manifest signatures
- **BLAKE3 Continuity Chains**: Cryptographic linking between archive segments
- **XChaCha20-Poly1305**: Chunk encryption with authenticated encryption

#### trst CLI Tool
- **wrap Command**: Create .trst archives from input files
- **verify Command**: Validate archives against device public keys
- **JSON Output**: Structured verification results with `--json` flag
- **Receipt Emission**: Export verification receipts with `--emit-receipt`

#### Browser Verification
- **WASM Verifier**: Browser-based archive verification (web/demo/)
- **trustedge-trst-wasm**: WebAssembly bindings for verification operations

#### Production Cryptography
- **AES-256-GCM Encryption**: Real chunk encryption replacing placeholders
- **PBKDF2 Key Derivation**: 100,000 iterations with HMAC-SHA256
- **Memory-Safe Key Handling**: All key material properly zeroized
- **Context-Bound Encryption**: Envelope context prevents key reuse

#### Digital Receipt System
- **Cryptographically Secure Receipts**: Production-ready with real encryption
- **Ownership Transfer Chains**: Multi-party assignment with verification
- **Amount Preservation**: Cryptographically protected through chains

#### Test Coverage
- **150+ Tests**: Comprehensive coverage across all crates
- **Security Attack Scenarios**: 23 tests for receipts including forgery, replay, tampering
- **Acceptance Tests**: End-to-end verification in crates/trst-cli/tests/acceptance.rs

---

## [0.2.0] - 2025-09-10

### 🎉 Major Features Added

#### YubiKey Hardware Integration
- **Real YubiKey PKCS#11 Support**: Full integration with YubiKey PIV applets for hardware-backed cryptographic operations
- **Hardware Signing Operations**: Actual signing operations using YubiKey hardware with ECDSA P-256
- **PIV Slot Management**: Support for all standard PIV slots (9a, 9c, 9d, 9e) with proper slot enumeration
- **Hardware Detection Framework**: Intelligent hardware detection with CI-safe fallbacks
- **Certificate Generation**: X.509 certificate generation with YubiKey public keys
- **Hardware Attestation**: Cryptographic proof of hardware-backed operations

#### Universal Backend Architecture
- **Pluggable Crypto Backends**: Capability-based backend system supporting multiple crypto providers
- **Backend Registry**: Runtime backend selection with preference-based routing
- **Software HSM Backend**: File-based HSM simulation with persistent key storage
- **Keyring Integration**: OS keyring support for secure key derivation
- **Operation Dispatch**: Type-safe crypto operation routing with comprehensive error handling

#### Transport Layer Implementation
- **Real TCP Transport**: Full TCP client-server implementation with actual network operations
- **Concurrent Connections**: Multi-client support with proper connection management
- **Large Data Transfer**: Support for multi-megabyte transfers with chunking
- **Connection Management**: Proper timeout handling, error recovery, and resource cleanup
- **Message Size Limits**: Configurable limits with enforcement and validation
- **Bidirectional Communication**: Full duplex communication support

### 🔧 Major Improvements

#### Test Suite Overhaul
- **204 Automated Tests**: Comprehensive test coverage across all components
- **Real Functional Testing**: Eliminated fake/stub tests in favor of actual operations
- **Hardware Test Separation**: Proper CI-safe vs hardware-required test categorization
- **Integration Test Coverage**: End-to-end validation of complete workflows
- **Network Integration Tests**: Real client-server testing with data transfer validation

#### Security Enhancements
- **Domain Separation**: Cryptographic domain separation for signature security
- **Resource Bounds**: DoS protection with comprehensive limits and validation
- **Hardware Root of Trust**: YubiKey integration provides hardware security foundation
- **Session Management**: Secure session handling with timeout controls

#### Developer Experience
- **Comprehensive Documentation**: 10,000+ lines of documentation across 27 files
- **CLI Tool Integration**: Full command-line interface for all operations
- **Example Workflows**: Complete examples for all major use cases
- **Error Handling**: Detailed error messages with recovery guidance

### 🐛 Bug Fixes
- Fixed transport layer configuration validation
- Resolved YubiKey hardware detection edge cases
- Corrected test isolation issues in concurrent scenarios
- Fixed memory management in large data transfers

### 📚 Documentation
- Added comprehensive YubiKey integration guide
- Updated CLI reference with all new options
- Enhanced troubleshooting documentation
- Added performance benchmarking guide

### 🔄 Breaking Changes
- Transport configuration API has been updated for better type safety
- YubiKey backend requires explicit feature flag (`--features yubikey`)
- Some test utilities have been moved to support real testing infrastructure

### 📦 Dependencies
- Added `yubikey` crate for hardware integration
- Added `pkcs11` crate for PKCS#11 operations
- Added `x509-cert` for certificate generation
- Updated `tokio-util` for transport layer improvements

### 🎯 Migration Guide
- Update `Cargo.toml` to version `0.2.0`
- Enable YubiKey support with `--features yubikey` if needed
- Review transport configuration for any custom implementations
- Update test dependencies if using TrustEdge test utilities

---

## [0.1.7] - 2025-09-08
### Fixed
- Resolved test infrastructure issues
- Updated CI workflows

## [0.1.0] - 2025-09-02
### Added
- Initial release with core encryption functionality
- Basic CLI tools
- Roundtrip encryption/decryption
- Ed25519 authentication system

---

[Unreleased]: https://github.com/TrustEdge-Labs/trustedge/compare/v3.0...HEAD
[3.0.0]: https://github.com/TrustEdge-Labs/trustedge/compare/v2.9...v3.0
[2.9.0]: https://github.com/TrustEdge-Labs/trustedge/compare/v2.8...v2.9
[2.8.0]: https://github.com/TrustEdge-Labs/trustedge/compare/v2.7...v2.8
[2.7.0]: https://github.com/TrustEdge-Labs/trustedge/compare/v2.6...v2.7
[2.6.0]: https://github.com/TrustEdge-Labs/trustedge/compare/v2.5...v2.6
[2.5.0]: https://github.com/TrustEdge-Labs/trustedge/compare/v2.4...v2.5
[2.4.0]: https://github.com/TrustEdge-Labs/trustedge/compare/v2.3...v2.4
[2.3.0]: https://github.com/TrustEdge-Labs/trustedge/compare/v2.2...v2.3
[2.2.0]: https://github.com/TrustEdge-Labs/trustedge/compare/v2.1...v2.2
[2.1.0]: https://github.com/TrustEdge-Labs/trustedge/compare/v2.0...v2.1
[2.0.0]: https://github.com/TrustEdge-Labs/trustedge/compare/v1.0...v2.0
[1.0.0]: https://github.com/TrustEdge-Labs/trustedge/compare/v0.3.0...v1.0
[0.3.0]: https://github.com/TrustEdge-Labs/trustedge/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/TrustEdge-Labs/trustedge/compare/v0.1.7...v0.2.0
[0.1.7]: https://github.com/TrustEdge-Labs/trustedge/compare/v0.1.0...v0.1.7
[0.1.0]: https://github.com/TrustEdge-Labs/trustedge/releases/tag/v0.1.0