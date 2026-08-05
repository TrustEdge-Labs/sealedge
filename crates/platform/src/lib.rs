//
// Copyright (c) 2025 TRUSTEDGE LABS LLC
// This source code is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Project: sealedge — Privacy and trust at the edge.
//

//! Sealedge Platform — consolidated verification and CA service crate.
//!
//! This crate provides:
//! - `verify` module: core verification logic (signature verify, continuity check, receipt construction)
//! - `ca` module (feature `ca`): Certificate Authority service using UniversalBackend
//! - `http` module (feature `http`): HTTP layer — Plan 02 creates this

pub mod verify;

// Device-chronicle witness (H1): the pure monotonic-ledger decision logic and
// receipt body. The postgres/HTTP wiring lives in `database` and `http`.
pub mod witness;

// Device revocation & rotation lineage (H1 Phase 2): pure enforcement decisions
// (revoke monotonicity, min-epoch gate, revoked/superseded witness refusal,
// rotation-lineage verification). The postgres/HTTP wiring lives in `database`
// and `http`.
pub mod revocation;

// CA module is library-only; not exposed via HTTP routes
#[cfg(feature = "ca")]
mod ca;

#[cfg(feature = "postgres")]
pub mod database;

#[cfg(feature = "http")]
pub mod http;
