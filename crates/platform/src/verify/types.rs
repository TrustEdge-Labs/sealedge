//
// Copyright (c) 2025 TRUSTEDGE LABS LLC
// This source code is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Project: sealedge — Privacy and trust at the edge.
//

//! Request/response types for the verification service.

use serde::{Deserialize, Serialize};

use super::engine::VerifyReport;

// The request wire types are the shared, canonical definitions from
// `sealedge-types` — the exact same types the CLI (`seal emit-request`)
// serializes. Re-exporting them (instead of maintaining a parallel copy here)
// guarantees the request contract cannot silently drift between the two sides.
// `sealedge_types::verification::SegmentRef` is aliased to `SegmentDigest` by
// the engine, so `VerifyRequest.segments` matches `verify_to_report`'s input.
pub use sealedge_types::verification::{VerifyOptions, VerifyRequest};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct VerifyResponse {
    pub verification_id: String,
    pub result: VerifyReport,
    pub receipt: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct HealthResponse {
    pub status: String,
    pub timestamp: String,
}
