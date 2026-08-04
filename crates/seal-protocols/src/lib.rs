//
// Copyright (c) 2025 TRUSTEDGE LABS LLC
// This source code is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Project: sealedge — Privacy and trust at the edge.
//

//! # Sealedge Protocols
//!
//! Protocol and format definitions for sealedge archives and capture profiles.
//!
//! This crate provides the single source of truth for protocol types used
//! by both the browser WASM verifier and the main sealedge-core library.
//! It has minimal dependencies suitable for WASM compilation.
//!
//! ## Modules
//!
//! - `archive` - Archive format types (manifest, chunks, signatures)
//! - `capture` - Capture profile types (cam.video and future profiles)
//!
//! ## Usage
//!
//! ```rust
//! use sealedge_seal_protocols::{TrstManifest, CamVideoManifest, DeviceInfo, ChunkInfo, SegmentInfo};
//!
//! // Generic profile (default)
//! let manifest = TrstManifest::new();
//!
//! // cam.video profile
//! let cam_manifest = TrstManifest::new_cam_video();
//!
//! // Backward-compatible alias
//! let _: CamVideoManifest = TrstManifest::new_cam_video();
//! ```

pub mod archive;
pub mod capture;

// Re-export all manifest types at crate root for convenience
pub use archive::manifest::{
    AudioMetadata, CamVideoManifest, CamVideoMetadata, CaptureInfo, ChunkInfo, DeviceInfo,
    EncryptionBlock, GenericMetadata, HpkeSuite, LogMetadata, ManifestFormatError, ProfileMetadata,
    RecipientEntry, SegmentInfo, SensorMetadata, TrstManifest,
};

// Backward compatibility alias for trst-wasm (temporary)
#[doc(hidden)]
pub use ManifestFormatError as ManifestError;
