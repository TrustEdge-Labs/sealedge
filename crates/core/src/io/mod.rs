//
// Copyright (c) 2025 TRUSTEDGE LABS LLC
// This source code is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Project: sealedge — Privacy and trust at the edge.
//

//! # Layer 6: I/O Adapters
//!
//! Input/output adapters connecting the core library to external systems.
//! This is the highest layer in the architecture and can import everything below.
//! It provides interfaces to filesystems, audio hardware, archive formats, and other I/O sources.
//!
//! ## Layer Contract
//!
//! **What belongs here:**
//! - Live audio capture from microphone hardware (cpal integration)
//! - Archive read/write operations (.trst format)
//! - Filesystem operations for encrypted data
//! - Input/output abstractions and adapters
//! - Hardware interface adapters
//!
//! **CAN import:**
//! - `primitives` (Layer 1) - for direct crypto operations
//! - `backends` (Layer 2) - for key management
//! - `protocols` (Layer 3) - for envelope and chain operations
//! - `applications` (Layer 4) - for high-level business logic
//! - `transport` (Layer 5) - for network operations
//!
//! **NEVER imports:**
//! - Nothing forbidden - this is the top layer
//!
//! ## Post-Consolidation Contents
//!
//! After Phase 2-8 migration, this module will contain:
//!
//! - `audio.rs` (from `crates/core/src/audio.rs` - feature-gated)
//!   - `AudioCapture` - live microphone capture
//!   - `AudioConfig` - capture configuration (sample rate, channels)
//!   - `AudioChunk` - captured audio segments
//!   - Integration with cpal for cross-platform audio (ALSA/CoreAudio/WASAPI)
//!
//! - `archive.rs` (from `crates/core/src/archive.rs`)
//!   - `read_manifest()` - read the manifest + signature only (no chunk load)
//!   - `validate_archive()` - verify structure, signatures, and continuity (streamed)
//!   - `write_archive()` - write envelope data to .seal format
//!   - `archive_dir_name()` - generate archive directory names
//!
//! ## Usage Example
//!
//! ```rust,ignore
//! use sealedge_core::io::{validate_archive, write_archive, AudioCapture};
//! use sealedge_core::protocols::Envelope;
//!
//! // Capture live audio
//! #[cfg(feature = "audio")]
//! {
//!     let config = AudioConfig { sample_rate: 48000, channels: 1 };
//!     let mut capture = AudioCapture::new(config)?;
//!     let chunk = capture.read_chunk()?;
//! }
//!
//! // Validate an archive (bounded, streamed — no whole-payload load)
//! let archive_path = "clip-12345.seal";
//! validate_archive(archive_path)?;
//!
//! // Write an archive
//! let envelope = Envelope::seal(data, &sender_key, &recipient_key)?;
//! write_archive("output.trst", &envelope)?;
//! ```
//!
//! ## Status
//!
//! **Phase 1 scaffolding - no code yet**
//!
//! This module structure was created in Phase 1 to establish the layer hierarchy.
//! Actual code migration happens in Phase 2-8 of the consolidation roadmap.
