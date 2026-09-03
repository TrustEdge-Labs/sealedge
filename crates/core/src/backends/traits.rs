//
// Copyright (c) 2025 TRUSTEDGE LABS LLC
// This source code is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Project: sealedge — Privacy and trust at the edge.
// GitHub: https://github.com/TrustEdge-Labs/sealedge
//

//! Key backend trait definitions
//!
//! This module defines the core traits that all key management backends must implement.

use crate::error::BackendError;
use serde::{Deserialize, Serialize};

/// Core trait that all key management backends must implement
pub trait KeyBackend: Send + Sync {
    /// Derive a key from the backend using the given key ID and context
    fn derive_key(&self, key_id: &[u8; 16], context: &KeyContext)
        -> Result<[u8; 32], BackendError>;

    /// Store a key in the backend (if supported)
    fn store_key(&self, key_id: &[u8; 16], key_data: &[u8; 32]) -> Result<(), BackendError>;

    /// Rotate a key from old ID to new ID (if supported)
    fn rotate_key(&self, old_id: &[u8; 16], new_id: &[u8; 16]) -> Result<(), BackendError>;

    /// List available keys with metadata (if supported)
    fn list_keys(&self) -> Result<Vec<KeyMetadata>, BackendError>;

    /// Get backend-specific information
    fn backend_info(&self) -> BackendInfo;

    /// Check if this backend supports key storage
    fn supports_storage(&self) -> bool {
        false // Default: read-only backends
    }

    /// Check if this backend supports key rotation
    fn supports_rotation(&self) -> bool {
        false // Default: no rotation support
    }
}

/// Context information for key derivation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyContext {
    /// Salt for key derivation (backend-specific interpretation)
    pub salt: Vec<u8>,
    /// Additional context data (e.g., device ID, session info)
    pub additional_data: Vec<u8>,
    /// Iteration count for PBKDF2-like backends
    pub iterations: Option<u32>,
}

impl KeyContext {
    pub fn new(salt: Vec<u8>) -> Self {
        Self {
            salt,
            additional_data: Vec::new(),
            iterations: Some(600_000), // OWASP 2023 recommended PBKDF2 iterations
        }
    }

    pub fn with_additional_data(mut self, data: Vec<u8>) -> Self {
        self.additional_data = data;
        self
    }

    /// Set the PBKDF2 iteration count, validating it against the accepted range.
    /// Fallible (no panic); the point-of-use check during derivation is authoritative.
    pub fn with_iterations(mut self, iterations: u32) -> Result<Self, BackendError> {
        crate::backends::universal::validate_pbkdf2_iterations(iterations)?;
        self.iterations = Some(iterations);
        Ok(self)
    }
}

/// Metadata about a stored key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// Key identifier
    pub key_id: [u8; 16],
    /// Human-readable description
    pub description: String,
    /// When the key was created (Unix timestamp)
    pub created_at: u64,
    /// When the key was last used (Unix timestamp)
    pub last_used: Option<u64>,
    /// Backend-specific metadata
    pub backend_data: Vec<u8>,
}

/// Information about a key backend
#[derive(Debug, Clone)]
pub struct BackendInfo {
    /// Backend name (e.g., "keyring", "tpm", "hsm")
    pub name: &'static str,
    /// Human-readable description
    pub description: &'static str,
    /// Backend version
    pub version: &'static str,
    /// Whether the backend is available on this system
    pub available: bool,
    /// Backend-specific configuration requirements
    pub config_requirements: Vec<&'static str>,
}

impl BackendInfo {
    pub fn keyring() -> Self {
        Self {
            name: "keyring",
            description: "OS keyring with PBKDF2 key derivation",
            version: "1.0.0",
            available: true, // Always available
            config_requirements: vec!["passphrase", "salt"],
        }
    }

    pub fn tpm() -> Self {
        Self {
            name: "tpm",
            description: "TPM 2.0 hardware security module",
            version: "1.0.0",
            available: false, // NOTE: TPM detection planned for post-P0
            config_requirements: vec!["device_path", "key_handle"],
        }
    }

    pub fn hsm() -> Self {
        Self {
            name: "hsm",
            description: "Hardware Security Module (PKCS#11)",
            version: "1.0.0",
            available: false, // NOTE: HSM detection planned for post-P0
            config_requirements: vec!["pkcs11_lib", "slot_id", "pin"],
        }
    }
}
