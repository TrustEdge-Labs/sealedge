//
// Copyright (c) 2025 TRUSTEDGE LABS LLC
// This source code is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Project: sealedge — Privacy and trust at the edge.
//

//! Universal backend trait for crypto operations
//!
//! This module defines a unified, capability-based approach to cryptographic backends.
//! Instead of a monolithic trait with many methods, backends implement a single
//! `perform_operation` method and advertise their capabilities through `supports_operation`.

use crate::error::BackendError;
use serde::{Deserialize, Serialize};

/// Minimum allowed PBKDF2 iteration count (KDF-01 requirement)
pub const PBKDF2_MIN_ITERATIONS: u32 = 300_000;

/// Maximum allowed PBKDF2 iteration count. Above this, a single key derivation
/// pins a CPU core for minutes (u32::MAX ≈ an hour) — an unbounded-work-factor DoS
/// when the count comes from less-trusted input. ~17× the 600k default.
pub const PBKDF2_MAX_ITERATIONS: u32 = 10_000_000;

/// Validate a caller-supplied PBKDF2 iteration count against the accepted range.
///
/// This is the **authoritative** gate and MUST be called at the point of use (key
/// derivation): `KeyDerivationContext`/`KeyContext` fields are `pub` and
/// `Deserialize`, so a builder-side check alone is bypassable. The builders call it
/// too, for early, fallible feedback (never a panic).
pub fn validate_pbkdf2_iterations(iterations: u32) -> Result<(), BackendError> {
    if iterations < PBKDF2_MIN_ITERATIONS {
        return Err(BackendError::OperationFailed(format!(
            "PBKDF2 iterations {iterations} is below the minimum of {PBKDF2_MIN_ITERATIONS}"
        )));
    }
    if iterations > PBKDF2_MAX_ITERATIONS {
        return Err(BackendError::OperationFailed(format!(
            "PBKDF2 iterations {iterations} exceeds the maximum of {PBKDF2_MAX_ITERATIONS}"
        )));
    }
    Ok(())
}

/// Cryptographic algorithms supported by backends
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymmetricAlgorithm {
    Aes256Gcm,
    ChaCha20Poly1305,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AsymmetricAlgorithm {
    Ed25519,
    EcdsaP256,
    Rsa2048,
    Rsa4096,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    Ed25519,
    EcdsaP256,
    RsaPkcs1v15,
    RsaPss,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

/// Key derivation context for backends that support key derivation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyDerivationContext {
    /// Salt for key derivation (backend-specific interpretation)
    pub salt: Vec<u8>,
    /// Additional context data (e.g., device ID, session info)
    pub additional_data: Vec<u8>,
    /// Iteration count for PBKDF2-like backends
    pub iterations: Option<u32>,
    /// Hash algorithm to use for derivation
    pub hash_algorithm: Option<HashAlgorithm>,
}

impl KeyDerivationContext {
    pub fn new(salt: Vec<u8>) -> Self {
        Self {
            salt,
            additional_data: Vec::new(),
            iterations: Some(600_000), // OWASP 2023 recommended PBKDF2 iterations
            hash_algorithm: Some(HashAlgorithm::Sha256),
        }
    }

    pub fn with_additional_data(mut self, data: Vec<u8>) -> Self {
        self.additional_data = data;
        self
    }

    /// Set the PBKDF2 iteration count, validating it against the accepted range.
    /// Fallible (no panic) so caller-controlled input can't crash the host; the
    /// point-of-use check during derivation remains authoritative.
    pub fn with_iterations(mut self, iterations: u32) -> Result<Self, BackendError> {
        validate_pbkdf2_iterations(iterations)?;
        self.iterations = Some(iterations);
        Ok(self)
    }

    pub fn with_hash_algorithm(mut self, algorithm: HashAlgorithm) -> Self {
        self.hash_algorithm = Some(algorithm);
        self
    }
}

/// Operations that can be performed by cryptographic backends
#[derive(Debug, Clone)]
pub enum CryptoOperation {
    // Symmetric operations
    Encrypt {
        plaintext: Vec<u8>,
        algorithm: SymmetricAlgorithm,
    },
    Decrypt {
        ciphertext: Vec<u8>,
        algorithm: SymmetricAlgorithm,
    },

    // Asymmetric operations
    Sign {
        data: Vec<u8>,
        algorithm: SignatureAlgorithm,
    },
    Verify {
        data: Vec<u8>,
        signature: Vec<u8>,
        algorithm: SignatureAlgorithm,
    },

    // Key management
    DeriveKey {
        context: KeyDerivationContext,
    },
    GenerateKeyPair {
        algorithm: AsymmetricAlgorithm,
    },
    GetPublicKey,

    // Advanced operations
    KeyExchange {
        peer_public_key: Vec<u8>,
        algorithm: AsymmetricAlgorithm,
    },
    Attest {
        challenge: Vec<u8>,
    }, // For hardware attestation

    // Hash operations
    Hash {
        data: Vec<u8>,
        algorithm: HashAlgorithm,
    },
}

/// Results from cryptographic operations
#[derive(Debug)]
pub enum CryptoResult {
    Encrypted(Vec<u8>),
    Decrypted(Vec<u8>),
    Signed(Vec<u8>),
    VerificationResult(bool),
    DerivedKey([u8; 32]),
    KeyPair {
        public_key: Vec<u8>,
        private_key_id: String,
    },
    PublicKey(Vec<u8>),
    SharedSecret(Vec<u8>),
    AttestationProof(Vec<u8>),
    Hash(Vec<u8>),
}

/// Backend capabilities description
#[derive(Debug, Clone)]
pub struct BackendCapabilities {
    /// Symmetric algorithms supported
    pub symmetric_algorithms: Vec<SymmetricAlgorithm>,
    /// Asymmetric algorithms supported
    pub asymmetric_algorithms: Vec<AsymmetricAlgorithm>,
    /// Signature algorithms supported
    pub signature_algorithms: Vec<SignatureAlgorithm>,
    /// Hash algorithms supported
    pub hash_algorithms: Vec<HashAlgorithm>,
    /// Whether keys are stored in hardware
    pub hardware_backed: bool,
    /// Whether backend supports key derivation
    pub supports_key_derivation: bool,
    /// Whether backend supports key generation
    pub supports_key_generation: bool,
    /// Whether backend supports hardware attestation
    pub supports_attestation: bool,
    /// Maximum key size supported (in bits)
    pub max_key_size: Option<u32>,
}

impl BackendCapabilities {
    /// Create capabilities for a software-only backend
    ///
    /// Returns capabilities for backends that perform operations in software,
    /// such as keyring-based key derivation or software-only hash functions.
    pub fn software_only() -> Self {
        Self {
            symmetric_algorithms: vec![SymmetricAlgorithm::Aes256Gcm],
            asymmetric_algorithms: vec![],
            signature_algorithms: vec![],
            hash_algorithms: vec![HashAlgorithm::Sha256, HashAlgorithm::Sha512],
            hardware_backed: false,
            supports_key_derivation: true,
            supports_key_generation: false,
            supports_attestation: false,
            max_key_size: None,
        }
    }

    /// Create capabilities for a hardware security module
    ///
    /// Returns capabilities typical of hardware security modules, including
    /// support for asymmetric operations, hardware-backed keys, and attestation.
    pub fn hardware_security_module() -> Self {
        Self {
            symmetric_algorithms: vec![SymmetricAlgorithm::Aes256Gcm],
            asymmetric_algorithms: vec![
                AsymmetricAlgorithm::Ed25519,
                AsymmetricAlgorithm::EcdsaP256,
                AsymmetricAlgorithm::Rsa2048,
            ],
            signature_algorithms: vec![
                SignatureAlgorithm::Ed25519,
                SignatureAlgorithm::EcdsaP256,
                SignatureAlgorithm::RsaPkcs1v15,
            ],
            hash_algorithms: vec![
                HashAlgorithm::Sha256,
                HashAlgorithm::Sha384,
                HashAlgorithm::Sha512,
            ],
            hardware_backed: true,
            supports_key_derivation: true,
            supports_key_generation: true,
            supports_attestation: true,
            max_key_size: Some(4096),
        }
    }
}

/// Universal backend trait for all cryptographic operations
pub trait UniversalBackend: Send + Sync {
    /// Perform a cryptographic operation with the specified key
    fn perform_operation(
        &self,
        key_id: &str,
        operation: CryptoOperation,
    ) -> Result<CryptoResult, BackendError>;

    /// Check if this backend supports a specific operation
    fn supports_operation(&self, operation: &CryptoOperation) -> bool;

    /// Get the capabilities of this backend
    fn get_capabilities(&self) -> BackendCapabilities;

    /// Get backend information (name, version, etc.)
    fn backend_info(&self) -> crate::backends::traits::BackendInfo;

    /// List available keys in this backend
    fn list_keys(&self) -> Result<Vec<crate::backends::traits::KeyMetadata>, BackendError> {
        Ok(vec![]) // Default: no key enumeration
    }
}

/// Helper function to check if an operation type is supported by backend capabilities
///
/// This function provides a quick way to check if a backend with the given capabilities
/// can theoretically support an operation type, without actually calling the backend.
///
/// # Arguments
/// * `capabilities` - The capabilities of a backend
/// * `operation` - The operation to check support for
///
/// # Returns
/// `true` if the backend capabilities indicate support for the operation type
pub fn operation_type_supported(
    capabilities: &BackendCapabilities,
    operation: &CryptoOperation,
) -> bool {
    match operation {
        CryptoOperation::Encrypt { algorithm, .. } | CryptoOperation::Decrypt { algorithm, .. } => {
            capabilities.symmetric_algorithms.contains(algorithm)
        }
        CryptoOperation::Sign { algorithm, .. } | CryptoOperation::Verify { algorithm, .. } => {
            capabilities.signature_algorithms.contains(algorithm)
        }
        CryptoOperation::DeriveKey { .. } => capabilities.supports_key_derivation,
        CryptoOperation::GenerateKeyPair { algorithm } => {
            capabilities.supports_key_generation
                && capabilities.asymmetric_algorithms.contains(algorithm)
        }
        CryptoOperation::GetPublicKey => capabilities.supports_key_generation,
        CryptoOperation::KeyExchange { algorithm, .. } => {
            capabilities.asymmetric_algorithms.contains(algorithm)
        }
        CryptoOperation::Attest { .. } => capabilities.supports_attestation,
        CryptoOperation::Hash { algorithm, .. } => capabilities.hash_algorithms.contains(algorithm),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation_context_builder() {
        let context = KeyDerivationContext::new(vec![1, 2, 3, 4])
            .with_additional_data(vec![5, 6, 7, 8])
            .with_iterations(600_000)
            .expect("600k is a valid iteration count")
            .with_hash_algorithm(HashAlgorithm::Sha512);

        assert_eq!(context.salt, vec![1, 2, 3, 4]);
        assert_eq!(context.additional_data, vec![5, 6, 7, 8]);
        assert_eq!(context.iterations, Some(600_000));
        assert_eq!(context.hash_algorithm, Some(HashAlgorithm::Sha512));
    }

    #[test]
    fn test_key_derivation_context_rejects_low_iterations() {
        // Fallible builder (no panic): below-min is Err, not a crash.
        assert!(KeyDerivationContext::new(vec![1, 2, 3, 4])
            .with_iterations(50_000)
            .is_err());
    }

    #[test]
    fn test_validate_pbkdf2_iterations_range() {
        // The authoritative point-of-use gate: reject below-min, zero, and above-max
        // (incl. u32::MAX); accept the in-range endpoints.
        assert!(validate_pbkdf2_iterations(0).is_err());
        assert!(validate_pbkdf2_iterations(PBKDF2_MIN_ITERATIONS - 1).is_err());
        assert!(validate_pbkdf2_iterations(PBKDF2_MAX_ITERATIONS + 1).is_err());
        assert!(validate_pbkdf2_iterations(u32::MAX).is_err());
        assert!(validate_pbkdf2_iterations(PBKDF2_MIN_ITERATIONS).is_ok());
        assert!(validate_pbkdf2_iterations(600_000).is_ok());
        assert!(validate_pbkdf2_iterations(PBKDF2_MAX_ITERATIONS).is_ok());
    }

    #[test]
    fn test_operation_type_supported() {
        let software_caps = BackendCapabilities::software_only();
        let hardware_caps = BackendCapabilities::hardware_security_module();

        // Test key derivation
        let derive_op = CryptoOperation::DeriveKey {
            context: KeyDerivationContext::new(vec![1, 2, 3, 4]),
        };
        assert!(operation_type_supported(&software_caps, &derive_op));
        assert!(operation_type_supported(&hardware_caps, &derive_op));

        // Test signing (software doesn't support, hardware does)
        let sign_op = CryptoOperation::Sign {
            data: vec![1, 2, 3],
            algorithm: SignatureAlgorithm::Ed25519,
        };
        assert!(!operation_type_supported(&software_caps, &sign_op));
        assert!(operation_type_supported(&hardware_caps, &sign_op));

        // Test attestation (only hardware supports)
        let attest_op = CryptoOperation::Attest {
            challenge: vec![1, 2, 3],
        };
        assert!(!operation_type_supported(&software_caps, &attest_op));
        assert!(operation_type_supported(&hardware_caps, &attest_op));
    }

    #[test]
    fn test_backend_capabilities() {
        let software_caps = BackendCapabilities::software_only();
        assert!(!software_caps.hardware_backed);
        assert!(software_caps.supports_key_derivation);
        assert!(!software_caps.supports_key_generation);
        assert!(!software_caps.supports_attestation);

        let hardware_caps = BackendCapabilities::hardware_security_module();
        assert!(hardware_caps.hardware_backed);
        assert!(hardware_caps.supports_key_derivation);
        assert!(hardware_caps.supports_key_generation);
        assert!(hardware_caps.supports_attestation);
    }
}
