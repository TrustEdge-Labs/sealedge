//
// Copyright (c) 2025 TRUSTEDGE LABS LLC
// This source code is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Project: sealedge — Privacy and trust at the edge.
//

//! Universal keyring backend implementation
//!
//! This module implements the UniversalBackend trait for the OS keyring,
//! supporting key derivation and hash operations.

use crate::backends::keyring::KeyringBackend;
use crate::backends::traits::{BackendInfo, KeyMetadata};
use crate::backends::universal::*;
use crate::error::BackendError;
use anyhow::{anyhow, Result};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

/// Universal backend wrapper for KeyringBackend
///
/// UniversalKeyringBackend implements the UniversalBackend trait for OS keyring
/// operations, providing key derivation and hash operations using the system
/// keyring for secure passphrase storage.
pub struct UniversalKeyringBackend {
    inner: KeyringBackend,
}

impl UniversalKeyringBackend {
    /// Create a new universal keyring backend
    pub fn new() -> Result<Self> {
        Ok(Self {
            inner: KeyringBackend::new()?,
        })
    }

    /// Create with custom service/username
    pub fn new_with_service(service_name: String, username: String) -> Result<Self> {
        Ok(Self {
            inner: KeyringBackend::new_with_service(service_name, username)?,
        })
    }

    /// Store a passphrase in the keyring
    pub fn store_passphrase(&self, passphrase: &str) -> Result<()> {
        self.inner.store_passphrase(passphrase)
    }

    /// Get the passphrase from the keyring
    pub fn get_passphrase(&self) -> Result<String> {
        self.inner.get_passphrase()
    }

    /// Derive a key using the specified context
    fn derive_key_internal(
        &self,
        key_id: &str,
        context: &KeyDerivationContext,
    ) -> Result<[u8; 32]> {
        // Validate salt length
        if context.salt.len() != 32 {
            return Err(anyhow!("Salt must be exactly 32 bytes for keyring backend"));
        }

        // Validate the PBKDF2 work factor (min AND max) before any keyring I/O. This
        // is the authoritative point-of-use gate — `iterations` is caller-controlled
        // via the pub, Deserialize-able KeyDerivationContext, so an upper bound here
        // prevents an unbounded-work-factor DoS (e.g. u32::MAX ≈ an hour of CPU).
        let iterations = context.iterations.unwrap_or(600_000);
        crate::backends::universal::validate_pbkdf2_iterations(iterations)?;

        // Get passphrase from keyring
        let passphrase = self
            .get_passphrase()
            .map_err(|e| anyhow!("Failed to get passphrase from keyring: {}", e))?;

        // Convert salt to array
        let mut salt_array = [0u8; 32];
        salt_array.copy_from_slice(&context.salt);
        let mut key = [0u8; 32];

        // Include key_id in the derivation for key isolation
        let mut input = passphrase.as_bytes().to_vec();
        input.extend_from_slice(key_id.as_bytes());
        input.extend_from_slice(&context.additional_data);

        // Use the hash algorithm from context or default to SHA-256
        match context
            .hash_algorithm
            .as_ref()
            .unwrap_or(&HashAlgorithm::Sha256)
        {
            HashAlgorithm::Sha256 => {
                pbkdf2_hmac::<Sha256>(&input, &salt_array, iterations, &mut key);
            }
            HashAlgorithm::Sha384 => {
                pbkdf2_hmac::<sha2::Sha384>(&input, &salt_array, iterations, &mut key);
            }
            HashAlgorithm::Sha512 => {
                pbkdf2_hmac::<sha2::Sha512>(&input, &salt_array, iterations, &mut key);
            }
        }

        Ok(key)
    }
}

impl UniversalBackend for UniversalKeyringBackend {
    fn perform_operation(
        &self,
        key_id: &str,
        operation: CryptoOperation,
    ) -> Result<CryptoResult, BackendError> {
        match operation {
            CryptoOperation::DeriveKey { context } => {
                let key = self.derive_key_internal(key_id, &context).map_err(|e| {
                    BackendError::OperationFailed(format!("Key derivation failed: {}", e))
                })?;
                Ok(CryptoResult::DerivedKey(key))
            }

            CryptoOperation::Encrypt {
                plaintext: _,
                algorithm,
            } => match algorithm {
                SymmetricAlgorithm::Aes256Gcm => {
                    // We need to derive a key first, but we need context
                    // For now, use a simple approach - in practice, the key would be provided
                    // or derived using a stored context
                    Err(BackendError::UnsupportedOperation(
                        "Encryption requires key derivation context. Use DeriveKey first, then use the raw key.".to_string()
                    ))
                }
                _ => Err(BackendError::UnsupportedOperation(format!(
                    "Symmetric algorithm {:?} not supported by keyring backend",
                    algorithm
                ))),
            },

            CryptoOperation::Decrypt {
                ciphertext: _,
                algorithm,
            } => match algorithm {
                SymmetricAlgorithm::Aes256Gcm => {
                    // Same issue as encrypt - need a way to get the key
                    Err(BackendError::UnsupportedOperation(
                        "Decryption requires key derivation context. Use DeriveKey first, then use the raw key.".to_string()
                    ))
                }
                _ => Err(BackendError::UnsupportedOperation(format!(
                    "Symmetric algorithm {:?} not supported by keyring backend",
                    algorithm
                ))),
            },

            CryptoOperation::Hash { data, algorithm } => match algorithm {
                HashAlgorithm::Sha256 => {
                    use sha2::{Digest, Sha256};
                    let hash = Sha256::digest(&data);
                    Ok(CryptoResult::Hash(hash.to_vec()))
                }
                HashAlgorithm::Sha384 => {
                    use sha2::{Digest, Sha384};
                    let hash = Sha384::digest(&data);
                    Ok(CryptoResult::Hash(hash.to_vec()))
                }
                HashAlgorithm::Sha512 => {
                    use sha2::{Digest, Sha512};
                    let hash = Sha512::digest(&data);
                    Ok(CryptoResult::Hash(hash.to_vec()))
                }
            },

            _ => Err(BackendError::UnsupportedOperation(format!(
                "Operation {:?} not supported by keyring backend",
                operation
            ))),
        }
    }

    fn supports_operation(&self, operation: &CryptoOperation) -> bool {
        matches!(
            operation,
            CryptoOperation::DeriveKey { .. }
                | CryptoOperation::Hash {
                    algorithm: HashAlgorithm::Sha256
                        | HashAlgorithm::Sha384
                        | HashAlgorithm::Sha512,
                    ..
                }
        )
    }

    fn get_capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            symmetric_algorithms: vec![], // We support AES-256-GCM but need better key management
            asymmetric_algorithms: vec![],
            signature_algorithms: vec![],
            hash_algorithms: vec![
                HashAlgorithm::Sha256,
                HashAlgorithm::Sha384,
                HashAlgorithm::Sha512,
            ],
            hardware_backed: false,
            supports_key_derivation: true,
            supports_key_generation: false,
            supports_attestation: false,
            max_key_size: None,
        }
    }

    fn backend_info(&self) -> BackendInfo {
        BackendInfo::keyring()
    }

    fn list_keys(&self) -> Result<Vec<KeyMetadata>, BackendError> {
        // Delegate to the inner keyring backend
        use crate::backends::traits::KeyBackend;
        self.inner.list_keys()
    }
}

impl Default for UniversalKeyringBackend {
    fn default() -> Self {
        Self::new().expect("Failed to create default universal keyring backend")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_universal_keyring_backend_creation() {
        let backend = UniversalKeyringBackend::new();
        assert!(backend.is_ok());
    }

    #[test]
    fn test_backend_capabilities() {
        let backend = UniversalKeyringBackend::new().unwrap();
        let capabilities = backend.get_capabilities();

        assert!(capabilities.supports_key_derivation);
        assert!(!capabilities.supports_key_generation);
        assert!(!capabilities.supports_attestation);
        assert!(!capabilities.hardware_backed);
        assert!(capabilities
            .hash_algorithms
            .contains(&HashAlgorithm::Sha256));
    }

    #[test]
    fn test_supports_operation() {
        let backend = UniversalKeyringBackend::new().unwrap();

        // Should support key derivation
        let derive_op = CryptoOperation::DeriveKey {
            context: KeyDerivationContext::new(vec![1; 32]),
        };
        assert!(backend.supports_operation(&derive_op));

        // Should support hashing
        let hash_op = CryptoOperation::Hash {
            data: vec![1, 2, 3],
            algorithm: HashAlgorithm::Sha256,
        };
        assert!(backend.supports_operation(&hash_op));

        // Should not support signing
        let sign_op = CryptoOperation::Sign {
            data: vec![1, 2, 3],
            algorithm: SignatureAlgorithm::Ed25519,
        };
        assert!(!backend.supports_operation(&sign_op));

        // Should not support attestation
        let attest_op = CryptoOperation::Attest {
            challenge: vec![1, 2, 3],
        };
        assert!(!backend.supports_operation(&attest_op));
    }

    #[test]
    fn test_hash_operation() {
        let backend = UniversalKeyringBackend::new().unwrap();
        let test_data = b"hello world";

        let result = backend.perform_operation(
            "test_key",
            CryptoOperation::Hash {
                data: test_data.to_vec(),
                algorithm: HashAlgorithm::Sha256,
            },
        );

        assert!(result.is_ok());
        if let Ok(CryptoResult::Hash(hash)) = result {
            assert_eq!(hash.len(), 32); // SHA-256 produces 32-byte hashes
        } else {
            panic!("Expected CryptoResult::Hash");
        }
    }

    #[test]
    fn test_key_derivation_operation() {
        let backend = UniversalKeyringBackend::new().unwrap();

        // This test will fail if no passphrase is stored in keyring
        // but should show the operation structure works
        let context = KeyDerivationContext::new(vec![1; 32])
            .with_additional_data(vec![2, 3, 4])
            .with_iterations(600_000)
            .expect("600k is a valid iteration count");

        let result = backend.perform_operation("test_key", CryptoOperation::DeriveKey { context });

        // May fail due to missing keyring passphrase, but should not panic
        match result {
            Ok(CryptoResult::DerivedKey(key)) => {
                assert_eq!(key.len(), 32);
            }
            Err(_) => {
                // Expected if no passphrase in keyring
                println!("Key derivation failed (likely no passphrase in keyring) - this is expected in tests");
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_pbkdf2_iterations_out_of_range_rejected() {
        // Fallible builder — no panic on caller-controlled input. Below-min, zero,
        // and above-max (incl. u32::MAX) are Err; the in-range endpoints are Ok.
        let mk = |n: u32| KeyDerivationContext::new(vec![1; 32]).with_iterations(n);
        assert!(mk(0).is_err());
        assert!(mk(1000).is_err());
        assert!(mk(299_999).is_err());
        assert!(mk(u32::MAX).is_err());
        assert!(mk(10_000_001).is_err());
        assert!(mk(300_000).is_ok());
        assert!(mk(10_000_000).is_ok());
    }
}
