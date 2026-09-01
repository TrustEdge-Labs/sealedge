//
// Copyright (c) 2025 TRUSTEDGE LABS LLC
// This source code is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Project: sealedge — Privacy and trust at the edge.
//

use aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce as AesGcmNonce};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chacha20poly1305::XChaCha20Poly1305;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use p256::ecdsa::{
    signature::Verifier as P256Verifier, Signature as P256Signature,
    VerifyingKey as P256VerifyingKey,
};
use pbkdf2::pbkdf2_hmac;
use rand_core::{OsRng, RngCore};
use serde_json::json;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

pub use crate::error::CryptoError;

/// Magic header prefix identifying an encrypted SealEdge key file.
const ENCRYPTED_KEY_HEADER: &str = "SEALEDGE-KEY-V1";

/// Minimum PBKDF2-HMAC-SHA256 iterations per OWASP 2023 guidelines.
/// See: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
const PBKDF2_MIN_ITERATIONS: u32 = 600_000;

/// Device keypair for Ed25519 signing operations
///
/// Note: The secret key is automatically zeroized when dropped for security
pub struct DeviceKeypair {
    pub public: String, // "ed25519:BASE64" format
    secret: [u8; 32],   // Raw secret key bytes (zeroized on drop)
}

impl Drop for DeviceKeypair {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl DeviceKeypair {
    /// Generate a new random Ed25519 keypair
    pub fn generate() -> Result<Self, CryptoError> {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let public = format!("ed25519:{}", BASE64.encode(verifying_key.as_bytes()));
        let secret = signing_key.to_bytes();

        Ok(Self { public, secret })
    }

    /// Export the secret key as "ed25519:BASE64" format
    pub fn export_secret(&self) -> String {
        format!("ed25519:{}", BASE64.encode(self.secret))
    }

    /// Import a keypair from secret key string (accepts "ed25519:BASE64" or hex)
    pub fn import_secret(secret_str: &str) -> Result<Self, CryptoError> {
        // Zeroizing: the decoded raw key must not linger on the heap after it is
        // copied into the ZeroizeOnDrop keypair (F1a — last copy on the import path).
        let secret_bytes = Zeroizing::new(
            if let Some(b64_part) = secret_str.strip_prefix("ed25519:") {
                // Base64 format
                BASE64
                    .decode(b64_part)
                    .map_err(|e| CryptoError::InvalidKeyFormat(format!("Invalid base64: {}", e)))?
            } else if secret_str.len() == 64 {
                // Hex format
                hex::decode(secret_str)
                    .map_err(|e| CryptoError::InvalidKeyFormat(format!("Invalid hex: {}", e)))?
            } else {
                return Err(CryptoError::InvalidKeyFormat(
                    "Must be ed25519:BASE64 or 64-char hex".to_string(),
                ));
            },
        );

        if secret_bytes.len() != 32 {
            return Err(CryptoError::InvalidKeyFormat(
                "Secret key must be 32 bytes".to_string(),
            ));
        }

        let mut secret = [0u8; 32];
        secret.copy_from_slice(&secret_bytes);

        // Compute public key from secret
        let signing_key = SigningKey::from_bytes(&secret);
        let verifying_key = signing_key.verifying_key();
        let public = format!("ed25519:{}", BASE64.encode(verifying_key.as_bytes()));

        Ok(Self { public, secret })
    }

    /// Import from public key string for verification only
    pub fn from_public(public_str: &str) -> Result<VerifyingKey, CryptoError> {
        if !public_str.starts_with("ed25519:") {
            return Err(CryptoError::InvalidKeyFormat(
                "Public key must start with 'ed25519:'".to_string(),
            ));
        }

        let b64_part = &public_str[8..];
        let pub_bytes = BASE64
            .decode(b64_part)
            .map_err(|e| CryptoError::InvalidKeyFormat(format!("Invalid base64: {}", e)))?;

        if pub_bytes.len() != 32 {
            return Err(CryptoError::InvalidKeyFormat(
                "Public key must be 32 bytes".to_string(),
            ));
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&pub_bytes);

        VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| CryptoError::InvalidKeyFormat(format!("Invalid public key: {}", e)))
    }

    /// Get the signing key for internal operations
    fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.secret)
    }

    /// Return the raw 32-byte secret key bytes.
    ///
    /// Use this to pass the device key into key derivation functions such as
    /// `derive_chunk_key`. Avoid storing or logging the returned reference.
    pub fn secret_bytes(&self) -> &[u8; 32] {
        &self.secret
    }

    /// Export the secret key encrypted with a passphrase using PBKDF2-SHA256 + AES-256-GCM.
    ///
    /// Output format:
    /// ```text
    /// SEALEDGE-KEY-V1\n
    /// {"salt":"<b64>","nonce":"<b64>","iterations":600000}\n
    /// <AES-256-GCM ciphertext bytes>
    /// ```
    pub fn export_secret_encrypted(&self, passphrase: &str) -> Result<Vec<u8>, CryptoError> {
        // Generate 32-byte random salt and 12-byte random nonce
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);

        let iterations: u32 = PBKDF2_MIN_ITERATIONS;

        // Derive 32-byte encryption key via PBKDF2-SHA256
        let mut derived_key = [0u8; 32];
        pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), &salt, iterations, &mut derived_key);

        // Encrypt secret key bytes with AES-256-GCM
        let cipher = Aes256Gcm::new_from_slice(&derived_key)
            .map_err(|e| CryptoError::EncryptionFailed(format!("AES key init: {e}")))?;
        derived_key.zeroize();

        let nonce = AesGcmNonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, self.secret.as_ref())
            .map_err(|e| CryptoError::EncryptionFailed(format!("AES-GCM encrypt: {e}")))?;

        // Build output: header\nJSON-metadata\nciphertext
        let metadata = serde_json::json!({
            "version": 1,
            "salt": BASE64.encode(salt),
            "nonce": BASE64.encode(nonce_bytes),
            "iterations": iterations,
        });
        let mut output = Vec::new();
        output.extend_from_slice(ENCRYPTED_KEY_HEADER.as_bytes());
        output.push(b'\n');
        output.extend_from_slice(metadata.to_string().as_bytes());
        output.push(b'\n');
        output.extend_from_slice(&ciphertext);

        Ok(output)
    }

    /// Import a keypair from an encrypted key file using a passphrase.
    ///
    /// Returns `Err(CryptoError::DecryptionFailed)` if the passphrase is wrong or
    /// the file is corrupted.
    pub fn import_secret_encrypted(data: &[u8], passphrase: &str) -> Result<Self, CryptoError> {
        // Parse header line
        let header_end = data
            .iter()
            .position(|&b| b == b'\n')
            .ok_or_else(|| CryptoError::InvalidKeyFormat("Missing header line".into()))?;
        let header = std::str::from_utf8(&data[..header_end])
            .map_err(|_| CryptoError::InvalidKeyFormat("Invalid UTF-8 header".into()))?;
        if header != ENCRYPTED_KEY_HEADER {
            return Err(CryptoError::InvalidKeyFormat(format!(
                "Expected header '{}', got '{}'",
                ENCRYPTED_KEY_HEADER, header
            )));
        }

        // Parse metadata JSON line
        let meta_start = header_end + 1;
        let meta_end = data[meta_start..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|p| meta_start + p)
            .ok_or_else(|| CryptoError::InvalidKeyFormat("Missing metadata line".into()))?;
        let meta_str = std::str::from_utf8(&data[meta_start..meta_end])
            .map_err(|_| CryptoError::InvalidKeyFormat("Invalid UTF-8 metadata".into()))?;
        let meta: serde_json::Value = serde_json::from_str(meta_str)
            .map_err(|e| CryptoError::InvalidKeyFormat(format!("Invalid JSON metadata: {e}")))?;

        let salt = BASE64
            .decode(
                meta["salt"]
                    .as_str()
                    .ok_or_else(|| CryptoError::InvalidKeyFormat("Missing salt".into()))?,
            )
            .map_err(|e| CryptoError::InvalidKeyFormat(format!("Invalid salt base64: {e}")))?;

        let nonce_bytes = BASE64
            .decode(
                meta["nonce"]
                    .as_str()
                    .ok_or_else(|| CryptoError::InvalidKeyFormat("Missing nonce".into()))?,
            )
            .map_err(|e| CryptoError::InvalidKeyFormat(format!("Invalid nonce base64: {e}")))?;

        // Validate as u64 BEFORE narrowing: a value that overflows u32 must be
        // rejected, not silently truncated into an accepted range.
        let iterations_u64 = meta["iterations"]
            .as_u64()
            .ok_or_else(|| CryptoError::InvalidKeyFormat("Missing iterations".into()))?;
        if iterations_u64 < PBKDF2_MIN_ITERATIONS as u64 {
            return Err(CryptoError::InvalidKeyFormat(format!(
                "Key file uses {} PBKDF2 iterations, minimum is {}",
                iterations_u64, PBKDF2_MIN_ITERATIONS
            )));
        }
        let iterations = u32::try_from(iterations_u64)
            .map_err(|_| CryptoError::InvalidKeyFormat("iterations value out of range".into()))?;

        if nonce_bytes.len() != 12 {
            return Err(CryptoError::InvalidKeyFormat(
                "Nonce must be 12 bytes".into(),
            ));
        }

        let ciphertext = &data[meta_end + 1..];

        // Derive key and decrypt
        let mut derived_key = [0u8; 32];
        pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), &salt, iterations, &mut derived_key);

        let cipher = Aes256Gcm::new_from_slice(&derived_key)
            .map_err(|e| CryptoError::EncryptionFailed(format!("AES key init: {e}")))?;
        derived_key.zeroize();

        let nonce = AesGcmNonce::from_slice(&nonce_bytes);
        // Zeroizing: wipe the decrypted raw private key from the heap on drop.
        let plaintext = Zeroizing::new(cipher.decrypt(nonce, ciphertext).map_err(|_| {
            CryptoError::DecryptionFailed("Wrong passphrase or corrupted key file".into())
        })?);

        if plaintext.len() != 32 {
            return Err(CryptoError::InvalidKeyFormat(
                "Decrypted key must be 32 bytes".into(),
            ));
        }

        let mut secret = [0u8; 32];
        secret.copy_from_slice(&plaintext);

        let signing_key = SigningKey::from_bytes(&secret);
        let verifying_key = signing_key.verifying_key();
        let public = format!("ed25519:{}", BASE64.encode(verifying_key.as_bytes()));

        Ok(Self { public, secret })
    }
}

/// Derive a 32-byte XChaCha20Poly1305 key from a 32-byte secret via HKDF-SHA256.
///
/// Uses HKDF-SHA256 (RFC 5869) with an empty salt (high-entropy IKM) and a fixed
/// domain tag `SEALEDGE_SEAL_CHUNK_KEY`. Deterministic: the same input always
/// yields the same key.
///
/// **C4 note:** as of the C4 redesign this is NO LONGER used on the archive path.
/// Content is encrypted under a per-archive random CEK ([`crate::keywrap::ContentKey`])
/// wrapped to recipients via HPKE — content keys must never be derived from the
/// Ed25519 signing secret. Retained only as a general KDF helper (see the SEC-07
/// key-derivation tests); do not wire it back into content encryption.
pub fn derive_chunk_key(device_secret_bytes: &[u8; 32]) -> chacha20poly1305::Key {
    let hkdf = Hkdf::<Sha256>::new(None, device_secret_bytes.as_slice());
    let mut okm = [0u8; 32];
    hkdf.expand(b"SEALEDGE_SEAL_CHUNK_KEY", &mut okm)
        .expect("HKDF expand with 32-byte OKM is always valid");
    chacha20poly1305::Key::from(okm)
}

/// Generate a 24-byte nonce for XChaCha20Poly1305
pub fn generate_nonce24() -> [u8; 24] {
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Format nonce for manifest storage
pub fn format_nonce(nonce: &[u8; 24]) -> String {
    format!("xchacha20:{}", BASE64.encode(nonce))
}

/// Parse nonce from manifest format
pub fn parse_nonce(nonce_str: &str) -> Result<[u8; 24], CryptoError> {
    if !nonce_str.starts_with("xchacha20:") {
        return Err(CryptoError::InvalidNonceFormat(
            "Nonce must start with 'xchacha20:'".to_string(),
        ));
    }

    let b64_part = &nonce_str[10..];
    let nonce_bytes = BASE64
        .decode(b64_part)
        .map_err(|e| CryptoError::InvalidNonceFormat(format!("Invalid base64: {}", e)))?;

    if nonce_bytes.len() != 24 {
        return Err(CryptoError::InvalidNonceFormat(
            "Nonce must be 24 bytes".to_string(),
        ));
    }

    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&nonce_bytes);
    Ok(nonce)
}

/// Encrypt segment data using XChaCha20Poly1305 with AAD
pub fn encrypt_segment(
    key: &chacha20poly1305::Key,
    nonce24: &[u8; 24],
    plaintext: &[u8],
    aad: &[u8], // Additional authenticated data (canonical header fields)
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key);

    cipher
        .encrypt(
            nonce24.into(),
            aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| {
            CryptoError::EncryptionFailed(format!("XChaCha20Poly1305 encryption failed: {}", e))
        })
}

/// Decrypt segment data using XChaCha20Poly1305 with AAD
pub fn decrypt_segment(
    key: &chacha20poly1305::Key,
    nonce24: &[u8; 24],
    ciphertext: &[u8],
    aad: &[u8], // Additional authenticated data (canonical header fields)
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key);

    cipher
        .decrypt(
            nonce24.into(),
            aead::Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|e| {
            CryptoError::DecryptionFailed(format!("XChaCha20Poly1305 decryption failed: {}", e))
        })
}

/// Generate AAD from canonical header fields
pub fn generate_aad(
    trst_version: &str,
    profile: &str,
    device_id: &str,
    started_at: &str,
) -> Vec<u8> {
    let aad_json = json!({
        "trst_version": trst_version,
        "profile": profile,
        "device.id": device_id,
        "capture.started_at": started_at
    });

    // Use compact JSON representation for AAD
    serde_json::to_string(&aad_json)
        .expect("AAD serialization is infallible")
        .into_bytes()
}

/// Detect whether raw bytes represent an encrypted SealEdge key file.
///
/// Returns `true` if `data` starts with `"SEALEDGE-KEY-V1\n"`, which is the
/// magic header written by [`DeviceKeypair::export_secret_encrypted`].
/// Returns `false` for plaintext `"ed25519:…"` key strings and any other content.
pub fn is_encrypted_key_file(data: &[u8]) -> bool {
    data.starts_with(b"SEALEDGE-KEY-V1\n")
}

/// Sign manifest canonical bytes with device secret key
pub fn sign_manifest(
    device_keypair: &DeviceKeypair,
    canonical_bytes: &[u8],
) -> Result<String, CryptoError> {
    let signing_key = device_keypair.signing_key();
    let signature = signing_key.sign(canonical_bytes);

    Ok(format!(
        "ed25519:{}",
        BASE64.encode(signature.to_bytes().as_ref())
    ))
}

/// Verify manifest signature with device public key.
///
/// Dispatches on the signature algorithm prefix:
/// - "ed25519:" — Ed25519 signature verification
/// - "ecdsa-p256:" — ECDSA P-256 (secp256r1) signature verification
///
/// Returns Ok(true) if valid, Ok(false) if the signature does not match,
/// or Err if the key/signature format is invalid or algorithms mismatch.
pub fn verify_manifest(
    device_public: &str,
    canonical_bytes: &[u8],
    signature_str: &str,
) -> Result<bool, CryptoError> {
    if let Some(b64_part) = signature_str.strip_prefix("ed25519:") {
        // Ed25519 path — requires matching "ed25519:" public key
        let verifying_key = DeviceKeypair::from_public(device_public)?;

        let sig_bytes = BASE64
            .decode(b64_part)
            .map_err(|e| CryptoError::InvalidSignatureFormat(format!("Invalid base64: {}", e)))?;

        if sig_bytes.len() != 64 {
            return Err(CryptoError::InvalidSignatureFormat(
                "Ed25519 signature must be 64 bytes".to_string(),
            ));
        }

        let signature = Signature::from_bytes(&sig_bytes.try_into().unwrap());

        match verifying_key.verify(canonical_bytes, &signature) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    } else if signature_str.starts_with("ecdsa-p256:") {
        verify_manifest_ecdsa_p256(device_public, canonical_bytes, signature_str)
    } else {
        Err(CryptoError::InvalidSignatureFormat(
            "Unsupported signature algorithm. Expected ed25519: or ecdsa-p256: prefix".to_string(),
        ))
    }
}

/// Verify a manifest signature using ECDSA P-256 (secp256r1).
///
/// - `device_public`: "ecdsa-p256:<base64_sec1_bytes>" (uncompressed or compressed)
/// - `signature_str`: "ecdsa-p256:<base64_der_encoded_signature>"
///
/// The p256 crate's `verify()` method hashes the message with SHA-256 internally,
/// so `canonical_bytes` is passed directly (not pre-hashed).
fn verify_manifest_ecdsa_p256(
    device_public: &str,
    canonical_bytes: &[u8],
    signature_str: &str,
) -> Result<bool, CryptoError> {
    // Parse public key
    let pub_b64 = device_public.strip_prefix("ecdsa-p256:").ok_or_else(|| {
        CryptoError::InvalidKeyFormat(
            "ECDSA P-256 public key must start with 'ecdsa-p256:'".to_string(),
        )
    })?;
    let pub_bytes = BASE64.decode(pub_b64).map_err(|e| {
        CryptoError::InvalidKeyFormat(format!("Invalid base64 in public key: {}", e))
    })?;
    let verifying_key = P256VerifyingKey::from_sec1_bytes(&pub_bytes)
        .map_err(|e| CryptoError::InvalidKeyFormat(format!("Invalid P-256 public key: {}", e)))?;

    // Parse signature (DER-encoded)
    let sig_b64 = signature_str.strip_prefix("ecdsa-p256:").ok_or_else(|| {
        CryptoError::InvalidSignatureFormat(
            "ECDSA P-256 signature must start with 'ecdsa-p256:'".to_string(),
        )
    })?;
    let sig_bytes = BASE64.decode(sig_b64).map_err(|e| {
        CryptoError::InvalidSignatureFormat(format!("Invalid base64 in signature: {}", e))
    })?;
    let signature = P256Signature::from_der(&sig_bytes).map_err(|e| {
        CryptoError::InvalidSignatureFormat(format!("Invalid P-256 DER signature: {}", e))
    })?;

    // Verify — P256Verifier::verify() hashes with SHA-256 internally
    match P256Verifier::verify(&verifying_key, canonical_bytes, &signature) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_keypair_generation() {
        let keypair = DeviceKeypair::generate().unwrap();
        assert!(keypair.public.starts_with("ed25519:"));

        let exported_secret = keypair.export_secret();
        assert!(exported_secret.starts_with("ed25519:"));
    }

    #[test]
    fn test_device_keypair_import_export() {
        let keypair1 = DeviceKeypair::generate().unwrap();
        let exported_secret = keypair1.export_secret();
        let exported_public = keypair1.public.clone();

        // Import from exported secret
        let keypair2 = DeviceKeypair::import_secret(&exported_secret).unwrap();
        assert_eq!(keypair2.public, exported_public);

        // Test hex import
        let hex_secret = hex::encode(&keypair1.secret);
        let keypair3 = DeviceKeypair::import_secret(&hex_secret).unwrap();
        assert_eq!(keypair3.public, exported_public);
    }

    #[test]
    fn test_public_key_parsing() {
        let keypair = DeviceKeypair::generate().unwrap();
        let verifying_key = DeviceKeypair::from_public(&keypair.public).unwrap();

        // Should be able to parse the public key successfully
        assert_eq!(verifying_key.as_bytes().len(), 32);
    }

    #[test]
    fn test_nonce_generation_and_formatting() {
        let nonce = generate_nonce24();
        assert_eq!(nonce.len(), 24);

        let formatted = format_nonce(&nonce);
        assert!(formatted.starts_with("xchacha20:"));

        let parsed = parse_nonce(&formatted).unwrap();
        assert_eq!(nonce, parsed);
    }

    #[test]
    fn test_round_trip_sign_verify() {
        let keypair = DeviceKeypair::generate().unwrap();
        let test_data = b"test canonical bytes for signing";

        // Sign the data
        let signature = sign_manifest(&keypair, test_data).unwrap();
        assert!(signature.starts_with("ed25519:"));

        // Verify the signature
        let is_valid = verify_manifest(&keypair.public, test_data, &signature).unwrap();
        assert!(is_valid);

        // Verify with wrong data should fail
        let wrong_data = b"wrong data";
        let is_valid_wrong = verify_manifest(&keypair.public, wrong_data, &signature).unwrap();
        assert!(!is_valid_wrong);
    }

    #[test]
    fn test_aead_encrypt_decrypt_round_trip() {
        // Generate key and nonce
        let key = XChaCha20Poly1305::generate_key(&mut OsRng);
        let nonce = generate_nonce24();

        // Test data
        let plaintext = b"test segment data for encryption";
        let aad = generate_aad("0.1.0", "cam.video", "TEST001", "2025-01-15T10:30:00Z");

        // Encrypt
        let ciphertext = encrypt_segment(&key, &nonce, plaintext, &aad).unwrap();
        assert_ne!(ciphertext, plaintext);

        // Decrypt
        let decrypted = decrypt_segment(&key, &nonce, &ciphertext, &aad).unwrap();
        assert_eq!(decrypted, plaintext);

        // Decrypt with wrong AAD should fail
        let wrong_aad = generate_aad("0.1.0", "cam.video", "WRONG", "2025-01-15T10:30:00Z");
        let result = decrypt_segment(&key, &nonce, &ciphertext, &wrong_aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_aad_generation() {
        let aad = generate_aad("0.1.0", "cam.video", "TEST001", "2025-01-15T10:30:00Z");
        let aad_str = String::from_utf8(aad).unwrap();

        // Should contain all the required fields
        assert!(aad_str.contains("0.1.0"));
        assert!(aad_str.contains("cam.video"));
        assert!(aad_str.contains("TEST001"));
        assert!(aad_str.contains("2025-01-15T10:30:00Z"));
    }

    #[test]
    fn test_base64_encoding_decoding() {
        let test_data = b"Hello, World! This is a test.";
        let encoded = BASE64.encode(test_data);
        let decoded = BASE64.decode(&encoded).unwrap();
        assert_eq!(test_data.to_vec(), decoded);
    }

    #[test]
    fn test_secret_zeroization() {
        let mut secret_bytes = [42u8; 32];

        {
            let _keypair = DeviceKeypair::generate().unwrap();
            // Keypair exists in this scope
        } // Keypair is dropped here and secret should be zeroized

        // We can't directly test that the memory was zeroized since it's private,
        // but we can test that zeroize works on our test data
        secret_bytes.zeroize();
        assert_eq!(secret_bytes, [0u8; 32]);
    }

    #[test]
    fn test_derive_chunk_key_deterministic() {
        let input = [0xABu8; 32];
        let key1 = derive_chunk_key(&input);
        let key2 = derive_chunk_key(&input);
        assert_eq!(key1.as_slice(), key2.as_slice());
    }

    #[test]
    fn test_derive_chunk_key_different_inputs() {
        let input_a = [0x01u8; 32];
        let input_b = [0x02u8; 32];
        let key_a = derive_chunk_key(&input_a);
        let key_b = derive_chunk_key(&input_b);
        assert_ne!(key_a.as_slice(), key_b.as_slice());
    }

    #[test]
    fn test_secret_bytes_accessor() {
        let keypair = DeviceKeypair::generate().unwrap();
        let secret = keypair.secret_bytes();
        assert_eq!(secret.len(), 32);

        // Round-trip: export secret string, import, compare secret bytes
        let exported = keypair.export_secret();
        let imported = DeviceKeypair::import_secret(&exported).unwrap();
        assert_eq!(keypair.secret_bytes(), imported.secret_bytes());
    }

    // ─── ECDSA P-256 tests ────────────────────────────────────────────────────

    #[test]
    fn test_ecdsa_p256_sign_verify_round_trip() {
        use p256::ecdsa::{signature::Signer as _, SigningKey as P256SigningKey};

        let signing_key = P256SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let canonical_bytes = b"test canonical bytes for p256 signing";

        // Sign: returns a fixed-size ECDSA signature which we DER-encode
        let signature: p256::ecdsa::Signature = signing_key.sign(canonical_bytes);
        let sig_der = signature.to_der();
        let sig_str = format!("ecdsa-p256:{}", BASE64.encode(sig_der.as_bytes()));

        // Format public key as SEC1 uncompressed bytes
        let pub_bytes = verifying_key.to_encoded_point(false);
        let pub_str = format!("ecdsa-p256:{}", BASE64.encode(pub_bytes.as_bytes()));

        let result = verify_manifest(&pub_str, canonical_bytes, &sig_str).unwrap();
        assert!(result, "ECDSA P-256 signature should verify correctly");
    }

    #[test]
    fn test_ecdsa_p256_wrong_data() {
        use p256::ecdsa::{signature::Signer as _, SigningKey as P256SigningKey};

        let signing_key = P256SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let canonical_bytes = b"original data";
        let wrong_data = b"tampered data";

        let signature: p256::ecdsa::Signature = signing_key.sign(canonical_bytes);
        let sig_der = signature.to_der();
        let sig_str = format!("ecdsa-p256:{}", BASE64.encode(sig_der.as_bytes()));

        let pub_bytes = verifying_key.to_encoded_point(false);
        let pub_str = format!("ecdsa-p256:{}", BASE64.encode(pub_bytes.as_bytes()));

        // Verify against wrong data should return Ok(false)
        let result = verify_manifest(&pub_str, wrong_data, &sig_str).unwrap();
        assert!(
            !result,
            "ECDSA P-256 signature with wrong data should return false"
        );
    }

    #[test]
    fn test_ed25519_still_works_after_dispatch() {
        // Regression: Ed25519 verification must still work after multi-algorithm dispatch
        let keypair = DeviceKeypair::generate().unwrap();
        let test_data = b"ed25519 regression test after p256 dispatch";

        let signature = sign_manifest(&keypair, test_data).unwrap();
        assert!(signature.starts_with("ed25519:"));

        let is_valid = verify_manifest(&keypair.public, test_data, &signature).unwrap();
        assert!(
            is_valid,
            "Ed25519 must still verify correctly after dispatch refactor"
        );
    }

    #[test]
    fn test_unknown_signature_prefix() {
        let keypair = DeviceKeypair::generate().unwrap();
        let test_data = b"some data";

        let result = verify_manifest(&keypair.public, test_data, "rsa:AAAA");
        assert!(
            result.is_err(),
            "Unknown signature prefix should return Err"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Unsupported signature algorithm"),
            "Error message should mention 'Unsupported signature algorithm', got: {err_msg}"
        );
    }

    // ─── Encrypted key file tests ─────────────────────────────────────────────

    #[test]
    fn test_encrypted_key_roundtrip() {
        let keypair = DeviceKeypair::generate().unwrap();
        let original_secret = *keypair.secret_bytes();

        let encrypted = keypair.export_secret_encrypted("test123").unwrap();
        let imported = DeviceKeypair::import_secret_encrypted(&encrypted, "test123").unwrap();

        assert_eq!(&original_secret, imported.secret_bytes());
        assert_eq!(keypair.public, imported.public);
    }

    #[test]
    fn test_encrypted_key_wrong_passphrase() {
        let keypair = DeviceKeypair::generate().unwrap();
        let encrypted = keypair
            .export_secret_encrypted("correct-passphrase")
            .unwrap();

        let result = DeviceKeypair::import_secret_encrypted(&encrypted, "wrong-passphrase");
        assert!(
            result.is_err(),
            "Wrong passphrase must return Err, not Ok with garbage data"
        );
    }

    #[test]
    fn test_encrypted_key_rejects_low_iterations() {
        // Build a synthetic key file with below-minimum iterations.
        // We manually construct the file format to bypass export_secret_encrypted.
        use aes_gcm::aead::Aead;
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce as AesGcmNonce};
        use pbkdf2::pbkdf2_hmac;
        use sha2::Sha256;

        let passphrase = "test";
        let low_iterations: u32 = 299_999;
        let salt = [1u8; 16];
        let nonce_bytes = [2u8; 12];
        let plaintext = [3u8; 32];

        let mut derived_key = [0u8; 32];
        pbkdf2_hmac::<Sha256>(
            passphrase.as_bytes(),
            &salt,
            low_iterations,
            &mut derived_key,
        );

        let cipher = Aes256Gcm::new_from_slice(&derived_key).unwrap();
        let nonce = AesGcmNonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();

        let meta = serde_json::json!({
            "salt": BASE64.encode(salt),
            "nonce": BASE64.encode(nonce_bytes),
            "iterations": low_iterations,
        });

        let mut file_data = format!("SEALEDGE-KEY-V1\n{}\n", meta).into_bytes();
        file_data.extend_from_slice(&ciphertext);

        let result = DeviceKeypair::import_secret_encrypted(&file_data, passphrase);
        assert!(
            result.is_err(),
            "Should reject key file with low iteration count"
        );
        let err_msg = result.err().unwrap().to_string();
        assert!(
            err_msg.contains("299999") || err_msg.contains("minimum"),
            "Error should mention the iteration count or minimum: {err_msg}"
        );
    }

    #[test]
    fn test_is_encrypted_key_file() {
        // True: starts with SEALEDGE-KEY-V1\n
        assert!(is_encrypted_key_file(b"SEALEDGE-KEY-V1\nsome data"));
        // False: plaintext ed25519: prefix
        assert!(!is_encrypted_key_file(b"ed25519:AAAA"));
        // False: empty
        assert!(!is_encrypted_key_file(b""));
        // False: random bytes
        assert!(!is_encrypted_key_file(b"\x00\x01\x02\x03"));
    }

    #[test]
    fn test_encrypted_key_format() {
        let keypair = DeviceKeypair::generate().unwrap();
        let encrypted = keypair.export_secret_encrypted("test-passphrase").unwrap();

        // First line must be SEALEDGE-KEY-V1
        let first_newline = encrypted.iter().position(|&b| b == b'\n').unwrap();
        let header = std::str::from_utf8(&encrypted[..first_newline]).unwrap();
        assert_eq!(header, "SEALEDGE-KEY-V1");

        // Second line must be valid JSON with salt, nonce, iterations
        let rest = &encrypted[first_newline + 1..];
        let second_newline = rest.iter().position(|&b| b == b'\n').unwrap();
        let meta_str = std::str::from_utf8(&rest[..second_newline]).unwrap();
        let meta: serde_json::Value = serde_json::from_str(meta_str).unwrap();

        assert!(meta["salt"].is_string(), "metadata must have salt field");
        assert!(meta["nonce"].is_string(), "metadata must have nonce field");
        assert!(
            meta["iterations"].is_number(),
            "metadata must have iterations field"
        );
        assert_eq!(meta["iterations"].as_u64().unwrap(), 600_000);
    }

    /// D-02 clean-break rejection: a buffer prefixed with the legacy TRUSTEDGE-KEY-V1
    /// magic bytes must be rejected by both is_encrypted_key_file() and the import
    /// path. No silent legacy fall-through (per CONTEXT.md §Decisions D-02 and
    /// Claude's Discretion: magic header detection function).
    #[test]
    fn test_old_header_rejected_cleanly() {
        const OLD_KEY_HEADER: &[u8] = b"TRUSTEDGE-KEY-V1";

        // Build a minimally plausible legacy-era buffer: old header + newline +
        // valid-looking JSON metadata + newline + 48 bytes of junk ciphertext.
        let mut legacy_buf: Vec<u8> = Vec::new();
        legacy_buf.extend_from_slice(OLD_KEY_HEADER);
        legacy_buf.push(b'\n');
        let meta = serde_json::json!({
            "version": 1,
            "salt": BASE64.encode([0u8; 32]),
            "nonce": BASE64.encode([0u8; 12]),
            "iterations": 600_000u32,
        });
        legacy_buf.extend_from_slice(meta.to_string().as_bytes());
        legacy_buf.push(b'\n');
        legacy_buf.extend_from_slice(&[0u8; 48]);

        // Detection fn rejects the legacy prefix — it only matches SEALEDGE-KEY-V1\n.
        assert!(
            !is_encrypted_key_file(&legacy_buf),
            "is_encrypted_key_file must NOT accept legacy TRUSTEDGE-KEY-V1 prefix"
        );

        // Import path rejects with a clear InvalidKeyFormat error (not silent decrypt).
        let result = DeviceKeypair::import_secret_encrypted(&legacy_buf, "any-passphrase");
        match result {
            Err(CryptoError::InvalidKeyFormat(msg)) => {
                assert!(
                    msg.contains("Expected header"),
                    "import error should mention expected-header mismatch, got: {msg}"
                );
            }
            Err(other) => panic!("expected InvalidKeyFormat on legacy header, got: {other:?}"),
            Ok(_) => panic!("legacy TRUSTEDGE-KEY-V1 header must not import successfully"),
        }
    }

    /// D-02 clean-break tests for the chunk-key HKDF domain. Per CONTEXT.md
    /// §Decisions D-02 — shadow const lives only in this test module, zero
    /// production footprint for the old value.
    mod clean_break_chunk_key_tests {
        use hkdf::Hkdf;
        use sha2::Sha256;

        /// Legacy HKDF info used before Phase 85 — kept ONLY in this test module.
        const OLD_CHUNK_KEY_DOMAIN: &[u8] = b"TRUSTEDGE_TRST_CHUNK_KEY";

        fn hkdf_expand_32(info: &[u8]) -> [u8; 32] {
            let ikm = [0x42u8; 32];
            let hkdf = Hkdf::<Sha256>::new(None, &ikm);
            let mut okm = [0u8; 32];
            hkdf.expand(info, &mut okm)
                .expect("HKDF expand with 32-byte OKM is always valid");
            okm
        }

        /// KAT: legacy and new chunk-key domains produce DISTINCT 32-byte OKMs
        /// for identical IKM. Proves HKDF domain separation is active.
        #[test]
        fn test_old_chunk_key_domain_produces_distinct_okm() {
            let okm_old = hkdf_expand_32(OLD_CHUNK_KEY_DOMAIN);
            let okm_new = hkdf_expand_32(b"SEALEDGE_SEAL_CHUNK_KEY");
            assert_ne!(
                okm_old, okm_new,
                "chunk-key HKDF domain separation failed: legacy and new info values must produce distinct 32-byte OKMs"
            );
        }

        /// D-02 rejection: a chunk encrypted under a key derived with the
        /// OLD_CHUNK_KEY_DOMAIN must fail to decrypt under a key derived with
        /// SEALEDGE_SEAL_CHUNK_KEY. Asserted at the key-material layer:
        /// distinct 32-byte AEAD keys imply XChaCha20Poly1305 tag failure.
        #[test]
        fn test_old_chunk_key_domain_rejected_cleanly() {
            let old_key = hkdf_expand_32(OLD_CHUNK_KEY_DOMAIN);
            let new_key = hkdf_expand_32(b"SEALEDGE_SEAL_CHUNK_KEY");
            assert_ne!(
                old_key, new_key,
                "chunk-key 32-byte AEAD keys derived under the two domains must differ — \
                 otherwise XChaCha20Poly1305 tag verification would NOT reject legacy chunks"
            );
        }
    }
}
