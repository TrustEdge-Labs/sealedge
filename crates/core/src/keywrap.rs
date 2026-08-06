//
// Copyright (c) 2025 TRUSTEDGE LABS LLC
// This source code is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Project: sealedge — Privacy and trust at the edge.
//

//! Content-encryption primitives for the C4 redesign (`trst_version` 0.2.0).
//!
//! This module keeps the Ed25519 signing key strictly for signing and moves
//! confidentiality onto:
//!
//! - an **independent X25519 key-agreement key** ([`KeyAgreementKeypair`]),
//! - a **per-archive random Content-Encryption Key** ([`ContentKey`]) that keys
//!   the chunk AEAD, and
//! - **HPKE (RFC 9180)** wrapping of that CEK to one or more recipients with
//!   ephemeral sender keys ([`hpke_seal_cek`] / [`hpke_open_cek`]) — the source
//!   of forward secrecy.
//!
//! The `SEALEDGE-KEY-V2` [`DeviceBundle`] stores both secrets at rest.
//!
//! HPKE suite: `DHKEM(X25519, HKDF-SHA256)` / `HKDF-SHA256` / `ChaCha20Poly1305`
//! (base mode). Pinned via `hpke` 0.12 to match the workspace crypto generation.
//! As of C4 Phase 3 the archive path uses these primitives exclusively;
//! `crate::crypto::derive_chunk_key` is no longer on the content-encryption path.

use aead::{Aead as _, KeyInit as _};
use aes_gcm::{Aes256Gcm, Nonce as AesGcmNonce};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable,
    Kem as KemTrait, OpModeR, OpModeS, Serializable,
};
use pbkdf2::pbkdf2_hmac;
use rand_core::{CryptoRng, OsRng, RngCore, SeedableRng};
use sha2::Sha256;
use x25519_dalek::{PublicKey as XPublic, StaticSecret as XSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::{CryptoError, DeviceKeypair};

/// HPKE ciphersuite (RFC 9180) — must match the manifest `encryption.hpke` block.
type HpkeKem = X25519HkdfSha256;
type HpkeKdf = HkdfSha256;
type HpkeAead = ChaCha20Poly1305;

/// Wire identifiers advertised in the manifest `encryption.hpke` block.
pub const HPKE_KEM_ID: &str = "DHKEM(X25519,HKDF-SHA256)";
pub const HPKE_KDF_ID: &str = "HKDF-SHA256";
pub const HPKE_AEAD_ID: &str = "ChaCha20Poly1305";
/// Content AEAD identifier advertised in `encryption.content_aead`.
pub const CONTENT_AEAD_ID: &str = "XChaCha20Poly1305";

const KEY_AGREEMENT_PREFIX: &str = "x25519:";
const BUNDLE_HEADER_V2: &str = "SEALEDGE-KEY-V2";
/// Minimum PBKDF2-HMAC-SHA256 iterations (OWASP 2023). Mirrors `crypto.rs`.
const PBKDF2_MIN_ITERATIONS: u32 = 600_000;
/// Maximum accepted PBKDF2 iterations. Legitimate writers use exactly the floor;
/// this ceiling (generous headroom over 600k) rejects a corrupt or hostile blob
/// that sets an absurd count to stall decryption — an availability guard
/// symmetric with the floor. F2.
const PBKDF2_MAX_ITERATIONS: u32 = 10_000_000;

/// On-disk header for a generic sealed secret — distinct from
/// [`BUNDLE_HEADER_V2`] so a single-secret blob and a dual-key bundle can never
/// be confused on load.
pub const SEALED_SECRET_HEADER_V1: &str = "SEALEDGE-SEALED-V1";

/// Encrypt arbitrary secret bytes at rest with PBKDF2-HMAC-SHA256 (600k) +
/// AES-256-GCM — the same scheme the `SEALEDGE-KEY-V2` bundle uses, exposed for
/// single-secret custody (e.g. the platform's JWKS signing key). Format:
/// `SEALEDGE-SEALED-V1\n{"version":1,"salt","nonce","iterations"}\n<ciphertext>`.
pub fn seal_secret(secret: &[u8], passphrase: &str) -> Result<Vec<u8>, CryptoError> {
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let iterations = PBKDF2_MIN_ITERATIONS;

    let mut derived_key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), &salt, iterations, &mut derived_key);
    let cipher = Aes256Gcm::new_from_slice(&derived_key)
        .map_err(|e| CryptoError::EncryptionFailed(format!("AES key init: {e}")))?;
    derived_key.zeroize();

    let ciphertext = cipher
        .encrypt(AesGcmNonce::from_slice(&nonce_bytes), secret)
        .map_err(|e| CryptoError::EncryptionFailed(format!("AES-GCM encrypt: {e}")))?;

    let metadata = serde_json::json!({
        "version": 1,
        "salt": BASE64.encode(salt),
        "nonce": BASE64.encode(nonce_bytes),
        "iterations": iterations,
    });
    let mut out = Vec::new();
    out.extend_from_slice(SEALED_SECRET_HEADER_V1.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(metadata.to_string().as_bytes());
    out.push(b'\n');
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt bytes produced by [`seal_secret`]. Wrong passphrase, corruption, a
/// foreign header, or a below-minimum iteration count all return `Err`. The
/// recovered plaintext is zeroized on drop.
pub fn open_secret(data: &[u8], passphrase: &str) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let header_end = data
        .iter()
        .position(|&b| b == b'\n')
        .ok_or_else(|| CryptoError::InvalidKeyFormat("Missing header line".into()))?;
    let header = std::str::from_utf8(&data[..header_end])
        .map_err(|_| CryptoError::InvalidKeyFormat("Invalid UTF-8 header".into()))?;
    if header != SEALED_SECRET_HEADER_V1 {
        return Err(CryptoError::InvalidKeyFormat(format!(
            "Expected header '{SEALED_SECRET_HEADER_V1}', got '{header}'"
        )));
    }

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
        .decode(meta["salt"].as_str().unwrap_or_default())
        .map_err(|e| CryptoError::InvalidKeyFormat(format!("Invalid salt base64: {e}")))?;
    let nonce_bytes = BASE64
        .decode(meta["nonce"].as_str().unwrap_or_default())
        .map_err(|e| CryptoError::InvalidKeyFormat(format!("Invalid nonce base64: {e}")))?;
    let iterations_u64 = meta["iterations"]
        .as_u64()
        .ok_or_else(|| CryptoError::InvalidKeyFormat("Missing iterations".into()))?;
    if iterations_u64 < PBKDF2_MIN_ITERATIONS as u64 {
        return Err(CryptoError::InvalidKeyFormat(format!(
            "Sealed secret uses {iterations_u64} PBKDF2 iterations, minimum is {PBKDF2_MIN_ITERATIONS}"
        )));
    }
    if iterations_u64 > PBKDF2_MAX_ITERATIONS as u64 {
        return Err(CryptoError::InvalidKeyFormat(format!(
            "Sealed secret uses {iterations_u64} PBKDF2 iterations, maximum is {PBKDF2_MAX_ITERATIONS}"
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
    let mut derived_key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), &salt, iterations, &mut derived_key);
    let cipher = Aes256Gcm::new_from_slice(&derived_key)
        .map_err(|e| CryptoError::EncryptionFailed(format!("AES key init: {e}")))?;
    derived_key.zeroize();

    let plaintext = cipher
        .decrypt(AesGcmNonce::from_slice(&nonce_bytes), ciphertext)
        .map_err(|_| {
            CryptoError::DecryptionFailed("Wrong passphrase or corrupted sealed secret".into())
        })?;
    Ok(Zeroizing::new(plaintext))
}

// ─── X25519 key-agreement keypair ─────────────────────────────────────────────

/// An independent X25519 key-agreement keypair (HPKE recipient identity).
///
/// Distinct from the Ed25519 signing key — a signer cannot decrypt and a
/// recipient cannot forge.
pub struct KeyAgreementKeypair {
    secret: [u8; 32],
    public: [u8; 32],
}

impl Drop for KeyAgreementKeypair {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl KeyAgreementKeypair {
    /// Generate a fresh random X25519 keypair.
    pub fn generate() -> Self {
        let secret = XSecret::random_from_rng(OsRng);
        let public = XPublic::from(&secret);
        Self {
            secret: secret.to_bytes(),
            public: public.to_bytes(),
        }
    }

    /// Public key in `x25519:<base64>` wire form.
    pub fn public_string(&self) -> String {
        format!("{}{}", KEY_AGREEMENT_PREFIX, BASE64.encode(self.public))
    }

    /// Secret key in `x25519:<base64>` form (handle with care).
    pub fn export_secret(&self) -> String {
        format!("{}{}", KEY_AGREEMENT_PREFIX, BASE64.encode(self.secret))
    }

    /// Import from an `x25519:<base64>` secret string; the public key is derived.
    pub fn import_secret(secret_str: &str) -> Result<Self, CryptoError> {
        let secret = parse_x25519_bytes(secret_str)?;
        let public = XPublic::from(&XSecret::from(secret)).to_bytes();
        Ok(Self { secret, public })
    }

    /// Raw public key bytes.
    pub fn public_bytes(&self) -> &[u8; 32] {
        &self.public
    }
}

/// Parse an `x25519:<base64>` string into 32 raw bytes.
fn parse_x25519_bytes(value: &str) -> Result<[u8; 32], CryptoError> {
    let b64 = value.strip_prefix(KEY_AGREEMENT_PREFIX).ok_or_else(|| {
        CryptoError::InvalidKeyFormat("Key-agreement key must start with 'x25519:'".into())
    })?;
    let bytes = BASE64
        .decode(b64)
        .map_err(|e| CryptoError::InvalidKeyFormat(format!("Invalid base64: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyFormat("X25519 key must be 32 bytes".into()))
}

/// Parse an `x25519:<base64>` public key string into 32 raw bytes.
pub fn parse_x25519_public(value: &str) -> Result<[u8; 32], CryptoError> {
    parse_x25519_bytes(value)
}

// ─── Content-encryption key ───────────────────────────────────────────────────

/// A per-archive Content-Encryption Key. Zeroized on drop.
#[derive(ZeroizeOnDrop)]
pub struct ContentKey([u8; 32]);

impl ContentKey {
    /// Generate a fresh random 32-byte CEK from the OS CSPRNG.
    pub fn generate() -> Self {
        Self::from_rng(&mut OsRng)
    }

    /// Generate a CEK from a caller-provided RNG. In seed/test mode this makes the
    /// CEK deterministic (M2); production passes `OsRng` via [`ContentKey::generate`].
    pub fn from_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut k = [0u8; 32];
        rng.fill_bytes(&mut k);
        Self(k)
    }

    /// Wrap existing key bytes (e.g. after HPKE unwrap).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Raw key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// ─── HPKE CEK wrapping (RFC 9180, base mode, ephemeral sender) ─────────────────

/// Build the HPKE `info` string binding the wrap to the signing identity and
/// format version (C4/M1: full `device.public_key`, not the truncated id).
pub fn cek_wrap_info(device_public_key: &str, trst_version: &str) -> Vec<u8> {
    let mut info = Vec::with_capacity(64);
    info.extend_from_slice(b"sealedge/cek-wrap/v1");
    info.extend_from_slice(device_public_key.as_bytes());
    info.extend_from_slice(trst_version.as_bytes());
    info
}

/// A short, non-authoritative recipient selection hint: `b3:<hex16>` over the
/// recipient's X25519 public key.
pub fn recipient_id(recipient_public: &str) -> Result<String, CryptoError> {
    let bytes = parse_x25519_bytes(recipient_public)?;
    let hash = blake3::hash(&bytes);
    Ok(format!("b3:{}", hex::encode(&hash.as_bytes()[..8])))
}

/// HPKE-seal a CEK to one recipient X25519 public key.
///
/// Returns `(enc_b64, wrapped_cek_b64)`: the encapsulated ephemeral key and the
/// sealed CEK. A fresh ephemeral is generated per call → forward secrecy.
pub fn hpke_seal_cek(
    recipient_public: &str,
    info: &[u8],
    aad: &[u8],
    cek: &ContentKey,
) -> Result<(String, String), CryptoError> {
    hpke_seal_cek_with_rng(&mut OsRng, recipient_public, info, aad, cek)
}

/// [`hpke_seal_cek`] with a caller-supplied RNG. Seed/test mode passes a
/// deterministic RNG (see [`seeded_test_rng`]) so the ephemeral — and thus the
/// whole archive — is byte-reproducible (M2). Production uses `OsRng`.
pub fn hpke_seal_cek_with_rng<R: RngCore + CryptoRng>(
    rng: &mut R,
    recipient_public: &str,
    info: &[u8],
    aad: &[u8],
    cek: &ContentKey,
) -> Result<(String, String), CryptoError> {
    let pk_bytes = parse_x25519_bytes(recipient_public)?;
    let pk = <HpkeKem as KemTrait>::PublicKey::from_bytes(&pk_bytes)
        .map_err(|e| CryptoError::EncryptionFailed(format!("HPKE recipient key: {e}")))?;

    let (enc, ciphertext) = hpke::single_shot_seal::<HpkeAead, HpkeKdf, HpkeKem, _>(
        &OpModeS::Base,
        &pk,
        info,
        cek.as_bytes(),
        aad,
        rng,
    )
    .map_err(|e| CryptoError::EncryptionFailed(format!("HPKE seal: {e}")))?;

    Ok((BASE64.encode(enc.to_bytes()), BASE64.encode(ciphertext)))
}

/// A deterministic rand_core-0.6 CSPRNG for **seed/test mode only** (never
/// production). Drives the CEK and HPKE ephemerals so a `--seed` wrap is
/// byte-for-byte reproducible (M2). `rand_chacha` 0.3 matches hpke 0.12's
/// rand_core generation.
pub fn seeded_test_rng(seed: u64) -> rand_chacha::ChaCha20Rng {
    let mut s = [0u8; 32];
    s[..8].copy_from_slice(&seed.to_le_bytes());
    rand_chacha::ChaCha20Rng::from_seed(s)
}

/// HPKE-open a wrapped CEK with the recipient's X25519 secret.
pub fn hpke_open_cek(
    recipient: &KeyAgreementKeypair,
    enc_b64: &str,
    info: &[u8],
    aad: &[u8],
    wrapped_cek_b64: &str,
) -> Result<ContentKey, CryptoError> {
    let cek_bytes =
        hpke_open_raw::<HpkeAead>(&recipient.secret, enc_b64, info, aad, wrapped_cek_b64)?;
    let arr: [u8; 32] = cek_bytes
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::DecryptionFailed("unwrapped CEK is not 32 bytes".into()))?;
    Ok(ContentKey::from_bytes(arr))
}

/// AEAD-generic HPKE open over `DHKEM(X25519,HKDF-SHA256)`/`HKDF-SHA256`. The
/// production path uses `ChaCha20Poly1305`; the RFC 9180 KAT (Appendix A.1)
/// exercises this same path with `AesGcm128`.
fn hpke_open_raw<A: hpke::aead::Aead>(
    recipient_secret: &[u8; 32],
    enc_b64: &str,
    info: &[u8],
    aad: &[u8],
    wrapped_b64: &str,
) -> Result<Vec<u8>, CryptoError> {
    let sk = <HpkeKem as KemTrait>::PrivateKey::from_bytes(recipient_secret)
        .map_err(|e| CryptoError::DecryptionFailed(format!("HPKE recipient secret: {e}")))?;
    let enc_bytes = BASE64
        .decode(enc_b64)
        .map_err(|e| CryptoError::DecryptionFailed(format!("Invalid enc base64: {e}")))?;
    let enc = <HpkeKem as KemTrait>::EncappedKey::from_bytes(&enc_bytes)
        .map_err(|e| CryptoError::DecryptionFailed(format!("HPKE encapped key: {e}")))?;
    let ciphertext = BASE64
        .decode(wrapped_b64)
        .map_err(|e| CryptoError::DecryptionFailed(format!("Invalid wrapped_cek base64: {e}")))?;

    hpke::single_shot_open::<A, HpkeKdf, HpkeKem>(&OpModeR::Base, &sk, &enc, info, &ciphertext, aad)
        .map_err(|e| CryptoError::DecryptionFailed(format!("HPKE open: {e}")))
}

// ─── Chunk AAD (C4/M1) ────────────────────────────────────────────────────────

/// Full-identity chunk AAD (M1): `BLAKE3("sealedge/aad/v1" || public_key ||
/// profile || started_at)`. Binds ciphertext to the full Ed25519 identity key
/// instead of the 48-bit truncated device id.
pub fn chunk_aad_v2(device_public_key: &str, profile: &str, started_at: &str) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"sealedge/aad/v1");
    h.update(device_public_key.as_bytes());
    h.update(profile.as_bytes());
    h.update(started_at.as_bytes());
    h.finalize().into()
}

// ─── SEALEDGE-KEY-V2 dual-key bundle ──────────────────────────────────────────

/// A device's full key material: an Ed25519 signing keypair plus an independent
/// X25519 key-agreement keypair. Persisted as `SEALEDGE-KEY-V2`.
pub struct DeviceBundle {
    pub signing: DeviceKeypair,
    pub key_agreement: KeyAgreementKeypair,
}

impl DeviceBundle {
    /// Generate a fresh device bundle (independent signing + key-agreement keys).
    pub fn generate() -> Result<Self, CryptoError> {
        Ok(Self {
            signing: DeviceKeypair::generate()?,
            key_agreement: KeyAgreementKeypair::generate(),
        })
    }

    /// The two public keys, one per line, for a `.pub` file:
    /// `ed25519:<b64>\nx25519:<b64>\n`.
    pub fn public_lines(&self) -> String {
        format!(
            "{}\n{}\n",
            self.signing.public,
            self.key_agreement.public_string()
        )
    }

    /// Plaintext JSON of both secrets (for CI `--unencrypted`; never production).
    pub fn to_plaintext(&self) -> String {
        serde_json::json!({
            "version": 2,
            "ed25519_secret": self.signing.export_secret(),
            "x25519_secret": self.key_agreement.export_secret(),
        })
        .to_string()
    }

    /// Parse a plaintext bundle produced by [`DeviceBundle::to_plaintext`].
    pub fn from_plaintext(s: &str) -> Result<Self, CryptoError> {
        let v: serde_json::Value = serde_json::from_str(s)
            .map_err(|e| CryptoError::InvalidKeyFormat(format!("Invalid bundle JSON: {e}")))?;
        let ed = v["ed25519_secret"]
            .as_str()
            .ok_or_else(|| CryptoError::InvalidKeyFormat("Missing ed25519_secret".into()))?;
        let x = v["x25519_secret"]
            .as_str()
            .ok_or_else(|| CryptoError::InvalidKeyFormat("Missing x25519_secret".into()))?;
        Ok(Self {
            signing: DeviceKeypair::import_secret(ed)?,
            key_agreement: KeyAgreementKeypair::import_secret(x)?,
        })
    }

    /// Encrypt the bundle at rest with PBKDF2-HMAC-SHA256 (600k) + AES-256-GCM.
    ///
    /// Format: `SEALEDGE-KEY-V2\n{"salt","nonce","iterations","version":2}\n<ct>`.
    pub fn export_encrypted(&self, passphrase: &str) -> Result<Vec<u8>, CryptoError> {
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let iterations = PBKDF2_MIN_ITERATIONS;

        let mut derived_key = [0u8; 32];
        pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), &salt, iterations, &mut derived_key);
        let cipher = Aes256Gcm::new_from_slice(&derived_key)
            .map_err(|e| CryptoError::EncryptionFailed(format!("AES key init: {e}")))?;
        derived_key.zeroize();

        let mut plaintext = self.to_plaintext();
        let ciphertext = cipher
            .encrypt(AesGcmNonce::from_slice(&nonce_bytes), plaintext.as_bytes())
            .map_err(|e| CryptoError::EncryptionFailed(format!("AES-GCM encrypt: {e}")))?;
        plaintext.zeroize();

        let metadata = serde_json::json!({
            "version": 2,
            "salt": BASE64.encode(salt),
            "nonce": BASE64.encode(nonce_bytes),
            "iterations": iterations,
        });
        let mut out = Vec::new();
        out.extend_from_slice(BUNDLE_HEADER_V2.as_bytes());
        out.push(b'\n');
        out.extend_from_slice(metadata.to_string().as_bytes());
        out.push(b'\n');
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypt a `SEALEDGE-KEY-V2` bundle. Wrong passphrase/corruption → Err.
    pub fn import_encrypted(data: &[u8], passphrase: &str) -> Result<Self, CryptoError> {
        let header_end = data
            .iter()
            .position(|&b| b == b'\n')
            .ok_or_else(|| CryptoError::InvalidKeyFormat("Missing header line".into()))?;
        let header = std::str::from_utf8(&data[..header_end])
            .map_err(|_| CryptoError::InvalidKeyFormat("Invalid UTF-8 header".into()))?;
        if header != BUNDLE_HEADER_V2 {
            return Err(CryptoError::InvalidKeyFormat(format!(
                "Expected header '{BUNDLE_HEADER_V2}', got '{header}'"
            )));
        }

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
            .decode(meta["salt"].as_str().unwrap_or_default())
            .map_err(|e| CryptoError::InvalidKeyFormat(format!("Invalid salt base64: {e}")))?;
        let nonce_bytes = BASE64
            .decode(meta["nonce"].as_str().unwrap_or_default())
            .map_err(|e| CryptoError::InvalidKeyFormat(format!("Invalid nonce base64: {e}")))?;
        // Validate as u64 before narrowing (reject overflow, don't truncate).
        let iterations_u64 = meta["iterations"]
            .as_u64()
            .ok_or_else(|| CryptoError::InvalidKeyFormat("Missing iterations".into()))?;
        if iterations_u64 < PBKDF2_MIN_ITERATIONS as u64 {
            return Err(CryptoError::InvalidKeyFormat(format!(
                "Bundle uses {iterations_u64} PBKDF2 iterations, minimum is {PBKDF2_MIN_ITERATIONS}"
            )));
        }
        if iterations_u64 > PBKDF2_MAX_ITERATIONS as u64 {
            return Err(CryptoError::InvalidKeyFormat(format!(
                "Bundle uses {iterations_u64} PBKDF2 iterations, maximum is {PBKDF2_MAX_ITERATIONS}"
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
        let mut derived_key = [0u8; 32];
        pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), &salt, iterations, &mut derived_key);
        let cipher = Aes256Gcm::new_from_slice(&derived_key)
            .map_err(|e| CryptoError::EncryptionFailed(format!("AES key init: {e}")))?;
        derived_key.zeroize();

        let plaintext = cipher
            .decrypt(AesGcmNonce::from_slice(&nonce_bytes), ciphertext)
            .map_err(|_| {
                CryptoError::DecryptionFailed("Wrong passphrase or corrupted bundle".into())
            })?;
        let plaintext_str = String::from_utf8(plaintext)
            .map_err(|_| CryptoError::DecryptionFailed("Bundle plaintext not UTF-8".into()))?;
        Self::from_plaintext(&plaintext_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x25519_keypair_roundtrip() {
        let kp = KeyAgreementKeypair::generate();
        let exported = kp.export_secret();
        let imported = KeyAgreementKeypair::import_secret(&exported).unwrap();
        // Public key derived on import must match the original.
        assert_eq!(kp.public_bytes(), imported.public_bytes());
        assert_eq!(kp.public_string(), imported.public_string());
        assert!(kp.public_string().starts_with("x25519:"));
    }

    #[test]
    fn test_hpke_seal_open_roundtrip() {
        let recipient = KeyAgreementKeypair::generate();
        let cek = ContentKey::generate();
        let info = cek_wrap_info("ed25519:device", "0.2.0");
        let aad = chunk_aad_v2("ed25519:device", "generic", "2025-01-01T00:00:00Z");

        let (enc, wrapped) = hpke_seal_cek(&recipient.public_string(), &info, &aad, &cek).unwrap();
        let opened = hpke_open_cek(&recipient, &enc, &info, &aad, &wrapped).unwrap();
        assert_eq!(opened.as_bytes(), cek.as_bytes());
    }

    #[test]
    fn test_hpke_wrong_recipient_fails() {
        let recipient = KeyAgreementKeypair::generate();
        let attacker = KeyAgreementKeypair::generate();
        let cek = ContentKey::generate();
        let info = cek_wrap_info("ed25519:device", "0.2.0");
        let aad = [0u8; 32];

        let (enc, wrapped) = hpke_seal_cek(&recipient.public_string(), &info, &aad, &cek).unwrap();
        assert!(hpke_open_cek(&attacker, &enc, &info, &aad, &wrapped).is_err());
    }

    #[test]
    fn test_hpke_aad_mismatch_fails() {
        let recipient = KeyAgreementKeypair::generate();
        let cek = ContentKey::generate();
        let info = cek_wrap_info("ed25519:device", "0.2.0");

        let (enc, wrapped) =
            hpke_seal_cek(&recipient.public_string(), &info, b"aad-one", &cek).unwrap();
        assert!(hpke_open_cek(&recipient, &enc, &info, b"aad-two", &wrapped).is_err());
    }

    /// RFC 9180 Appendix A.1.1 known-answer test (base mode,
    /// DHKEM(X25519,HKDF-SHA256)/HKDF-SHA256/AES-128-GCM). Exercises the exact
    /// KEM+KDF decap wiring the production ChaCha path uses. The AEAD differs
    /// (A.1 = AES-128-GCM); ChaCha (A.2 suite) is covered by the round-trip tests.
    /// The test self-verifies by decrypting to the RFC's known plaintext, so a
    /// mis-transcribed vector fails rather than passing falsely.
    #[test]
    fn test_rfc9180_a1_base_kat() {
        // Recipient X25519 secret (skRm) and encapsulated key (enc == pkEm).
        let sk_rm = hex::decode("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8")
            .unwrap();
        let sk_rm: [u8; 32] = sk_rm.try_into().unwrap();
        let enc = BASE64.encode(
            hex::decode("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431")
                .unwrap(),
        );
        let info = hex::decode("4f6465206f6e2061204772656369616e2055726e").unwrap();
        let aad = hex::decode("436f756e742d30").unwrap();
        let ct = BASE64.encode(
            hex::decode(
                "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a",
            )
            .unwrap(),
        );
        let expected_pt =
            hex::decode("4265617574792069732074727574682c20747275746820626561757479").unwrap();

        let pt = hpke_open_raw::<hpke::aead::AesGcm128>(&sk_rm, &enc, &info, &aad, &ct).unwrap();
        assert_eq!(pt, expected_pt);
        assert_eq!(&pt, b"Beauty is truth, truth beauty");
    }

    #[test]
    fn test_device_bundle_encrypted_roundtrip() {
        let bundle = DeviceBundle::generate().unwrap();
        let signing_pub = bundle.signing.public.clone();
        let ka_pub = bundle.key_agreement.public_string();

        let blob = bundle
            .export_encrypted("correct horse battery staple")
            .unwrap();
        assert!(blob.starts_with(b"SEALEDGE-KEY-V2\n"));

        let restored =
            DeviceBundle::import_encrypted(&blob, "correct horse battery staple").unwrap();
        assert_eq!(restored.signing.public, signing_pub);
        assert_eq!(restored.key_agreement.public_string(), ka_pub);

        // Wrong passphrase must fail.
        assert!(DeviceBundle::import_encrypted(&blob, "wrong").is_err());
    }

    #[test]
    fn test_seal_open_secret_roundtrip() {
        let secret = [7u8; 32];
        let blob = seal_secret(&secret, "correct horse battery staple").unwrap();
        // Headered, and the plaintext key is not present in the blob.
        assert!(blob.starts_with(b"SEALEDGE-SEALED-V1\n"));
        assert!(
            !blob.windows(secret.len()).any(|w| w == secret),
            "raw secret must not appear in the sealed blob"
        );
        let opened = open_secret(&blob, "correct horse battery staple").unwrap();
        assert_eq!(&opened[..], &secret[..]);
    }

    #[test]
    fn test_open_secret_rejects_wrong_passphrase_and_tamper() {
        let blob = seal_secret(b"a-32-byte-or-any-length-secret!!", "pw").unwrap();
        // Wrong passphrase.
        assert!(open_secret(&blob, "nope").is_err());
        // Tampered ciphertext (flip the last byte) → AEAD failure.
        let mut bad = blob.clone();
        *bad.last_mut().unwrap() ^= 0x01;
        assert!(open_secret(&bad, "pw").is_err());
    }

    /// F1: the live Ed25519 signing key must zeroize on drop. This is a
    /// compile-time guard — if the `zeroize` feature is dropped from
    /// ed25519-dalek, `SigningKey: ZeroizeOnDrop` no longer holds and this test
    /// fails to build, flagging the regression.
    #[test]
    fn signing_key_zeroizes_on_drop() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<ed25519_dalek::SigningKey>();
    }

    #[test]
    fn test_open_secret_rejects_out_of_range_iterations() {
        // F2: reject a blob whose metadata sets an absurd iteration count (a
        // decrypt-stall DoS) — symmetric with the floor. Rewrite just the meta
        // line's "iterations" field, keeping the header + ciphertext.
        let blob = seal_secret(&[3u8; 32], "pw").unwrap();
        let text = String::from_utf8_lossy(&blob);
        let mut lines = text.splitn(3, '\n');
        let header = lines.next().unwrap();
        let meta = lines.next().unwrap();
        let hacked_meta = meta.replace("\"iterations\":600000", "\"iterations\":4000000000");
        assert_ne!(hacked_meta, meta, "meta must contain the iterations field");
        // Rebuild: header \n hacked_meta \n <original ciphertext bytes>.
        let ct_start = header.len() + 1 + meta.len() + 1;
        let mut hacked = Vec::new();
        hacked.extend_from_slice(header.as_bytes());
        hacked.push(b'\n');
        hacked.extend_from_slice(hacked_meta.as_bytes());
        hacked.push(b'\n');
        hacked.extend_from_slice(&blob[ct_start..]);

        let err = open_secret(&hacked, "pw").unwrap_err();
        assert!(
            format!("{err}").contains("maximum"),
            "must reject above-ceiling iterations, got: {err}"
        );
    }

    #[test]
    fn test_open_secret_rejects_foreign_header() {
        // A SEALEDGE-KEY-V2 bundle must not open as a sealed secret (no confusion).
        let bundle = DeviceBundle::generate().unwrap();
        let bundle_blob = bundle.export_encrypted("pw").unwrap();
        assert!(open_secret(&bundle_blob, "pw").is_err());
    }

    #[test]
    fn test_device_bundle_plaintext_roundtrip() {
        let bundle = DeviceBundle::generate().unwrap();
        let json = bundle.to_plaintext();
        let restored = DeviceBundle::from_plaintext(&json).unwrap();
        assert_eq!(restored.signing.public, bundle.signing.public);
        assert_eq!(
            restored.key_agreement.public_string(),
            bundle.key_agreement.public_string()
        );
    }

    #[test]
    fn test_chunk_aad_v2_deterministic_and_bound() {
        let a = chunk_aad_v2("ed25519:AAAA", "generic", "t0");
        let b = chunk_aad_v2("ed25519:AAAA", "generic", "t0");
        let c = chunk_aad_v2("ed25519:BBBB", "generic", "t0");
        assert_eq!(a, b, "same inputs must give same AAD");
        assert_ne!(a, c, "different public key must change the AAD");
    }

    #[test]
    fn test_recipient_id_stable() {
        let kp = KeyAgreementKeypair::generate();
        let id1 = recipient_id(&kp.public_string()).unwrap();
        let id2 = recipient_id(&kp.public_string()).unwrap();
        assert_eq!(id1, id2);
        assert!(id1.starts_with("b3:"));
    }
}
