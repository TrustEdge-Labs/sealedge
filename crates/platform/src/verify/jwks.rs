//
// Copyright (c) 2025 TRUSTEDGE LABS LLC
// This source code is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Project: sealedge — Privacy and trust at the edge.
//

//! JWKS key management — Ed25519 signing key lifecycle with rotation support.

use anyhow::{anyhow, Context, Result};
use base64::{
    engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD as BASE64URL},
    Engine,
};
use sealedge_core::{open_secret, seal_secret, SigningKey, VerifyingKey, SEALED_SECRET_HEADER_V1};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::Write as _;
use std::{fs, path::Path};
use zeroize::Zeroize as _;

#[derive(Clone)]
pub struct KeyManager {
    key_path: String,
    /// Passphrase for encryption-at-rest (M2). `Some` ⇒ the key file is a
    /// `SEALEDGE-SEALED-V1` blob; `None` ⇒ plaintext dev fallback (debug only).
    /// Held in memory alongside the signing key it protects; zeroized on drop.
    passphrase: Option<String>,
    current_key: SigningKey,
    current_kid: String,
    previous_key: Option<SigningKey>,
    previous_kid: Option<String>,
}

// Manual Debug: never render the passphrase or key material — only whether the
// key is encrypted at rest and its non-secret identifiers.
impl std::fmt::Debug for KeyManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyManager")
            .field("key_path", &self.key_path)
            .field("encrypted_at_rest", &self.passphrase.is_some())
            .field("current_kid", &self.current_kid)
            .field("previous_kid", &self.previous_kid)
            .finish()
    }
}

impl Drop for KeyManager {
    fn drop(&mut self) {
        if let Some(p) = self.passphrase.as_mut() {
            p.zeroize();
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredKey {
    kid: String,
    private_key: String,
    created_at: String,
}

impl KeyManager {
    /// Create a `KeyManager` from environment configuration (M2).
    ///
    /// - `JWKS_KEY_PATH` locates the key file. In **release** it is **required**
    ///   (no temp-dir default — the signing/timestamp root must not live in
    ///   `/tmp`). In debug it defaults to a temp path for convenience.
    /// - `JWKS_KEY_PASSPHRASE` encrypts the key at rest. In **release** it is
    ///   **required** (fail closed). In debug, if unset, the key is written
    ///   unencrypted with a loud warning (dev/test escape hatch).
    pub fn new() -> Result<Self> {
        let key_path = Self::resolve_key_path()?;
        let passphrase = Self::resolve_passphrase()?;
        Self::open_or_generate(&key_path, passphrase)
    }

    /// Create a `KeyManager` with an explicit key file path; the passphrase is
    /// still resolved from `JWKS_KEY_PASSPHRASE` (required in release). Used by
    /// tests and callers that manage the path themselves.
    pub fn new_with_path(key_path: &str) -> Result<Self> {
        let passphrase = Self::resolve_passphrase()?;
        Self::open_or_generate(key_path, passphrase)
    }

    /// Create a `KeyManager` with an explicit passphrase (always encrypted at
    /// rest), bypassing env resolution. Deterministic for tests and programmatic
    /// custody.
    pub fn new_sealed(key_path: &str, passphrase: &str) -> Result<Self> {
        Self::open_or_generate(key_path, Some(passphrase.to_string()))
    }

    /// Resolve the key path: `JWKS_KEY_PATH`, or a temp default in debug only.
    fn resolve_key_path() -> Result<String> {
        if let Ok(p) = std::env::var("JWKS_KEY_PATH") {
            if !p.is_empty() {
                return Ok(p);
            }
        }
        if cfg!(debug_assertions) {
            Ok(std::env::temp_dir()
                .join("sealedge_signing_key.json")
                .to_string_lossy()
                .into_owned())
        } else {
            Err(anyhow!(
                "JWKS_KEY_PATH must be set in release builds — refusing to place the platform \
                 signing key (JWKS + witness/timestamp root) in a temp directory"
            ))
        }
    }

    /// Resolve the at-rest passphrase: `JWKS_KEY_PASSPHRASE`, required in release.
    fn resolve_passphrase() -> Result<Option<String>> {
        match std::env::var("JWKS_KEY_PASSPHRASE") {
            Ok(p) if !p.is_empty() => Ok(Some(p)),
            _ => {
                if cfg!(debug_assertions) {
                    Ok(None)
                } else {
                    Err(anyhow!(
                        "JWKS_KEY_PASSPHRASE must be set in release builds — the platform signing \
                         key (which signs witness/timestamp receipts, the revocation root) must be \
                         encrypted at rest"
                    ))
                }
            }
        }
    }

    fn open_or_generate(key_path: &str, passphrase: Option<String>) -> Result<Self> {
        if Path::new(key_path).exists() {
            Self::load_from_file(key_path, passphrase)
        } else {
            Self::generate_new(key_path, passphrase)
        }
    }

    fn generate_new(key_path: &str, passphrase: Option<String>) -> Result<Self> {
        let signing_key = SigningKey::generate(&mut rand_core::OsRng);
        let kid = format!("key_{}", uuid::Uuid::new_v4().simple());

        let key_manager = KeyManager {
            key_path: key_path.to_string(),
            passphrase,
            current_key: signing_key,
            current_kid: kid,
            previous_key: None,
            previous_kid: None,
        };

        key_manager.save_to_file()?;
        key_manager.write_jwks_file()?;

        Ok(key_manager)
    }

    fn load_from_file(key_path: &str, passphrase: Option<String>) -> Result<Self> {
        let bytes = fs::read(key_path)
            .with_context(|| format!("Failed to read signing key from {}", key_path))?;

        // Recover the StoredKey JSON, decrypting if the file is sealed at rest.
        let mut stored: StoredKey = if bytes.starts_with(SEALED_SECRET_HEADER_V1.as_bytes()) {
            let pass = passphrase.as_deref().ok_or_else(|| {
                anyhow!("key file {key_path} is encrypted but JWKS_KEY_PASSPHRASE is not set")
            })?;
            let plaintext = open_secret(&bytes, pass)
                .map_err(|e| anyhow!("failed to decrypt signing key at {key_path}: {e}"))?;
            serde_json::from_slice(&plaintext).with_context(|| {
                format!("Failed to parse decrypted signing key from {}", key_path)
            })?
        } else {
            // Plaintext file. Only valid as the debug fallback with NO passphrase;
            // if a passphrase is configured, refuse rather than trust plaintext.
            if passphrase.is_some() {
                return Err(anyhow!(
                    "key file {key_path} is unencrypted but a passphrase is configured; \
                     remove it to regenerate an encrypted key"
                ));
            }
            serde_json::from_slice(&bytes)
                .with_context(|| format!("Failed to parse signing key JSON from {}", key_path))?
        };

        let mut seed_vec = BASE64.decode(&stored.private_key)?;
        let seed_arr: [u8; 32] = seed_vec
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("Invalid private key length"))?;
        let signing_key = SigningKey::from_bytes(&seed_arr);
        // Scrub transient copies of the secret seed / its base64 encoding.
        seed_vec.zeroize();
        let mut seed_arr = seed_arr;
        seed_arr.zeroize();
        stored.private_key.zeroize();

        Ok(KeyManager {
            key_path: key_path.to_string(),
            passphrase,
            current_key: signing_key,
            current_kid: stored.kid,
            previous_key: None,
            previous_kid: None,
        })
    }

    fn save_to_file(&self) -> Result<()> {
        let mut seed = self.current_key.to_bytes();
        let mut json = serde_json::to_string(&StoredKey {
            kid: self.current_kid.clone(),
            private_key: BASE64.encode(seed),
            created_at: chrono::Utc::now().to_rfc3339(),
        })?;
        seed.zeroize();

        match self.passphrase.as_deref() {
            Some(pass) => {
                // Encrypt at rest (PBKDF2 600k + AES-256-GCM). Ciphertext is not
                // secret, but scrub the plaintext JSON once sealed.
                let blob = seal_secret(json.as_bytes(), pass)
                    .map_err(|e| anyhow!("failed to encrypt signing key: {e}"))?;
                json.zeroize();
                Self::write_secure(Path::new(&self.key_path), &blob)?;
            }
            None => {
                // Defense in depth: never persist plaintext in a release build,
                // even if the constructor guard were somehow bypassed.
                if !cfg!(debug_assertions) {
                    json.zeroize();
                    return Err(anyhow!(
                        "refusing to write an unencrypted signing key in a release build"
                    ));
                }
                eprintln!(
                    "\u{26A0} WARNING: writing the JWKS signing key UNENCRYPTED to {} — \
                     JWKS_KEY_PASSPHRASE is not set (dev/test only)",
                    self.key_path
                );
                let res = Self::write_secure(Path::new(&self.key_path), json.as_bytes());
                json.zeroize();
                res?;
            }
        }
        Ok(())
    }

    /// Atomically write `bytes` to `path` with `0600` set **at creation** (no
    /// world-readable window between write and chmod): write a sibling temp file
    /// opened with mode 0600, then rename it over the target.
    fn write_secure(path: &Path, bytes: &[u8]) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory for {}", path.display()))?;
        }
        // Unique temp sibling per writer. A fixed ".tmp" name let two concurrent
        // writers to the same target share one temp file: the first's rename moved
        // it into place, and the second's rename then failed with "No such file"
        // ("Failed to finalize signing key ..."). This surfaced as a flaky CI
        // failure when parallel tests generated the same default key path; it is
        // also a real hazard for any two processes sharing a JWKS_KEY_PATH.
        use std::sync::atomic::{AtomicU64, Ordering};
        static TMP_SEQ: AtomicU64 = AtomicU64::new(0);
        let mut tmp_os = path.as_os_str().to_owned();
        tmp_os.push(format!(
            ".tmp.{}.{}",
            std::process::id(),
            TMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let tmp = std::path::PathBuf::from(tmp_os);

        {
            #[cfg(unix)]
            let mut f = {
                use std::os::unix::fs::OpenOptionsExt;
                fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(&tmp)
                    .with_context(|| format!("Failed to create {}", tmp.display()))?
            };
            #[cfg(not(unix))]
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp)
                .with_context(|| format!("Failed to create {}", tmp.display()))?;

            f.write_all(bytes)
                .with_context(|| format!("Failed to write {}", tmp.display()))?;
            let _ = f.sync_all();
        }

        fs::rename(&tmp, path)
            .with_context(|| format!("Failed to finalize signing key at {}", path.display()))?;
        Ok(())
    }

    fn jwks_path(&self) -> std::path::PathBuf {
        Path::new(&self.key_path)
            .parent()
            .unwrap_or(Path::new("."))
            .join("jwks.json")
    }

    fn write_jwks_file(&self) -> Result<()> {
        let jwks_path = self.jwks_path();
        if let Some(parent) = jwks_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create directory for {}", jwks_path.display())
            })?;
        }

        let jwks = self.to_jwks();
        let content = serde_json::to_string_pretty(&jwks)?;
        fs::write(&jwks_path, content)
            .with_context(|| format!("Failed to write JWKS file to {}", jwks_path.display()))?;

        Ok(())
    }

    pub fn current_kid(&self) -> String {
        self.current_kid.clone()
    }

    pub fn current_signing_key(&self) -> &SigningKey {
        &self.current_key
    }

    pub fn to_jwks(&self) -> Value {
        let mut keys = Vec::new();

        // Current key
        let current_verifying_key = self.current_key.verifying_key();
        keys.push(self.key_to_jwk(&current_verifying_key, &self.current_kid));

        // Previous key if it exists
        if let (Some(prev_key), Some(prev_kid)) = (&self.previous_key, &self.previous_kid) {
            let prev_verifying_key = prev_key.verifying_key();
            keys.push(self.key_to_jwk(&prev_verifying_key, prev_kid));
        }

        json!({
            "keys": keys
        })
    }

    fn key_to_jwk(&self, verifying_key: &VerifyingKey, kid: &str) -> Value {
        let public_key_bytes = verifying_key.as_bytes();

        json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": kid,
            "use": "sig",
            "alg": "EdDSA",
            // RFC 8037 §2: the OKP `x` parameter is base64url-encoded WITHOUT
            // padding. Using standard base64 here breaks interop with conformant
            // JWK consumers.
            "x": BASE64URL.encode(public_key_bytes)
        })
    }

    pub fn rotate_key(&mut self) -> Result<()> {
        let new_signing_key = SigningKey::generate(&mut rand_core::OsRng);
        let new_kid = format!("key_{}", uuid::Uuid::new_v4().simple());

        self.previous_key = Some(self.current_key.clone());
        self.previous_kid = Some(self.current_kid.clone());
        self.current_key = new_signing_key;
        self.current_kid = new_kid;

        self.save_to_file()?;
        self.write_jwks_file()?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8037 §2 requires the OKP `x` parameter to be base64url-encoded with no
    /// padding. Regression guard for the standard-base64 interop bug (M1).
    #[test]
    fn jwk_x_is_base64url_unpadded_rfc8037() {
        let dir = std::env::temp_dir().join(format!(
            "sealedge_jwks_rfc8037_{}",
            uuid::Uuid::new_v4().simple()
        ));
        fs::create_dir_all(&dir).unwrap();
        let key_path = dir.join("key.json");
        let km = KeyManager::new_with_path(key_path.to_str().unwrap()).unwrap();

        let jwks = km.to_jwks();
        let x = jwks["keys"][0]["x"]
            .as_str()
            .expect("JWKS key must have an 'x' field");

        // Unpadded, URL-safe alphabet: no '=', '+', or '/'.
        assert!(!x.contains('='), "x must be unpadded (no '='): {x}");
        assert!(
            !x.contains('+') && !x.contains('/'),
            "x must use the URL-safe alphabet (no '+'/'/'): {x}"
        );

        // Decodes as base64url-no-pad to the raw 32-byte Ed25519 public key.
        let decoded = BASE64URL
            .decode(x)
            .expect("x must decode as base64url-no-pad");
        assert_eq!(
            decoded,
            km.current_key.verifying_key().as_bytes(),
            "x must be the raw Ed25519 public key"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    fn temp_key_path(tag: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "sealedge_jwks_{tag}_{}",
            uuid::Uuid::new_v4().simple()
        ));
        fs::create_dir_all(&dir).unwrap();
        let key = dir.join("key.json");
        (dir, key)
    }

    /// M2: an encrypted key file is a SEALEDGE-SEALED-V1 blob (no plaintext seed
    /// on disk), reloads to the same identity, and is 0600 with no chmod race.
    #[test]
    fn sealed_key_roundtrips_and_file_is_encrypted() {
        let (dir, key) = temp_key_path("sealed");
        let pass = "correct horse battery staple";

        let km = KeyManager::new_sealed(key.to_str().unwrap(), pass).unwrap();
        let kid = km.current_kid();
        let pub_bytes = km.current_key.verifying_key().to_bytes();
        let seed_b64 = BASE64.encode(km.current_key.to_bytes());

        // On-disk file is encrypted, and the raw secret is nowhere in it.
        let raw = fs::read(&key).unwrap();
        assert!(
            raw.starts_with(SEALED_SECRET_HEADER_V1.as_bytes()),
            "key file must be a sealed blob"
        );
        let raw_str = String::from_utf8_lossy(&raw);
        assert!(
            !raw_str.contains(&seed_b64),
            "plaintext secret seed must not appear in the sealed file"
        );

        // 0600, created atomically (no leftover temp sibling).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&key).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "key file must be owner-only");
        }
        let mut tmp = key.as_os_str().to_owned();
        tmp.push(".tmp");
        assert!(
            !std::path::Path::new(&tmp).exists(),
            "atomic write must leave no temp sibling"
        );

        // Reload with the same passphrase → same identity.
        let reloaded = KeyManager::new_sealed(key.to_str().unwrap(), pass).unwrap();
        assert_eq!(reloaded.current_kid(), kid);
        assert_eq!(reloaded.current_key.verifying_key().to_bytes(), pub_bytes);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn sealed_key_wrong_passphrase_fails() {
        let (dir, key) = temp_key_path("wrongpass");
        KeyManager::new_sealed(key.to_str().unwrap(), "right").unwrap();
        let err = KeyManager::new_sealed(key.to_str().unwrap(), "wrong");
        assert!(err.is_err(), "wrong passphrase must fail to load");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn sealed_ctor_refuses_preexisting_plaintext_key() {
        // A plaintext key file must not be silently trusted when a passphrase is
        // configured — force a re-key instead.
        let (dir, key) = temp_key_path("plainrefuse");
        let stored = serde_json::json!({
            "kid": "key_test",
            "private_key": BASE64.encode([9u8; 32]),
            "created_at": "2026-08-06T00:00:00Z"
        });
        fs::write(&key, serde_json::to_vec(&stored).unwrap()).unwrap();

        let err = KeyManager::new_sealed(key.to_str().unwrap(), "pass");
        assert!(
            err.is_err(),
            "must refuse a plaintext key file when a passphrase is set"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
