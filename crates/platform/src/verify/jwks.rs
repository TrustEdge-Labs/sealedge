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
use sealedge_core::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{fs, path::Path};

#[derive(Debug, Clone)]
pub struct KeyManager {
    key_path: String,
    current_key: SigningKey,
    current_kid: String,
    previous_key: Option<SigningKey>,
    previous_kid: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredKey {
    kid: String,
    private_key: String,
    created_at: String,
}

impl KeyManager {
    /// Create a new `KeyManager`, reading the key path from the `JWKS_KEY_PATH`
    /// environment variable. If unset, defaults to a path in the system temp directory.
    pub fn new() -> Result<Self> {
        let key_path = std::env::var("JWKS_KEY_PATH").unwrap_or_else(|_| {
            std::env::temp_dir()
                .join("sealedge_signing_key.json")
                .to_string_lossy()
                .into_owned()
        });
        Self::new_with_path(&key_path)
    }

    /// Create a `KeyManager` with an explicit key file path.
    ///
    /// Public for testing — allows callers to specify a deterministic path.
    pub fn new_with_path(key_path: &str) -> Result<Self> {
        if Path::new(key_path).exists() {
            Self::load_from_file(key_path)
        } else {
            Self::generate_new(key_path)
        }
    }

    fn generate_new(key_path: &str) -> Result<Self> {
        let signing_key = SigningKey::generate(&mut rand_core::OsRng);
        let kid = format!("key_{}", uuid::Uuid::new_v4().simple());

        let key_manager = KeyManager {
            key_path: key_path.to_string(),
            current_key: signing_key,
            current_kid: kid,
            previous_key: None,
            previous_kid: None,
        };

        key_manager.save_to_file()?;
        key_manager.write_jwks_file()?;

        Ok(key_manager)
    }

    fn load_from_file(key_path: &str) -> Result<Self> {
        let content = fs::read_to_string(key_path)
            .with_context(|| format!("Failed to read signing key from {}", key_path))?;
        let stored: StoredKey = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse signing key JSON from {}", key_path))?;

        let private_key_bytes = BASE64.decode(&stored.private_key)?;
        let signing_key = SigningKey::from_bytes(
            &private_key_bytes
                .try_into()
                .map_err(|_| anyhow!("Invalid private key length"))?,
        );

        Ok(KeyManager {
            key_path: key_path.to_string(),
            current_key: signing_key,
            current_kid: stored.kid,
            previous_key: None,
            previous_kid: None,
        })
    }

    fn save_to_file(&self) -> Result<()> {
        if let Some(parent) = Path::new(&self.key_path).parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory for {}", self.key_path))?;
        }

        let stored = StoredKey {
            kid: self.current_kid.clone(),
            private_key: BASE64.encode(self.current_key.to_bytes()),
            created_at: chrono::Utc::now().to_rfc3339(),
        };

        let content = serde_json::to_string_pretty(&stored)?;
        fs::write(&self.key_path, content)
            .with_context(|| format!("Failed to write signing key to {}", self.key_path))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&self.key_path, perms)
                .with_context(|| format!("Failed to set permissions on {}", self.key_path))?;
        }

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
}
