//
// Copyright (c) 2025 TRUSTEDGE LABS LLC
// This source code is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Project: sealedge — Privacy and trust at the edge.
//

//! JWS receipt signing using Ed25519 keys managed by KeyManager.

use anyhow::{anyhow, Result};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};

use super::engine::ReceiptClaims;
use super::jwks::KeyManager;

#[derive(Debug, Serialize, Deserialize)]
struct JwsPayload {
    iss: String,
    sub: String,
    iat: i64,
    exp: i64,
    receipt: ReceiptClaims,
}

pub async fn sign_receipt_jws(
    receipt: &ReceiptClaims,
    key_manager: &KeyManager,
    ttl_secs: u64,
) -> Result<String> {
    let now = chrono::Utc::now().timestamp();
    let exp = now + ttl_secs as i64;

    let payload = JwsPayload {
        iss: "sealedge-verify-service".to_string(),
        // The subject is the cryptographic signer (the verifying public key), not
        // the client-supplied device_id (C3). The device_id — trustworthy only
        // when receipt.device_registered is true — remains inside the receipt.
        sub: receipt.signer_pub.clone(),
        iat: now,
        exp,
        receipt: receipt.clone(),
    };

    let kid = key_manager.current_kid();
    let signing_key = key_manager.current_signing_key();

    let header = Header {
        alg: Algorithm::EdDSA,
        kid: Some(kid),
        typ: Some("JWT".to_string()),
        ..Default::default()
    };

    // Convert Ed25519 key to PKCS#8 DER format that jsonwebtoken expects
    let signing_key_bytes = signing_key.to_bytes();

    // Create PKCS#8 DER wrapper for Ed25519 private key
    // Ed25519 private key in PKCS#8 DER format
    let mut pkcs8_der = Vec::new();
    // SEQUENCE
    pkcs8_der.extend_from_slice(&[0x30, 0x2e]);
    // INTEGER version
    pkcs8_der.extend_from_slice(&[0x02, 0x01, 0x00]);
    // SEQUENCE algorithm identifier
    pkcs8_der.extend_from_slice(&[0x30, 0x05]);
    // OID for Ed25519
    pkcs8_der.extend_from_slice(&[0x06, 0x03, 0x2b, 0x65, 0x70]);
    // OCTET STRING private key
    pkcs8_der.extend_from_slice(&[0x04, 0x22]);
    // OCTET STRING content
    pkcs8_der.extend_from_slice(&[0x04, 0x20]);
    // The actual 32-byte Ed25519 private key
    pkcs8_der.extend_from_slice(&signing_key_bytes);

    let encoding_key = EncodingKey::from_ed_der(&pkcs8_der);

    let token = encode(&header, &payload, &encoding_key)
        .map_err(|e| anyhow!("Failed to encode JWT: {}", e))?;

    Ok(token)
}
