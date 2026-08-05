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
use crate::witness::WitnessReceipt;

/// Wrap a raw 32-byte Ed25519 secret key in the PKCS#8 DER envelope that
/// `jsonwebtoken` expects for EdDSA signing.
fn ed25519_pkcs8_der(secret: &[u8; 32]) -> Vec<u8> {
    let mut der = Vec::with_capacity(48);
    der.extend_from_slice(&[
        0x30, 0x2e, // SEQUENCE
        0x02, 0x01, 0x00, // INTEGER version 0
        0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, // AlgorithmIdentifier: Ed25519 OID
        0x04, 0x22, 0x04, 0x20, // OCTET STRING (private key), 32 bytes
    ]);
    der.extend_from_slice(secret);
    der
}

/// JWS payload of a witness receipt (H1c). Mirrors the verification-receipt
/// envelope (same `iss`, `sub` = signer) but with `typ: "witness"` and — by
/// design — NO `exp`: a witnessed timestamp is a permanent historical fact (A4).
#[derive(Debug, Serialize, Deserialize)]
struct JwsWitnessPayload {
    iss: String,
    sub: String,
    typ: String,
    iat: i64,
    witness: WitnessReceipt,
}

/// Sign a witness receipt as an EdDSA JWS using the platform's current JWKS key.
pub fn sign_witness_jws(receipt: &WitnessReceipt, key_manager: &KeyManager) -> Result<String> {
    let payload = JwsWitnessPayload {
        iss: "sealedge-verify-service".to_string(),
        sub: receipt.device_pub.clone(),
        typ: "witness".to_string(),
        iat: chrono::Utc::now().timestamp(),
        witness: receipt.clone(),
    };

    let header = Header {
        alg: Algorithm::EdDSA,
        kid: Some(key_manager.current_kid()),
        typ: Some("JWT".to_string()),
        ..Default::default()
    };
    let encoding_key = EncodingKey::from_ed_der(&ed25519_pkcs8_der(
        &key_manager.current_signing_key().to_bytes(),
    ));

    encode(&header, &payload, &encoding_key)
        .map_err(|e| anyhow!("Failed to encode witness JWT: {}", e))
}

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

    let encoding_key = EncodingKey::from_ed_der(&ed25519_pkcs8_der(&signing_key.to_bytes()));

    let token = encode(&header, &payload, &encoding_key)
        .map_err(|e| anyhow!("Failed to encode JWT: {}", e))?;

    Ok(token)
}
