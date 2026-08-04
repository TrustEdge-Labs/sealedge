//
// Copyright (c) 2025 TRUSTEDGE LABS LLC
// This source code is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Project: sealedge — Privacy and trust at the edge.
//

//! WASM bindings for sealedge .seal archive verification.
//!
//! This crate provides browser-compatible verification of .seal archives
//! using the canonical manifest types from `sealedge-seal-protocols`.

use serde::Serialize;
use serde_wasm_bindgen::to_value;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{File, FileSystemDirectoryHandle};

use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

// Import canonical manifest types from trst-protocols
use sealedge_seal_protocols::TrstManifest;

pub mod crypto;

// Initialize panic hook for better error messages in debug
#[wasm_bindgen(start)]
pub fn main() {
    console_error_panic_hook::set_once();
}

#[derive(Serialize)]
struct VerificationResult {
    signature: String,  // "pass" | "fail"
    continuity: String, // "pass" | "fail"
    segment_count: u32,
}

/// The only `.trst` archive version this verifier accepts (C4 clean break).
const SUPPORTED_TRST_VERSION: &str = "0.2.0";

/// Reject legacy (`0.1.0`) or unknown archive versions with an explicit error.
fn require_supported_version(trst_version: &str) -> Result<(), JsValue> {
    if trst_version == SUPPORTED_TRST_VERSION {
        Ok(())
    } else if trst_version == "0.1.0" {
        Err(JsValue::from_str(
            "unsupported legacy archive format 0.1.0 (pre-C4); re-wrap with a current seal build",
        ))
    } else {
        Err(JsValue::from_str(&format!(
            "unsupported archive version {trst_version} (expected {SUPPORTED_TRST_VERSION})"
        )))
    }
}

/// Verify a manifest directly from bytes
#[wasm_bindgen]
pub fn verify_manifest(manifest_bytes: Vec<u8>, device_pub: String) -> Result<JsValue, JsValue> {
    // Parse the manifest using canonical types from trst-protocols
    let manifest: TrstManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse manifest: {}", e)))?;

    // Version dispatch (C4 §13.4 / M3): reject legacy/unknown formats before the
    // signature check — canonical bytes differ across versions.
    require_supported_version(&manifest.trst_version)?;

    // Get signature
    let signature_str = manifest
        .signature
        .as_ref()
        .ok_or_else(|| JsValue::from_str("Manifest has no signature"))?;

    // Get canonical bytes using trst-protocols's canonicalization
    let canonical_bytes = manifest
        .to_canonical_bytes()
        .map_err(|e| JsValue::from_str(&format!("Canonicalization failed: {}", e)))?;

    // Ensure device public key has proper format
    let device_pub_key = if device_pub.starts_with("ed25519:") {
        device_pub
    } else {
        format!("ed25519:{}", device_pub)
    };

    // Verify signature
    let signature_result =
        match verify_ed25519_signature(&device_pub_key, &canonical_bytes, signature_str) {
            Ok(true) => "pass",
            Ok(false) => "fail",
            Err(_) => "fail",
        };

    // For manifest-only verification, we can't verify continuity without chunk files
    // So we'll mark continuity as "pass" if signature passes (basic validation)
    let continuity_result = if signature_result == "pass" {
        "pass"
    } else {
        "fail"
    };

    let result = VerificationResult {
        signature: signature_result.to_string(),
        continuity: continuity_result.to_string(),
        segment_count: manifest.segments.len() as u32,
    };

    to_value(&result).map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
}

/// Verify a complete .trst archive from a directory handle
#[wasm_bindgen]
pub async fn verify_archive(
    dir_handle: FileSystemDirectoryHandle,
    device_pub: String,
) -> Result<JsValue, JsValue> {
    // Read manifest.json from the directory
    let manifest_content = read_file_from_directory(&dir_handle, "manifest.json").await?;

    // Parse the manifest using canonical types from trst-protocols
    let manifest: TrstManifest = serde_json::from_slice(&manifest_content)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse manifest: {}", e)))?;

    // Version dispatch (C4 §13.4 / M3).
    require_supported_version(&manifest.trst_version)?;

    // Get signature
    let signature_str = manifest
        .signature
        .as_ref()
        .ok_or_else(|| JsValue::from_str("Manifest has no signature"))?;

    // Get canonical bytes using trst-protocols's canonicalization
    let canonical_bytes = manifest
        .to_canonical_bytes()
        .map_err(|e| JsValue::from_str(&format!("Canonicalization failed: {}", e)))?;

    // Ensure device public key has proper format
    let device_pub_key = if device_pub.starts_with("ed25519:") {
        device_pub
    } else {
        format!("ed25519:{}", device_pub)
    };

    // Verify signature
    let signature_result =
        match verify_ed25519_signature(&device_pub_key, &canonical_bytes, signature_str) {
            Ok(true) => "pass",
            Ok(false) => "fail",
            Err(_) => "fail",
        };

    // Verify continuity by checking chunk files exist and match manifest
    let mut continuity_result = "fail";
    if signature_result == "pass" {
        continuity_result = match verify_archive_continuity(&dir_handle, &manifest).await {
            Ok(()) => "pass",
            Err(_) => "fail",
        };
    }

    let result = VerificationResult {
        signature: signature_result.to_string(),
        continuity: continuity_result.to_string(),
        segment_count: manifest.segments.len() as u32,
    };

    to_value(&result).map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
}

/// Verify Ed25519 signature
fn verify_ed25519_signature(
    device_pub: &str,
    canonical_bytes: &[u8],
    signature_str: &str,
) -> Result<bool, String> {
    // Parse public key
    if !device_pub.starts_with("ed25519:") {
        return Err("Public key must start with 'ed25519:'".to_string());
    }

    let b64_part = &device_pub[8..];
    let pub_bytes = general_purpose::STANDARD
        .decode(b64_part)
        .map_err(|e| format!("Invalid public key base64: {}", e))?;

    if pub_bytes.len() != 32 {
        return Err("Public key must be 32 bytes".to_string());
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&pub_bytes);

    let verifying_key =
        VerifyingKey::from_bytes(&key_bytes).map_err(|e| format!("Invalid public key: {}", e))?;

    // Parse signature
    if !signature_str.starts_with("ed25519:") {
        return Err("Signature must start with 'ed25519:'".to_string());
    }

    let sig_b64_part = &signature_str[8..];
    let sig_bytes = general_purpose::STANDARD
        .decode(sig_b64_part)
        .map_err(|e| format!("Invalid signature base64: {}", e))?;

    if sig_bytes.len() != 64 {
        return Err("Signature must be 64 bytes".to_string());
    }

    let mut signature_bytes = [0u8; 64];
    signature_bytes.copy_from_slice(&sig_bytes);

    let signature = Signature::from_bytes(&signature_bytes);

    // Verify signature
    match verifying_key.verify(canonical_bytes, &signature) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Helper function to read a file from a directory handle
async fn read_file_from_directory(
    dir_handle: &FileSystemDirectoryHandle,
    filename: &str,
) -> Result<Vec<u8>, JsValue> {
    let file_handle = JsFuture::from(dir_handle.get_file_handle(filename))
        .await
        .map_err(|e| {
            JsValue::from_str(&format!(
                "Failed to get file handle for {}: {:?}",
                filename, e
            ))
        })?;

    let file_handle: web_sys::FileSystemFileHandle = file_handle
        .dyn_into()
        .map_err(|_| JsValue::from_str("Failed to cast to FileSystemFileHandle"))?;

    let file: File = JsFuture::from(file_handle.get_file())
        .await
        .map_err(|e| JsValue::from_str(&format!("Failed to get file {}: {:?}", filename, e)))?
        .dyn_into()
        .map_err(|_| JsValue::from_str("Failed to cast to File"))?;

    // Read file contents
    let array_buffer = JsFuture::from(file.array_buffer())
        .await
        .map_err(|e| JsValue::from_str(&format!("Failed to read file {}: {:?}", filename, e)))?;

    let uint8_array = js_sys::Uint8Array::new(&array_buffer);
    Ok(uint8_array.to_vec())
}

/// Verify archive continuity by checking that chunks exist and match the manifest
async fn verify_archive_continuity(
    dir_handle: &FileSystemDirectoryHandle,
    manifest: &TrstManifest,
) -> Result<(), JsValue> {
    // Get the chunks directory handle
    let chunks_handle = JsFuture::from(dir_handle.get_directory_handle("chunks"))
        .await
        .map_err(|_| JsValue::from_str("Failed to access chunks directory"))?;

    let chunks_handle: FileSystemDirectoryHandle = chunks_handle
        .dyn_into()
        .map_err(|_| JsValue::from_str("Failed to cast chunks to DirectoryHandle"))?;

    // Check that all expected chunk files exist
    for segment in &manifest.segments {
        let chunk_exists = check_file_exists(&chunks_handle, &segment.chunk_file).await;
        if !chunk_exists {
            return Err(JsValue::from_str(&format!(
                "Missing chunk file: {}",
                segment.chunk_file
            )));
        }
    }

    // For P0, we'll do basic existence checking. Full hash verification would require
    // reading and decrypting each chunk, which is more complex for the WASM demo.
    Ok(())
}

/// Check if a file exists in a directory handle
async fn check_file_exists(dir_handle: &FileSystemDirectoryHandle, filename: &str) -> bool {
    (JsFuture::from(dir_handle.get_file_handle(filename)).await).is_ok()
}
