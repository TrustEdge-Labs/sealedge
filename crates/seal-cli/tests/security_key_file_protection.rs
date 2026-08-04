//
// Copyright (c) 2025 TRUSTEDGE LABS LLC
// This source code is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Project: sealedge — Privacy and trust at the edge.
//

//! Security tests for SEALEDGE-KEY-V1 encrypted key format — covers threat model T3 (key protection).
//!
//! Tests are organized by requirement:
//!   KEY-01: Auto-generated key files from trst wrap have 0600 Unix permissions
//!   SEC-08: Truncated encrypted key files are rejected with explicit errors (no panic, no partial key)
//!   SEC-09: Corrupted JSON headers in encrypted key files produce clear parse errors
//!   SEC-10: Wrong passphrase on a valid encrypted key file returns a clear authentication error
//!   SEC-11: Additional truncation points (single-byte ciphertext, GCM tag boundary)
//!   SEC-12: Corrupted JSON fields (version type, iterations type, nonce base64, salt length, unknown fields)

// Allow deprecated cargo_bin usage - the replacement cargo_bin_cmd! macro
// is not yet stable across all assert_cmd versions
#![allow(deprecated)]

use assert_cmd::prelude::*;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use sealedge_core::{CryptoError, DeviceKeypair};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// KEY-01: Auto-generated wrap key file permissions
// ---------------------------------------------------------------------------

/// KEY-01: After `trst wrap --unencrypted` auto-generates a keypair, the secret key
/// file (`device.key`) must have Unix mode 0600 (owner-read/write only).
///
/// This prevents world-readable key files created by the default umask.
#[cfg(unix)]
#[test]
fn test_wrap_autogen_key_permissions_0600() {
    use std::os::unix::fs::PermissionsExt;

    let tempdir = TempDir::new().expect("failed to create tempdir");

    // Write a small dummy input file
    let input_path = tempdir.path().join("input.bin");
    let data: Vec<u8> = (0..1024).map(|i| (i % 251) as u8).collect();
    fs::write(&input_path, &data).expect("failed to write input");

    let archive_path = tempdir.path().join("archive.seal");

    // Run trst wrap without --device-key so it auto-generates the keypair
    Command::cargo_bin("seal")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "wrap",
            "--in",
            input_path.to_str().unwrap(),
            "--out",
            archive_path.to_str().unwrap(),
            "--unencrypted",
        ])
        .assert()
        .success();

    // Check that device.key exists and has mode 0600
    let key_path: PathBuf = tempdir.path().join("device.key");
    assert!(key_path.exists(), "device.key was not created");

    let metadata = fs::metadata(&key_path).expect("failed to stat device.key");
    let mode = metadata.permissions().mode();
    // 0o100600 = regular file (0o100000) | owner rw (0o600)
    assert_eq!(
        mode & 0o777,
        0o600,
        "device.key must have mode 0600, got mode {:o}",
        mode & 0o777
    );

    // Public key should exist but NOT have restricted permissions (no assertion on pub key mode)
    let pub_path: PathBuf = tempdir.path().join("device.pub");
    assert!(pub_path.exists(), "device.pub was not created");
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Generate a valid encrypted key file using a known passphrase.
/// Returns the raw bytes of the SEALEDGE-KEY-V1 format.
fn make_valid_encrypted_key() -> Vec<u8> {
    let keypair = DeviceKeypair::generate().expect("generate must succeed");
    keypair
        .export_secret_encrypted("test-passphrase-123")
        .expect("export_secret_encrypted must succeed")
}

/// Build a syntactically valid metadata JSON line with correct base64 fields
/// but allow overriding individual fields for targeted corruption tests.
fn build_corrupted_key_file(meta_json: &str, ciphertext: &[u8]) -> Vec<u8> {
    let mut data = b"SEALEDGE-KEY-V1\n".to_vec();
    data.extend_from_slice(meta_json.as_bytes());
    data.push(b'\n');
    data.extend_from_slice(ciphertext);
    data
}

/// Assert that the error is `CryptoError::InvalidKeyFormat` containing the expected substring.
fn assert_invalid_key_format(result: Result<DeviceKeypair, CryptoError>, expected_substr: &str) {
    match result {
        Err(CryptoError::InvalidKeyFormat(msg)) => {
            assert!(
                msg.contains(expected_substr),
                "expected error message to contain {:?}, got: {:?}",
                expected_substr,
                msg
            );
        }
        Err(other) => panic!(
            "expected InvalidKeyFormat({:?}), got: {:?}",
            expected_substr, other
        ),
        Ok(_) => panic!(
            "expected Err(InvalidKeyFormat({:?})), got Ok",
            expected_substr
        ),
    }
}

/// Assert that the error is `CryptoError::DecryptionFailed` containing the expected substring.
fn assert_decryption_failed(result: Result<DeviceKeypair, CryptoError>, expected_substr: &str) {
    match result {
        Err(CryptoError::DecryptionFailed(msg)) => {
            assert!(
                msg.contains(expected_substr),
                "expected error message to contain {:?}, got: {:?}",
                expected_substr,
                msg
            );
        }
        Err(other) => panic!(
            "expected DecryptionFailed({:?}), got: {:?}",
            expected_substr, other
        ),
        Ok(_) => panic!(
            "expected Err(DecryptionFailed({:?})), got Ok",
            expected_substr
        ),
    }
}

// ---------------------------------------------------------------------------
// SEC-08: Truncated files
// ---------------------------------------------------------------------------

/// SEC-08: Data "SEALEDGE-KEY" (no newline) is rejected with "Missing header line".
///
/// The format requires a newline-terminated header as its first structural element.
/// A file that ends before the first newline cannot be parsed and must be rejected.
#[test]
fn sec_08_truncated_before_header_newline() {
    let data = b"SEALEDGE-KEY".to_vec();
    let result = DeviceKeypair::import_secret_encrypted(&data, "any-passphrase");
    assert_invalid_key_format(result, "Missing header line");
}

/// SEC-08: Data "SEALEDGE-KEY-V1\n" (header only, no JSON metadata) is rejected with "Missing metadata line".
///
/// After parsing the header the parser expects a second newline-terminated line
/// containing the JSON metadata. A file that ends after the header newline must be rejected.
#[test]
fn sec_08_truncated_after_header() {
    let data = b"SEALEDGE-KEY-V1\n".to_vec();
    let result = DeviceKeypair::import_secret_encrypted(&data, "any-passphrase");
    assert_invalid_key_format(result, "Missing metadata line");
}

/// SEC-08: Partial JSON "SEALEDGE-KEY-V1\n{\"salt\":" (no closing newline) is rejected.
///
/// If the metadata line is truncated mid-way (no second newline found), the parser
/// must detect the missing structural delimiter and reject the file.
#[test]
fn sec_08_truncated_mid_json() {
    let data = b"SEALEDGE-KEY-V1\n{\"salt\":".to_vec();
    let result = DeviceKeypair::import_secret_encrypted(&data, "any-passphrase");
    assert_invalid_key_format(result, "Missing metadata line");
}

/// SEC-08: Valid header + valid JSON + newline but zero ciphertext bytes is rejected.
///
/// AES-256-GCM requires at least 16 bytes of authentication tag; an empty ciphertext
/// section cannot be decrypted and must produce DecryptionFailed.
#[test]
fn sec_08_truncated_no_ciphertext() {
    let valid = make_valid_encrypted_key();
    // Find the end of the second line (after the metadata newline)
    let first_newline = valid.iter().position(|&b| b == b'\n').unwrap();
    let second_newline = valid[first_newline + 1..]
        .iter()
        .position(|&b| b == b'\n')
        .unwrap()
        + first_newline
        + 1;
    // Truncate to include header and metadata but zero ciphertext bytes
    let truncated = valid[..=second_newline].to_vec();
    let result = DeviceKeypair::import_secret_encrypted(&truncated, "test-passphrase-123");
    assert_decryption_failed(result, "Wrong passphrase");
}

/// SEC-08: Valid header + valid JSON + newline + first half of ciphertext is rejected.
///
/// A file truncated mid-ciphertext loses the AES-GCM authentication tag and must
/// fail authentication, producing DecryptionFailed.
#[test]
fn sec_08_truncated_mid_ciphertext() {
    let valid = make_valid_encrypted_key();
    let first_newline = valid.iter().position(|&b| b == b'\n').unwrap();
    let second_newline = valid[first_newline + 1..]
        .iter()
        .position(|&b| b == b'\n')
        .unwrap()
        + first_newline
        + 1;
    let ciphertext_start = second_newline + 1;
    let ciphertext_len = valid.len() - ciphertext_start;
    // Keep only the first half of the ciphertext
    let half = ciphertext_len / 2;
    let truncated = valid[..ciphertext_start + half].to_vec();
    let result = DeviceKeypair::import_secret_encrypted(&truncated, "test-passphrase-123");
    assert_decryption_failed(result, "Wrong passphrase");
}

// ---------------------------------------------------------------------------
// SEC-09: Corrupted JSON header
// ---------------------------------------------------------------------------

/// SEC-09: Non-JSON second line is rejected with "Invalid JSON metadata".
///
/// When the metadata line is present but cannot be parsed as JSON, the parser
/// must report the structural error clearly.
#[test]
fn sec_09_json_not_json() {
    let data = build_corrupted_key_file("not-json-at-all", b"dummy-ciphertext");
    let result = DeviceKeypair::import_secret_encrypted(&data, "any-passphrase");
    assert_invalid_key_format(result, "Invalid JSON metadata");
}

/// SEC-09: Valid JSON missing the "salt" field is rejected with "Missing salt".
#[test]
fn sec_09_json_missing_salt() {
    let meta = r#"{"nonce":"AAAAAAAAAAAAAAAA","iterations":600000}"#;
    let data = build_corrupted_key_file(meta, b"dummy-ciphertext");
    let result = DeviceKeypair::import_secret_encrypted(&data, "any-passphrase");
    assert_invalid_key_format(result, "Missing salt");
}

/// SEC-09: Valid JSON missing the "nonce" field is rejected with "Missing nonce".
#[test]
fn sec_09_json_missing_nonce() {
    let salt_b64 = BASE64.encode([0u8; 32]);
    let meta = format!(r#"{{"salt":"{salt_b64}","iterations":600000}}"#);
    let data = build_corrupted_key_file(&meta, b"dummy-ciphertext");
    let result = DeviceKeypair::import_secret_encrypted(&data, "any-passphrase");
    assert_invalid_key_format(result, "Missing nonce");
}

/// SEC-09: Valid JSON missing the "iterations" field is rejected with "Missing iterations".
#[test]
fn sec_09_json_missing_iterations() {
    let salt_b64 = BASE64.encode([0u8; 32]);
    let nonce_b64 = BASE64.encode([0u8; 12]);
    let meta = format!(r#"{{"salt":"{salt_b64}","nonce":"{nonce_b64}"}}"#);
    let data = build_corrupted_key_file(&meta, b"dummy-ciphertext");
    let result = DeviceKeypair::import_secret_encrypted(&data, "any-passphrase");
    assert_invalid_key_format(result, "Missing iterations");
}

/// SEC-09: Salt field containing invalid base64 "!!not-base64!!" is rejected with "Invalid salt base64".
#[test]
fn sec_09_json_bad_base64_salt() {
    let nonce_b64 = BASE64.encode([0u8; 12]);
    let meta = format!(r#"{{"salt":"!!not-base64!!","nonce":"{nonce_b64}","iterations":600000}}"#);
    let data = build_corrupted_key_file(&meta, b"dummy-ciphertext");
    let result = DeviceKeypair::import_secret_encrypted(&data, "any-passphrase");
    assert_invalid_key_format(result, "Invalid salt base64");
}

/// SEC-09: Nonce field with valid base64 decoding to 8 bytes (not 12) is rejected with "Nonce must be 12 bytes".
///
/// AES-256-GCM requires exactly 12-byte nonces. A nonce of any other length must
/// be explicitly rejected rather than silently truncated or padded.
#[test]
fn sec_09_json_wrong_nonce_length() {
    let salt_b64 = BASE64.encode([0u8; 32]);
    // 8 bytes of nonce — valid base64, wrong length
    let short_nonce_b64 = BASE64.encode([0u8; 8]);
    let meta =
        format!(r#"{{"salt":"{salt_b64}","nonce":"{short_nonce_b64}","iterations":600000}}"#);
    let data = build_corrupted_key_file(&meta, b"dummy-ciphertext");
    let result = DeviceKeypair::import_secret_encrypted(&data, "any-passphrase");
    assert_invalid_key_format(result, "Nonce must be 12 bytes");
}

// ---------------------------------------------------------------------------
// SEC-10: Wrong passphrase
// ---------------------------------------------------------------------------

/// SEC-10: Encrypting with "correct" and importing with "wrong" returns DecryptionFailed.
///
/// The AES-GCM authentication tag ensures that a wrong passphrase produces a
/// distinct decryption key that fails the integrity check, not garbage plaintext.
#[test]
fn sec_10_wrong_passphrase_returns_error() {
    let valid = make_valid_encrypted_key();
    let result = DeviceKeypair::import_secret_encrypted(&valid, "wrong-passphrase");
    assert_decryption_failed(result, "Wrong passphrase");
}

/// SEC-10: Wrong passphrase produces DecryptionFailed variant (not Ok with garbage key material).
///
/// This test explicitly pattern-matches the error variant to confirm no key material
/// is returned — a AEAD scheme must either authenticate successfully or fail entirely.
#[test]
fn sec_10_wrong_passphrase_no_partial_key() {
    let valid = make_valid_encrypted_key();
    let result = DeviceKeypair::import_secret_encrypted(&valid, "wrong-passphrase");
    assert!(
        matches!(result, Err(CryptoError::DecryptionFailed(_))),
        "expected Err(DecryptionFailed(_)) but got a different variant or Ok"
    );
}

/// SEC-10: Empty passphrase on a key encrypted with a real passphrase returns DecryptionFailed.
///
/// An empty string must not be treated as a special bypass or default credential.
/// PBKDF2 with an empty passphrase derives a different key, which the AES-GCM tag rejects.
#[test]
fn sec_10_empty_passphrase() {
    let valid = make_valid_encrypted_key();
    let result = DeviceKeypair::import_secret_encrypted(&valid, "");
    assert_decryption_failed(result, "Wrong passphrase");
}

// ---------------------------------------------------------------------------
// SEC-11: Additional truncation boundaries
// ---------------------------------------------------------------------------

/// SEC-11: Ciphertext truncated to a single byte is rejected with DecryptionFailed.
///
/// AES-256-GCM requires at least 16 bytes of authentication tag. A ciphertext of only
/// 1 byte cannot contain a valid AEAD tag and must be rejected without panicking.
#[test]
fn sec_11_truncated_single_byte_ciphertext() {
    let valid = make_valid_encrypted_key();
    // Find the ciphertext start (after second newline)
    let first_newline = valid.iter().position(|&b| b == b'\n').unwrap();
    let second_newline = valid[first_newline + 1..]
        .iter()
        .position(|&b| b == b'\n')
        .unwrap()
        + first_newline
        + 1;
    let ciphertext_start = second_newline + 1;
    // Keep only 1 byte of ciphertext
    let mut truncated = valid[..ciphertext_start].to_vec();
    truncated.push(valid[ciphertext_start]);
    let result = DeviceKeypair::import_secret_encrypted(&truncated, "test-passphrase-123");
    assert_decryption_failed(result, "Wrong passphrase");
}

/// SEC-11: Ciphertext truncated to exactly 16 bytes (AES-GCM tag size, no plaintext) is rejected.
///
/// Even when the ciphertext is exactly the size of an AES-GCM authentication tag,
/// the tag will fail to authenticate because the expected plaintext is absent.
/// This confirms the implementation does not panic on minimum-size inputs.
#[test]
fn sec_11_truncated_at_gcm_tag_boundary() {
    let valid = make_valid_encrypted_key();
    // Find the ciphertext start (after second newline)
    let first_newline = valid.iter().position(|&b| b == b'\n').unwrap();
    let second_newline = valid[first_newline + 1..]
        .iter()
        .position(|&b| b == b'\n')
        .unwrap()
        + first_newline
        + 1;
    let ciphertext_start = second_newline + 1;
    // Keep exactly 16 bytes of ciphertext (AES-GCM tag size)
    let truncated = valid[..ciphertext_start + 16].to_vec();
    let result = DeviceKeypair::import_secret_encrypted(&truncated, "test-passphrase-123");
    assert_decryption_failed(result, "Wrong passphrase");
}

// ---------------------------------------------------------------------------
// SEC-12: Corrupted JSON fields (extended)
// ---------------------------------------------------------------------------

/// SEC-12: "version" field present with wrong type (string instead of integer) is tolerated.
///
/// The import function reads version via `as_u64()` which returns None for a string value;
/// the implementation currently does not validate version, so it proceeds to decryption.
/// The dummy ciphertext then fails AEAD authentication. This confirms that an unexpected
/// version field type does not cause a panic or InvalidKeyFormat — backward compat is maintained.
#[test]
fn sec_12_json_version_wrong_type() {
    let salt_b64 = BASE64.encode([0u8; 32]);
    let nonce_b64 = BASE64.encode([0u8; 12]);
    let meta = format!(
        r#"{{"version":"not-a-number","salt":"{salt_b64}","nonce":"{nonce_b64}","iterations":600000}}"#
    );
    let data = build_corrupted_key_file(&meta, b"dummy-ciphertext");
    let result = DeviceKeypair::import_secret_encrypted(&data, "any-passphrase");
    assert_decryption_failed(result, "Wrong passphrase");
}

/// SEC-12: "iterations" field with wrong type (string instead of integer) is rejected with "Missing iterations".
///
/// The import reads iterations via `.as_u64()`. A string value returns None,
/// which must be treated as a missing field — not silently defaulted to zero or any other value.
#[test]
fn sec_12_json_iterations_wrong_type() {
    let salt_b64 = BASE64.encode([0u8; 32]);
    let nonce_b64 = BASE64.encode([0u8; 12]);
    let meta =
        format!(r#"{{"salt":"{salt_b64}","nonce":"{nonce_b64}","iterations":"not-a-number"}}"#);
    let data = build_corrupted_key_file(&meta, b"dummy-ciphertext");
    let result = DeviceKeypair::import_secret_encrypted(&data, "any-passphrase");
    assert_invalid_key_format(result, "Missing iterations");
}

/// SEC-12: "nonce" field with invalid base64 characters is rejected with "Invalid nonce base64".
///
/// The import decodes nonce via the standard base64 engine. Characters outside the
/// base64 alphabet must produce a decode error, not garbage bytes used as a nonce.
#[test]
fn sec_12_json_nonce_bad_base64() {
    let salt_b64 = BASE64.encode([0u8; 32]);
    let meta = format!(r#"{{"salt":"{salt_b64}","nonce":"$$invalid$$","iterations":600000}}"#);
    let data = build_corrupted_key_file(&meta, b"dummy-ciphertext");
    let result = DeviceKeypair::import_secret_encrypted(&data, "any-passphrase");
    assert_invalid_key_format(result, "Invalid nonce base64");
}

/// SEC-12: "salt" field containing only 16 bytes (too short) causes PBKDF2 to derive a different key.
///
/// A 16-byte salt is valid base64 but produces a different derived key than a 32-byte salt.
/// The AES-GCM authentication tag then rejects the decryption. This confirms short salts
/// do not cause panics — the implementation handles any salt length gracefully.
#[test]
fn sec_12_json_salt_wrong_length() {
    // 16-byte salt (half of the expected 32 bytes)
    let salt_b64 = BASE64.encode([0u8; 16]);
    let nonce_b64 = BASE64.encode([0u8; 12]);
    let meta = format!(r#"{{"salt":"{salt_b64}","nonce":"{nonce_b64}","iterations":600000}}"#);
    let data = build_corrupted_key_file(&meta, b"dummy-ciphertext");
    let result = DeviceKeypair::import_secret_encrypted(&data, "any-passphrase");
    assert_decryption_failed(result, "Wrong passphrase");
}

/// SEC-12: Extra unknown JSON fields are tolerated — the parser does not reject forward-compatible fields.
///
/// Unknown fields in the metadata JSON must not cause an `InvalidKeyFormat` error.
/// This allows future format evolution (e.g., adding a "kdf_variant" field) without
/// breaking older parsers. The dummy ciphertext still fails AEAD, producing DecryptionFailed.
#[test]
fn sec_12_json_extra_unknown_fields() {
    let salt_b64 = BASE64.encode([0u8; 32]);
    let nonce_b64 = BASE64.encode([0u8; 12]);
    let meta = format!(
        r#"{{"salt":"{salt_b64}","nonce":"{nonce_b64}","iterations":600000,"future_field":"ignored","another":42}}"#
    );
    let data = build_corrupted_key_file(&meta, b"dummy-ciphertext");
    let result = DeviceKeypair::import_secret_encrypted(&data, "any-passphrase");
    // Must NOT fail with InvalidKeyFormat — unknown fields are tolerated
    assert_decryption_failed(result, "Wrong passphrase");
}
