//
// Copyright (c) 2025 TRUSTEDGE LABS LLC
// This source code is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Project: sealedge — Privacy and trust at the edge.
//

// Allow deprecated cargo_bin usage - the replacement cargo_bin_cmd! macro
// is not yet stable across all assert_cmd versions
#![allow(deprecated)]

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_wrap_and_verify_basic_workflow() {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();

    // Create test input file
    let input_file = temp_path.join("test-input.bin");
    fs::write(&input_file, b"Hello, Sealedge P0 Implementation!").unwrap();

    // Create output archive path
    let output_archive = temp_path.join("test-archive.seal");

    // Run wrap command
    let mut cmd = Command::cargo_bin("seal").unwrap();
    cmd.arg("wrap")
        .arg("--profile")
        .arg("cam.video")
        .arg("--in")
        .arg(&input_file)
        .arg("--out")
        .arg(&output_archive)
        .arg("--chunk-size")
        .arg("1048576")
        .arg("--chunk-seconds")
        .arg("2.0")
        .arg("--fps")
        .arg("30")
        .arg("--unencrypted")
        .current_dir(temp_path);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Archive:"))
        .stdout(predicate::str::contains("Signature:"))
        .stdout(predicate::str::contains("Segments: 1"))
        .stdout(predicate::str::contains("Generated device key: device.key"))
        .stdout(predicate::str::contains("Generated device pub: device.pub"));

    // Check that files were created
    assert!(output_archive.exists());
    assert!(output_archive.join("manifest.json").exists());
    assert!(output_archive.join("chunks").join("00000.bin").exists());
    assert!(output_archive
        .join("signatures")
        .join("manifest.sig")
        .exists());
    assert!(temp_path.join("device.key").exists());
    assert!(temp_path.join("device.pub").exists());

    // Read the generated device public key
    let device_pub_file = fs::read_to_string(temp_path.join("device.pub")).unwrap();
    let device_pub = device_pub_file
        .lines()
        .find(|l| l.starts_with("ed25519:"))
        .unwrap();

    // Run verify command
    let mut verify_cmd = Command::cargo_bin("seal").unwrap();
    verify_cmd
        .arg("verify")
        .arg(&output_archive)
        .arg("--device-pub")
        .arg(device_pub)
        .current_dir(temp_path);

    verify_cmd
        .assert()
        .success()
        .stdout(predicate::str::contains("Signature: PASS"))
        .stdout(predicate::str::contains("Continuity: PASS"))
        .stdout(predicate::str::contains("Segments: 1"));
}

#[test]
fn test_wrap_with_existing_device_key() {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();

    // Create test input file
    let input_file = temp_path.join("test-input.bin");
    fs::write(&input_file, b"Test with existing key").unwrap();

    // Generate an existing V2 key bundle up front, then wrap against it.
    let device_key_file = temp_path.join("my-device.key");
    let device_pub_file = temp_path.join("my-device.pub");
    Command::cargo_bin("seal")
        .unwrap()
        .arg("keygen")
        .arg("--out-key")
        .arg(&device_key_file)
        .arg("--out-pub")
        .arg(&device_pub_file)
        .arg("--unencrypted")
        .current_dir(temp_path)
        .assert()
        .success();

    // Create output archive path
    let output_archive = temp_path.join("test-archive.seal");

    // Run wrap command with existing key
    let mut cmd = Command::cargo_bin("seal").unwrap();
    cmd.arg("wrap")
        .arg("--profile")
        .arg("cam.video")
        .arg("--in")
        .arg(&input_file)
        .arg("--out")
        .arg(&output_archive)
        .arg("--device-key")
        .arg(&device_key_file)
        .arg("--unencrypted")
        .current_dir(temp_path);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Archive:"))
        .stdout(predicate::str::contains("Signature:"))
        .stdout(predicate::str::contains("Segments: 1"))
        .stdout(predicate::str::contains("Generated device key").not());

    // The Ed25519 public key line for the generated key.
    let pub_content = fs::read_to_string(&device_pub_file).unwrap();
    let expected_pub_key = pub_content
        .lines()
        .find(|l| l.starts_with("ed25519:"))
        .unwrap();

    // Run verify command
    let mut verify_cmd = Command::cargo_bin("seal").unwrap();
    verify_cmd
        .arg("verify")
        .arg(&output_archive)
        .arg("--device-pub")
        .arg(expected_pub_key)
        .current_dir(temp_path);

    verify_cmd
        .assert()
        .success()
        .stdout(predicate::str::contains("Signature: PASS"))
        .stdout(predicate::str::contains("Continuity: PASS"));
}

#[test]
fn test_verify_with_wrong_public_key() {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();

    // Create test input file and archive first
    let input_file = temp_path.join("test-input.bin");
    fs::write(&input_file, b"Test verification failure").unwrap();

    let output_archive = temp_path.join("test-archive.seal");

    // Run wrap command
    let mut cmd = Command::cargo_bin("seal").unwrap();
    cmd.arg("wrap")
        .arg("--profile")
        .arg("cam.video")
        .arg("--in")
        .arg(&input_file)
        .arg("--out")
        .arg(&output_archive)
        .arg("--unencrypted")
        .current_dir(temp_path);

    cmd.assert().success();

    // Try to verify with wrong public key
    let wrong_pub_key = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    let mut verify_cmd = Command::cargo_bin("seal").unwrap();
    verify_cmd
        .arg("verify")
        .arg(&output_archive)
        .arg("--device-pub")
        .arg(wrong_pub_key)
        .current_dir(temp_path);

    verify_cmd.assert().failure().code(10); // signature_fail
}

#[test]
fn test_wrap_nonexistent_input_file() {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();

    let nonexistent_file = temp_path.join("does-not-exist.bin");
    let output_archive = temp_path.join("test-archive.seal");

    let mut cmd = Command::cargo_bin("seal").unwrap();
    cmd.arg("wrap")
        .arg("--profile")
        .arg("cam.video")
        .arg("--in")
        .arg(&nonexistent_file)
        .arg("--out")
        .arg(&output_archive)
        .arg("--unencrypted")
        .current_dir(temp_path);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Failed to read input file"));
}

#[test]
fn test_verify_nonexistent_archive() {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();

    let nonexistent_archive = temp_path.join("does-not-exist.seal");
    let pub_key = "ed25519:tQ8g8XOQSKfRFBEzHzQcGsNWz9t4pf04sJMCPElcRZ0=";

    let mut cmd = Command::cargo_bin("seal").unwrap();
    cmd.arg("verify")
        .arg(&nonexistent_archive)
        .arg("--device-pub")
        .arg(pub_key)
        .current_dir(temp_path);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("error"));
}

#[test]
fn test_invalid_output_directory_name() {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();

    let input_file = temp_path.join("test-input.bin");
    fs::write(&input_file, b"Test invalid output name").unwrap();

    let invalid_output = temp_path.join("invalid-name-without-trst-extension");

    let mut cmd = Command::cargo_bin("seal").unwrap();
    cmd.arg("wrap")
        .arg("--profile")
        .arg("cam.video")
        .arg("--in")
        .arg(&input_file)
        .arg("--out")
        .arg(&invalid_output)
        .arg("--unencrypted")
        .current_dir(temp_path);

    cmd.assert().failure().stderr(predicate::str::contains(
        "Output directory must end with .seal",
    ));
}

#[test]
fn test_verify_emit_receipt() {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();

    // Create test input file
    let input_file = temp_path.join("test-input.bin");
    fs::write(&input_file, b"Test emit receipt functionality").unwrap();

    // Create output archive path
    let output_archive = temp_path.join("test-archive.seal");

    // Run wrap command to create archive
    let mut cmd = Command::cargo_bin("seal").unwrap();
    cmd.arg("wrap")
        .arg("--profile")
        .arg("cam.video")
        .arg("--in")
        .arg(&input_file)
        .arg("--out")
        .arg(&output_archive)
        .arg("--unencrypted")
        .current_dir(temp_path);

    cmd.assert().success();

    // Read the generated device public key
    let device_pub_file = fs::read_to_string(temp_path.join("device.pub")).unwrap();
    let device_pub = device_pub_file
        .lines()
        .find(|l| l.starts_with("ed25519:"))
        .unwrap();

    // Test emit-receipt without --json (human output + receipt file)
    let receipt_path = temp_path.join("receipt.json");
    let mut verify_cmd = Command::cargo_bin("seal").unwrap();
    verify_cmd
        .arg("verify")
        .arg(&output_archive)
        .arg("--device-pub")
        .arg(device_pub)
        .arg("--emit-receipt")
        .arg(&receipt_path)
        .current_dir(temp_path);

    verify_cmd
        .assert()
        .success()
        .stdout(predicate::str::contains("Signature: PASS"))
        .stdout(predicate::str::contains("Continuity: PASS"));

    // Check that receipt file was created
    assert!(receipt_path.exists());

    // Parse and validate receipt JSON
    let receipt_content = fs::read_to_string(&receipt_path).unwrap();
    let receipt: Value = serde_json::from_str(&receipt_content).unwrap();

    // Validate receipt structure and values
    assert_eq!(receipt["signature"], "pass");
    assert_eq!(receipt["continuity"], "pass");
    assert_eq!(receipt["profile"], "cam.video");
    assert!(receipt["verify_time_ms"].as_u64().is_some());
    assert!(receipt["segments"].as_u64().unwrap() >= 1);

    // Test emit-receipt with --json (JSON output + identical receipt file)
    let receipt_path_json = temp_path.join("receipt-json.json");
    let mut verify_json_cmd = Command::cargo_bin("seal").unwrap();
    verify_json_cmd
        .arg("verify")
        .arg(&output_archive)
        .arg("--device-pub")
        .arg(device_pub)
        .arg("--json")
        .arg("--emit-receipt")
        .arg(&receipt_path_json)
        .current_dir(temp_path);

    let json_output = verify_json_cmd
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    // Check that receipt file was created
    assert!(receipt_path_json.exists());

    // Parse JSON output from stdout
    let stdout_json: Value = serde_json::from_slice(&json_output).unwrap();

    // Parse receipt file content
    let receipt_file_content = fs::read_to_string(&receipt_path_json).unwrap();
    let receipt_file_json: Value = serde_json::from_str(&receipt_file_content).unwrap();

    // Verify that stdout JSON and receipt file contain equivalent data
    assert_eq!(stdout_json["signature"], receipt_file_json["signature"]);
    assert_eq!(stdout_json["continuity"], receipt_file_json["continuity"]);
    assert_eq!(stdout_json["profile"], receipt_file_json["profile"]);
    assert_eq!(stdout_json["segments"], receipt_file_json["segments"]);

    // Both should indicate pass/pass
    assert!(receipt_file_json["signature"] == "pass" || receipt_file_json["signature"] == "fail");
}

#[test]
fn test_seed_deterministic_output() {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();

    // Create test input file
    let input_file = temp_path.join("test-input.bin");
    fs::write(
        &input_file,
        b"Test deterministic seeded output functionality",
    )
    .unwrap();

    // Generate a device key bundle for consistent results across wraps.
    let device_key_file = temp_path.join("test-device.key");
    Command::cargo_bin("seal")
        .unwrap()
        .arg("keygen")
        .arg("--out-key")
        .arg(&device_key_file)
        .arg("--out-pub")
        .arg(temp_path.join("test-device.pub"))
        .arg("--unencrypted")
        .current_dir(temp_path)
        .assert()
        .success();

    // Create first archive with seed
    let output_archive1 = temp_path.join("test-archive1.seal");
    let mut cmd1 = Command::cargo_bin("seal").unwrap();
    cmd1.arg("wrap")
        .arg("--profile")
        .arg("cam.video")
        .arg("--in")
        .arg(&input_file)
        .arg("--out")
        .arg(&output_archive1)
        .arg("--device-key")
        .arg(&device_key_file)
        .arg("--seed")
        .arg("42")
        .arg("--unencrypted")
        .current_dir(temp_path);

    cmd1.assert().success();

    // Create second archive with same seed and device key
    let output_archive2 = temp_path.join("test-archive2.seal");
    let mut cmd2 = Command::cargo_bin("seal").unwrap();
    cmd2.arg("wrap")
        .arg("--profile")
        .arg("cam.video")
        .arg("--in")
        .arg(&input_file)
        .arg("--out")
        .arg(&output_archive2)
        .arg("--device-key")
        .arg(&device_key_file)
        .arg("--seed")
        .arg("42")
        .arg("--unencrypted")
        .current_dir(temp_path);

    cmd2.assert().success();

    // Create third archive without seed (but same device key)
    let output_archive3 = temp_path.join("test-archive3.seal");
    let mut cmd3 = Command::cargo_bin("seal").unwrap();
    cmd3.arg("wrap")
        .arg("--profile")
        .arg("cam.video")
        .arg("--in")
        .arg(&input_file)
        .arg("--out")
        .arg(&output_archive3)
        .arg("--device-key")
        .arg(&device_key_file)
        .arg("--unencrypted")
        .current_dir(temp_path);

    cmd3.assert().success();

    // Read manifests
    let manifest1_content = fs::read_to_string(output_archive1.join("manifest.json")).unwrap();
    let manifest2_content = fs::read_to_string(output_archive2.join("manifest.json")).unwrap();
    let manifest3_content = fs::read_to_string(output_archive3.join("manifest.json")).unwrap();

    let manifest1: Value = serde_json::from_str(&manifest1_content).unwrap();
    let manifest2: Value = serde_json::from_str(&manifest2_content).unwrap();
    let manifest3: Value = serde_json::from_str(&manifest3_content).unwrap();

    // Test that seeded runs produce identical results
    assert_eq!(manifest1["segments"], manifest2["segments"]);
    assert_eq!(
        manifest1["metadata"]["started_at"],
        manifest2["metadata"]["started_at"]
    );
    assert_eq!(
        manifest1["metadata"]["ended_at"],
        manifest2["metadata"]["ended_at"]
    );

    // Check that segment hashes are identical (indicating same nonces were used)
    let segments1 = manifest1["segments"].as_array().unwrap();
    let segments2 = manifest2["segments"].as_array().unwrap();
    for (seg1, seg2) in segments1.iter().zip(segments2.iter()) {
        assert_eq!(seg1["blake3_hash"], seg2["blake3_hash"]);
        assert_eq!(seg1["continuity_hash"], seg2["continuity_hash"]);
    }

    // Test that non-seeded run produces different results
    // (timestamps should be different, and hashes likely different due to different nonces)
    assert_ne!(
        manifest1["metadata"]["started_at"],
        manifest3["metadata"]["started_at"]
    );

    // Segment hashes should be different (due to different nonces)
    let segments3 = manifest3["segments"].as_array().unwrap();
    let different_hashes = segments1
        .iter()
        .zip(segments3.iter())
        .any(|(seg1, seg3)| seg1["blake3_hash"] != seg3["blake3_hash"]);
    assert!(
        different_hashes,
        "Non-seeded run should produce different segment hashes"
    );
}

#[test]
fn test_a1_successful_verification() {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();

    // Create test input file
    let input_file = temp_path.join("test-input.bin");
    fs::write(&input_file, b"A1 test: successful verification").unwrap();

    // Create archive
    let output_archive = temp_path.join("test-archive.seal");
    let mut wrap_cmd = Command::cargo_bin("seal").unwrap();
    wrap_cmd
        .arg("wrap")
        .arg("--profile")
        .arg("cam.video")
        .arg("--in")
        .arg(&input_file)
        .arg("--out")
        .arg(&output_archive)
        .arg("--unencrypted")
        .current_dir(temp_path);

    wrap_cmd.assert().success();

    // Read device public key
    let device_pub_file = fs::read_to_string(temp_path.join("device.pub")).unwrap();
    let device_pub = device_pub_file
        .lines()
        .find(|l| l.starts_with("ed25519:"))
        .unwrap();

    // A1: Successful verification should exit 0
    let mut verify_cmd = Command::cargo_bin("seal").unwrap();
    verify_cmd
        .arg("verify")
        .arg(&output_archive)
        .arg("--device-pub")
        .arg(device_pub)
        .current_dir(temp_path);

    verify_cmd
        .assert()
        .success() // exit code 0
        .stdout(predicate::str::starts_with("Signature: PASS"))
        .stdout(predicate::str::contains("Continuity: PASS"));
}

#[test]
fn test_a2_archive_not_found() {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();

    // A2: Non-existent archive should exit 12
    let mut verify_cmd = Command::cargo_bin("seal").unwrap();
    verify_cmd
        .arg("verify")
        .arg("nonexistent.seal")
        .arg("--device-pub")
        .arg("ed25519:fakepubkey==")
        .current_dir(temp_path);

    verify_cmd.assert().failure().code(12); // io_or_schema error
}

#[test]
fn test_a3_signature_verification_failure() {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();

    // Create test input file
    let input_file = temp_path.join("test-input.bin");
    fs::write(&input_file, b"A3 test: signature verification failure").unwrap();

    // Create archive
    let output_archive = temp_path.join("test-archive.seal");
    let mut wrap_cmd = Command::cargo_bin("seal").unwrap();
    wrap_cmd
        .arg("wrap")
        .arg("--profile")
        .arg("cam.video")
        .arg("--in")
        .arg(&input_file)
        .arg("--out")
        .arg(&output_archive)
        .arg("--unencrypted")
        .current_dir(temp_path);

    wrap_cmd.assert().success();

    // A3: Wrong device public key should exit 10
    let mut verify_cmd = Command::cargo_bin("seal").unwrap();
    verify_cmd
        .arg("verify")
        .arg(&output_archive)
        .arg("--device-pub")
        .arg("ed25519:WRONG_KEY_THAT_WILL_FAIL_VERIFICATION_HERE=")
        .current_dir(temp_path);

    verify_cmd.assert().failure().code(10); // signature_fail
}

#[test]
fn test_a4_missing_signature_in_manifest() {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();

    // Create test input file and archive
    let input_file = temp_path.join("test-input.bin");
    fs::write(&input_file, b"A4 test: missing signature").unwrap();

    let output_archive = temp_path.join("test-archive.seal");
    let mut wrap_cmd = Command::cargo_bin("seal").unwrap();
    wrap_cmd
        .arg("wrap")
        .arg("--profile")
        .arg("cam.video")
        .arg("--in")
        .arg(&input_file)
        .arg("--out")
        .arg(&output_archive)
        .arg("--unencrypted")
        .current_dir(temp_path);

    wrap_cmd.assert().success();

    // Read and modify manifest to remove signature
    let manifest_path = output_archive.join("manifest.json");
    let manifest_content = fs::read_to_string(&manifest_path).unwrap();
    let mut manifest: Value = serde_json::from_str(&manifest_content).unwrap();

    // Remove signature field
    if let Some(obj) = manifest.as_object_mut() {
        obj.remove("signature");
    }

    // Write back modified manifest
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    // A4: Missing signature should exit 12
    let mut verify_cmd = Command::cargo_bin("seal").unwrap();
    verify_cmd
        .arg("verify")
        .arg(&output_archive)
        .arg("--device-pub")
        .arg("ed25519:fakepubkey==")
        .current_dir(temp_path);

    verify_cmd
        .assert()
        .failure()
        .code(12) // io_or_schema error
        .stderr(predicate::str::starts_with("Manifest missing signature"));
}

#[test]
fn test_a5_continuity_failure_with_json() {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();

    // Create test input file and archive
    let input_file = temp_path.join("test-input.bin");
    fs::write(&input_file, b"A5 test: continuity failure").unwrap();

    let output_archive = temp_path.join("test-archive.seal");
    let mut wrap_cmd = Command::cargo_bin("seal").unwrap();
    wrap_cmd
        .arg("wrap")
        .arg("--profile")
        .arg("cam.video")
        .arg("--in")
        .arg(&input_file)
        .arg("--out")
        .arg(&output_archive)
        .arg("--unencrypted")
        .current_dir(temp_path);

    wrap_cmd.assert().success();

    // Read device public key
    let device_pub_file = fs::read_to_string(temp_path.join("device.pub")).unwrap();
    let device_pub = device_pub_file
        .lines()
        .find(|l| l.starts_with("ed25519:"))
        .unwrap();

    // Corrupt a chunk file to cause continuity failure
    let chunk_file = output_archive.join("chunks").join("00000.bin");
    let mut chunk_data = fs::read(&chunk_file).unwrap();
    if !chunk_data.is_empty() {
        chunk_data[0] = chunk_data[0].wrapping_add(1); // Flip a bit
    }
    fs::write(&chunk_file, chunk_data).unwrap();

    // A5: Continuity failure should exit 11 with JSON
    let mut verify_cmd = Command::cargo_bin("seal").unwrap();
    verify_cmd
        .arg("verify")
        .arg(&output_archive)
        .arg("--device-pub")
        .arg(device_pub)
        .arg("--json")
        .current_dir(temp_path);

    let output = verify_cmd
        .assert()
        .failure()
        .code(11) // continuity_fail
        .get_output()
        .stdout
        .clone();

    // Parse JSON output and verify error fields
    let json_output: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json_output["signature"], "pass");
    assert_eq!(json_output["continuity"], "fail");
    assert!(json_output["error"].as_str().is_some());
}

#[test]
fn test_emit_request_basic_functionality() {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();

    // Create test input file
    let input_file = temp_path.join("test-input.bin");
    fs::write(&input_file, b"Test data for emit-request").unwrap();

    // Create archive
    let output_archive = temp_path.join("test-archive.seal");
    let mut wrap_cmd = Command::cargo_bin("seal").unwrap();
    wrap_cmd
        .arg("wrap")
        .arg("--profile")
        .arg("cam.video")
        .arg("--in")
        .arg(&input_file)
        .arg("--out")
        .arg(&output_archive)
        .arg("--unencrypted")
        .current_dir(temp_path);

    wrap_cmd.assert().success();

    // Test emit-request command
    let device_pub_file = temp_path.join("device.pub");
    let output_json = temp_path.join("verify_request.json");

    let mut emit_cmd = Command::cargo_bin("seal").unwrap();
    emit_cmd
        .arg("emit-request")
        .arg("--archive")
        .arg(&output_archive)
        .arg("--device-pub")
        .arg(&device_pub_file)
        .arg("--out")
        .arg(&output_json)
        .current_dir(temp_path);

    emit_cmd
        .assert()
        .success()
        .stdout(predicate::str::contains("Generated verify request:"));

    // Verify the JSON file was created and has correct structure
    assert!(output_json.exists());
    let json_content = fs::read_to_string(&output_json).unwrap();
    let verify_request: Value = serde_json::from_str(&json_content).unwrap();

    // Check required fields exist
    assert!(verify_request["device_pub"].is_string());
    assert!(verify_request["manifest"].is_object());
    assert!(verify_request["segments"].is_array());
    assert!(verify_request["options"].is_object());

    // Check options structure
    assert_eq!(verify_request["options"]["return_receipt"], true);
    assert!(verify_request["options"]["device_id"].is_string());

    // Check segments have proper b3: hash format
    let segments = verify_request["segments"].as_array().unwrap();
    assert!(!segments.is_empty());
    for segment in segments {
        assert!(segment["index"].is_number());
        let hash = segment["hash"].as_str().unwrap();
        assert!(hash.starts_with("b3:"));
        assert_eq!(hash.len(), 67); // "b3:" + 64 hex chars
    }
}

#[test]
fn test_emit_request_blake3_computation() {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();

    // Create test input with known content
    let input_file = temp_path.join("test-input.bin");
    let test_data = b"Known test data for BLAKE3 verification";
    fs::write(&input_file, test_data).unwrap();

    // Create archive
    let output_archive = temp_path.join("test-archive.seal");
    let mut wrap_cmd = Command::cargo_bin("seal").unwrap();
    wrap_cmd
        .arg("wrap")
        .arg("--profile")
        .arg("cam.video")
        .arg("--in")
        .arg(&input_file)
        .arg("--out")
        .arg(&output_archive)
        .arg("--chunk-size")
        .arg("50") // Small chunk size to ensure we get at least one chunk
        .arg("--unencrypted")
        .current_dir(temp_path);

    wrap_cmd.assert().success();

    // Emit request
    let device_pub_file = temp_path.join("device.pub");
    let output_json = temp_path.join("verify_request.json");

    let mut emit_cmd = Command::cargo_bin("seal").unwrap();
    emit_cmd
        .arg("emit-request")
        .arg("--archive")
        .arg(&output_archive)
        .arg("--device-pub")
        .arg(&device_pub_file)
        .arg("--out")
        .arg(&output_json)
        .current_dir(temp_path);

    emit_cmd.assert().success();

    // Parse and verify the JSON structure
    let json_content = fs::read_to_string(&output_json).unwrap();
    let verify_request: Value = serde_json::from_str(&json_content).unwrap();

    // Verify segments array is properly structured
    let segments = verify_request["segments"].as_array().unwrap();
    assert!(!segments.is_empty());

    // Check that segments are indexed properly (0-based)
    for (i, segment) in segments.iter().enumerate() {
        assert_eq!(segment["index"], i);
        let hash = segment["hash"].as_str().unwrap();
        assert!(hash.starts_with("b3:"));

        // Verify hex chars are valid
        let hex_part = &hash[3..];
        assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));
    }
}

#[test]
fn test_emit_request_http_error_handling() {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();

    // Create test input file and archive
    let input_file = temp_path.join("test-input.bin");
    fs::write(&input_file, b"Test data for POST request").unwrap();

    let output_archive = temp_path.join("test-archive.seal");
    let mut wrap_cmd = Command::cargo_bin("seal").unwrap();
    wrap_cmd
        .arg("wrap")
        .arg("--profile")
        .arg("cam.video")
        .arg("--in")
        .arg(&input_file)
        .arg("--out")
        .arg(&output_archive)
        .arg("--unencrypted")
        .current_dir(temp_path);

    wrap_cmd.assert().success();

    // Test emit-request with invalid URL (should fail with connection error)
    let device_pub_file = temp_path.join("device.pub");
    let output_json = temp_path.join("verify_request.json");

    let mut emit_cmd = Command::cargo_bin("seal").unwrap();
    emit_cmd
        .arg("emit-request")
        .arg("--archive")
        .arg(&output_archive)
        .arg("--device-pub")
        .arg(&device_pub_file)
        .arg("--out")
        .arg(&output_json)
        .arg("--post")
        .arg("http://localhost:99999/v1/verify") // Invalid port
        .current_dir(temp_path);

    emit_cmd
        .assert()
        .failure() // Should fail due to connection error
        .stderr(predicate::str::contains("Failed to POST"));

    // Verify the JSON file was still created despite POST failure
    assert!(output_json.exists());
}
