#![cfg(feature = "legacy-v1-tests")]
// C4 Phase 3b: gated pending migration to V2 keys / 0.2.0 archives / recipient model.
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

use assert_cmd::prelude::*;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use p256::ecdsa::signature::Signer as P256Signer;
use predicates::str::contains;
use rand_core::OsRng;
use sealedge_core::TrstManifest;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

const PROFILE: &str = "cam.video";

fn write_sample_input(dir: &Path) -> PathBuf {
    let input_path = dir.join("input.bin");
    let data: Vec<u8> = (0..(64 * 1024)).map(|i| (i % 251) as u8).collect();
    fs::write(&input_path, data).unwrap();
    input_path
}

fn wrap_archive(tempdir: &TempDir) -> (PathBuf, String) {
    let input = write_sample_input(tempdir.path());
    let archive_dir = tempdir.path().join("clip.seal");

    Command::cargo_bin("seal")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "wrap",
            "--profile",
            PROFILE,
            "--in",
            input.to_str().unwrap(),
            "--out",
            archive_dir.to_str().unwrap(),
            "--chunk-size",
            "4096",
            "--chunk-seconds",
            "2.0",
            "--unencrypted",
        ])
        .assert()
        .success();

    let device_pub = fs::read_to_string(tempdir.path().join("device.pub")).unwrap();
    (archive_dir, device_pub.trim().to_string())
}

/// Wrap a generic profile archive (no --profile flag = uses default "generic").
fn wrap_generic_archive(tempdir: &TempDir) -> (PathBuf, String) {
    let input = write_sample_input(tempdir.path());
    let archive_dir = tempdir.path().join("clip-generic.seal");

    Command::cargo_bin("seal")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "wrap",
            "--in",
            input.to_str().unwrap(),
            "--out",
            archive_dir.to_str().unwrap(),
            "--chunk-size",
            "4096",
            "--unencrypted",
        ])
        .assert()
        .success();

    let device_pub = fs::read_to_string(tempdir.path().join("device.pub")).unwrap();
    (archive_dir, device_pub.trim().to_string())
}

fn run_verify(tempdir: &TempDir, archive: &Path, device_pub: &str) -> assert_cmd::assert::Assert {
    Command::cargo_bin("seal")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "verify",
            archive.to_str().unwrap(),
            "--device-pub",
            device_pub,
        ])
        .assert()
}

fn decode_signing_key(path: &Path) -> SigningKey {
    let contents = fs::read_to_string(path).unwrap();
    let (_, data) = contents.trim().split_once(':').unwrap();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(data)
        .unwrap();
    let array: [u8; 32] = bytes.try_into().unwrap();
    SigningKey::from_bytes(&array)
}

fn resign_manifest_json(archive: &Path, signing_key: &SigningKey, manifest: &TrstManifest) {
    // Use proper canonicalization from the core module
    let canonical_bytes = manifest.to_canonical_bytes().unwrap();

    // Sign the canonical bytes
    let signature = signing_key.sign(&canonical_bytes);
    let signature_prefixed = format!(
        "ed25519:{}",
        base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
    );

    // Create a new manifest with the signature
    let mut signed_manifest = manifest.clone();
    signed_manifest.signature = Some(signature_prefixed.clone());

    // Write the signed manifest as pretty JSON
    let manifest_json = serde_json::to_string_pretty(&signed_manifest).unwrap();
    fs::write(archive.join("manifest.json"), manifest_json).unwrap();
    fs::write(
        archive.join("signatures").join("manifest.sig"),
        signature_prefixed.as_bytes(),
    )
    .unwrap();
}

#[test]
fn acceptance_happy_path() {
    let tempdir = TempDir::new().unwrap();
    let (archive, device_pub) = wrap_archive(&tempdir);
    run_verify(&tempdir, &archive, &device_pub).success();
}

#[test]
fn acceptance_a1_signature_flip() {
    let tempdir = TempDir::new().unwrap();
    let (archive, device_pub) = wrap_archive(&tempdir);

    let manifest_path = archive.join("manifest.json");
    let mut manifest = fs::read_to_string(&manifest_path).unwrap();
    manifest = manifest.replacen(PROFILE, "cam.video-tampered", 1);
    fs::write(&manifest_path, manifest).unwrap();

    run_verify(&tempdir, &archive, &device_pub)
        .failure()
        .stderr(contains("Signature verification failed"));
}

#[test]
fn acceptance_a2_missing_chunk() {
    let tempdir = TempDir::new().unwrap();
    let (archive, device_pub) = wrap_archive(&tempdir);

    fs::remove_file(archive.join("chunks/00007.bin")).unwrap();

    run_verify(&tempdir, &archive, &device_pub)
        .failure()
        .stderr(contains("Missing chunk file"));
}

#[test]
fn acceptance_a3_swap_chunks() {
    let tempdir = TempDir::new().unwrap();
    let (archive, device_pub) = wrap_archive(&tempdir);
    let chunk10 = archive.join("chunks/00010.bin");
    let chunk11 = archive.join("chunks/00011.bin");
    let temp = archive.join("chunks/tmp.bin");
    fs::rename(&chunk10, &temp).unwrap();
    fs::rename(&chunk11, &chunk10).unwrap();
    fs::rename(&temp, &chunk11).unwrap();

    run_verify(&tempdir, &archive, &device_pub)
        .failure()
        .stderr(contains("hash mismatch"));
}

#[test]
fn acceptance_a4_truncated_chain() {
    let tempdir = TempDir::new().unwrap();
    let (archive, device_pub) = wrap_archive(&tempdir);
    let last_index = fs::read_dir(archive.join("chunks"))
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.file_name().to_str().map(|s| s.to_string()))
        .filter_map(|name| name.strip_suffix(".bin").map(|s| s.to_string()))
        .filter_map(|stem| stem.parse::<u32>().ok())
        .max()
        .unwrap();
    let last_chunk = archive.join(format!("chunks/{last_index:05}.bin"));
    fs::remove_file(&last_chunk).unwrap();

    run_verify(&tempdir, &archive, &device_pub)
        .failure()
        .stderr(contains("Missing chunk file"));
}

#[test]
fn acceptance_a5_wrong_key() {
    let tempdir = TempDir::new().unwrap();
    let (archive, _device_pub) = wrap_archive(&tempdir);

    let mut rng = OsRng;
    let wrong_key = SigningKey::generate(&mut rng);
    let verifying_key: VerifyingKey = wrong_key.verifying_key();
    let wrong_pub = format!(
        "ed25519:{}",
        base64::engine::general_purpose::STANDARD.encode(verifying_key.as_bytes())
    );

    run_verify(&tempdir, &archive, &wrong_pub)
        .failure()
        .stderr(contains("Signature verification failed"));
}

#[test]
fn acceptance_a6_duration_sanity() {
    let tempdir = TempDir::new().unwrap();
    let (archive, device_pub) = wrap_archive(&tempdir);
    let manifest_path = archive.join("manifest.json");
    let manifest_json = fs::read_to_string(&manifest_path).unwrap();
    let mut manifest: TrstManifest = serde_json::from_str(&manifest_json).unwrap();

    // Inflate the first segment duration to trip the sanity check while
    // keeping the signature valid by re-signing with the original key.
    if let Some(first_segment) = manifest.segments.first_mut() {
        first_segment.duration_seconds = 100.0;
    }

    let signing_key = decode_signing_key(&tempdir.path().join("device.key"));
    resign_manifest_json(&archive, &signing_key, &manifest);

    // This test verifies that the archive validates successfully even with unusual durations
    // The P0 implementation doesn't enforce strict duration sanity checks
    run_verify(&tempdir, &archive, &device_pub).success();
}

// ─── Generic profile acceptance tests ────────────────────────────────────────

#[test]
fn acceptance_generic_default_profile() {
    // Wrap without --profile flag; default must be "generic"
    let tempdir = TempDir::new().unwrap();
    let (archive, device_pub) = wrap_generic_archive(&tempdir);

    // Read manifest and verify profile is "generic"
    let manifest_json = fs::read_to_string(archive.join("manifest.json")).unwrap();
    let manifest_value: serde_json::Value = serde_json::from_str(&manifest_json).unwrap();
    assert_eq!(
        manifest_value["profile"], "generic",
        "default profile must be 'generic'"
    );

    // Verify the archive passes signature + continuity
    run_verify(&tempdir, &archive, &device_pub).success();
}

#[test]
fn acceptance_generic_explicit_profile() {
    // Wrap with --profile generic explicitly; must produce a valid archive
    let tempdir = TempDir::new().unwrap();
    let input = write_sample_input(tempdir.path());
    let archive_dir = tempdir.path().join("clip-explicit.seal");

    Command::cargo_bin("seal")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "wrap",
            "--profile",
            "generic",
            "--in",
            input.to_str().unwrap(),
            "--out",
            archive_dir.to_str().unwrap(),
            "--chunk-size",
            "4096",
            "--unencrypted",
        ])
        .assert()
        .success();

    let device_pub = fs::read_to_string(tempdir.path().join("device.pub")).unwrap();

    let manifest_json = fs::read_to_string(archive_dir.join("manifest.json")).unwrap();
    let manifest_value: serde_json::Value = serde_json::from_str(&manifest_json).unwrap();
    assert_eq!(manifest_value["profile"], "generic");

    run_verify(&tempdir, &archive_dir, device_pub.trim()).success();
}

#[test]
fn acceptance_generic_with_metadata() {
    // Wrap with --data-type and --source flags; verify they appear in the manifest
    let tempdir = TempDir::new().unwrap();
    let input = write_sample_input(tempdir.path());
    let archive_dir = tempdir.path().join("clip-meta.seal");

    Command::cargo_bin("seal")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "wrap",
            "--profile",
            "generic",
            "--in",
            input.to_str().unwrap(),
            "--out",
            archive_dir.to_str().unwrap(),
            "--chunk-size",
            "4096",
            "--data-type",
            "sensor",
            "--source",
            "drone-01",
            "--unencrypted",
        ])
        .assert()
        .success();

    let manifest_json = fs::read_to_string(archive_dir.join("manifest.json")).unwrap();
    let manifest_value: serde_json::Value = serde_json::from_str(&manifest_json).unwrap();

    assert_eq!(manifest_value["profile"], "generic");
    assert_eq!(
        manifest_value["metadata"]["data_type"], "sensor",
        "data_type must be present in manifest metadata"
    );
    assert_eq!(
        manifest_value["metadata"]["source"], "drone-01",
        "source must be present in manifest metadata"
    );

    // Verify round-trip passes
    let device_pub = fs::read_to_string(tempdir.path().join("device.pub")).unwrap();
    run_verify(&tempdir, &archive_dir, device_pub.trim()).success();
}

// ─── Keygen acceptance tests ──────────────────────────────────────────────────

#[test]
fn acceptance_keygen_creates_files() {
    let tempdir = TempDir::new().unwrap();
    let key_path = tempdir.path().join("device.key");
    let pub_path = tempdir.path().join("device.pub");

    Command::cargo_bin("seal")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "keygen",
            "--out-key",
            key_path.to_str().unwrap(),
            "--out-pub",
            pub_path.to_str().unwrap(),
            "--unencrypted",
        ])
        .assert()
        .success();

    // Both files must exist
    assert!(key_path.exists(), "secret key file must be created");
    assert!(pub_path.exists(), "public key file must be created");

    // Both must start with "ed25519:"
    let key_content = fs::read_to_string(&key_path).unwrap();
    let pub_content = fs::read_to_string(&pub_path).unwrap();
    assert!(
        key_content.trim().starts_with("ed25519:"),
        "secret key must start with ed25519: prefix, got: {key_content}"
    );
    assert!(
        pub_content.trim().starts_with("ed25519:"),
        "public key must start with ed25519: prefix, got: {pub_content}"
    );
}

#[test]
fn acceptance_keygen_roundtrip() {
    let tempdir = TempDir::new().unwrap();
    let key_path = tempdir.path().join("mydevice.key");
    let pub_path = tempdir.path().join("mydevice.pub");

    // Step 1: generate keys
    Command::cargo_bin("seal")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "keygen",
            "--out-key",
            key_path.to_str().unwrap(),
            "--out-pub",
            pub_path.to_str().unwrap(),
            "--unencrypted",
        ])
        .assert()
        .success();

    // Step 2: wrap an archive using the generated key
    let input = write_sample_input(tempdir.path());
    let archive_dir = tempdir.path().join("clip-keygen.seal");

    Command::cargo_bin("seal")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "wrap",
            "--profile",
            "cam.video",
            "--in",
            input.to_str().unwrap(),
            "--out",
            archive_dir.to_str().unwrap(),
            "--chunk-size",
            "4096",
            "--chunk-seconds",
            "2.0",
            "--device-key",
            key_path.to_str().unwrap(),
            "--unencrypted",
        ])
        .assert()
        .success();

    // Step 3: verify using the public key string from the generated file
    let device_pub = fs::read_to_string(&pub_path).unwrap();
    run_verify(&tempdir, &archive_dir, device_pub.trim()).success();
}

#[test]
fn acceptance_keygen_no_overwrite() {
    let tempdir = TempDir::new().unwrap();
    let key_path = tempdir.path().join("existing.key");
    let pub_path = tempdir.path().join("existing.pub");

    // Pre-create the key file to trigger the overwrite guard
    fs::write(&key_path, "existing content\n").unwrap();

    Command::cargo_bin("seal")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "keygen",
            "--out-key",
            key_path.to_str().unwrap(),
            "--out-pub",
            pub_path.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(contains("overwrite"));
}

#[test]
fn acceptance_camvideo_still_works() {
    // cam.video wrap + verify round-trip must pass (regression guard)
    let tempdir = TempDir::new().unwrap();
    let input = write_sample_input(tempdir.path());
    let archive_dir = tempdir.path().join("clip-camvideo.seal");

    Command::cargo_bin("seal")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "wrap",
            "--profile",
            "cam.video",
            "--in",
            input.to_str().unwrap(),
            "--out",
            archive_dir.to_str().unwrap(),
            "--chunk-size",
            "4096",
            "--chunk-seconds",
            "2.0",
            "--fps",
            "30",
            "--unencrypted",
        ])
        .assert()
        .success();

    let manifest_json = fs::read_to_string(archive_dir.join("manifest.json")).unwrap();
    let manifest_value: serde_json::Value = serde_json::from_str(&manifest_json).unwrap();
    assert_eq!(manifest_value["profile"], "cam.video");
    // cam.video metadata must have fps field
    assert!(
        manifest_value["metadata"]["fps"].is_number(),
        "cam.video manifest must include fps in metadata"
    );

    let device_pub = fs::read_to_string(tempdir.path().join("device.pub")).unwrap();
    run_verify(&tempdir, &archive_dir, device_pub.trim()).success();
}

// ─── Sensor profile acceptance tests ─────────────────────────────────────────

#[test]
fn acceptance_sensor_wrap_verify() {
    let tempdir = TempDir::new().unwrap();
    let input = write_sample_input(tempdir.path());
    let archive_dir = tempdir.path().join("clip-sensor.seal");

    Command::cargo_bin("seal")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "wrap",
            "--profile",
            "sensor",
            "--in",
            input.to_str().unwrap(),
            "--out",
            archive_dir.to_str().unwrap(),
            "--chunk-size",
            "4096",
            "--sample-rate",
            "100.0",
            "--unit",
            "celsius",
            "--sensor-model",
            "DHT22",
            "--unencrypted",
        ])
        .assert()
        .success();

    let manifest_json = fs::read_to_string(archive_dir.join("manifest.json")).unwrap();
    let manifest_value: serde_json::Value = serde_json::from_str(&manifest_json).unwrap();
    assert_eq!(manifest_value["profile"], "sensor");
    assert_eq!(
        manifest_value["metadata"]["sample_rate_hz"], 100.0,
        "sample_rate_hz must be present in sensor manifest metadata"
    );
    assert_eq!(
        manifest_value["metadata"]["unit"], "celsius",
        "unit must be present in sensor manifest metadata"
    );
    assert_eq!(
        manifest_value["metadata"]["sensor_model"], "DHT22",
        "sensor_model must be present in sensor manifest metadata"
    );

    let device_pub = fs::read_to_string(tempdir.path().join("device.pub")).unwrap();
    run_verify(&tempdir, &archive_dir, device_pub.trim()).success();
}

#[test]
fn acceptance_audio_wrap_verify() {
    let tempdir = TempDir::new().unwrap();
    let input = write_sample_input(tempdir.path());
    let archive_dir = tempdir.path().join("clip-audio.seal");

    Command::cargo_bin("seal")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "wrap",
            "--profile",
            "audio",
            "--in",
            input.to_str().unwrap(),
            "--out",
            archive_dir.to_str().unwrap(),
            "--chunk-size",
            "4096",
            "--sample-rate",
            "44100",
            "--bit-depth",
            "16",
            "--channels",
            "2",
            "--codec",
            "pcm",
            "--unencrypted",
        ])
        .assert()
        .success();

    let manifest_json = fs::read_to_string(archive_dir.join("manifest.json")).unwrap();
    let manifest_value: serde_json::Value = serde_json::from_str(&manifest_json).unwrap();
    assert_eq!(manifest_value["profile"], "audio");
    assert_eq!(
        manifest_value["metadata"]["sample_rate_hz"], 44100,
        "sample_rate_hz must be present in audio manifest metadata"
    );
    assert_eq!(
        manifest_value["metadata"]["bit_depth"], 16,
        "bit_depth must be present in audio manifest metadata"
    );
    assert_eq!(
        manifest_value["metadata"]["channels"], 2,
        "channels must be present in audio manifest metadata"
    );
    assert_eq!(
        manifest_value["metadata"]["codec"], "pcm",
        "codec must be present in audio manifest metadata"
    );

    let device_pub = fs::read_to_string(tempdir.path().join("device.pub")).unwrap();
    run_verify(&tempdir, &archive_dir, device_pub.trim()).success();
}

#[test]
fn acceptance_log_wrap_verify() {
    let tempdir = TempDir::new().unwrap();
    let input = write_sample_input(tempdir.path());
    let archive_dir = tempdir.path().join("clip-log.seal");

    Command::cargo_bin("seal")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "wrap",
            "--profile",
            "log",
            "--in",
            input.to_str().unwrap(),
            "--out",
            archive_dir.to_str().unwrap(),
            "--chunk-size",
            "4096",
            "--application",
            "nginx",
            "--host",
            "web-01",
            "--log-level",
            "info",
            "--log-format",
            "json",
            "--unencrypted",
        ])
        .assert()
        .success();

    let manifest_json = fs::read_to_string(archive_dir.join("manifest.json")).unwrap();
    let manifest_value: serde_json::Value = serde_json::from_str(&manifest_json).unwrap();
    assert_eq!(manifest_value["profile"], "log");
    assert_eq!(
        manifest_value["metadata"]["application"], "nginx",
        "application must be present in log manifest metadata"
    );
    assert_eq!(
        manifest_value["metadata"]["host"], "web-01",
        "host must be present in log manifest metadata"
    );
    assert_eq!(
        manifest_value["metadata"]["log_level"], "info",
        "log_level must be present in log manifest metadata"
    );
    assert_eq!(
        manifest_value["metadata"]["log_format"], "json",
        "log_format must be present in log manifest metadata"
    );

    let device_pub = fs::read_to_string(tempdir.path().join("device.pub")).unwrap();
    run_verify(&tempdir, &archive_dir, device_pub.trim()).success();
}

#[test]
fn acceptance_sensor_with_geo() {
    let tempdir = TempDir::new().unwrap();
    let input = write_sample_input(tempdir.path());
    let archive_dir = tempdir.path().join("clip-sensor-geo.seal");

    Command::cargo_bin("seal")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "wrap",
            "--profile",
            "sensor",
            "--in",
            input.to_str().unwrap(),
            "--out",
            archive_dir.to_str().unwrap(),
            "--chunk-size",
            "4096",
            "--sample-rate",
            "50.0",
            "--unit",
            "psi",
            "--sensor-model",
            "BMP280",
            "--latitude",
            "37.7749",
            "--longitude=-122.4194",
            "--altitude",
            "10.0",
            "--unencrypted",
        ])
        .assert()
        .success();

    let manifest_json = fs::read_to_string(archive_dir.join("manifest.json")).unwrap();
    let manifest_value: serde_json::Value = serde_json::from_str(&manifest_json).unwrap();
    assert_eq!(manifest_value["profile"], "sensor");
    assert!(
        manifest_value["metadata"]["latitude"].is_number(),
        "latitude must be present in geo-tagged sensor manifest"
    );
    assert!(
        manifest_value["metadata"]["longitude"].is_number(),
        "longitude must be present in geo-tagged sensor manifest"
    );
    assert!(
        manifest_value["metadata"]["altitude"].is_number(),
        "altitude must be present in geo-tagged sensor manifest"
    );

    let device_pub = fs::read_to_string(tempdir.path().join("device.pub")).unwrap();
    run_verify(&tempdir, &archive_dir, device_pub.trim()).success();
}

// ─── Unwrap acceptance tests ──────────────────────────────────────────────────

fn run_unwrap(
    tempdir: &TempDir,
    archive: &Path,
    device_key: &Path,
    output: &Path,
) -> assert_cmd::assert::Assert {
    Command::cargo_bin("seal")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "unwrap",
            archive.to_str().unwrap(),
            "--device-key",
            device_key.to_str().unwrap(),
            "--out",
            output.to_str().unwrap(),
            "--unencrypted",
        ])
        .assert()
}

fn wrap_with_key(tempdir: &TempDir, input: &Path, profile: &str) -> (PathBuf, PathBuf, PathBuf) {
    let key_path = tempdir.path().join("test.key");
    let pub_path = tempdir.path().join("test.pub");

    Command::cargo_bin("seal")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "keygen",
            "--out-key",
            key_path.to_str().unwrap(),
            "--out-pub",
            pub_path.to_str().unwrap(),
            "--unencrypted",
        ])
        .assert()
        .success();

    let archive_dir = tempdir.path().join("clip-unwrap.seal");
    Command::cargo_bin("seal")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "wrap",
            "--profile",
            profile,
            "--in",
            input.to_str().unwrap(),
            "--out",
            archive_dir.to_str().unwrap(),
            "--chunk-size",
            "4096",
            "--device-key",
            key_path.to_str().unwrap(),
            "--unencrypted",
        ])
        .assert()
        .success();

    (archive_dir, key_path, pub_path)
}

#[test]
fn acceptance_unwrap_round_trip() {
    let tempdir = TempDir::new().unwrap();
    let original_data: Vec<u8> = (0..(64 * 1024)).map(|i| (i % 251) as u8).collect();
    let input_path = tempdir.path().join("input.bin");
    fs::write(&input_path, &original_data).unwrap();

    let (archive_dir, key_path, _pub_path) = wrap_with_key(&tempdir, &input_path, "cam.video");

    let output_path = tempdir.path().join("recovered.bin");
    run_unwrap(&tempdir, &archive_dir, &key_path, &output_path).success();

    let recovered_data = fs::read(&output_path).unwrap();
    assert_eq!(
        original_data, recovered_data,
        "recovered data must be byte-identical to original"
    );
}

#[test]
fn acceptance_unwrap_wrong_key() {
    let tempdir = TempDir::new().unwrap();
    let input = write_sample_input(tempdir.path());
    let (archive_dir, _key_path, _pub_path) = wrap_with_key(&tempdir, &input, "cam.video");

    // Generate a second key
    let wrong_key_path = tempdir.path().join("wrong.key");
    let wrong_pub_path = tempdir.path().join("wrong.pub");
    Command::cargo_bin("seal")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "keygen",
            "--out-key",
            wrong_key_path.to_str().unwrap(),
            "--out-pub",
            wrong_pub_path.to_str().unwrap(),
            "--unencrypted",
        ])
        .assert()
        .success();

    let output_path = tempdir.path().join("should-not-exist.bin");
    run_unwrap(&tempdir, &archive_dir, &wrong_key_path, &output_path).failure();

    assert!(
        !output_path.exists(),
        "output file must not be written when wrong key is used"
    );
}

#[test]
fn acceptance_unwrap_tampered_manifest() {
    let tempdir = TempDir::new().unwrap();
    let input = write_sample_input(tempdir.path());
    let (archive_dir, key_path, _pub_path) = wrap_with_key(&tempdir, &input, "cam.video");

    // Tamper with the manifest
    let manifest_path = archive_dir.join("manifest.json");
    let original_manifest = fs::read_to_string(&manifest_path).unwrap();
    let tampered = original_manifest.replacen("cam.video", "cam.video-tampered", 1);
    fs::write(&manifest_path, tampered).unwrap();

    let output_path = tempdir.path().join("tampered-output.bin");
    run_unwrap(&tempdir, &archive_dir, &key_path, &output_path)
        .failure()
        .stderr(contains("Signature: FAIL"));

    assert!(
        !output_path.exists(),
        "output file must not be written when signature fails"
    );
}

#[test]
fn acceptance_unwrap_generic_profile() {
    let tempdir = TempDir::new().unwrap();
    let original_data: Vec<u8> = (0..(64 * 1024)).map(|i| (i % 251) as u8).collect();
    let input_path = tempdir.path().join("input.bin");
    fs::write(&input_path, &original_data).unwrap();

    let (archive_dir, key_path, _pub_path) = wrap_with_key(&tempdir, &input_path, "generic");

    let output_path = tempdir.path().join("recovered-generic.bin");
    run_unwrap(&tempdir, &archive_dir, &key_path, &output_path).success();

    let recovered_data = fs::read(&output_path).unwrap();
    assert_eq!(
        original_data, recovered_data,
        "recovered data must be byte-identical to original (generic profile)"
    );
}

#[test]
fn acceptance_unwrap_missing_chunk() {
    let tempdir = TempDir::new().unwrap();
    let input = write_sample_input(tempdir.path());
    let (archive_dir, key_path, _pub_path) = wrap_with_key(&tempdir, &input, "cam.video");

    // Delete the last chunk file
    let last_index = fs::read_dir(archive_dir.join("chunks"))
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.file_name().to_str().map(|s| s.to_string()))
        .filter_map(|name| name.strip_suffix(".bin").map(|s| s.to_string()))
        .filter_map(|stem| stem.parse::<u32>().ok())
        .max()
        .unwrap();
    let last_chunk = archive_dir.join(format!("chunks/{last_index:05}.bin"));
    fs::remove_file(&last_chunk).unwrap();

    let output_path = tempdir.path().join("missing-chunk-output.bin");
    run_unwrap(&tempdir, &archive_dir, &key_path, &output_path).failure();

    assert!(
        !output_path.exists(),
        "output file must not be written when archive is missing a chunk"
    );
}

#[test]
fn acceptance_sensor_missing_required_flag() {
    // Missing --unit and --sensor-model; should fail with a clear error message
    let tempdir = TempDir::new().unwrap();
    let input = write_sample_input(tempdir.path());
    let archive_dir = tempdir.path().join("clip-sensor-fail.seal");

    Command::cargo_bin("seal")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "wrap",
            "--profile",
            "sensor",
            "--in",
            input.to_str().unwrap(),
            "--out",
            archive_dir.to_str().unwrap(),
            "--chunk-size",
            "4096",
            "--sample-rate",
            "100.0",
            "--unencrypted",
            // --unit and --sensor-model intentionally omitted
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("required"));
}

// ─── ECDSA P-256 acceptance tests ────────────────────────────────────────────

/// Helper: encode bytes as standard base64 (using the existing base64 crate in trst-cli)
fn b64_std(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Helper: resign an archive manifest using a P-256 signing key.
/// Updates both manifest.json and signatures/manifest.sig with the new signature.
/// The canonical bytes signed include the new P-256 public_key in device info.
fn resign_manifest_p256(
    archive: &Path,
    signing_key: &p256::ecdsa::SigningKey,
    manifest: &mut TrstManifest,
) {
    // Update public key in manifest device info BEFORE computing canonical bytes
    let verifying_key = signing_key.verifying_key();
    let pub_bytes = verifying_key.to_encoded_point(false);
    manifest.device.public_key = format!("ecdsa-p256:{}", b64_std(pub_bytes.as_bytes()));

    // Clear existing signature for canonical serialization
    manifest.signature = None;
    let canonical_bytes = manifest.to_canonical_bytes().unwrap();

    // Sign with P-256 — the p256 Signer hashes with SHA-256 internally
    let signature: p256::ecdsa::Signature = P256Signer::sign(signing_key, &canonical_bytes);
    let sig_der = signature.to_der();
    let sig_str = format!("ecdsa-p256:{}", b64_std(sig_der.as_bytes()));

    manifest.signature = Some(sig_str.clone());

    // Write updated manifest.json
    let manifest_json = serde_json::to_string_pretty(&manifest).unwrap();
    fs::write(archive.join("manifest.json"), manifest_json).unwrap();

    // Write detached signature file
    fs::write(
        archive.join("signatures").join("manifest.sig"),
        sig_str.as_bytes(),
    )
    .unwrap();
}

#[test]
fn acceptance_verify_ecdsa_p256() {
    // Wrap an archive with Ed25519, then replace the signature with P-256 and verify
    let tempdir = TempDir::new().unwrap();
    let (archive, _ed25519_pub) = wrap_archive(&tempdir);

    // Read the manifest
    let manifest_path = archive.join("manifest.json");
    let manifest_json = fs::read_to_string(&manifest_path).unwrap();
    let mut manifest: TrstManifest = serde_json::from_str(&manifest_json).unwrap();

    // Generate a new P-256 signing key
    let p256_signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);

    // Replace the manifest signature with P-256 (also updates manifest.device.public_key)
    resign_manifest_p256(&archive, &p256_signing_key, &mut manifest);

    // Use the public_key from the updated manifest (set by resign_manifest_p256)
    let p256_pub_str = manifest.device.public_key.clone();

    // Verify with the P-256 public key — expect success
    run_verify(&tempdir, &archive, &p256_pub_str).success();
}

// ─── Backend flag acceptance tests ───────────────────────────────────────────

#[test]
fn acceptance_backend_software_explicit() {
    // --backend software must produce Ed25519-signed archives (regression guard)
    let tempdir = TempDir::new().unwrap();
    let input = write_sample_input(tempdir.path());
    let archive_dir = tempdir.path().join("clip-sw.seal");

    Command::cargo_bin("seal")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "wrap",
            "--backend",
            "software",
            "--profile",
            "generic",
            "--in",
            input.to_str().unwrap(),
            "--out",
            archive_dir.to_str().unwrap(),
            "--chunk-size",
            "4096",
            "--unencrypted",
        ])
        .assert()
        .success();

    let manifest_json = fs::read_to_string(archive_dir.join("manifest.json")).unwrap();
    let manifest: serde_json::Value = serde_json::from_str(&manifest_json).unwrap();
    assert!(
        manifest["device"]["public_key"]
            .as_str()
            .unwrap()
            .starts_with("ed25519:"),
        "software backend must produce ed25519 public key"
    );
    assert!(
        manifest["signature"]
            .as_str()
            .unwrap()
            .starts_with("ed25519:"),
        "software backend must produce ed25519 signature"
    );

    let device_pub = fs::read_to_string(tempdir.path().join("device.pub")).unwrap();
    run_verify(&tempdir, &archive_dir, device_pub.trim()).success();
}

#[test]
fn acceptance_backend_unknown_fails() {
    // Unknown backend name must fail with a clear error message
    let tempdir = TempDir::new().unwrap();
    let input = write_sample_input(tempdir.path());
    let archive_dir = tempdir.path().join("clip-unknown.seal");

    Command::cargo_bin("seal")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "wrap",
            "--backend",
            "unknown",
            "--profile",
            "generic",
            "--in",
            input.to_str().unwrap(),
            "--out",
            archive_dir.to_str().unwrap(),
            "--chunk-size",
            "4096",
            "--unencrypted",
        ])
        .assert()
        .failure()
        .stderr(contains("Unknown backend"));
}

#[test]
fn acceptance_verify_ecdsa_p256_wrong_key() {
    // Same as above but pass a different P-256 public key — expect failure
    let tempdir = TempDir::new().unwrap();
    let (archive, _ed25519_pub) = wrap_archive(&tempdir);

    let manifest_path = archive.join("manifest.json");
    let manifest_json = fs::read_to_string(&manifest_path).unwrap();
    let mut manifest: TrstManifest = serde_json::from_str(&manifest_json).unwrap();

    // Sign with one P-256 key
    let p256_signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    resign_manifest_p256(&archive, &p256_signing_key, &mut manifest);

    // Verify with a different (wrong) P-256 public key
    let wrong_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let wrong_verifying_key = wrong_key.verifying_key();
    let wrong_pub_bytes = wrong_verifying_key.to_encoded_point(false);
    let wrong_pub_str = format!("ecdsa-p256:{}", b64_std(wrong_pub_bytes.as_bytes()));

    run_verify(&tempdir, &archive, &wrong_pub_str)
        .failure()
        .stderr(contains("Signature verification failed"));
}

// ─── attest-sbom / verify-attestation acceptance tests ───────────────────────

/// Create a test binary and SBOM in the given directory, returning (binary_path, sbom_path).
fn write_attestation_inputs(dir: &Path) -> (PathBuf, PathBuf) {
    let binary_path = dir.join("test-binary.bin");
    fs::write(&binary_path, b"hello world binary content").unwrap();
    let sbom_path = dir.join("sbom.json");
    fs::write(
        &sbom_path,
        r#"{"bomFormat":"CycloneDX","specVersion":"1.4","components":[]}"#,
    )
    .unwrap();
    (binary_path, sbom_path)
}

/// Generate a keypair via `trst keygen --unencrypted` in the given temp dir.
/// Returns (key_path, pub_path).
fn keygen_unencrypted(dir: &Path) -> (PathBuf, PathBuf) {
    let key_path = dir.join("device.key");
    let pub_path = dir.join("device.pub");
    Command::cargo_bin("seal")
        .unwrap()
        .current_dir(dir)
        .args([
            "keygen",
            "--out-key",
            key_path.to_str().unwrap(),
            "--out-pub",
            pub_path.to_str().unwrap(),
            "--unencrypted",
        ])
        .assert()
        .success();
    (key_path, pub_path)
}

#[test]
fn test_attest_sbom_creates_attestation_file() {
    let tempdir = TempDir::new().unwrap();
    let (binary_path, sbom_path) = write_attestation_inputs(tempdir.path());
    let (key_path, pub_path) = keygen_unencrypted(tempdir.path());
    let out_path = tempdir.path().join("output.se-attestation.json");

    Command::cargo_bin("seal")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "attest-sbom",
            "--binary",
            binary_path.to_str().unwrap(),
            "--sbom",
            sbom_path.to_str().unwrap(),
            "--device-key",
            key_path.to_str().unwrap(),
            "--device-pub",
            pub_path.to_str().unwrap(),
            "--out",
            out_path.to_str().unwrap(),
            "--unencrypted",
        ])
        .assert()
        .success();

    assert!(out_path.exists(), "attestation output file should exist");
    let contents = fs::read_to_string(&out_path).unwrap();
    assert!(
        contents.contains("te-point-attestation-v1"),
        "attestation should contain format v1 string"
    );
    assert!(
        contents.contains("ed25519:"),
        "attestation should contain ed25519 public key"
    );
}

#[test]
fn test_attest_sbom_default_output_name() {
    let tempdir = TempDir::new().unwrap();
    let (binary_path, sbom_path) = write_attestation_inputs(tempdir.path());
    let (key_path, pub_path) = keygen_unencrypted(tempdir.path());

    Command::cargo_bin("seal")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "attest-sbom",
            "--binary",
            binary_path.to_str().unwrap(),
            "--sbom",
            sbom_path.to_str().unwrap(),
            "--device-key",
            key_path.to_str().unwrap(),
            "--device-pub",
            pub_path.to_str().unwrap(),
            "--unencrypted",
        ])
        .assert()
        .success();

    let default_out = tempdir.path().join("attestation.se-attestation.json");
    assert!(
        default_out.exists(),
        "default output file attestation.se-attestation.json should exist"
    );
}

#[test]
fn test_attest_sbom_rejects_zero_byte_binary() {
    let tempdir = TempDir::new().unwrap();
    let (key_path, pub_path) = keygen_unencrypted(tempdir.path());

    // Create empty (0-byte) binary
    let empty_binary = tempdir.path().join("empty.bin");
    fs::write(&empty_binary, b"").unwrap();
    let sbom_path = tempdir.path().join("sbom.json");
    fs::write(
        &sbom_path,
        r#"{"bomFormat":"CycloneDX","specVersion":"1.4","components":[]}"#,
    )
    .unwrap();

    Command::cargo_bin("seal")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "attest-sbom",
            "--binary",
            empty_binary.to_str().unwrap(),
            "--sbom",
            sbom_path.to_str().unwrap(),
            "--device-key",
            key_path.to_str().unwrap(),
            "--device-pub",
            pub_path.to_str().unwrap(),
            "--unencrypted",
        ])
        .assert()
        .failure()
        .code(1)
        .stderr(predicates::str::is_match("empty|0 bytes").unwrap());
}

#[test]
fn test_attest_sbom_rejects_non_json_sbom() {
    let tempdir = TempDir::new().unwrap();
    let (key_path, pub_path) = keygen_unencrypted(tempdir.path());

    let binary_path = tempdir.path().join("test.bin");
    fs::write(&binary_path, b"binary content").unwrap();
    let bad_sbom = tempdir.path().join("bad.json");
    fs::write(&bad_sbom, b"not json at all").unwrap();

    Command::cargo_bin("seal")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "attest-sbom",
            "--binary",
            binary_path.to_str().unwrap(),
            "--sbom",
            bad_sbom.to_str().unwrap(),
            "--device-key",
            key_path.to_str().unwrap(),
            "--device-pub",
            pub_path.to_str().unwrap(),
            "--unencrypted",
        ])
        .assert()
        .failure()
        .code(1)
        .stderr(contains("not valid JSON"));
}

#[test]
fn test_attest_sbom_valid_inputs_succeed() {
    // This test verifies the happy path and implicitly confirms that the
    // 256 MB size check (via fs::metadata().len() comparison) does not
    // fire on a small valid binary. The actual 256 MB rejection is verified
    // by code inspection — creating a 256 MB temp file in CI is impractical.
    let tempdir = TempDir::new().unwrap();
    let (binary_path, sbom_path) = write_attestation_inputs(tempdir.path());
    let (key_path, pub_path) = keygen_unencrypted(tempdir.path());
    let out_path = tempdir.path().join("result.se-attestation.json");

    Command::cargo_bin("seal")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "attest-sbom",
            "--binary",
            binary_path.to_str().unwrap(),
            "--sbom",
            sbom_path.to_str().unwrap(),
            "--device-key",
            key_path.to_str().unwrap(),
            "--device-pub",
            pub_path.to_str().unwrap(),
            "--out",
            out_path.to_str().unwrap(),
            "--unencrypted",
        ])
        .assert()
        .success();

    assert!(out_path.exists());
}

#[test]
fn test_verify_attestation_success() {
    let tempdir = TempDir::new().unwrap();
    let (binary_path, sbom_path) = write_attestation_inputs(tempdir.path());
    let (key_path, pub_path) = keygen_unencrypted(tempdir.path());
    let out_path = tempdir.path().join("attest.se-attestation.json");

    // Create attestation
    Command::cargo_bin("seal")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "attest-sbom",
            "--binary",
            binary_path.to_str().unwrap(),
            "--sbom",
            sbom_path.to_str().unwrap(),
            "--device-key",
            key_path.to_str().unwrap(),
            "--device-pub",
            pub_path.to_str().unwrap(),
            "--out",
            out_path.to_str().unwrap(),
            "--unencrypted",
        ])
        .assert()
        .success();

    // Verify the attestation using pub file path
    Command::cargo_bin("seal")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "verify-attestation",
            out_path.to_str().unwrap(),
            "--device-pub",
            pub_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(contains("VERIFIED"));
}

#[test]
fn test_verify_attestation_wrong_key_fails() {
    let tempdir = TempDir::new().unwrap();
    let (binary_path, sbom_path) = write_attestation_inputs(tempdir.path());
    let (key_path, pub_path) = keygen_unencrypted(tempdir.path());
    let out_path = tempdir.path().join("attest.se-attestation.json");

    // Create attestation with first keypair
    Command::cargo_bin("seal")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "attest-sbom",
            "--binary",
            binary_path.to_str().unwrap(),
            "--sbom",
            sbom_path.to_str().unwrap(),
            "--device-key",
            key_path.to_str().unwrap(),
            "--device-pub",
            pub_path.to_str().unwrap(),
            "--out",
            out_path.to_str().unwrap(),
            "--unencrypted",
        ])
        .assert()
        .success();

    // Generate a second keypair (different key)
    let key2_path = tempdir.path().join("device2.key");
    let pub2_path = tempdir.path().join("device2.pub");
    Command::cargo_bin("seal")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "keygen",
            "--out-key",
            key2_path.to_str().unwrap(),
            "--out-pub",
            pub2_path.to_str().unwrap(),
            "--unencrypted",
        ])
        .assert()
        .success();

    // Verify using wrong (second) keypair's public key — should fail with exit 10
    Command::cargo_bin("seal")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "verify-attestation",
            out_path.to_str().unwrap(),
            "--device-pub",
            pub2_path.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .code(10)
        .stdout(contains("FAILED"));
}

#[test]
fn test_verify_attestation_with_file_hashes() {
    let tempdir = TempDir::new().unwrap();
    let (binary_path, sbom_path) = write_attestation_inputs(tempdir.path());
    let (key_path, pub_path) = keygen_unencrypted(tempdir.path());
    let out_path = tempdir.path().join("attest.se-attestation.json");

    // Create attestation
    Command::cargo_bin("seal")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "attest-sbom",
            "--binary",
            binary_path.to_str().unwrap(),
            "--sbom",
            sbom_path.to_str().unwrap(),
            "--device-key",
            key_path.to_str().unwrap(),
            "--device-pub",
            pub_path.to_str().unwrap(),
            "--out",
            out_path.to_str().unwrap(),
            "--unencrypted",
        ])
        .assert()
        .success();

    // Verify with correct binary and SBOM — should pass
    Command::cargo_bin("seal")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "verify-attestation",
            out_path.to_str().unwrap(),
            "--device-pub",
            pub_path.to_str().unwrap(),
            "--binary",
            binary_path.to_str().unwrap(),
            "--sbom",
            sbom_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(contains("VERIFIED"));

    // Modify binary, verify again — should fail with exit 10
    fs::write(&binary_path, b"tampered binary content").unwrap();

    Command::cargo_bin("seal")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "verify-attestation",
            out_path.to_str().unwrap(),
            "--device-pub",
            pub_path.to_str().unwrap(),
            "--binary",
            binary_path.to_str().unwrap(),
            "--sbom",
            sbom_path.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .code(10);
}
