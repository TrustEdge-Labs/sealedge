//
// Copyright (c) 2025 TRUSTEDGE LABS LLC
// This source code is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Project: sealedge — Privacy and trust at the edge.
//

//! Security tests for archive integrity — covers threat model T1 (chunk tampering) and T2 (manifest forgery).
//!
//! Tests are organized by requirement:
//!   SEC-01: Byte-level chunk mutation is detected (BLAKE3 hash mismatch)
//!   SEC-02: Chunk injection (unreferenced files and replaced chunks) is detected
//!   SEC-03: Chunk reordering is detected (BLAKE3 hash mismatch via continuity chain)
//!   SEC-04: Manifest modification after signing is detected (Ed25519 signature mismatch)

// Allow deprecated cargo_bin usage — the replacement cargo_bin_cmd! macro
// is not yet stable across all assert_cmd versions.
#![allow(deprecated)]

use assert_cmd::prelude::*;
use predicates::str::contains;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Write 64 KB of deterministic data (same pattern as acceptance.rs).
fn write_sample_input(dir: &Path) -> PathBuf {
    let input_path = dir.join("input.bin");
    let data: Vec<u8> = (0..(64 * 1024)).map(|i| (i % 251) as u8).collect();
    fs::write(&input_path, data).unwrap();
    input_path
}

/// Create an unencrypted-key archive (chunks are still AES-256-GCM encrypted).
/// Returns `(archive_dir, device_pub_string)`.
fn wrap_unencrypted_archive(tempdir: &TempDir) -> (PathBuf, String) {
    let input = write_sample_input(tempdir.path());
    let archive_dir = tempdir.path().join("clip.seal");

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
            "--unencrypted",
        ])
        .assert()
        .success();

    let device_pub = fs::read_to_string(tempdir.path().join("device.pub"))
        .unwrap()
        .lines()
        .find(|l| l.starts_with("ed25519:"))
        .unwrap()
        .to_string();
    (archive_dir, device_pub)
}

/// Create an archive using a pre-generated unencrypted key (keygen first, then wrap).
/// Returns `(archive_dir, device_pub_string, key_path)`.
fn wrap_encrypted_archive(tempdir: &TempDir) -> (PathBuf, String, PathBuf) {
    let key_path = tempdir.path().join("device.key");
    let pub_path = tempdir.path().join("device.pub");

    // Generate unencrypted key so no passphrase prompt blocks the test.
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

    let input = write_sample_input(tempdir.path());
    let archive_dir = tempdir.path().join("clip.seal");

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
            "--device-pub",
            pub_path.to_str().unwrap(),
            "--unencrypted",
        ])
        .assert()
        .success();

    let device_pub = fs::read_to_string(&pub_path)
        .unwrap()
        .lines()
        .find(|l| l.starts_with("ed25519:"))
        .unwrap()
        .to_string();
    (archive_dir, device_pub, key_path)
}

/// Run `trst verify <archive> --device-pub <pub>` and return the assert handle.
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

// ---------------------------------------------------------------------------
// SEC-01: Byte-level chunk mutation
// ---------------------------------------------------------------------------

/// SEC-01: Flipping a byte inside an encrypted chunk causes hash mismatch (exit 11).
///
/// The BLAKE3 hash in the manifest was computed over the original ciphertext.
/// Any mutation of the on-disk ciphertext invalidates the stored hash.
#[test]
fn test_sec01_encrypted_chunk_byte_flip() {
    let tempdir = TempDir::new().unwrap();
    let (archive, device_pub, _key_path) = wrap_encrypted_archive(&tempdir);

    // 64 KB / 4096 = 16 chunks (00000.bin .. 00015.bin); pick a middle chunk.
    let chunk_path = archive.join("chunks/00005.bin");
    let mut data = fs::read(&chunk_path).unwrap();
    assert!(data.len() > 10, "chunk must be longer than 10 bytes");
    data[10] = data[10].wrapping_add(1);
    fs::write(&chunk_path, &data).unwrap();

    run_verify(&tempdir, &archive, &device_pub)
        .failure()
        .code(11)
        .stderr(contains("hash mismatch"));
}

/// SEC-01: Flipping the last byte of an unencrypted-key archive's first chunk causes hash mismatch.
///
/// Tests the edge case where the mutation is at the very end of the chunk, not the start.
#[test]
fn test_sec01_unencrypted_chunk_byte_flip_last_byte() {
    let tempdir = TempDir::new().unwrap();
    let (archive, device_pub) = wrap_unencrypted_archive(&tempdir);

    let chunk_path = archive.join("chunks/00000.bin");
    let mut data = fs::read(&chunk_path).unwrap();
    assert!(!data.is_empty(), "chunk must not be empty");
    let last = data.len() - 1;
    data[last] = data[last].wrapping_add(1);
    fs::write(&chunk_path, &data).unwrap();

    run_verify(&tempdir, &archive, &device_pub)
        .failure()
        .code(11)
        .stderr(contains("hash mismatch"));
}

// ---------------------------------------------------------------------------
// SEC-02: Chunk injection
// ---------------------------------------------------------------------------

/// SEC-02: Adding a spurious chunk file not referenced in the manifest is detected (exit 11).
///
/// validate_archive() now scans the chunks/ directory for .bin files not listed
/// in manifest.segments. An attacker cannot silently embed extra data.
#[test]
fn test_sec02_injected_extra_chunk() {
    let tempdir = TempDir::new().unwrap();
    let (archive, device_pub) = wrap_unencrypted_archive(&tempdir);

    // Verify chunk count is 16 as expected.
    let chunk_count = fs::read_dir(archive.join("chunks"))
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".bin"))
        .count();
    assert_eq!(chunk_count, 16, "expected 16 chunks from 64KB/4096 split");

    // Inject a spurious chunk not referenced in manifest.
    let spurious = archive.join("chunks/00016.bin");
    fs::write(&spurious, vec![0xFFu8; 4096]).unwrap();

    run_verify(&tempdir, &archive, &device_pub)
        .failure()
        .code(11)
        .stderr(contains("nreferenced chunk"));
}

/// SEC-02: Replacing a manifest-referenced chunk with garbage is detected (exit 11).
///
/// Even though the filename still matches the manifest, the BLAKE3 hash no longer matches.
#[test]
fn test_sec02_injected_chunk_replacing_existing() {
    let tempdir = TempDir::new().unwrap();
    let (archive, device_pub) = wrap_unencrypted_archive(&tempdir);

    // Overwrite chunk 5 with all-0xFF garbage.
    let chunk_path = archive.join("chunks/00005.bin");
    fs::write(&chunk_path, vec![0xFFu8; 4096]).unwrap();

    run_verify(&tempdir, &archive, &device_pub)
        .failure()
        .code(11)
        .stderr(contains("hash mismatch"));
}

// ---------------------------------------------------------------------------
// SEC-03: Chunk reordering
// ---------------------------------------------------------------------------

/// SEC-03: Swapping two adjacent chunk files is detected via BLAKE3 hash mismatch (exit 11).
///
/// Each segment's blake3_hash in the manifest covers the original chunk content.
/// After a swap the hashes no longer match the swapped-in content.
#[test]
fn test_sec03_swap_adjacent_chunks() {
    let tempdir = TempDir::new().unwrap();
    let (archive, device_pub) = wrap_unencrypted_archive(&tempdir);

    let chunk3 = archive.join("chunks/00003.bin");
    let chunk4 = archive.join("chunks/00004.bin");
    let tmp = archive.join("chunks/tmp_swap.bin");

    fs::rename(&chunk3, &tmp).unwrap();
    fs::rename(&chunk4, &chunk3).unwrap();
    fs::rename(&tmp, &chunk4).unwrap();

    run_verify(&tempdir, &archive, &device_pub)
        .failure()
        .code(11)
        .stderr(contains("hash mismatch"));
}

// ---------------------------------------------------------------------------
// SEC-04: Manifest modification after signing
// ---------------------------------------------------------------------------

/// SEC-04: Changing the "profile" field in manifest.json invalidates the Ed25519 signature.
///
/// The manifest is signed over its canonical JSON bytes. Any field change breaks the sig.
#[test]
fn test_sec04_manifest_profile_change() {
    let tempdir = TempDir::new().unwrap();
    let (archive, device_pub) = wrap_unencrypted_archive(&tempdir);

    let manifest_path = archive.join("manifest.json");
    let content = fs::read_to_string(&manifest_path).unwrap();
    let mut value: serde_json::Value = serde_json::from_str(&content).unwrap();
    value["profile"] = serde_json::json!("tampered");
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&value).unwrap(),
    )
    .unwrap();

    run_verify(&tempdir, &archive, &device_pub)
        .failure()
        .code(10)
        .stderr(contains("Signature verification failed"));
}

/// SEC-04: Changing the device ID field in manifest.json invalidates the Ed25519 signature.
#[test]
fn test_sec04_manifest_device_id_change() {
    let tempdir = TempDir::new().unwrap();
    let (archive, device_pub) = wrap_unencrypted_archive(&tempdir);

    let manifest_path = archive.join("manifest.json");
    let content = fs::read_to_string(&manifest_path).unwrap();
    let mut value: serde_json::Value = serde_json::from_str(&content).unwrap();
    value["device"]["id"] = serde_json::json!("ATTACKER-DEVICE");
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&value).unwrap(),
    )
    .unwrap();

    run_verify(&tempdir, &archive, &device_pub)
        .failure()
        .code(10)
        .stderr(contains("Signature verification failed"));
}

/// SEC-04: Changing a segment's blake3_hash in manifest.json invalidates the Ed25519 signature.
///
/// The signature check runs before hash validation. Even if the hash itself would fail,
/// the signature check catches the tampered manifest first (exit 10, not 11).
#[test]
fn test_sec04_manifest_segment_hash_change() {
    let tempdir = TempDir::new().unwrap();
    let (archive, device_pub) = wrap_unencrypted_archive(&tempdir);

    let manifest_path = archive.join("manifest.json");
    let content = fs::read_to_string(&manifest_path).unwrap();
    let mut value: serde_json::Value = serde_json::from_str(&content).unwrap();
    // Replace the first segment's blake3_hash with 64 'a' characters.
    value["segments"][0]["blake3_hash"] = serde_json::json!("a".repeat(64));
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&value).unwrap(),
    )
    .unwrap();

    run_verify(&tempdir, &archive, &device_pub)
        .failure()
        .code(10)
        .stderr(contains("Signature verification failed"));
}
