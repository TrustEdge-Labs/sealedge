//
// Copyright (c) 2025 TRUSTEDGE LABS LLC
// This source code is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Project: sealedge — Privacy and trust at the edge.
//

//! Security tests for nonce uniqueness and HKDF key derivation — covers threat model T5 (nonce reuse)
//! and T6 (key derivation weakness).
//!
//! Tests are organized by requirement:
//!   SEC-05: All chunk nonces within a single archive are unique (no nonce reuse)
//!   SEC-06: Same plaintext + same device key produces different nonces across two separate archives
//!   SEC-07: HKDF derivation with different device keys produces different chunk encryption keys

// Allow deprecated cargo_bin usage — the replacement cargo_bin_cmd! macro
// is not yet stable across all assert_cmd versions.
#![allow(deprecated)]

use assert_cmd::prelude::*;
use sealedge_core::derive_chunk_key;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Write 64 KB of deterministic data.
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

    let device_pub = fs::read_to_string(tempdir.path().join("device.pub")).unwrap();
    (archive_dir, device_pub.trim().to_string())
}

/// Generate a keypair (unencrypted) into key_path and pub_path.
fn keygen_unencrypted(tempdir: &TempDir, key_path: &Path, pub_path: &Path) {
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
}

/// Read the 24-byte nonce prefix from a chunk file.
fn read_nonce(chunk_path: &Path) -> [u8; 24] {
    let data = fs::read(chunk_path).expect("chunk file must be readable");
    assert!(
        data.len() >= 24,
        "chunk file must be at least 24 bytes (nonce prefix)"
    );
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&data[..24]);
    nonce
}

/// Collect all chunk .bin files from the chunks/ directory of an archive, sorted by name.
fn collect_chunk_paths(archive_dir: &Path) -> Vec<PathBuf> {
    let chunks_dir = archive_dir.join("chunks");
    let mut paths: Vec<PathBuf> = fs::read_dir(&chunks_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map(|ext| ext == "bin").unwrap_or(false))
        .collect();
    paths.sort();
    paths
}

// ---------------------------------------------------------------------------
// SEC-05: Nonce uniqueness within an archive
// ---------------------------------------------------------------------------

/// SEC-05: All chunk nonces within a single archive are unique (no nonce reuse).
///
/// A 64 KB archive split at 4096-byte chunks produces 16 chunks. Each chunk's
/// first 24 bytes are the XChaCha20 nonce. We collect all nonces into a HashSet
/// and assert no duplicates exist.
#[test]
fn test_sec05_all_chunk_nonces_unique_within_archive() {
    let tempdir = TempDir::new().unwrap();
    let (archive, _device_pub) = wrap_unencrypted_archive(&tempdir);

    let chunk_paths = collect_chunk_paths(&archive);
    assert_eq!(
        chunk_paths.len(),
        16,
        "expected 16 chunks from 64KB / 4096-byte chunk-size"
    );

    let mut nonce_set: HashSet<[u8; 24]> = HashSet::new();
    for path in &chunk_paths {
        let nonce = read_nonce(path);
        let is_new = nonce_set.insert(nonce);
        assert!(
            is_new,
            "duplicate nonce detected in chunk {}: {:?}",
            path.display(),
            nonce
        );
    }

    assert_eq!(
        nonce_set.len(),
        16,
        "HashSet must contain exactly 16 unique nonces"
    );
}

/// SEC-05: No nonce within the archive is all-zero (sanity check that nonces are populated).
///
/// An all-zero 24-byte nonce would indicate a failure to initialize the nonce
/// before encryption, which is a critical security flaw.
#[test]
fn test_sec05_nonce_not_all_zeros() {
    let tempdir = TempDir::new().unwrap();
    let (archive, _device_pub) = wrap_unencrypted_archive(&tempdir);

    let chunk_paths = collect_chunk_paths(&archive);
    assert!(
        !chunk_paths.is_empty(),
        "archive must contain at least one chunk"
    );

    let all_zeros = [0u8; 24];
    for path in &chunk_paths {
        let nonce = read_nonce(path);
        assert_ne!(
            nonce,
            all_zeros,
            "nonce in chunk {} is all zeros — nonce was not initialized",
            path.display()
        );
    }
}

// ---------------------------------------------------------------------------
// SEC-06: Nonce uniqueness across archives
// ---------------------------------------------------------------------------

/// SEC-06: Same plaintext + same device key produces different nonces across two archives.
///
/// Nonces are randomly generated per-chunk, so two archives created from the
/// same input with the same key must have independent (statistically unique) nonces.
/// A collision probability for 24-byte random nonces is negligible (~2^{-192}).
#[test]
fn test_sec06_same_plaintext_same_key_different_nonces() {
    let tempdir = TempDir::new().unwrap();

    let key_path = tempdir.path().join("device.key");
    let pub_path = tempdir.path().join("device.pub");
    keygen_unencrypted(&tempdir, &key_path, &pub_path);

    let archive1 = tempdir.path().join("archive1.seal");
    let archive2 = tempdir.path().join("archive2.seal");

    // Write the same input twice (identical plaintext).
    let input1 = tempdir.path().join("input1.bin");
    let data: Vec<u8> = (0..(64 * 1024)).map(|i| (i % 251) as u8).collect();
    fs::write(&input1, &data).unwrap();

    let input2 = tempdir.path().join("input2.bin");
    fs::write(&input2, &data).unwrap();

    // Wrap both from identical plaintext with identical key.
    Command::cargo_bin("seal")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "wrap",
            "--profile",
            "cam.video",
            "--in",
            input1.to_str().unwrap(),
            "--out",
            archive1.to_str().unwrap(),
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

    Command::cargo_bin("seal")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "wrap",
            "--profile",
            "cam.video",
            "--in",
            input2.to_str().unwrap(),
            "--out",
            archive2.to_str().unwrap(),
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

    let nonce1 = read_nonce(&archive1.join("chunks/00000.bin"));
    let nonce2 = read_nonce(&archive2.join("chunks/00000.bin"));

    assert_ne!(
        nonce1, nonce2,
        "chunk 00000.bin nonces must differ across two archives created from the same input and key"
    );
}

// ---------------------------------------------------------------------------
// SEC-07: HKDF key binding
// ---------------------------------------------------------------------------

/// SEC-07: Different device keys produce different chunk encryption keys.
///
/// HKDF must be sensitive to its input keying material — two different device
/// secrets must yield distinct derived chunk keys.
#[test]
fn test_sec07_different_device_keys_produce_different_chunk_keys() {
    let input_a = [0x01u8; 32];
    let input_b = [0x02u8; 32];

    let key_a = derive_chunk_key(&input_a);
    let key_b = derive_chunk_key(&input_b);

    assert_ne!(
        key_a.as_slice(),
        key_b.as_slice(),
        "derive_chunk_key must produce distinct keys for distinct device secrets"
    );
}

/// SEC-07: Same device key always produces the same chunk encryption key (deterministic HKDF).
///
/// Key derivation must be deterministic so that decryption is reproducible.
#[test]
fn test_sec07_same_device_key_produces_same_chunk_key() {
    let input = [0xABu8; 32];

    let key1 = derive_chunk_key(&input);
    let key2 = derive_chunk_key(&input);

    assert_eq!(
        key1.as_slice(),
        key2.as_slice(),
        "derive_chunk_key must be deterministic for the same device secret"
    );
}

/// SEC-07: HKDF-derived key has full entropy — not all zeros, not all 0xFF, and exactly 32 bytes.
///
/// A trivial or degenerate implementation that produces an all-zero or all-ones key
/// would be catastrophically insecure. This test guards against that.
#[test]
fn test_sec07_hkdf_produces_full_entropy_key() {
    let input = [0x42u8; 32];
    let key = derive_chunk_key(&input);

    let key_bytes = key.as_slice();
    assert_eq!(key_bytes.len(), 32, "derived key must be exactly 32 bytes");

    let all_zeros = [0u8; 32];
    assert_ne!(key_bytes, all_zeros, "derived key must not be all zeros");

    let all_ones = [0xFFu8; 32];
    assert_ne!(
        key_bytes,
        all_ones.as_slice(),
        "derived key must not be all 0xFF"
    );
}
