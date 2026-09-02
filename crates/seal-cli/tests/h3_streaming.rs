//
// Copyright (c) 2025 TRUSTEDGE LABS LLC
// This source code is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Project: sealedge — Privacy and trust at the edge.
//

//! H3 streaming-wrap acceptance tests: a large multi-chunk input wraps, verifies,
//! and round-trips through unwrap (exercising the constant-memory streaming path
//! over hundreds of chunks); and a seeded wrap is byte-identical across runs
//! (guards the SA3 RNG-interleaving invariant — CEK pre-loop / nonces in-loop /
//! HPKE post-loop). Exercises the real `seal` binary end-to-end.

#![allow(deprecated)]

use assert_cmd::prelude::*;
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

fn seal() -> Command {
    Command::cargo_bin("seal").expect("seal binary")
}

fn keygen(dir: &Path, name: &str) -> String {
    let key = dir.join(format!("{name}.key"));
    let pubp = dir.join(format!("{name}.pub"));
    seal()
        .args([
            "keygen",
            "--unencrypted",
            "--out-key",
            key.to_str().unwrap(),
            "--out-pub",
            pubp.to_str().unwrap(),
        ])
        .assert()
        .success();
    fs::read_to_string(&pubp)
        .unwrap()
        .lines()
        .find(|l| l.starts_with("ed25519:"))
        .expect("ed25519 line")
        .to_string()
}

/// A deterministic pseudo-random payload of `n` bytes (not crypto — just varied
/// content so chunk hashes differ).
fn payload(n: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(n);
    let mut x: u32 = 0x1234_5678;
    for _ in 0..n {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        v.push((x >> 24) as u8);
    }
    v
}

#[test]
fn large_input_streams_verifies_and_roundtrips() {
    let dir = TempDir::new().unwrap();
    let _ed = keygen(dir.path(), "device");
    let key = dir.path().join("device.key");
    let ed = fs::read_to_string(dir.path().join("device.pub"))
        .unwrap()
        .lines()
        .find(|l| l.starts_with("ed25519:"))
        .unwrap()
        .to_string();

    // ~1 MiB at 4 KiB chunks ⇒ 256 chunks through the streaming path.
    let data = payload(1024 * 1024);
    let input = dir.path().join("big.bin");
    fs::write(&input, &data).unwrap();
    let archive = dir.path().join("big.seal");

    seal()
        .args([
            "wrap",
            "--unencrypted",
            "--in",
            input.to_str().unwrap(),
            "--out",
            archive.to_str().unwrap(),
            "--device-key",
            key.to_str().unwrap(),
            "--chunk-size",
            "4096",
        ])
        .assert()
        .success();

    // 256 chunk files were streamed to disk.
    let chunk_count = fs::read_dir(archive.join("chunks")).unwrap().count();
    assert_eq!(chunk_count, 256, "1 MiB / 4 KiB = 256 chunks");

    // Verifies public-key-only.
    seal()
        .args(["verify", archive.to_str().unwrap(), "--device-pub", &ed])
        .assert()
        .success();

    // Round-trips exactly through unwrap.
    let out = dir.path().join("recovered.bin");
    seal()
        .args([
            "unwrap",
            archive.to_str().unwrap(),
            "--device-key",
            key.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--unencrypted",
        ])
        .assert()
        .success();
    assert_eq!(fs::read(&out).unwrap(), data, "unwrap(wrap(x)) == x");

    // F2: a successful unwrap leaves no `.partial` temp behind (rename + disarm).
    let leftover = fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .any(|e| e.file_name().to_string_lossy().contains(".partial"));
    assert!(!leftover, "unwrap left a .partial temp after success");
}

/// F2: a *failed* unwrap must not leave a partial/truncated output that could be
/// mistaken for a complete recovery. Point `--out` at an existing directory so the
/// streamed write to the temp succeeds but the finalizing rename fails; the
/// TempFileGuard must delete the temp, leaving nothing behind.
#[test]
fn unwrap_failure_leaves_no_partial_output() {
    let dir = TempDir::new().unwrap();
    let _ed = keygen(dir.path(), "device");
    let key = dir.path().join("device.key");

    let data = payload(64 * 1024);
    let input = dir.path().join("in.bin");
    fs::write(&input, &data).unwrap();
    let archive = dir.path().join("a.seal");
    seal()
        .args([
            "wrap",
            "--unencrypted",
            "--in",
            input.to_str().unwrap(),
            "--out",
            archive.to_str().unwrap(),
            "--device-key",
            key.to_str().unwrap(),
            "--chunk-size",
            "4096",
        ])
        .assert()
        .success();

    // --out is an existing directory: decrypt + streamed write succeed, but the
    // final rename (file over a directory) fails.
    let out_dir = dir.path().join("out_is_a_dir");
    fs::create_dir(&out_dir).unwrap();
    seal()
        .args([
            "unwrap",
            archive.to_str().unwrap(),
            "--device-key",
            key.to_str().unwrap(),
            "--out",
            out_dir.to_str().unwrap(),
            "--unencrypted",
        ])
        .assert()
        .failure();

    // The temp is a sibling of --out; assert none survives the failure.
    let leftover: Vec<_> = fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().contains(".partial"))
        .collect();
    assert!(
        leftover.is_empty(),
        "partial temp not cleaned up: {leftover:?}"
    );
    assert!(out_dir.is_dir(), "output directory should be untouched");
}

#[test]
fn seeded_wrap_is_byte_identical() {
    // SA3: seeded wrap draws CEK (pre-loop), per-chunk nonces (in-loop), and the
    // HPKE CEK wrap (post-loop) in a fixed order. Two seeded runs of the same
    // input must be byte-identical — manifest and every chunk — or a determinism
    // regression slipped in.
    let dir = TempDir::new().unwrap();
    let _ed = keygen(dir.path(), "device");
    let key = dir.path().join("device.key");

    let data = payload(100_000); // spans multiple 4 KiB chunks
    let input = dir.path().join("in.bin");
    fs::write(&input, &data).unwrap();

    let wrap_seeded = |out: &Path| {
        seal()
            .args([
                "wrap",
                "--unencrypted",
                "--in",
                input.to_str().unwrap(),
                "--out",
                out.to_str().unwrap(),
                "--device-key",
                key.to_str().unwrap(),
                "--chunk-size",
                "4096",
                "--seed",
                "42",
            ])
            .assert()
            .success();
    };

    let a = dir.path().join("a.seal");
    let b = dir.path().join("b.seal");
    wrap_seeded(&a);
    wrap_seeded(&b);

    // Manifest bytes identical.
    assert_eq!(
        fs::read(a.join("manifest.json")).unwrap(),
        fs::read(b.join("manifest.json")).unwrap(),
        "seeded manifest must be byte-identical"
    );
    // Every chunk file identical.
    let n = fs::read_dir(a.join("chunks")).unwrap().count();
    assert!(n > 1, "expected multiple chunks");
    for i in 0..n {
        let name = format!("{i:05}.bin");
        assert_eq!(
            fs::read(a.join("chunks").join(&name)).unwrap(),
            fs::read(b.join("chunks").join(&name)).unwrap(),
            "seeded chunk {name} must be byte-identical"
        );
    }
}

#[test]
fn empty_input_is_rejected_without_creating_archive() {
    // N1: the empty-input error string is unchanged, and no .seal directory is
    // left behind (the metadata pre-check fires before the writer is created).
    let dir = TempDir::new().unwrap();
    let _ed = keygen(dir.path(), "device");
    let key = dir.path().join("device.key");
    let input = dir.path().join("empty.bin");
    fs::write(&input, b"").unwrap();
    let archive = dir.path().join("empty.seal");

    seal()
        .args([
            "wrap",
            "--unencrypted",
            "--in",
            input.to_str().unwrap(),
            "--out",
            archive.to_str().unwrap(),
            "--device-key",
            key.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("Input file is empty"));

    assert!(
        !archive.exists(),
        "no archive dir should be created on empty input"
    );
}

#[test]
fn emit_request_rejects_mismatched_chunk_file() {
    // F5: emit-request recomputes segment hashes from positional NNNNN.bin; it must
    // refuse a manifest whose segment names a different chunk file (integrity parity
    // with verify/read_archive), rather than hashing a file the manifest doesn't name.
    let dir = TempDir::new().unwrap();
    let _ed = keygen(dir.path(), "device");
    let key = dir.path().join("device.key");
    let pubp = dir.path().join("device.pub");

    let input = dir.path().join("in.bin");
    fs::write(&input, payload(1000)).unwrap(); // single chunk -> 00000.bin
    let archive = dir.path().join("a.seal");
    seal()
        .args([
            "wrap",
            "--unencrypted",
            "--in",
            input.to_str().unwrap(),
            "--out",
            archive.to_str().unwrap(),
            "--device-key",
            key.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Point segment 0 at a different chunk file in the manifest (chunk_file only
    // appears as this value; the detached signature is untouched, so read_manifest
    // still parses — F5 is what must catch it).
    let manifest_path = archive.join("manifest.json");
    let manifest = fs::read_to_string(&manifest_path).unwrap();
    assert!(
        manifest.contains("00000.bin"),
        "manifest must name the chunk file"
    );
    fs::write(&manifest_path, manifest.replace("00000.bin", "0000x.bin")).unwrap();

    let out = dir.path().join("req.json");
    seal()
        .args([
            "emit-request",
            "--archive",
            archive.to_str().unwrap(),
            "--device-pub",
            pubp.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .assert()
        .failure();
    assert!(
        !out.exists(),
        "no request should be written when a segment mismatches"
    );
}
