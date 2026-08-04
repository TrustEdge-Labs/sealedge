//
// Copyright (c) 2025 TRUSTEDGE LABS LLC
// This source code is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Project: sealedge — Privacy and trust at the edge.
//

//! C4 end-to-end acceptance tests: dual-key keygen, per-archive CEK with HPKE
//! recipient wrapping, recipient-model unwrap, sign-only mode, and seed-mode
//! determinism (M2). Exercises the real `seal` binary against the 0.2.0 format.

// `cargo_bin` is deprecated in assert_cmd 2.x but its replacement isn't stable
// across the versions we support; the legacy suite allows it the same way.
#![allow(deprecated)]

use assert_cmd::prelude::*;
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

fn seal() -> Command {
    Command::cargo_bin("seal").expect("seal binary")
}

/// Generate an unencrypted V2 key bundle at `dir/<name>.key` (+ `.pub`) and
/// return `(ed25519_pub, x25519_pub)`.
fn keygen(dir: &Path, name: &str) -> (String, String) {
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
    let pub_contents = fs::read_to_string(&pubp).unwrap();
    let ed = pub_contents
        .lines()
        .find(|l| l.starts_with("ed25519:"))
        .expect("ed25519 line")
        .to_string();
    let x = pub_contents
        .lines()
        .find(|l| l.starts_with("x25519:"))
        .expect("x25519 line")
        .to_string();
    (ed, x)
}

#[test]
fn c4_roundtrip_device_and_auditor_recipient() {
    let dir = TempDir::new().unwrap();
    let (dev_ed, _dev_x) = keygen(dir.path(), "device");
    let (_aud_ed, aud_x) = keygen(dir.path(), "auditor");

    let input = dir.path().join("input.bin");
    let payload = b"the quick brown fox jumps over the lazy dog, repeatedly.".repeat(200);
    fs::write(&input, &payload).unwrap();

    let archive = dir.path().join("clip.seal");
    seal()
        .args([
            "wrap",
            "--unencrypted",
            "--in",
            input.to_str().unwrap(),
            "--out",
            archive.to_str().unwrap(),
            "--device-key",
            dir.path().join("device.key").to_str().unwrap(),
            "--recipient",
            &aud_x,
        ])
        .assert()
        .success();

    // Manifest must be 0.2.0 with an encryption block naming both recipients.
    let manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(archive.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["trst_version"], "0.2.0");
    assert!(manifest["device"]["key_agreement_public"]
        .as_str()
        .unwrap()
        .starts_with("x25519:"));
    let recips = manifest["encryption"]["recipients"].as_array().unwrap();
    assert_eq!(recips.len(), 2, "device + auditor");

    // Verify (public key only).
    seal()
        .args(["verify", archive.to_str().unwrap(), "--device-pub", &dev_ed])
        .assert()
        .success();

    // Unwrap as the DEVICE.
    let out_dev = dir.path().join("out_dev.bin");
    seal()
        .args([
            "unwrap",
            archive.to_str().unwrap(),
            "--unencrypted",
            "--device-key",
            dir.path().join("device.key").to_str().unwrap(),
            "--out",
            out_dev.to_str().unwrap(),
        ])
        .assert()
        .success();
    assert_eq!(fs::read(&out_dev).unwrap(), payload);

    // Unwrap as the AUDITOR — the whole point of C4: a recipient reads content
    // with its OWN key, never the device's signing key.
    let out_aud = dir.path().join("out_aud.bin");
    seal()
        .args([
            "unwrap",
            archive.to_str().unwrap(),
            "--unencrypted",
            "--device-key",
            dir.path().join("auditor.key").to_str().unwrap(),
            "--out",
            out_aud.to_str().unwrap(),
        ])
        .assert()
        .success();
    assert_eq!(fs::read(&out_aud).unwrap(), payload);
}

#[test]
fn c4_non_recipient_cannot_unwrap() {
    let dir = TempDir::new().unwrap();
    keygen(dir.path(), "device");
    let (_s_ed, _s_x) = keygen(dir.path(), "stranger");

    let input = dir.path().join("input.bin");
    fs::write(&input, b"secret payload").unwrap();
    let archive = dir.path().join("clip.seal");
    seal()
        .args([
            "wrap",
            "--unencrypted",
            "--in",
            input.to_str().unwrap(),
            "--out",
            archive.to_str().unwrap(),
            "--device-key",
            dir.path().join("device.key").to_str().unwrap(),
        ])
        .assert()
        .success();

    // A key that is not a recipient must fail to unwrap.
    let out = dir.path().join("out.bin");
    seal()
        .args([
            "unwrap",
            archive.to_str().unwrap(),
            "--unencrypted",
            "--device-key",
            dir.path().join("stranger.key").to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .assert()
        .failure();
}

#[test]
fn c4_seed_mode_is_byte_deterministic() {
    let dir = TempDir::new().unwrap();
    keygen(dir.path(), "device");

    let input = dir.path().join("input.bin");
    fs::write(&input, b"deterministic content for M2").unwrap();

    let wrap = |out: &Path| {
        seal()
            .args([
                "wrap",
                "--unencrypted",
                "--seed",
                "42",
                "--in",
                input.to_str().unwrap(),
                "--out",
                out.to_str().unwrap(),
                "--device-key",
                dir.path().join("device.key").to_str().unwrap(),
            ])
            .assert()
            .success();
    };
    let a = dir.path().join("a.seal");
    let b = dir.path().join("b.seal");
    wrap(&a);
    wrap(&b);

    // Same seed + same key + same input ⇒ byte-identical manifest (M2): CEK,
    // chunk nonces, and HPKE ephemerals are all seeded, so the signature matches.
    assert_eq!(
        fs::read(a.join("manifest.json")).unwrap(),
        fs::read(b.join("manifest.json")).unwrap(),
        "seeded wrap must be byte-deterministic"
    );
}

#[test]
fn c4_sign_only_mode() {
    let dir = TempDir::new().unwrap();
    let (dev_ed, _dev_x) = keygen(dir.path(), "device");

    let input = dir.path().join("input.bin");
    let payload = b"signed but not encrypted".to_vec();
    fs::write(&input, &payload).unwrap();
    let archive = dir.path().join("clip.seal");
    seal()
        .args([
            "wrap",
            "--unencrypted",
            "--sign-only",
            "--in",
            input.to_str().unwrap(),
            "--out",
            archive.to_str().unwrap(),
            "--device-key",
            dir.path().join("device.key").to_str().unwrap(),
        ])
        .assert()
        .success();

    // Sign-only ⇒ no encryption block; verify still passes.
    let manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(archive.join("manifest.json")).unwrap()).unwrap();
    assert!(manifest.get("encryption").is_none() || manifest["encryption"].is_null());
    seal()
        .args(["verify", archive.to_str().unwrap(), "--device-pub", &dev_ed])
        .assert()
        .success();

    // Unwrap returns the plaintext directly.
    let out = dir.path().join("out.bin");
    seal()
        .args([
            "unwrap",
            archive.to_str().unwrap(),
            "--unencrypted",
            "--device-key",
            dir.path().join("device.key").to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .assert()
        .success();
    assert_eq!(fs::read(&out).unwrap(), payload);
}
