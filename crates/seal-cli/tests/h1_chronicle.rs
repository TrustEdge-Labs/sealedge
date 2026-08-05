//
// Copyright (c) 2025 TRUSTEDGE LABS LLC
// This source code is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Project: sealedge — Privacy and trust at the edge.
//

//! H1 device-chronicle acceptance tests: genesis + linkage via `--chronicle`,
//! `verify-chronicle` linkage/contiguity, gap/wrong-signer detection, single
//! `verify` chronicle-position reporting, and the `--prev-hash`/`--prev-seq`
//! pairing rule. Exercises the real `seal` binary end-to-end.

// `cargo_bin` is deprecated in assert_cmd 2.x but its replacement isn't stable
// across the versions we support; the legacy suite allows it the same way.
#![allow(deprecated)]

use assert_cmd::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

fn seal() -> Command {
    Command::cargo_bin("seal").expect("seal binary")
}

/// Generate an unencrypted V2 key bundle at `dir/<name>.key` (+ `.pub`) and
/// return the `ed25519:` public line.
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

/// Wrap `payload` into `dir/<name>.seal`, advancing `chronicle`. Returns the
/// archive path.
fn wrap_chronicle(
    dir: &Path,
    device_key: &Path,
    chronicle: &Path,
    name: &str,
    payload: &[u8],
) -> PathBuf {
    let input = dir.join(format!("{name}.bin"));
    fs::write(&input, payload).unwrap();
    let archive = dir.join(format!("{name}.seal"));
    seal()
        .args([
            "wrap",
            "--unencrypted",
            "--in",
            input.to_str().unwrap(),
            "--out",
            archive.to_str().unwrap(),
            "--device-key",
            device_key.to_str().unwrap(),
            "--chronicle",
            chronicle.to_str().unwrap(),
        ])
        .assert()
        .success();
    archive
}

fn manifest_json(archive: &Path) -> serde_json::Value {
    let content = fs::read_to_string(archive.join("manifest.json")).unwrap();
    serde_json::from_str(&content).unwrap()
}

#[test]
fn chronicle_genesis_link_and_verify() {
    let dir = TempDir::new().unwrap();
    let ed = keygen(dir.path(), "device");
    let key = dir.path().join("device.key");
    let chronicle = dir.path().join("device.chronicle");

    let a0 = wrap_chronicle(dir.path(), &key, &chronicle, "clip0", b"first payload");
    let a1 = wrap_chronicle(dir.path(), &key, &chronicle, "clip1", b"second payload");

    // Genesis: sequence 0, no prev.
    let m0 = manifest_json(&a0);
    assert_eq!(m0["sequence"], 0);
    assert!(m0.get("prev_archive_hash").is_none() || m0["prev_archive_hash"].is_null());

    // Link: sequence 1, prev = b3:<hex> pointing back.
    let m1 = manifest_json(&a1);
    assert_eq!(m1["sequence"], 1);
    let prev = m1["prev_archive_hash"].as_str().expect("prev present");
    assert!(
        prev.starts_with("b3:") && prev.len() == 3 + 64,
        "prev shape: {prev}"
    );

    // The state file tracks the latest tip at sequence 1.
    let state: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&chronicle).unwrap()).unwrap();
    assert_eq!(state["sequence"], 1);
    assert_eq!(state["device_pub"], ed);

    // verify-chronicle over both archives succeeds.
    seal()
        .args([
            "verify-chronicle",
            a0.to_str().unwrap(),
            a1.to_str().unwrap(),
            "--device-pub",
            &ed,
        ])
        .assert()
        .success();
}

#[test]
fn chronicle_detects_mid_chain_deletion() {
    let dir = TempDir::new().unwrap();
    let ed = keygen(dir.path(), "device");
    let key = dir.path().join("device.key");
    let chronicle = dir.path().join("device.chronicle");

    let a0 = wrap_chronicle(dir.path(), &key, &chronicle, "clip0", b"p0");
    let a1 = wrap_chronicle(dir.path(), &key, &chronicle, "clip1", b"p1");
    let a2 = wrap_chronicle(dir.path(), &key, &chronicle, "clip2", b"p2");

    // Drop the middle archive: sequences become 0,2 — a contiguity gap.
    fs::remove_dir_all(&a1).unwrap();

    seal()
        .args([
            "verify-chronicle",
            a0.to_str().unwrap(),
            a2.to_str().unwrap(),
            "--device-pub",
            &ed,
        ])
        .assert()
        .failure()
        .code(13);
}

#[test]
fn chronicle_rejects_wrong_signer() {
    let dir = TempDir::new().unwrap();
    let _ed = keygen(dir.path(), "device");
    let other_ed = keygen(dir.path(), "other");
    let key = dir.path().join("device.key");
    let chronicle = dir.path().join("device.chronicle");

    let a0 = wrap_chronicle(dir.path(), &key, &chronicle, "clip0", b"p0");

    // Verifying against a different signer must fail (exit 10).
    seal()
        .args([
            "verify-chronicle",
            a0.to_str().unwrap(),
            "--device-pub",
            &other_ed,
        ])
        .assert()
        .failure()
        .code(10);
}

#[test]
fn verify_reports_chronicle_position_json() {
    let dir = TempDir::new().unwrap();
    let ed = keygen(dir.path(), "device");
    let key = dir.path().join("device.key");
    let chronicle = dir.path().join("device.chronicle");

    let _a0 = wrap_chronicle(dir.path(), &key, &chronicle, "clip0", b"p0");
    let a1 = wrap_chronicle(dir.path(), &key, &chronicle, "clip1", b"p1");

    let out = seal()
        .args([
            "verify",
            a1.to_str().unwrap(),
            "--device-pub",
            &ed,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(report["chronicle_sequence"], 1);
    assert_eq!(report["signature"], "pass");
}

#[test]
fn prev_hash_requires_prev_seq() {
    let dir = TempDir::new().unwrap();
    let _ed = keygen(dir.path(), "device");
    let key = dir.path().join("device.key");
    let input = dir.path().join("in.bin");
    fs::write(&input, b"payload").unwrap();
    let archive = dir.path().join("clip.seal");

    // --prev-hash without --prev-seq is a hard error.
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
            "--prev-hash",
            &format!("b3:{}", "0".repeat(64)),
        ])
        .assert()
        .failure();
}

/// Build a witness receipt JWS (as the platform would) plus a JWKS carrying the
/// signing key, so the CLI's `--witness` cross-check can be exercised without a
/// live platform. Returns `(jws_token, jwks_json)`.
fn make_witness_jws(sequence: u64, tip: &str) -> (String, String) {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use base64::Engine as _;

    // Stand-in platform JWKS key.
    let kp = sealedge_core::DeviceKeypair::generate().unwrap();
    let header = serde_json::json!({ "alg": "EdDSA", "kid": "k1", "typ": "JWT" });
    let payload = serde_json::json!({
        "iss": "sealedge-verify-service",
        "sub": kp.public,
        "typ": "witness",
        "witness": { "sequence": sequence, "tip": tip },
    });
    let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
    let signing_input = format!("{h}.{p}");

    // Sign via core, then re-encode the raw signature as base64url (JWS form).
    let sig_str = sealedge_core::sign_manifest(&kp, signing_input.as_bytes()).unwrap();
    let raw_sig = STANDARD
        .decode(sig_str.strip_prefix("ed25519:").unwrap())
        .unwrap();
    let token = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(&raw_sig));

    let raw_pub = STANDARD
        .decode(kp.public.strip_prefix("ed25519:").unwrap())
        .unwrap();
    let jwks = serde_json::json!({
        "keys": [{ "kty": "OKP", "crv": "Ed25519", "kid": "k1", "x": URL_SAFE_NO_PAD.encode(&raw_pub) }]
    });
    (token, serde_json::to_string(&jwks).unwrap())
}

#[test]
fn witness_crosscheck_passes_when_tip_matches() {
    let dir = TempDir::new().unwrap();
    let ed = keygen(dir.path(), "device");
    let key = dir.path().join("device.key");
    let chronicle = dir.path().join("device.chronicle");
    let a0 = wrap_chronicle(dir.path(), &key, &chronicle, "clip0", b"p0");
    let a1 = wrap_chronicle(dir.path(), &key, &chronicle, "clip1", b"p1");

    let state: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&chronicle).unwrap()).unwrap();
    let seq = state["sequence"].as_u64().unwrap();
    let tip = state["tip"].as_str().unwrap();

    let (token, jwks) = make_witness_jws(seq, tip);
    let rp = dir.path().join("receipt.jws");
    let jp = dir.path().join("jwks.json");
    fs::write(&rp, &token).unwrap();
    fs::write(&jp, &jwks).unwrap();

    seal()
        .args([
            "verify-chronicle",
            a0.to_str().unwrap(),
            a1.to_str().unwrap(),
            "--device-pub",
            &ed,
            "--witness",
            rp.to_str().unwrap(),
            "--witness-jwks",
            jp.to_str().unwrap(),
        ])
        .assert()
        .success();
}

#[test]
fn witness_crosscheck_detects_tail_deletion() {
    let dir = TempDir::new().unwrap();
    let ed = keygen(dir.path(), "device");
    let key = dir.path().join("device.key");
    let chronicle = dir.path().join("device.chronicle");
    let a0 = wrap_chronicle(dir.path(), &key, &chronicle, "clip0", b"p0");
    let a1 = wrap_chronicle(dir.path(), &key, &chronicle, "clip1", b"p1");

    let state: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&chronicle).unwrap()).unwrap();
    let seq = state["sequence"].as_u64().unwrap();

    // The witness has seen a HIGHER sequence than the local chain — the tail was
    // deleted. Cross-check must fail with exit 13.
    let (token, jwks) = make_witness_jws(seq + 1, &format!("b3:{}", "f".repeat(64)));
    let rp = dir.path().join("receipt.jws");
    let jp = dir.path().join("jwks.json");
    fs::write(&rp, &token).unwrap();
    fs::write(&jp, &jwks).unwrap();

    seal()
        .args([
            "verify-chronicle",
            a0.to_str().unwrap(),
            a1.to_str().unwrap(),
            "--device-pub",
            &ed,
            "--witness",
            rp.to_str().unwrap(),
            "--witness-jwks",
            jp.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .code(13);
}
