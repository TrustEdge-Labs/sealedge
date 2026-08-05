//
// Copyright (c) 2025 TRUSTEDGE LABS LLC
// This source code is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Project: sealedge — Privacy and trust at the edge.
//

//! H1 Phase 2 acceptance tests: `seal rekey` (dual-signed rotation entry),
//! `wrap` stamping `key_epoch` from the rotated chronicle, the `verify-chronicle`
//! active-identity walk across rotations, the PA3 witness receipt binding on a
//! rotated chain, and the adversarial cases (forged co-signature, unauthorized
//! successor, PN4 empty-state). Exercises the real `seal` binary end-to-end.

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

/// Wrap `payload` into `dir/<name>.seal`, advancing `chronicle` under `device_key`.
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

/// Run `seal rekey`, producing a rotation entry directory at `dir/<name>`.
fn rekey(dir: &Path, chronicle: &Path, old_key: &Path, new_key: &Path, name: &str) -> PathBuf {
    let out = dir.join(name);
    seal()
        .args([
            "rekey",
            "--unencrypted",
            "--chronicle",
            chronicle.to_str().unwrap(),
            "--old-key",
            old_key.to_str().unwrap(),
            "--new-key",
            new_key.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .assert()
        .success();
    out
}

fn manifest_json(archive: &Path) -> serde_json::Value {
    serde_json::from_str(&fs::read_to_string(archive.join("manifest.json")).unwrap()).unwrap()
}

fn state_json(chronicle: &Path) -> serde_json::Value {
    serde_json::from_str(&fs::read_to_string(chronicle).unwrap()).unwrap()
}

/// Build a witness receipt JWS (as the platform would) plus a JWKS carrying its
/// signing key, so the CLI's `--witness` cross-check runs without a live platform.
fn make_witness_jws(device_pub: &str, sequence: u64, tip: &str) -> (String, String) {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use base64::Engine as _;

    let kp = sealedge_core::DeviceKeypair::generate().unwrap();
    let header = serde_json::json!({ "alg": "EdDSA", "kid": "k1", "typ": "JWT" });
    let payload = serde_json::json!({
        "iss": "sealedge-verify-service",
        "sub": device_pub,
        "typ": "witness",
        "witness": { "device_pub": device_pub, "sequence": sequence, "tip": tip },
    });
    let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
    let signing_input = format!("{h}.{p}");
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
fn rotate_wrap_and_verify_chronicle_walk() {
    let dir = TempDir::new().unwrap();
    let gen_ed = keygen(dir.path(), "gen");
    let new_ed = keygen(dir.path(), "new");
    let gen_key = dir.path().join("gen.key");
    let new_key = dir.path().join("new.key");
    let chronicle = dir.path().join("device.chronicle");

    // Genesis archive under the original key (epoch 0), then rotate, then wrap
    // under the new key (epoch 1).
    let a0 = wrap_chronicle(dir.path(), &gen_key, &chronicle, "clip0", b"p0");
    let rot = rekey(dir.path(), &chronicle, &gen_key, &new_key, "rot1");
    let a2 = wrap_chronicle(dir.path(), &new_key, &chronicle, "clip2", b"p2");

    // Genesis stamps no epoch (epoch 0 == absence); post-rotation archive stamps 1.
    let m0 = manifest_json(&a0);
    assert!(m0["device"].get("key_epoch").is_none());
    assert_eq!(m0["sequence"], 0);
    let m2 = manifest_json(&a2);
    assert_eq!(m2["device"]["key_epoch"], 1);
    assert_eq!(m2["device"]["public_key"], new_ed);
    assert_eq!(m2["sequence"], 2);

    // The rotation entry is a directory with rotation.json and no manifest.json.
    assert!(rot.join("rotation.json").is_file());
    assert!(!rot.join("manifest.json").exists());

    // State now tracks the new identity at epoch 1, sequence 2.
    let st = state_json(&chronicle);
    assert_eq!(st["device_pub"], new_ed);
    assert_eq!(st["key_epoch"], 1);
    assert_eq!(st["sequence"], 2);

    // verify-chronicle walks the identity change: --device-pub pins genesis.
    let out = seal()
        .args([
            "verify-chronicle",
            a0.to_str().unwrap(),
            rot.to_str().unwrap(),
            a2.to_str().unwrap(),
            "--device-pub",
            &gen_ed,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(report["chronicle"], "pass");
    assert_eq!(report["rotations"], 1);
    assert_eq!(report["tip_sequence"], 2);
    assert_eq!(report["current_identity"], new_ed);
    assert_eq!(report["current_epoch"], 1);
}

#[test]
fn witness_crosscheck_passes_on_rotated_chain() {
    // PA3: the receipt is bound to the ACTIVE signer at the witnessed sequence
    // (the post-rotation key), not the genesis pin.
    let dir = TempDir::new().unwrap();
    let gen_ed = keygen(dir.path(), "gen");
    let new_ed = keygen(dir.path(), "new");
    let gen_key = dir.path().join("gen.key");
    let new_key = dir.path().join("new.key");
    let chronicle = dir.path().join("device.chronicle");

    let a0 = wrap_chronicle(dir.path(), &gen_key, &chronicle, "clip0", b"p0");
    let rot = rekey(dir.path(), &chronicle, &gen_key, &new_key, "rot1");
    let a2 = wrap_chronicle(dir.path(), &new_key, &chronicle, "clip2", b"p2");

    let st = state_json(&chronicle);
    let seq = st["sequence"].as_u64().unwrap();
    let tip = st["tip"].as_str().unwrap();

    // The device witnesses under its CURRENT (new) key.
    let (token, jwks) = make_witness_jws(&new_ed, seq, tip);
    let rp = dir.path().join("receipt.jws");
    let jp = dir.path().join("jwks.json");
    fs::write(&rp, &token).unwrap();
    fs::write(&jp, &jwks).unwrap();

    seal()
        .args([
            "verify-chronicle",
            a0.to_str().unwrap(),
            rot.to_str().unwrap(),
            a2.to_str().unwrap(),
            "--device-pub",
            &gen_ed,
            "--witness",
            rp.to_str().unwrap(),
            "--witness-jwks",
            jp.to_str().unwrap(),
        ])
        .assert()
        .success();

    // A receipt bound to an unrelated key still fails loud (PA3 preserves F2).
    let other_ed = keygen(dir.path(), "other");
    let (bad_token, bad_jwks) = make_witness_jws(&other_ed, seq, tip);
    fs::write(&rp, &bad_token).unwrap();
    fs::write(&jp, &bad_jwks).unwrap();
    seal()
        .args([
            "verify-chronicle",
            a0.to_str().unwrap(),
            rot.to_str().unwrap(),
            a2.to_str().unwrap(),
            "--device-pub",
            &gen_ed,
            "--witness",
            rp.to_str().unwrap(),
            "--witness-jwks",
            jp.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .code(13);
}

#[test]
fn verify_chronicle_rejects_tampered_rotation_signature() {
    let dir = TempDir::new().unwrap();
    let gen_ed = keygen(dir.path(), "gen");
    let _new_ed = keygen(dir.path(), "new");
    let gen_key = dir.path().join("gen.key");
    let new_key = dir.path().join("new.key");
    let chronicle = dir.path().join("device.chronicle");

    let a0 = wrap_chronicle(dir.path(), &gen_key, &chronicle, "clip0", b"p0");
    let rot = rekey(dir.path(), &chronicle, &gen_key, &new_key, "rot1");

    // Corrupt sig_new in the rotation entry: the possession proof no longer holds.
    let rp = rot.join("rotation.json");
    let mut rec: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&rp).unwrap()).unwrap();
    let good = rec["sig_new"].as_str().unwrap().to_string();
    // Flip a character in the base64 body (keep the ed25519: prefix + length).
    let body = good.strip_prefix("ed25519:").unwrap();
    let flipped: String = body
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if i == 0 && c != 'A' {
                'A'
            } else if i == 0 {
                'B'
            } else {
                c
            }
        })
        .collect();
    rec["sig_new"] = serde_json::json!(format!("ed25519:{flipped}"));
    fs::write(&rp, serde_json::to_string_pretty(&rec).unwrap()).unwrap();

    seal()
        .args([
            "verify-chronicle",
            a0.to_str().unwrap(),
            rot.to_str().unwrap(),
            "--device-pub",
            &gen_ed,
        ])
        .assert()
        .failure()
        .code(10);
}

#[test]
fn verify_chronicle_rejects_unauthorized_successor() {
    // A rotation co-signed by keys that are NOT the chronicle's active identity
    // must be rejected: the old key in the rotation isn't the genesis signer.
    use sealedge_core::{format_archive_id, DeviceBundle, RotationRecord};

    let dir = TempDir::new().unwrap();
    let gen_ed = keygen(dir.path(), "gen");
    let gen_key = dir.path().join("gen.key");
    let chronicle = dir.path().join("device.chronicle");

    let a0 = wrap_chronicle(dir.path(), &gen_key, &chronicle, "clip0", b"p0");
    let genesis_tip = state_json(&chronicle)["tip"].as_str().unwrap().to_string();

    // Attacker fabricates a self-consistent (dual-signed) rotation from a key it
    // controls — but that key is not the genesis identity.
    let attacker_old = DeviceBundle::generate().unwrap();
    let attacker_new = DeviceBundle::generate().unwrap();
    let record = RotationRecord::create_signed(
        &attacker_old.signing,
        0,
        &attacker_new,
        1,
        genesis_tip,
        "2026-08-05T12:00:00Z",
    )
    .unwrap();
    assert!(
        record.verify(),
        "the forged rotation is internally consistent"
    );
    // Sanity: its digest is well-formed (chains like any entry).
    let _ = format_archive_id(&record.archive_digest());

    let rot = dir.path().join("rot1");
    fs::create_dir_all(&rot).unwrap();
    fs::write(
        rot.join("rotation.json"),
        serde_json::to_string_pretty(&record).unwrap(),
    )
    .unwrap();

    // The walk rejects it: old.public_key != the active (genesis) identity.
    seal()
        .args([
            "verify-chronicle",
            a0.to_str().unwrap(),
            rot.to_str().unwrap(),
            "--device-pub",
            &gen_ed,
        ])
        .assert()
        .failure()
        .code(13);
}

#[test]
fn rekey_requires_existing_chronicle() {
    // PN4: rotating with no chronicle state is an explicit error.
    let dir = TempDir::new().unwrap();
    let _gen = keygen(dir.path(), "gen");
    let _new = keygen(dir.path(), "new");
    let gen_key = dir.path().join("gen.key");
    let new_key = dir.path().join("new.key");
    let chronicle = dir.path().join("missing.chronicle");
    let out = dir.path().join("rot1");

    seal()
        .args([
            "rekey",
            "--unencrypted",
            "--chronicle",
            chronicle.to_str().unwrap(),
            "--old-key",
            gen_key.to_str().unwrap(),
            "--new-key",
            new_key.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .assert()
        .failure();
}

#[test]
fn rekey_rejects_wrong_old_key() {
    // The --old-key must be the chronicle's current identity.
    let dir = TempDir::new().unwrap();
    let _gen = keygen(dir.path(), "gen");
    let _wrong = keygen(dir.path(), "wrong");
    let _new = keygen(dir.path(), "new");
    let gen_key = dir.path().join("gen.key");
    let wrong_key = dir.path().join("wrong.key");
    let new_key = dir.path().join("new.key");
    let chronicle = dir.path().join("device.chronicle");

    let _a0 = wrap_chronicle(dir.path(), &gen_key, &chronicle, "clip0", b"p0");
    let out = dir.path().join("rot1");

    seal()
        .args([
            "rekey",
            "--unencrypted",
            "--chronicle",
            chronicle.to_str().unwrap(),
            "--old-key",
            wrong_key.to_str().unwrap(), // not the genesis identity
            "--new-key",
            new_key.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .assert()
        .failure();
}

#[test]
fn wrap_on_h1_era_state_stays_epoch_zero() {
    // PN1 at the CLI boundary: an H1-era chronicle state (no key_epoch field)
    // loads, wrap continues at epoch 0, and no key_epoch is stamped.
    let dir = TempDir::new().unwrap();
    let ed = keygen(dir.path(), "device");
    let key = dir.path().join("device.key");
    let chronicle = dir.path().join("device.chronicle");

    let a0 = wrap_chronicle(dir.path(), &key, &chronicle, "clip0", b"p0");

    // Rewrite the state file in the H1 shape (drop key_epoch entirely).
    let mut st = state_json(&chronicle);
    let obj = st.as_object_mut().unwrap();
    obj.remove("key_epoch");
    fs::write(&chronicle, serde_json::to_string_pretty(&st).unwrap()).unwrap();

    let a1 = wrap_chronicle(dir.path(), &key, &chronicle, "clip1", b"p1");
    let m1 = manifest_json(&a1);
    assert!(
        m1["device"].get("key_epoch").is_none(),
        "epoch stays absent"
    );
    assert_eq!(m1["sequence"], 1);

    // And the chain still verifies.
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
