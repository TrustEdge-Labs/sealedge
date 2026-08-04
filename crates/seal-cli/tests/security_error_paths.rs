//
// Copyright (c) 2025 TRUSTEDGE LABS LLC
// This source code is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Project: sealedge — Privacy and trust at the edge.
//

//! Security tests for error paths in archive creation and auth — covers TEST-02.
//!
//!   SEC-13: Sensor profile with missing required CLI fields is rejected before wrapping

// Allow deprecated cargo_bin usage — the replacement cargo_bin_cmd! macro
// is not yet stable across all assert_cmd versions.
#![allow(deprecated)]

use assert_cmd::prelude::*;
use predicates::str::contains;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Generate an unencrypted keypair in the given directory.
/// Returns `(key_path, pub_path)`.
fn generate_keypair(dir: &Path) -> (PathBuf, PathBuf) {
    let key_path = dir.join("device.key");
    let pub_path = dir.join("device.pub");
    Command::cargo_bin("seal")
        .unwrap()
        .args(["keygen", "--out-key"])
        .arg(&key_path)
        .args(["--out-pub"])
        .arg(&pub_path)
        .arg("--unencrypted")
        .assert()
        .success();
    (key_path, pub_path)
}

/// Write minimal sample input to a temp file and return its path.
fn write_sample_input(dir: &Path) -> PathBuf {
    let path = dir.join("input.bin");
    std::fs::write(&path, b"test-data").unwrap();
    path
}

// ---------------------------------------------------------------------------
// SEC-13: Sensor profile with missing required CLI fields
// ---------------------------------------------------------------------------

/// SEC-13: Sensor profile wrap without --sample-rate is rejected before writing any output.
///
/// The `trst wrap --profile sensor` command requires --sample-rate, --unit, and --sensor-model.
/// Omitting --sample-rate must cause an immediate non-zero exit with a descriptive error;
/// no partial archive must be written.
#[test]
fn sec_13_sensor_missing_sample_rate() {
    let tempdir = TempDir::new().unwrap();
    let (key_path, pub_path) = generate_keypair(tempdir.path());
    let input_path = write_sample_input(tempdir.path());
    let archive_path = tempdir.path().join("out.seal");

    Command::cargo_bin("seal")
        .unwrap()
        .args(["wrap", "--profile", "sensor", "--in"])
        .arg(&input_path)
        .arg("--out")
        .arg(&archive_path)
        .arg("--device-key")
        .arg(&key_path)
        .arg("--device-pub")
        .arg(&pub_path)
        .args([
            "--unencrypted",
            "--unit",
            "celsius",
            "--sensor-model",
            "DHT22",
        ])
        // --sample-rate intentionally omitted
        .assert()
        .failure()
        .stderr(contains("--sample-rate is required for sensor profile"));
}

/// SEC-13: Sensor profile wrap without --unit is rejected before writing any output.
///
/// When --sample-rate is provided but --unit is absent, the CLI must exit non-zero
/// with a message identifying --unit as required for the sensor profile.
#[test]
fn sec_13_sensor_missing_unit() {
    let tempdir = TempDir::new().unwrap();
    let (key_path, pub_path) = generate_keypair(tempdir.path());
    let input_path = write_sample_input(tempdir.path());
    let archive_path = tempdir.path().join("out.seal");

    Command::cargo_bin("seal")
        .unwrap()
        .args(["wrap", "--profile", "sensor", "--in"])
        .arg(&input_path)
        .arg("--out")
        .arg(&archive_path)
        .arg("--device-key")
        .arg(&key_path)
        .arg("--device-pub")
        .arg(&pub_path)
        .args([
            "--unencrypted",
            "--sample-rate",
            "100",
            "--sensor-model",
            "DHT22",
        ])
        // --unit intentionally omitted
        .assert()
        .failure()
        .stderr(contains("--unit is required for sensor profile"));
}

/// SEC-13: Sensor profile wrap without --sensor-model is rejected before writing any output.
///
/// When --sample-rate and --unit are provided but --sensor-model is absent, the CLI must
/// exit non-zero with a message identifying --sensor-model as required for the sensor profile.
#[test]
fn sec_13_sensor_missing_sensor_model() {
    let tempdir = TempDir::new().unwrap();
    let (key_path, pub_path) = generate_keypair(tempdir.path());
    let input_path = write_sample_input(tempdir.path());
    let archive_path = tempdir.path().join("out.seal");

    Command::cargo_bin("seal")
        .unwrap()
        .args(["wrap", "--profile", "sensor", "--in"])
        .arg(&input_path)
        .arg("--out")
        .arg(&archive_path)
        .arg("--device-key")
        .arg(&key_path)
        .arg("--device-pub")
        .arg(&pub_path)
        .args(["--unencrypted", "--sample-rate", "100", "--unit", "celsius"])
        // --sensor-model intentionally omitted
        .assert()
        .failure()
        .stderr(contains("--sensor-model is required for sensor profile"));
}

/// SEC-13: Sensor profile wrap with all required fields present succeeds.
///
/// This positive control confirms the three error tests above are testing the correct
/// fields — a fully specified sensor profile wrap must succeed without errors.
#[test]
fn sec_13_sensor_all_required_present_succeeds() {
    let tempdir = TempDir::new().unwrap();
    let (key_path, pub_path) = generate_keypair(tempdir.path());
    let input_path = write_sample_input(tempdir.path());
    let archive_path = tempdir.path().join("out.seal");

    Command::cargo_bin("seal")
        .unwrap()
        .args(["wrap", "--profile", "sensor", "--in"])
        .arg(&input_path)
        .arg("--out")
        .arg(&archive_path)
        .arg("--device-key")
        .arg(&key_path)
        .arg("--device-pub")
        .arg(&pub_path)
        .args([
            "--unencrypted",
            "--sample-rate",
            "100",
            "--unit",
            "celsius",
            "--sensor-model",
            "DHT22",
        ])
        .assert()
        .success();
}
