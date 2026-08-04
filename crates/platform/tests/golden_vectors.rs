//
// Copyright (c) 2025 TRUSTEDGE LABS LLC
// This source code is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Project: sealedge — Privacy and trust at the edge.
//

//! Golden vectors for the `.trst` signing contract (C1 regression gate).
//!
//! These freeze the *exact* bytes the two independent sides of the product
//! agree on:
//!
//! - `GOLDEN_CANONICAL` — the canonical JSON `TrstManifest::to_canonical_bytes()`
//!   produces for a fixed manifest. Locks the canonicalization (field order,
//!   number formatting, signature exclusion).
//! - `GOLDEN_SIGNATURE` — the Ed25519 signature `crypto::sign_manifest` produces
//!   over those bytes with a fixed key. Locks the signature wire format
//!   (`ed25519:BASE64`, deterministic Ed25519).
//!
//! The final test then feeds the reassembled wire manifest through the platform
//! verification engine and asserts it verifies. If either component's
//! canonicalization or signature handling drifts, one of these assertions
//! fails — the failure mode C1 describes could no longer ship silently.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use sealedge_core::{
    ChunkInfo, DeviceInfo, DeviceKeypair, GenericMetadata, ProfileMetadata, SegmentInfo,
    TrstManifest,
};
use sealedge_platform::verify::engine::{verify_to_report, SegmentDigest};

/// A fixed 32-byte Ed25519 secret (all `0x07`) — deterministic across runs.
fn golden_keypair() -> DeviceKeypair {
    DeviceKeypair::import_secret(&format!("ed25519:{}", BASE64.encode([7u8; 32]))).unwrap()
}

/// The fixed device public key derived from [`golden_keypair`].
const GOLDEN_DEVICE_PUB: &str = "ed25519:6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw=";

/// Golden canonical manifest bytes (see module docs).
const GOLDEN_CANONICAL: &str = r#"{"trst_version":"0.1.0","profile":"generic","device":{"id":"golden-device","model":"TrustEdgeRefCam","firmware_version":"1.0.0","public_key":"ed25519:6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw="},"metadata":{"started_at":"2025-01-15T10:30:00Z","ended_at":"2025-01-15T10:30:02Z"},"chunk":{"size_bytes":4096,"duration_seconds":2},"segments":[{"chunk_file":"00000.bin","blake3_hash":"b3:00","start_time":"2025-01-15T10:30:00Z","duration_seconds":2,"continuity_hash":"b3:00"}],"claims":["location:unknown"]}"#;

/// Golden Ed25519 signature over [`GOLDEN_CANONICAL`] (see module docs).
const GOLDEN_SIGNATURE: &str = "ed25519:oyKgd6SUXDpzqn/SNUqiW5ZPzZao9MkfPQbEDrk2sNVCoNvwvGawCh0vFO76aHSnv6ItB9uuwvGYMQ+ZYvmsCw==";

/// Build the fixed golden manifest (unsigned).
fn golden_manifest(public_key: &str) -> TrstManifest {
    TrstManifest {
        trst_version: "0.1.0".to_string(),
        profile: "generic".to_string(),
        device: DeviceInfo {
            id: "golden-device".to_string(),
            model: "TrustEdgeRefCam".to_string(),
            firmware_version: "1.0.0".to_string(),
            public_key: public_key.to_string(),
        },
        metadata: ProfileMetadata::Generic(GenericMetadata {
            started_at: "2025-01-15T10:30:00Z".to_string(),
            ended_at: "2025-01-15T10:30:02Z".to_string(),
            ..Default::default()
        }),
        chunk: ChunkInfo {
            size_bytes: 4096,
            duration_seconds: 2.0,
        },
        segments: vec![SegmentInfo {
            chunk_file: "00000.bin".to_string(),
            blake3_hash: "b3:00".to_string(),
            start_time: "2025-01-15T10:30:00Z".to_string(),
            duration_seconds: 2.0,
            continuity_hash: "b3:00".to_string(),
        }],
        claims: vec!["location:unknown".to_string()],
        prev_archive_hash: None,
        signature: None,
    }
}

#[test]
fn golden_device_pub_is_stable() {
    assert_eq!(golden_keypair().public, GOLDEN_DEVICE_PUB);
}

#[test]
fn golden_canonicalization_is_stable() {
    let manifest = golden_manifest(GOLDEN_DEVICE_PUB);
    let canonical = String::from_utf8(manifest.to_canonical_bytes().unwrap()).unwrap();
    assert_eq!(
        canonical, GOLDEN_CANONICAL,
        "canonical manifest bytes drifted — this breaks every existing signature"
    );
}

#[test]
fn golden_signature_is_stable() {
    let keypair = golden_keypair();
    let manifest = golden_manifest(&keypair.public);
    let canonical = manifest.to_canonical_bytes().unwrap();
    let signature = sealedge_core::crypto::sign_manifest(&keypair, &canonical).unwrap();
    assert_eq!(
        signature, GOLDEN_SIGNATURE,
        "signature wire format drifted — this breaks the CLI/platform contract"
    );
}

#[test]
fn golden_vector_verifies_through_platform_engine() {
    // Reassemble the wire manifest exactly as `seal emit-request` would: the
    // full signed TrstManifest serialized to JSON, signature stored inline.
    let keypair = golden_keypair();
    let mut manifest = golden_manifest(&keypair.public);
    let canonical = manifest.to_canonical_bytes().unwrap();
    let signature = sealedge_core::crypto::sign_manifest(&keypair, &canonical).unwrap();
    manifest.set_signature(signature);

    let manifest_value = serde_json::to_value(&manifest).unwrap();
    let segments = vec![SegmentDigest {
        index: 0,
        hash: "b3:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
    }];

    let report = verify_to_report(&manifest_value, &segments, &keypair.public).unwrap();

    assert!(
        report.signature_verification.passed,
        "golden vector must verify through the real platform engine"
    );
    assert!(report.continuity_verification.passed);
}
