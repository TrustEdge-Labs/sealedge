//
// Copyright (c) 2025 TRUSTEDGE LABS LLC
// This source code is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Project: sealedge — Privacy and trust at the edge.
//

//! Device chronicle helpers (H1): archive digests, the local chronicle state
//! file, and witness-request signing.
//!
//! A *chronicle* is a per-device, append-only, hash-linked chain of archives.
//! These helpers are shared by the `seal` CLI (build and verify the chain,
//! submit a witness) and the platform (verify a witness request). See
//! `docs/designs/h1-device-chronicle.md`.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use sealedge_seal_protocols::archive::manifest::{ManifestFormatError, TrstManifest};

use crate::{segment_hash, sign_manifest, verify_manifest, CryptoError, DeviceKeypair};

/// Stable identifier of an archive: BLAKE3 over its canonical (signed) bytes.
///
/// Shares its preimage with the HPKE `pre_digest` used in the wrap path, but is a
/// distinct concept — this is the chronicle link, not CEK-binding context (OQ1).
pub fn archive_digest(manifest: &TrstManifest) -> Result<[u8; 32], ManifestFormatError> {
    Ok(segment_hash(&manifest.to_canonical_bytes()?))
}

/// Format an archive digest as the on-wire chronicle id, `b3:<hex>`.
pub fn format_archive_id(digest: &[u8; 32]) -> String {
    format!("b3:{}", hex::encode(digest))
}

/// A device's local chronicle head pointer.
///
/// Not a secret — the `0600` permissions on the backing file are for integrity,
/// not confidentiality (design §4/N3), and the state is fully re-derivable from
/// the newest archive (`archive_digest` + its `sequence`), so losing it is
/// annoying, not fatal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChronicleState {
    /// The signing identity this chronicle belongs to (`ed25519:<base64>`).
    pub device_pub: String,
    /// Sequence of the most recently written archive.
    pub sequence: u64,
    /// `archive_digest` of the most recently written archive (`b3:<hex>`).
    pub tip: String,
    /// RFC 3339 timestamp of the last update (informational).
    pub updated_at: String,
}

impl ChronicleState {
    /// Read a chronicle state file.
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let bytes = fs::read(path)?;
        serde_json::from_slice(&bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    /// Atomically persist the chronicle state (temp file + rename; `0600` on
    /// unix). Single-writer assumption holds — one device advances its own
    /// chronicle; equivocation is caught by the platform witness ledger.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let tmp = tmp_sibling(path);
        fs::write(&tmp, json.as_bytes())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }
        fs::rename(&tmp, path)?;
        Ok(())
    }
}

fn tmp_sibling(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".tmp");
    path.with_file_name(name)
}

/// A device-signed assertion of its chronicle tip, submitted to the platform
/// witness endpoint (design §7.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessRequest {
    /// Device signing key, `ed25519:<base64>`.
    pub device_pub: String,
    /// Chronicle sequence of the tip being witnessed.
    pub sequence: u64,
    /// Chronicle tip, `b3:<hex>` (`archive_digest` of the archive at `sequence`).
    pub tip: String,
    /// Device-asserted time — **untrusted, diagnostic only** (design N5). The
    /// only trusted time is the platform's `observed_at` in the witness receipt.
    pub signed_at: String,
    /// Ed25519 signature over [`WitnessRequest::signing_bytes`].
    pub signature: String,
}

impl WitnessRequest {
    /// Canonical bytes covered by the signature: fixed field order, signature
    /// excluded. Mirrors the manifest's hand-ordered canonicalization so signing
    /// and verification agree byte-for-byte across CLI and platform.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut s = String::from("{");
        s.push_str(&format!("\"device_pub\":{}", json_str(&self.device_pub)));
        s.push_str(&format!(",\"sequence\":{}", self.sequence));
        s.push_str(&format!(",\"tip\":{}", json_str(&self.tip)));
        s.push_str(&format!(",\"signed_at\":{}", json_str(&self.signed_at)));
        s.push('}');
        s.into_bytes()
    }

    /// Build and sign a witness request for a chronicle tip.
    pub fn create_signed(
        signing: &DeviceKeypair,
        sequence: u64,
        tip: impl Into<String>,
        signed_at: impl Into<String>,
    ) -> Result<Self, CryptoError> {
        let mut req = Self {
            device_pub: signing.public.clone(),
            sequence,
            tip: tip.into(),
            signed_at: signed_at.into(),
            signature: String::new(),
        };
        req.signature = sign_manifest(signing, &req.signing_bytes())?;
        Ok(req)
    }

    /// Verify the request's signature against its own embedded `device_pub`.
    /// (Whether that key is *trusted* — registered, not revoked — is a separate,
    /// caller/platform concern.)
    pub fn verify(&self) -> bool {
        verify_manifest(&self.device_pub, &self.signing_bytes(), &self.signature).unwrap_or(false)
    }
}

/// JSON-encode a string (quoting + escaping) for canonical bytes. Serializing a
/// `&str` is infallible, so this cannot panic in practice.
fn json_str(s: &str) -> String {
    serde_json::to_string(s).expect("JSON string serialization of a &str is infallible")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archive_digest_matches_blake3_over_canonical() {
        let m = TrstManifest::new();
        let d = archive_digest(&m).unwrap();
        assert_eq!(d, segment_hash(&m.to_canonical_bytes().unwrap()));
        // deterministic
        assert_eq!(archive_digest(&m).unwrap(), d);
    }

    #[test]
    fn format_archive_id_shape() {
        assert_eq!(
            format_archive_id(&[0u8; 32]),
            format!("b3:{}", "0".repeat(64))
        );
        assert_eq!(format_archive_id(&[0u8; 32]).len(), 3 + 64);
    }

    #[test]
    fn chronicle_state_round_trip_atomic() {
        let dir = std::env::temp_dir().join(format!("sealedge_chron_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("device.chronicle");
        let st = ChronicleState {
            device_pub: "ed25519:AAAA".to_string(),
            sequence: 5,
            tip: format!("b3:{}", "a".repeat(64)),
            updated_at: "2026-08-05T00:00:00Z".to_string(),
        };
        st.save(&path).unwrap();
        let loaded = ChronicleState::load(&path).unwrap();
        assert_eq!(loaded, st);
        // The temp sibling must be gone after the atomic rename.
        assert!(!dir.join("device.chronicle.tmp").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn witness_request_sign_verify_roundtrip() {
        let kp = DeviceKeypair::generate().unwrap();
        let tip = format!("b3:{}", "b".repeat(64));
        let req =
            WitnessRequest::create_signed(&kp, 3, tip.clone(), "2026-08-05T00:00:00Z").unwrap();
        assert_eq!(req.device_pub, kp.public);
        assert_eq!(req.tip, tip);
        assert!(req.verify(), "freshly signed request must verify");

        // Tampering the tip breaks the signature.
        let mut tampered = req.clone();
        tampered.tip = format!("b3:{}", "c".repeat(64));
        assert!(!tampered.verify(), "tampered request must fail");

        // A bogus signature fails cleanly (no panic).
        let mut badsig = req.clone();
        badsig.signature = format!("ed25519:{}", "A".repeat(86));
        assert!(!badsig.verify());
    }

    #[test]
    fn witness_signing_bytes_fixed_order_excludes_signature() {
        let kp = DeviceKeypair::generate().unwrap();
        let req = WitnessRequest::create_signed(&kp, 1, "b3:tip", "t").unwrap();
        let s = String::from_utf8(req.signing_bytes()).unwrap();
        let dp = s.find("device_pub").unwrap();
        let sq = s.find("sequence").unwrap();
        let tp = s.find("tip").unwrap();
        let sa = s.find("signed_at").unwrap();
        assert!(dp < sq && sq < tp && tp < sa, "fixed field order: {s}");
        assert!(!s.contains("signature"), "signature excluded: {s}");
    }
}
