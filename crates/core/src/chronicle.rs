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

use crate::{
    segment_hash, sign_manifest, verify_manifest, CryptoError, DeviceBundle, DeviceKeypair,
};

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
    /// After a rotation this becomes the **new** key.
    pub device_pub: String,
    /// Sequence of the most recently written entry (archive or rotation).
    pub sequence: u64,
    /// `archive_digest` of the most recently written entry (`b3:<hex>`).
    pub tip: String,
    /// Key epoch of `device_pub` (H1 Phase 2). `#[serde(default)]` is **load-
    /// bearing**: every H1-era state file predates this field, so it must
    /// default to 0 (the genesis epoch) rather than fail to deserialize (PN1).
    #[serde(default)]
    pub key_epoch: u32,
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
    /// The rotation entry, present iff this witnesses a *rotation tip* (H1 Phase 2,
    /// PA1). It lets the platform verify the co-signatures and record device
    /// lineage. **Not** covered by `signature` — it needs no separate signature
    /// because it carries its own dual co-signatures AND is bound to the signed
    /// `tip` (the platform checks `tip == archive_digest(rotation)`), so it cannot
    /// be swapped without breaking the signed tip.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation: Option<RotationRecord>,
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
            rotation: None,
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

/// The old identity a rotation supersedes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationOld {
    /// Superseded Ed25519 signing key, `ed25519:<base64>`.
    pub public_key: String,
    /// Epoch of the superseded key.
    pub key_epoch: u32,
}

/// The new identity a rotation installs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationNew {
    /// New Ed25519 signing key, `ed25519:<base64>`.
    pub public_key: String,
    /// New X25519 key-agreement key, `x25519:<base64>`.
    pub key_agreement_public: String,
    /// Epoch of the new key. MUST equal `old.key_epoch + 1`.
    pub key_epoch: u32,
}

/// A dedicated chronicle entry that rotates a device's signing identity (H1
/// Phase 2, design §3). It consumes one `sequence` slot and is hash-linked into
/// the chronicle exactly like an archive (its [`RotationRecord::archive_digest`]
/// becomes the next entry's `prev_archive_hash`), but carries no content chunks.
///
/// It is **co-signed**: `sig_old` proves the old key authorized this successor
/// (only the current holder may extend the chain), and `sig_new` proves the
/// holder controls the new key (no committing someone else's key). Both cover the
/// canonical bytes with *both* signatures excluded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationRecord {
    /// Archive format version (`0.2.0`).
    pub trst_version: String,
    /// Entry discriminator; always `"rotation"`.
    pub kind: String,
    /// Chronicle position of this rotation.
    pub sequence: u64,
    /// `archive_digest` of the preceding entry, `b3:<hex>`.
    pub prev_archive_hash: String,
    /// The identity being superseded.
    pub old: RotationOld,
    /// The identity being installed.
    pub new: RotationNew,
    /// RFC 3339 rotation time — **untrusted, diagnostic only** (as with a
    /// manifest's timestamps; trusted time comes from the witness `observed_at`).
    pub rotated_at: String,
    /// Ed25519 signature by the OLD key over [`RotationRecord::signing_bytes`].
    pub sig_old: String,
    /// Ed25519 signature by the NEW key over [`RotationRecord::signing_bytes`].
    pub sig_new: String,
}

/// Discriminator value for a rotation entry's `kind` field.
pub const ROTATION_KIND: &str = "rotation";

impl RotationRecord {
    /// Canonical bytes covered by BOTH signatures: fixed field order, `sig_old`
    /// and `sig_new` excluded. Hand-ordered to match the manifest's
    /// canonicalization philosophy so CLI and platform agree byte-for-byte.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut s = String::from("{");
        s.push_str(&format!(
            "\"trst_version\":{}",
            json_str(&self.trst_version)
        ));
        s.push_str(&format!(",\"kind\":{}", json_str(&self.kind)));
        s.push_str(&format!(",\"sequence\":{}", self.sequence));
        s.push_str(&format!(
            ",\"prev_archive_hash\":{}",
            json_str(&self.prev_archive_hash)
        ));
        s.push_str(&format!(
            ",\"old\":{{\"public_key\":{},\"key_epoch\":{}}}",
            json_str(&self.old.public_key),
            self.old.key_epoch
        ));
        s.push_str(&format!(
            ",\"new\":{{\"public_key\":{},\"key_agreement_public\":{},\"key_epoch\":{}}}",
            json_str(&self.new.public_key),
            json_str(&self.new.key_agreement_public),
            self.new.key_epoch
        ));
        s.push_str(&format!(",\"rotated_at\":{}", json_str(&self.rotated_at)));
        s.push('}');
        s.into_bytes()
    }

    /// Stable identifier of a rotation entry: BLAKE3 over its canonical bytes.
    /// Identical machinery to [`archive_digest`] so a rotation links into the
    /// hash chain like any other entry.
    pub fn archive_digest(&self) -> [u8; 32] {
        segment_hash(&self.signing_bytes())
    }

    /// Build and co-sign a rotation from the old signing key to a new bundle.
    ///
    /// `old_epoch` is the epoch of `old_signing` in the chronicle; the new key is
    /// installed at `old_epoch + 1`.
    pub fn create_signed(
        old_signing: &DeviceKeypair,
        old_epoch: u32,
        new_bundle: &DeviceBundle,
        sequence: u64,
        prev_archive_hash: impl Into<String>,
        rotated_at: impl Into<String>,
    ) -> Result<Self, CryptoError> {
        let mut rec = Self {
            trst_version: "0.2.0".to_string(),
            kind: ROTATION_KIND.to_string(),
            sequence,
            prev_archive_hash: prev_archive_hash.into(),
            old: RotationOld {
                public_key: old_signing.public.clone(),
                key_epoch: old_epoch,
            },
            new: RotationNew {
                public_key: new_bundle.signing.public.clone(),
                key_agreement_public: new_bundle.key_agreement.public_string(),
                key_epoch: old_epoch + 1,
            },
            rotated_at: rotated_at.into(),
            sig_old: String::new(),
            sig_new: String::new(),
        };
        let bytes = rec.signing_bytes();
        rec.sig_old = sign_manifest(old_signing, &bytes)?;
        rec.sig_new = sign_manifest(&new_bundle.signing, &bytes)?;
        Ok(rec)
    }

    /// Self-contained validity: `kind == "rotation"`, the epoch bump is exactly
    /// `+1`, and BOTH co-signatures verify against their respective keys. Whether
    /// `old.public_key` is the chronicle's *active* signer at this point — the
    /// authorization-chain check — is the verifier's job (the active-identity walk
    /// in `verify-chronicle`), because it needs chain context this record lacks.
    pub fn verify(&self) -> bool {
        if self.kind != ROTATION_KIND {
            return false;
        }
        if self.new.key_epoch != self.old.key_epoch.wrapping_add(1) {
            return false;
        }
        let bytes = self.signing_bytes();
        let old_ok = verify_manifest(&self.old.public_key, &bytes, &self.sig_old).unwrap_or(false);
        let new_ok = verify_manifest(&self.new.public_key, &bytes, &self.sig_new).unwrap_or(false);
        old_ok && new_ok
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
            key_epoch: 2,
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
    fn chronicle_state_h1_era_loads_at_epoch_zero() {
        // PN1: an H1-era state file has no `key_epoch`; it must load, defaulting to
        // epoch 0, rather than fail to deserialize.
        let h1 = r#"{"device_pub":"ed25519:AAAA","sequence":3,"tip":"b3:aa","updated_at":"t"}"#;
        let st: ChronicleState = serde_json::from_str(h1).unwrap();
        assert_eq!(st.key_epoch, 0, "missing key_epoch defaults to genesis (0)");
        assert_eq!(st.sequence, 3);
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

    #[test]
    fn witness_rotation_attachment_is_not_signed() {
        // PA1: attaching a rotation entry must not change the signing bytes or
        // invalidate the signature — the rotation is bound to the signed tip, not
        // signed itself.
        let kp = DeviceKeypair::generate().unwrap();
        let new = DeviceBundle::generate().unwrap();
        let mut req = WitnessRequest::create_signed(&kp, 1, "b3:tip", "t").unwrap();
        let bytes_before = req.signing_bytes();
        assert!(req.verify());

        let rec =
            RotationRecord::create_signed(&kp, 0, &new, 1, format!("b3:{}", "0".repeat(64)), "t")
                .unwrap();
        req.rotation = Some(rec);

        assert_eq!(
            req.signing_bytes(),
            bytes_before,
            "rotation must not enter the signed bytes"
        );
        assert!(
            req.verify(),
            "signature still valid after attaching rotation"
        );
    }

    // ── H1 Phase 2: rotation records ──

    /// PN5: frozen golden fixture for the rotation canonical bytes. These bytes
    /// are a NEW signature surface — pin the exact serialization so any accidental
    /// field-order/format change is a loud test failure, not a silent break.
    #[test]
    fn rotation_signing_bytes_frozen_golden() {
        let rec = RotationRecord {
            trst_version: "0.2.0".to_string(),
            kind: ROTATION_KIND.to_string(),
            sequence: 7,
            prev_archive_hash: format!("b3:{}", "a".repeat(64)),
            old: RotationOld {
                public_key: "ed25519:OLDPUB".to_string(),
                key_epoch: 0,
            },
            new: RotationNew {
                public_key: "ed25519:NEWPUB".to_string(),
                key_agreement_public: "x25519:NEWKA".to_string(),
                key_epoch: 1,
            },
            rotated_at: "2026-08-05T12:00:00Z".to_string(),
            // Signatures are excluded from signing_bytes, so their values here
            // must not affect the frozen output.
            sig_old: "ed25519:SHOULD_BE_IGNORED".to_string(),
            sig_new: "ed25519:ALSO_IGNORED".to_string(),
        };
        let expected = format!(
            "{{\"trst_version\":\"0.2.0\",\"kind\":\"rotation\",\"sequence\":7,\
\"prev_archive_hash\":\"b3:{}\",\
\"old\":{{\"public_key\":\"ed25519:OLDPUB\",\"key_epoch\":0}},\
\"new\":{{\"public_key\":\"ed25519:NEWPUB\",\"key_agreement_public\":\"x25519:NEWKA\",\"key_epoch\":1}},\
\"rotated_at\":\"2026-08-05T12:00:00Z\"}}",
            "a".repeat(64)
        );
        assert_eq!(
            String::from_utf8(rec.signing_bytes()).unwrap(),
            expected,
            "rotation canonical bytes drifted from the frozen golden"
        );
    }

    #[test]
    fn rotation_sign_verify_roundtrip() {
        let old = DeviceKeypair::generate().unwrap();
        let new = DeviceBundle::generate().unwrap();
        let prev = format!("b3:{}", "0".repeat(64));
        let rec =
            RotationRecord::create_signed(&old, 0, &new, 4, prev.clone(), "2026-08-05T12:00:00Z")
                .unwrap();

        assert_eq!(rec.old.public_key, old.public);
        assert_eq!(rec.new.public_key, new.signing.public);
        assert_eq!(
            rec.new.key_agreement_public,
            new.key_agreement.public_string()
        );
        assert_eq!(rec.old.key_epoch, 0);
        assert_eq!(rec.new.key_epoch, 1);
        assert!(rec.verify(), "freshly co-signed rotation must verify");

        // The digest is stable and chains: it is BLAKE3 over the canonical bytes.
        assert_eq!(rec.archive_digest(), segment_hash(&rec.signing_bytes()));
    }

    #[test]
    fn rotation_rejects_forged_or_missing_cosignature() {
        let old = DeviceKeypair::generate().unwrap();
        let new = DeviceBundle::generate().unwrap();
        let other = DeviceBundle::generate().unwrap();
        let prev = format!("b3:{}", "0".repeat(64));
        let good =
            RotationRecord::create_signed(&old, 0, &new, 4, prev, "2026-08-05T12:00:00Z").unwrap();

        // sig_new by a key that isn't `new.public_key` → possession proof fails.
        let mut forged_new = good.clone();
        forged_new.sig_new = sign_manifest(&other.signing, &good.signing_bytes()).unwrap();
        assert!(!forged_new.verify(), "sig_new must be by the new key");

        // sig_old by a key that isn't `old.public_key` → authorization fails.
        let mut forged_old = good.clone();
        forged_old.sig_old = sign_manifest(&other.signing, &good.signing_bytes()).unwrap();
        assert!(!forged_old.verify(), "sig_old must be by the old key");

        // Tampering any signed field breaks both signatures.
        let mut tampered = good.clone();
        tampered.new.public_key = other.signing.public.clone();
        assert!(!tampered.verify(), "tampered successor must fail");
    }

    #[test]
    fn rotation_rejects_bad_epoch_bump_and_kind() {
        let old = DeviceKeypair::generate().unwrap();
        let new = DeviceBundle::generate().unwrap();
        let prev = format!("b3:{}", "0".repeat(64));

        // Epoch must bump by exactly 1. Re-sign after mutating so we isolate the
        // epoch check from the signature check.
        let mut skip = RotationRecord {
            trst_version: "0.2.0".to_string(),
            kind: ROTATION_KIND.to_string(),
            sequence: 4,
            prev_archive_hash: prev,
            old: RotationOld {
                public_key: old.public.clone(),
                key_epoch: 0,
            },
            new: RotationNew {
                public_key: new.signing.public.clone(),
                key_agreement_public: new.key_agreement.public_string(),
                key_epoch: 2, // skips 1
            },
            rotated_at: "t".to_string(),
            sig_old: String::new(),
            sig_new: String::new(),
        };
        let bytes = skip.signing_bytes();
        skip.sig_old = sign_manifest(&old, &bytes).unwrap();
        skip.sig_new = sign_manifest(&new.signing, &bytes).unwrap();
        assert!(
            !skip.verify(),
            "epoch skip must fail even with valid signatures"
        );

        // Wrong `kind` fails.
        let mut bad_kind = skip.clone();
        bad_kind.new.key_epoch = 1;
        bad_kind.kind = "archive".to_string();
        let b = bad_kind.signing_bytes();
        bad_kind.sig_old = sign_manifest(&old, &b).unwrap();
        bad_kind.sig_new = sign_manifest(&new.signing, &b).unwrap();
        assert!(!bad_kind.verify(), "non-rotation kind must fail");
    }

    #[test]
    fn rotation_round_trip_json() {
        let old = DeviceKeypair::generate().unwrap();
        let new = DeviceBundle::generate().unwrap();
        let prev = format!("b3:{}", "0".repeat(64));
        let rec =
            RotationRecord::create_signed(&old, 1, &new, 9, prev, "2026-08-05T12:00:00Z").unwrap();
        let json = serde_json::to_string(&rec).unwrap();
        let round: RotationRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(round, rec);
        assert!(round.verify());
    }
}
