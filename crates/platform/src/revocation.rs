//
// Copyright (c) 2025 TRUSTEDGE LABS LLC
// This source code is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Project: sealedge — Privacy and trust at the edge.
//

//! Device revocation & rotation-lineage enforcement (H1 Phase 2).
//!
//! Like [`crate::witness::decide`], every function here is **pure** — no clock,
//! no DB, no I/O — so the security-critical rules can be exhaustively unit-tested
//! and run in CI (which does not build the postgres feature). The postgres/HTTP
//! handlers load state, call these, and act on the result. See
//! `docs/designs/h1-phase2-rotation-revocation.md` §5.

use chrono::DateTime;
use sealedge_core::RotationRecord;

use crate::witness::WitnessDecision;

/// A device's current revocation columns.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RevocationState {
    /// RFC 3339 instant the key is considered revoked from; `None` = active.
    pub revoked_at: Option<String>,
    /// Reject archives whose `key_epoch` is below this; `None` = no floor.
    pub min_epoch: Option<u32>,
}

/// Outcome of an org-admin revoke request (PA4 — monotonic-only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevokeOutcome {
    /// Apply these (already-validated) values to the device row.
    Apply {
        revoked_at: String,
        min_epoch: Option<u32>,
    },
    /// Reject the request (monotonicity violation / malformed timestamp).
    Reject(String),
}

/// Decide the effect of a revoke request against the device's current state.
///
/// **PA4 — monotonic-only.** `revoked_at` may be set, and moved *earlier*
/// (compromise discovered to predate the first estimate), but never moved later
/// and never cleared. `min_epoch` is strictly non-decreasing. This closes the
/// laundering hole where an admin could retroactively bless a post-compromise
/// forgery by pushing `revoked_at` later or clearing it.
pub fn decide_revoke(
    current: &RevocationState,
    req_revoked_at: Option<&str>,
    req_min_epoch: Option<u32>,
    now: &str,
) -> RevokeOutcome {
    // Resolve the new revoked_at under the earlier-only / never-cleared rule.
    let new_revoked_at = match (current.revoked_at.as_deref(), req_revoked_at) {
        // First revoke: default to now, or take the (valid) explicit instant.
        (None, None) => now.to_string(),
        (None, Some(r)) => {
            if parse(r).is_none() {
                return RevokeOutcome::Reject(format!("malformed revoked_at: {r}"));
            }
            r.to_string()
        }
        // Already revoked, no new instant supplied: keep it (never push later).
        (Some(c), None) => c.to_string(),
        // Already revoked, new instant supplied: must be earlier-or-equal.
        (Some(c), Some(r)) => match (parse(c), parse(r)) {
            (Some(cd), Some(rd)) if rd <= cd => r.to_string(),
            (Some(_), Some(_)) => {
                return RevokeOutcome::Reject(
                    "revoked_at may only move earlier, never later".to_string(),
                );
            }
            _ => return RevokeOutcome::Reject(format!("malformed revoked_at: {r}")),
        },
    };

    // min_epoch is strictly non-decreasing; omitting it keeps the current floor.
    let new_min_epoch = match (current.min_epoch, req_min_epoch) {
        (cur, None) => cur,
        (None, Some(r)) => Some(r),
        (Some(c), Some(r)) if r >= c => Some(r),
        (Some(c), Some(r)) => {
            return RevokeOutcome::Reject(format!(
                "min_epoch must be non-decreasing (current {c}, got {r})"
            ));
        }
    };

    RevokeOutcome::Apply {
        revoked_at: new_revoked_at,
        min_epoch: new_min_epoch,
    }
}

/// True iff a device is revoked (has a `revoked_at`).
pub fn is_revoked(state: &RevocationState) -> bool {
    state.revoked_at.is_some()
}

/// Whether an archive at `archive_epoch` clears the device's `min_epoch` floor.
/// Used by `/v1/verify` to fail closed on downgraded/retired epochs.
pub fn epoch_allowed(min_epoch: Option<u32>, archive_epoch: u32) -> bool {
    match min_epoch {
        Some(floor) => archive_epoch >= floor,
        None => true,
    }
}

/// **PA5** — a revoked device is refused a *new* witness, but already-witnessed
/// entries still replay (past facts stay retrievable). The gate is on device
/// *state*, not tip time (a witness request carries no trusted time).
pub fn refuse_revoked_witness(revoked: bool, decision: &WitnessDecision) -> bool {
    revoked && matches!(decision, WitnessDecision::Record { .. })
}

/// **PA2** — once lineage records `old_pub → new_pub @ rotation_seq`, the old
/// key's ledger is closed: a *new* tip beyond the rotation is refused
/// ("superseded"), so a stolen old key cannot fork a second co-signed timeline.
/// Replays and entries at or below `rotation_seq` still succeed.
///
/// `rotation_seq` is the sequence at which `device_pub` rotated away (from the
/// `device_lineage` table), or `None` if the key has not been superseded.
pub fn refuse_superseded(
    rotation_seq: Option<u64>,
    sequence: u64,
    decision: &WitnessDecision,
) -> bool {
    match rotation_seq {
        Some(rseq) => sequence > rseq && matches!(decision, WitnessDecision::Record { .. }),
        None => false,
    }
}

/// Result of verifying a rotation entry attached to a witness request (PA1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineageCheck {
    /// The rotation is valid and bound to the request; record this lineage.
    Ok { old_pub: String, rotation_seq: u64 },
    /// Reject with this reason.
    Reject(String),
}

/// **PA1** — verify a rotation entry carried on a witness request before the
/// platform records lineage. Checks (i) both co-signatures + the `+1` epoch bump
/// (via [`RotationRecord::verify`]), (ii) `new.public_key == request.device_pub`
/// (the requester controls the new key it claims), and (iii) the rotation is the
/// witnessed tip (`sequence` and `tip == archive_digest(rotation)`).
///
/// The defense-in-depth check (iv) — that `old.public_key`'s known witnessed
/// chain ends at `rotation.prev_archive_hash` — needs the ledger and is done by
/// the handler; this pure part covers everything decidable from the record alone.
pub fn verify_lineage_rotation(
    rec: &RotationRecord,
    req_device_pub: &str,
    req_sequence: u64,
    req_tip: &str,
) -> LineageCheck {
    if !rec.verify() {
        return LineageCheck::Reject("rotation co-signature/epoch verification failed".to_string());
    }
    if rec.new.public_key != req_device_pub {
        return LineageCheck::Reject(
            "rotation new.public_key does not match the request device_pub".to_string(),
        );
    }
    if rec.sequence != req_sequence {
        return LineageCheck::Reject(format!(
            "rotation sequence {} does not match request sequence {req_sequence}",
            rec.sequence
        ));
    }
    let digest = sealedge_core::format_archive_id(&rec.archive_digest());
    if digest != req_tip {
        return LineageCheck::Reject(
            "rotation digest does not match the witnessed tip".to_string(),
        );
    }
    LineageCheck::Ok {
        old_pub: rec.old.public_key.clone(),
        rotation_seq: rec.sequence,
    }
}

/// Parse an RFC 3339 timestamp for comparison; `None` if malformed. Kept private
/// so callers deal only in strings.
fn parse(s: &str) -> Option<DateTime<chrono::FixedOffset>> {
    DateTime::parse_from_rfc3339(s).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sealedge_core::{DeviceBundle, DeviceKeypair};

    fn state(revoked_at: Option<&str>, min_epoch: Option<u32>) -> RevocationState {
        RevocationState {
            revoked_at: revoked_at.map(|s| s.to_string()),
            min_epoch,
        }
    }

    // ── PA4: revoke monotonicity ──

    #[test]
    fn first_revoke_defaults_to_now() {
        let out = decide_revoke(&state(None, None), None, None, "2026-08-05T00:00:00Z");
        assert_eq!(
            out,
            RevokeOutcome::Apply {
                revoked_at: "2026-08-05T00:00:00Z".to_string(),
                min_epoch: None
            }
        );
    }

    #[test]
    fn first_revoke_accepts_explicit_instant() {
        let out = decide_revoke(
            &state(None, None),
            Some("2026-08-01T00:00:00Z"),
            Some(2),
            "2026-08-05T00:00:00Z",
        );
        assert_eq!(
            out,
            RevokeOutcome::Apply {
                revoked_at: "2026-08-01T00:00:00Z".to_string(),
                min_epoch: Some(2)
            }
        );
    }

    #[test]
    fn revoked_at_may_move_earlier() {
        let out = decide_revoke(
            &state(Some("2026-08-05T00:00:00Z"), None),
            Some("2026-08-01T00:00:00Z"),
            None,
            "2026-08-09T00:00:00Z",
        );
        assert_eq!(
            out,
            RevokeOutcome::Apply {
                revoked_at: "2026-08-01T00:00:00Z".to_string(),
                min_epoch: None
            }
        );
    }

    #[test]
    fn revoked_at_may_not_move_later() {
        let out = decide_revoke(
            &state(Some("2026-08-01T00:00:00Z"), None),
            Some("2026-08-09T00:00:00Z"),
            None,
            "2026-08-09T00:00:00Z",
        );
        assert!(matches!(out, RevokeOutcome::Reject(_)), "later is rejected");
    }

    #[test]
    fn omitting_revoked_at_keeps_existing_never_pushes_to_now() {
        // Already revoked earlier; a bare re-revoke must NOT bump it to `now`.
        let out = decide_revoke(
            &state(Some("2026-08-01T00:00:00Z"), None),
            None,
            Some(3),
            "2026-08-09T00:00:00Z",
        );
        assert_eq!(
            out,
            RevokeOutcome::Apply {
                revoked_at: "2026-08-01T00:00:00Z".to_string(),
                min_epoch: Some(3)
            }
        );
    }

    #[test]
    fn min_epoch_must_not_decrease() {
        let out = decide_revoke(
            &state(Some("2026-08-01T00:00:00Z"), Some(5)),
            None,
            Some(4),
            "2026-08-09T00:00:00Z",
        );
        assert!(matches!(out, RevokeOutcome::Reject(_)));
    }

    #[test]
    fn min_epoch_may_increase_or_stay() {
        let out = decide_revoke(
            &state(Some("2026-08-01T00:00:00Z"), Some(5)),
            None,
            Some(7),
            "2026-08-09T00:00:00Z",
        );
        assert_eq!(
            out,
            RevokeOutcome::Apply {
                revoked_at: "2026-08-01T00:00:00Z".to_string(),
                min_epoch: Some(7)
            }
        );
    }

    #[test]
    fn malformed_timestamp_rejected() {
        let out = decide_revoke(
            &state(None, None),
            Some("not-a-date"),
            None,
            "2026-08-05T00:00:00Z",
        );
        assert!(matches!(out, RevokeOutcome::Reject(_)));
    }

    #[test]
    fn earlier_comparison_handles_offsets() {
        // 2026-08-05T00:00:00+02:00 == 2026-08-04T22:00:00Z, which is earlier than
        // the current 2026-08-04T23:00:00Z, so it must be accepted.
        let out = decide_revoke(
            &state(Some("2026-08-04T23:00:00Z"), None),
            Some("2026-08-05T00:00:00+02:00"),
            None,
            "2026-08-09T00:00:00Z",
        );
        assert!(
            matches!(out, RevokeOutcome::Apply { .. }),
            "offset-aware compare"
        );
    }

    // ── min_epoch gate ──

    #[test]
    fn epoch_gate() {
        assert!(epoch_allowed(None, 0));
        assert!(epoch_allowed(Some(2), 2));
        assert!(epoch_allowed(Some(2), 3));
        assert!(!epoch_allowed(Some(2), 1));
    }

    // ── PA5: revoked witness gate ──

    #[test]
    fn revoked_refuses_new_tip_but_allows_replay() {
        let record = WitnessDecision::Record { prev: None };
        let replay = WitnessDecision::Replay {
            existing: crate::witness::WitnessEntry {
                sequence: 1,
                tip: "b3:x".to_string(),
                observed_at: "t".to_string(),
            },
            prev: None,
        };
        assert!(refuse_revoked_witness(true, &record), "new tip refused");
        assert!(!refuse_revoked_witness(true, &replay), "replay allowed");
        assert!(
            !refuse_revoked_witness(false, &record),
            "active device fine"
        );
    }

    // ── PA2: superseded-ledger gate ──

    #[test]
    fn superseded_refuses_new_tip_beyond_rotation() {
        let record = WitnessDecision::Record { prev: None };
        // Superseded at seq 3: a new tip at 4 is refused, at 3 or below is allowed.
        assert!(refuse_superseded(Some(3), 4, &record));
        assert!(!refuse_superseded(Some(3), 3, &record));
        assert!(!refuse_superseded(Some(3), 2, &record));
        // Not superseded: never refused.
        assert!(!refuse_superseded(None, 99, &record));
        // Replays of already-witnessed entries are never refused.
        let replay = WitnessDecision::Replay {
            existing: crate::witness::WitnessEntry {
                sequence: 5,
                tip: "b3:x".to_string(),
                observed_at: "t".to_string(),
            },
            prev: None,
        };
        assert!(!refuse_superseded(Some(3), 5, &replay));
    }

    // ── PA1: lineage rotation verification ──

    fn signed_rotation() -> (RotationRecord, DeviceBundle) {
        let old = DeviceKeypair::generate().unwrap();
        let new = DeviceBundle::generate().unwrap();
        let rec = RotationRecord::create_signed(
            &old,
            0,
            &new,
            7,
            format!("b3:{}", "a".repeat(64)),
            "2026-08-05T12:00:00Z",
        )
        .unwrap();
        (rec, new)
    }

    #[test]
    fn lineage_accepts_bound_rotation() {
        let (rec, _new) = signed_rotation();
        let tip = sealedge_core::format_archive_id(&rec.archive_digest());
        let out = verify_lineage_rotation(&rec, &rec.new.public_key.clone(), 7, &tip);
        assert_eq!(
            out,
            LineageCheck::Ok {
                old_pub: rec.old.public_key.clone(),
                rotation_seq: 7
            }
        );
    }

    #[test]
    fn lineage_rejects_wrong_device_pub() {
        let (rec, _new) = signed_rotation();
        let tip = sealedge_core::format_archive_id(&rec.archive_digest());
        let out = verify_lineage_rotation(&rec, "ed25519:someone-else", 7, &tip);
        assert!(matches!(out, LineageCheck::Reject(_)));
    }

    #[test]
    fn lineage_rejects_wrong_sequence_or_tip() {
        let (rec, _new) = signed_rotation();
        let tip = sealedge_core::format_archive_id(&rec.archive_digest());
        assert!(matches!(
            verify_lineage_rotation(&rec, &rec.new.public_key, 8, &tip),
            LineageCheck::Reject(_)
        ));
        assert!(matches!(
            verify_lineage_rotation(&rec, &rec.new.public_key, 7, "b3:wrong"),
            LineageCheck::Reject(_)
        ));
    }

    #[test]
    fn lineage_rejects_forged_cosignature() {
        let (mut rec, _new) = signed_rotation();
        let tip = sealedge_core::format_archive_id(&rec.archive_digest());
        rec.sig_new = format!("ed25519:{}", "A".repeat(86));
        // Tip is computed over signing bytes (excludes sigs), so it's unchanged;
        // the co-signature check is what fails.
        assert!(matches!(
            verify_lineage_rotation(&rec, &rec.new.public_key, 7, &tip),
            LineageCheck::Reject(_)
        ));
    }
}
