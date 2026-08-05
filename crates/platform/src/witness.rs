//
// Copyright (c) 2025 TRUSTEDGE LABS LLC
// This source code is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Project: sealedge — Privacy and trust at the edge.
//

//! Device-chronicle witness (H1c): the append-only, monotonic per-device
//! ledger decision logic and the witness-receipt body.
//!
//! The [`decide`] function is the security-critical heart of the witness: it is
//! **pure** (no clock, no DB, no I/O) so it can be exhaustively unit-tested. The
//! postgres-backed HTTP handler loads the device's existing entries, calls
//! `decide`, and — only on [`WitnessDecision::Record`] — inserts the new row and
//! issues a signed receipt. See `docs/designs/h1-device-chronicle.md` §7.

use serde::{Deserialize, Serialize};

/// One previously-witnessed ledger entry for a device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessEntry {
    pub sequence: u64,
    pub tip: String,
    /// Trusted timestamp the platform recorded when it first witnessed this tip.
    pub observed_at: String,
}

/// The outcome of attempting to witness a `(sequence, tip)` for a device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessDecision {
    /// New, strictly-higher sequence — insert it. `prev` is the current head
    /// (highest sequence below this one), if any.
    Record { prev: Option<WitnessEntry> },
    /// Exact `(sequence, tip)` already witnessed — idempotent replay. Re-issue a
    /// receipt bearing the ORIGINAL `observed_at`.
    Replay {
        existing: WitnessEntry,
        prev: Option<WitnessEntry>,
    },
    /// Same sequence, different tip — equivocation / fork. Reject (409).
    Fork { existing_tip: String },
    /// Sequence at or below the current max but not an exact replay — a rollback
    /// / attempt to rewrite history. Reject (409).
    Rollback { max_sequence: u64 },
}

/// Decide how to witness `(sequence, tip)` against a device's existing ledger
/// entries. Pure and total: no clock, no I/O.
///
/// Monotonic append-only semantics:
/// - a strictly-higher sequence than any seen (gaps allowed) is **recorded**;
/// - an exact `(sequence, tip)` repeat is an idempotent **replay**;
/// - the same sequence with a different tip is a **fork**;
/// - any other sequence at or below the max is a **rollback**.
pub fn decide(existing: &[WitnessEntry], sequence: u64, tip: &str) -> WitnessDecision {
    if let Some(same) = existing.iter().find(|e| e.sequence == sequence) {
        if same.tip == tip {
            return WitnessDecision::Replay {
                existing: same.clone(),
                prev: prev_entry(existing, sequence),
            };
        }
        return WitnessDecision::Fork {
            existing_tip: same.tip.clone(),
        };
    }

    if let Some(max) = existing.iter().map(|e| e.sequence).max() {
        if sequence <= max {
            return WitnessDecision::Rollback { max_sequence: max };
        }
    }

    WitnessDecision::Record {
        prev: prev_entry(existing, sequence),
    }
}

/// The highest-sequence entry strictly below `sequence` (the chronicle head this
/// observation follows), if any.
fn prev_entry(existing: &[WitnessEntry], sequence: u64) -> Option<WitnessEntry> {
    existing
        .iter()
        .filter(|e| e.sequence < sequence)
        .max_by_key(|e| e.sequence)
        .cloned()
}

/// The witness-receipt body (design §7.3). Wrapped in a JWS by
/// `verify::signing::sign_witness_jws` and signed by the platform's JWKS key.
/// Deliberately non-expiring — a witnessed timestamp is a permanent fact (A4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessReceipt {
    pub device_pub: String,
    /// True iff the device's signing key is bound in the platform registry.
    pub device_registered: bool,
    pub sequence: u64,
    pub tip: String,
    /// Trusted timestamp: the archive existed at or before this instant.
    pub observed_at: String,
    /// The previously-witnessed entry (NOT necessarily `sequence - 1`; gaps are
    /// allowed) — lets a client chain receipts without querying the ledger (A6).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_sequence: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_tip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_observed_at: Option<String>,
    /// Unique receipt id.
    pub jti: String,
}

impl WitnessReceipt {
    /// Assemble a receipt body. `observed_at` is the trusted timestamp (for a
    /// replay, pass the original entry's `observed_at`); `prev` is the preceding
    /// ledger entry from the [`WitnessDecision`].
    pub fn build(
        device_pub: &str,
        device_registered: bool,
        sequence: u64,
        tip: &str,
        observed_at: String,
        prev: Option<&WitnessEntry>,
        jti: String,
    ) -> Self {
        Self {
            device_pub: device_pub.to_string(),
            device_registered,
            sequence,
            tip: tip.to_string(),
            observed_at,
            prev_sequence: prev.map(|p| p.sequence),
            prev_tip: prev.map(|p| p.tip.clone()),
            prev_observed_at: prev.map(|p| p.observed_at.clone()),
            jti,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(seq: u64, tip: &str) -> WitnessEntry {
        WitnessEntry {
            sequence: seq,
            tip: tip.to_string(),
            observed_at: format!("2026-08-05T00:0{seq}:00Z"),
        }
    }

    #[test]
    fn genesis_is_recorded_with_no_prev() {
        assert_eq!(
            decide(&[], 0, "b3:aaa"),
            WitnessDecision::Record { prev: None }
        );
    }

    #[test]
    fn higher_sequence_records_with_prev_head() {
        let existing = vec![entry(0, "b3:aaa")];
        assert_eq!(
            decide(&existing, 1, "b3:bbb"),
            WitnessDecision::Record {
                prev: Some(entry(0, "b3:aaa"))
            }
        );
    }

    #[test]
    fn gaps_are_allowed() {
        let existing = vec![entry(0, "b3:aaa")];
        // Jump straight to 5 — prev is the current head (0).
        assert_eq!(
            decide(&existing, 5, "b3:ccc"),
            WitnessDecision::Record {
                prev: Some(entry(0, "b3:aaa"))
            }
        );
    }

    #[test]
    fn exact_repeat_is_idempotent_replay() {
        let existing = vec![entry(0, "b3:aaa"), entry(1, "b3:bbb")];
        assert_eq!(
            decide(&existing, 1, "b3:bbb"),
            WitnessDecision::Replay {
                existing: entry(1, "b3:bbb"),
                prev: Some(entry(0, "b3:aaa")),
            }
        );
    }

    #[test]
    fn same_sequence_different_tip_is_fork() {
        let existing = vec![entry(0, "b3:aaa"), entry(1, "b3:bbb")];
        assert_eq!(
            decide(&existing, 1, "b3:EVIL"),
            WitnessDecision::Fork {
                existing_tip: "b3:bbb".to_string()
            }
        );
    }

    #[test]
    fn backfilling_a_gap_below_max_is_rollback() {
        // Ledger has 0 and 2 (a gap at 1). Trying to insert 1 later is a rollback
        // — history is append-only above the max, never backfilled.
        let existing = vec![entry(0, "b3:aaa"), entry(2, "b3:ccc")];
        assert_eq!(
            decide(&existing, 1, "b3:bbb"),
            WitnessDecision::Rollback { max_sequence: 2 }
        );
    }

    #[test]
    fn prev_is_highest_below_sequence() {
        let existing = vec![entry(0, "b3:aaa"), entry(2, "b3:ccc"), entry(5, "b3:eee")];
        assert_eq!(
            decide(&existing, 6, "b3:fff"),
            WitnessDecision::Record {
                prev: Some(entry(5, "b3:eee"))
            }
        );
    }

    #[test]
    fn receipt_build_populates_prev() {
        let prev = entry(4, "b3:ddd");
        let r = WitnessReceipt::build(
            "ed25519:dev",
            true,
            5,
            "b3:eee",
            "2026-08-05T00:05:00Z".to_string(),
            Some(&prev),
            "jti-1".to_string(),
        );
        assert_eq!(r.sequence, 5);
        assert_eq!(r.prev_sequence, Some(4));
        assert_eq!(r.prev_tip.as_deref(), Some("b3:ddd"));
        assert_eq!(
            r.prev_observed_at.as_deref(),
            Some(prev.observed_at.as_str())
        );
    }
}
