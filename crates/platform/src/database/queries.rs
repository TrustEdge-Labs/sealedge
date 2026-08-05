//
// Copyright (c) 2025 TRUSTEDGE LABS LLC
// This source code is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Project: sealedge — Privacy and trust at the edge.
//

//! PostgreSQL CRUD operations for organizations, devices, verifications, and receipts.

use anyhow::Result;
use sqlx::{PgPool, Row};
use uuid::Uuid;

pub async fn create_connection_pool(database_url: &str) -> Result<PgPool> {
    let pool = PgPool::connect(database_url).await?;
    Ok(pool)
}

pub async fn run_migrations(pool: &PgPool) -> Result<()> {
    sqlx::migrate!("./migrations").run(pool).await?;
    Ok(())
}

pub async fn create_organization(pool: &PgPool, name: &str, plan: &str) -> Result<Uuid> {
    let row = sqlx::query("INSERT INTO organizations (name, plan) VALUES ($1, $2) RETURNING id")
        .bind(name)
        .bind(plan)
        .fetch_one(pool)
        .await?;
    Ok(row.get("id"))
}

pub async fn create_api_key(pool: &PgPool, org_id: Uuid, token_hash: &str) -> Result<Uuid> {
    let row = sqlx::query("INSERT INTO api_keys (org_id, token_hash) VALUES ($1, $2) RETURNING id")
        .bind(org_id)
        .bind(token_hash)
        .fetch_one(pool)
        .await?;
    Ok(row.get("id"))
}

pub async fn get_org_by_token_hash(pool: &PgPool, token_hash: &str) -> Result<Option<Uuid>> {
    let row = sqlx::query("SELECT org_id FROM api_keys WHERE token_hash = $1")
        .bind(token_hash)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| r.get("org_id")))
}

pub async fn create_device(
    pool: &PgPool,
    org_id: Uuid,
    device_id: &str,
    device_pub: &str,
    label: Option<&str>,
) -> Result<Uuid> {
    let row = sqlx::query(
        "INSERT INTO devices (org_id, device_id, device_pub, label) VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind(org_id)
    .bind(device_id)
    .bind(device_pub)
    .bind(label)
    .fetch_one(pool)
    .await?;
    Ok(row.get("id"))
}

/// Look up a device row and its registered public key by (org, device_id).
///
/// Returns `(id, device_pub)`. Used to bind a verification request's key to the
/// registered device key (C3 registry binding) — callers must fail closed when
/// this returns `None` or the stored key does not match the request.
pub async fn get_device_with_pub(
    pool: &PgPool,
    org_id: Uuid,
    device_id: &str,
) -> Result<Option<(Uuid, String)>> {
    let row =
        sqlx::query("SELECT id, device_pub FROM devices WHERE org_id = $1 AND device_id = $2")
            .bind(org_id)
            .bind(device_id)
            .fetch_optional(pool)
            .await?;
    Ok(row.map(|r| (r.get("id"), r.get("device_pub"))))
}

pub async fn create_verification(
    pool: &PgPool,
    org_id: Uuid,
    device_id: Option<Uuid>,
    manifest_digest: &str,
    result_json: &serde_json::Value,
) -> Result<Uuid> {
    let row = sqlx::query(
        "INSERT INTO verifications (org_id, device_id, manifest_digest, result_json) VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind(org_id)
    .bind(device_id)
    .bind(manifest_digest)
    .bind(result_json)
    .fetch_one(pool)
    .await?;
    Ok(row.get("id"))
}

pub async fn create_receipt(
    pool: &PgPool,
    verification_id: Uuid,
    jws: &str,
    kid: &str,
) -> Result<Uuid> {
    let row = sqlx::query(
        "INSERT INTO receipts (verification_id, jws, kid) VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(verification_id)
    .bind(jws)
    .bind(kid)
    .fetch_one(pool)
    .await?;
    Ok(row.get("id"))
}

pub async fn get_receipt(
    pool: &PgPool,
    org_id: Uuid,
    receipt_id: Uuid,
) -> Result<Option<(String, String)>> {
    let row = sqlx::query(
        r#"
        SELECT r.jws, r.kid
        FROM receipts r
        JOIN verifications v ON r.verification_id = v.id
        WHERE r.id = $1 AND v.org_id = $2
        "#,
    )
    .bind(receipt_id)
    .bind(org_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| (r.get("jws"), r.get("kid"))))
}

// ─── H1 device chronicle: witness registry binding + ledger ───────────────────

/// Look up a device by its signing public key (A2). Returns its row id when the
/// key is registered. Relies on the `devices_device_pub_uniq` index.
pub async fn get_device_by_pub(pool: &PgPool, device_pub: &str) -> Result<Option<Uuid>> {
    let row = sqlx::query("SELECT id FROM devices WHERE device_pub = $1")
        .bind(device_pub)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| r.get("id")))
}

/// Load a device's witness-ledger entries, ascending by sequence.
pub async fn witness_entries(
    pool: &PgPool,
    device_pub: &str,
) -> Result<Vec<crate::witness::WitnessEntry>> {
    let rows =
        sqlx::query("SELECT sequence, tip, observed_at FROM witness_log WHERE device_pub = $1 ORDER BY sequence")
            .bind(device_pub)
            .fetch_all(pool)
            .await?;
    Ok(rows
        .iter()
        .map(|r| {
            let sequence: i64 = r.get("sequence");
            crate::witness::WitnessEntry {
                sequence: sequence as u64,
                tip: r.get("tip"),
                observed_at: r.get("observed_at"),
            }
        })
        .collect())
}

/// Append a witness-ledger row. The `(device_pub, sequence)` primary key makes a
/// concurrent fork a hard conflict (surfaced to the caller as an error → 409).
#[allow(clippy::too_many_arguments)]
pub async fn witness_insert(
    pool: &PgPool,
    device_pub: &str,
    sequence: u64,
    tip: &str,
    observed_at: &str,
    device_registered: bool,
    signed_at: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO witness_log (device_pub, sequence, tip, observed_at, device_registered, signed_at) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(device_pub)
    .bind(sequence as i64)
    .bind(tip)
    .bind(observed_at)
    .bind(device_registered)
    .bind(signed_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// A single witnessed ledger entry for a device at an exact sequence, if present.
pub async fn witness_entry_at(
    pool: &PgPool,
    device_pub: &str,
    sequence: u64,
) -> Result<Option<crate::witness::WitnessEntry>> {
    let row = sqlx::query(
        "SELECT sequence, tip, observed_at FROM witness_log WHERE device_pub = $1 AND sequence = $2",
    )
    .bind(device_pub)
    .bind(sequence as i64)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| {
        let seq: i64 = r.get("sequence");
        crate::witness::WitnessEntry {
            sequence: seq as u64,
            tip: r.get("tip"),
            observed_at: r.get("observed_at"),
        }
    }))
}

// ─── H1 Phase 2: revocation & rotation lineage ────────────────────────────────

/// Load a device's revocation state by signing key (A2). Returns `(id, state)`
/// when the key is registered. Used by `/v1/witness` (revoked gate) and
/// `/v1/verify` (min_epoch enforcement + annotation).
pub async fn get_device_revocation_by_pub(
    pool: &PgPool,
    device_pub: &str,
) -> Result<Option<(Uuid, crate::revocation::RevocationState)>> {
    let row = sqlx::query("SELECT id, revoked_at, min_epoch FROM devices WHERE device_pub = $1")
        .bind(device_pub)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| {
        let min_epoch: Option<i32> = r.get("min_epoch");
        (
            r.get("id"),
            crate::revocation::RevocationState {
                revoked_at: r.get("revoked_at"),
                min_epoch: min_epoch.map(|e| e as u32),
            },
        )
    }))
}

/// Load a device's revocation state by (org, device UUID) for the revoke
/// endpoint — tenant-scoped so an org may only revoke its own device. Returns
/// `(device_pub, state)`.
pub async fn get_device_revocation(
    pool: &PgPool,
    org_id: Uuid,
    id: Uuid,
) -> Result<Option<(String, crate::revocation::RevocationState)>> {
    let row = sqlx::query(
        "SELECT device_pub, revoked_at, min_epoch FROM devices WHERE id = $1 AND org_id = $2",
    )
    .bind(id)
    .bind(org_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| {
        let min_epoch: Option<i32> = r.get("min_epoch");
        (
            r.get("device_pub"),
            crate::revocation::RevocationState {
                revoked_at: r.get("revoked_at"),
                min_epoch: min_epoch.map(|e| e as u32),
            },
        )
    }))
}

/// Apply revocation columns to a device row (tenant-scoped). Returns whether a
/// row was updated (false ⇒ no such device in this org). Monotonicity is decided
/// by `revocation::decide_revoke` before this is called.
pub async fn set_device_revocation(
    pool: &PgPool,
    org_id: Uuid,
    id: Uuid,
    revoked_at: &str,
    min_epoch: Option<u32>,
) -> Result<bool> {
    let result = sqlx::query(
        "UPDATE devices SET revoked_at = $1, min_epoch = $2, status = 'revoked' \
         WHERE id = $3 AND org_id = $4",
    )
    .bind(revoked_at)
    .bind(min_epoch.map(|e| e as i32))
    .bind(id)
    .bind(org_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// The sequence at which `old_pub` rotated away, if it has been superseded (PA2).
pub async fn lineage_rotation_seq(pool: &PgPool, old_pub: &str) -> Result<Option<u64>> {
    let row = sqlx::query("SELECT rotation_seq FROM device_lineage WHERE old_pub = $1")
        .bind(old_pub)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| {
        let seq: i64 = r.get("rotation_seq");
        seq as u64
    }))
}

/// Record a verified rotation lineage `old_pub → new_pub @ rotation_seq` (PA1).
/// Idempotent on `new_pub` (a new key continues exactly one prior identity), so a
/// replayed rotation witness does not error.
pub async fn lineage_insert(
    pool: &PgPool,
    new_pub: &str,
    old_pub: &str,
    rotation_seq: u64,
    observed_at: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO device_lineage (new_pub, old_pub, rotation_seq, observed_at) \
         VALUES ($1, $2, $3, $4) ON CONFLICT (new_pub) DO NOTHING",
    )
    .bind(new_pub)
    .bind(old_pub)
    .bind(rotation_seq as i64)
    .bind(observed_at)
    .execute(pool)
    .await?;
    Ok(())
}
