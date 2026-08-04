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
