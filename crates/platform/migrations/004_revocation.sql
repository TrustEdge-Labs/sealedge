-- Copyright (c) 2025 TRUSTEDGE LABS LLC
-- MPL-2.0: https://mozilla.org/MPL/2.0/
-- Project: sealedge — Privacy and trust at the edge.
--
-- H1 Phase 2: device revocation & rotation lineage.
--
-- Revocation is a registry fact (org-admin scoped). Its teeth come from the H1
-- witness timestamps: a verifier trusts an archive under a revoked key only if it
-- was witnessed before `revoked_at`. `min_epoch` fails closed on downgraded or
-- retired key epochs. Both columns are enforced monotonic in the service layer
-- (revoked_at earlier-only/never-cleared; min_epoch non-decreasing) — see the
-- `revocation` module.

ALTER TABLE devices ADD COLUMN IF NOT EXISTS revoked_at TEXT;   -- RFC 3339; NULL = active
ALTER TABLE devices ADD COLUMN IF NOT EXISTS min_epoch  INTEGER; -- reject key_epoch < this

-- Rotation lineage: old_pub -> new_pub at the rotation's sequence. Populated when
-- a device witnesses a rotation tip under its new key and the platform verifies
-- the rotation entry's co-signatures (PA1). One row per new key (a new key
-- continues exactly one prior identity). Also closes the old key's witness ledger
-- beyond `rotation_seq` (PA2, enforced in the service layer).
CREATE TABLE IF NOT EXISTS device_lineage (
    new_pub      TEXT   NOT NULL,
    old_pub      TEXT   NOT NULL,
    rotation_seq BIGINT NOT NULL,
    observed_at  TEXT   NOT NULL,   -- trusted timestamp the lineage was recorded
    PRIMARY KEY (new_pub)
);

-- Look up "is this old key superseded, and at what sequence?" (PA2) by old_pub.
CREATE INDEX IF NOT EXISTS device_lineage_old_pub ON device_lineage (old_pub);
