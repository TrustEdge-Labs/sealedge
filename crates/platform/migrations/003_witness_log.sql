-- Copyright (c) 2025 TRUSTEDGE LABS LLC
-- MPL-2.0: https://mozilla.org/MPL/2.0/
-- Project: sealedge — Privacy and trust at the edge.
--
-- H1 device chronicle: append-only, monotonic per-device witness ledger.
-- One (device_pub, sequence) row per witnessed chronicle tip. The primary key
-- makes a fork attempt (same sequence, different tip) a hard PK conflict, and
-- ORDER BY sequence lets the service enforce monotonicity in the decision layer.
-- Timestamps are stored as RFC 3339 TEXT so a replay re-issues the identical
-- observed_at that was originally witnessed.

CREATE TABLE IF NOT EXISTS witness_log (
    device_pub        TEXT    NOT NULL,
    sequence          BIGINT  NOT NULL,
    tip               TEXT    NOT NULL,
    observed_at       TEXT    NOT NULL,   -- trusted timestamp (platform clock)
    device_registered BOOLEAN NOT NULL,
    signed_at         TEXT,               -- device-asserted, diagnostic-only (N5)
    PRIMARY KEY (device_pub, sequence)
);

-- Witness registry binding is by public key (A2): the request carries no
-- device_id. That requires signing keys to be unique across orgs.
CREATE UNIQUE INDEX IF NOT EXISTS devices_device_pub_uniq ON devices (device_pub);
