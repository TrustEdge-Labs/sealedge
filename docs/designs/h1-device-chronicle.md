<!--
Copyright (c) 2025 TRUSTEDGE LABS LLC
This source code is subject to the terms of the Mozilla Public License, v. 2.0.
If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

Project: sealedge — Privacy and trust at the edge.
-->

# H1 — Device chronicle (cross-archive continuity) + witness receipts

Status: **APPROVED (amendments A1–A6, nits N1–N5) — H1.1–H1.5 IMPLEMENTED.**
Chronicle linkage, `verify-chronicle`, the platform witness endpoint, and the
`seal witness` / `--witness` cross-check have shipped. Key rotation / revocation /
key-epoch (§8; C4 §12 "Phase 2") remain designed-only for a following phase.

> **Implementation note (A4 reconciliation):** the witness receipt JWS omits
> `aud` to match the existing verification receipts (which carry no `aud`), rather
> than introducing `JWT_AUDIENCE` on only one receipt type. Everything else in
> §7.3 shipped as written.

Related: [C4 content-encryption redesign](c4-content-encryption-redesign.md)
(§12 reserved these mechanisms). Trust-model lineage: C1 (canonical signing),
C2 (real continuity), C3 (honest public verifier + registry binding), C4
(key separation + content encryption).

---

## 0. Decisions locked (from scoping)

| Decision | Choice | Rationale |
|---|---|---|
| **Format** | Additive-optional in `trst_version` 0.2.0 | Chronicle fields are inherently optional (a standalone archive is legitimate), so a version bump wouldn't make them mandatory; it would only re-break the C4 golden vectors for no gain (solo builder, no deployed archives). Same optional-field pattern C4 used: absent ⇒ canonical bytes byte-identical. |
| **Chaining UX** | Chronicle state file + explicit override | `seal wrap --chronicle device.chronicle` auto-advances the device's head; `--prev-archive` / `--prev-hash`+`--prev-seq` seed the first link or drive CI. |
| **Witness (H1c)** | MVP: monotonic per-device ledger + JWS witness receipt | Verifies a device-signed tip, enforces append-only monotonicity, stamps a trusted timestamp, returns a JWS signed by the existing JWKS key. Merkle tree / inclusion proofs / gossip explicitly deferred. |
| **Rotation/revocation/epoch** | Design together, implement H1 first | One coherent "device's story over time" narrative; H1 (a/b/c) ships first and stays reviewable + CI-green. |

---

## 1. The gap H1 closes

Today each `.seal` archive is an **island**. `prev_archive_hash` is a signed
manifest field (C1) but is **always `null`** — `wrap` never populates it. As a
result:

- **Wholesale deletion** of a device's archives is invisible: nothing records
  that archive #7 ever existed, so dropping it (or the whole tail) leaves no
  trace.
- **Reordering** archives is invisible: there is no ordering a verifier can check.
- **Timestamps are self-asserted:** `metadata.started_at` is whatever the device
  wrote. Nothing independent answers *"when did this actually exist?"*

H1 turns a device's archives into a **chronicle**: a per-device, append-only,
hash-linked, sequence-numbered chain, plus an optional platform **witness** that
co-signs the chain tip with a **trusted timestamp**. The witness is the cheap
substitute for a full transparency log — enough to answer "when did this exist?"
and to make deletion / reordering / history-rewriting detectable.

**Non-goals (this pass):** Merkle transparency log, inclusion/consistency
proofs, cross-client equivocation resistance (gossip), and the actual key
rotation/revocation *mechanisms* (designed in §8, built later).

---

## 2. Concepts & vocabulary

- **Archive digest** — `archive_digest(m) = BLAKE3(m.to_canonical_bytes())`,
  formatted `b3:<hex>`. Hashes the **signed content** (canonical bytes exclude
  the signature; Ed25519 is deterministic, so re-signing identical content is a
  no-op). This is the stable identifier of an archive.
- **Chronicle** — the linear chain of a single device's archives, ordered by
  `sequence`, each linking to the previous via `prev_archive_hash`.
- **Sequence** — `sequence: u64`, monotonic per device, starting at `0`
  (genesis). Genesis has no predecessor.
- **Chronicle tip** — `(sequence, archive_digest)` of the most recent archive.
  **Distinct from the existing `chain_tip`**, which is the *intra-archive*
  continuity hash (last segment). We never overload that name; the cross-archive
  head is the *chronicle tip*.
- **Witness receipt** — a platform-signed JWS asserting "at `observed_at` I saw
  device X at `(sequence, tip)`, consistent with my append-only record."

---

## 3. Manifest changes (additive, `trst_version` stays `0.2.0`)

`crates/seal-protocols/src/archive/manifest.rs`.

Add one field now; reserve one for Phase 2:

```rust
pub struct TrstManifest {
    // ... existing fields ...
    pub claims: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<EncryptionBlock>,
    // NEW (H1): monotonic per-device chronicle position. Present ⇒ this archive
    // is part of a chronicle. seq 0 = genesis (prev_archive_hash absent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_archive_hash: Option<String>, // now POPULATED; "b3:<hex>" of prev archive_digest
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}
```

`DeviceInfo` reserves the Phase-2 epoch slot (see §8; **not populated in H1**):

```rust
pub struct DeviceInfo {
    // ... id, model, firmware_version, public_key ...
    pub key_agreement_public: Option<String>,
    // RESERVED (Phase 2): device key epoch; None/absent in H1.
    // pub key_epoch: Option<u32>,   // added when rotation lands
}
```

### 3.1 Canonical order (`serialize_canonical`)

Insert `sequence` between `encryption` and `prev_archive_hash`; both emitted
only when present. Everything else unchanged, so **non-chronicle archives
canonicalize byte-for-byte as they do today** (C4 golden vectors hold):

```
trst_version, profile, device{...}, metadata{...}, chunk{...},
segments[...], claims[...],
[encryption{...}]?,        # C4, when present
[sequence]?,               # H1, when present  (number, no quotes)
[prev_archive_hash]?,      # H1, when present  ("b3:<hex>")
# signature excluded
```

### 3.2 Validation rules (`validate()`)

- `sequence` absent ⇒ `prev_archive_hash` must be absent (standalone archive).
- `sequence == 0` ⇒ `prev_archive_hash` must be **absent** (genesis).
- `sequence > 0` ⇒ `prev_archive_hash` must be **present** and match `b3:<64-hex>`.
- `prev_archive_hash` present ⇒ `sequence` must be present and `> 0`.

These are *well-formedness* checks on a single manifest; cross-archive linkage
(that `prev_archive_hash` equals the real predecessor's digest) is checked by
`verify-chronicle` (§6), which requires more than one archive.

> **N1 (ride-along in H1.1):** `TrstManifest::new()` / `new_cam_video()` (and the
> other constructors) still default `trst_version: "0.1.0"` — a stale pre-C4
> crumb and a latent trap. Fix to `"0.2.0"` while touching this file.

### 3.3 Old-verifier interaction (A1)

A **pre-H1 0.2.0 verifier** has no `sequence` field. On parse it silently drops
the unknown field (there is no `deny_unknown_fields`), re-serializes canonical
bytes *without* it, and the Ed25519 check therefore **fails closed** with a
"signature invalid" (exit 10). This is the confusing-signature-error hazard C4
§10.1 flagged, in reverse: safe (never silent acceptance) but opaque. The
additive-0.2.0 decision stands **because no external parties are on old
verifiers**. If that ever changes, the calculus flips to a `0.3.0` bump —
`require_supported_version` runs *before* the signature check
(`seal-cli/src/main.rs:1097`), so a version gate rejects old-verifier reads
cleanly with an explicit "unsupported version" instead of a mystery signature
failure.

---

## 4. Archive digest & chronicle state (core)

`crates/core` (re-exported for the CLI, mirroring the C4 helpers):

```rust
/// Stable identifier of an archive: BLAKE3 over its canonical (signed) bytes.
pub fn archive_digest(manifest: &TrstManifest) -> Result<[u8; 32]>;  // b3 of to_canonical_bytes()
pub fn format_archive_id(d: &[u8; 32]) -> String;                     // "b3:<hex>"
```

`archive_digest` is the same BLAKE3-over-canonical-bytes already computed in the
HPKE wrap path as `pre_digest` (`seal-cli/src/main.rs:955`); share one
implementation but keep the **name distinct** — `pre_digest` is CEK-binding
context, `archive_digest` is the chronicle link (OQ1).

**Chronicle state file** (`device.chronicle`, JSON, owner-only 0600):

```json
{
  "device_pub": "ed25519:<base64>",
  "sequence": 6,
  "tip": "b3:<hex>",
  "updated_at": "2026-08-04T18:25:03Z"
}
```

- `device_pub` binds the file to a signing identity; `wrap` fails if it doesn't
  match the key it's about to sign with (prevents cross-device chronicle mixups).
- Writes are **atomic** (temp + rename). Single-writer assumption: one device
  advances its own chronicle. Concurrent/forked writers are not prevented locally
  — the **witness ledger** (§7) is what catches equivocation.
- Permissions are **0600 for integrity, not confidentiality** (N3) — the file
  holds no secrets (a public tip + sequence). It is fully **re-derivable from the
  newest archive** (`archive_digest` + its `sequence`), so losing it is annoying,
  not fatal.

---

## 5. (a) `wrap` — building the chronicle

New flags on `seal wrap`:

| Flag | Meaning |
|---|---|
| `--chronicle <path>` | Read/advance a chronicle state file. Absent file ⇒ genesis (seq 0). |
| `--prev-archive <path>` | Derive prev from an existing `.seal` (its `archive_digest` + `sequence`+1). |
| `--prev-hash <b3:...>` `--prev-seq <N>` | Fully explicit link (CI). New archive is `seq N+1`, `prev = hash`. |

Resolution:

1. Determine `(sequence, prev)`:
   - `--prev-archive` given → `prev = archive_digest(that)`, `sequence = that.sequence + 1`.
   - else `--prev-hash` **and** `--prev-seq` → `prev = hash`, `sequence = N + 1`.
   - else `--chronicle` with existing file → `prev = file.tip`, `sequence = file.sequence + 1`.
   - else `--chronicle` with no file → **genesis**: `sequence = 0`, `prev = None`.
   - else (no chronicle flags) → **standalone**: both `None` (today's behavior).

   **Errors (A3):**
   - `--prev-archive` pointing at a **standalone** predecessor (no `sequence`) is a
     hard error: *"cannot chain onto a non-chronicle archive; start a chronicle
     with `--chronicle` or supply `--prev-hash`/`--prev-seq`."* There is no
     sequence to increment.
   - `--prev-hash` and `--prev-seq` are a **required pair** — supplying one without
     the other is an error.
2. Build the manifest with `sequence` / `prev_archive_hash` set, then sign as usual
   (they are inside the signed canonical bytes).
3. After writing, compute `archive_digest(new manifest)` and, if `--chronicle`
   was given, atomically update the state file to `(sequence, tip=new_digest)`.

Genesis is `sequence: 0`, `prev_archive_hash` absent — mirrors the intra-archive
chain's genesis (no synthetic sentinel in the manifest). `--sign-only` and
encrypted archives both support chronicle fields (they're independent of content
encryption).

---

## 6. (b) `verify` / `verify-chronicle` — linkage

**Single-archive `seal verify`** (unchanged inputs): additionally enforces the
§3.2 well-formedness rules. It **cannot** prove linkage with only one archive, so
it reports the archive's `(sequence, prev)` and notes "chronicle position N
(linkage unverified — supply the chain to `verify-chronicle`)." Single-archive
verify **exits `0`** when the chronicle fields are well-formed but linkage is
unverified — this is informational, **never** exit `13`; `13` is reserved for
`verify-chronicle` contiguity/linkage failures (N2).

**New `seal verify-chronicle`** — the multi-archive check:

```
seal verify-chronicle <dir | archive...> --device-pub ed25519:<...>
    [--witness <receipt.json> --witness-jwks <url|file>]
    [--json]
```

Steps:

1. Load all archives; sort by `sequence`.
2. For each: verify signature + intra-archive continuity (existing engine) and
   that `device.public_key` is the same across the chain (one signer).
3. **Contiguity:** sequences are `0,1,2,…,N` with no gaps and no duplicates.
   (A gap ⇒ a mid-chain archive was deleted; a duplicate `sequence` with a
   different digest ⇒ a fork.)
4. **Linkage:** for every `k > 0`, `archives[k].prev_archive_hash ==
   format_archive_id(archive_digest(archives[k-1]))`.
5. **Optional witness cross-check:** if `--witness` given, verify the receipt's
   JWS against the platform JWKS, then assert `local_tip.sequence >=
   receipt.sequence` and, when equal, `local_tip.tip == receipt.tip`. If the
   local chain is **behind** the witnessed tip, the tail was deleted — fail.

Exit codes extend the existing verify scheme: `0` ok, `10` signature, `11`
continuity, `13` **chronicle linkage/contiguity failure** (new), `12` schema/IO,
`1` other. (13 chosen to avoid colliding with 14=canonicalization.)

Detection matrix:

| Attack | Detected by | Offline? |
|---|---|---|
| Tamper an archive's content | signature (existing) | yes |
| Mid-chain deletion | sequence gap (§6.3) | yes |
| Reordering | sequence + linkage | yes |
| Fork / equivocation (two archives, same seq) | duplicate seq / witness PK conflict | yes (given both) |
| **Tail deletion** (drop the newest N) | witness cross-check (local behind witnessed) | **no — needs the witness** |
| Backdating `started_at` | witness `observed_at` upper bound | no — needs the witness |

Tail deletion and "when did this exist?" are exactly why the witness exists.

---

## 7. (c) Platform witness receipt

New endpoint: `POST /v1/witness` (`crates/platform`, `http` feature).

### 7.1 Request (device-signed)

```json
{
  "device_pub": "ed25519:<base64>",
  "sequence": 6,
  "tip": "b3:<hex>",
  "signed_at": "2026-08-04T18:25:03Z",     // device-asserted, UNTRUSTED
  "signature": "ed25519:<base64>"          // over canonical(device_pub,sequence,tip,signed_at)
}
```

The signed bytes use a fixed-order canonical JSON (same philosophy as the
manifest): `{"device_pub":…,"sequence":…,"tip":…,"signed_at":…}`. The device
produces this from its chronicle tip via a new `seal witness` helper (§7.5).

### 7.2 Platform processing

1. **Verify** the Ed25519 signature over the canonical request bytes. Reject
   `401` on failure.
2. **Registry binding (C3):** look the device up **by public key**
   (`WHERE public_key = $1`) — the witness request carries no `device_id`, unlike
   the existing `(org_id, device_id)`-keyed query, so H1.4 adds a by-pubkey lookup
   (A2). This requires signing keys to be **unique across orgs**; verify the schema
   and add a unique index on `public_key` if absent. If found, `device_registered
   = true`; if not found, record with `device_registered = false` — *honest public
   witness*, consistent with C3's honest-public-verifier stance.
3. **Monotonic append-only insert** into `witness_log` keyed by
   `(device_pub, sequence)`:
   - `sequence > max(existing)` → **accept**, insert.
   - `sequence == existing` and `tip ==` stored → **idempotent replay**, return
     the stored receipt.
   - `sequence == existing` and `tip !=` stored → **fork / equivocation**:
     reject `409`, record the conflict as evidence.
   - `sequence < max(existing)` → **rollback**: reject `409`.
   The `(device_pub, sequence)` **primary key** enforces one-tip-per-position at
   the DB layer; a fork attempt is a PK conflict, not a race.
4. **Trusted timestamp:** `observed_at = <platform UTC now>`. This is the
   trustworthy bound: the archive existed **at or before** `observed_at`.
5. **Issue** the witness receipt (§7.3).

The platform **MUST NOT** reject or gate on `signed_at` clock skew (N5):
`signed_at` is device-asserted and **diagnostic-only**. Treating it as freshness
would manufacture a guarantee the protocol does not provide — the only trusted
time is `observed_at`.

### 7.3 Witness receipt (JWS, signed by the platform JWKS key)

Reuses the existing JWKS signing key + `/.well-known/jwks.json` distribution, so
any party already able to verify a verification receipt can verify a witness
receipt. Claims follow the existing receipt conventions (A4): **same `iss` and
`aud`** as verification receipts, `sub` = the device signing key, and `typ` as
the discriminator.

```json
{
  "iss": "sealedge-verify-service",             // same issuer as verification receipts (A4)
  "aud": "<JWT_AUDIENCE>",                       // same audience policy applies (A4)
  "sub": "ed25519:<base64>",                     // device signing key (A4)
  "typ": "witness",                              // discriminator vs the "JWT" verification receipts
  "device_registered": true,
  "sequence": 6,
  "tip": "b3:<hex>",
  "observed_at": "2026-08-04T18:25:04Z",         // TRUSTED timestamp
  "prev_sequence": 5,                            // previously-witnessed entry (NOT seq-1; gaps allowed) (A6)
  "prev_tip": "b3:<hex>",                        // its tip (A6)
  "prev_observed_at": "2026-08-04T17:10:00Z",    // when it was witnessed (null at first witness)
  "iat": 1785...,
  "jti": "<uuid>"
}
```

The `prev_*` claims refer to the device's **previously witnessed entry** —
because the ledger accepts `sequence > max` (gaps), that is **not necessarily
`sequence - 1`** (A6). Carrying `prev_sequence`/`prev_tip` alongside
`prev_observed_at` makes cross-receipt chaining verifiable from receipts alone
(detect timestamp regressions and skipped witnessings without querying the
ledger).

**Deliberately non-expiring (A4):** witness receipts carry **no `exp`** — a
witnessed timestamp is a permanent historical fact, so `RECEIPT_TTL_SECS` (which
bounds the freshness of *verification* receipts) must **not** be copied here.

### 7.4 Ledger schema (postgres; extends the C3 store)

```sql
CREATE TABLE witness_log (
    device_pub        TEXT        NOT NULL,
    sequence          BIGINT      NOT NULL,
    tip               TEXT        NOT NULL,
    observed_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    device_registered BOOLEAN     NOT NULL,
    signed_at         TIMESTAMPTZ,            -- device-asserted, untrusted
    PRIMARY KEY (device_pub, sequence)        -- monotonic uniqueness; fork = PK conflict
);
```

**Durability honesty (A5):** a running server built **without** the `postgres`
feature MUST refuse `/v1/witness` loudly — return `503 Service Unavailable`,
never issue a RAM-backed receipt that implies durable, monotonic history it
cannot keep. This is the same don't-fabricate-durability principle as the C3
receipt and CA-mock fixes. A bounded in-memory ledger exists **only** for
unit/integration tests (behind `cfg(test)` / the `test-utils` feature), never for
a live server.

### 7.5 Device side (`seal witness`)

```
seal witness --chronicle device.chronicle --device-key device.key \
    --post http://localhost:3001/v1/witness --out receipt.json
```

Reads the chronicle tip, builds + signs the request, POSTs it, and stores the
returned receipt. `--out` alone (no `--post`) just emits the signed request for
offline submission (mirrors `emit-request`).

### 7.6 Trust model of the witness

The platform is a **timestamp + monotonicity witness**, not a content authority
(consistent with C3). It attests *when* it saw a tip and that the device's
history is *append-only from its vantage point*. It **cannot** forge device
signatures. Residual, explicitly out of scope:

- A malicious platform can **withhold** service or **lie about time**; signed
  receipts + `prev_observed_at` let clients detect time regressions but not a
  uniformly-shifted clock.
- **Cross-client equivocation** (showing different logs to different verifiers)
  is *not* prevented — that needs gossip / a Merkle log with consistency proofs.
  This is the acknowledged gap that makes this the "cheap version." §9 sketches
  the upgrade path.

---

## 8. Phase 2 (designed here, built later) — rotation, revocation, key-epoch

The chronicle is the substrate that makes rotation/revocation meaningful:
"the device's story over time." Mechanisms (implemented after H1):

- **`device.key_epoch: u32`** — monotonic per device, `0` for H1 archives.
  Added to the manifest (reserved slot, §3) and to the chronicle state.
- **Rotation (`seal rekey`)** — generates a new SEALEDGE-KEY-V2 bundle and emits
  a **rotation record**, itself a chronicle entry (it consumes a `sequence`):
  ```
  rotation { old_pub, new_pub, new_key_epoch, rotated_at,
             prev_archive_hash,               // chronicle tip at rotation
             sig_by_old, sig_by_new }         // old authorizes, new proves possession
  ```
  The chain continues across it: `…archive(seq k, epoch e, old) → rotation(seq
  k+1, old+new) → archive(seq k+2, epoch e+1, new)…`. Because the rotation is
  co-signed by the old key, `verify-chronicle` can follow the identity change
  without trusting the platform. The witness ledger links `old_pub → new_pub`
  via a `device_lineage` row so the append-only history survives the key change.
- **Revocation** — the platform registry (extends C3) gains `revoked_at` /
  `min_epoch`. `/v1/verify` and `/v1/witness` annotate or fail-closed on revoked
  or below-min-epoch keys. A signed revocation entry is compromise-evidence.
- **Synergy (the payoff):** the witness's **trusted timestamp** is what makes
  revocation usable — a verifier can decide "was this archive *witnessed before*
  the key was revoked?" and thus trust pre-compromise archives while rejecting
  post-compromise ones.

Adding `key_epoch` in H1 as an always-`None` field (to lock its canonical slot)
is optional — see OQ2.

---

## 9. Upgrade path to a real transparency log (future, out of scope)

The MVP ledger is a per-device append-only map. To close the equivocation gap
later: make `witness_log` a Merkle tree, return **inclusion proofs** in receipts
and **consistency proofs** between tree heads, and publish signed tree heads
(STHs) for gossip. The receipt shape (`sequence`, `tip`, `observed_at`) is a
forward-compatible subset, so clients written against the MVP keep working.

---

## 10. Implementation plan (phased, each CI-green)

- **H1.1 — protocol types.** Add `sequence` to `TrstManifest`; extend
  `serialize_canonical` (§3.1) and `validate()` (§3.2); **fix N1** (constructors
  default `trst_version` `0.1.0`→`0.2.0`). Update all workspace `TrstManifest`
  literals. Unit tests incl. "absent ⇒ golden vectors unchanged."
- **H1.2 — core.** `archive_digest` / `format_archive_id`; chronicle state
  read/write (atomic, 0600); witness-request canonical bytes + sign/verify.
- **H1.3 — seal CLI.** `wrap` chronicle flags + state advance; `verify`
  well-formedness; new `verify-chronicle`; new `seal witness`. Acceptance tests:
  genesis→link round-trip, reorder/gap/tamper/fork detection, tail-deletion via
  witness.
- **H1.4 — platform.** `/v1/witness` (verify, **registry-bind by public key
  (A2)**, monotonic insert, trusted timestamp, JWS receipt); `witness_log`
  (postgres) + tests-only in-memory; **server `503`s without postgres (A5)**.
  Integration tests: accept, idempotent replay, fork `409`, rollback `409`,
  `503`-without-postgres, receipt verifies against JWKS.
- **H1.5 — docs + threat model.** Add **T14** (§11), update CLAUDE.md,
  format/protocol docs, **add exit `13` to `crates/seal-cli/README.md` (OQ6)**,
  CHANGELOG.
- **Phase 2** (separate) — `key_epoch`, `seal rekey` + rotation record,
  revocation registry, verify honoring epoch/revocation + witness-vs-revocation.

---

## 11. Threat model additions (T14 — cross-archive integrity)

| Vector | Mitigation | Residual |
|---|---|---|
| Mid-chain deletion / reordering | sequence contiguity + hash linkage (offline) | none within a provided chain |
| Tail deletion | witness cross-check (local behind witnessed tip) | needs a prior witness receipt |
| "When did this exist?" | witness `observed_at` (trusted upper bound) | no lower bound without prior witnessing |
| Fork / equivocation (one device) | ledger PK `(device_pub, sequence)` → `409` | cross-client equivocation (needs gossip) |
| Platform lies about time / withholds | signed receipts + `prev_observed_at` monotonicity | uniform clock shift; DoS |
| Cross-device chronicle confusion | state-file `device_pub` bind; one-signer check in verify | — |

**Deepest residual (N4):** detection begins at the **first witness**. Any
rewriting of a device's history *before any tip was ever witnessed* is
undetectable — there is no independent record to contradict it. Witness early and
often; the first receipt is the anchor everything after it hangs from.

---

## 12. Open questions — RESOLVED (review 2026-08)

- **OQ1 — `prev_archive_hash` preimage → canonical (signed) bytes.** Confirmed.
  Share the BLAKE3-over-canonical implementation with the HPKE `pre_digest`
  (`seal-cli/src/main.rs:955`); keep the name `archive_digest` distinct (§4).
- **OQ2 — `device.key_epoch` → reserve now, add in Phase 2.** Confirmed.
- **OQ3 — witness store without postgres → require postgres in prod; in-memory
  is tests-only and the server `503`s otherwise (A5).** Confirmed.
- **OQ4 — `verify-chronicle` is a new subcommand.** Confirmed.
- **OQ5 — receipt is a JWS via the existing JWKS.** Confirmed.
- **OQ6 — linkage-failure exit code `13`.** Confirmed free (10/11/12/14 in use);
  document it in `crates/seal-cli/README.md` during H1.5.
