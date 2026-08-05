<!--
Copyright (c) 2025 TRUSTEDGE LABS LLC
This source code is subject to the terms of the Mozilla Public License, v. 2.0.
If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

Project: sealedge — Privacy and trust at the edge.
-->

# H1 Phase 2 — Key rotation & revocation ("the device's story over time")

Status: **APPROVED (with amendments PA1–PA5 + nits PN1–PN5, folded in below) —
P2.1 ready to build.**

Builds on [H1 device chronicle](h1-device-chronicle.md) (§8 sketched this) and
C4 (§12). H1 gave a device a signed, hash-linked, witnessed chronicle under a
*single* key. Phase 2 lets that identity **change over time** — rotate to a new
key without breaking the chain, and revoke a compromised key — while keeping
every past archive verifiable.

---

## 0. Decisions locked (from scoping)

| Decision | Choice | Consequence |
|---|---|---|
| **Rotation record** | A **dedicated rotation entry** occupying its own chronicle `sequence`, co-signed by the old key (authorizes) and the new key (proves possession). | Explicit, independently witnessable; `verify-chronicle` switches the active signer at that point. Content archives never carry rotation metadata — they only gain `key_epoch`. |
| **Revocation** | **Registry / org-admin via the platform** (extends the C3 registry, bearer-authenticated). | `revoked_at` / `min_epoch` on the device row; `/v1/verify` and `/v1/witness` enforce. No new signed-statement format. |
| **Phasing** | **P2.1** `key_epoch` + `seal rekey` + rotation entry + `verify-chronicle` rotation handling; **P2.2** revocation + witness lineage. | Each sub-phase lands CI-green independently, C4/H1 rhythm. |

Format: **additive-optional within `trst_version` 0.2.0** (same rationale as H1 —
the new fields are optional; absent ⇒ byte-identical canonical output; existing
archives/golden vectors unaffected).

---

## 1. The gap Phase 2 closes

Today a chronicle is bound to one signing key forever:

- **No rotation.** If a device's key ages out or a holder wants to roll it, the
  only options are to start a brand-new (unlinked) chronicle or keep using the
  old key. There is no signed way to say "key B continues the history of key A."
- **No revocation.** If a signing key is compromised, nothing marks it invalid;
  a verifier can't distinguish archives made by the legitimate holder before the
  compromise from forgeries made after.

Phase 2 adds a **key epoch** to every archive, a **rotation entry** that links a
new key to the old one inside the chronicle, and **registry revocation** whose
teeth come from H1's trusted witness timestamps: *"was this archive witnessed
before the key was revoked?"*

**Non-goals:** device-signed self-revocation (deferred — registry only, per
scoping), automatic re-wrapping of past archives to a new key, and a published
CRL/transparency feed (registry lookup only).

---

## 2. Key epoch (P2.1)

A monotonic `key_epoch: u32` per device identity. Epoch `0` is the genesis key
(all H1 archives). Each rotation increments it by exactly 1.

### 2.1 Manifest change (`crates/seal-protocols`)

`DeviceInfo` gains the slot reserved in H1 (OQ2):

```rust
pub struct DeviceInfo {
    pub id: String,
    pub model: String,
    pub firmware_version: String,
    pub public_key: String,                    // Ed25519 signing key
    pub key_agreement_public: Option<String>,  // X25519 (C4)
    // NEW (P2.1): the epoch of `public_key`. Absent ⇒ 0 (genesis / all H1
    // archives). Emitted only when > 0, so epoch-0 archives canonicalize
    // byte-identically to H1.
    pub key_epoch: Option<u32>,
}
```

Canonical order: `key_epoch` immediately after `key_agreement_public` inside
`device`, emitted only when `Some` and `> 0`. Validation: if present it must be
`>= 1` (epoch 0 is represented by absence).

> **PN3 — old-verifier interaction (mirrors H1 §3.3).** An epoch-bearing archive
> (epoch ≥ 1) fed to a pre-P2.1 verifier fails **closed**: the unknown `key_epoch`
> field changes the reserialized canonical bytes, so the Ed25519 signature check
> fails with an opaque signature error rather than silently ignoring the field.
> Epoch-0 archives are byte-identical to H1 and verify everywhere. This is the
> same unknown-field/reserialize property H1 relied on — stated here so the
> failure mode is documented, not surprising.

> **PN2 — `device.id` is per-key.** `device.id` is derived from the signing key
> (`pub_key_to_device_id`), so a rotated device produces a *different* `device.id`
> in its post-rotation archives. This is not a flaw: the registry and witness bind
> by `device_pub`, and continuity across rotations lives in the chronicle (hash
> chain + rotation entries) and the platform's `device_lineage`, never in
> `device.id`. Consumers keying off `device.id` for "same device" must instead
> follow the chronicle / lineage.

### 2.2 Chronicle state

`ChronicleState` gains `key_epoch: u32` (default 0). After a rotation the state's
`device_pub` becomes the **new** key and `key_epoch` becomes the new epoch, so
subsequent `seal wrap --chronicle` signs with the new key and stamps
`device.key_epoch` accordingly.

> **PN1 — `#[serde(default)]` is a code requirement, not a nicety.** The new
> field MUST carry `#[serde(default)]` so every H1-written `device.chronicle`
> state file (which has no `key_epoch`) still deserializes after upgrade,
> defaulting to epoch 0. An acceptance test loads an H1-era state file and asserts
> it round-trips at epoch 0.

---

## 3. Rotation entry (P2.1)

A rotation is a **first-class chronicle entry** that consumes one `sequence`
slot. It is not a content archive (no chunks). On disk it is a directory holding
a single `rotation.json` (no `manifest.json`, no `chunks/`), so it sits alongside
content archives in a chronicle folder and `verify-chronicle` collects it
naturally (a directory with either `manifest.json` **or** `rotation.json`).

### 3.1 `rotation.json` schema

```json
{
  "trst_version": "0.2.0",
  "kind": "rotation",
  "sequence": 7,
  "prev_archive_hash": "b3:<digest of entry 6>",
  "old": { "public_key": "ed25519:<b64>", "key_epoch": 0 },
  "new": {
    "public_key": "ed25519:<b64>",
    "key_agreement_public": "x25519:<b64>",
    "key_epoch": 1
  },
  "rotated_at": "2026-08-05T12:00:00Z",
  "sig_old": "ed25519:<b64>",
  "sig_new": "ed25519:<b64>"
}
```

- **Canonical bytes** are a fixed-field-order serialization (same philosophy as
  the manifest) with **both signatures excluded**. `sig_old` and `sig_new` are
  each computed over those canonical bytes.
- **`archive_digest`** of a rotation entry = `b3(canonical bytes)` — identical
  machinery to archives, so the next content archive's `prev_archive_hash` points
  at the rotation entry and the hash chain is unbroken.
- **Co-signature semantics:** `sig_old` proves the *old* key authorized this
  successor (only the current holder can extend the chain); `sig_new` proves the
  holder controls the *new* key (no committing someone else's key). Both are
  required.
- `new.key_epoch` MUST equal `old.key_epoch + 1`. `old.public_key` /
  `old.key_epoch` MUST match the chronicle's current active signer / epoch.

### 3.2 `seal rekey`

```
seal rekey --chronicle <state> --old-key <old V2 bundle> --new-key <new V2 bundle>
           --out <dir.seal> [--unencrypted]
```

0. **(PN4)** If `--chronicle` state is missing or empty, error explicitly
   ("nothing to rotate — no chronicle state at `<path>`; run `seal wrap
   --chronicle` first") rather than silently rotating a genesis-less chain.
1. Load `ChronicleState`; assert `old-key`'s signing pub == `state.device_pub`.
2. Load `new-key` (pre-generated with `seal keygen`).
3. Build the rotation entry at `sequence = state.sequence + 1`,
   `prev_archive_hash = state.tip`, `old = {state signer, state.key_epoch}`,
   `new = {new signer, new x25519, state.key_epoch + 1}`.
4. Sign canonical bytes with the old key → `sig_old`, then the new key →
   `sig_new`; write `rotation.json`.
5. Advance the state: `device_pub = new signer`, `sequence += 1`,
   `tip = archive_digest(rotation)`, `key_epoch += 1`.

The next `seal wrap --chronicle` then produces an archive signed by the new key
with `device.key_epoch = 1`, linked to the rotation entry.

---

## 4. `verify-chronicle` across rotations (P2.1)

H1's `verify-chronicle` assumes **one signer**. P2.1 replaces that with an
active-identity walk:

1. Collect entries (archives + rotation entries); sort by `sequence`; check
   contiguity + hash linkage exactly as H1 (rotations are just entries in the
   digest chain).
2. Track `(active_signer, active_epoch)`, seeded from the **genesis** entry.
   `--device-pub` pins the genesis (epoch-0) identity — the root of the chronicle;
   rotations extend it.
3. For each entry in order:
   - **archive** → `device.public_key == active_signer` and
     `key_epoch(or 0) == active_epoch`; verify signature + continuity as in H1.
   - **rotation** → `old.public_key == active_signer`,
     `old.key_epoch == active_epoch`, `new.key_epoch == active_epoch + 1`; verify
     BOTH `sig_old` (against `active_signer`) and `sig_new` (against
     `new.public_key`); then set `active_signer = new.public_key`,
     `active_epoch = new.key_epoch`.
4. Report the chain, the current (tip) identity + epoch, and the rotation points.
   Exit `13` on any linkage / signer / epoch violation.

The `--witness` cross-check (H1) is unchanged in spirit: it compares the local
tip `(sequence, digest)` against the witnessed tip; the tip may now be a rotation
entry or a new-key archive.

> **PA3 (must-fix) — the F2 receipt-binding breaks on every rotated chain.**
> `verify-chronicle --witness` (shipped in 9f3bd34, F2) rejects a receipt whose
> `device_pub != --device-pub`. With OQ2 pinning the *genesis* identity, a
> post-rotation witness receipt carries the **current** key and would always fail
> its own cross-check. P2.1 MUST change that comparison: the receipt's
> `device_pub` must equal the **active signer at the witnessed sequence**
> (computed by the same active-identity walk — normally the tip identity), not the
> genesis pin. The F2 fail-loud guarantee is preserved — a receipt whose
> `device_pub` matches *no* identity at that point in the chronicle still fails.
> Acceptance test: genesis-wrap → rotate → wrap-under-new-key → witness under the
> new key → `verify-chronicle --device-pub <genesis> --witness` passes; a receipt
> bound to an unrelated key still fails.

---

## 5. Revocation (P2.2) — registry + enforcement

### 5.1 Registry

The C3 `devices` row gains:

```sql
ALTER TABLE devices ADD COLUMN revoked_at  TEXT;   -- RFC 3339; NULL = active
ALTER TABLE devices ADD COLUMN min_epoch   INTEGER; -- reject key_epoch < this
```

Org-admin endpoint (bearer-authenticated, like `/v1/devices`):

```
POST /v1/devices/:id/revoke   { "revoked_at": "<rfc3339?>", "min_epoch": <u32?> }
```

Sets `revoked_at` (defaulting to now) and/or `min_epoch`. Only the owning org may
revoke its device (C3 tenant isolation).

> **PA4 (must-fix) — revocation is monotonic-only.** "Idempotent" alone leaves a
> laundering hole: if an admin could clear `revoked_at` or push it *later*, a
> post-compromise forgery witnessed after the original revocation time could be
> retroactively blessed. Rule:
> - `revoked_at` may be **set**, and **moved earlier** (compromise discovered to
>   predate the first estimate), but **never moved later and never cleared**.
> - `min_epoch` is **strictly non-decreasing**.
>
> Requests that violate monotonicity are rejected (`409`), not silently ignored.
> This sharpens OQ4: admin backdating is allowed, but *earlier-only*.

### 5.2 Enforcement

- **`/v1/witness`** *(PA5 — enforceable wording)*: a witness request carries no
  trusted time, so there is **no** tip→`revoked_at` mapping to gate on. The rule
  is therefore purely on device state, not on tip time:
  - once the device is revoked, a request for a **new** (not-yet-witnessed) tip is
    refused (`403`) — the platform will not extend a revoked key's chronicle;
  - **idempotent replays of already-witnessed entries still return their original
    receipts** — a fact witnessed before revocation stays retrievable forever.

  (The "witnessed before revocation" judgement lives entirely on the verifier
  side in §5.3, using the `observed_at` already baked into those pre-revocation
  receipts — the platform never has to reconstruct tip time.)
- **`/v1/verify`**: annotates the receipt with `revoked_at` / `min_epoch` and
  fails closed when `key_epoch < min_epoch`. It does **not** by itself reject on
  `revoked_at` — that requires knowing *when* the archive existed…

### 5.3 The payoff (revocation × witness timestamp)

A signing key seen after compromise can forge archives with any self-asserted
timestamp. The only trusted time is the witness `observed_at`. So the
revocation-aware verdict is a **verifier-side composition**:

> An archive at `(sequence, tip)` is trustworthy under a revoked key iff it was
> **witnessed before `revoked_at`** — i.e. there is a witness receipt whose
> `observed_at ≤ revoked_at` covering that tip (or a later one that transitively
> covers it).

Documented as the recommended verify flow: `verify-chronicle --witness` (trusted
tip time) + registry `revoked_at` → accept pre-revocation history, reject
post-revocation forgeries.

### 5.4 Witness lineage & closing the old ledger

When a device rotates, the platform must (a) learn of the rotation so the ledger
reflects one continuous history, and (b) stop co-signing the superseded key's
chronicle. Both need the platform to actually *see and verify* the rotation
entry — which the H1 witness request does not carry.

**PA1 — the platform must receive the rotation entry.** The H1 witness request is
only `{device_pub, sequence, tip, signed_at, signature}`; it never contains the
rotation entry, so the platform cannot "verify `sig_old`/`sig_new` before
recording lineage" as originally written. Fix: the witness request for a
*rotation tip* carries an optional full `rotation.json` payload (a
`rotation: Option<RotationRecord>` field; a plain content-archive witness omits
it). When present, before recording anything the platform verifies:

  1. `sig_old` (against `rotation.old.public_key`) **and** `sig_new` (against
     `rotation.new.public_key`) over the rotation canonical bytes;
  2. `rotation.new.public_key == request.device_pub` (the requester controls the
     new key it is claiming);
  3. `tip == archive_digest(rotation)` **and** `request.sequence ==
     rotation.sequence` (the witnessed tip *is* this rotation);
  4. **defense-in-depth:** `rotation.old.public_key` matches a device the platform
     already knows (its witnessed chain under `old_pub` ends at
     `rotation.prev_archive_hash` / `rotation.sequence - 1`).

Only then does it record lineage and the rotation tip.

```sql
CREATE TABLE device_lineage (
    new_pub        TEXT NOT NULL,
    old_pub        TEXT NOT NULL,
    rotation_seq   BIGINT NOT NULL,
    observed_at    TEXT NOT NULL,
    PRIMARY KEY (new_pub)
);
```

**PA2 — the superseded key's ledger closes at the rotation point.** H1's witness
ledger accepts monotonically-newer tips for a key *forever*. Without a stop rule,
a stolen old key could keep obtaining witness receipts on the old-key ledger at
`sequence > rotation_seq` — a platform-co-signed **parallel history** diverging
from the one true (rotated) chain. Rule, enforced once lineage
`old_pub → new_pub @ rotation_seq` is recorded:

  - a new old-`pub` entry with `sequence > rotation_seq` → refused **`409`
    "superseded"** (that key's chronicle ended at the rotation);
  - `sequence <= rotation_seq`, and idempotent replays of already-witnessed
    entries, still succeed (past facts stay retrievable — consistent with PA5).

This is what makes rotation *real on the platform*: after rotation there is
exactly one extendable ledger — the new key's.

Together these let the witness answer "what is the full witnessed history of this
device identity across rotations?" while guaranteeing a compromised old key can't
fork a second co-signed timeline. (The offline `verify-chronicle` already follows
rotations without the platform; lineage is the platform-side mirror.)

---

## 6. Threat model additions (T15 — key lifecycle)

| Vector | Mitigation | Residual |
|---|---|---|
| Signing-key rotation without losing history | dual-signed rotation entry in the chain; `verify-chronicle` walks identities by epoch | — |
| Attacker commits a key they don't control | `sig_new` (possession proof) required | — |
| Attacker extends the chain with an unauthorized successor | `sig_old` (authorization) required | old-key compromise (see next row) |
| Compromised key forges post-compromise archives | registry `revoked_at` + witness `observed_at`: reject archives not witnessed before revocation | archives witnessed before the compromise was noticed/revoked are trusted (inherent — that's what "before revocation" means) |
| Stolen **old** key forks a second platform-co-signed timeline after rotation | superseded-ledger rule (PA2): once lineage records the rotation, old-key tips beyond `rotation_seq` are refused `409` | pre-rotation old-key tips remain valid (they are genuine history) |
| Downgrade to a retired key/epoch | `min_epoch` rejects below-threshold epochs | — |
| Malicious platform lies about `revoked_at` | signed receipts bound the timestamps; revocation is an org-scoped registry fact | equivocation (H1 T14 residual) — needs a transparency log |

---

## 7. Implementation plan

- **P2.1 — epoch + rotation (protocol → core → CLI):**
  - seal-protocols: `device.key_epoch` (canonical + validation, emit-when-`>0`);
    unit tests incl. "epoch-0 ⇒ golden vectors unchanged".
  - core: `RotationRecord` type + canonical bytes + dual-sign/verify helpers +
    `archive_digest` support; `ChronicleState.key_epoch` (`#[serde(default)]`,
    PN1). Unit tests + **frozen golden fixture for rotation canonical bytes**
    (PN5 — a new signature surface; freeze it like `golden_vectors.rs`, not just
    property tests). `RotationRecord` lives in core (not just the CLI) so P2.2's
    platform can reuse the same verify helpers for PA1.
  - seal-cli: `seal rekey` (PN4 empty-state error); `wrap` stamps `key_epoch` from
    state; `verify-chronicle` active-identity walk **+ PA3 receipt-binding fix**
    (receipt `device_pub` must match the active signer at the witnessed sequence,
    not the genesis pin). Acceptance tests: rotate → wrap-under-new-key →
    verify-chronicle passes; rotate → witness-under-new-key → `--witness` passes
    (PA3); forged `sig_new`/`sig_old` → fail; epoch skip → fail; wrong successor →
    fail; H1-era state file loads at epoch 0 (PN1).
- **P2.2 — revocation (platform):**
  - migration: `devices.revoked_at`, `devices.min_epoch`, `device_lineage`.
  - `POST /v1/devices/:id/revoke` (org-scoped, **monotonic-only** per PA4);
    `/v1/witness` refuses revoked keys' new tips (`403`) but replays past receipts
    (PA5), and enforces the superseded-ledger `409` rule (PA2); witness request
    gains the optional `rotation: RotationRecord` payload and the platform
    verifies it before recording lineage (PA1); `/v1/verify` annotates + enforces
    `min_epoch`. `#[ignore]` DB integration tests (convention) + CI-runnable
    `decide`-style unit tests for each pure enforcement decision (revoke
    monotonicity, superseded-ledger, revoked-witness gate, min_epoch).
  - docs: T15, CHANGELOG, CLAUDE.md, seal-cli README (`rekey`), design status.

Each sub-phase: `./scripts/ci-check.sh` green; postgres paths compile-checked
locally with `--features postgres,http` (CI doesn't build postgres).

---

## 8. Open questions — RESOLVED on review

All five resolved to the recommended option; OQ4/OQ5 as amended by PA4/PA5.

- **OQ1 — rotation entry on disk → directory containing `rotation.json`**
  (uniform with archives for collection/ordering).
- **OQ2 — `--device-pub` for a rotated chain → pin the genesis identity**; let
  `verify-chronicle` follow rotations. (Interacts with PA3: the `--witness`
  cross-check binds the receipt to the *active* signer at the witnessed sequence,
  not to this genesis pin.)
- **OQ3 — `seal rekey --new-key` source → require a pre-generated V2 bundle**
  (`seal keygen`); `rekey` does not mint keys inline.
- **OQ4 — revoke endpoint → `POST /v1/devices/:id/revoke`.** Admin backdating of
  `revoked_at` is allowed but **earlier-only** (PA4 monotonicity); the witness
  timestamp is what verifiers actually trust.
- **OQ5 — witness under a revoked key → hard refusal.** New tips → `403`;
  already-witnessed replays still return their original receipts (PA5). The
  platform never extends a revoked chronicle.
