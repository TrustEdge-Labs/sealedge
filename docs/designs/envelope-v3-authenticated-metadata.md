<!--
Copyright (c) 2025 TRUSTEDGE LABS LLC
This source code is subject to the terms of the Mozilla Public License, v. 2.0.
If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

Project: sealedge — Privacy and trust at the edge.
-->

# Envelope v3 — authenticate envelope-level metadata

Status: **PROPOSED** (design only — not implemented). Tracks cyberscan finding #1,
P1b. Breaking wire-format change; do it deliberately.

## Problem

`Envelope::verify()` (crates/core/src/envelope.rs) authenticates **only** the
per-chunk signatures (over each `ChunkManifest` hash: seq, size, timestamp) and the
chunk sequence. Several envelope-level header fields are **cleartext, unsigned, and
absent from the AEAD AAD** (AAD covers header_hash, seq, nonce, manifest_hash,
chunk_len — see format.rs:304):

- `beneficiary_key_bytes` — the recipient identity.
- `hkdf_salt`, `metadata` — key-derivation salt and envelope metadata.

Chunk signatures verify against `verifying_key_bytes` (the issuer/signer) but never
bind `beneficiary_key_bytes`.

### Consequence

`beneficiary_key_bytes` is malleable: an attacker can take any public envelope
(e.g. Alice→Bob), rewrite its beneficiary to an attacker key, and `verify()` still
returns `true`. This makes `verify_signature_chain`'s issuer→beneficiary continuity
check graftable — append an attacker-issued successor and the signature/continuity
screen passes. (The keyed `verify_receipt_chain_with_keys` already mitigates this for
verifiers holding the decryption keys: it checks `prev_envelope_hash == prev.hash()`,
and `hash()` covers the whole envelope including the beneficiary — but a *public*
verifier, and `verify()` itself, still cannot detect the tamper.)

## Goal

A public verifier (no decryption keys) can detect any tampering with envelope-level
metadata — starting with `beneficiary_key_bytes` — via `Envelope::verify()` alone.

## Options

- **A — issuer signature over the canonical header (recommended).** Add a top-level
  Ed25519 signature by the issuer over a canonical serialization of the header:
  `verifying_key_bytes`, `beneficiary_key_bytes`, `hkdf_salt`, `metadata`, and the
  ordered chunk manifest hashes. `verify()` checks it. Public-verifiable (no
  decryption), authenticates *all* metadata with one signature, and composes with
  the existing chunk signatures.
- **B — fold the fields into the per-chunk AAD.** Add `beneficiary_key_bytes`
  (and `hkdf_salt`) to the AAD at format.rs:304. Binds them cryptographically, but
  only *detectable on decrypt* — a public verifier still can't check them. Weaker
  than A for the stated goal.
- **C — both.** Belt-and-suspenders; A already covers the public-verifier goal.

**Recommendation: Option A.** B alone doesn't meet the public-verifiability goal; C
is more than needed. Skip the scanner's ZKP suggestion (overkill).

## Format / compatibility

- Bump the envelope format version `v2 → v3`. v3 carries a `header_sig` field.
- `verify()`: v3 requires a valid `header_sig`; decide v2 policy — either reject v2
  (clean, forces re-seal) or accept v2 with a documented "unauthenticated metadata"
  caveat during a transition window. Prefer **reject v2 in verify by default**, with
  an explicit opt-in for legacy read, given the security intent.
- `seal()` emits v3. No auto-migration of existing archives (re-seal to upgrade).
- Update golden vectors and both WASM verifiers (sealedge-wasm, sealedge-seal-wasm).

## Blast radius

`envelope.rs` (seal/verify/struct + version), `format.rs` (AAD if Option B/C),
golden-vector fixtures, WASM verify paths, and any receipts docs. No CLI/platform
consumer of the receipts module today, so the archive `.seal` format (separate,
`trst_version` 0.2.0) is unaffected — this is the `Envelope` format used by the
receipts/attestation layer.

## Non-goals

- No double-spend resistance / ledger (out of scope; the receipts module is
  deliberately ledgerless).
- No ZKP.

## Acceptance

- A public verifier rejects an envelope whose `beneficiary_key_bytes` (or other
  covered header field) was altered post-seal.
- Round-trip + golden vectors pass for v3; the malleability test (rewrite
  beneficiary → `verify()` must now return false) is added.
