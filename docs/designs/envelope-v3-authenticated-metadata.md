<!--
Copyright (c) 2025 TRUSTEDGE LABS LLC
This source code is subject to the terms of the Mozilla Public License, v. 2.0.
If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

Project: sealedge — Privacy and trust at the edge.
-->

# Envelope v3 — authenticate envelope-level metadata

Status: **APPROVED (with amendments) — design only, not implemented.** Tracks
cyberscan finding #1, P1b. Breaking wire-format change; implement deliberately.

## Problem

`Envelope::verify()` (crates/core/src/envelope.rs) authenticates **only** the
per-chunk signatures (each `NetworkChunk`'s Ed25519 signature over
`blake3(manifest_bytes)`) and the chunk sequence. Several envelope-level header
fields are **cleartext, unsigned, and absent from the AEAD AAD** (AAD covers
header_hash, seq, nonce, manifest_hash, chunk_len — format.rs:304):

- `beneficiary_key_bytes` — the recipient identity.
- `hkdf_salt`, `metadata` — key-derivation salt and envelope metadata.

Chunk signatures verify against `verifying_key_bytes` (the issuer/signer) but never
bind `beneficiary_key_bytes`.

### Consequence

`beneficiary_key_bytes` is malleable: take any public envelope (Alice→Bob), rewrite
its beneficiary to an attacker key, and `verify()` still returns `true`. This makes
`verify_signature_chain`'s issuer→beneficiary continuity check graftable. (The keyed
`verify_receipt_chain_with_keys` already mitigates this for verifiers holding the
decryption keys, via `prev_envelope_hash == prev.hash()` where `hash()` covers the
whole envelope — but a *public* verifier, and `verify()` itself, cannot detect it.)

## Goal

A public verifier (no decryption keys) detects any tampering with envelope-level
metadata — starting with `beneficiary_key_bytes` — via `Envelope::verify()` alone.

## Solution: issuer signature over a frozen header preimage (Option A)

Add a top-level Ed25519 `header_sig` by the issuer over a **frozen preimage
structure**, checked in `verify()`. (Considered and rejected: folding fields into
the per-chunk AAD — only detectable on decrypt, fails the public-verifier goal; and
the scanner's ZKP suggestion — overkill.)

### A1. Signature domain separation (mandatory)

Chunk signatures today are raw `sign(blake3(manifest_bytes))` with **no prefix**,
and `auth.rs` signs unrelated payloads (cert_data, session_data, challenges) with
the same Ed25519 key class. A bare `sign(blake3(canonical_header))` would share a
signature shape with those — cross-object confusion becomes a layout coincidence
away from exploitable. **`header_sig` MUST sign a domain-separated preimage:**

```
header_sig = Ed25519_sign( issuer_sk,
    b"SEALEDGE_ENVELOPE_V3_HEADER\0" || header_preimage_bytes )
```

The prefix is normative and fixed. (Follow-up, out of scope here: retrofitting
domain-separation prefixes onto chunk and auth signatures.)

### A2. Frozen header preimage (byte-exact, normative)

Do **not** sign an ad-hoc "canonical serialization." Define a dedicated, frozen
`EnvelopeHeaderV3` preimage with a fixed field list, fixed order, and fixed
encoding. The two WASM verifiers (sealedge-wasm, sealedge-seal-wasm) reimplement
this independently, so it must be byte-exact and covered by golden vectors.

Fields, in this exact order (encoding: **bincode, little-endian** — consistent with
the `hash()` precedent at envelope.rs:262; explicit length-prefixed concatenation is
an acceptable alternative if specified byte-for-byte):

1. `version: u8` — **must be inside the preimage** (see A3).
2. `verifying_key_bytes: [u8;32]`
3. `beneficiary_key_bytes: [u8;32]`
4. `hkdf_salt: [u8; 32]` — fixed 32-byte salt (matches the struct today,
   envelope.rs:37); the preimage encodes exactly these 32 bytes, no length prefix.
5. `metadata` — with its own field order pinned explicitly (enumerate every
   `EnvelopeMetadata` field and its order in this doc when implementing).
6. ordered `blake3(manifest_bytes)` of each chunk, in ascending `sequence`.

Ship golden test vectors (known keys/salt/metadata → known `header_sig`) so both
WASM verifiers can be validated against the Rust implementation byte-for-byte.

### A3. Version dispatch must be built from scratch, and version must be bound

`version` is **write-only today**: `seal()` sets `version: 2` (envelope.rs:186) and
nothing in `verify()`/`unseal()` ever reads it — only tests assert on it
(envelope.rs:718/751/773/787). So:

- **(a) Build real version dispatch.** With bincode's flat sequential layout you
  cannot peek `version` mid-struct, so introduce a version-tagged enum or a custom
  `Deserialize` that reads the leading `version` byte and dispatches. Plan this now;
  it does not exist.
- **(b) Bind `version` in the signed preimage** (field 1 above). Otherwise a v3
  envelope can be re-labeled v2 to bypass the `header_sig` check.

## Compatibility (amended — old binaries are silently unsafe under JSON)

Because old binaries never check `version`, behavior on a v3 envelope diverges by
codec:

- **bincode:** the extra `header_sig` field fails deserialization → **fail-closed
  (fine).**
- **serde_json** (this codebase uses it — a test asserts `"version":2` in JSON
  output): the unknown `header_sig` field is **silently ignored**, so an old binary
  "verifies" a v3 envelope with the new security property **absent**.

Therefore:

- **Ship a "reject unknown versions" gate in a v2 patch release *before or with*
  v3.** `verify()`/`unseal()` must read `version` and refuse anything they don't
  understand, closing the JSON silent-accept path on already-deployed binaries.
  **DONE** — shipped ahead of v3: `Envelope::verify` returns `false` and
  `Envelope::unseal` errors for any `version != ENVELOPE_VERSION_V2` (envelope.rs).
- **Document the JSON-vs-bincode divergence** for integrators.
- `seal()` emits v3; `verify()` requires a valid `header_sig` for v3. **Reject v2 in
  `verify()` by default**, with an explicit, non-public legacy opt-in (see below).
  No auto-migration of existing archives (re-seal to upgrade).

## P1a interaction & transition policy (mixed v2→v3 chains)

`verify_receipt_chain_with_keys` recomputes `prev.hash()` over whole envelopes, so a
mixed v2→v3 chain verifies correctly on the hash-link math. But "reject v2 in
`verify()` by default" means the keyed verifier would refuse legacy v2 predecessors
unless it explicitly opts into a legacy read path. Pin this:

- **Keyed receipt verification (`verify_receipt_chain_with_keys`):** MAY use the
  legacy opt-in to accept v2 predecessors, with the documented caveat that v2
  metadata is unauthenticated (the hash-link still binds the predecessor's bytes).
- **Public `verify_signature_chain` and bare `Envelope::verify()`:** MUST NEVER use
  the legacy opt-in.
- **Opt-in shape:** a distinct, explicit parameter/type (e.g. an
  `AllowLegacyV2`/`VerifyPolicy` argument), **not** a mutable global or default, and
  scoped/named so it cannot leak into public verification paths by accident. It must
  be impossible to reach the legacy path without naming it at the call site.

## Blast radius

`envelope.rs` (struct + `version` dispatch + `seal`/`verify` + `header_sig`),
`format.rs` (only if AAD is also touched — not required by Option A), golden-vector
fixtures, both WASM verify paths, the v2-patch "reject unknown versions" gate, and
receipts docs. The archive `.seal` format (separate, `trst_version` 0.2.0) is
unaffected — this is the `Envelope` format used by the receipts/attestation layer;
no CLI/platform consumer of receipts exists today.

## Non-goals

- No double-spend resistance / ledger (the receipts module is deliberately
  ledgerless).
- No ZKP.
- Retrofitting domain separation onto chunk/auth signatures (worth doing, tracked
  in `docs/designs/signature-domain-separation.md`).

## Acceptance

- A public verifier rejects a v3 envelope whose `beneficiary_key_bytes` (or any
  covered header field, incl. a downgraded `version`) was altered post-seal.
- Cross-object confusion test: a chunk-manifest signature or an `auth.rs` signature
  is not accepted as a `header_sig` (domain-separation prefix enforced).
- **Same-issuer chunk-splice test:** given two v3 envelopes sealed by the *same*
  issuer key (so per-chunk signatures remain individually valid after moving), a
  verifier rejects an envelope whose chunk set is spliced from the other — chunks
  reordered, added, dropped, or swapped in. `header_sig` covers the ordered
  `blake3(manifest_bytes)` of every chunk in ascending `sequence` (field 6), so any
  such edit changes the preimage and invalidates `header_sig`. This is the case the
  per-chunk signatures alone cannot catch (they say each chunk is authentic, not that
  *this* set in *this* order is the sealed set).
- Deployed-binary safety: a pre-v3 binary with the v2 "reject unknown versions" gate
  refuses a v3 envelope under both bincode and serde_json (no silent accept).
  **(Gate shipped ahead of v3** — `Envelope::verify`/`unseal` reject any
  `version != 2`, envelope.rs; see `ENVELOPE_VERSION_V2`. The serde_json divergence
  this closes is the reason it landed early.)
- Golden vectors for `header_sig` pass identically in Rust and both WASM verifiers.
- Round-trip + existing golden vectors pass for v3.
