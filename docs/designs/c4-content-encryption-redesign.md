<!--
Copyright (c) 2025 TRUSTEDGE LABS LLC
MPL-2.0: https://mozilla.org/MPL/2.0/
Project: sealedge — Privacy and trust at the edge.
GitHub: https://github.com/TrustEdge-Labs/sealedge
-->

# C4 — Content-Encryption Redesign: per-archive CEK, HPKE recipients, forward secrecy

**Status:** Proposed (design approved; implementation pending)
**Date:** 2026-08-03
**Owner:** Platform / crypto
**Supersedes:** the master-key content-encryption model in `docs/technical/format.md` (`.trst` `trst_version` `0.1.0`)
**Related:** `docs/technical/threat-model.md`, `docs/technical/format.md`, security finding **C4**

---

## 1. Motivation

Security review finding **C4** identified that one 32-byte Ed25519 device secret currently does everything:

- **identity / signing** — manifest signature (`crypto::sign_manifest`)
- **content-encryption root** — `derive_chunk_key(device_secret)` is a deterministic, salt-less HKDF over the *signing* secret ([`crates/core/src/crypto.rs`](../../crates/core/src/crypto.rs))
- **envelope ECDH** — static-static X25519 derived from the same long-term key ([`crates/core/src/envelope.rs`](../../crates/core/src/envelope.rs))
- **auth session keys** — X25519 ECDH from the same key ([`crates/core/src/auth.rs`](../../crates/core/src/auth.rs))

Consequences confirmed in code:

1. **Key-separation violation.** Compromise of the one secret destroys authenticity *and* confidentiality, retroactively and fleet-wide per device.
2. **No forward secrecy.** Static-static X25519 means a later key readout (flash dump of a decommissioned IoT board is the canonical case) decrypts every archive/envelope ever produced.
3. **No recipient model.** `seal unwrap` recovers the chunk key from `device_keypair.secret_bytes()` ([`crates/seal-cli/src/main.rs`](../../crates/seal-cli/src/main.rs)); sharing archive contents with an insurer/auditor means handing over the master identity (forgery) key.
4. **Confidentiality against everyone, including legitimate auditors.** A public-key verifier can verify but never recover plaintext.

This document specifies the replacement.

## 2. Decisions (from C4 review)

| Decision | Choice |
|---|---|
| Scope of first delivery | **Design doc first**, then implement (this document) |
| Key-wrap primitive | **HPKE — RFC 9180** (`hpke` crate), not hand-rolled |
| Device key structure | **Separate keys**: an Ed25519 *signing* key and an independent X25519 *key-agreement* key. Ed25519 is used **only** for signing. |
| Backward compatibility | **Clean break.** New `trst_version` `0.2.0`. `wrap` emits `0.2.0` only; `0.1.0` archives are no longer produced. |

## 3. Goals / Non-goals

**Goals**
- G1 — Ed25519 signing key is used *only* for signatures. Content confidentiality no longer derives from it.
- G2 — Per-archive random Content-Encryption Key (CEK); chunks encrypted under the CEK.
- G3 — CEK wrapped to *one or more* recipients via HPKE with **ephemeral sender keys** → forward secrecy against later recipient/device key compromise.
- G4 — A recipient (auditor, insurer, the device owner) can read contents using *their own* key-agreement key, gaining **no** ability to forge.
- G5 — Public-key verification (signature + continuity) is unchanged in capability and remains decryption-free.

**Non-goals (this document)**
- Key **rotation, revocation, and key-epoch / compromise-evidence** — sketched in §12 as Phase 2; manifest reserves fields for it but the mechanisms are out of scope here.
- Replacing the network transport auth handshake (`auth.rs`). Its static-static ECDH is a separate finding surface; called out in §11 but not redesigned here.
- Migration tooling to re-wrap existing `0.1.0` archives (clean break; see §10).

## 4. Key model

Every device **and** every recipient (auditor/insurer/owner) has two independent keypairs:

| Key | Curve | Purpose | Wire encoding (public) |
|---|---|---|---|
| Signing key | Ed25519 | Manifest signatures, identity | `ed25519:<base64(32)>` |
| Key-agreement key | X25519 | HPKE recipient (CEK unwrap) | `x25519:<base64(32)>` |

- The X25519 key is generated **independently** (`x25519_dalek::StaticSecret::random`), **not** derived from the Ed25519 key. This is the concrete break from today's `to_scalar_bytes()` conversion.
- `device.public_key` in the manifest continues to be the **Ed25519** key (the C3 cross-check still applies: it must equal the verification key). A new field carries the X25519 key (see §7).

### 4.1 Key file / bundle format (`SEALEDGE-KEY-V2`)

Today `SEALEDGE-KEY-V1` stores a single Ed25519 secret (PBKDF2-HMAC-SHA256 600k + AES-256-GCM; `--unencrypted` escape hatch). We introduce **`SEALEDGE-KEY-V2`**, a bundle holding both secrets under the same passphrase-derived key:

```
SEALEDGE-KEY-V2\n
{"salt":"<b64>","nonce":"<b64>","iterations":600000}\n
<AES-256-GCM ciphertext of: {"ed25519_secret":"<b64:32>","x25519_secret":"<b64:32>"}>
```

- `keygen` emits `--out-key` (V2 bundle) and `--out-pub` containing **both** public keys:
  `ed25519:<b64>\nx25519:<b64>\n`.
- `SEALEDGE-KEY-V1` files are read for a deprecation window **only to derive a fresh X25519 key is NOT possible** (independent key), so V1 keys must be re-issued for content ops. `seal keygen --migrate --in-key old.key` MAY generate a new X25519 key alongside the existing Ed25519 key and write a V2 bundle (owner keeps the same identity, gains a key-agreement key). Verification of old signatures is unaffected.
- The `--unencrypted` escape hatch is preserved for CI.

### 4.2 Recipient references

A recipient is identified by its X25519 public key. For convenience the manifest also stores a short, non-authoritative `recipient_id` = `b3:<hex>[..16]` of the recipient X25519 public key, used only to select the right wrapped-CEK entry quickly. Selection MUST fall back to trial-unwrap if the id is absent/ambiguous — the id is a hint, never a trust signal.

## 5. HPKE ciphersuite

Per RFC 9180, using the [`hpke`](https://crates.io/crates/hpke) crate (pure-Rust, `no_std`-capable, WASM-friendly; pin the latest audited release at implementation time and record the exact version in `Cargo.toml` + this doc):

| HPKE component | Choice | Rationale |
|---|---|---|
| KEM | `DHKEM(X25519, HKDF-SHA256)` | Matches our existing X25519 stack |
| KDF | `HKDF-SHA256` | Already used throughout (`hkdf`/`sha2`) |
| AEAD (HPKE) | `ChaCha20Poly1305` | Matches our content AEAD; constant-time, no AES-NI dependence for IoT |
| Mode | **Base** (`mode_base`) with per-recipient ephemeral encapsulation | Ephemeral sender key ⇒ forward secrecy; auth-mode not needed since the manifest is separately Ed25519-signed |

Content chunks keep **XChaCha20-Poly1305** (24-byte random nonce per chunk), unchanged except that the key is now the per-archive CEK.

## 6. Per-archive content encryption

1. `wrap` generates a random 32-byte **CEK** (`OsRng`).
2. Each chunk is encrypted `XChaCha20Poly1305(CEK, nonce24_random, chunk, aad)`; on-disk chunk stays `[nonce:24][ciphertext:N]` (unchanged layout).
3. AAD binding for each chunk is unchanged (`generate_aad(version, profile, device_id, started_at)`); it continues to bind ciphertext to manifest identity fields.
4. Continuity chain is computed over the ciphertext (`segment_hash(nonce||ciphertext)`) exactly as today (C2 verifier is unaffected).
5. `derive_chunk_key(device_secret)` is **removed** from the archive path. The signing secret never touches content encryption.

## 7. Recipient wrapping (HPKE)

For each recipient public key `R_i` (X25519):

```
(enc_i, ct_i) = HPKE.Seal(
    mode        = base,
    pkR         = R_i,
    info        = "sealedge/cek-wrap/v1" || device.id || trst_version,
    aad         = BLAKE3(canonical_manifest_without_encryption_block),
    plaintext   = CEK (32 bytes)
)
```

- `enc_i` is the **encapsulated ephemeral public key** (fresh per recipient ⇒ per-recipient forward secrecy).
- `aad` binds each wrapped CEK to the exact manifest it belongs to, so a wrapped CEK cannot be transplanted onto a different manifest.
- The device owner is simply **recipient #0**, wrapping to the device's own X25519 public key. Additional recipients (auditor, insurer) are added by passing their X25519 public keys to `wrap`.
- Adding a recipient later requires re-wrapping (a new `wrap` run, or a dedicated `seal add-recipient` that re-seals only the CEK to the new key — Phase 2). Because the CEK is per-archive random, adding a recipient does **not** weaken forward secrecy of other archives.

## 8. Manifest `0.2.0` schema

New/changed fields (JSON shown pretty; canonical form is compact and field-ordered per §8.1):

```json
{
  "trst_version": "0.2.0",
  "profile": "generic",
  "device": {
    "id": "…",
    "model": "…",
    "firmware_version": "…",
    "public_key": "ed25519:…",          // signing key (unchanged; C3 cross-check)
    "key_agreement_public": "x25519:…"  // NEW: device's X25519 key
  },
  "metadata": { … },
  "chunk": { … },
  "segments": [ … ],
  "claims": [ … ],
  "encryption": {                        // NEW block
    "content_aead": "XChaCha20Poly1305",
    "hpke": {
      "kem": "DHKEM(X25519,HKDF-SHA256)",
      "kdf": "HKDF-SHA256",
      "aead": "ChaCha20Poly1305"
    },
    "recipients": [
      {
        "recipient_id": "b3:…",          // hint only (§4.2)
        "recipient_pub": "x25519:…",
        "enc": "b64(encapsulated_key)",
        "wrapped_cek": "b64(ciphertext||tag)"
      }
    ]
  },
  "prev_archive_hash": null,
  "signature": "ed25519:…"               // covers everything above except itself
}
```

### 8.1 Canonicalization & signature coverage

- `TrstManifest::serialize_canonical` (the C1 hand-ordered serializer in `crates/seal-protocols/src/archive/manifest.rs`) is extended to emit `device.key_agreement_public` (after `public_key`) and the whole `encryption` block (after `claims`, before `prev_archive_hash`) in a fixed field order. Recipients are serialized in array order; `wrap` MUST emit them in a deterministic order (recipient #0 = device, then as supplied).
- The Ed25519 **signature covers the `encryption` block**, so the recipient set, the device's X25519 key, and every wrapped CEK are integrity-protected and bound to the signer. An attacker cannot add/alter recipients without invalidating the signature.
- Golden vectors (C1/C2) are regenerated for `0.2.0`; a new golden vector locks a full recipient round-trip.

## 9. Flows

**keygen**
- Generate Ed25519 + X25519 keypairs → write `SEALEDGE-KEY-V2` bundle + `.pub` (both public keys).

**wrap** (`seal wrap --in … --out … --device-key dev.key [--recipient x25519:… ]*`)
1. Random CEK; encrypt chunks; build segments + continuity (as today).
2. Recipients = `[device_x25519] + [--recipient …]`; HPKE-Seal CEK to each (§7).
3. Assemble `0.2.0` manifest incl. `encryption` block; canonicalize; **sign with Ed25519**; write archive.

**verify** (public only — CLI `seal verify`, platform `/v1/verify`, WASM)
- Unchanged semantics: signature (C1/C3 cross-check) + continuity (C2). Verifiers parse the `encryption` block only to include it in canonical bytes; they never need any secret. **No capability change.**

**unwrap** (`seal unwrap … --key recipient.key`)
1. Verify signature + continuity first (fail closed).
2. Select the recipient entry matching the caller's X25519 public key (id hint + trial).
3. `CEK = HPKE.Open(skR, enc_i, info, aad, wrapped_cek)`.
4. Decrypt chunks with CEK. **The Ed25519 signing key is never required to read content.**

## 10. Clean break & versioning

- `wrap` emits `trst_version` `0.2.0` exclusively.
- `verify`/`unwrap` accept `0.2.0`. A `0.1.0` manifest is rejected with a clear, actionable error: `unsupported legacy archive format 0.1.0 (pre-C4); re-wrap with sealedge >= <ver>`. No silent behavior.
- Rationale: crates are unpublished / path-only and pre-1.0 (see memory: sealedge crates not published), so a flag-day is acceptable and avoids carrying the insecure master-key decryption path.
- `derive_chunk_key` and the static-static envelope ECDH are removed from the archive path. `envelope.rs`/`hybrid.rs` (the unused RSA `seal_for_recipient`) are evaluated for deletion in the implementation PR (§13).

## 11. Security properties & residual risk

**Achieved**
- **Key separation (G1):** signing secret never encrypts content. Signing-key compromise ⇒ forgery risk only, not confidentiality of past archives.
- **Forward secrecy (G3):** ephemeral HPKE sender keys mean a later readout of a *recipient's* X25519 secret exposes only archives wrapped to that recipient, and only the CEKs — not the ephemeral private keys (never stored). A device X25519 compromise exposes archives wrapped to the device, but **not** those wrapped only to other recipients.
- **Recipient model (G4):** auditors read with their own key; they cannot forge (no signing key).
- **Manifest binding:** the signature and the per-recipient HPKE `aad` bind wrapped CEKs to the exact manifest.

**Residual risk / explicitly out of scope here**
- **Root/device X25519 compromise** still exposes archives wrapped to that device. Mitigation = rotation/revocation (Phase 2, §12).
- **`auth.rs` transport handshake** still uses static-static ECDH from the long-term key. Not fixed here; tracked as a follow-up (recommend ephemeral-static or Noise-style handshake).
- **Recipient privacy:** `recipient_pub` values are in the manifest (who can read is visible). Acceptable for a provenance product; note in threat model.
- Update `docs/technical/threat-model.md` with these deltas.

## 12. Phase 2 (future) — rotation, revocation, key-epoch

Sketch only; manifest reserves room:
- **key-epoch:** add `device.key_epoch: u32`; verifiers can require a minimum epoch.
- **Revocation:** platform maintains a device-key registry (extends the C3 registry) with a `revoked_at` / `min_epoch`; `/v1/verify` can annotate or fail closed on revoked/old-epoch keys.
- **Rotation:** `seal rekey` issues a new X25519 key, publishes it, and (optionally) re-wraps live archives. Compromise-evidence = signed revocation entries in the registry / a published revocation list.

## 13. Implementation plan (post-approval PRs)

1. **seal-protocols:** `0.2.0` manifest types (`key_agreement_public`, `encryption` block), extend `serialize_canonical`, unit tests. (No crypto yet.)
2. **core:** independent X25519 keygen; `SEALEDGE-KEY-V2` bundle; HPKE wrap/unwrap helpers (`hpke` crate); remove `derive_chunk_key` from archive path; unit + KAT tests.
3. **seal-cli:** `keygen` (dual key + V2), `wrap --recipient`, `unwrap --key` (recipient), legacy-reject; acceptance tests + golden vectors.
4. **platform + wasm:** parse `encryption` block into canonical bytes (verify unaffected); regenerate C1/C2 golden vectors; confirm no decryption capability added.
5. **docs:** update `format.md`, `threat-model.md`, `CLAUDE.md` examples; changelog.

Each PR keeps `./scripts/ci-check.sh` green (fmt, clippy `-D warnings`, workspace tests, WASM build).

## 14. Open questions

- OQ1 — Do we want `seal add-recipient` (re-seal CEK only) in the first implementation, or defer to Phase 2? (Leaning defer.)
- OQ2 — Should `verify`-only consumers reject archives with **zero** recipients (encryption present but unreadable by anyone), or allow "sign-only, unencrypted" archives as a distinct mode? (Recommend an explicit `encryption: null` sign-only mode rather than an empty recipient list.)
- OQ3 — Exact `hpke` crate version/features to pin (confirm audit status at implementation time).
