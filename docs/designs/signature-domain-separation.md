<!--
Copyright (c) 2025 TRUSTEDGE LABS LLC
MPL-2.0: https://mozilla.org/MPL/2.0/
Project: sealedge — Privacy and trust at the edge.
GitHub: https://github.com/TrustEdge-Labs/sealedge
-->

# Tracking: domain separation for chunk & auth signatures

**Status:** PROPOSED (tracking artifact — not scheduled)
**Owner:** unassigned
**Origin:** split out of `docs/designs/envelope-v3-authenticated-metadata.md`
(Non-goals), which lists this as "tracked separately." This file *is* that track.

## Problem

Ed25519 signatures in the crate are produced over hashes without a per-context
domain-separation prefix, so a signature made in one context is, in principle,
byte-identical to one that would be valid in another. Two signature families are in
scope:

- **Per-chunk manifest signatures** — each `NetworkChunk` signs `blake3(manifest_bytes)`
  (see `format.rs` / `envelope.rs` chunk signing).
- **`auth.rs` handshake signatures** — Ed25519 signatures over challenge/transcript
  material in the mutual-auth path.

Envelope v3's `header_sig` (see the envelope-v3 design) *will* carry a mandatory
domain-separation prefix (`b"SEALEDGE_ENVELOPE_V3_HEADER\0"`), and manifest
signatures already use `b"sealedge.manifest.v1"` (SECURITY.md). The gap is that the
chunk and auth families predate that discipline and are not individually
domain-separated, so a cross-family confusion argument cannot yet be closed by
construction.

## Why it is not part of envelope v3

v3 closes the confusion path *for `header_sig`* by prefixing it and asserting
(Acceptance) that a chunk-manifest or `auth.rs` signature is not accepted as a
`header_sig`. That is sufficient for v3's goal. Retrofitting prefixes onto the
existing chunk and auth signatures is a **wire-format change** to already-emitted
archives and live handshakes — a separate migration with its own compatibility
story — so it is deliberately out of v3 scope.

## Scope when scheduled

- Add distinct domain-separation prefixes to chunk-manifest signing/verification and
  to `auth.rs` signing/verification.
- Decide the compatibility story (versioned verify accepting both, or a hard cutover)
  — chunk signatures live in persisted `.seal`/envelope archives; auth signatures are
  ephemeral per-session, so the two families can migrate on independent timelines.
- Cross-family negative tests: a signature from one family must never verify as
  another.

## Acceptance (when scheduled)

- Every Ed25519 signing site in the crate signs over a context-prefixed preimage, and
  the set of prefixes is enumerated in one place.
- A signature produced for family A fails verification when presented as family B, for
  every ordered pair of families.
- Compatibility path (if chosen) is covered by round-trip tests against fixtures from
  the pre-retrofit format.

## Links

- `docs/designs/envelope-v3-authenticated-metadata.md` — the `header_sig` prefix and
  the cross-object confusion Acceptance test that motivated splitting this out.
- SECURITY.md — "Domain Separation" (existing `b"sealedge.manifest.v1"` precedent).
