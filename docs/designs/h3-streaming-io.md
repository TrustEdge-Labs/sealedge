<!--
Copyright (c) 2025 TRUSTEDGE LABS LLC
This source code is subject to the terms of the Mozilla Public License, v. 2.0.
If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

Project: sealedge — Privacy and trust at the edge.
-->

# H3 — Streaming I/O (constant-memory wrap + bounded reads)

Status: **IMPLEMENTED** (P1 + P2). Approved with amendments SA1–SA4 + nits
N1–N3, all folded in below and shipped. Streaming wrap (`ArchiveWriter`) and the
bounded read paths (stream-hash `validate_archive`, `read_manifest`, streaming
`unwrap`/`emit-request`/`hash_file`, manifest/sig caps) are implemented; no format
change, golden vectors + seeded output byte-identical.

The biggest remaining product gap. Two problems, one theme (never hold a whole
payload in RAM):

1. **`wrap` uses ~2× payload RAM.** `handle_wrap` does `fs::read(input)` (1×)
   then accumulates every encrypted chunk in `encrypted_chunks: Vec<Vec<u8>>`
   (another ~1×) before `write_archive` flushes them. At GB scale on an edge
   camera this breaks the stated use case.
2. **Unbounded reads are a latent DoS.** `read_archive` / `validate_archive`
   `read_to_end` **every** chunk into RAM; `hash_file` does `fs::read` of a whole
   binary/SBOM; `read_archive` `read_to_string`s `manifest.json` with no cap. A
   hostile or oversized archive can OOM a verifier/ingest path.

**Non-goals / invariants:**
- **No format change.** The on-disk `.seal` layout is byte-for-byte identical
  (`manifest.json`, `signatures/manifest.sig`, `chunks/NNNNN.bin`).
- **Golden vectors unchanged.** The canonical manifest and archive digest for the
  existing fixtures must be identical (streaming changes *how* bytes are produced,
  not *which*).
- **Seeded determinism preserved.** `--seed` wrap stays byte-identical: chunk
  boundaries, CEK, and per-chunk nonces are generated in the same order.

---

## 1. Streaming wrap (P1)

### 1.1 Core: `ArchiveWriter` (push-based, constant memory)

Add to `sealedge-core` (`archive.rs`) a writer that owns the streaming discipline
so the CLI just drives it and it's unit-testable in core:

```rust
pub struct ArchiveWriter { /* base dir, chunks dir, chunk index, chain state */ }

impl ArchiveWriter {
    /// Create the .seal directory skeleton (chunks/, signatures/).
    pub fn create<P: AsRef<Path>>(base_dir: P) -> Result<Self, ArchiveError>;

    /// Write one already-encrypted (or plaintext, sign-only) chunk to
    /// chunks/NNNNN.bin, returning its BLAKE3 hash + advanced continuity hash.
    /// Holds only this chunk in memory.
    pub fn push_chunk(&mut self, stored_bytes: &[u8]) -> Result<ChunkOutcome, ArchiveError>;

    /// After all chunks: write manifest.json + signatures/manifest.sig.
    /// ERRORS if the serialized manifest exceeds `MANIFEST_MAX_BYTES` — the
    /// producer guard for SA1 (see §2.1): wrap must never emit a manifest a
    /// compliant reader would refuse.
    pub fn finalize(self, manifest: &TrstManifest, detached_sig: &[u8]) -> Result<(), ArchiveError>;
}

// N2: stored_len is free here and handy for CLI stats (SegmentInfo doesn't need it).
pub struct ChunkOutcome { pub index: u32, pub blake3: [u8; 32], pub continuity: [u8; 32], pub stored_len: usize }
```

`push_chunk` computes `segment_hash(stored_bytes)`, advances the internal chain
(`chain_next`), writes the file, and returns the hashes the caller needs to build
its `SegmentInfo`. Peak core RAM: one chunk file's bytes.

### 1.2 CLI: stream the input

`handle_wrap` replaces `fs::read(input)` + `input_data.chunks().collect()` +
`encrypted_chunks` with a chunk-at-a-time loop over a `BufReader`:

```
reader = BufReader(File::open(input))
writer = ArchiveWriter::create(out)
loop:
    buf = read_exact_or_eof(reader, chunk_size)   // full chunk_size, last may be short
    if buf empty && first: bail "Input file is empty"
    if buf empty: break
    stored = match cek { Some => [nonce24 || encrypt_segment(...)], None => buf }
    outcome = writer.push_chunk(&stored)
    segments.push(SegmentInfo { ..from outcome.. })
build manifest (encryption block = HPKE-wrap CEK, as today); sign canonical bytes
writer.finalize(&manifest, sig.as_bytes())
```

Peak CLI RAM: `chunk_size` plaintext + its ciphertext (+ constant overhead) —
**O(1) in payload size**. Chunk boundaries match `slice::chunks` exactly, so the
CEK/nonce sequence and every hash are unchanged ⇒ golden vectors + seeded output
identical. `read_exact_or_eof` fills a full `chunk_size` buffer, coalescing short
`BufRead` reads, and returns a final short/empty buffer at EOF.

> **SA3 — the determinism invariant, stated explicitly.** Seeded (`--seed`) wrap
> draws from **two** RNG streams in a **fixed interleaving** that the streaming
> rewrite MUST preserve:
> 1. **CEK + HPKE ephemerals** from the rand_core-0.6 `seed_rng` — the CEK is
>    drawn **once, pre-loop**;
> 2. **per-chunk nonces** from the `rng` (`generate_seeded_nonce24`) — drawn
>    **in-loop, one per chunk in index order**;
> 3. the **HPKE wrap of the CEK** to recipients — **post-loop**, when the manifest
>    encryption block is built.
>
> Order = CEK (pre) → nonce₀, nonce₁, … (in) → HPKE-wrap (post). The
> seeded-fixture acceptance test pins the resulting bytes so a future "tidy-up"
> that reorders these draws fails loudly instead of silently changing output.

> **N1 — empty-input error.** Reuse the existing message verbatim
> (`"Input file is empty"`) so acceptance tests don't churn.

`write_archive` (the "collect then write" API) stays for tests and small in-memory
callers; the CLI stops using it.

---

## 2. Bounded reads (P2)

The archive is written once but read on every `verify`, `unwrap`,
`verify-chronicle`, `emit-request` — the DoS surface. Add bounded/streaming read
paths in core and migrate each caller to the narrowest one it needs.

> **SA2 — `verify` today reads the chunks twice.** `handle_verify` calls
> `read_archive` (loading *all* chunk bytes) purely to peek the manifest, discards
> them, then `validate_archive` → `read_archive` loads them *all again* to hash.
> P2 replaces the first with `read_manifest` (no chunks) and makes the second
> stream-hash — so verify goes from **2× full-payload reads + unbounded RAM** to
> **1× streamed pass + O(buffer) RAM**.

| Caller | Needs today (via `read_archive`) | Change to |
|---|---|---|
| `verify` → `validate_archive` | all chunk bytes, to hash + chain | **stream-hash** each chunk file (fixed buffer → BLAKE3), never hold all |
| `verify` (manifest peek), `verify-chronicle`, `wrap --prev-archive` | `(manifest, _chunks)` — chunks discarded | new `read_manifest(dir)` — parse `manifest.json` + sig only |
| `unwrap` | all chunk bytes, to decrypt | **stream** per chunk: read → decrypt → write output; one chunk in RAM |
| `emit-request` | all chunk bytes, to hash | **stream-hash** per chunk |
| `hash_file` (attestations) | whole file (`fs::read`) | **stream** BLAKE3 over a `BufReader` |

Core additions:
- `validate_archive` reworked to stream-hash (its own file read loop; no
  `read_archive`). Same checks (hash match, continuity chain, unreferenced-chunk,
  manifest validity), constant RAM.
- `read_manifest(dir) -> (TrstManifest, Vec<u8> sig)` — bounded (see §2.1).
  **SA4:** it preserves `read_archive`'s embedded-vs-detached signature
  consistency check (`archive.rs:83-88`: error on `embedded_sig != detached_sig`),
  so swapping callers onto it changes no read semantics.
- `hash_file` streams via `blake3::Hasher::update` over fixed buffers.
- `unwrap`/`emit-request` iterate `chunks/NNNNN.bin` by index from the manifest,
  processing one at a time.

**N3:** `read_archive` (load-all) is retained for compatibility and small callers
but gets a doc-comment — *"compat / small-caller API; do NOT use on verify/ingest
paths (loads every chunk into RAM). Use `validate_archive`, `read_manifest`, or a
per-chunk stream instead."* — so the DoS can't sneak back in via the next caller.

### 2.1 Manifest / signature caps (defense-in-depth)

`manifest.json` and `manifest.sig` are small by construction; a hostile archive
could make them huge. `read_manifest` (and `read_archive`) cap each with a
`.take(MANIFEST_MAX_BYTES)` bounded read (proposed **8 MiB** manifest, **4 KiB**
sig) and error past the cap, rather than `read_to_string`/`read_to_end` unbounded.

> **SA1 (must-fix) — the cap needs a producer-side twin.** `--chunk-size` has a
> ceiling (`MAX_CHUNK_SIZE`) but **no floor**: `wrap --chunk-size 4096` on a 1 GiB
> input yields ~260k segments ≈ a ~50 MB `manifest.json` — which the 8 MiB reader
> cap would then **reject at verify time**. A cap without a producer guard is a
> correctness bug (wrap emits an unverifiable archive).
>
> **Invariant:** *wrap must never produce a manifest a compliant reader refuses.*
> **Rule:** `ArchiveWriter::finalize` errors when the serialized manifest exceeds
> `MANIFEST_MAX_BYTES` — message *"manifest exceeds the reader cap
> (<n> > <MANIFEST_MAX_BYTES>); increase --chunk-size"*. `MANIFEST_MAX_BYTES` is
> **one shared `pub const` in core**, used by both `finalize` (producer) and
> `read_manifest`/`read_archive` (consumer), so the two can't drift. This is what
> makes the OQ3 cap safe rather than a footgun.

---

## 3. Threat model

Extends **T-DoS** (resource exhaustion): the verify/ingest path is now bounded to
one chunk buffer regardless of archive size; `wrap` is bounded regardless of input
size. Note in `docs/technical/threat-model.md` (fits under an availability entry).

---

## 4. Implementation plan

- **P1 — streaming wrap:** core `ArchiveWriter` (+ unit tests); rewrite
  `handle_wrap` to stream; `read_exact_or_eof` helper. Acceptance: existing golden
  vectors unchanged; seeded wrap byte-identical (compare vs a pre-refactor fixture);
  a large-input test (e.g. 64 MiB via small chunk_size) asserts success; all
  existing seal-cli acceptance tests still pass.
- **P2 — bounded reads:** `validate_archive` stream-hash; `read_manifest`;
  `hash_file` stream; `unwrap` + `emit-request` stream; manifest/sig caps. Migrate
  the five call sites. Acceptance: verify/unwrap/emit round-trips unchanged; a
  crafted oversized-manifest test hits the cap; unit test that `unwrap(wrap(x)) == x`
  for a multi-chunk input.

Each phase lands CI-green (`./scripts/ci-check.sh`).

---

## 5. Open questions — RESOLVED on review

- **OQ1 — write API → core `ArchiveWriter`.** The seam is unit-testable in core.
- **OQ2 — P2 scope → all five read sites + caps now.** A half-migrated read
  discipline is exactly how the unbounded reads return.
- **OQ3 — manifest cap → 8 MiB manifest / 4 KiB sig**, conditional on **SA1**: the
  cap ships with the `ArchiveWriter::finalize` producer guard (shared
  `MANIFEST_MAX_BYTES`). Cap without guard = correctness bug; cap with guard =
  defense-in-depth.
