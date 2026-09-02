//
// Copyright (c) 2025 TRUSTEDGE LABS LLC
// This source code is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Project: sealedge — Privacy and trust at the edge.
//

use crate::TrstManifest;
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub use crate::error::{ArchiveError, ChainError, ManifestError};

/// Type alias for chunk data (index, bytes)
type ChunkData = Vec<(usize, Vec<u8>)>;

/// Maximum accepted `manifest.json` size (H3 SA1). A single shared constant so
/// the producer guard ([`ArchiveWriter::finalize`]) and the bounded readers
/// ([`read_manifest`], [`read_archive`]) can never drift: `wrap` refuses to emit
/// a manifest a compliant reader would reject, and readers refuse a hostile
/// oversized manifest (parse-DoS defense-in-depth).
pub const MANIFEST_MAX_BYTES: usize = 8 * 1024 * 1024;
/// Maximum accepted detached-signature size (H3). A signature is ~100 bytes; this
/// is a generous defense-in-depth bound.
pub const SIG_MAX_BYTES: usize = 4 * 1024;

/// Producer cap on plaintext chunk size (256 MiB). `seal wrap` refuses a larger
/// `--chunk-size`; the reader caps the *stored* chunk symmetrically (see
/// [`MAX_STORED_CHUNK_BYTES`]) so producer and consumer can't drift (SA1-style, T16).
pub const MAX_CHUNK_SIZE_BYTES: usize = 256 * 1024 * 1024;
/// Reader cap on a stored chunk file: the plaintext cap plus one
/// XChaCha20-Poly1305 nonce (24 bytes) and AEAD tag (16 bytes). A chunk file larger
/// than this is rejected, so a hostile archive can't exhaust memory on the
/// unwrap/verify paths (closes the T16 residual on per-chunk reads).
pub const MAX_STORED_CHUNK_BYTES: usize = MAX_CHUNK_SIZE_BYTES + 24 + 16;

/// Outcome of streaming one chunk through [`ArchiveWriter::push_chunk`].
#[derive(Debug, Clone, Copy)]
pub struct ChunkOutcome {
    pub index: u32,
    pub blake3: [u8; 32],
    pub continuity: [u8; 32],
    /// Bytes written to `chunks/NNNNN.bin` (N2 — handy for CLI stats).
    pub stored_len: usize,
}

/// Streaming, constant-memory `.seal` writer (H3 P1).
///
/// `create` lays down the directory skeleton; each `push_chunk` writes one chunk
/// file and advances the BLAKE3 continuity chain, holding only that chunk in
/// memory; `finalize` writes the manifest + detached signature. Peak memory is
/// one chunk regardless of total payload size — versus the "collect every
/// ciphertext then flush" [`write_archive`] path, which is ~1× payload.
pub struct ArchiveWriter {
    base_path: PathBuf,
    chunks_dir: PathBuf,
    next_index: u32,
    chain_state: [u8; 32],
}

impl ArchiveWriter {
    /// Create the `.seal` directory skeleton (`chunks/`, `signatures/`) and seed
    /// the continuity chain from genesis.
    pub fn create<P: AsRef<Path>>(base_dir: P) -> Result<Self, ArchiveError> {
        let base_path = base_dir.as_ref().to_path_buf();
        let chunks_dir = base_path.join("chunks");
        fs::create_dir_all(&base_path)?;
        fs::create_dir_all(base_path.join("signatures"))?;
        fs::create_dir_all(&chunks_dir)?;
        Ok(Self {
            base_path,
            chunks_dir,
            next_index: 0,
            chain_state: crate::chain::genesis(),
        })
    }

    /// Write one already-stored chunk (encrypted `[nonce||ct]`, or plaintext in
    /// sign-only mode) to `chunks/NNNNN.bin`, hashing it and advancing the
    /// continuity chain. Returns the hashes the caller needs to build its
    /// `SegmentInfo`. Holds only `stored_bytes` in memory.
    pub fn push_chunk(&mut self, stored_bytes: &[u8]) -> Result<ChunkOutcome, ArchiveError> {
        let blake3 = crate::chain::segment_hash(stored_bytes);
        let continuity = crate::chain::chain_next(&self.chain_state, &blake3);

        let filename = format!("{:05}.bin", self.next_index);
        let mut f = File::create(self.chunks_dir.join(filename))?;
        f.write_all(stored_bytes)?;

        let outcome = ChunkOutcome {
            index: self.next_index,
            blake3,
            continuity,
            stored_len: stored_bytes.len(),
        };
        self.chain_state = continuity;
        self.next_index += 1;
        Ok(outcome)
    }

    /// Finalize: write `manifest.json` + `signatures/manifest.sig`.
    ///
    /// Errors (SA1) if the serialized manifest exceeds [`MANIFEST_MAX_BYTES`] —
    /// `wrap` must never emit a manifest a compliant reader would refuse; the fix
    /// is a larger `--chunk-size` (fewer segments). Also checks the segment count
    /// matches the chunks actually written.
    pub fn finalize(
        self,
        manifest: &TrstManifest,
        detached_sig: &[u8],
    ) -> Result<(), ArchiveError> {
        if manifest.segments.len() != self.next_index as usize {
            return Err(ArchiveError::SchemaMismatch(format!(
                "Chunk count mismatch: {} chunks written, {} segments in manifest",
                self.next_index,
                manifest.segments.len()
            )));
        }

        let manifest_json = serde_json::to_string_pretty(manifest)?;
        if manifest_json.len() > MANIFEST_MAX_BYTES {
            return Err(ArchiveError::SchemaMismatch(format!(
                "manifest exceeds the reader cap ({} > {} bytes); increase --chunk-size",
                manifest_json.len(),
                MANIFEST_MAX_BYTES
            )));
        }

        let mut manifest_file = File::create(self.base_path.join("manifest.json"))?;
        manifest_file.write_all(manifest_json.as_bytes())?;

        let mut sig_file = File::create(self.base_path.join("signatures/manifest.sig"))?;
        sig_file.write_all(detached_sig)?;
        Ok(())
    }
}

/// Write a complete .trst archive with manifest, signature, and chunk files.
///
/// N3: compat / small-caller API — it collects every chunk ciphertext in memory.
/// Do NOT use it on verify/ingest or large-payload paths; use [`ArchiveWriter`]
/// to stream writes, and [`validate_archive`] / [`read_manifest`] / per-chunk
/// streaming to read.
pub fn write_archive<P: AsRef<Path>>(
    base_dir: P,
    manifest: &TrstManifest,
    chunk_ciphertexts: Vec<Vec<u8>>,
    detached_sig: &[u8],
) -> Result<(), ArchiveError> {
    let base_path = base_dir.as_ref();

    // Validate inputs
    if chunk_ciphertexts.len() != manifest.segments.len() {
        return Err(ArchiveError::SchemaMismatch(format!(
            "Chunk count mismatch: {} chunks provided, {} segments in manifest",
            chunk_ciphertexts.len(),
            manifest.segments.len()
        )));
    }

    // Create directory structure
    fs::create_dir_all(base_path)?;
    fs::create_dir_all(base_path.join("signatures"))?;
    fs::create_dir_all(base_path.join("chunks"))?;

    // Write manifest.json
    let manifest_json = serde_json::to_string_pretty(manifest)?;
    let mut manifest_file = File::create(base_path.join("manifest.json"))?;
    manifest_file.write_all(manifest_json.as_bytes())?;

    // Write detached signature
    let mut sig_file = File::create(base_path.join("signatures/manifest.sig"))?;
    sig_file.write_all(detached_sig)?;

    // Write chunk files with zero-padded five-digit names
    for (index, chunk_data) in chunk_ciphertexts.iter().enumerate() {
        let chunk_filename = format!("{:05}.bin", index);
        let chunk_path = base_path.join("chunks").join(chunk_filename);
        let mut chunk_file = File::create(chunk_path)?;
        chunk_file.write_all(chunk_data)?;
    }

    Ok(())
}

/// Read at most `max` bytes from `path`, erroring if the file exceeds the cap
/// (H3 — bounded reads / parse-DoS defense). Reads `max + 1` and rejects if the
/// extra byte materializes.
fn read_capped(path: &Path, max: usize) -> Result<Vec<u8>, ArchiveError> {
    let f = File::open(path)?;
    let mut buf = Vec::new();
    f.take(max as u64 + 1).read_to_end(&mut buf)?;
    if buf.len() > max {
        return Err(ArchiveError::SchemaMismatch(format!(
            "{} exceeds the {}-byte cap",
            path.display(),
            max
        )));
    }
    Ok(buf)
}

/// BLAKE3-hash a chunk file by streaming it through a fixed 64 KiB buffer (H3) —
/// bounded RAM regardless of chunk size. Matches [`crate::chain::segment_hash`]
/// (plain BLAKE3 of the file bytes).
/// Open a chunk file, mapping a missing file to [`ArchiveError::MissingChunk`].
/// Opening directly (rather than `exists()` then `open()`) closes a TOCTOU where
/// the file could vanish between the check and the open (F11).
fn open_chunk(path: &Path, filename: &str) -> Result<File, ArchiveError> {
    File::open(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => ArchiveError::MissingChunk(filename.to_string()),
        _ => ArchiveError::from(e),
    })
}

fn stream_hash_chunk(path: &Path, filename: &str) -> Result<[u8; 32], ArchiveError> {
    let f = open_chunk(path, filename)?;
    let mut reader = std::io::BufReader::new(f);
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total: usize = 0;
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        // F10: reject a chunk file larger than any wrap could have produced, so a
        // hostile archive can't drive unbounded work on the verify path.
        total = total.saturating_add(n);
        if total > MAX_STORED_CHUNK_BYTES {
            return Err(ArchiveError::SchemaMismatch(format!(
                "chunk {filename} exceeds the {MAX_STORED_CHUNK_BYTES}-byte cap"
            )));
        }
        hasher.update(&buf[..n]);
    }
    Ok(*hasher.finalize().as_bytes())
}

/// Read and parse `manifest.json` + the detached signature only — bounded and
/// chunk-free (H3). This is the read path for callers that need the manifest but
/// not the payload (`verify` peek, `verify-chronicle`, `wrap --prev-archive`);
/// it does NOT load any chunk bytes, so it is safe on the ingest/DoS surface.
///
/// Both files are size-capped ([`MANIFEST_MAX_BYTES`] / [`SIG_MAX_BYTES`]), and
/// the embedded-vs-detached signature consistency check is preserved (SA4), so
/// swapping callers off `read_archive` changes no read semantics.
pub fn read_manifest<P: AsRef<Path>>(base_dir: P) -> Result<(TrstManifest, Vec<u8>), ArchiveError> {
    let base_path = base_dir.as_ref();

    let manifest_bytes = read_capped(&base_path.join("manifest.json"), MANIFEST_MAX_BYTES)?;
    let manifest: TrstManifest = serde_json::from_slice(&manifest_bytes)?;

    let detached_sig = read_capped(&base_path.join("signatures/manifest.sig"), SIG_MAX_BYTES)?;

    if let Some(ref embedded_sig) = manifest.signature {
        let detached_sig_str = String::from_utf8_lossy(&detached_sig);
        if embedded_sig != &detached_sig_str {
            return Err(ArchiveError::SignatureMismatch);
        }
    }

    Ok((manifest, detached_sig))
}

/// Read a complete .trst archive and return manifest and chunk data.
///
/// N3: compat / small-caller API — it loads EVERY chunk into memory. Do NOT use
/// it on verify/ingest or large-payload paths; use [`validate_archive`] (stream-
/// hashes), [`read_manifest`] (manifest only), or a per-chunk stream instead.
pub fn read_archive<P: AsRef<Path>>(
    base_dir: P,
) -> Result<(TrstManifest, ChunkData), ArchiveError> {
    let base_path = base_dir.as_ref();

    // Manifest + signature (bounded, sig-consistency checked).
    let (manifest, _detached_sig) = read_manifest(base_path)?;

    // Read chunk files
    let chunks_dir = base_path.join("chunks");
    let mut chunk_data = Vec::new();

    for (expected_index, segment) in manifest.segments.iter().enumerate() {
        let chunk_filename = format!("{:05}.bin", expected_index);
        let chunk_path = chunks_dir.join(&chunk_filename);

        // Validate the declared name, then open directly (missing -> MissingChunk,
        // no exists()/open() TOCTOU, F11).
        if segment.chunk_file != chunk_filename {
            return Err(ArchiveError::InvalidChunkIndex {
                expected: expected_index,
                found: parse_chunk_index(&segment.chunk_file)?,
            });
        }

        // Read chunk data with a bounded read (stored-chunk cap, F10): read one
        // byte past the cap and reject if the file is larger.
        let chunk_file = open_chunk(&chunk_path, &chunk_filename)?;
        let mut chunk_bytes = Vec::new();
        chunk_file
            .take(MAX_STORED_CHUNK_BYTES as u64 + 1)
            .read_to_end(&mut chunk_bytes)?;
        if chunk_bytes.len() > MAX_STORED_CHUNK_BYTES {
            return Err(ArchiveError::SchemaMismatch(format!(
                "chunk {chunk_filename} exceeds the {MAX_STORED_CHUNK_BYTES}-byte cap"
            )));
        }

        chunk_data.push((expected_index, chunk_bytes));
    }

    Ok((manifest, chunk_data))
}

/// Validate archive integrity including continuity chain.
///
/// H3: reads the manifest bounded ([`read_manifest`]) and **stream-hashes** each
/// chunk file through a fixed buffer — it never loads the payload into memory, so
/// verification is bounded to one buffer regardless of archive size (closes the
/// unbounded-read DoS on the verify path).
pub fn validate_archive<P: AsRef<Path>>(base_dir: P) -> Result<(), ArchiveError> {
    let base_path = base_dir.as_ref();
    let (manifest, _sig) = read_manifest(base_path)?;

    // Check for unreferenced chunk files (SEC-02)
    let expected_chunks: HashSet<String> = manifest
        .segments
        .iter()
        .map(|s| s.chunk_file.clone())
        .collect();

    let chunks_dir = base_path.join("chunks");
    if chunks_dir.is_dir() {
        for entry in std::fs::read_dir(&chunks_dir)? {
            let entry = entry?;
            let file_name = entry.file_name().to_string_lossy().to_string();
            if file_name.ends_with(".bin") && !expected_chunks.contains(&file_name) {
                return Err(ArchiveError::UnreferencedChunk(file_name));
            }
        }
    }

    // Validate manifest structure
    manifest.validate().map_err(|e| {
        ArchiveError::ValidationFailed(format!("Manifest validation failed: {}", e))
    })?;

    // Validate chunk hashes and continuity chain, stream-hashing each chunk.
    let mut chain_segments = Vec::with_capacity(manifest.segments.len());

    for (index, segment) in manifest.segments.iter().enumerate() {
        let chunk_filename = format!("{:05}.bin", index);
        let chunk_path = chunks_dir.join(&chunk_filename);

        // Validate the declared name (no FS access), then open directly — a missing
        // file maps to MissingChunk, avoiding an exists()/open() TOCTOU (F11).
        if segment.chunk_file != chunk_filename {
            return Err(ArchiveError::InvalidChunkIndex {
                expected: index,
                found: parse_chunk_index(&segment.chunk_file)?,
            });
        }

        // Stream-hash the chunk (bounded RAM, capped size) and match the stored hash.
        let computed_hash = stream_hash_chunk(&chunk_path, &chunk_filename)?;
        let computed_hash_hex = hex::encode(computed_hash);
        if segment.blake3_hash != computed_hash_hex {
            return Err(ArchiveError::ValidationFailed(format!(
                "Chunk {} hash mismatch: expected {}, computed {}",
                index, segment.blake3_hash, computed_hash_hex
            )));
        }

        // Parse stored continuity hash
        let stored_continuity = hex::decode(&segment.continuity_hash).map_err(|_| {
            ArchiveError::ValidationFailed(format!(
                "Invalid continuity hash format: {}",
                segment.continuity_hash
            ))
        })?;
        if stored_continuity.len() != 32 {
            return Err(ArchiveError::ValidationFailed(format!(
                "Continuity hash must be 32 bytes, got {}",
                stored_continuity.len()
            )));
        }
        let mut continuity_array = [0u8; 32];
        continuity_array.copy_from_slice(&stored_continuity);

        chain_segments.push(crate::chain::ChainSegment {
            index,
            stored_hash: computed_hash,
            stored_continuity: continuity_array,
        });
    }

    // Validate continuity chain
    crate::chain::validate_chain(&chain_segments)?;

    Ok(())
}

/// Parse chunk index from filename (e.g., "00002.bin" -> 2)
fn parse_chunk_index(filename: &str) -> Result<usize, ArchiveError> {
    if !filename.ends_with(".bin") || filename.len() != 9 {
        return Err(ArchiveError::SchemaMismatch(format!(
            "Invalid chunk filename format: {}",
            filename
        )));
    }

    let index_str = &filename[0..5];
    index_str.parse::<usize>().map_err(|_| {
        ArchiveError::SchemaMismatch(format!("Invalid chunk index in filename: {}", filename))
    })
}

/// Get the expected archive directory name for a given ID
pub fn archive_dir_name(id: &str) -> String {
    format!("clip-{}.seal", id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProfileMetadata, SegmentInfo, TrstManifest};
    use tempfile::TempDir;

    fn create_test_manifest() -> TrstManifest {
        let mut manifest = TrstManifest::new_cam_video();
        manifest.device.id = "TEST001".to_string();
        manifest.device.public_key = "ed25519:test_key".to_string();
        if let ProfileMetadata::CamVideo(ref mut m) = manifest.metadata {
            m.started_at = "2025-01-15T10:30:00Z".to_string();
            m.ended_at = "2025-01-15T10:30:06Z".to_string();
        }

        // Compute continuity chain up front
        let genesis = crate::chain::genesis();
        let hash0 = crate::chain::segment_hash(b"test_chunk_0");
        let hash1 = crate::chain::segment_hash(b"test_chunk_1");
        let hash2 = crate::chain::segment_hash(b"test_chunk_2");

        let continuity0 = crate::chain::chain_next(&genesis, &hash0);
        let continuity1 = crate::chain::chain_next(&continuity0, &hash1);
        let continuity2 = crate::chain::chain_next(&continuity1, &hash2);

        manifest.segments = vec![
            SegmentInfo {
                chunk_file: "00000.bin".to_string(),
                blake3_hash: hex::encode(hash0),
                start_time: "2025-01-15T10:30:00Z".to_string(),
                duration_seconds: 2.0,
                continuity_hash: hex::encode(continuity0),
            },
            SegmentInfo {
                chunk_file: "00001.bin".to_string(),
                blake3_hash: hex::encode(hash1),
                start_time: "2025-01-15T10:30:02Z".to_string(),
                duration_seconds: 2.0,
                continuity_hash: hex::encode(continuity1),
            },
            SegmentInfo {
                chunk_file: "00002.bin".to_string(),
                blake3_hash: hex::encode(hash2),
                start_time: "2025-01-15T10:30:04Z".to_string(),
                duration_seconds: 2.0,
                continuity_hash: hex::encode(continuity2),
            },
        ];

        manifest.signature = Some("ed25519:test_signature".to_string());

        manifest
    }

    #[test]
    fn test_write_and_read_archive_round_trip() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("test.seal");

        let manifest = create_test_manifest();
        let chunk_data = vec![
            b"test_chunk_0".to_vec(),
            b"test_chunk_1".to_vec(),
            b"test_chunk_2".to_vec(),
        ];
        let detached_sig = b"ed25519:test_signature";

        // Write archive
        write_archive(&archive_path, &manifest, chunk_data.clone(), detached_sig).unwrap();

        // Verify directory structure exists
        assert!(archive_path.join("manifest.json").exists());
        assert!(archive_path.join("signatures/manifest.sig").exists());
        assert!(archive_path.join("chunks/00000.bin").exists());
        assert!(archive_path.join("chunks/00001.bin").exists());
        assert!(archive_path.join("chunks/00002.bin").exists());

        // Read archive back
        let (read_manifest, read_chunks) = read_archive(&archive_path).unwrap();

        // Verify manifest matches
        assert_eq!(read_manifest.device.id, manifest.device.id);
        assert_eq!(read_manifest.segments.len(), manifest.segments.len());

        // Verify chunks match
        assert_eq!(read_chunks.len(), 3);
        for (i, (index, chunk_bytes)) in read_chunks.iter().enumerate() {
            assert_eq!(*index, i);
            assert_eq!(*chunk_bytes, chunk_data[i]);
        }
    }

    #[test]
    fn test_archive_validation() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("test.seal");

        let manifest = create_test_manifest();
        let chunk_data = vec![
            b"test_chunk_0".to_vec(),
            b"test_chunk_1".to_vec(),
            b"test_chunk_2".to_vec(),
        ];
        let detached_sig = b"ed25519:test_signature";

        // Write archive
        write_archive(&archive_path, &manifest, chunk_data, detached_sig).unwrap();

        // Validate should pass
        validate_archive(&archive_path).unwrap();
    }

    #[test]
    fn test_mutation_missing_chunk_causes_validation_failure() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("test.seal");

        let manifest = create_test_manifest();
        let chunk_data = vec![
            b"test_chunk_0".to_vec(),
            b"test_chunk_1".to_vec(),
            b"test_chunk_2".to_vec(),
        ];
        let detached_sig = b"ed25519:test_signature";

        // Write archive
        write_archive(&archive_path, &manifest, chunk_data, detached_sig).unwrap();

        // Delete chunks/00002.bin
        let chunk_to_delete = archive_path.join("chunks/00002.bin");
        fs::remove_file(chunk_to_delete).unwrap();

        // Validation should fail
        let result = validate_archive(&archive_path);
        assert!(result.is_err());
        match result.unwrap_err() {
            ArchiveError::MissingChunk(filename) => {
                assert_eq!(filename, "00002.bin");
            }
            other => panic!("Expected MissingChunk error, got {:?}", other),
        }
    }

    #[test]
    fn test_schema_mismatch_chunk_count() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("test.seal");

        let manifest = create_test_manifest();
        let wrong_chunk_data = vec![
            b"test_chunk_0".to_vec(),
            b"test_chunk_1".to_vec(),
            // Missing chunk 2
        ];
        let detached_sig = b"ed25519:test_signature";

        // Should fail to write
        let result = write_archive(&archive_path, &manifest, wrong_chunk_data, detached_sig);
        assert!(result.is_err());
        match result.unwrap_err() {
            ArchiveError::SchemaMismatch(msg) => {
                assert!(msg.contains("Chunk count mismatch"));
            }
            other => panic!("Expected SchemaMismatch error, got {:?}", other),
        }
    }

    #[test]
    fn test_signature_mismatch() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("test.seal");

        let mut manifest = create_test_manifest();
        manifest.signature = Some("ed25519:different_signature".to_string());
        let chunk_data = vec![
            b"test_chunk_0".to_vec(),
            b"test_chunk_1".to_vec(),
            b"test_chunk_2".to_vec(),
        ];
        let detached_sig = b"ed25519:test_signature"; // Different from manifest

        // Write archive
        write_archive(&archive_path, &manifest, chunk_data, detached_sig).unwrap();

        // Read should fail due to signature mismatch
        let result = read_archive(&archive_path);
        assert!(result.is_err());
        match result.unwrap_err() {
            ArchiveError::SignatureMismatch => (),
            other => panic!("Expected SignatureMismatch error, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_chunk_index() {
        assert_eq!(parse_chunk_index("00000.bin").unwrap(), 0);
        assert_eq!(parse_chunk_index("00042.bin").unwrap(), 42);
        assert_eq!(parse_chunk_index("99999.bin").unwrap(), 99999);

        // Invalid formats should fail
        assert!(parse_chunk_index("0.bin").is_err());
        assert!(parse_chunk_index("chunk.bin").is_err());
        assert!(parse_chunk_index("00000.txt").is_err());
    }

    #[test]
    fn test_archive_dir_name() {
        assert_eq!(archive_dir_name("test123"), "clip-test123.seal");
        assert_eq!(archive_dir_name("CAM-001"), "clip-CAM-001.seal");
    }

    #[test]
    fn test_archive_writer_streams_readable_archive() {
        // ArchiveWriter (streaming) must produce an archive read_archive/
        // validate_archive accept — identical bytes to write_archive for the same
        // inputs. Push the exact chunks create_test_manifest's segments hash.
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("test.seal");
        let manifest = create_test_manifest();
        let chunks: [&[u8]; 3] = [b"test_chunk_0", b"test_chunk_1", b"test_chunk_2"];

        let mut w = ArchiveWriter::create(&archive_path).unwrap();
        for (i, data) in chunks.iter().enumerate() {
            let o = w.push_chunk(data).unwrap();
            assert_eq!(o.index as usize, i);
            assert_eq!(o.stored_len, data.len());
            // Hash + continuity match the pre-computed manifest.
            assert_eq!(hex::encode(o.blake3), manifest.segments[i].blake3_hash);
            assert_eq!(
                hex::encode(o.continuity),
                manifest.segments[i].continuity_hash
            );
        }
        w.finalize(&manifest, b"ed25519:test_signature").unwrap();

        // Reads back and validates like any write_archive output.
        let (rm, read_chunks) = read_archive(&archive_path).unwrap();
        assert_eq!(rm.segments.len(), 3);
        assert_eq!(read_chunks.len(), 3);
        assert_eq!(read_chunks[1].1, b"test_chunk_1");
        validate_archive(&archive_path).unwrap();
    }

    #[test]
    fn test_archive_writer_rejects_count_mismatch() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("test.seal");
        let manifest = create_test_manifest(); // 3 segments

        let mut w = ArchiveWriter::create(&archive_path).unwrap();
        w.push_chunk(b"only_one").unwrap(); // 1 chunk vs 3 segments
        let err = w.finalize(&manifest, b"sig").unwrap_err();
        assert!(matches!(err, ArchiveError::SchemaMismatch(_)));
    }

    #[test]
    fn test_read_manifest_rejects_oversized_manifest_file() {
        // H3 reader cap: a manifest.json over MANIFEST_MAX_BYTES is refused before
        // parsing (parse-DoS defense). Write an oversized file directly.
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("big.seal");
        fs::create_dir_all(archive_path.join("signatures")).unwrap();
        fs::write(
            archive_path.join("manifest.json"),
            vec![b'x'; MANIFEST_MAX_BYTES + 1],
        )
        .unwrap();
        fs::write(archive_path.join("signatures/manifest.sig"), b"sig").unwrap();

        let err = read_manifest(&archive_path).unwrap_err();
        match err {
            ArchiveError::SchemaMismatch(msg) => assert!(msg.contains("cap"), "got: {msg}"),
            other => panic!("expected cap SchemaMismatch, got {other:?}"),
        }
    }

    #[test]
    fn test_read_manifest_roundtrips_and_checks_sig() {
        // read_manifest returns the manifest + sig without loading chunks, and
        // preserves the embedded-vs-detached signature consistency check (SA4).
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("m.seal");
        let manifest = create_test_manifest();
        let chunks = vec![
            b"test_chunk_0".to_vec(),
            b"test_chunk_1".to_vec(),
            b"test_chunk_2".to_vec(),
        ];
        write_archive(&archive_path, &manifest, chunks, b"ed25519:test_signature").unwrap();

        let (m, sig) = read_manifest(&archive_path).unwrap();
        assert_eq!(m.segments.len(), 3);
        assert_eq!(sig, b"ed25519:test_signature");

        // Corrupt the detached sig → SA4 consistency check fires.
        fs::write(
            archive_path.join("signatures/manifest.sig"),
            b"ed25519:different",
        )
        .unwrap();
        assert!(matches!(
            read_manifest(&archive_path),
            Err(ArchiveError::SignatureMismatch)
        ));
    }

    #[test]
    fn test_archive_writer_finalize_rejects_oversized_manifest() {
        // SA1 producer guard: a manifest larger than the shared reader cap must be
        // refused at wrap time (never emit an archive a reader would reject). Bloat
        // a non-segment field so the check is cheap (no giant chunk fan-out).
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("big.seal");
        let mut manifest = TrstManifest::new(); // generic, no segments
        manifest.claims = vec!["x".repeat(MANIFEST_MAX_BYTES + 1)];

        let w = ArchiveWriter::create(&archive_path).unwrap(); // 0 chunks == 0 segments
        let err = w.finalize(&manifest, b"sig").unwrap_err();
        match err {
            ArchiveError::SchemaMismatch(msg) => {
                assert!(
                    msg.contains("manifest exceeds the reader cap"),
                    "got: {msg}"
                );
            }
            other => panic!("expected cap SchemaMismatch, got {other:?}"),
        }
    }

    #[test]
    fn test_unreferenced_chunk_detected() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("test.seal");

        let manifest = create_test_manifest();
        let chunk_data = vec![
            b"test_chunk_0".to_vec(),
            b"test_chunk_1".to_vec(),
            b"test_chunk_2".to_vec(),
        ];
        let detached_sig = b"ed25519:test_signature";

        // Write a valid archive
        write_archive(&archive_path, &manifest, chunk_data, detached_sig).unwrap();

        // Write a spurious chunk file not referenced in the manifest
        let spurious_chunk = archive_path.join("chunks/99999.bin");
        fs::write(&spurious_chunk, b"spurious").unwrap();

        // Validation should fail with UnreferencedChunk error
        let result = validate_archive(&archive_path);
        assert!(
            result.is_err(),
            "validate_archive should fail with spurious chunk"
        );
        match result.unwrap_err() {
            ArchiveError::UnreferencedChunk(filename) => {
                assert_eq!(filename, "99999.bin");
            }
            other => panic!("Expected UnreferencedChunk error, got {:?}", other),
        }
    }
}
