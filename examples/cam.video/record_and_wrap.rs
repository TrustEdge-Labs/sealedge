//
// Copyright (c) 2025 TRUSTEDGE LABS LLC
// This source code is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Project: sealedge — Privacy and trust at the edge.
//

use chacha20poly1305::Key;
use chrono::{DateTime, SecondsFormat, Utc};
use sealedge_core::{
    cek_wrap_info, chain_next, chunk_aad_v2, encrypt_segment, generate_nonce24, genesis,
    hpke_seal_cek, recipient_id, segment_hash, sign_manifest, write_archive, CamVideoManifest,
    CamVideoMetadata, ChunkInfo, ContentKey, DeviceBundle, DeviceInfo, EncryptionBlock, HpkeSuite,
    ProfileMetadata, RecipientEntry, SegmentInfo, CONTENT_AEAD_ID, HPKE_AEAD_ID, HPKE_KDF_ID,
    HPKE_KEM_ID,
};
use std::error::Error;
use std::fs;

fn main() -> Result<(), Box<dyn Error>> {
    println!("Sealedge cam.video Example: Record and Wrap (trst_version 0.2.0 / C4)");

    // C4: a device now has an Ed25519 signing key AND an independent X25519
    // key-agreement key, persisted together as a SEALEDGE-KEY-V2 bundle. This
    // example writes a plaintext bundle for a non-interactive demo; production
    // devices keep the bundle encrypted at rest (see `seal keygen`).
    let bundle = DeviceBundle::generate()?;
    let device_id = "te:cam:example".to_string();
    let signing_public_key = bundle.signing.public.clone();
    let key_agreement_public = bundle.key_agreement.public_string();

    fs::write(
        "examples/cam.video/device.key",
        format!("{}\n", bundle.to_plaintext()),
    )?;
    fs::write("examples/cam.video/device.pub", bundle.public_lines())?;

    println!("Generated device key bundle (SEALEDGE-KEY-V2):");
    println!("  Secret: examples/cam.video/device.key");
    println!("  Public: examples/cam.video/device.pub (ed25519 + x25519, one per line)");

    // Read sample data
    let input_path = "examples/cam.video/sample.bin";
    let input_data =
        fs::read(input_path).map_err(|e| format!("Failed to read {}: {}", input_path, e))?;

    if input_data.is_empty() {
        return Err("Input file is empty".into());
    }

    println!("Read {} bytes from {}", input_data.len(), input_path);

    // Configure parameters
    let chunk_size = 1_048_576; // 1MB chunks
    let chunk_seconds = 2.0;
    let fps = 30;
    let profile = "cam.video";

    // Create timestamps
    let started_at = current_timestamp()?;

    // C4: a per-archive random Content-Encryption Key (CEK) keys the chunk AEAD.
    // It is never derived from the signing key; it is HPKE-wrapped to recipients
    // (below). The chunk AAD binds every ciphertext to the full signing identity.
    let cek = ContentKey::generate();
    let chunk_key = Key::from_slice(cek.as_bytes());
    let chunk_aad = chunk_aad_v2(&signing_public_key, profile, &started_at);

    // Process chunks
    let chunks = input_data.chunks(chunk_size).collect::<Vec<_>>();
    let mut segments = Vec::new();
    let mut chain_state = genesis();
    let mut encrypted_chunks = Vec::new();

    let capture_end_time = if !chunks.is_empty() {
        let total_duration = chunks.len() as f64 * chunk_seconds;
        let end_timestamp = DateTime::parse_from_rfc3339(&started_at)?
            + chrono::Duration::milliseconds((total_duration * 1000.0) as i64);
        end_timestamp.to_rfc3339_opts(SecondsFormat::Secs, true)
    } else {
        started_at.clone()
    };

    println!("Processing {} chunks...", chunks.len());

    for (i, chunk_data) in chunks.iter().enumerate() {
        let chunk_id = i as u32;

        // On-disk chunk is [nonce:24][ciphertext]. The continuity chain hashes the
        // STORED bytes so a verifier can rebuild it from disk without the key.
        let nonce = generate_nonce24();
        let ciphertext = encrypt_segment(chunk_key, &nonce, chunk_data, &chunk_aad)?;
        let mut stored_chunk = Vec::with_capacity(24 + ciphertext.len());
        stored_chunk.extend_from_slice(&nonce);
        stored_chunk.extend_from_slice(&ciphertext);

        let hash = segment_hash(&stored_chunk);
        let next_state = chain_next(&chain_state, &hash);

        let segment = SegmentInfo {
            chunk_file: format!("{:05}.bin", chunk_id),
            blake3_hash: hex::encode(hash),
            start_time: format!("{:.3}s", i as f64 * chunk_seconds),
            duration_seconds: chunk_seconds,
            continuity_hash: hex::encode(next_state),
        };

        segments.push(segment);
        chain_state = next_state;
        encrypted_chunks.push(stored_chunk);

        println!(
            "  Chunk {}: {} bytes -> {} bytes stored (nonce + ciphertext)",
            chunk_id,
            chunk_data.len(),
            encrypted_chunks[i].len()
        );
    }

    // Build the 0.2.0 manifest (unsigned, encryption not yet attached).
    let mut manifest = CamVideoManifest {
        trst_version: "0.2.0".to_string(),
        profile: profile.to_string(),
        device: DeviceInfo {
            id: device_id,
            model: "TrustEdgeRefCam".to_string(),
            firmware_version: "1.0.0".to_string(),
            public_key: signing_public_key.clone(),
            key_agreement_public: Some(key_agreement_public.clone()),
        },
        metadata: ProfileMetadata::CamVideo(CamVideoMetadata {
            started_at: started_at.clone(),
            ended_at: capture_end_time,
            timezone: "UTC".to_string(),
            fps: fps as f64,
            resolution: "1920x1080".to_string(),
            codec: "raw".to_string(),
        }),
        chunk: ChunkInfo {
            size_bytes: chunk_size as u64,
            duration_seconds: chunk_seconds,
        },
        segments,
        claims: vec!["location:example".to_string()],
        encryption: None,
        prev_archive_hash: None,
        signature: None,
    };

    // HPKE-wrap the CEK to the device's own key-agreement key (recipient #0). The
    // HPKE aad is the digest of the manifest WITHOUT its encryption block, so a
    // wrapped CEK cannot be transplanted onto a different manifest.
    let pre_digest = segment_hash(&manifest.to_canonical_bytes()?);
    let info = cek_wrap_info(&signing_public_key, &manifest.trst_version);
    let (enc, wrapped_cek) = hpke_seal_cek(&key_agreement_public, &info, &pre_digest, &cek)?;
    manifest.encryption = Some(EncryptionBlock {
        content_aead: CONTENT_AEAD_ID.to_string(),
        hpke: HpkeSuite {
            kem: HPKE_KEM_ID.to_string(),
            kdf: HPKE_KDF_ID.to_string(),
            aead: HPKE_AEAD_ID.to_string(),
        },
        recipients: vec![RecipientEntry {
            recipient_id: recipient_id(&key_agreement_public)?,
            recipient_pub: key_agreement_public,
            enc,
            wrapped_cek,
        }],
    });

    // Sign the finished manifest's canonical bytes and write the archive.
    let canonical_bytes = manifest.to_canonical_bytes()?;
    let signature = sign_manifest(&bundle.signing, &canonical_bytes)?;
    manifest.set_signature(signature.clone());

    let output_path = "examples/cam.video/clip.seal";
    write_archive(
        output_path,
        &manifest,
        encrypted_chunks,
        signature.as_bytes(),
    )?;

    println!("✔ Archive created: {}", output_path);
    println!("   Signature: {}", signature);
    println!("   Segments: {}", manifest.segments.len());
    println!(
        "   Total duration: {:.1}s",
        manifest
            .segments
            .iter()
            .map(|s| s.duration_seconds)
            .sum::<f64>()
    );
    println!("   Encrypted to device recipient (recipient #0)");

    Ok(())
}

fn current_timestamp() -> Result<String, Box<dyn Error>> {
    let now: DateTime<Utc> = Utc::now();
    Ok(now.to_rfc3339_opts(SecondsFormat::Secs, true))
}
