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
    chain_next, encrypt_segment, generate_aad, generate_nonce24, genesis, segment_hash,
    sign_manifest, write_archive, CamVideoManifest, CamVideoMetadata, ChunkInfo, DeviceInfo,
    DeviceKeypair, ProfileMetadata, SegmentInfo,
};
use std::error::Error;
use std::fs;

fn main() -> Result<(), Box<dyn Error>> {
    println!("Sealedge P0 cam.video Example: Record and Wrap");

    // Generate device keypair
    let device_keypair = DeviceKeypair::generate()?;
    let device_id = "te:cam:example".to_string();

    // Save device keys for verification
    fs::write(
        "examples/cam.video/device.key",
        device_keypair.export_secret(),
    )?;
    fs::write("examples/cam.video/device.pub", &device_keypair.public)?;

    println!("Generated device keypair:");
    println!("  Secret: examples/cam.video/device.key");
    println!("  Public: examples/cam.video/device.pub");

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

    // Process chunks
    let chunks = input_data.chunks(chunk_size).collect::<Vec<_>>();
    let mut segments = Vec::new();
    let mut chain_state = genesis();
    let mut encrypted_chunks = Vec::new();

    // Generate a symmetric key for encryption (simplified for P0)
    let encryption_key = &Key::from(*b"example_demo_key_32_bytes_long__"); // 32 bytes

    // Create timestamps
    let started_at = current_timestamp()?;
    let capture_end_time = if !chunks.is_empty() {
        let total_duration = chunks.len() as f64 * chunk_seconds;
        let end_timestamp = chrono::DateTime::parse_from_rfc3339(&started_at)?
            + chrono::Duration::milliseconds((total_duration * 1000.0) as i64);
        end_timestamp.to_rfc3339_opts(SecondsFormat::Secs, true)
    } else {
        started_at.clone()
    };

    println!("Processing {} chunks...", chunks.len());

    for (i, chunk_data) in chunks.iter().enumerate() {
        let chunk_id = i as u32;

        // Generate nonce and encrypt
        let nonce = generate_nonce24();
        let aad = generate_aad("0.1.0", "cam.video", &device_id, &started_at);
        let encrypted_data = encrypt_segment(encryption_key, &nonce, chunk_data, &aad)?;
        encrypted_chunks.push(encrypted_data.clone());

        // Calculate hash and update chain (hash the encrypted data)
        let hash = segment_hash(&encrypted_data);
        let next_state = chain_next(&chain_state, &hash);

        // Create segment info
        let start_time = format!("{:.3}s", i as f64 * chunk_seconds);
        let chunk_filename = format!("{:05}.bin", chunk_id);

        let segment = SegmentInfo {
            chunk_file: chunk_filename,
            blake3_hash: hex::encode(hash),
            start_time,
            duration_seconds: chunk_seconds,
            continuity_hash: hex::encode(next_state),
        };

        segments.push(segment);
        chain_state = next_state;

        println!(
            "  Chunk {}: {} bytes -> {} bytes encrypted",
            chunk_id,
            chunk_data.len(),
            encrypted_data.len()
        );
    }

    // Create manifest
    let manifest = CamVideoManifest {
        trst_version: "0.1.0".to_string(),
        profile: "cam.video".to_string(),
        device: DeviceInfo {
            id: device_id,
            model: "TrustEdgeRefCam".to_string(),
            firmware_version: "1.0.0".to_string(),
            public_key: device_keypair.public.clone(),
            key_agreement_public: None,
        },
        metadata: ProfileMetadata::CamVideo(CamVideoMetadata {
            started_at,
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

    // Sign manifest
    let canonical_bytes = manifest.to_canonical_bytes()?;
    let signature = sign_manifest(&device_keypair, &canonical_bytes)?;
    let signed_manifest = CamVideoManifest {
        signature: Some(signature.clone()),
        ..manifest
    };

    // Write archive
    let output_path = "examples/cam.video/clip.seal";
    let detached_sig = signature.as_bytes();
    write_archive(
        output_path,
        &signed_manifest,
        encrypted_chunks,
        detached_sig,
    )?;

    println!("✔ Archive created: {}", output_path);
    println!("   Signature: {}", signature);
    println!("   Segments: {}", signed_manifest.segments.len());
    println!(
        "   Total duration: {:.1}s",
        signed_manifest
            .segments
            .iter()
            .map(|s| s.duration_seconds)
            .sum::<f64>()
    );

    Ok(())
}

fn current_timestamp() -> Result<String, Box<dyn Error>> {
    let now: DateTime<Utc> = Utc::now();
    Ok(now.to_rfc3339_opts(SecondsFormat::Secs, true))
}
