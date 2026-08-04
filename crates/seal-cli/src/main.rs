//
// Copyright (c) 2025 TRUSTEDGE LABS LLC
// This source code is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Project: sealedge — Privacy and trust at the edge.
//

use std::collections::BTreeMap;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use base64::Engine as _;

use anyhow::{Context, Result};
use blake3::Hasher;
use chrono::{DateTime, SecondsFormat, Utc};
use clap::{Args, Parser, Subcommand};
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use sealedge_core::{
    chain_next, decrypt_segment, derive_chunk_key, encrypt_segment, generate_aad, genesis,
    is_encrypted_key_file, read_archive, segment_hash, sign_manifest, validate_archive,
    verify_manifest, write_archive, AudioMetadata, CamVideoMetadata, ChunkInfo, DeviceInfo,
    DeviceKeypair, GenericMetadata, LogMetadata, PointAttestation, ProfileMetadata, SegmentInfo,
    SensorMetadata, TrstManifest,
};
use serde::Serialize;
use std::time::Instant;
// Shared wire types from sealedge-types (accessed via sealedge-core re-export or directly).
// SegmentRef, VerifyOptions, VerifyRequest use the shared canonical definitions.
use sealedge_types::verification::{SegmentRef, VerifyOptions, VerifyRequest};

#[cfg(feature = "yubikey")]
use p256::pkcs8::DecodePublicKey;
#[cfg(feature = "yubikey")]
use sealedge_core::backends::universal::{
    CryptoOperation, CryptoResult, SignatureAlgorithm, UniversalBackend,
};
#[cfg(feature = "yubikey")]
use sealedge_core::backends::yubikey::YubiKeyConfig;
#[cfg(feature = "yubikey")]
use sealedge_core::backends::YubiKeyBackend;

/// Emit a security warning when --unencrypted is used.
fn warn_unencrypted() {
    eprintln!("\u{26A0} WARNING: --unencrypted generates/reads plaintext key files. Key material is NOT protected at rest. Use only for CI/automation.");
}

/// Carries a specific exit code through the error propagation chain.
/// This lets subcommands return `Result<()>` while preserving distinct exit codes
/// (10=verify, 11=integrity, 12=signature, 14=chain, 1=general).
/// Drop/Zeroize handlers run normally before `main()` calls `std::process::exit`.
#[derive(Debug)]
struct CliExitError {
    code: i32,
    message: String,
}

impl std::fmt::Display for CliExitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for CliExitError {}

#[derive(Debug)]
struct WrapResult {
    output_dir: PathBuf,
    signature: String,
    chunk_count: usize,
}

// NOTE: Differs from sealedge_types::verify_report::VerifyReport — this version uses
// `out_of_order: Option<bool>` (a simple presence flag) while the shared type uses
// `out_of_order: Option<OutOfOrder>` (structured {expected, found} hash strings from ChainError).
// Kept local to avoid losing the boolean semantics used in CLI output formatting.
#[derive(Serialize, Default)]
struct VerifyReport {
    signature: String,  // "pass" | "fail" | "unknown"
    continuity: String, // "pass" | "fail" | "skip" | "unknown"
    segments: u32,
    duration_s: f32,
    profile: String,
    device_id: String,
    verify_time_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>, // Error description for failures
    #[serde(skip_serializing_if = "Option::is_none")]
    first_gap_index: Option<u32>, // Index of first continuity gap
    #[serde(skip_serializing_if = "Option::is_none")]
    out_of_order: Option<bool>, // Whether segments are out of order
}

#[derive(Parser, Debug)]
#[command(author, version, about = "Sealedge .seal archival tool", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
#[allow(clippy::large_enum_variant)]
enum Commands {
    Wrap(WrapCmd),
    Verify(VerifyCmd),
    Unwrap(UnwrapCmd),
    EmitRequest(EmitRequestCmd),
    Keygen(KeygenCmd),
    AttestSbom(AttestSbomCmd),
    VerifyAttestation(VerifyAttestationCmd),
}

#[derive(Args, Debug)]
struct WrapCmd {
    #[arg(long = "in", value_name = "PATH", help = "Input file to wrap")]
    input: PathBuf,
    #[arg(long = "out", value_name = "PATH", help = "Output .seal directory")]
    output: PathBuf,
    /// Archive profile. Defaults to "generic". Use "cam.video" for video capture archives.
    #[arg(long, default_value = "generic")]
    profile: String,
    #[arg(long, default_value_t = 1_048_576)]
    chunk_size: usize,
    /// Chunk duration in seconds (cam.video profile only)
    #[arg(long, help = "Chunk duration in seconds (cam.video profile only)")]
    chunk_seconds: Option<f64>,
    /// Frames per second (cam.video profile only)
    #[arg(long, help = "Frames per second (cam.video profile only)")]
    fps: Option<u32>,
    #[arg(
        long = "device-key",
        value_name = "PATH",
        help = "Path to device signing key file"
    )]
    device_key: Option<PathBuf>,
    #[arg(
        long = "device-pub",
        value_name = "PATH",
        help = "Path to device public key file"
    )]
    device_pub: Option<PathBuf>,
    #[arg(
        long = "seed",
        value_name = "U64",
        help = "Seed RNG for deterministic output (for testing/CI, not cryptographically secure)"
    )]
    seed: Option<u64>,
    /// Data type for generic profile (e.g. video, sensor, audio, log, binary)
    #[arg(
        long,
        help = "Data type (generic profile: video, sensor, audio, log, binary)"
    )]
    data_type: Option<String>,
    /// Source identifier for generic profile
    #[arg(long, help = "Data source identifier (generic profile)")]
    source: Option<String>,
    /// Description for generic profile
    #[arg(long, help = "Description (generic profile)")]
    description: Option<String>,
    /// MIME type for generic profile
    #[arg(long, help = "MIME type (generic profile)")]
    mime_type: Option<String>,
    /// Sample rate in Hz (sensor or audio profile)
    #[arg(long, help = "Sample rate in Hz (sensor or audio profile)")]
    sample_rate: Option<f64>,
    /// Measurement unit (sensor profile: celsius, psi, rpm, etc.)
    #[arg(long, help = "Measurement unit (sensor profile)")]
    unit: Option<String>,
    /// Sensor model identifier (sensor profile: DHT22, BMP280, etc.)
    #[arg(long, help = "Sensor model (sensor profile)")]
    sensor_model: Option<String>,
    /// Latitude for geo-tagged sensor data
    #[arg(long, help = "Latitude (sensor profile, optional)")]
    latitude: Option<f64>,
    /// Longitude for geo-tagged sensor data
    #[arg(long, help = "Longitude (sensor profile, optional)")]
    longitude: Option<f64>,
    /// Altitude for geo-tagged sensor data
    #[arg(long, help = "Altitude in meters (sensor profile, optional)")]
    altitude: Option<f64>,
    /// Bit depth (audio profile: 16, 24, 32)
    #[arg(long, help = "Bit depth (audio profile)")]
    bit_depth: Option<u16>,
    /// Number of audio channels (audio profile: 1=mono, 2=stereo)
    #[arg(long, help = "Number of channels (audio profile)")]
    channels: Option<u8>,
    /// Audio codec (audio profile: pcm, opus, aac)
    #[arg(long, help = "Audio codec (audio profile)")]
    codec: Option<String>,
    /// Application name (log profile: nginx, syslog, etc.)
    #[arg(long, help = "Application name (log profile)")]
    application: Option<String>,
    /// Host identifier (log profile)
    #[arg(long, help = "Host identifier (log profile)")]
    host: Option<String>,
    /// Log level (log profile: info, error, debug, etc.)
    #[arg(long, help = "Log level (log profile)")]
    log_level: Option<String>,
    /// Log format (log profile: json, syslog, plaintext)
    #[arg(long, help = "Log format (log profile)")]
    log_format: Option<String>,
    /// Signing backend: "software" (default) or "yubikey"
    #[arg(long, default_value = "software")]
    backend: String,
    /// PIV slot for YubiKey signing (9a, 9c, 9d, 9e). Default: 9c (Digital Signature)
    #[arg(long, default_value = "9c")]
    slot: String,
    /// Accept plaintext key files without passphrase prompt (for CI/automation only)
    #[arg(long)]
    unencrypted: bool,
}

#[derive(Args, Debug)]
struct VerifyCmd {
    #[arg(value_name = "ARCHIVE", help = "Path to .seal archive directory")]
    archive: PathBuf,
    #[arg(
        long = "device-pub",
        value_name = "KEY",
        help = "Device public key (ed25519:<base64> or ecdsa-p256:<base64>)"
    )]
    device_pub: String,
    #[arg(long, help = "Output results as JSON")]
    json: bool,
    #[arg(
        long = "emit-receipt",
        value_name = "PATH",
        help = "Write JSON verification receipt to file"
    )]
    emit_receipt: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct UnwrapCmd {
    #[arg(value_name = "ARCHIVE", help = "Path to .seal archive directory")]
    archive: PathBuf,
    #[arg(
        long = "device-key",
        value_name = "PATH",
        help = "Path to device signing key file"
    )]
    device_key: PathBuf,
    #[arg(
        long = "out",
        value_name = "PATH",
        help = "Output file path for recovered data"
    )]
    output: PathBuf,
    /// Accept plaintext key files without passphrase prompt (for CI/automation only)
    #[arg(long)]
    unencrypted: bool,
}

#[derive(Args, Debug)]
struct KeygenCmd {
    #[arg(
        long = "out-key",
        value_name = "PATH",
        help = "Output path for secret key file"
    )]
    out_key: PathBuf,
    #[arg(
        long = "out-pub",
        value_name = "PATH",
        help = "Output path for public key file"
    )]
    out_pub: PathBuf,
    /// Write plaintext key (insecure, for CI/automation only)
    #[arg(long)]
    unencrypted: bool,
}

#[derive(Args, Debug)]
struct EmitRequestCmd {
    #[arg(
        long = "archive",
        value_name = "PATH",
        help = "Path to .seal archive directory"
    )]
    archive: PathBuf,
    #[arg(
        long = "device-pub",
        value_name = "PATH",
        help = "Path to device public key file"
    )]
    device_pub: PathBuf,
    #[arg(long = "out", value_name = "PATH", help = "Output JSON file path")]
    out: PathBuf,
    #[arg(
        long = "post",
        value_name = "URL",
        help = "Optional HTTP POST endpoint"
    )]
    post: Option<String>,
}

#[derive(Args, Debug)]
struct AttestSbomCmd {
    #[arg(long, value_name = "PATH", help = "Path to binary artifact")]
    binary: PathBuf,
    #[arg(long, value_name = "PATH", help = "Path to CycloneDX JSON SBOM")]
    sbom: PathBuf,
    #[arg(
        long = "device-key",
        value_name = "PATH",
        help = "Path to device signing key file"
    )]
    device_key: PathBuf,
    #[arg(
        long = "device-pub",
        value_name = "PATH",
        help = "Path to device public key file"
    )]
    device_pub: PathBuf,
    #[arg(
        long,
        value_name = "PATH",
        help = "Output path [default: attestation.se-attestation.json]"
    )]
    out: Option<PathBuf>,
    #[arg(long, help = "Use unencrypted key file (CI/automation only)")]
    unencrypted: bool,
}

#[derive(Args, Debug)]
struct VerifyAttestationCmd {
    #[arg(value_name = "ATTESTATION", help = "Path to .se-attestation.json file")]
    attestation: PathBuf,
    #[arg(
        long = "device-pub",
        value_name = "KEY",
        help = "Public key (ed25519:... string or path to .pub file)"
    )]
    device_pub: String,
    #[arg(
        long,
        value_name = "PATH",
        help = "Optional binary for hash verification"
    )]
    binary: Option<PathBuf>,
    #[arg(
        long,
        value_name = "PATH",
        help = "Optional SBOM for hash verification"
    )]
    sbom: Option<PathBuf>,
}

fn generate_seeded_nonce24(rng: &mut dyn RngCore) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    rng.fill_bytes(&mut nonce);
    nonce
}

/// Derive a device_id string from a prefixed public key string.
///
/// Extracts the first 6 bytes of the raw key bytes (after the prefix) and formats
/// them as "te:cam:<hex>". Works for both "ed25519:<base64>" and "ecdsa-p256:<base64>" formats.
fn pub_key_to_device_id(pub_key_str: &str) -> Result<String> {
    let raw_b64 = if let Some(rest) = pub_key_str.strip_prefix("ed25519:") {
        rest
    } else if let Some(rest) = pub_key_str.strip_prefix("ecdsa-p256:") {
        rest
    } else {
        anyhow::bail!("Unrecognized public key prefix in: {}", pub_key_str);
    };
    let key_bytes = base64::engine::general_purpose::STANDARD
        .decode(raw_b64)
        .with_context(|| "Failed to decode public key bytes for device_id")?;
    if key_bytes.len() < 6 {
        anyhow::bail!(
            "Public key bytes too short for device_id (got {} bytes)",
            key_bytes.len()
        );
    }
    Ok(format!("te:cam:{}", hex::encode(&key_bytes[..6])))
}

#[tokio::main]
async fn main() {
    // run() returns before std::process::exit, so all local variables (including key
    // material protected by Zeroize) are dropped before the process terminates.
    let code = match run().await {
        Ok(()) => 0,
        Err(e) => {
            if let Some(cli_err) = e.downcast_ref::<CliExitError>() {
                eprintln!("{}", cli_err.message);
                cli_err.code
            } else {
                eprintln!("error: {e:#}");
                1
            }
        }
    };
    std::process::exit(code);
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Wrap(args) => handle_wrap(args),
        Commands::Verify(args) => handle_verify(args),
        Commands::Unwrap(args) => handle_unwrap(args),
        Commands::EmitRequest(args) => handle_emit_request(args).await,
        Commands::Keygen(args) => handle_keygen(args),
        Commands::AttestSbom(args) => handle_attest_sbom(args),
        Commands::VerifyAttestation(args) => handle_verify_attestation(args),
    }
}

fn handle_keygen(args: KeygenCmd) -> Result<()> {
    if args.unencrypted {
        warn_unencrypted();
    }
    // Refuse to overwrite existing files
    if args.out_key.exists() {
        anyhow::bail!(
            "Refusing to overwrite existing file: {}",
            args.out_key.display()
        );
    }
    if args.out_pub.exists() {
        anyhow::bail!(
            "Refusing to overwrite existing file: {}",
            args.out_pub.display()
        );
    }

    let device_keypair = DeviceKeypair::generate()?;

    if args.unencrypted {
        fs::write(
            &args.out_key,
            format!("{}\n", device_keypair.export_secret()),
        )
        .with_context(|| format!("Failed to write secret key: {}", args.out_key.display()))?;
    } else {
        let passphrase =
            rpassword::prompt_password("Passphrase: ").context("Failed to read passphrase")?;
        let confirm = rpassword::prompt_password("Confirm passphrase: ")
            .context("Failed to read passphrase confirmation")?;
        if passphrase != confirm {
            anyhow::bail!("Passphrases do not match");
        }
        let encrypted = device_keypair
            .export_secret_encrypted(&passphrase)
            .context("Failed to encrypt key")?;
        fs::write(&args.out_key, &encrypted)
            .with_context(|| format!("Failed to write secret key: {}", args.out_key.display()))?;
    }

    // Set secret key file to owner-only permissions (0600)
    #[cfg(unix)]
    {
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&args.out_key, perms)
            .with_context(|| format!("Failed to set permissions on {}", args.out_key.display()))?;
    }
    #[cfg(not(unix))]
    {
        eprintln!(
            "Warning: Unable to restrict key file permissions on this platform. Manually restrict access to {}",
            args.out_key.display()
        );
    }

    fs::write(&args.out_pub, format!("{}\n", device_keypair.public))
        .with_context(|| format!("Failed to write public key: {}", args.out_pub.display()))?;

    println!("Generated device key: {}", args.out_key.display());
    println!("Generated device pub: {}", args.out_pub.display());
    Ok(())
}

fn handle_wrap(args: WrapCmd) -> Result<()> {
    if args.unencrypted {
        warn_unencrypted();
    }
    // Reject chunk sizes above 256 MB (268_435_456 bytes) to prevent memory exhaustion.
    const MAX_CHUNK_SIZE: usize = 268_435_456;
    if args.chunk_size > MAX_CHUNK_SIZE {
        anyhow::bail!(
            "--chunk-size must not exceed 256 MB ({} bytes), got {} bytes",
            MAX_CHUNK_SIZE,
            args.chunk_size
        );
    }

    // Validate backend-specific requirements up front
    if args.backend == "yubikey" && args.device_key.is_none() {
        anyhow::bail!(
            "--device-key is required with --backend yubikey (used for chunk encryption)"
        );
    }

    let (device_keypair, secret_path, public_path, generated) =
        load_or_generate_keypair(args.device_key.as_deref(), args.unencrypted)?;

    // Read input file
    let input_data = fs::read(&args.input)
        .with_context(|| format!("Failed to read input file: {}", args.input.display()))?;

    if input_data.is_empty() {
        anyhow::bail!("Input file is empty");
    }

    // Create output directory
    let archive_name = args
        .output
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("Invalid output path"))?
        .to_string_lossy();

    if !archive_name.ends_with(".seal") {
        anyhow::bail!("Output directory must end with .seal");
    }

    fs::create_dir_all(&args.output)?;
    fs::create_dir_all(args.output.join("chunks"))?;
    fs::create_dir_all(args.output.join("signatures"))?;

    // Initialize RNG - seeded if provided, otherwise use default
    let mut rng: Box<dyn RngCore> = match args.seed {
        Some(seed) => Box::new(ChaCha20Rng::seed_from_u64(seed)),
        None => Box::new(rand::rng()),
    };

    // Resolve chunk_seconds: cam.video default 2.0, generic default 0.0
    let chunk_seconds = match args.profile.as_str() {
        "cam.video" => args.chunk_seconds.unwrap_or(2.0),
        _ => args.chunk_seconds.unwrap_or(0.0),
    };

    // Process chunks
    let chunks = input_data.chunks(args.chunk_size).collect::<Vec<_>>();
    let mut segments = Vec::new();
    let mut chain_state = genesis();
    let mut encrypted_chunks = Vec::new();

    // Derive encryption key from device signing key via HKDF-SHA256.
    // For yubikey backend, the software device key is still used for chunk encryption.
    let encryption_key = derive_chunk_key(device_keypair.secret_bytes());

    // Create timestamp for all operations - deterministic if seeded
    let started_at = if args.seed.is_some() {
        // Use deterministic timestamp for seeded runs
        "2025-01-01T00:00:00Z".to_string()
    } else {
        current_timestamp()?
    };

    // Compute device_id from the initial software public key (will be overridden for yubikey
    // after we obtain the hardware public key below)
    let initial_pub_str = &device_keypair.public;
    let device_id = pub_key_to_device_id(initial_pub_str)?;

    for (i, chunk_data) in chunks.iter().enumerate() {
        let chunk_id = i as u32;

        // Generate nonce - seeded if provided
        let nonce = generate_seeded_nonce24(&mut *rng);
        let aad = generate_aad("0.1.0", &args.profile, &device_id, &started_at);
        let encrypted_data = encrypt_segment(&encryption_key, &nonce, chunk_data, &aad)?;

        // Prepend the 24-byte nonce to the ciphertext so unwrap can decrypt:
        // on-disk format is [nonce:24][ciphertext:N]
        let mut chunk_with_nonce = Vec::with_capacity(24 + encrypted_data.len());
        chunk_with_nonce.extend_from_slice(&nonce);
        chunk_with_nonce.extend_from_slice(&encrypted_data);

        // Hash nonce+ciphertext to match what validate_archive reads from disk
        let hash = segment_hash(&chunk_with_nonce);
        encrypted_chunks.push(chunk_with_nonce);
        let next_state = chain_next(&chain_state, &hash);

        // Build start_time: time-based for cam.video, index-based for generic
        let start_time = if args.profile == "cam.video" {
            format!("{:.3}s", i as f64 * chunk_seconds)
        } else {
            format!("segment-{}", i)
        };
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
    }

    // Build profile metadata and compute end time
    let metadata = match args.profile.as_str() {
        "cam.video" => {
            let fps = args.fps.unwrap_or(30);
            let capture_end_time = if !chunks.is_empty() {
                let last_chunk_start = (chunks.len() - 1) as f64 * chunk_seconds;
                let end_timestamp = chrono::DateTime::parse_from_rfc3339(&started_at)?
                    + chrono::Duration::milliseconds((last_chunk_start * 1000.0) as i64)
                    + chrono::Duration::milliseconds((chunk_seconds * 1000.0) as i64);
                end_timestamp.to_rfc3339_opts(SecondsFormat::Secs, true)
            } else {
                started_at.clone()
            };
            ProfileMetadata::CamVideo(CamVideoMetadata {
                started_at: started_at.clone(),
                ended_at: capture_end_time,
                timezone: "UTC".to_string(),
                fps: fps as f64,
                resolution: "1920x1080".to_string(),
                codec: "raw".to_string(),
            })
        }
        "sensor" => {
            let sample_rate = args
                .sample_rate
                .ok_or_else(|| anyhow::anyhow!("--sample-rate is required for sensor profile"))?;
            let unit = args
                .unit
                .ok_or_else(|| anyhow::anyhow!("--unit is required for sensor profile"))?;
            let sensor_model = args
                .sensor_model
                .ok_or_else(|| anyhow::anyhow!("--sensor-model is required for sensor profile"))?;
            ProfileMetadata::Sensor(SensorMetadata {
                started_at: started_at.clone(),
                ended_at: started_at.clone(),
                sample_rate_hz: sample_rate,
                unit,
                sensor_model,
                latitude: args.latitude,
                longitude: args.longitude,
                altitude: args.altitude,
                labels: BTreeMap::new(),
            })
        }
        "audio" => {
            let sample_rate = args
                .sample_rate
                .ok_or_else(|| anyhow::anyhow!("--sample-rate is required for audio profile"))?;
            let bit_depth = args
                .bit_depth
                .ok_or_else(|| anyhow::anyhow!("--bit-depth is required for audio profile"))?;
            let channels = args
                .channels
                .ok_or_else(|| anyhow::anyhow!("--channels is required for audio profile"))?;
            let codec = args
                .codec
                .ok_or_else(|| anyhow::anyhow!("--codec is required for audio profile"))?;
            ProfileMetadata::Audio(AudioMetadata {
                started_at: started_at.clone(),
                ended_at: started_at.clone(),
                sample_rate_hz: sample_rate as u32,
                bit_depth,
                channels,
                codec,
            })
        }
        "log" => {
            let application = args
                .application
                .ok_or_else(|| anyhow::anyhow!("--application is required for log profile"))?;
            let host = args
                .host
                .ok_or_else(|| anyhow::anyhow!("--host is required for log profile"))?;
            let log_level = args
                .log_level
                .ok_or_else(|| anyhow::anyhow!("--log-level is required for log profile"))?;
            let log_format = args
                .log_format
                .ok_or_else(|| anyhow::anyhow!("--log-format is required for log profile"))?;
            ProfileMetadata::Log(LogMetadata {
                started_at: started_at.clone(),
                ended_at: started_at.clone(),
                application,
                host,
                log_level,
                log_format,
            })
        }
        _ => {
            // generic profile (and any future unknown profiles default to generic)
            ProfileMetadata::Generic(GenericMetadata {
                started_at: started_at.clone(),
                ended_at: started_at.clone(), // generic data is not time-based
                data_type: args.data_type,
                source: args.source,
                description: args.description,
                mime_type: args.mime_type,
                labels: BTreeMap::new(),
            })
        }
    };

    // Determine signing public key string and signature based on backend
    let (signing_public_key, signature) = match args.backend.as_str() {
        "software" => {
            let pub_key = device_keypair.public.clone();
            let canonical_bytes = {
                // Build a temporary manifest to get canonical bytes for signing
                let tmp = TrstManifest {
                    trst_version: "0.1.0".to_string(),
                    profile: args.profile.clone(),
                    device: DeviceInfo {
                        id: device_id.clone(),
                        model: "TrustEdgeRefCam".to_string(),
                        firmware_version: "1.0.0".to_string(),
                        public_key: pub_key.clone(),
                        key_agreement_public: None,
                    },
                    metadata: metadata.clone(),
                    chunk: ChunkInfo {
                        size_bytes: args.chunk_size as u64,
                        duration_seconds: chunk_seconds,
                    },
                    segments: segments.clone(),
                    claims: vec!["location:unknown".to_string()],
                    encryption: None,
                    prev_archive_hash: None,
                    signature: None,
                };
                tmp.to_canonical_bytes()?
            };
            let sig = sign_manifest(&device_keypair, &canonical_bytes)?;
            (pub_key, sig)
        }
        "yubikey" => {
            #[cfg(feature = "yubikey")]
            {
                // Prompt for PIN interactively without echoing
                let pin =
                    rpassword::prompt_password("YubiKey PIN: ").context("Failed to read PIN")?;
                let config = YubiKeyConfig::builder()
                    .pin(pin)
                    .default_slot(args.slot.clone())
                    .build();
                let backend = YubiKeyBackend::with_config(config)
                    .map_err(|e| anyhow::anyhow!("Failed to connect to YubiKey: {}", e))?;

                // Extract public key from hardware slot (DER-encoded SPKI)
                let pub_key_result = backend
                    .perform_operation(&args.slot, CryptoOperation::GetPublicKey)
                    .map_err(|e| anyhow::anyhow!("Failed to get YubiKey public key: {}", e))?;
                let der_bytes = match pub_key_result {
                    CryptoResult::PublicKey(b) => b,
                    _ => anyhow::bail!("Unexpected result from GetPublicKey"),
                };

                // Parse SPKI DER to SEC1 uncompressed point bytes
                let p256_pub = p256::PublicKey::from_public_key_der(&der_bytes)
                    .map_err(|e| anyhow::anyhow!("Failed to parse P-256 public key: {}", e))?;
                let sec1_bytes = p256_pub.to_sec1_bytes();
                let pub_key_str = format!(
                    "ecdsa-p256:{}",
                    base64::engine::general_purpose::STANDARD.encode(sec1_bytes.as_ref())
                );

                // Build canonical bytes with the P-256 public key and updated device_id
                let yk_device_id = pub_key_to_device_id(&pub_key_str)?;
                let canonical_bytes = {
                    let tmp = TrstManifest {
                        trst_version: "0.1.0".to_string(),
                        profile: args.profile.clone(),
                        device: DeviceInfo {
                            id: yk_device_id,
                            model: "TrustEdgeRefCam".to_string(),
                            firmware_version: "1.0.0".to_string(),
                            public_key: pub_key_str.clone(),
                            key_agreement_public: None,
                        },
                        metadata: metadata.clone(),
                        chunk: ChunkInfo {
                            size_bytes: args.chunk_size as u64,
                            duration_seconds: chunk_seconds,
                        },
                        segments: segments.clone(),
                        claims: vec!["location:unknown".to_string()],
                        encryption: None,
                        prev_archive_hash: None,
                        signature: None,
                    };
                    tmp.to_canonical_bytes()?
                };

                // Sign with YubiKey hardware (ECDSA P-256)
                let sign_result = backend
                    .perform_operation(
                        &args.slot,
                        CryptoOperation::Sign {
                            data: canonical_bytes,
                            algorithm: SignatureAlgorithm::EcdsaP256,
                        },
                    )
                    .map_err(|e| anyhow::anyhow!("YubiKey signing failed: {}", e))?;
                let sig_bytes = match sign_result {
                    CryptoResult::Signed(b) => b,
                    _ => anyhow::bail!("Unexpected result from Sign operation"),
                };
                let sig_str = format!(
                    "ecdsa-p256:{}",
                    base64::engine::general_purpose::STANDARD.encode(&sig_bytes)
                );

                (pub_key_str, sig_str)
            }
            #[cfg(not(feature = "yubikey"))]
            {
                anyhow::bail!("YubiKey support requires building with --features yubikey");
            }
        }
        other => anyhow::bail!("Unknown backend '{}'. Use 'software' or 'yubikey'", other),
    };

    // Recompute device_id from the final signing public key (handles yubikey override)
    let final_device_id = pub_key_to_device_id(&signing_public_key)?;

    // Build the TrstManifest with the final public key and device_id
    let signed_manifest = TrstManifest {
        trst_version: "0.1.0".to_string(),
        profile: args.profile.clone(),
        device: DeviceInfo {
            id: final_device_id,
            model: "TrustEdgeRefCam".to_string(),
            firmware_version: "1.0.0".to_string(),
            public_key: signing_public_key,
            key_agreement_public: None,
        },
        metadata,
        chunk: ChunkInfo {
            size_bytes: args.chunk_size as u64,
            duration_seconds: chunk_seconds,
        },
        segments,
        claims: vec!["location:unknown".to_string()],
        encryption: None,
        prev_archive_hash: None,
        signature: Some(signature.clone()),
    };

    // Write archive
    let detached_sig = signature.as_bytes();
    write_archive(
        &args.output,
        &signed_manifest,
        encrypted_chunks,
        detached_sig,
    )?;

    let result = WrapResult {
        output_dir: args.output,
        signature,
        chunk_count: chunks.len(),
    };

    println!("Archive: {}", result.output_dir.display());
    println!("Signature: {}", result.signature);
    println!("Segments: {}", result.chunk_count);
    if generated {
        println!("Generated device key: {}", secret_path.display());
        println!("Generated device pub: {}", public_path.display());
    }

    Ok(())
}

fn handle_verify(args: VerifyCmd) -> Result<()> {
    let start_time = Instant::now();

    // Initialize report with defaults
    let mut report = VerifyReport::default();

    // Handle IO/Schema errors (exit 12)
    let (manifest, _chunks) = match read_archive(&args.archive) {
        Ok(data) => data,
        Err(e) => {
            report.error = Some(format!("Archive read failed: {}", e));
            report.verify_time_ms = start_time.elapsed().as_millis() as u64;

            // Map error types to human messages
            let first_line = match e {
                sealedge_core::archive::ArchiveError::MissingChunk(_) => "Missing chunk file",
                sealedge_core::archive::ArchiveError::UnreferencedChunk(_) => {
                    "Unreferenced chunk file"
                }
                sealedge_core::archive::ArchiveError::InvalidChunkIndex { .. } => {
                    "Missing chunk file"
                }
                sealedge_core::archive::ArchiveError::Json(_) => "Invalid manifest format",
                sealedge_core::archive::ArchiveError::SignatureMismatch => {
                    "Signature verification failed"
                }
                sealedge_core::archive::ArchiveError::Io(_) => "Archive read error",
                sealedge_core::archive::ArchiveError::SchemaMismatch(_) => "Schema error",
                sealedge_core::archive::ArchiveError::Manifest(_) => "Manifest error",
                sealedge_core::archive::ArchiveError::Chain(_) => "Continuity chain error",
                sealedge_core::archive::ArchiveError::ValidationFailed(_) => "Validation error",
            };

            output_error(&args, &report, first_line)?;
            return Err(CliExitError {
                code: 12,
                message: first_line.to_string(),
            }
            .into());
        }
    };

    // Parse device public key: pass through recognized prefixes, default bare keys to ed25519
    let device_pub_key =
        if args.device_pub.starts_with("ed25519:") || args.device_pub.starts_with("ecdsa-p256:") {
            args.device_pub.clone()
        } else {
            format!("ed25519:{}", args.device_pub)
        };

    // Populate report with manifest data
    report.profile = manifest.profile.clone();
    report.device_id = manifest.device.id.clone();
    report.segments = manifest.segments.len() as u32;
    report.duration_s = manifest
        .segments
        .iter()
        .map(|s| s.duration_seconds as f32)
        .sum();

    // Check for signature presence (schema error)
    let signature = match manifest.signature.as_ref() {
        Some(sig) => sig,
        None => {
            report.signature = "fail".to_string();
            report.continuity = "skip".to_string();
            report.error = Some("Manifest missing signature".to_string());
            report.verify_time_ms = start_time.elapsed().as_millis() as u64;
            output_error(&args, &report, "Manifest missing signature")?;
            return Err(CliExitError {
                code: 12,
                message: "Manifest missing signature".to_string(),
            }
            .into());
        }
    };

    // Get canonical bytes (internal error if this fails)
    let canonical_bytes = match manifest.to_canonical_bytes() {
        Ok(bytes) => bytes,
        Err(e) => {
            report.signature = "fail".to_string();
            report.continuity = "skip".to_string();
            report.error = Some(format!("Canonical serialization failed: {}", e));
            report.verify_time_ms = start_time.elapsed().as_millis() as u64;
            output_error(&args, &report, "Internal canonicalization error")?;
            return Err(CliExitError {
                code: 14,
                message: "Internal canonicalization error".to_string(),
            }
            .into());
        }
    };

    // Verify signature (exit 10 on failure)
    match verify_manifest(&device_pub_key, &canonical_bytes, signature) {
        Ok(true) => {
            report.signature = "pass".to_string();

            // Validate archive structure and continuity (exit 11 on failure)
            match validate_archive(&args.archive) {
                Ok(()) => {
                    report.continuity = "pass".to_string();
                }
                Err(e) => {
                    report.continuity = "fail".to_string();
                    let error_msg = format!("{}", e);
                    report.error = Some(error_msg.clone());

                    // Extract structured information from chain errors
                    if let sealedge_core::archive::ArchiveError::Chain(chain_err) = &e {
                        match chain_err {
                            sealedge_core::chain::ChainError::Gap(index) => {
                                report.first_gap_index = Some(*index as u32);
                            }
                            sealedge_core::chain::ChainError::OutOfOrder { .. } => {
                                report.out_of_order = Some(true);
                            }
                            _ => {} // Other chain errors don't have specific structured data
                        }
                    }

                    report.verify_time_ms = start_time.elapsed().as_millis() as u64;
                    output_continuity_error(&args, &report)?;
                    return Err(CliExitError {
                        code: 11,
                        message: "Continuity chain verification failed".to_string(),
                    }
                    .into());
                }
            }
        }
        Ok(false) => {
            report.signature = "fail".to_string();
            report.continuity = "skip".to_string();
            report.error = Some("Signature verification failed".to_string());
            report.verify_time_ms = start_time.elapsed().as_millis() as u64;
            output_error(&args, &report, "Signature verification failed")?;
            return Err(CliExitError {
                code: 10,
                message: "Signature verification failed".to_string(),
            }
            .into());
        }
        Err(e) => {
            report.signature = "fail".to_string();
            report.continuity = "skip".to_string();
            report.error = Some(format!("Signature verification error: {}", e));
            report.verify_time_ms = start_time.elapsed().as_millis() as u64;
            output_error(&args, &report, "Signature verification failed")?;
            return Err(CliExitError {
                code: 10,
                message: "Signature verification failed".to_string(),
            }
            .into());
        }
    }

    // Success case
    report.verify_time_ms = start_time.elapsed().as_millis() as u64;
    output_success(&args, &report)?;
    Ok(())
}

fn handle_unwrap(args: UnwrapCmd) -> Result<()> {
    if args.unencrypted {
        warn_unencrypted();
    }
    // Load device keypair from file
    let key_bytes = fs::read(&args.device_key)
        .with_context(|| format!("failed to read device key '{}'", args.device_key.display()))?;
    let device_keypair = if is_encrypted_key_file(&key_bytes) {
        let passphrase =
            rpassword::prompt_password("Passphrase: ").context("Failed to read passphrase")?;
        DeviceKeypair::import_secret_encrypted(&key_bytes, &passphrase)
            .map_err(|e| anyhow::anyhow!("Failed to decrypt key: {}", e))?
    } else if args.unencrypted {
        let contents = String::from_utf8_lossy(&key_bytes).trim().to_string();
        DeviceKeypair::import_secret(&contents)
            .map_err(|e| anyhow::anyhow!("Failed to import key: {}", e))?
    } else {
        anyhow::bail!("Key file is not encrypted. Use --unencrypted to bypass.");
    };

    // Read archive
    let (manifest, chunks) = read_archive(&args.archive)
        .with_context(|| format!("Failed to read archive: {}", args.archive.display()))?;

    // Verify signature BEFORE any decryption
    let signature = manifest
        .signature
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Archive has no signature"))?;
    let canonical_bytes = manifest.to_canonical_bytes()?;
    let sig_valid = verify_manifest(&device_keypair.public, &canonical_bytes, signature)?;
    if !sig_valid {
        eprintln!("Signature: FAIL");
        return Err(CliExitError {
            code: 10,
            message: "Signature: FAIL".to_string(),
        }
        .into());
    }
    eprintln!("Signature: PASS");

    // Validate continuity chain
    if let Err(e) = validate_archive(&args.archive) {
        eprintln!("Continuity: FAIL ({})", e);
        return Err(CliExitError {
            code: 11,
            message: format!("Continuity: FAIL ({})", e),
        }
        .into());
    }
    eprintln!("Continuity: PASS");

    // Derive chunk key from device signing key via HKDF-SHA256
    let encryption_key = derive_chunk_key(device_keypair.secret_bytes());

    // Extract started_at from metadata for AAD reconstruction
    let started_at = match &manifest.metadata {
        ProfileMetadata::CamVideo(m) => m.started_at.clone(),
        ProfileMetadata::Sensor(m) => m.started_at.clone(),
        ProfileMetadata::Audio(m) => m.started_at.clone(),
        ProfileMetadata::Log(m) => m.started_at.clone(),
        ProfileMetadata::Generic(m) => m.started_at.clone(),
    };

    // Decrypt chunks in order and reassemble
    let aad = generate_aad(
        &manifest.trst_version,
        &manifest.profile,
        &manifest.device.id,
        &started_at,
    );
    let mut output_data: Vec<u8> = Vec::new();

    for (index, chunk_bytes) in &chunks {
        if chunk_bytes.len() < 24 {
            anyhow::bail!(
                "Chunk {:05} too short to contain nonce ({} bytes)",
                index,
                chunk_bytes.len()
            );
        }
        let nonce: [u8; 24] = chunk_bytes[..24].try_into().unwrap();
        let ciphertext = &chunk_bytes[24..];
        let plaintext =
            decrypt_segment(&encryption_key, &nonce, ciphertext, &aad).map_err(|e| {
                CliExitError {
                    code: 1,
                    message: format!(
                        "Decryption failed — wrong device key or corrupted archive: {}",
                        e
                    ),
                }
            })?;
        output_data.extend_from_slice(&plaintext);
    }

    // Write output file
    fs::write(&args.output, &output_data)
        .with_context(|| format!("Failed to write output: {}", args.output.display()))?;

    // Print summary to stderr
    eprintln!("Chunks: {}", chunks.len());
    eprintln!("Bytes: {}", output_data.len());
    eprintln!("Output: {}", args.output.display());

    Ok(())
}

fn output_success(args: &VerifyCmd, report: &VerifyReport) -> Result<()> {
    if args.json {
        let json_output = serde_json::to_string(report)?;
        println!("{}", json_output);
    } else {
        println!("Signature: PASS");
        println!("Continuity: PASS");
        println!(
            "Segments: {}  Duration(s): {:.1}  Chunk(s): {:.1}",
            report.segments,
            report.duration_s,
            if report.segments > 0 {
                report.duration_s / report.segments as f32
            } else {
                0.0
            }
        );
    }

    // Emit receipt if requested
    if let Some(receipt_path) = &args.emit_receipt {
        let json_output = serde_json::to_string_pretty(report)?;
        fs::write(receipt_path, json_output)?;
    }

    Ok(())
}

fn output_error(args: &VerifyCmd, report: &VerifyReport, first_line: &str) -> Result<()> {
    if args.json {
        let json_output = serde_json::to_string(report)?;
        println!("{}", json_output);
    } else {
        eprintln!("{}", first_line);
    }

    // Emit receipt if requested
    if let Some(receipt_path) = &args.emit_receipt {
        let json_output = serde_json::to_string_pretty(report)?;
        fs::write(receipt_path, json_output)?;
    }

    Ok(())
}

fn output_continuity_error(args: &VerifyCmd, report: &VerifyReport) -> Result<()> {
    if args.json {
        let json_output = serde_json::to_string(report)?;
        println!("{}", json_output);
    } else {
        // Check error message for specific failure types
        if let Some(error) = &report.error {
            if error.contains("hash mismatch") {
                eprintln!("hash mismatch");
                return Ok(());
            }
            if error.contains("Unreferenced chunk file") {
                eprintln!("Unreferenced chunk file: {}", error);
                return Ok(());
            }
        }

        // Extract concise first line for continuity errors
        if let Some(gap_idx) = report.first_gap_index {
            eprintln!("Continuity: FAIL (gap at index {})", gap_idx);
        } else if report.out_of_order == Some(true) {
            eprintln!("Continuity: FAIL (segments out of order)");
        } else {
            eprintln!("Continuity: FAIL");
        }
    }

    // Emit receipt if requested
    if let Some(receipt_path) = &args.emit_receipt {
        let json_output = serde_json::to_string_pretty(report)?;
        fs::write(receipt_path, json_output)?;
    }

    Ok(())
}

// Removed: extract_gap_index() function eliminated string parsing
// Gap index information should come from structured error types, not string parsing

fn load_or_generate_keypair(
    path: Option<&Path>,
    unencrypted: bool,
) -> Result<(DeviceKeypair, PathBuf, PathBuf, bool)> {
    match path {
        Some(existing) => {
            let key_bytes = fs::read(existing)
                .with_context(|| format!("failed to read device key '{}'", existing.display()))?;
            let device_keypair = if is_encrypted_key_file(&key_bytes) {
                if unencrypted {
                    anyhow::bail!("Cannot use --unencrypted with an encrypted key file");
                }
                let passphrase = rpassword::prompt_password("Passphrase: ")
                    .context("Failed to read passphrase")?;
                DeviceKeypair::import_secret_encrypted(&key_bytes, &passphrase)
                    .map_err(|e| anyhow::anyhow!("Failed to decrypt key: {}", e))?
            } else if unencrypted {
                let contents = String::from_utf8_lossy(&key_bytes).trim().to_string();
                DeviceKeypair::import_secret(&contents)
                    .map_err(|e| anyhow::anyhow!("Failed to import key: {}", e))?
            } else {
                anyhow::bail!("Key file is not encrypted. Use --unencrypted to bypass.");
            };
            let public_path = existing.with_extension("pub");
            Ok((device_keypair, existing.to_path_buf(), public_path, false))
        }
        None => {
            let device_keypair = DeviceKeypair::generate()?;
            let secret_path = PathBuf::from("device.key");
            let public_path = PathBuf::from("device.pub");
            if unencrypted {
                let secret_string = device_keypair.export_secret();
                let public_string = device_keypair.public.clone();
                fs::write(&secret_path, format!("{secret_string}\n"))?;
                fs::write(&public_path, format!("{public_string}\n"))?;
            } else {
                let passphrase = rpassword::prompt_password("Passphrase: ")
                    .context("Failed to read passphrase")?;
                let confirm = rpassword::prompt_password("Confirm passphrase: ")
                    .context("Failed to read passphrase confirmation")?;
                if passphrase != confirm {
                    anyhow::bail!("Passphrases do not match");
                }
                let encrypted = device_keypair
                    .export_secret_encrypted(&passphrase)
                    .context("Failed to encrypt key")?;
                fs::write(&secret_path, &encrypted)?;
                let public_string = device_keypair.public.clone();
                fs::write(&public_path, format!("{public_string}\n"))?;
            }
            // Set secret key file to owner-only permissions (0600)
            #[cfg(unix)]
            {
                let perms = std::fs::Permissions::from_mode(0o600);
                std::fs::set_permissions(&secret_path, perms).with_context(|| {
                    format!("Failed to set permissions on {}", secret_path.display())
                })?;
            }
            #[cfg(not(unix))]
            {
                eprintln!(
                    "Warning: Unable to restrict key file permissions on this platform. Manually restrict access to {}",
                    secret_path.display()
                );
            }
            Ok((device_keypair, secret_path, public_path, true))
        }
    }
}

fn current_timestamp() -> Result<String> {
    let now: DateTime<Utc> = Utc::now();
    Ok(now.to_rfc3339_opts(SecondsFormat::Secs, true))
}

async fn handle_emit_request(args: EmitRequestCmd) -> Result<()> {
    // Read manifest from archive
    let (manifest, chunks) = read_archive(&args.archive)
        .with_context(|| format!("Failed to read archive: {}", args.archive.display()))?;

    // Compute segments by BLAKE3 over each chunk in sorted order
    let mut segments = Vec::new();
    for (chunk_index, chunk_data) in chunks.iter() {
        let mut hasher = Hasher::new();
        hasher.update(chunk_data);
        let hash = hasher.finalize();
        let hash_hex = format!("b3:{}", hex::encode(hash.as_bytes()));

        segments.push(SegmentRef {
            index: *chunk_index as u32,
            hash: hash_hex,
        });
    }

    // Load device pub from file
    let device_pub_content = fs::read_to_string(&args.device_pub).with_context(|| {
        format!(
            "Failed to read device pub file: {}",
            args.device_pub.display()
        )
    })?;
    let device_pub = device_pub_content.trim().to_string();

    // Build VerifyRequest using shared sealedge_types::verification::VerifyRequest.
    // TrstManifest is serialized to serde_json::Value for compatibility with the shared type.
    let manifest_value = serde_json::to_value(&manifest)
        .with_context(|| "Failed to serialize manifest to JSON value")?;
    let verify_request = VerifyRequest {
        device_pub: device_pub.clone(),
        manifest: manifest_value,
        segments,
        options: VerifyOptions {
            return_receipt: true,
            device_id: Some(manifest.device.id.clone()),
        },
    };

    // Write JSON to output file
    let json_output = serde_json::to_string_pretty(&verify_request)?;
    fs::write(&args.out, &json_output)
        .with_context(|| format!("Failed to write output file: {}", args.out.display()))?;

    println!("Generated verify request: {}", args.out.display());

    // If --post provided, POST it and handle response
    if let Some(post_url) = args.post {
        let client = reqwest::Client::new();
        let response = client
            .post(&post_url)
            .json(&verify_request)
            .send()
            .await
            .with_context(|| format!("Failed to POST to {}", post_url))?;

        let status = response.status();
        if status.is_success() {
            let response_text = response.text().await?;
            // Try to parse as JSON for pretty printing
            match serde_json::from_str::<serde_json::Value>(&response_text) {
                Ok(json_value) => {
                    let pretty_json = serde_json::to_string_pretty(&json_value)?;
                    println!("{}", pretty_json);
                }
                Err(_) => {
                    println!("{}", response_text);
                }
            }
        } else {
            let error_text = response.text().await?;
            eprintln!(
                "HTTP {} {}",
                status.as_u16(),
                status.canonical_reason().unwrap_or("")
            );
            eprintln!("{}", error_text);
            return Err(CliExitError {
                code: status.as_u16() as i32,
                message: format!(
                    "HTTP {} {}",
                    status.as_u16(),
                    status.canonical_reason().unwrap_or("")
                ),
            }
            .into());
        }
    }

    Ok(())
}

fn handle_attest_sbom(args: AttestSbomCmd) -> Result<()> {
    if args.unencrypted {
        warn_unencrypted();
    }

    // Validate binary file
    let binary_meta = fs::metadata(&args.binary)
        .with_context(|| format!("Failed to read binary file: {}", args.binary.display()))?;
    let binary_size = binary_meta.len();
    if binary_size == 0 {
        return Err(CliExitError {
            code: 1,
            message: "Error: binary file is empty (0 bytes)".to_string(),
        }
        .into());
    }
    const MAX_BINARY_SIZE: u64 = 256 * 1024 * 1024;
    if binary_size > MAX_BINARY_SIZE {
        return Err(CliExitError {
            code: 1,
            message: format!(
                "Error: binary file exceeds 256 MB limit ({} bytes)",
                binary_size
            ),
        }
        .into());
    }

    // Validate SBOM is valid JSON
    let sbom_content = fs::read_to_string(&args.sbom)
        .with_context(|| format!("Failed to read SBOM file: {}", args.sbom.display()))?;
    if serde_json::from_str::<serde_json::Value>(&sbom_content).is_err() {
        return Err(CliExitError {
            code: 1,
            message: "Error: SBOM file is not valid JSON".to_string(),
        }
        .into());
    }

    // Load device keypair
    let key_bytes = fs::read(&args.device_key)
        .with_context(|| format!("failed to read device key '{}'", args.device_key.display()))?;
    let device_keypair = if args.unencrypted {
        let contents = String::from_utf8_lossy(&key_bytes).trim().to_string();
        DeviceKeypair::import_secret(&contents)
            .map_err(|e| anyhow::anyhow!("Failed to import key: {}", e))?
    } else if is_encrypted_key_file(&key_bytes) {
        let passphrase = rpassword::prompt_password("Enter passphrase for device key: ")
            .context("Failed to read passphrase")?;
        DeviceKeypair::import_secret_encrypted(&key_bytes, &passphrase)
            .map_err(|e| anyhow::anyhow!("Failed to decrypt key: {}", e))?
    } else {
        anyhow::bail!("Key file is not encrypted. Use --unencrypted to bypass.");
    };

    // Create attestation
    let attestation =
        PointAttestation::create(&args.binary, "binary", &args.sbom, "sbom", &device_keypair)
            .with_context(|| "Failed to create attestation")?;

    // Serialize to JSON
    let json = attestation
        .to_json()
        .with_context(|| "Failed to serialize attestation")?;

    // Determine output path
    let out_path = args
        .out
        .unwrap_or_else(|| PathBuf::from("attestation.se-attestation.json"));

    // Write output file
    fs::write(&out_path, &json)
        .with_context(|| format!("Failed to write attestation: {}", out_path.display()))?;

    // Set permissions to 0644 on Unix (public data, not secret)
    #[cfg(unix)]
    {
        let perms = std::fs::Permissions::from_mode(0o644);
        std::fs::set_permissions(&out_path, perms)
            .with_context(|| format!("Failed to set permissions on {}", out_path.display()))?;
    }

    eprintln!("\u{2714} Attestation written to {}", out_path.display());
    eprintln!("  Public key: {}", attestation.public_key);
    eprintln!(
        "  Subject:    {} ({})",
        attestation.subject.hash, attestation.subject.filename
    );
    eprintln!(
        "  Evidence:   {} ({})",
        attestation.evidence.hash, attestation.evidence.filename
    );

    Ok(())
}

fn handle_verify_attestation(args: VerifyAttestationCmd) -> Result<()> {
    // Read attestation file
    let attestation_json = fs::read_to_string(&args.attestation)
        .with_context(|| format!("Failed to read attestation: {}", args.attestation.display()))?;
    let attestation = PointAttestation::from_json(&attestation_json)
        .with_context(|| "Failed to parse attestation JSON")?;

    // Resolve device public key: inline "ed25519:..." or file path
    let device_pub = if args.device_pub.starts_with("ed25519:") {
        args.device_pub.clone()
    } else {
        let content = fs::read_to_string(&args.device_pub)
            .with_context(|| format!("Failed to read public key file: {}", args.device_pub))?;
        content.trim().to_string()
    };

    // Verify signature
    let sig_valid = attestation
        .verify_signature(&device_pub)
        .with_context(|| "Failed to verify signature")?;

    // Optionally verify file hashes
    if args.binary.is_some() || args.sbom.is_some() {
        let binary_ref = args.binary.as_deref();
        let sbom_ref = args.sbom.as_deref();
        if let Err(e) = attestation.verify_file_hashes(binary_ref, sbom_ref) {
            println!("Format:     {}", attestation.format);
            println!("Public key: {}", attestation.public_key);
            println!("Timestamp:  {}", attestation.timestamp);
            println!(
                "Subject:    {} ({})",
                attestation.subject.hash, attestation.subject.filename
            );
            println!(
                "Evidence:   {} ({})",
                attestation.evidence.hash, attestation.evidence.filename
            );
            println!("Signature:  FAILED");
            return Err(CliExitError {
                code: 10,
                message: format!("Hash mismatch: {}", e),
            }
            .into());
        }
    }

    // Print human-readable result
    println!("Format:     {}", attestation.format);
    println!("Public key: {}", attestation.public_key);
    println!("Timestamp:  {}", attestation.timestamp);
    println!(
        "Subject:    {} ({})",
        attestation.subject.hash, attestation.subject.filename
    );
    println!(
        "Evidence:   {} ({})",
        attestation.evidence.hash, attestation.evidence.filename
    );

    if sig_valid {
        println!("Signature:  VERIFIED");
        Ok(())
    } else {
        println!("Signature:  FAILED");
        Err(CliExitError {
            code: 10,
            message: "Signature verification failed".to_string(),
        }
        .into())
    }
}
