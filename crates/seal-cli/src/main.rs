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
    archive_digest, cek_wrap_info, chunk_aad_v2, decrypt_segment, encrypt_segment,
    format_archive_id, hpke_open_cek, hpke_seal_cek, hpke_seal_cek_with_rng, is_encrypted_key_file,
    read_manifest, recipient_id, seeded_test_rng, segment_hash, sign_manifest, validate_archive,
    verify_manifest, ArchiveWriter, AudioMetadata, CamVideoMetadata, ChronicleState, ChunkInfo,
    ContentKey, DeviceBundle, DeviceInfo, DeviceKeypair, EncryptionBlock, GenericMetadata,
    HpkeSuite, LogMetadata, PointAttestation, ProfileMetadata, RecipientEntry, RotationRecord,
    SegmentInfo, SensorMetadata, TrstManifest, WitnessRequest, CONTENT_AEAD_ID, HPKE_AEAD_ID,
    HPKE_KDF_ID, HPKE_KEM_ID,
};
use serde::Serialize;
use std::io::{BufReader, BufWriter, Read, Write as _};
use std::time::Instant;
use zeroize::Zeroizing;
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
    #[serde(skip_serializing_if = "Option::is_none")]
    chronicle_sequence: Option<u64>, // This archive's chronicle position (if any)
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
    VerifyChronicle(VerifyChronicleCmd),
    Rekey(RekeyCmd),
    Witness(WitnessCmd),
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
    /// Additional recipient X25519 public key(s) ("x25519:<base64>") that may
    /// decrypt this archive. The device key is always recipient #0. Repeatable.
    #[arg(long = "recipient", value_name = "X25519_PUB")]
    recipients: Vec<String>,
    /// Produce a signed-but-unencrypted archive (plaintext chunks, no CEK).
    #[arg(long = "sign-only")]
    sign_only: bool,
    /// Chronicle state file to read and advance (the device's head pointer). An
    /// absent file starts a new chronicle at sequence 0 (genesis).
    #[arg(long = "chronicle", value_name = "PATH")]
    chronicle: Option<PathBuf>,
    /// Link onto a specific previous archive (derives its digest + sequence).
    #[arg(long = "prev-archive", value_name = "PATH")]
    prev_archive: Option<PathBuf>,
    /// Explicit previous archive digest ("b3:<hex>"); requires --prev-seq.
    #[arg(long = "prev-hash", value_name = "B3")]
    prev_hash: Option<String>,
    /// Sequence of the previous archive (used with --prev-hash).
    #[arg(long = "prev-seq", value_name = "N")]
    prev_seq: Option<u64>,
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
struct VerifyChronicleCmd {
    /// One or more `.seal` archives, or a directory containing them.
    #[arg(value_name = "PATHS", required = true, num_args = 1..)]
    paths: Vec<PathBuf>,
    #[arg(
        long = "device-pub",
        value_name = "KEY",
        help = "Expected signer public key (ed25519:<base64>)"
    )]
    device_pub: String,
    #[arg(long, help = "Output results as JSON")]
    json: bool,
    /// Witness receipt (JWS) to cross-check the local tip against (detects tail
    /// deletion). Requires --witness-jwks.
    #[arg(long = "witness", value_name = "PATH")]
    witness: Option<PathBuf>,
    /// Platform JWKS (URL or file path) used to verify the witness receipt.
    #[arg(long = "witness-jwks", value_name = "URL|PATH")]
    witness_jwks: Option<String>,
}

#[derive(Args, Debug)]
struct WitnessCmd {
    #[arg(
        long = "chronicle",
        value_name = "PATH",
        help = "Chronicle state file whose tip to witness"
    )]
    chronicle: PathBuf,
    #[arg(
        long = "device-key",
        value_name = "PATH",
        help = "Device key bundle that signs the witness request"
    )]
    device_key: PathBuf,
    #[arg(
        long = "out",
        value_name = "PATH",
        help = "Write the receipt (with --post) or the signed request (without)"
    )]
    out: Option<PathBuf>,
    #[arg(
        long = "post",
        value_name = "URL",
        help = "Platform /v1/witness endpoint to submit to"
    )]
    post: Option<String>,
    /// Rotation entry directory to attach when the tip being witnessed is a
    /// rotation (H1 Phase 2) — lets the platform verify it and record lineage.
    #[arg(long = "rotation", value_name = "DIR")]
    rotation: Option<PathBuf>,
    /// Accept a plaintext key bundle without a passphrase (CI/automation only).
    #[arg(long)]
    unencrypted: bool,
}

#[derive(Args, Debug)]
struct RekeyCmd {
    #[arg(
        long = "chronicle",
        value_name = "PATH",
        help = "Chronicle state file to rotate and advance"
    )]
    chronicle: PathBuf,
    #[arg(
        long = "old-key",
        value_name = "PATH",
        help = "Current device key bundle (authorizes the successor)"
    )]
    old_key: PathBuf,
    #[arg(
        long = "new-key",
        value_name = "PATH",
        help = "Pre-generated new device key bundle (run `seal keygen` first)"
    )]
    new_key: PathBuf,
    #[arg(
        long = "out",
        value_name = "DIR",
        help = "Output directory for the rotation entry (contains rotation.json)"
    )]
    out: PathBuf,
    /// Accept plaintext key bundles without a passphrase (CI/automation only).
    #[arg(long)]
    unencrypted: bool,
}

#[derive(Args, Debug)]
struct UnwrapCmd {
    #[arg(value_name = "ARCHIVE", help = "Path to .seal archive directory")]
    archive: PathBuf,
    #[arg(
        long = "device-key",
        value_name = "PATH",
        help = "Path to the recipient's V2 key bundle (device owner or auditor)"
    )]
    device_key: PathBuf,
    #[arg(
        long = "out",
        value_name = "PATH",
        help = "Output file path for recovered data"
    )]
    output: PathBuf,
    /// Optional expected signer. When set, unwrap fails unless it equals the
    /// manifest's device.public_key. The signature is always verified against the
    /// manifest's embedded key regardless; this flag pins which signer you expect.
    #[arg(
        long = "device-pub",
        value_name = "KEY",
        help = "Optional expected signer (ed25519:<base64>); pins manifest.device.public_key"
    )]
    device_pub: Option<String>,
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

/// Read up to `size` bytes, coalescing short `Read`s so each returned buffer is
/// exactly `size` except the final one (which may be shorter). Returns an empty
/// buffer at EOF. This reproduces `slice::chunks(size)` boundaries while reading
/// the input incrementally (H3 streaming wrap) — identical chunk boundaries keep
/// the CEK/nonce sequence and every hash byte-identical to the pre-stream path.
fn read_exact_or_eof<R: Read>(reader: &mut R, size: usize) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; size];
    let mut filled = 0;
    while filled < size {
        let n = reader.read(&mut buf[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    buf.truncate(filled);
    Ok(buf)
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
        Commands::VerifyChronicle(args) => handle_verify_chronicle(args).await,
        Commands::Rekey(args) => handle_rekey(args),
        Commands::Witness(args) => handle_witness(args).await,
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

    // C4: a device now has an Ed25519 signing key AND an independent X25519
    // key-agreement key, persisted together as a SEALEDGE-KEY-V2 bundle.
    let bundle = DeviceBundle::generate()?;

    if args.unencrypted {
        // Append the newline into the zeroizing buffer (no unzeroed format! copy).
        let mut pt = bundle.to_plaintext();
        pt.push('\n');
        fs::write(&args.out_key, pt.as_bytes())
            .with_context(|| format!("Failed to write secret key: {}", args.out_key.display()))?;
    } else {
        let passphrase = Zeroizing::new(
            rpassword::prompt_password("Passphrase: ").context("Failed to read passphrase")?,
        );
        let confirm = Zeroizing::new(
            rpassword::prompt_password("Confirm passphrase: ")
                .context("Failed to read passphrase confirmation")?,
        );
        if *passphrase != *confirm {
            anyhow::bail!("Passphrases do not match");
        }
        let encrypted = bundle
            .export_encrypted(&passphrase)
            .context("Failed to encrypt key bundle")?;
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

    // Public file carries both keys, one per line: ed25519:...\nx25519:...\n
    fs::write(&args.out_pub, bundle.public_lines())
        .with_context(|| format!("Failed to write public key: {}", args.out_pub.display()))?;

    println!("Generated device key: {}", args.out_key.display());
    println!("Generated device pub: {}", args.out_pub.display());
    Ok(())
}

/// Load a `SEALEDGE-KEY-V2` device bundle from a file (encrypted or, with
/// `unencrypted`, plaintext). A legacy V1 (`SEALEDGE-KEY-V1` / bare `ed25519:`)
/// key is rejected with an actionable error — content encryption (C4) needs the
/// X25519 key that only V2 bundles carry.
fn load_bundle(path: &Path, unencrypted: bool) -> Result<DeviceBundle> {
    let bytes = fs::read(path)
        .with_context(|| format!("failed to read device key '{}'", path.display()))?;

    if bytes.starts_with(b"SEALEDGE-KEY-V2\n") {
        if unencrypted {
            anyhow::bail!("Cannot use --unencrypted with an encrypted key bundle");
        }
        let passphrase = Zeroizing::new(
            rpassword::prompt_password("Passphrase: ").context("Failed to read passphrase")?,
        );
        return DeviceBundle::import_encrypted(&bytes, &passphrase)
            .map_err(|e| anyhow::anyhow!("Failed to decrypt key bundle: {}", e));
    }

    if unencrypted {
        let contents = String::from_utf8_lossy(&bytes);
        if let Ok(bundle) = DeviceBundle::from_plaintext(contents.trim()) {
            return Ok(bundle);
        }
    }

    if is_encrypted_key_file(&bytes) || bytes.starts_with(b"ed25519:") {
        anyhow::bail!(
            "Legacy V1 key file detected. C4 archives need a V2 key bundle (Ed25519 + X25519). \
             Run `seal keygen` to generate a new SEALEDGE-KEY-V2 bundle."
        );
    }

    anyhow::bail!("Unrecognized key file format (expected SEALEDGE-KEY-V2)")
}

/// Load only the Ed25519 signing key from a key file. Prefers a `SEALEDGE-KEY-V2`
/// bundle (returning its signing key) and falls back to a legacy V1 key file.
/// Used by operations that sign but do not encrypt (e.g. `attest-sbom`).
fn load_signing_keypair(path: &Path, unencrypted: bool) -> Result<DeviceKeypair> {
    let bytes = fs::read(path)
        .with_context(|| format!("failed to read device key '{}'", path.display()))?;

    if bytes.starts_with(b"SEALEDGE-KEY-V2\n") {
        if unencrypted {
            anyhow::bail!("Cannot use --unencrypted with an encrypted key bundle");
        }
        let passphrase = Zeroizing::new(
            rpassword::prompt_password("Passphrase: ").context("Failed to read passphrase")?,
        );
        return DeviceBundle::import_encrypted(&bytes, &passphrase)
            .map(|b| b.signing)
            .map_err(|e| anyhow::anyhow!("Failed to decrypt key bundle: {}", e));
    }

    if unencrypted {
        let contents = String::from_utf8_lossy(&bytes);
        if let Ok(bundle) = DeviceBundle::from_plaintext(contents.trim()) {
            return Ok(bundle.signing);
        }
        return DeviceKeypair::import_secret(contents.trim())
            .map_err(|e| anyhow::anyhow!("Failed to import key: {}", e));
    }

    if is_encrypted_key_file(&bytes) {
        let passphrase = Zeroizing::new(
            rpassword::prompt_password("Enter passphrase for device key: ")
                .context("Failed to read passphrase")?,
        );
        return DeviceKeypair::import_secret_encrypted(&bytes, &passphrase)
            .map_err(|e| anyhow::anyhow!("Failed to decrypt key: {}", e));
    }

    anyhow::bail!("Key file is not encrypted. Use --unencrypted to bypass.")
}

/// Load an existing V2 bundle, or generate one and write `device.key` +
/// `device.pub` when no path is supplied. Returns `(bundle, key_path, pub_path,
/// generated)`.
fn load_or_generate_bundle(
    path: Option<&Path>,
    unencrypted: bool,
) -> Result<(DeviceBundle, PathBuf, PathBuf, bool)> {
    match path {
        Some(existing) => {
            let bundle = load_bundle(existing, unencrypted)?;
            let public_path = existing.with_extension("pub");
            Ok((bundle, existing.to_path_buf(), public_path, false))
        }
        None => {
            let bundle = DeviceBundle::generate()?;
            let secret_path = PathBuf::from("device.key");
            let public_path = PathBuf::from("device.pub");
            if unencrypted {
                let mut pt = bundle.to_plaintext();
                pt.push('\n');
                fs::write(&secret_path, pt.as_bytes())?;
            } else {
                let passphrase = Zeroizing::new(
                    rpassword::prompt_password("Passphrase: ")
                        .context("Failed to read passphrase")?,
                );
                let confirm = Zeroizing::new(
                    rpassword::prompt_password("Confirm passphrase: ")
                        .context("Failed to read passphrase confirmation")?,
                );
                if *passphrase != *confirm {
                    anyhow::bail!("Passphrases do not match");
                }
                let encrypted = bundle
                    .export_encrypted(&passphrase)
                    .context("Failed to encrypt key bundle")?;
                fs::write(&secret_path, &encrypted)?;
            }
            #[cfg(unix)]
            {
                let perms = std::fs::Permissions::from_mode(0o600);
                std::fs::set_permissions(&secret_path, perms).with_context(|| {
                    format!("Failed to set permissions on {}", secret_path.display())
                })?;
            }
            fs::write(&public_path, bundle.public_lines())?;
            Ok((bundle, secret_path, public_path, true))
        }
    }
}

/// Version dispatch (M3): accept only supported archive formats, rejecting both
/// legacy `0.1.0` and unknown versions with explicit errors — before any
/// signature check, because canonical bytes differ across versions.
fn require_supported_version(trst_version: &str) -> Result<()> {
    match trst_version {
        "0.2.0" => Ok(()),
        "0.1.0" => anyhow::bail!(
            "unsupported legacy archive format 0.1.0 (pre-C4); re-wrap with a current seal build"
        ),
        other => anyhow::bail!("unsupported archive version {other}; upgrade the seal tool"),
    }
}

/// Extract the `started_at` timestamp from any profile's metadata.
fn manifest_started_at(manifest: &TrstManifest) -> String {
    match &manifest.metadata {
        ProfileMetadata::CamVideo(m) => m.started_at.clone(),
        ProfileMetadata::Sensor(m) => m.started_at.clone(),
        ProfileMetadata::Audio(m) => m.started_at.clone(),
        ProfileMetadata::Log(m) => m.started_at.clone(),
        ProfileMetadata::Generic(m) => m.started_at.clone(),
    }
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
        anyhow::bail!("--device-key is required with --backend yubikey");
    }
    // C4: content encryption binds the chunk AAD and HPKE info to the signing
    // key. For yubikey that key lives on hardware (not the device X25519 key we
    // wrap to), so encrypted+yubikey is deferred — require --sign-only there.
    if args.backend == "yubikey" && !args.sign_only {
        anyhow::bail!(
            "--backend yubikey currently requires --sign-only (C4 content encryption is software-backend only)"
        );
    }

    let (bundle, secret_path, public_path, generated) =
        load_or_generate_bundle(args.device_key.as_deref(), args.unencrypted)?;

    // Resolve the signing public key up front: it goes into the manifest, the
    // chunk AAD, and the HPKE info binding (M1). Software uses the bundle's
    // Ed25519 key; yubikey reads it from hardware and keeps a handle to sign
    // the finished manifest below.
    #[cfg(feature = "yubikey")]
    let mut yk_backend: Option<(YubiKeyBackend, String)> = None;
    let signing_public_key: String = match args.backend.as_str() {
        "software" => bundle.signing.public.clone(),
        "yubikey" => {
            #[cfg(feature = "yubikey")]
            {
                let pin =
                    rpassword::prompt_password("YubiKey PIN: ").context("Failed to read PIN")?;
                let config = YubiKeyConfig::builder()
                    .pin(pin)
                    .default_slot(args.slot.clone())
                    .build();
                let backend = YubiKeyBackend::with_config(config)
                    .map_err(|e| anyhow::anyhow!("Failed to connect to YubiKey: {}", e))?;
                let pub_key_result = backend
                    .perform_operation(&args.slot, CryptoOperation::GetPublicKey)
                    .map_err(|e| anyhow::anyhow!("Failed to get YubiKey public key: {}", e))?;
                let der_bytes = match pub_key_result {
                    CryptoResult::PublicKey(b) => b,
                    _ => anyhow::bail!("Unexpected result from GetPublicKey"),
                };
                let p256_pub = p256::PublicKey::from_public_key_der(&der_bytes)
                    .map_err(|e| anyhow::anyhow!("Failed to parse P-256 public key: {}", e))?;
                let sec1_bytes = p256_pub.to_sec1_bytes();
                let pub_key_str = format!(
                    "ecdsa-p256:{}",
                    base64::engine::general_purpose::STANDARD.encode(sec1_bytes.as_ref())
                );
                yk_backend = Some((backend, args.slot.clone()));
                pub_key_str
            }
            #[cfg(not(feature = "yubikey"))]
            {
                anyhow::bail!("YubiKey support requires building with --features yubikey");
            }
        }
        other => anyhow::bail!("Unknown backend '{}'. Use 'software' or 'yubikey'", other),
    };
    let device_id = pub_key_to_device_id(&signing_public_key)?;

    // Reject empty input before creating any output (matches prior behavior and
    // avoids leaving an empty .seal directory). The context string is kept as
    // "Failed to read input file" for a missing/unreadable input so the message
    // is stable (N1) across the streaming rewrite.
    if fs::metadata(&args.input)
        .with_context(|| format!("Failed to read input file: {}", args.input.display()))?
        .len()
        == 0
    {
        anyhow::bail!("Input file is empty");
    }

    // Open input for streaming (H3): read one chunk at a time, never the whole
    // payload — peak RAM is O(chunk_size), not O(payload).
    let input_file = fs::File::open(&args.input)
        .with_context(|| format!("Failed to read input file: {}", args.input.display()))?;
    let mut reader = BufReader::new(input_file);

    // Validate output name, then lay down the .seal skeleton via the streaming
    // writer (it creates chunks/ and signatures/).
    let archive_name = args
        .output
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("Invalid output path"))?
        .to_string_lossy();

    if !archive_name.ends_with(".seal") {
        anyhow::bail!("Output directory must end with .seal");
    }

    let mut writer = ArchiveWriter::create(&args.output)
        .with_context(|| format!("Failed to create archive: {}", args.output.display()))?;

    // Initialize RNG - seeded if provided, otherwise use default
    let mut rng: Box<dyn RngCore> = match args.seed {
        Some(seed) => Box::new(ChaCha20Rng::seed_from_u64(seed)),
        None => Box::new(rand::rng()),
    };
    // Separate rand_core-0.6 CSPRNG for the CEK + HPKE ephemerals so a seeded
    // wrap is byte-deterministic (M2). None ⇒ production OsRng path.
    let mut seed_rng = args.seed.map(seeded_test_rng);

    // Resolve chunk_seconds: cam.video default 2.0, generic default 0.0
    let chunk_seconds = match args.profile.as_str() {
        "cam.video" => args.chunk_seconds.unwrap_or(2.0),
        _ => args.chunk_seconds.unwrap_or(0.0),
    };

    let mut segments = Vec::new();

    // Create timestamp for all operations - deterministic if seeded
    let started_at = if args.seed.is_some() {
        // Use deterministic timestamp for seeded runs
        "2025-01-01T00:00:00Z".to_string()
    } else {
        current_timestamp()?
    };

    // C4: a per-archive random CEK keys the chunk AEAD (deterministic in seed
    // mode via seed_rng). --sign-only leaves chunks in plaintext (no CEK).
    // SA3 determinism: the CEK is drawn ONCE here, pre-loop; per-chunk nonces are
    // drawn in-loop below; the HPKE wrap of the CEK happens post-loop. That fixed
    // interleaving is what keeps seeded output byte-identical — do not reorder it.
    let cek: Option<ContentKey> = if args.sign_only {
        None
    } else if let Some(rng) = seed_rng.as_mut() {
        Some(ContentKey::from_rng(rng))
    } else {
        Some(ContentKey::generate())
    };
    // Chunk AAD binds ciphertext to the full signing identity (M1).
    let chunk_aad = chunk_aad_v2(&signing_public_key, &args.profile, &started_at);

    // Borrow the CEK once as an AEAD key. `from_slice` is a reference into the
    // ContentKey (zeroized on drop) — not a separate owned/non-zeroizing copy.
    let chunk_key = cek
        .as_ref()
        .map(|c| chacha20poly1305::Key::from_slice(c.as_bytes()));

    // Stream the input one chunk_size buffer at a time: read → encrypt → write →
    // segment. Peak RAM is one chunk (+ its ciphertext), independent of payload
    // size. Boundaries match the former `input_data.chunks(chunk_size)` exactly.
    let mut chunk_count = 0usize;
    loop {
        let chunk_data = read_exact_or_eof(&mut reader, args.chunk_size)
            .with_context(|| format!("Failed to read input file: {}", args.input.display()))?;
        if chunk_data.is_empty() {
            break; // EOF (non-empty guaranteed by the metadata check above)
        }
        let i = chunk_count;

        // Encrypted mode: on-disk chunk is [nonce:24][ciphertext]. Sign-only mode
        // stores the plaintext chunk directly. Nonces are drawn in-loop, one per
        // chunk in index order (SA3).
        let stored_chunk = match chunk_key {
            Some(key) => {
                let nonce = generate_seeded_nonce24(&mut *rng);
                let ct = encrypt_segment(key, &nonce, &chunk_data, &chunk_aad)?;
                let mut c = Vec::with_capacity(24 + ct.len());
                c.extend_from_slice(&nonce);
                c.extend_from_slice(&ct);
                c
            }
            None => chunk_data,
        };

        // Stream the chunk to disk (hashes + advances the continuity chain).
        let outcome = writer.push_chunk(&stored_chunk)?;

        // Build start_time: time-based for cam.video, index-based for generic
        let start_time = if args.profile == "cam.video" {
            format!("{:.3}s", i as f64 * chunk_seconds)
        } else {
            format!("segment-{}", i)
        };

        segments.push(SegmentInfo {
            chunk_file: format!("{:05}.bin", outcome.index),
            blake3_hash: hex::encode(outcome.blake3),
            start_time,
            duration_seconds: chunk_seconds,
            continuity_hash: hex::encode(outcome.continuity),
        });
        chunk_count += 1;
    }

    // Build profile metadata and compute end time
    let metadata = match args.profile.as_str() {
        "cam.video" => {
            let fps = args.fps.unwrap_or(30);
            let capture_end_time = if chunk_count > 0 {
                let last_chunk_start = (chunk_count - 1) as f64 * chunk_seconds;
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

    // Build the 0.2.0 manifest (unsigned), wrap the CEK to recipients, then sign.
    let ka_pub = bundle.key_agreement.public_string();
    let mut manifest = TrstManifest {
        trst_version: "0.2.0".to_string(),
        profile: args.profile.clone(),
        device: DeviceInfo {
            id: device_id.clone(),
            model: "TrustEdgeRefCam".to_string(),
            firmware_version: "1.0.0".to_string(),
            public_key: signing_public_key.clone(),
            key_agreement_public: Some(ka_pub.clone()),
            key_epoch: None, // stamped from chronicle state below (H1 Phase 2)
        },
        metadata,
        chunk: ChunkInfo {
            size_bytes: args.chunk_size as u64,
            duration_seconds: chunk_seconds,
        },
        segments,
        claims: vec!["location:unknown".to_string()],
        encryption: None,
        sequence: None,
        prev_archive_hash: None,
        signature: None,
    };

    // H1: resolve chronicle linkage and set it BEFORE the HPKE wrap + signing —
    // sequence and prev_archive_hash are inside the signed canonical bytes (and
    // the pre-encryption digest the CEK is bound to).
    let chronicle_link = resolve_chronicle(
        args.chronicle.as_deref(),
        args.prev_archive.as_deref(),
        args.prev_hash.as_deref(),
        args.prev_seq,
        &signing_public_key,
    )?;
    if let Some(ref link) = chronicle_link {
        manifest.sequence = Some(link.sequence);
        manifest.prev_archive_hash = link.prev.clone();
        // H1 Phase 2: stamp the signing key's epoch (omitted at epoch 0 so
        // genesis archives canonicalize byte-identically to H1).
        manifest.device.key_epoch = (link.key_epoch > 0).then_some(link.key_epoch);
    }

    // Encrypted mode: HPKE-wrap the CEK to each recipient. The HPKE aad binds
    // each wrapped CEK to the manifest-without-encryption digest, so a wrapped
    // CEK cannot be transplanted onto a different manifest (design §7).
    if let Some(cek) = cek.as_ref() {
        let pre_digest = segment_hash(&manifest.to_canonical_bytes()?);
        let info = cek_wrap_info(&signing_public_key, &manifest.trst_version);

        // Recipient #0 is always the device's own key-agreement key; then any
        // --recipient keys (deduplicated, order-stable).
        let mut recipient_pubs = vec![ka_pub.clone()];
        for r in &args.recipients {
            if !recipient_pubs.contains(r) {
                recipient_pubs.push(r.clone());
            }
        }

        let mut recipients = Vec::with_capacity(recipient_pubs.len());
        for pub_str in &recipient_pubs {
            let (enc, wrapped_cek) = match seed_rng.as_mut() {
                Some(rng) => hpke_seal_cek_with_rng(rng, pub_str, &info, &pre_digest, cek)?,
                None => hpke_seal_cek(pub_str, &info, &pre_digest, cek)?,
            };
            recipients.push(RecipientEntry {
                recipient_id: recipient_id(pub_str)?,
                recipient_pub: pub_str.clone(),
                enc,
                wrapped_cek,
            });
        }

        manifest.encryption = Some(EncryptionBlock {
            content_aead: CONTENT_AEAD_ID.to_string(),
            hpke: HpkeSuite {
                kem: HPKE_KEM_ID.to_string(),
                kdf: HPKE_KDF_ID.to_string(),
                aead: HPKE_AEAD_ID.to_string(),
            },
            recipients,
        });
    } else if !args.recipients.is_empty() {
        anyhow::bail!(
            "--recipient cannot be combined with --sign-only (sign-only archives are unencrypted)"
        );
    }

    // Sign the finished manifest's canonical bytes.
    let canonical_bytes = manifest.to_canonical_bytes()?;
    let signature = match args.backend.as_str() {
        "software" => sign_manifest(&bundle.signing, &canonical_bytes)?,
        "yubikey" => {
            #[cfg(feature = "yubikey")]
            {
                let (backend, slot) = yk_backend.as_ref().expect("yubikey backend resolved above");
                let sign_result = backend
                    .perform_operation(
                        slot,
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
                format!(
                    "ecdsa-p256:{}",
                    base64::engine::general_purpose::STANDARD.encode(&sig_bytes)
                )
            }
            #[cfg(not(feature = "yubikey"))]
            {
                unreachable!("yubikey backend rejected earlier without the feature")
            }
        }
        _ => unreachable!("backend validated above"),
    };

    manifest.set_signature(signature.clone());

    // Finalize: write manifest.json + signatures/manifest.sig (chunks already
    // streamed to disk above). SA1: finalize errors if the manifest exceeds the
    // shared reader cap, so wrap never emits an archive verify would reject.
    let detached_sig = signature.as_bytes();
    writer
        .finalize(&manifest, detached_sig)
        .with_context(|| format!("Failed to finalize archive: {}", args.output.display()))?;

    // H1: advance the chronicle head pointer (the tip is the digest of the
    // signed manifest we just wrote).
    if let Some(link) = chronicle_link.as_ref() {
        if let Some(state_path) = link.state_path.as_ref() {
            let tip = format_archive_id(&archive_digest(&manifest)?);
            let state = ChronicleState {
                device_pub: signing_public_key.clone(),
                sequence: link.sequence,
                tip,
                key_epoch: link.key_epoch,
                updated_at: current_timestamp()?,
            };
            state.save(state_path).with_context(|| {
                format!("Failed to update chronicle state: {}", state_path.display())
            })?;
        }
    }

    let result = WrapResult {
        output_dir: args.output,
        signature,
        chunk_count,
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

    // Handle IO/Schema errors (exit 12). Manifest-only (H3 SA2): the chunk hashing
    // happens in validate_archive (streamed) — don't load chunk bytes here.
    let (manifest, _sig) = match read_manifest(&args.archive) {
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

    // Version dispatch (M3): reject legacy/unknown formats with an explicit error
    // before touching the signature (canonical bytes differ across versions).
    if let Err(e) = require_supported_version(&manifest.trst_version) {
        report.error = Some(e.to_string());
        report.verify_time_ms = start_time.elapsed().as_millis() as u64;
        output_error(&args, &report, "Unsupported archive version")?;
        return Err(CliExitError {
            code: 12,
            message: e.to_string(),
        }
        .into());
    }

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
    report.chronicle_sequence = manifest.sequence;
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

/// A process-unique temp path in the same directory as `output`, so the recovered
/// file can be finalized with an atomic same-filesystem rename (F2).
fn unwrap_tmp_path(output: &Path) -> PathBuf {
    let mut name = output
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(format!(".seal-unwrap.{}.partial", std::process::id()));
    match output.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.join(name),
        _ => PathBuf::from(name),
    }
}

/// Deletes a partially-written file on drop unless [`TempFileGuard::disarm`] is
/// called first. Makes `unwrap` all-or-nothing (F2): any early return leaves no
/// truncated output that could be mistaken for a complete recovery.
struct TempFileGuard {
    path: Option<PathBuf>,
}

impl TempFileGuard {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }
    fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if let Some(p) = &self.path {
            let _ = fs::remove_file(p);
        }
    }
}

fn handle_unwrap(args: UnwrapCmd) -> Result<()> {
    if args.unencrypted {
        warn_unencrypted();
    }
    // Load the recipient's V2 key bundle (device owner OR an auditor/insurer).
    let bundle = load_bundle(&args.device_key, args.unencrypted)?;

    // Read the manifest only (bounded); chunks are streamed during recovery below.
    let (manifest, _sig) = read_manifest(&args.archive)
        .with_context(|| format!("Failed to read archive: {}", args.archive.display()))?;

    // Version dispatch (M3) before any signature check.
    require_supported_version(&manifest.trst_version)?;

    // Optional signer pin (N3): if the caller states an expected signer, it must
    // equal the manifest's embedded device key. The signature is verified against
    // that embedded key either way; this just fails closed on an unexpected signer.
    if let Some(expected) = args.device_pub.as_deref() {
        let expected = if expected.starts_with("ed25519:") || expected.starts_with("ecdsa-p256:") {
            expected.to_string()
        } else {
            format!("ed25519:{}", expected)
        };
        if expected != manifest.device.public_key {
            return Err(CliExitError {
                code: 10,
                message: format!(
                    "Signer mismatch: expected {}, archive is signed by {}",
                    expected, manifest.device.public_key
                ),
            }
            .into());
        }
    }

    // Verify signature against the manifest's OWN device.public_key (the signer).
    // The party unwrapping may be a recipient other than the device, so we do NOT
    // verify against the unwrapping key.
    let signature = manifest
        .signature
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Archive has no signature"))?;
    let canonical_bytes = manifest.to_canonical_bytes()?;
    let sig_valid = verify_manifest(&manifest.device.public_key, &canonical_bytes, signature)?;
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

    // Recover content by STREAMING one chunk at a time from disk to the output
    // file (H3) — never materializing the whole payload. Sign-only archives store
    // plaintext chunks; encrypted archives HPKE-open the CEK once, then decrypt
    // each chunk as it is read. validate_archive above already confirmed every
    // chunk exists, hashes, and chains, so the reads here are on trusted files.
    let decrypt_ctx: Option<(ContentKey, [u8; 32])> = match &manifest.encryption {
        None => None,
        Some(enc) => {
            // Find the recipient entry matching our X25519 key.
            let my_pub = bundle.key_agreement.public_string();
            let entry = enc
                .recipients
                .iter()
                .find(|r| r.recipient_pub == my_pub)
                .ok_or_else(|| anyhow::anyhow!("This key is not a recipient of the archive"))?;

            // Recompute the HPKE aad = digest of the manifest WITHOUT its
            // encryption block (must match what wrap sealed against, design §7).
            let pre_digest = {
                let mut pre = manifest.clone();
                pre.encryption = None;
                segment_hash(&pre.to_canonical_bytes()?)
            };
            let info = cek_wrap_info(&manifest.device.public_key, &manifest.trst_version);
            let cek = hpke_open_cek(
                &bundle.key_agreement,
                &entry.enc,
                &info,
                &pre_digest,
                &entry.wrapped_cek,
            )
            .map_err(|e| CliExitError {
                code: 1,
                message: format!("Failed to unwrap content key: {}", e),
            })?;
            let started_at = manifest_started_at(&manifest);
            let chunk_aad =
                chunk_aad_v2(&manifest.device.public_key, &manifest.profile, &started_at);
            Some((cek, chunk_aad))
        }
    };

    let chunks_dir = args.archive.join("chunks");

    // F2: recover to a temp sibling, then atomically rename on success. A guard
    // deletes the temp on any early return (I/O error, disk full, AEAD failure),
    // so unwrap stays all-or-nothing — a partial recovery is never left behind
    // where it could be mistaken for a complete one.
    let tmp_path = unwrap_tmp_path(&args.output);
    let mut cleanup = TempFileGuard::new(tmp_path.clone());
    let out_file = fs::File::create(&tmp_path)
        .with_context(|| format!("Failed to create temp output: {}", tmp_path.display()))?;
    let mut writer = BufWriter::new(out_file);
    let chunk_count = manifest.segments.len();
    let mut total_bytes: usize = 0;

    for index in 0..chunk_count {
        let chunk_path = chunks_dir.join(format!("{index:05}.bin"));
        let stored = fs::read(&chunk_path)
            .with_context(|| format!("Failed to read chunk: {}", chunk_path.display()))?;

        match &decrypt_ctx {
            None => {
                writer.write_all(&stored)?;
                total_bytes += stored.len();
            }
            Some((cek, chunk_aad)) => {
                if stored.len() < 24 {
                    anyhow::bail!(
                        "Chunk {index:05} too short to contain nonce ({} bytes)",
                        stored.len()
                    );
                }
                let nonce: [u8; 24] = stored[..24].try_into().unwrap();
                let ciphertext = &stored[24..];
                let key = chacha20poly1305::Key::from_slice(cek.as_bytes());
                let plaintext =
                    decrypt_segment(key, &nonce, ciphertext, chunk_aad).map_err(|e| {
                        CliExitError {
                            code: 1,
                            message: format!(
                                "Decryption failed — wrong key or corrupted archive: {e}"
                            ),
                        }
                    })?;
                writer.write_all(&plaintext)?;
                total_bytes += plaintext.len();
            }
        }
    }
    writer
        .flush()
        .with_context(|| format!("Failed to flush output: {}", tmp_path.display()))?;
    drop(writer); // close the temp file before renaming it into place
    fs::rename(&tmp_path, &args.output)
        .with_context(|| format!("Failed to finalize output: {}", args.output.display()))?;
    cleanup.disarm();

    // Print summary to stderr
    eprintln!("Chunks: {chunk_count}");
    eprintln!("Bytes: {total_bytes}");
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
        if let Some(seq) = report.chronicle_sequence {
            println!(
                "Chronicle: position {} (linkage unverified — use `seal verify-chronicle`)",
                seq
            );
        }
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
            // H3: a missing chunk is now surfaced by the streamed validate_archive
            // (it no longer eager-loads chunks); preserve the "Missing chunk file"
            // message the acceptance tests and users expect.
            if error.contains("Missing chunk file") {
                eprintln!("{error}");
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

/// A resolved chronicle link for `wrap`: the sequence to write, the optional
/// predecessor digest, the key epoch to stamp, and the state file to advance
/// (if any).
struct ChronicleLink {
    sequence: u64,
    prev: Option<String>,
    /// Key epoch of the signing identity (H1 Phase 2). Taken from the chronicle
    /// state (the authoritative record of the current identity); 0 for genesis
    /// and for the manual `--prev-*` escape hatches where no state is consulted.
    key_epoch: u32,
    state_path: Option<PathBuf>,
}

/// Resolve chronicle linkage from the wrap flags (design §5). `None` = a
/// standalone (non-chronicle) archive.
fn resolve_chronicle(
    chronicle: Option<&Path>,
    prev_archive: Option<&Path>,
    prev_hash: Option<&str>,
    prev_seq: Option<u64>,
    signing_public_key: &str,
) -> Result<Option<ChronicleLink>> {
    if let Some(prev_path) = prev_archive {
        let (m, _sig) = read_manifest(prev_path)
            .with_context(|| format!("Failed to read --prev-archive: {}", prev_path.display()))?;
        let prev_seq = m.sequence.ok_or_else(|| {
            anyhow::anyhow!(
                "--prev-archive points at a non-chronicle archive (no sequence); \
                 start a chronicle with --chronicle or supply --prev-hash/--prev-seq"
            )
        })?;
        return Ok(Some(ChronicleLink {
            sequence: prev_seq + 1,
            prev: Some(format_archive_id(&archive_digest(&m)?)),
            // Same signing identity as the predecessor, so inherit its epoch.
            key_epoch: m.device.key_epoch.unwrap_or(0),
            state_path: chronicle.map(|p| p.to_path_buf()),
        }));
    }

    match (prev_hash, prev_seq) {
        (Some(hash), Some(seq)) => {
            validate_prev_hash(hash)?;
            return Ok(Some(ChronicleLink {
                sequence: seq + 1,
                prev: Some(hash.to_string()),
                // Manual escape hatch: no manifest to read an epoch from.
                key_epoch: 0,
                state_path: chronicle.map(|p| p.to_path_buf()),
            }));
        }
        (Some(_), None) | (None, Some(_)) => {
            anyhow::bail!("--prev-hash and --prev-seq must be supplied together");
        }
        (None, None) => {}
    }

    if let Some(path) = chronicle {
        if path.exists() {
            let st = ChronicleState::load(path)
                .with_context(|| format!("Failed to read chronicle state: {}", path.display()))?;
            if st.device_pub != signing_public_key {
                anyhow::bail!(
                    "chronicle state belongs to device {} but wrap is signing with {}",
                    st.device_pub,
                    signing_public_key
                );
            }
            return Ok(Some(ChronicleLink {
                sequence: st.sequence + 1,
                prev: Some(st.tip),
                key_epoch: st.key_epoch,
                state_path: Some(path.to_path_buf()),
            }));
        }
        // No state file yet: genesis.
        return Ok(Some(ChronicleLink {
            sequence: 0,
            prev: None,
            key_epoch: 0,
            state_path: Some(path.to_path_buf()),
        }));
    }

    Ok(None)
}

fn validate_prev_hash(h: &str) -> Result<()> {
    let ok = h
        .strip_prefix("b3:")
        .map(|x| x.len() == 64 && x.bytes().all(|b| b.is_ascii_hexdigit()))
        .unwrap_or(false);
    if !ok {
        anyhow::bail!("--prev-hash must be 'b3:<64 hex>'");
    }
    Ok(())
}

/// True if a directory is a chronicle entry: a content archive (`manifest.json`)
/// or a rotation entry (`rotation.json`, H1 Phase 2).
fn is_chronicle_entry_dir(dir: &Path) -> bool {
    dir.join("manifest.json").is_file() || dir.join("rotation.json").is_file()
}

/// Expand verify-chronicle path args into chronicle-entry directories: a path
/// that is itself an entry is taken directly; a plain directory is scanned for
/// immediate entry children (archives *and* rotation entries).
fn collect_archive_dirs(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut dirs = Vec::new();
    for p in paths {
        if is_chronicle_entry_dir(p) {
            dirs.push(p.clone());
        } else if p.is_dir() {
            let mut children: Vec<PathBuf> = fs::read_dir(p)
                .with_context(|| format!("Failed to read directory: {}", p.display()))?
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|c| is_chronicle_entry_dir(c))
                .collect();
            children.sort();
            dirs.append(&mut children);
        } else {
            anyhow::bail!("not a .seal archive or directory: {}", p.display());
        }
    }
    Ok(dirs)
}

/// Read a rotation entry's `rotation.json` (H1 Phase 2).
fn read_rotation(dir: &Path) -> Result<RotationRecord> {
    let path = dir.join("rotation.json");
    let bytes = fs::read(&path)
        .with_context(|| format!("Failed to read rotation entry: {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("Malformed rotation entry: {}", path.display()))
}

async fn handle_verify_chronicle(args: VerifyChronicleCmd) -> Result<()> {
    let device_pub =
        if args.device_pub.starts_with("ed25519:") || args.device_pub.starts_with("ecdsa-p256:") {
            args.device_pub.clone()
        } else {
            format!("ed25519:{}", args.device_pub)
        };

    let archive_dirs = collect_archive_dirs(&args.paths)?;
    if archive_dirs.is_empty() {
        return Err(CliExitError {
            code: 12,
            message: "No .seal archives found in the given paths".to_string(),
        }
        .into());
    }

    // A chronicle entry is either a content archive or a rotation (H1 Phase 2).
    // We collect structural info first (seq, digest, prev-link), then verify
    // signatures during the active-identity walk below — signature validity
    // depends on which identity is active at each point, which requires order.
    enum EntryKind {
        Archive(Box<TrstManifest>),
        Rotation(Box<RotationRecord>),
    }
    struct Entry {
        seq: u64,
        digest: [u8; 32],
        prev: Option<String>,
        path: PathBuf,
        kind: EntryKind,
    }
    let mut entries: Vec<Entry> = Vec::with_capacity(archive_dirs.len());

    for dir in &archive_dirs {
        if dir.join("rotation.json").is_file() {
            let record = read_rotation(dir).map_err(|e| CliExitError {
                code: 12,
                message: format!("{}: {}", dir.display(), e),
            })?;
            require_supported_version(&record.trst_version).map_err(|e| CliExitError {
                code: 12,
                message: format!("{}: {}", dir.display(), e),
            })?;
            entries.push(Entry {
                seq: record.sequence,
                digest: record.archive_digest(),
                prev: Some(record.prev_archive_hash.clone()),
                path: dir.clone(),
                kind: EntryKind::Rotation(Box::new(record)),
            });
            continue;
        }

        let (manifest, _sig) = read_manifest(dir).map_err(|e| CliExitError {
            code: 12,
            message: format!("{}: archive read failed: {}", dir.display(), e),
        })?;
        require_supported_version(&manifest.trst_version).map_err(|e| CliExitError {
            code: 12,
            message: format!("{}: {}", dir.display(), e),
        })?;
        let seq = manifest.sequence.ok_or_else(|| CliExitError {
            code: 13,
            message: format!("{}: not a chronicle archive (no sequence)", dir.display()),
        })?;
        let digest = archive_digest(&manifest)?;
        let prev = manifest.prev_archive_hash.clone();
        entries.push(Entry {
            seq,
            digest,
            prev,
            path: dir.clone(),
            kind: EntryKind::Archive(Box::new(manifest)),
        });
    }

    entries.sort_by_key(|e| e.seq);

    // Contiguity: sequences must be 0,1,..,N with no gaps or duplicates.
    for (i, e) in entries.iter().enumerate() {
        if e.seq != i as u64 {
            return Err(CliExitError {
                code: 13,
                message: format!(
                    "chronicle gap/disorder: expected sequence {}, found {} ({})",
                    i,
                    e.seq,
                    e.path.display()
                ),
            }
            .into());
        }
    }

    // Genesis must be a content archive with no predecessor — a chronicle cannot
    // begin with a rotation (there is no prior identity to rotate from).
    if matches!(entries[0].kind, EntryKind::Rotation(_)) {
        return Err(CliExitError {
            code: 13,
            message: "genesis (sequence 0) must be a content archive, not a rotation".to_string(),
        }
        .into());
    }
    if let Some(prev) = &entries[0].prev {
        return Err(CliExitError {
            code: 13,
            message: format!("genesis (sequence 0) must not set prev_archive_hash ({prev})"),
        }
        .into());
    }

    // Linkage: each entry points at the previous entry's digest (kind-agnostic).
    for k in 1..entries.len() {
        let expected = format_archive_id(&entries[k - 1].digest);
        match &entries[k].prev {
            Some(p) if *p == expected => {}
            Some(p) => {
                return Err(CliExitError {
                    code: 13,
                    message: format!(
                        "broken chronicle link at sequence {}: prev={}, expected={}",
                        entries[k].seq, p, expected
                    ),
                }
                .into())
            }
            None => {
                return Err(CliExitError {
                    code: 13,
                    message: format!("missing prev_archive_hash at sequence {}", entries[k].seq),
                }
                .into())
            }
        }
    }

    // Active-identity walk (design §4). `--device-pub` pins the GENESIS identity;
    // each rotation switches the active signer forward. `signer_at_seq[k]` is the
    // identity in effect AFTER processing entry k — i.e. the key the device holds
    // (and would witness with) at that tip. Used by the witness cross-check (PA3).
    let mut active_signer = device_pub.clone();
    let mut active_epoch: u32 = 0;
    let mut rotations = 0usize;
    let mut signer_at_seq: Vec<String> = Vec::with_capacity(entries.len());

    for e in &entries {
        match &e.kind {
            EntryKind::Archive(m) => {
                if m.device.public_key != active_signer {
                    return Err(CliExitError {
                        code: 10,
                        message: format!(
                            "{}: signed by {}, but the active identity at sequence {} is {}",
                            e.path.display(),
                            m.device.public_key,
                            e.seq,
                            active_signer
                        ),
                    }
                    .into());
                }
                let epoch = m.device.key_epoch.unwrap_or(0);
                if epoch != active_epoch {
                    return Err(CliExitError {
                        code: 13,
                        message: format!(
                            "{}: key_epoch {} does not match the active epoch {} at sequence {}",
                            e.path.display(),
                            epoch,
                            active_epoch,
                            e.seq
                        ),
                    }
                    .into());
                }
                let sig = m.signature.as_ref().ok_or_else(|| CliExitError {
                    code: 12,
                    message: format!("{}: manifest missing signature", e.path.display()),
                })?;
                let canonical = m.to_canonical_bytes()?;
                let sig_ok = verify_manifest(&active_signer, &canonical, sig).map_err(|err| {
                    CliExitError {
                        code: 10,
                        message: format!("{}: signature error: {}", e.path.display(), err),
                    }
                })?;
                if !sig_ok {
                    return Err(CliExitError {
                        code: 10,
                        message: format!("{}: signature verification failed", e.path.display()),
                    }
                    .into());
                }
                validate_archive(&e.path).map_err(|err| CliExitError {
                    code: 11,
                    message: format!("{}: continuity failed: {}", e.path.display(), err),
                })?;
            }
            EntryKind::Rotation(r) => {
                // Authorization: the old identity must be the active signer/epoch.
                if r.old.public_key != active_signer {
                    return Err(CliExitError {
                        code: 13,
                        message: format!(
                            "{}: rotation supersedes {}, but the active identity at sequence {} is {}",
                            e.path.display(),
                            r.old.public_key,
                            e.seq,
                            active_signer
                        ),
                    }
                    .into());
                }
                if r.old.key_epoch != active_epoch {
                    return Err(CliExitError {
                        code: 13,
                        message: format!(
                            "{}: rotation old epoch {} does not match active epoch {} at sequence {}",
                            e.path.display(),
                            r.old.key_epoch,
                            active_epoch,
                            e.seq
                        ),
                    }
                    .into());
                }
                // Both co-signatures + the exact +1 epoch bump (core-verified).
                if !r.verify() {
                    return Err(CliExitError {
                        code: 10,
                        message: format!(
                            "{}: rotation co-signature/epoch verification failed",
                            e.path.display()
                        ),
                    }
                    .into());
                }
                active_signer = r.new.public_key.clone();
                active_epoch = r.new.key_epoch;
                rotations += 1;
            }
        }
        signer_at_seq.push(active_signer.clone());
    }

    let last = entries
        .last()
        .expect("entries is non-empty (checked above)");
    let tip = format_archive_id(&last.digest);
    let tip_seq = last.seq;
    let tip_signer = active_signer.clone();
    let tip_epoch = active_epoch;

    // Optional witness cross-check (design §6): the offline chain can't detect
    // TAIL deletion — a platform witness receipt can. The local tip must be at or
    // ahead of the witnessed tip.
    let mut witnessed: Option<(u64, String)> = None;
    if let Some(receipt_path) = args.witness.as_deref() {
        let token = fs::read_to_string(receipt_path).with_context(|| {
            format!("Failed to read witness receipt: {}", receipt_path.display())
        })?;
        let jwks = load_jwks(args.witness_jwks.as_deref()).await?;
        let (w_dev, w_seq, w_tip) = verify_witness_receipt_jws(&token, &jwks)?;
        // Tail deletion: the local tip must be at or ahead of the witnessed tip.
        // (Checked before the identity binding so a truncated chain — which may not
        // even reach w_seq in signer_at_seq — reports the honest error.)
        if tip_seq < w_seq {
            return Err(CliExitError {
                code: 13,
                message: format!(
                    "local chronicle tip (sequence {tip_seq}) is BEHIND the witnessed tip \
                     (sequence {w_seq}) — archives after {tip_seq} are missing (tail deletion)"
                ),
            }
            .into());
        }
        // PA3: bind the receipt to the ACTIVE signer at the witnessed sequence, not
        // to the genesis pin. On a rotated chain the device witnesses under its
        // current key, so the receipt's device_pub is the identity in effect at
        // w_seq — not the genesis identity `--device-pub`.
        let expected_signer = &signer_at_seq[w_seq as usize];
        if w_dev != *expected_signer {
            return Err(CliExitError {
                code: 13,
                message: format!(
                    "witness receipt is for device {w_dev}, but the active identity at \
                     sequence {w_seq} is {expected_signer}"
                ),
            }
            .into());
        }
        // The witnessed tip must match our local entry at that sequence (catches a
        // fork that diverged at or before the witnessed point, even if local is
        // ahead overall).
        let local_at_wseq = format_archive_id(&entries[w_seq as usize].digest);
        if w_tip != local_at_wseq {
            return Err(CliExitError {
                code: 13,
                message: format!(
                    "tip mismatch at sequence {w_seq}: local {local_at_wseq} vs witnessed {w_tip}"
                ),
            }
            .into());
        }
        witnessed = Some((w_seq, w_tip));
    }

    if args.json {
        let mut out = serde_json::json!({
            "chronicle": "pass",
            "device_pub": device_pub,
            "count": entries.len(),
            "rotations": rotations,
            "first_sequence": 0,
            "tip_sequence": tip_seq,
            "tip": tip,
            "current_identity": tip_signer,
            "current_epoch": tip_epoch,
        });
        if let Some((w_seq, w_tip)) = &witnessed {
            out["witnessed_sequence"] = serde_json::json!(w_seq);
            out["witnessed_tip"] = serde_json::json!(w_tip);
        }
        println!("{}", serde_json::to_string(&out)?);
    } else {
        println!("Chronicle: PASS");
        println!("Genesis device: {device_pub}");
        println!(
            "Entries: {} (sequence 0..{}, {} rotation{})",
            entries.len(),
            tip_seq,
            rotations,
            if rotations == 1 { "" } else { "s" }
        );
        if rotations > 0 {
            println!("Current identity: {tip_signer} (epoch {tip_epoch})");
        }
        println!("Tip: {tip} @ sequence {tip_seq}");
        if let Some((w_seq, _)) = &witnessed {
            if tip_seq == *w_seq {
                println!("Witness: PASS (tip matches witnessed sequence {w_seq})");
            } else {
                println!(
                    "Witness: PASS (local ahead — witnessed sequence {w_seq}, local {tip_seq})"
                );
            }
        }
    }

    Ok(())
}

/// Load a JWKS document from a URL (http/https) or a file path.
async fn load_jwks(source: Option<&str>) -> Result<String> {
    let src = source
        .ok_or_else(|| anyhow::anyhow!("--witness requires --witness-jwks (a URL or file path)"))?;
    if src.starts_with("http://") || src.starts_with("https://") {
        let client = reqwest::Client::new();
        Ok(client
            .get(src)
            .send()
            .await
            .with_context(|| format!("Failed to fetch JWKS from {src}"))?
            .text()
            .await?)
    } else {
        fs::read_to_string(src).with_context(|| format!("Failed to read JWKS file: {src}"))
    }
}

/// Verify a witness-receipt JWS (EdDSA) against a JWKS and return its
/// `(sequence, tip)`. Reuses `sealedge_core::verify_manifest` for the Ed25519
/// check (no jsonwebtoken dependency in the CLI): the JWKS `x` and the JWS
/// signature are base64url — re-encode them into the `ed25519:<base64>` form
/// the core verifier expects.
fn verify_witness_receipt_jws(token: &str, jwks_json: &str) -> Result<(String, u64, String)> {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

    let parts: Vec<&str> = token.trim().split('.').collect();
    if parts.len() != 3 {
        anyhow::bail!("witness receipt is not a JWS (expected 3 dot-separated parts)");
    }

    let header: serde_json::Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0])?)
        .with_context(|| "Failed to decode JWS header")?;
    let kid = header.get("kid").and_then(|k| k.as_str());

    let jwks: serde_json::Value =
        serde_json::from_str(jwks_json).with_context(|| "Failed to parse JWKS")?;
    let keys = jwks
        .get("keys")
        .and_then(|k| k.as_array())
        .ok_or_else(|| anyhow::anyhow!("JWKS has no 'keys' array"))?;
    let key = keys
        .iter()
        .find(|k| kid.is_none() || k.get("kid").and_then(|v| v.as_str()) == kid)
        .ok_or_else(|| anyhow::anyhow!("no JWKS key matches the receipt's kid"))?;
    let x = key
        .get("x")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("JWKS key missing 'x'"))?;

    let pubkey = format!("ed25519:{}", STANDARD.encode(URL_SAFE_NO_PAD.decode(x)?));
    let sig = format!(
        "ed25519:{}",
        STANDARD.encode(URL_SAFE_NO_PAD.decode(parts[2])?)
    );
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    if !verify_manifest(&pubkey, signing_input.as_bytes(), &sig)? {
        anyhow::bail!("witness receipt signature is invalid");
    }

    let payload: serde_json::Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1])?)
        .with_context(|| "Failed to decode JWS payload")?;
    // Defense-in-depth: reject a non-witness JWS (e.g. a verification receipt).
    if let Some(typ) = payload.get("typ").and_then(|t| t.as_str()) {
        if typ != "witness" {
            anyhow::bail!("receipt 'typ' is '{typ}', expected 'witness'");
        }
    }
    let body = payload.get("witness").unwrap_or(&payload);
    // Bind the receipt to a device: prefer the receipt body's device_pub, then
    // the JWS `sub`. The caller checks this equals the chain's signer.
    let device_pub = body
        .get("device_pub")
        .and_then(|d| d.as_str())
        .or_else(|| payload.get("sub").and_then(|s| s.as_str()))
        .ok_or_else(|| anyhow::anyhow!("witness receipt missing device identity (device_pub/sub)"))?
        .to_string();
    let seq = body
        .get("sequence")
        .and_then(|s| s.as_u64())
        .ok_or_else(|| anyhow::anyhow!("witness receipt missing 'sequence'"))?;
    let tip = body
        .get("tip")
        .and_then(|s| s.as_str())
        .ok_or_else(|| anyhow::anyhow!("witness receipt missing 'tip'"))?
        .to_string();
    Ok((device_pub, seq, tip))
}

/// Rotate a chronicle to a new signing identity (H1 Phase 2, design §3.2).
/// Emits a dual-signed rotation entry and advances the chronicle state to the
/// new key/epoch, so the next `seal wrap --chronicle` signs under the new key.
fn handle_rekey(args: RekeyCmd) -> Result<()> {
    if args.unencrypted {
        warn_unencrypted();
    }

    // PN4: rotating requires an existing chronicle to rotate FROM.
    if !args.chronicle.exists() {
        anyhow::bail!(
            "nothing to rotate: no chronicle state at {} (start one with `seal wrap --chronicle` first)",
            args.chronicle.display()
        );
    }
    let state = ChronicleState::load(&args.chronicle).with_context(|| {
        format!(
            "Failed to read chronicle state: {}",
            args.chronicle.display()
        )
    })?;

    let old = load_bundle(&args.old_key, args.unencrypted)
        .with_context(|| format!("Failed to load --old-key: {}", args.old_key.display()))?;
    let new = load_bundle(&args.new_key, args.unencrypted)
        .with_context(|| format!("Failed to load --new-key: {}", args.new_key.display()))?;

    // The old key must be the chronicle's current active identity.
    if old.signing.public != state.device_pub {
        anyhow::bail!(
            "--old-key ({}) is not the chronicle's current identity ({})",
            old.signing.public,
            state.device_pub
        );
    }
    if new.signing.public == old.signing.public {
        anyhow::bail!("--new-key must differ from --old-key");
    }
    if args.out.exists() {
        anyhow::bail!(
            "Refusing to overwrite existing path: {}",
            args.out.display()
        );
    }

    let sequence = state.sequence + 1;
    let record = RotationRecord::create_signed(
        &old.signing,
        state.key_epoch,
        &new,
        sequence,
        state.tip.clone(),
        current_timestamp()?,
    )?;

    // A rotation entry on disk is a directory holding a single rotation.json
    // (no manifest.json, no chunks/), so verify-chronicle collects it naturally.
    fs::create_dir_all(&args.out).with_context(|| {
        format!(
            "Failed to create rotation entry directory: {}",
            args.out.display()
        )
    })?;
    let rotation_path = args.out.join("rotation.json");
    let json = serde_json::to_string_pretty(&record)?;
    fs::write(&rotation_path, format!("{json}\n"))
        .with_context(|| format!("Failed to write {}", rotation_path.display()))?;

    // Advance the chronicle head to the NEW identity/epoch.
    let tip = format_archive_id(&record.archive_digest());
    let new_state = ChronicleState {
        device_pub: new.signing.public.clone(),
        sequence,
        tip: tip.clone(),
        key_epoch: record.new.key_epoch,
        updated_at: current_timestamp()?,
    };
    new_state.save(&args.chronicle).with_context(|| {
        format!(
            "Failed to update chronicle state: {}",
            args.chronicle.display()
        )
    })?;

    println!("Rotation: sequence {sequence}");
    println!(
        "  {} (epoch {}) \u{2192} {} (epoch {})",
        old.signing.public, state.key_epoch, new.signing.public, record.new.key_epoch
    );
    println!("  entry: {}", rotation_path.display());
    println!("  tip:   {tip}");
    Ok(())
}

async fn handle_witness(args: WitnessCmd) -> Result<()> {
    if args.unencrypted {
        warn_unencrypted();
    }
    let state = ChronicleState::load(&args.chronicle).with_context(|| {
        format!(
            "Failed to read chronicle state: {}",
            args.chronicle.display()
        )
    })?;
    let bundle = load_bundle(&args.device_key, args.unencrypted)?;
    if bundle.signing.public != state.device_pub {
        anyhow::bail!(
            "chronicle state belongs to {} but the device key is {}",
            state.device_pub,
            bundle.signing.public
        );
    }

    let signed_at = current_timestamp()?;
    let mut request = WitnessRequest::create_signed(
        &bundle.signing,
        state.sequence,
        state.tip.clone(),
        signed_at,
    )?;

    // H1 Phase 2: attach the rotation entry when witnessing a rotation tip, so the
    // platform can verify its co-signatures and record device lineage (PA1).
    if let Some(rot_dir) = args.rotation.as_deref() {
        let rec = read_rotation(rot_dir)?;
        let rot_tip = format_archive_id(&rec.archive_digest());
        if rot_tip != state.tip {
            anyhow::bail!(
                "--rotation entry digest ({rot_tip}) does not match the chronicle tip ({}) — \
                 attach the rotation you just created with `seal rekey`",
                state.tip
            );
        }
        request.rotation = Some(rec);
    }

    match args.post.as_deref() {
        Some(url) => {
            let client = reqwest::Client::new();
            let response = client
                .post(url)
                .json(&request)
                .send()
                .await
                .with_context(|| format!("Failed to POST witness to {url}"))?;
            let status = response.status();
            let text = response.text().await?;
            if !status.is_success() {
                return Err(CliExitError {
                    code: status.as_u16() as i32,
                    message: format!("witness rejected: HTTP {} — {}", status.as_u16(), text),
                }
                .into());
            }
            let v: serde_json::Value =
                serde_json::from_str(&text).with_context(|| "witness response was not JSON")?;
            let jws = v
                .get("jws")
                .and_then(|j| j.as_str())
                .ok_or_else(|| anyhow::anyhow!("witness response missing 'jws'"))?;
            match args.out.as_deref() {
                Some(out) => {
                    fs::write(out, jws)?;
                    eprintln!("Witness receipt written to {}", out.display());
                }
                None => println!("{jws}"),
            }
            eprintln!("Witnessed sequence {} (tip {})", state.sequence, state.tip);
        }
        None => {
            // No endpoint: emit the signed request for offline submission.
            let json = serde_json::to_string_pretty(&request)?;
            match args.out.as_deref() {
                Some(out) => {
                    fs::write(out, &json)?;
                    eprintln!("Signed witness request written to {}", out.display());
                }
                None => println!("{json}"),
            }
        }
    }

    Ok(())
}

fn current_timestamp() -> Result<String> {
    let now: DateTime<Utc> = Utc::now();
    Ok(now.to_rfc3339_opts(SecondsFormat::Secs, true))
}

async fn handle_emit_request(args: EmitRequestCmd) -> Result<()> {
    // Read the manifest only (bounded); hash chunks by streaming each file (H3)
    // so a large archive is bounded to one buffer, not the whole payload.
    let (manifest, _sig) = read_manifest(&args.archive)
        .with_context(|| format!("Failed to read archive: {}", args.archive.display()))?;

    // Compute segments by BLAKE3 over each chunk file, in index order.
    let chunks_dir = args.archive.join("chunks");
    let mut segments = Vec::with_capacity(manifest.segments.len());
    for index in 0..manifest.segments.len() {
        let chunk_path = chunks_dir.join(format!("{index:05}.bin"));
        let mut reader = BufReader::new(
            fs::File::open(&chunk_path)
                .with_context(|| format!("Failed to read chunk: {}", chunk_path.display()))?,
        );
        let mut hasher = Hasher::new();
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        segments.push(SegmentRef {
            index: index as u32,
            hash: format!("b3:{}", hex::encode(hasher.finalize().as_bytes())),
        });
    }

    // Load device pub from file. A V2 .pub carries two lines (ed25519 + x25519);
    // the platform verifies the Ed25519 signing key, so select that line.
    let device_pub_content = fs::read_to_string(&args.device_pub).with_context(|| {
        format!(
            "Failed to read device pub file: {}",
            args.device_pub.display()
        )
    })?;
    let device_pub = device_pub_content
        .lines()
        .map(|l| l.trim())
        .find(|l| l.starts_with("ed25519:"))
        .map(|l| l.to_string())
        .unwrap_or_else(|| device_pub_content.trim().to_string());

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

    // Load the signing keypair. Attestations only need the Ed25519 signing key;
    // accept a V2 bundle (preferred) and fall back to a legacy V1 key file.
    let device_keypair = load_signing_keypair(&args.device_key, args.unencrypted)?;

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

    // Resolve device public key: inline "ed25519:..." or a .pub file path. A V2
    // .pub carries two lines (ed25519 + x25519); attestations are Ed25519-signed,
    // so select that line.
    let device_pub = if args.device_pub.starts_with("ed25519:") {
        args.device_pub.clone()
    } else {
        let content = fs::read_to_string(&args.device_pub)
            .with_context(|| format!("Failed to read public key file: {}", args.device_pub))?;
        content
            .lines()
            .map(|l| l.trim())
            .find(|l| l.starts_with("ed25519:"))
            .map(|l| l.to_string())
            .unwrap_or_else(|| content.trim().to_string())
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
