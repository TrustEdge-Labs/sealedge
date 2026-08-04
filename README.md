<!--
Copyright (c) 2025 TRUSTEDGE LABS LLC
MPL-2.0: https://mozilla.org/MPL/2.0/
Project: sealedge — Privacy and trust at the edge.
GitHub: https://github.com/TrustEdge-Labs/sealedge
-->

[![CI Status](https://github.com/TrustEdge-Labs/sealedge/workflows/CI/badge.svg)](https://github.com/TrustEdge-Labs/sealedge/actions)
[![License: MPL 2.0](https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg)](https://opensource.org/licenses/MPL-2.0)
[![Commercial License](https://img.shields.io/badge/Commercial-License%20Available-blue.svg)](mailto:enterprise@trustedgelabs.com)
[![Rust](https://img.shields.io/badge/rust-stable-brightgreen.svg)](https://www.rust-lang.org)
[![Version](https://img.shields.io/badge/version-6.0.0-blue.svg)](https://github.com/TrustEdge-Labs/sealedge/releases/tag/v6.0.0)
[![YubiKey](https://img.shields.io/badge/YubiKey-Hardware%20Supported-green.svg)](https://www.yubico.com/)

# Sealedge

Cryptographic provenance for edge device data and software supply chains.

## Problem

Edge devices generate data, video, sensor readings, audio, logs, but there is no way to
prove that data has not been tampered with between capture and consumption. Software teams
generate SBOMs but can't cryptographically prove the SBOM matches the actual binary.
Sealedge provides cryptographic chain of custody: sign at the source, verify with an
independent service, and receive a cryptographic receipt as proof.

## Quick Start: SBOM Attestation

Cryptographically bind an SBOM to a binary artifact and verify it:

```bash
# Generate a signing key
seal keygen --out-key build.key --out-pub build.pub --unencrypted

# Attest: bind SBOM to binary
seal attest-sbom --binary target/release/myapp --sbom bom.cdx.json \
  --device-key build.key --device-pub build.pub --out attestation.se-attestation.json

# Verify locally
seal verify-attestation attestation.se-attestation.json --device-pub "$(cat build.pub)"
```

Or use the [GitHub Action](https://github.com/TrustEdge-Labs/sealedge-attest-sbom-action) for one-line CI integration (verifies `seal` binary SHA256 before executing):

```yaml
- uses: TrustEdge-Labs/sealedge-attest-sbom-action@v2
  with:
    binary: target/release/myapp
    sbom: bom.cdx.json
```

Sealedge self-attests its own releases: every GitHub release includes `seal.se-attestation.json` and `build.pub` as downloadable assets. Verify with `seal verify-attestation seal.se-attestation.json --device-pub "$(cat build.pub)"`.

See the [third-party attestation guide](docs/third-party-attestation-guide.md) for complete manual and CI workflows.

## Quick Start: Archive Verification

For continuous data streams (video, audio, sensor data), use `.seal` archives:

```bash
git clone https://github.com/TrustEdge-Labs/sealedge.git && cd sealedge
cp deploy/.env.example deploy/.env
docker compose -f deploy/docker-compose.yml up -d --build
./scripts/demo.sh
```

This starts the full Sealedge stack (platform server, PostgreSQL, dashboard) and runs an
end-to-end demo: key generation, archive wrapping, server-side verification, and receipt
retrieval.

No Docker? Run `./scripts/demo.sh --local` with just Rust installed for local-only
verification.

## Use Cases

### Firmware SBOM Attestation

An IoT manufacturer ships firmware updates and needs to prove the SBOM matches the actual
binary for EU CRA compliance. Sealedge cryptographically binds the two artifacts together.

```bash
seal attest-sbom --binary firmware-v2.3.bin --sbom firmware-v2.3.cdx.json \
  --device-key build.key --device-pub build.pub --out firmware-v2.3.se-attestation.json
seal verify-attestation firmware-v2.3.se-attestation.json --device-pub "$(cat build.pub)" \
  --binary firmware-v2.3.bin --sbom firmware-v2.3.cdx.json
```

The `.se-attestation.json` is a lightweight JSON document with Ed25519 signature over
BLAKE3 hashes of both files, a random nonce, and timestamp. Any third party can verify
it using only the attestation document and the embedded public key.

### Drone Inspection

A drone captures inspection footage of infrastructure. The operator needs to prove the video
has not been edited between capture and submission to the client.

```bash
seal keygen --out-key drone.key --out-pub drone.pub
# For CI/automation (no passphrase prompt):
# seal keygen --out-key drone.key --out-pub drone.pub --unencrypted
seal wrap --in flight-recording.bin --out inspection.seal \
  --data-type video --source "DJI-Mavic-3E" --description "Bridge inspection flight 2024-03-15" \
  --device-key drone.key --device-pub drone.pub
seal verify inspection.seal --device-pub "$(cat drone.pub)"
```

### Sensor Logs

Industrial sensors produce continuous readings. Regulators need assurance that the submitted
logs match what was actually recorded.

```bash
seal wrap --in sensor-readings.csv --out telemetry.seal \
  --data-type sensor --source "Modbus-RTU-Unit-7" --description "Temperature readings Q1 2024" \
  --device-key sensor.key --device-pub sensor.pub
```

### Body Camera

Law enforcement body cameras record interactions. The footage must be verifiably unaltered
for evidentiary use.

```bash
seal wrap --in bodycam-clip.mp4 --out evidence.seal \
  --data-type video --source "Axon-Body-4" --description "Incident report 2024-0847" \
  --device-key officer.key --device-pub officer.pub
```

### Audio Capture

A journalist records an interview. The publication needs to prove the audio is the original
unedited recording.

```bash
seal wrap --in interview.wav --out recording.seal \
  --data-type audio --source "Zoom-H6" --description "Interview with source, 2024-03-15" \
  --device-key recorder.key --device-pub recorder.pub
```

Named profiles are also available for use-case-specific metadata:

```bash
# Sensor data with geo-tagging
seal wrap --profile sensor --in readings.csv --out telemetry.seal \
  --sample-rate 100 --unit celsius --sensor-model DHT22 \
  --latitude 40.7128 --longitude=-74.0060 \
  --device-key sensor.key --device-pub sensor.pub

# Audio with codec metadata
seal wrap --profile audio --in call.wav --out recording.seal \
  --sample-rate 44100 --bit-depth 16 --channels 2 --codec pcm \
  --device-key mic.key --device-pub mic.pub

# Application logs
seal wrap --profile log --in access.log --out logs.seal \
  --application nginx --host web-01 --log-level info --log-format json \
  --device-key server.key --device-pub server.pub
```

Archives are encrypted to the device's own X25519 key by default. Add extra readers with
`--recipient x25519:<pub>` (repeatable), or produce signed-but-unencrypted archives with
`--sign-only`.

To decrypt and recover original data:

```bash
seal unwrap recording.seal --device-key mic.key --out recovered.wav
```

For cam.video-specific archives with frame rate and segment duration, see [examples/cam.video](examples/cam.video/).

## How It Works

**Security Posture (v6.0):** Sealedge uses X25519 ECDH with HKDF-SHA256 for envelope key agreement (RSA OAEP-SHA256 is used only in the optional hybrid encryption path). Envelopes are v2-only format with HKDF-SHA256 key derivation. Point attestations use Ed25519 signing over BLAKE3 hashes with random nonces (`.se-attestation.json`). Device private keys are encrypted at rest using SEALEDGE-KEY-V2 format (an Ed25519 signing key plus an independent X25519 key-agreement key, stored together; PBKDF2-HMAC-SHA256 600k + AES-256-GCM, versioned metadata); a passphrase is prompted at runtime. Key-holding structs zeroize memory on drop. Platform HTTP endpoints enforce a 2 MB body limit and per-IP rate limiting on `/v1/verify` and `/v1/verify-attestation`. JWKS signing key path is configurable via `JWKS_KEY_PATH`. Receipt TTL is configurable via `RECEIPT_TTL_SECS` (default 3600s). Tested across 9 workspace crates.

**Two attestation modes:**

**Point Attestation** (for single artifacts: SBOMs, firmware, documents):
1. **Hash** -- BLAKE3 hash of the binary and SBOM (or any two artifacts)
2. **Sign** -- Ed25519 signature over the hashes, timestamp, and random nonce
3. **Verify** -- Any third party verifies using the embedded public key
4. **Receipt** -- Platform issues a JWS receipt proving verification at a specific time

**Stream Attestation** (for continuous data: video, audio, sensor readings):
1. **Sign** -- Ed25519 keypair (or YubiKey ECDSA P-256) signs data at capture
2. **Encrypt** -- Chunks encrypted under a per-archive random Content-Encryption Key (XChaCha20-Poly1305); the CEK is HPKE-wrapped (X25519) to one or more recipients
3. **Wrap** -- Chunks, manifest, and signature packaged into a `.seal` archive with BLAKE3 continuity chain
4. **Verify** -- Independent verification service checks signature, chain integrity, and manifest
5. **Unwrap** -- Original data recovered after mandatory signature and chain verification
6. **Receipt** -- Cryptographic receipt proving verification at a specific time

Hardware-backed signing is supported via YubiKey PIV (`seal wrap --backend yubikey`). See [docs/yubikey-guide.md](docs/yubikey-guide.md).

## Architecture

Sealedge is a Rust workspace with 9 crates organized as a monolithic core library with thin
CLI and WASM shells, plus a platform verification service with PostgreSQL backend and
SvelteKit dashboard.

For crate breakdown, module hierarchy, data flow, and testing details, see
[docs/architecture.md](docs/architecture.md).

For hardware-backed signing with YubiKey PIV, see [docs/yubikey-guide.md](docs/yubikey-guide.md).

## Commercial Support

Building edge devices that need cryptographic provenance? We offer commercial SDK, custom
hardware integration, fleet management, and compliance consulting.

Contact: pilot@trustedgelabs.com

## License

Mozilla Public License 2.0. See [LICENSE](LICENSE) for details.

Commercial licenses available for enterprise use. Contact: enterprise@trustedgelabs.com

(c) 2025 TrustEdge Labs LLC

---

*Sealedge -- Privacy and trust at the edge.*
