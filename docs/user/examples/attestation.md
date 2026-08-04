<!--
Copyright (c) 2025 TRUSTEDGE LABS LLC
MPL-2.0: https://mozilla.org/MPL/2.0/
Project: sealedge — Privacy and trust at the edge.
GitHub: https://github.com/TrustEdge-Labs/sealedge
-->

# Software Attestation Examples

Create and verify cryptographically signed **point attestations** that bind a
software artifact (the subject) to its CycloneDX SBOM (the evidence). Each
attestation is a self-contained `.se-attestation.json` file carrying BLAKE3
hashes of both files, an Ed25519 signature, a random nonce, a timestamp, and the
signer's public key — so any third party can verify it with no Sealedge
infrastructure.

Attestation lives in the `seal` CLI as two subcommands: `attest-sbom` and
`verify-attestation`. There are no `sealedge-attest` / `sealedge-verify`
binaries.

## Basic Attestation Workflow

```bash
# Build your application
cargo build --release

# One-time: generate a signing key bundle (SEALEDGE-KEY-V2)
# Use --unencrypted only for CI/automation; omit it to be prompted for a passphrase.
seal keygen --out-key build.key --out-pub build.pub --unencrypted

# Generate a CycloneDX SBOM (e.g. via cargo-cyclonedx)
cargo cyclonedx --format json

# Create an attestation binding the SBOM to the binary
seal attest-sbom \
  --binary target/release/my-app \
  --sbom bom.json \
  --device-key build.key \
  --device-pub build.pub \
  --out my-app.se-attestation.json \
  --unencrypted

# Example output (stderr):
# ✔ Attestation written to my-app.se-attestation.json
#   Public key: ed25519:GAUpGXoor5gP6JDkeVtj/PV4quuyLlZlojizplendEU=
#   Subject:    a1b2c3d4e5f6789a... (my-app)
#   Evidence:   0f1e2d3c4b5a6978... (bom.json)

# Verify the attestation (signature only)
seal verify-attestation my-app.se-attestation.json --device-pub build.pub

# Example output:
# Format:     te-point-attestation-v1
# Public key: ed25519:GAUpGXoor5gP6JDkeVtj/PV4quuyLlZlojizplendEU=
# Timestamp:  2025-09-19T14:30:00Z
# Subject:    a1b2c3d4e5f6789a... (my-app)
# Evidence:   0f1e2d3c4b5a6978... (bom.json)
# Signature:  VERIFIED

# Verify signature AND re-hash the files (fails on any mismatch, exit 10)
seal verify-attestation my-app.se-attestation.json \
  --device-pub build.pub \
  --binary target/release/my-app \
  --sbom bom.json
```

`--device-pub` accepts either an inline `ed25519:<base64>` string or a path to a
`.pub` file (a V2 `.pub` has two lines; the Ed25519 line is selected
automatically).

## CI/CD Integration Example

Integrate attestation into your CI/CD pipeline:

```bash
#!/bin/bash
# .github/workflows/release.yml or similar
set -e

# Build the release
cargo build --release

# Generate SBOM and (unencrypted) signing key for the runner
cargo cyclonedx --format json
seal keygen --out-key build.key --out-pub build.pub --unencrypted

ARTIFACT_NAME="my-app-${GITHUB_REF_NAME}"

# Create the attestation
seal attest-sbom \
  --binary "target/release/my-app" \
  --sbom bom.json \
  --device-key build.key \
  --device-pub build.pub \
  --out "${ARTIFACT_NAME}.se-attestation.json" \
  --unencrypted

# Upload artifact, SBOM, and attestation
aws s3 cp "target/release/my-app" "s3://releases/${ARTIFACT_NAME}"
aws s3 cp "bom.json" "s3://releases/${ARTIFACT_NAME}.bom.json"
aws s3 cp "${ARTIFACT_NAME}.se-attestation.json" "s3://releases/${ARTIFACT_NAME}.se-attestation.json"

echo "✔ Release ${ARTIFACT_NAME} uploaded with attestation"
```

## Supply Chain Verification

Verify software throughout the supply chain. Because the attestation embeds the
signer's public key, you only need the artifact, its SBOM, and the trusted
public key you expect the signer to hold.

```bash
# Download artifact, SBOM, and attestation
aws s3 cp "s3://releases/my-app-v1.0.0" ./my-app
aws s3 cp "s3://releases/my-app-v1.0.0.bom.json" ./bom.json
aws s3 cp "s3://releases/my-app-v1.0.0.se-attestation.json" ./my-app.se-attestation.json

# Verify signature and re-hash both files against the attestation
seal verify-attestation my-app.se-attestation.json \
  --device-pub "ed25519:GAUpGXoor5gP6JDkeVtj/PV4quuyLlZlojizplendEU=" \
  --binary my-app \
  --sbom bom.json

# Check exit code for automation (0 = pass, 10 = signature/hash mismatch)
if [ $? -eq 0 ]; then
    echo "✔ Software verification PASSED - safe to deploy"
    chmod +x my-app
else
    echo "✖ Software verification FAILED - DO NOT DEPLOY"
    exit 1
fi
```

## Inspecting an Attestation

The attestation is plain JSON — inspect it directly:

```bash
cat my-app.se-attestation.json | jq .

# Example structure:
# {
#   "format": "te-point-attestation-v1",
#   "subject":  { "hash": "a1b2c3...", "filename": "my-app", "label": "binary" },
#   "evidence": { "hash": "0f1e2d...", "filename": "bom.json", "label": "sbom" },
#   "nonce": "9f8e7d6c5b4a39281706...",
#   "timestamp": "2025-09-19T14:30:00Z",
#   "public_key": "ed25519:GAUpGXoor5gP6JDkeVtj/PV4quuyLlZlojizplendEU=",
#   "signature": "..."
# }
```

## Submit to the Platform Server

For a hosted verification receipt, POST the attestation to a running
platform server:

```bash
curl -X POST http://localhost:3001/v1/verify-attestation \
  -H "Content-Type: application/json" \
  -d @my-app.se-attestation.json
```

## Multi-Platform Release Attestation

Create attestations for multiple build targets:

```bash
#!/bin/bash
# Multi-platform build and attestation script
set -e

TARGETS=("x86_64-unknown-linux-gnu" "aarch64-unknown-linux-gnu" "x86_64-pc-windows-gnu")

# One SBOM and signing key for the release
cargo cyclonedx --format json
seal keygen --out-key build.key --out-pub build.pub --unencrypted
mkdir -p releases

for target in "${TARGETS[@]}"; do
    echo "Building for target: $target"
    cargo build --release --target "$target"

    seal attest-sbom \
      --binary "target/${target}/release/my-app" \
      --sbom bom.json \
      --device-key build.key \
      --device-pub build.pub \
      --out "releases/my-app-${target}.se-attestation.json" \
      --unencrypted

    echo "✔ Attestation created for $target"
done

echo "✔ All platform attestations created in releases/"
ls -la releases/
```

---


[← Back to Examples Index](README.md)

---

*This document is part of the Sealedge project documentation.*

**📖 Links:**
- **[Sealedge Home](https://github.com/TrustEdge-Labs/sealedge)** - Main repository
- **[Sealedge Labs](https://github.com/TrustEdge-Labs)** - Organization profile
- **[Documentation](https://github.com/TrustEdge-Labs/sealedge/tree/main/docs)** - Complete docs
- **[Issues](https://github.com/TrustEdge-Labs/sealedge/issues)** - Bug reports & features

**⚖️ Legal:**
- **Copyright**: © 2025 Sealedge Labs LLC
- **License**: Mozilla Public License 2.0 ([MPL-2.0](https://mozilla.org/MPL/2.0/))
- **Commercial**: [Enterprise licensing available](mailto:enterprise@trustedgelabs.com)
