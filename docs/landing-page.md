<!--
Copyright (c) 2025 TRUSTEDGE LABS LLC
This source code is subject to the terms of the Mozilla Public License, v. 2.0.
If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

Project: sealedge — Privacy and trust at the edge.
-->

# Prove your software bill of materials hasn't been tampered with — from build to delivery.

Supply chain attacks don't announce themselves. By the time an auditor asks for your SBOM, the damage is done. Sealedge gives you a cryptographic receipt you can hand to any auditor, customer, or regulator — provable at the moment of creation, verifiable forever.

## What It Does

Sealedge creates Ed25519-signed, BLAKE3-hashed attestations that bind your SBOM to the binary it describes. The attestation is a single JSON file — no proprietary platform, no cloud account required. Works with any CI provider. Verifiable by anyone with your public key or via the public verifier.

**EU CRA compliance:** Attestations provide the technical evidence chain required under the EU Cyber Resilience Act for software component provenance.

## Why Sealedge

| | GitHub Attestations | Sigstore / cosign | Sealedge |
|---|---|---|---|
| **Works anywhere** | GitHub only | Yes | Yes |
| **Identity requirement** | GitHub account | Fulcio CA + OIDC | None — ephemeral keys per build |
| **Attests SBOMs** | Limited | Container images | Yes — SBOM + binary binding |
| **Hardware key support** | No | No | Yes — YubiKey PIV |
| **Infrastructure lock-in** | GitHub | Sigstore PKI | None |

GitHub Attestations require GitHub identity and are locked to GitHub infrastructure. Sigstore/cosign is excellent for container images but brings a complex PKI (Fulcio, Rekor, OIDC). Sealedge is infrastructure-independent: ephemeral Ed25519 keys per build, no external identity provider, deployable on any CI system.

## Quick Start

Three commands from zero to verified:

```bash
# 1. Generate an ephemeral Ed25519 keypair
seal keygen --out-key device.key --out-pub device.pub --unencrypted

# 2. Attest your binary and its SBOM
seal attest-sbom --binary ./my-app --sbom sbom.cdx.json \
  --device-key device.key --device-pub device.pub \
  --out attestation.se-attestation.json --unencrypted

# 3. Verify locally
seal verify-attestation attestation.se-attestation.json \
  --device-pub device.pub
```

Output: `attestation.se-attestation.json` — a signed JSON document containing BLAKE3 hashes of both the binary and SBOM, an Ed25519 signature, a nonce, and a timestamp. Ship it alongside your release binary and SBOM.

## GitHub Action

One line in your CI pipeline:

```yaml
- uses: TrustEdge-Labs/attest-sbom-action@v1
  with:
    binary: ./target/release/my-app
    sbom: sbom.cdx.json
```

The action generates a keypair, runs `seal attest-sbom`, and uploads the attestation as a release asset — no secrets required, ephemeral keys per build.

## Links

- **Public verifier:** [https://verify.sealedge.dev/verify](https://verify.sealedge.dev/verify) — paste or upload any `.se-attestation.json` file to verify online
- **GitHub Action:** [TrustEdge-Labs/attest-sbom-action](https://github.com/TrustEdge-Labs/attest-sbom-action) — one-line CI integration
- **Source code:** [TrustEdge-Labs/sealedge](https://github.com/TrustEdge-Labs/sealedge) — MPL-2.0 licensed
- **Integration guide:** [Third-Party Attestation Guide](third-party-attestation-guide.md) — copy-paste manual and CI workflows

## What Goes in an Attestation

Each `.se-attestation.json` file contains:

- BLAKE3 hash of the binary artifact (`b3:` prefixed)
- BLAKE3 hash of the CycloneDX SBOM (`b3:` prefixed)
- Ed25519 signature over canonical JSON
- Random nonce (replay prevention)
- RFC 3339 timestamp
- Format version discriminant (`te-point-attestation-v1`)

The attestation stores hashes, not the files themselves — keep the original binary and SBOM to re-check the hashes at verification time. Verifying needs no Sealedge infrastructure; public key distribution is left to you (GitHub releases, DNS, key servers, or direct exchange).
