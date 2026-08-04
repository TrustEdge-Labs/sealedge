<!--
Copyright (c) 2025 TRUSTEDGE LABS LLC
MPL-2.0: https://mozilla.org/MPL/2.0/
Project: sealedge — Privacy and trust at the edge.
GitHub: https://github.com/TrustEdge-Labs/sealedge
-->

# Development Examples

Development workflows and project management examples.

## Development and Project Management Examples

### Development Workflow Integration

```bash
# Pre-commit hook for attested builds
#!/bin/bash
# .git/hooks/pre-commit

# Build and test
cargo build --release
cargo test

# One-time (or cached) signing key for the build machine
# (use --unencrypted only in automation where no passphrase prompt is possible)
[ -f build.key ] || ./target/release/seal keygen \
  --out-key build.key --out-pub build.pub --unencrypted

# Generate a CycloneDX SBOM (e.g. via cargo-cyclonedx)
cargo cyclonedx --format json

# Bind the SBOM to the binary with an Ed25519 point attestation
./target/release/seal attest-sbom \
  --binary target/release/seal \
  --sbom bom.json \
  --device-key build.key \
  --device-pub build.pub \
  --out dev-attestation.se-attestation.json \
  --unencrypted

echo "✔ Development build attested"
```

### Debugging and Troubleshooting

```bash
# Debug mode with verbose logging
RUST_LOG=debug ./target/release/sealedge \
  --input test.txt \
  --out /dev/null \
  --envelope debug.seal \
  --key-out debug.key \
  --verbose

# Inspect internal state without decrypting
./target/release/sealedge \
  --input debug.seal \
  --inspect \
  --verbose
```

### Testing Workflows

```bash
# Automated testing script
#!/bin/bash
set -e

echo "Running Sealedge integration tests..."

# Test basic encryption/decryption
echo "Test data" > test_input.txt
./target/release/sealedge \
  --input test_input.txt \
  --out /dev/null \
  --envelope test.seal \
  --key-out test.key

./target/release/sealedge \
  --decrypt \
  --input test.seal \
  --out test_output.txt \
  --key-hex $(cat test.key)

# Verify integrity
if diff test_input.txt test_output.txt; then
  echo "✔ Basic encryption test passed"
else
  echo "✖ Basic encryption test failed"
  exit 1
fi

# Cleanup
rm test_input.txt test.seal test.key test_output.txt
echo "✔ All tests passed"
```

### Release Management

```bash
# Release preparation script
#!/bin/bash
VERSION="$1"

if [ -z "$VERSION" ]; then
  echo "Usage: $0 <version>"
  exit 1
fi

# Build release
cargo build --release --all-features

# Generate an SBOM once for the workspace
cargo cyclonedx --format json

# Create SBOM attestations for all binaries
mkdir -p release
for binary in sealedge sealedge-server sealedge-client seal; do
  ./target/release/seal attest-sbom \
    --binary "target/release/$binary" \
    --sbom bom.json \
    --device-key build.key \
    --device-pub build.pub \
    --out "release/$binary-$VERSION.se-attestation.json" \
    --unencrypted
done

echo "✔ Release $VERSION prepared with attestations"
```

### Monitoring and Metrics

```bash
# Performance monitoring during development
#!/bin/bash

# Monitor encryption performance
echo "Monitoring encryption performance..."
for size in 1M 10M 100M; do
  dd if=/dev/urandom of="test_$size.bin" bs=1 count=$size 2>/dev/null

  start_time=$(date +%s.%N)
  ./target/release/sealedge \
    --input "test_$size.bin" \
    --out /dev/null \
    --envelope "test_$size.seal" \
    --key-out "key_$size.hex"
  end_time=$(date +%s.%N)

  duration=$(echo "$end_time - $start_time" | bc)
  echo "$size file: ${duration}s"

  # Cleanup
  rm "test_$size.bin" "test_$size.seal" "key_$size.hex"
done
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
