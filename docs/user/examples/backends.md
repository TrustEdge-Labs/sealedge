<!--
Copyright (c) 2025 TRUSTEDGE LABS LLC
MPL-2.0: https://mozilla.org/MPL/2.0/
Project: sealedge — Privacy and trust at the edge.
GitHub: https://github.com/TrustEdge-Labs/sealedge
-->

# Backend Examples

Universal Backend system and hardware integration examples.

## Universal Backend Workflows

The `sealedge` envelope CLI selects a key-management backend with `--backend`.
Valid values are `keyring` (default), `tpm`, `hsm`, and `matter`. Use
`--list-backends` to see what is available in your build.

### List available backends

```bash
./target/release/sealedge --list-backends
```

### HSM Backend

```bash
# Use the HSM backend for key generation
# (encrypt mode requires --out; /dev/null discards the round-trip copy)
./target/release/sealedge \
  --input document.txt \
  --out /dev/null \
  --envelope document.seal \
  --backend hsm \
  --key-out generated.key
```

### Keyring Backend

The keyring backend (`--set-passphrase`, `--use-keyring`, `--backend keyring`)
requires a build with the `keyring` feature:
`cargo build -p sealedge-cli --features keyring`.

```bash
# Store passphrase in OS keyring
./target/release/sealedge --set-passphrase "my secure passphrase"

# Use keyring-derived keys
./target/release/sealedge \
  --input file.txt \
  --out /dev/null \
  --envelope file.seal \
  --backend keyring \
  --salt-hex $(openssl rand -hex 16)
```

### Backend-specific configuration

Some backends accept extra settings via `--backend-config key=value` (repeatable):

```bash
./target/release/sealedge \
  --input file.txt \
  --out /dev/null \
  --envelope file.seal \
  --backend tpm \
  --backend-config "device=/dev/tpm0"
```

## Hardware Backend Demonstrations

### YubiKey Examples (Library-Based)

YubiKey connectivity is exercised through **Rust examples** in `sealedge-core`,
built with the `yubikey` feature:

```bash
# Verify YubiKey connectivity (auto-detects OpenSC)
cargo run -p sealedge-core --example verify_yubikey --features yubikey

# Verify with a custom PIN
cargo run -p sealedge-core --example verify_yubikey_custom_pin --features yubikey -- YOUR_PIN
```

**Note**: YubiKey operations require:
- YubiKey with PIV applet
- OpenSC PKCS#11 module: `sudo apt install opensc-pkcs11`

### YubiKey Hardware Signing (seal archives)

The `sealedge` envelope CLI does not currently sign with a YubiKey. Hardware
signing is available in the `seal` archive tool, which signs a manifest with a
YubiKey PIV key. Hardware signing is `--sign-only` (plaintext chunks); content
encryption is software-backend only.

```bash
# Sign a .seal archive with a YubiKey (requires the yubikey feature)
cargo run -p sealedge-seal-cli --features yubikey -- wrap \
  --backend yubikey \
  --sign-only \
  --in data.bin \
  --out archive.seal \
  --device-key device.key \
  --slot 9c

# Verify the resulting archive with the ecdsa-p256 public key it prints
cargo run -p sealedge-seal-cli -- verify archive.seal --device-pub "ecdsa-p256:..."
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
