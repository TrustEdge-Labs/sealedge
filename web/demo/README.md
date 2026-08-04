<!--
Copyright (c) 2025 TRUSTEDGE LABS LLC
MPL-2.0: https://mozilla.org/MPL/2.0/
Project: sealedge — Privacy and trust at the edge.
GitHub: https://github.com/TrustEdge-Labs/sealedge
-->


# Sealedge WASM Verifier Demo

This directory contains a WebAssembly-powered demo for verifying Sealedge `.seal`
archives (`trst_version` 0.2.0) in the browser.

> **📚 For complete WASM documentation**, see:
> - **[WASM.md](../../WASM.md)** - Comprehensive build/test/deploy guide
> - **[FEATURES.md](../../FEATURES.md)** - Feature flag reference

## 🎯 Features

- **Client-side verification**: No server required - all verification runs in the browser
- **Ed25519 signature verification**: Cryptographic validation of archive signatures
- **Version gating**: Accepts only `trst_version` 0.2.0; rejects legacy `0.1.0` and unknown versions
- **Continuity chain checking**: Validates that all expected chunk files are present
- **Directory upload**: Select entire `.seal` directories using modern browser APIs
- **Real-time feedback**: Visual indicators for pass/fail status

## 🚀 Quick Start

### Prerequisites

1. **Rust toolchain** with `wasm-pack` installed:
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   cargo install wasm-pack
   ```

2. **Node.js** (for serving the demo locally):
   ```bash
   # Install Node.js from https://nodejs.org or via package manager
   node --version  # Should be v16+
   ```

### Build Steps

1. **Build the WASM module**:
   ```bash
   # From the project root
   wasm-pack build crates/seal-wasm --target web --out-dir ../../web/demo/pkg
   ```

2. **Serve the demo locally**:
   ```bash
   # From web/demo directory
   cd web/demo
   npx serve .
   ```

3. **Open in browser**:
   - Navigate to `http://localhost:3000` (or the URL shown by serve)
   - The demo should load with the Sealedge verifier interface

### Alternative Build Script

For convenience, you can also run:

```bash
# From project root
./scripts/build-wasm-demo.sh
```

## 📱 Usage

1. **Create a test archive** (if you don't have one):
   ```bash
   # From project root
   head -c 4M </dev/urandom > test-input.bin

   # Generate a device keypair (plaintext bundle for a quick demo)
   cargo run -p sealedge-seal-cli -- keygen --out-key device.key --out-pub device.pub --unencrypted

   # Wrap the input into a signed, encrypted archive
   cargo run -p sealedge-seal-cli -- wrap --profile cam.video \
     --in test-input.bin --out test-archive.seal \
     --device-key device.key --unencrypted
   ```

2. **Open the demo** in a modern browser (Chrome 86+, Edge 86+ recommended)

3. **Select archive**: Click "Select .seal Archive Directory" and choose your `.seal` folder

4. **Enter public key**: Paste the **signing** (`ed25519:`) line from `device.pub`
   (the `.pub` file has two lines — an `ed25519:` line and an `x25519:` line)

5. **Verify**: Click "Verify Archive" to see the results

## 🔧 Browser Compatibility

| Feature | Chrome | Firefox | Safari | Edge |
|---------|--------|---------|--------|------|
| Directory Selection | 86+ ✅ | ❌ | ❌ | 86+ ✅ |
| WebAssembly | 57+ ✅ | 52+ ✅ | 11+ ✅ | 16+ ✅ |

**Note**: The demo uses the File System Access API for directory selection, which is currently only supported in Chromium-based browsers. Other browsers can still verify individual manifest files.

## 🏗️ Architecture

### WASM Bindings

The WASM module exposes two main functions:

- **`verify_manifest(manifest_bytes, device_pub)`**: Verifies a manifest file directly
- **`verify_archive(dir_handle, device_pub)`**: Verifies a complete archive directory

Both reject any archive whose `trst_version` is not 0.2.0, and return a
`VerificationResult` of `{ signature, continuity, segment_count }`.

### Security Model

- **Version gating**: Legacy (`0.1.0`) and unknown archive versions are rejected before signature checks
- **Signature verification**: Uses Ed25519 cryptography to validate manifest signatures
- **Continuity checking**: Ensures all expected chunk files are present
- **No decryption**: This demo only verifies signatures and structure (no data decryption)

### Limitations

- **Basic continuity**: Only checks that each expected chunk file exists, not full chunk-hash validation
- **No chunk decryption**: Encrypted chunk contents are not read or validated

## 🧪 Testing

### Manual Testing

1. Create test archives with different configurations:
   ```bash
   # Valid archive
   cargo run -p sealedge-seal-cli -- wrap --profile cam.video \
     --in test.bin --out valid.seal --device-key device.key --unencrypted

   # Test verification (use the ed25519 line from device.pub)
   cargo run -p sealedge-seal-cli -- verify valid.seal --device-pub "$(grep '^ed25519:' device.pub)"
   ```

2. Test with a wrong public key to verify failure detection

3. Remove chunk files to test continuity checking

### Automated Testing

```bash
# Run WASM-specific tests
wasm-pack test crates/seal-wasm --chrome --headless
```

## 📦 Distribution

To deploy the demo:

1. Build the WASM module: `wasm-pack build crates/seal-wasm --target web`
2. Copy `web/demo/` contents to your web server
3. Ensure proper CORS headers for `.wasm` files
4. Serve with HTTPS for File System Access API support

## 🔍 Troubleshooting

### Build Issues

- **"wasm-pack not found"**: Install with `cargo install wasm-pack`
- **"target not supported"**: Ensure you're using `--target web` flag
- **"out-dir not found"**: Create the directory: `mkdir -p web/demo/pkg`

### Runtime Issues

- **"Directory selection not working"**: Use Chrome/Edge 86+ or test with individual files
- **"WASM module failed to load"**: Check browser console for CORS errors
- **"Verification always fails"**: Ensure the public key is the `ed25519:` line from `device.pub`
- **"unsupported archive version"**: The archive is not `trst_version` 0.2.0; re-wrap with a current `seal` build

### Performance

- **Large archives**: The demo is optimized for archives under 100MB
- **Many segments**: Performance may degrade with 1000+ segments
- **File I/O**: Directory scanning can be slow for very large archives

## 📚 Related Documentation

- **[C4 content-encryption design](../../docs/designs/c4-content-encryption-redesign.md)** - The 0.2.0 content-encryption model
- **[seal CLI](../../crates/seal-cli/)** - Command-line interface
- **[Core API](../../crates/core/)** - Low-level verification APIs
- **[Examples](../../examples/cam.video/)** - End-to-end usage examples

---

*This demo showcases Sealedge `.seal` (`trst_version` 0.2.0) archive verification in WebAssembly.*
