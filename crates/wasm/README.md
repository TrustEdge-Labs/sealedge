<!--
Copyright (c) 2025 TRUSTEDGE LABS LLC
MPL-2.0: https://mozilla.org/MPL/2.0/
Project: sealedge — Privacy and trust at the edge.
GitHub: https://github.com/TrustEdge-Labs/sealedge
-->


# Sealedge WASM

> **EXPERIMENTAL** -- This crate is Tier 2 (experimental). General WASM bindings for sealedge. No maintenance commitment. For browser archive verification, use `sealedge-seal-wasm` (Tier 1) instead.

WebAssembly bindings for general sealedge cryptographic helpers (AES-256-GCM
encrypt/decrypt and small utilities) for use in browsers and Node.js.

This crate is **not published to npm or crates.io**; build it from source with
`wasm-pack`.

> **Complete WASM guide**: see **[WASM.md](../../WASM.md)** for build, test, and deployment documentation.

## Exported API

The crate exports free functions and two small classes via `wasm-bindgen` (names
are preserved from Rust). The current surface includes:

- `generate_key()` / `generate_nonce()` — generate a base64 key / nonce
- `encrypt_simple(data, key)` — encrypt with an auto-generated nonce, returns `EncryptedData`
- `encrypt(data, key, nonce)` — encrypt with an explicit nonce
- `decrypt(encrypted_data, key)` — decrypt an `EncryptedData`
- `validate_key(key)` / `validate_nonce(nonce)` — format checks
- `generate_random_bytes(length)` — base64 random bytes
- `EncryptedData` — `{ ciphertext, nonce, key_id }` with `to_json` / `from_json`
- `Timer` — `elapsed()` / `log_elapsed(operation)` for coarse timing

> The exact signatures are the source of truth; consult
> [`src/lib.rs`](src/lib.rs), [`src/crypto.rs`](src/crypto.rs), and
> [`src/utils.rs`](src/utils.rs) before relying on any function here.

## Building from Source

### Prerequisites

- Rust toolchain
- `wasm-pack`
- Node.js (for testing)

### Build Steps

```bash
# Install wasm-pack
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

# Add WASM target
rustup target add wasm32-unknown-unknown

# Build for web
wasm-pack build --target web --out-dir pkg

# Build for Node.js
wasm-pack build --target nodejs --out-dir pkg-node

# Build for bundlers
wasm-pack build --target bundler --out-dir pkg-bundler
```

## Security

- **AES-256-GCM**: authenticated encryption with 256-bit keys
- **Secure random**: cryptographically secure random number generation
- **Memory safety**: Rust's memory-safety guarantees

## License

Licensed under the Mozilla Public License 2.0 (MPL-2.0).

## Support

- **Issues**: [GitHub Issues](https://github.com/TrustEdge-Labs/sealedge/issues)
- **Enterprise**: [enterprise@trustedgelabs.com](mailto:enterprise@trustedgelabs.com)
