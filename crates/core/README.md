<!--
Copyright (c) 2025 TRUSTEDGE LABS LLC
MPL-2.0: https://mozilla.org/MPL/2.0/
Project: sealedge — Privacy and trust at the edge.
GitHub: https://github.com/TrustEdge-Labs/sealedge
-->

# Sealedge Core

> **STABLE** -- This crate is Tier 1 (Stable). Production-committed, tested in CI, and actively maintained.

**Core cryptographic library and CLI tools for privacy-preserving edge computing.**

[![License: MPL 2.0](https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg)](https://opensource.org/licenses/MPL-2.0)

---

## Overview

Sealedge Core is the **foundational crate** of the sealedge ecosystem, providing production-ready cryptographic primitives, CLI applications, and system architecture for privacy-preserving edge computing. It implements data-agnostic encryption, universal backend systems, and secure network operations.

### Key Features

- **Production Cryptography**: AES-256-GCM encryption with PBKDF2 key derivation (600,000 iterations)
- **Universal Backend System**: Pluggable crypto operations (Software HSM, Keyring, YubiKey)
- **Live Audio Capture**: Real-time microphone input with configurable quality and device selection
- **Network Operations**: Secure client-server communication with mutual authentication
- **Hardware Integration**: YubiKey PIV support with real hardware signing
- **Algorithm Agility**: Configurable cryptographic algorithms with forward compatibility
- **Format-Aware Processing**: MIME type detection and format-preserving encryption/decryption
- **Memory Safety**: Proper key material cleanup with zeroization

[↑ Back to top](#sealedge-core)

---

## Architecture

Sealedge Core provides both a **library** and **CLI applications**:

```
sealedge-core/
├── src/lib.rs                   # Core library exports
├── src/bin/                     # CLI tools
│   ├── sealedge-server.rs       # Network server
│   ├── sealedge-client.rs       # Network client
│   ├── software-hsm-demo.rs     # Software HSM demonstration
│   └── inspect-seal.rs          # .seal archive inspector
├── src/backends/                # Universal Backend system
├── src/transport/               # Network transport layer
├── examples/                    # Runnable examples
└── tests/                       # Test suite
```

### Core Modules

| Module | Purpose | Key Types |
|--------|---------|-----------|
| **envelope** | Cryptographic envelope format | `Envelope`, `EnvelopeMetadata` |
| **backends** | Universal Backend system | `UniversalBackend`, `UniversalBackendRegistry` |
| **audio** | Live audio capture | `AudioCapture`, `AudioConfig` |
| **auth** | Network authentication | `SessionManager`, `AuthChallenge` |
| **transport** | Network operations | `TransportConfig`, `NetworkChunk` |
| **asymmetric** | Public key cryptography | `KeyPair`, `PrivateKey`, `PublicKey` |
| **format** | Data format handling | `DataType` |

[↑ Back to top](#sealedge-core)

---

## Quick Start

### Library Usage

`sealedge-core` is not published to crates.io. Depend on it by path from within the
workspace (or via a git dependency):

```toml
[dependencies]
sealedge-core = { path = "../core" }
```

**Basic encryption/decryption:**

```rust
use sealedge_core::Envelope;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

// Generate key pairs
let sender_key = SigningKey::generate(&mut OsRng);
let recipient_key = SigningKey::generate(&mut OsRng);

// Encrypt data
let data = b"Secret message";
let envelope = Envelope::seal(data, &sender_key, &recipient_key.verifying_key())?;

// Decrypt data
let decrypted = envelope.unseal(&recipient_key)?;
assert_eq!(decrypted, data);
```

**Universal Backend usage:**

```rust
use sealedge_core::{CryptoOperation, CryptoResult, HashAlgorithm, UniversalBackendRegistry};

// Create a registry with the default backends
let registry = UniversalBackendRegistry::with_defaults()?;

// Perform an operation; the registry routes it to a capable backend
let operation = CryptoOperation::Hash {
    data: b"Hello, Universal Backend!".to_vec(),
    algorithm: HashAlgorithm::Sha256,
};
let result = registry.perform_operation("my_key", operation, None)?;
```

### CLI Applications

**Main CLI (`sealedge`):**
```bash
# Encrypt a file
./target/release/sealedge --input document.txt --envelope document.seal --key-out key.hex

# Decrypt a file
./target/release/sealedge --decrypt --input document.seal --out recovered.txt --key-hex $(cat key.hex)

# Live audio capture
./target/release/sealedge --live-capture --envelope voice.seal --key-out voice.key --max-duration 10
```

**Network Server:**
```bash
# Start authenticated server
./target/release/sealedge-server --listen 127.0.0.1:8080 --require-auth --decrypt
```

**Network Client:**
```bash
# Connect with authentication
./target/release/sealedge-client --server 127.0.0.1:8080 --file file.txt --enable-auth
```

[↑ Back to top](#sealedge-core)

---

## Core Systems

### Universal Backend System

The Universal Backend provides **pluggable cryptographic operations** across different backends,
dispatched by capability through a registry:

```rust
use sealedge_core::{CryptoOperation, HashAlgorithm, UniversalBackendRegistry};

// Discover and register the default backends
let registry = UniversalBackendRegistry::with_defaults()?;

for name in registry.list_backend_names() {
    if let Some(backend) = registry.get_backend(name) {
        let info = backend.backend_info();
        println!("{}: {}", info.name, info.description);
    }
}

// Perform an operation — the registry picks a backend that supports it
let operation = CryptoOperation::Hash {
    data: b"data".to_vec(),
    algorithm: HashAlgorithm::Sha256,
};
let result = registry.perform_operation("key_id", operation, None)?;
```

**Supported Backends:**
- **Keyring Backend**: OS keyring integration for key derivation (feature `keyring`)
- **YubiKey Backend**: Hardware PIV operations (feature `yubikey`)
- **Software HSM**: In-memory cryptographic operations
- **TPM Backend**: TPM 2.0 operations (planned)

### Envelope System

Sealedge uses a **secure envelope format** for data protection:

```rust
use sealedge_core::Envelope;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

// Generate keys
let sender_key = SigningKey::generate(&mut OsRng);
let recipient_key = SigningKey::generate(&mut OsRng);
let data = b"example data";

// Create envelope
let envelope = Envelope::seal(
    data,
    &sender_key,
    &recipient_key.verifying_key(),
)?;

// Inspect metadata without decrypting
println!("Envelope hash: {:?}", envelope.hash()?);
println!("Beneficiary: {:?}", envelope.beneficiary()?);
println!("Metadata: {:?}", envelope.metadata());
```

### Audio Capture System

Real-time audio capture with **format-aware processing** (feature `audio`):

```rust
use sealedge_core::{AudioCapture, AudioConfig, Envelope};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

// Configure audio capture (defaults: 44.1 kHz, mono, 1s chunks)
let config = AudioConfig {
    sample_rate: 44100,
    channels: 1,
    device_name: None, // Use default device
    ..AudioConfig::default()
};

// Capture audio in chunks
let mut capture = AudioCapture::new(config)?;
capture.initialize()?;
capture.start()?;
let chunk = capture.next_chunk()?;
capture.stop()?;

// Encrypt the captured chunk
let key = SigningKey::generate(&mut OsRng);
let envelope = Envelope::seal(&chunk.to_bytes(), &key, &key.verifying_key())?;
```

### Network Authentication

**Mutual authentication** with Ed25519 signatures:

```rust
use sealedge_core::auth::{SessionManager, ClientCertificate};

// Server setup — creates a self-signed server certificate
let mut session_manager = SessionManager::new("my-server".to_string())?;
let challenge = session_manager.create_challenge()?;

// Client setup — generates a client certificate/key pair
let client_cert = ClientCertificate::generate("my-client")?;
```

[↑ Back to top](#sealedge-core)

---

## CLI Applications

### Main CLI (`sealedge`)

The primary command-line interface for sealedge operations:

**File Operations:**
```bash
# Basic encryption
sealedge --input file.txt --envelope file.seal --key-out key.hex

# Keyring-based encryption
sealedge --input file.txt --envelope file.seal --use-keyring --salt-hex $(openssl rand -hex 16)

# Format inspection
sealedge --input file.seal --inspect --verbose
```

**Audio Operations:**
```bash
# List audio devices
sealedge --list-audio-devices

# Capture with specific device
sealedge --live-capture --audio-device "hw:CARD=USB,DEV=0" --envelope audio.seal --key-out audio.key
```

### Network Applications

**Server (`sealedge-server`):**
```bash
# Basic server
sealedge-server --listen 0.0.0.0:8080

# Authenticated server with decryption
sealedge-server --listen 0.0.0.0:8080 --require-auth --decrypt --verbose
```

**Client (`sealedge-client`):**
```bash
# Send file to server
sealedge-client --server 192.168.1.100:8080 --file document.txt

# Authenticated transfer
sealedge-client --server 192.168.1.100:8080 --file document.txt --enable-auth
```

### Hardware Demonstrations

**Software HSM Demo:**
```bash
# Generate key
software-hsm-demo generate-key my_key ed25519

# Sign data
software-hsm-demo sign my_key "Hello sealedge!"

# List keys
software-hsm-demo list-keys
```

**YubiKey (requires `--features yubikey`):**

YubiKey verification is demonstrated through examples rather than a standalone binary:
```bash
cargo run -p sealedge-core --features yubikey --example verify_yubikey
cargo run -p sealedge-core --features yubikey --example verify_yubikey_custom_pin
```

[↑ Back to top](#sealedge-core)

---

## Examples

### Example 1: Basic Library Usage

```rust
use sealedge_core::Envelope;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate keys
    let alice_key = SigningKey::generate(&mut OsRng);
    let bob_key = SigningKey::generate(&mut OsRng);

    // Alice encrypts for Bob
    let message = b"Hello Bob from Alice!";
    let envelope = Envelope::seal(message, &alice_key, &bob_key.verifying_key())?;

    // Bob decrypts
    let decrypted = envelope.unseal(&bob_key)?;
    assert_eq!(decrypted, message);

    println!("✔ Encryption/decryption successful");
    Ok(())
}
```

### Example 2: Universal Backend

```rust
use sealedge_core::{CryptoOperation, HashAlgorithm, UniversalBackendRegistry};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a registry with default backends
    let registry = UniversalBackendRegistry::with_defaults()?;

    // Hash some data through whichever backend supports it
    let operation = CryptoOperation::Hash {
        data: b"user data".to_vec(),
        algorithm: HashAlgorithm::Sha256,
    };

    let _result = registry.perform_operation("user_key", operation, None)?;
    println!("✔ Hash operation successful");
    Ok(())
}
```

A fuller walkthrough lives in `examples/universal_backend_demo.rs`:
```bash
cargo run -p sealedge-core --example universal_backend_demo
```

### Example 3: Audio Capture

```rust
#[cfg(feature = "audio")]
use sealedge_core::{AudioCapture, AudioConfig, Envelope};
#[cfg(feature = "audio")]
use ed25519_dalek::SigningKey;
#[cfg(feature = "audio")]
use rand::rngs::OsRng;

#[cfg(feature = "audio")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup audio capture
    let mut capture = AudioCapture::new(AudioConfig::default())?;
    capture.initialize()?;
    capture.start()?;

    // Grab one chunk
    let chunk = capture.next_chunk()?;
    capture.stop()?;
    let bytes = chunk.to_bytes();
    println!("Captured {} bytes of audio", bytes.len());

    // Encrypt captured audio
    let key = SigningKey::generate(&mut OsRng);
    let _envelope = Envelope::seal(&bytes, &key, &key.verifying_key())?;

    println!("✔ Audio capture and encryption successful");
    Ok(())
}

#[cfg(not(feature = "audio"))]
fn main() {
    println!("Audio features not enabled. Build with --features audio");
}
```

### Example 4: Network Authentication Setup

```rust
use sealedge_core::auth::{SessionManager, ClientCertificate};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Server setup — SessionManager creates a self-signed server certificate
    let mut session_manager = SessionManager::new("demo-server".to_string())?;
    let _challenge = session_manager.create_challenge()?;

    // Client setup
    let _client_cert = ClientCertificate::generate("demo-client")?;

    println!("✔ Network authentication setup complete");
    Ok(())
}
```

[↑ Back to top](#sealedge-core)

---

## Features

### Cargo Features

Default build enables **no** features for fast CI and maximum portability.

| Feature | Description | Default |
|---------|-------------|---------|
| `audio` | Enable live audio capture functionality | No |
| `yubikey` | Enable YubiKey hardware backend | No |
| `git-attestation` | Enable git repository state attestation | No |
| `keyring` | Enable OS keyring integration | No |
| `insecure-tls` | Skip TLS certificate verification (development only) | No |

**Build with features:**
```bash
# Audio support
cargo build --features audio

# YubiKey support
cargo build --features yubikey

# Multiple features
cargo build --features audio,yubikey
```

### System Dependencies

**Audio Features:**
```bash
# Ubuntu/Debian
sudo apt-get install libasound2-dev pkg-config

# macOS (included with Xcode)
# No additional packages needed

# Windows (included with Windows SDK)
# No additional packages needed
```

**YubiKey Features:**
```bash
# Ubuntu/Debian
sudo apt-get install opensc-pkcs11

# macOS
brew install opensc

# Windows
# Download OpenSC from https://github.com/OpenSC/OpenSC/releases
```

[↑ Back to top](#sealedge-core)

---

## Testing

Sealedge Core includes a comprehensive test suite covering all functionality:

```bash
# Run all tests
cargo test

# Run with features
cargo test --features audio,yubikey

# Run specific test categories
cargo test envelope
cargo test backends
cargo test audio
cargo test auth

# Run benchmarks
cargo bench
```

**Test Categories:**
- **Envelope Tests**: Encryption/decryption, format handling
- **Backend Tests**: Universal Backend system, keyring integration
- **Audio Tests**: Live capture, format detection
- **Authentication Tests**: Mutual auth, session management
- **Transport Tests**: Network operations, error handling
- **Hardware Tests**: YubiKey integration (requires hardware)

### Performance Testing

```bash
# Quick benchmarks (from project root)
./scripts/fast-bench.sh

# Full benchmark suite
cargo bench

# Transport demo
cargo run --example transport_demo --release
```

[↑ Back to top](#sealedge-core)

---

## API Reference

### Core Types

#### `Envelope`
Secure cryptographic envelope for data protection:

```rust
impl Envelope {
    pub fn seal(payload: &[u8], signing_key: &SigningKey, beneficiary_key: &VerifyingKey) -> Result<Self>;
    pub fn unseal(&self, decryption_key: &SigningKey) -> Result<Vec<u8>>;
    pub fn verify(&self) -> bool;
    pub fn hash(&self) -> Result<[u8; 32]>;
    pub fn beneficiary(&self) -> Result<VerifyingKey>;
    pub fn issuer(&self) -> Result<VerifyingKey>;
    pub fn metadata(&self) -> &EnvelopeMetadata;
}
```

#### `UniversalBackendRegistry`
Capability-based routing across pluggable backends:

```rust
impl UniversalBackendRegistry {
    pub fn with_defaults() -> Result<Self>;
    pub fn perform_operation(&self, key_id: &str, operation: CryptoOperation, preferences: Option<&BackendPreferences>) -> Result<CryptoResult, BackendError>;
    pub fn list_backend_names(&self) -> Vec<&str>;
    pub fn get_backend(&self, name: &str) -> Option<&dyn UniversalBackend>;
}
```

`UniversalBackend` is the trait each backend implements; its core methods are
`perform_operation`, `supports_operation`, `backend_info`, and `get_capabilities`.

#### `AudioCapture`
Live audio capture functionality (feature `audio`):

```rust
impl AudioCapture {
    pub fn new(config: AudioConfig) -> Result<Self>;
    pub fn initialize(&mut self) -> Result<()>;
    pub fn start(&mut self) -> Result<()>;
    pub fn next_chunk(&self) -> Result<AudioChunk>;
    pub fn stop(&mut self) -> Result<()>;
    pub fn list_devices(&self) -> Result<Vec<String>>;
    pub fn config(&self) -> &AudioConfig;
}
```

### Error Handling

Sealedge Core exposes a single top-level error enum, `TrustEdgeError`, which wraps the
domain-specific error types:

```rust
use sealedge_core::TrustEdgeError;

match operation_result {
    Ok(data) => println!("Success: {} bytes", data.len()),
    Err(TrustEdgeError::Crypto(e)) => eprintln!("Crypto error: {}", e),
    Err(TrustEdgeError::Transport(e)) => eprintln!("Transport error: {}", e),
    Err(TrustEdgeError::Archive(e)) => eprintln!("Archive error: {}", e),
    Err(e) => eprintln!("Other error: {}", e),
}
```

The full set of variants is `Crypto`, `PointAttestation`, `Backend`, `Transport`,
`Archive`, `Manifest`, `Chain`, `Asymmetric`, `Io`, and `Json`.

[↑ Back to top](#sealedge-core)

---

## Performance

Sealedge Core is optimized for streaming edge workloads. Rather than publish figures
that drift out of date, measure on your own hardware:

```bash
# Quick local benchmarks (from project root)
./scripts/fast-bench.sh

# Full statistical benchmark suite
cargo bench
```

### Optimization Tips

1. **Reuse Keys**: Generate key pairs once and reuse
2. **Batch Operations**: Process multiple files together
3. **Streaming**: Use chunked processing for large files
4. **Backend Selection**: Choose appropriate backend for use case

```rust
use sealedge_core::Envelope;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

// Efficient batch processing
let key = SigningKey::generate(&mut OsRng);
let files = vec!["file1.txt", "file2.txt", "file3.txt"];

for file in files {
    let data = std::fs::read(file)?;
    let _envelope = Envelope::seal(&data, &key, &key.verifying_key())?;
    // Process envelope...
}
```

---

## Integration

### With Other Sealedge Crates

```rust
// Receipts (consolidated in core)
use sealedge_core::create_receipt;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

let key = SigningKey::generate(&mut OsRng);
let receipt = create_receipt(&key, &key.verifying_key(), 1000, None)?;

// Attestation (consolidated in core)
use sealedge_core::{create_signed_attestation, AttestationConfig};

// With sealedge-wasm
use sealedge_core::Envelope;
// Export envelope functionality to WebAssembly

// With sealedge-pubky (community/experimental)
use sealedge_core::UniversalBackendRegistry;
// Use core backends with Pubky network integration
```

### External Integration

```rust
// With tokio for async I/O; serialize the envelope with bincode
use tokio::fs;
use sealedge_core::Envelope;

async fn write_envelope(envelope: &Envelope) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = bincode::serialize(envelope)?;
    fs::write("file.seal", bytes).await?;
    Ok(())
}
```

[↑ Back to top](#sealedge-core)

---

## Contributing

We welcome contributions to Sealedge Core:

1. **Core Cryptography**: Improve encryption/decryption performance
2. **Backend Development**: Add new Universal Backend implementations
3. **Audio Processing**: Enhance audio capture capabilities
4. **Network Features**: Improve transport layer functionality
5. **Hardware Integration**: Expand hardware security module support

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for detailed guidelines.

### Development Setup

```bash
# Clone repository
git clone https://github.com/TrustEdge-Labs/sealedge.git
cd sealedge

# Run tests
cargo test -p sealedge-core

# Run with all features
cargo test -p sealedge-core --features audio,yubikey

# Run examples
cargo run -p sealedge-core --example universal_backend_demo
cargo run -p sealedge-core --example transport_demo

# Check formatting
cargo fmt --check
```

[↑ Back to top](#sealedge-core)

---

## Documentation

### Crate-Specific Documentation
- **[AUTHENTICATION.md](AUTHENTICATION.md)** - Network authentication details

### Project Documentation
- **[Main README](../../README.md)** - Project overview and quick start

[↑ Back to top](#sealedge-core)

---

## License

This project is licensed under the Mozilla Public License 2.0 (MPL-2.0).

**Commercial Licensing**: Enterprise licenses available for commercial use without source disclosure requirements. Contact [enterprise@trustedgelabs.com](mailto:enterprise@trustedgelabs.com).

[↑ Back to top](#sealedge-core)

---

## Security

For security issues, please follow our [responsible disclosure policy](../../SECURITY.md).

**Security Contact**: [security@trustedgelabs.com](mailto:security@trustedgelabs.com)

[↑ Back to top](#sealedge-core)

---

*Sealedge Core - The foundation of privacy-preserving edge computing.*
