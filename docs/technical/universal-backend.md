<!--
Copyright (c) 2025 TRUSTEDGE LABS LLC
MPL-2.0: https://mozilla.org/MPL/2.0/
Project: sealedge — Privacy and trust at the edge.
GitHub: https://github.com/TrustEdge-Labs/sealedge
-->


# Universal Backend System

The Sealedge Universal Backend system provides a unified, capability-based approach to cryptographic operations across different backend types.

## Design Philosophy

Instead of a monolithic trait with many methods, the Universal Backend uses:

- **Single operation method**: `perform_operation(key_id, operation)` 
- **Capability discovery**: `supports_operation(operation)` and `get_capabilities()`
- **Runtime selection**: Backends can be selected based on their capabilities
- **Extensibility**: New operations and backends can be added without changing existing code

## Core Components

### 1. Operations (`CryptoOperation`)

```rust
pub enum CryptoOperation {
    // Symmetric operations
    Encrypt { plaintext: Vec<u8>, algorithm: SymmetricAlgorithm },
    Decrypt { ciphertext: Vec<u8>, algorithm: SymmetricAlgorithm },
    
    // Asymmetric operations  
    Sign { data: Vec<u8>, algorithm: SignatureAlgorithm },
    Verify { data: Vec<u8>, signature: Vec<u8>, algorithm: SignatureAlgorithm },
    
    // Key management
    DeriveKey { context: KeyDerivationContext },
    GenerateKeyPair { algorithm: AsymmetricAlgorithm },
    GetPublicKey,
    
    // Advanced operations
    KeyExchange { peer_public_key: Vec<u8>, algorithm: AsymmetricAlgorithm },
    Attest { challenge: Vec<u8> }, // Hardware attestation
    Hash { data: Vec<u8>, algorithm: HashAlgorithm },
}
```

### 2. Results (`CryptoResult`)

```rust
pub enum CryptoResult {
    Encrypted(Vec<u8>),
    Decrypted(Vec<u8>),
    Signed(Vec<u8>),
    VerificationResult(bool),
    DerivedKey([u8; 32]),
    KeyPair { public_key: Vec<u8>, private_key_id: String },
    PublicKey(Vec<u8>),
    SharedSecret(Vec<u8>),
    AttestationProof(Vec<u8>),
    Hash(Vec<u8>),
}
```

### 3. The Universal Backend Trait

```rust
pub trait UniversalBackend: Send + Sync {
    fn perform_operation(&self, key_id: &str, operation: CryptoOperation) -> Result<CryptoResult>;
    fn supports_operation(&self, operation: &CryptoOperation) -> bool;
    fn get_capabilities(&self) -> BackendCapabilities;
    fn backend_info(&self) -> BackendInfo;
}
```

## Current Backends

### 1. Software HSM Backend (`SoftwareHsmBackend`)

**Capabilities:**
- ✔ Symmetric encryption/decryption (AES-256-GCM)
- ✔ Asymmetric key generation (Ed25519, ECDSA P-256, RSA 2048/4096)
- ✔ Digital signing (Ed25519, ECDSA, RSA-PSS/PKCS1v15)
- ✔ Key derivation (PBKDF2, Argon2id)
- ✔ Cross-session persistence with encrypted storage
- ✖ Hardware attestation (software-only backend)

**Use Cases:**
- Development and testing
- Software-only deployments
- High-performance symmetric operations

### 2. YubiKey Hardware Backend (`YubiKeyBackend`)

**Capabilities:**
- ✔ Hardware-backed signing (ECDSA P-256, RSA 2048/4096)
- ✔ Real YubiKey PIV operations via PKCS#11
- ✔ Hardware attestation
- ✔ PIN-protected private key operations
- ✔ X.509 certificate generation and management
- ✖ Symmetric encryption (hardware keys for signing only)

**Hardware Requirements:**
- YubiKey with PIV applet enabled
- PKCS#11 libraries (OpenSC)
- System dependencies: `libpcsclite-dev`

**Example:**
```rust
use sealedge_core::backends::yubikey::{YubiKeyBackend, YubiKeyConfig};

let config = YubiKeyConfig {
    pkcs11_module_path: "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so".to_string(),
    pin: Some("123456".to_string()),
    slot: None, // Auto-detect
    verbose: true,
};

let yubikey = YubiKeyBackend::with_config(config)?;

// Real hardware signing
let signature = yubikey.perform_operation(
    "9c", // PIV slot 9C (SIGNATURE)
    CryptoOperation::Sign {
        data: b"message".to_vec(),
        algorithm: SignatureAlgorithm::EcdsaP256,
    },
)?;
```

### 3. OS Keyring Backend (`UniversalKeyringBackend`)

**Capabilities:**
- ✔ Key derivation using PBKDF2
- ✔ Hash operations (SHA-256, SHA-384, SHA-512, BLAKE3)
- ✔ OS keyring integration for credential storage
- ✖ Digital signing (software-only backend)
- ✖ Hardware attestation

**Use Cases:**
- Password-based key derivation
- File integrity verification
- Development and testing

## Usage Examples

### Basic Hash Operation

```rust
use sealedge_core::{UniversalBackendRegistry, CryptoOperation, HashAlgorithm};

let registry = UniversalBackendRegistry::with_defaults()?;

let result = registry.perform_operation(
    "my_key",
    CryptoOperation::Hash {
        data: b"Hello World".to_vec(),
        algorithm: HashAlgorithm::Sha256,
    },
    None
)?;

if let CryptoResult::Hash(hash) = result {
    println!("SHA-256: {}", hex::encode(hash));
}
```

### Key Derivation

```rust
use sealedge_core::{CryptoOperation, KeyDerivationContext};

let context = KeyDerivationContext::new(vec![1; 16]) // 16-byte salt
    .with_additional_data(b"app_context".to_vec())
    .with_iterations(600_000);

let result = registry.perform_operation(
    "encryption_key",
    CryptoOperation::DeriveKey { context },
    None
)?;

if let CryptoResult::DerivedKey(key) = result {
    // Use the derived key for AES encryption
    println!("Derived key: {}", hex::encode(key));
}
```

### Capability-Based Backend Selection

```rust
// Find backends that support signing
let sign_op = CryptoOperation::Sign {
    data: vec![1, 2, 3],
    algorithm: SignatureAlgorithm::Ed25519,
};

let backends = registry.find_all_backends_for_operation(&sign_op);
if backends.is_empty() {
    println!("No backends support Ed25519 signing");
} else {
    println!("Signing supported by: {:?}", 
        backends.iter().map(|(name, _)| name).collect::<Vec<_>>());
}
```

### Preference-Based Selection

```rust
use sealedge_core::BackendPreferences;

// Prefer hardware-backed backends
let prefs = BackendPreferences::hardware_preferred();

let result = registry.perform_operation(
    "secure_key",
    CryptoOperation::Sign { /* ... */ },
    Some(&prefs)
)?;
```

## Adding New Backends

To add a new backend (e.g., YubiKey), implement the `UniversalBackend` trait:

```rust
pub struct YubiKeyBackend {
    // YubiKey connection details
}

impl UniversalBackend for YubiKeyBackend {
    fn perform_operation(&self, key_id: &str, operation: CryptoOperation) -> Result<CryptoResult> {
        match operation {
            CryptoOperation::Sign { data, algorithm } => {
                // Use YubiKey PIV for signing
                let signature = self.piv_sign(key_id, &data, algorithm)?;
                Ok(CryptoResult::Signed(signature))
            }
            CryptoOperation::Attest { challenge } => {
                // Use YubiKey attestation
                let proof = self.hardware_attest(&challenge)?;
                Ok(CryptoResult::AttestationProof(proof))
            }
            _ => Err(anyhow!("Operation not supported by YubiKey backend"))
        }
    }
    
    fn supports_operation(&self, operation: &CryptoOperation) -> bool {
        matches!(operation,
            CryptoOperation::Sign { .. } |
            CryptoOperation::Verify { .. } |
            CryptoOperation::GenerateKeyPair { .. } |
            CryptoOperation::Attest { .. }
        )
    }
    
    fn get_capabilities(&self) -> BackendCapabilities {
        BackendCapabilities::hardware_security_module()
    }
}
```

## Future Extensions

The Universal Backend system is designed for extensibility:

### New Operations
- `KeyExchange` for ECDH/post-quantum key exchange
- `Verify` for signature verification
- `GenerateKeyPair` for key generation
- `RotateKey` for key lifecycle management

### New Backends
- **✅ YubiKey Backend**: Hardware-backed signing, attestation, and X.509 certificate generation (IMPLEMENTED)
- **TPM Backend**: Platform-based root of trust
- **HSM Backend**: Enterprise hardware security modules
- **Post-Quantum Backend**: Quantum-resistant algorithms

### New Algorithms
- Post-quantum signatures (Dilithium, Falcon)
- Post-quantum key exchange (Kyber)
- Custom elliptic curves
- Hardware-specific algorithms

## Benefits

✔ **Composability**: Mix and match backends for different operations  
✔ **Runtime Discovery**: Applications can adapt to available hardware  
✔ **Clear Intent**: Operations are self-describing and type-safe  
✔ **Future-Proof**: Easy to add new crypto without breaking existing code  
✔ **Testing**: Mock backends can be easily created for testing  
✔ **Security Policies**: Preference system enforces security requirements  

## Migration from Old Backend System

The old `KeyBackend` trait remains available for backward compatibility. The Universal Backend system can be used alongside the old system, and migration can happen gradually:

1. **Phase 1**: Use Universal Backend for new features
2. **Phase 2**: Create adapter layer for old backend calls
3. **Phase 3**: Migrate existing code to Universal Backend
4. **Phase 4**: Remove old backend system

The Universal Backend system represents the future of cryptographic operations in Sealedge, providing the flexibility needed to support everything from software-only encryption to advanced hardware security modules.
