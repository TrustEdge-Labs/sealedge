<!--
Copyright (c) 2025 TRUSTEDGE LABS LLC
MPL-2.0: https://mozilla.org/MPL/2.0/
Project: sealedge — Privacy and trust at the edge.
GitHub: https://github.com/TrustEdge-Labs/sealedge
-->

# Adding secp256k1 (K1) Support to Sealedge

**Status**: Planning Phase  
**Priority**: P1  
**Target**: Post-P0 Enhancement

## 📋 Overview

This document outlines the plan to add **secp256k1 (K1 curve)** support alongside the existing **secp256r1 (P-256/R1 curve)** support. This will enable Sealedge to interoperate with Bitcoin, Ethereum, and other blockchain ecosystems while maintaining compatibility with standard NIST curves.

**Why Both Curves**:
- **secp256r1 (P-256/R1)**: NIST standard, used by YubiKey, TPM, government systems
- **secp256k1 (K1)**: Bitcoin/Ethereum standard, used by cryptocurrency wallets, Web3 apps

---

## 🎯 Goals

1. **Add K1 support** to Universal Backend system
2. **Maintain R1 compatibility** - both curves work side-by-side
3. **Enable curve selection** via configuration/feature flags
4. **Interoperate with Web3** - sign/verify Ethereum transactions
5. **Support hardware wallets** - Ledger, Trezor use K1

---

## 🏗️ Implementation Plan

### Phase 1: Core Algorithm Support

#### 1.1 Add `k256` Dependency

**File**: `Cargo.toml` (workspace)

```toml
[workspace.dependencies]
# Add K1 support alongside existing P-256 support
k256 = { version = "0.13", features = ["ecdsa", "ecdh", "pem"] }
p256 = { version = "0.13", features = ["ecdsa", "pem", "ecdh"] }  # Existing
```

**File**: `crates/core/Cargo.toml`

```toml
[dependencies]
k256 = { workspace = true }
p256 = { workspace = true }  # Existing
```

---

#### 1.2 Extend `AsymmetricAlgorithm` Enum

**File**: `crates/core/src/backends/universal.rs`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AsymmetricAlgorithm {
    Ed25519,
    EcdsaP256,      // Existing (secp256r1/NIST P-256)
    EcdsaK256,      // NEW: secp256k1 (Bitcoin/Ethereum curve)
    Rsa2048,
    Rsa4096,
}
```

---

#### 1.3 Extend `SignatureAlgorithm` Enum

**File**: `crates/core/src/backends/universal.rs`

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    Ed25519,
    EcdsaP256,      // Existing: ECDSA with P-256
    EcdsaK256,      // NEW: ECDSA with secp256k1
    RsaPkcs1v15,
    RsaPss,
}
```

---

#### 1.4 Add K1 Key Generation

**File**: `crates/core/src/asymmetric.rs`

Add new function parallel to existing `generate_ecdsa_p256()`:

```rust
fn generate_ecdsa_k256() -> Result<Self> {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::SecretKey;
    
    let secret = SecretKey::random(&mut OsRng);
    let public = secret.public_key();
    
    Ok(KeyPair {
        private_key: PrivateKey::new(
            secret.to_bytes().to_vec(),
            AsymmetricAlgorithm::EcdsaK256,
        ),
        public_key: PublicKey::new(
            public.to_encoded_point(false).as_bytes().to_vec(),
            AsymmetricAlgorithm::EcdsaK256,
        ),
    })
}
```

Update `KeyPair::generate()`:

```rust
pub fn generate(algorithm: AsymmetricAlgorithm) -> Result<Self> {
    match algorithm {
        AsymmetricAlgorithm::Ed25519 => Self::generate_ed25519(),
        AsymmetricAlgorithm::EcdsaP256 => Self::generate_ecdsa_p256(),
        AsymmetricAlgorithm::EcdsaK256 => Self::generate_ecdsa_k256(),  // NEW
        AsymmetricAlgorithm::Rsa2048 => Self::generate_rsa(2048),
        AsymmetricAlgorithm::Rsa4096 => Self::generate_rsa(4096),
    }
}
```

---

#### 1.5 Add K1 ECDH Support

**File**: `crates/core/src/asymmetric.rs`

Add new function parallel to existing `ecdh_p256()`:

```rust
fn ecdh_k256(private_key: &PrivateKey, public_key: &PublicKey) -> Result<Vec<u8>, AsymmetricError> {
    use k256::elliptic_curve::sec1::FromEncodedPoint;
    use k256::{ecdh::diffie_hellman, PublicKey as K256PublicKey, SecretKey};
    
    // Parse private key
    let secret = SecretKey::from_bytes(&private_key.key_bytes.clone().into())
        .map_err(|e| AsymmetricError::KeyError(format!("Invalid K256 private key: {}", e)))?;
    
    // Parse public key
    let point = k256::EncodedPoint::from_bytes(&public_key.key_bytes)
        .map_err(|e| AsymmetricError::KeyError(format!("Invalid K256 public key: {}", e)))?;
    
    let peer_public = K256PublicKey::from_encoded_point(&point)
        .ok_or_else(|| AsymmetricError::KeyError("Invalid K256 public key point".into()))?;
    
    // Perform ECDH
    let shared_secret = diffie_hellman(secret.to_nonzero_scalar(), peer_public.as_affine());
    Ok(shared_secret.raw_secret_bytes().to_vec())
}
```

Update `key_exchange()`:

```rust
pub fn key_exchange(
    my_private_key: &PrivateKey,
    peer_public_key: &PublicKey,
) -> Result<Vec<u8>, AsymmetricError> {
    match (my_private_key.algorithm, peer_public_key.algorithm) {
        (AsymmetricAlgorithm::EcdsaP256, AsymmetricAlgorithm::EcdsaP256) => {
            ecdh_p256(my_private_key, peer_public_key)
        }
        (AsymmetricAlgorithm::EcdsaK256, AsymmetricAlgorithm::EcdsaK256) => {  // NEW
            ecdh_k256(my_private_key, peer_public_key)
        }
        _ => Err(AsymmetricError::AlgorithmMismatch),
    }
}
```

---

### Phase 2: Backend Integration

#### 2.1 Update Software HSM Backend

**File**: `crates/core/src/backends/software_hsm.rs`

Add K1 support to `perform_operation()`:

```rust
CryptoOperation::Sign { data, algorithm } => {
    match algorithm {
        SignatureAlgorithm::Ed25519 => { /* existing */ }
        SignatureAlgorithm::EcdsaP256 => { /* existing */ }
        SignatureAlgorithm::EcdsaK256 => {  // NEW
            use k256::ecdsa::{SigningKey, Signature, signature::Signer};
            
            let signing_key = SigningKey::from_bytes(&key_data.into())
                .map_err(|e| anyhow!("Invalid K256 key: {}", e))?;
            
            let signature: Signature = signing_key.sign(&data);
            Ok(CryptoResult::Signed(signature.to_vec()))
        }
        _ => Err(anyhow!("Unsupported signature algorithm")),
    }
}
```

Update `get_capabilities()`:

```rust
fn get_capabilities(&self) -> BackendCapabilities {
    BackendCapabilities {
        hardware_backed: false,
        supports_attestation: false,
        symmetric_algorithms: vec![SymmetricAlgorithm::Aes256Gcm],
        asymmetric_algorithms: vec![
            AsymmetricAlgorithm::Ed25519,
            AsymmetricAlgorithm::EcdsaP256,
            AsymmetricAlgorithm::EcdsaK256,  // NEW
            AsymmetricAlgorithm::Rsa2048,
        ],
        signature_algorithms: vec![
            SignatureAlgorithm::Ed25519,
            SignatureAlgorithm::EcdsaP256,
            SignatureAlgorithm::EcdsaK256,  // NEW
        ],
        hash_algorithms: vec![HashAlgorithm::Sha256],
        supports_key_derivation: true,
        max_key_size: None,
    }
}
```

---

#### 2.2 Update YubiKey Backend

**File**: `crates/core/src/backends/yubikey.rs`

**Note**: YubiKey PIV slots support **P-256 only**, NOT K1. Document this limitation:

```rust
impl UniversalBackend for YubiKeyBackend {
    fn get_capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            // YubiKey only supports P-256, not K1
            asymmetric_algorithms: vec![AsymmetricAlgorithm::EcdsaP256],
            signature_algorithms: vec![SignatureAlgorithm::EcdsaP256],
            // ...
        }
    }
    
    fn supports_operation(&self, operation: &CryptoOperation) -> bool {
        match operation {
            CryptoOperation::Sign { algorithm, .. } => {
                // YubiKey PIV does NOT support K1
                matches!(algorithm, SignatureAlgorithm::EcdsaP256)
            }
            _ => false,
        }
    }
}
```

---

### Phase 3: Testing

#### 3.1 Unit Tests

**File**: `crates/core/src/asymmetric.rs`

```rust
#[test]
fn test_k256_key_generation() {
    let keypair = KeyPair::generate(AsymmetricAlgorithm::EcdsaK256).unwrap();
    assert_eq!(keypair.private_key.algorithm, AsymmetricAlgorithm::EcdsaK256);
    assert_eq!(keypair.public_key.algorithm, AsymmetricAlgorithm::EcdsaK256);
    assert_eq!(keypair.private_key.key_bytes.len(), 32);
}

#[test]
fn test_k256_ecdh() {
    let alice = KeyPair::generate(AsymmetricAlgorithm::EcdsaK256).unwrap();
    let bob = KeyPair::generate(AsymmetricAlgorithm::EcdsaK256).unwrap();
    
    let alice_shared = key_exchange(&alice.private_key, &bob.public_key).unwrap();
    let bob_shared = key_exchange(&bob.private_key, &alice.public_key).unwrap();
    
    assert_eq!(alice_shared, bob_shared);
}

#[test]
fn test_k256_sign_verify() {
    let keypair = KeyPair::generate(AsymmetricAlgorithm::EcdsaK256).unwrap();
    let message = b"test message";
    
    use k256::ecdsa::{SigningKey, VerifyingKey, Signature, signature::{Signer, Verifier}};
    
    let signing_key = SigningKey::from_bytes(&keypair.private_key.key_bytes.clone().into()).unwrap();
    let signature: Signature = signing_key.sign(message);
    
    let verifying_key = VerifyingKey::from_sec1_bytes(&keypair.public_key.key_bytes).unwrap();
    assert!(verifying_key.verify(message, &signature).is_ok());
}
```

---

#### 3.2 Integration Tests

**File**: `crates/core/tests/k256_integration.rs` (NEW)

```rust
use sealedge_core::backends::{
    SoftwareHsmBackend, UniversalBackend, CryptoOperation, 
    SignatureAlgorithm, AsymmetricAlgorithm
};

#[test]
fn test_software_hsm_k256_operations() {
    let backend = SoftwareHsmBackend::new().unwrap();
    
    // Generate K256 key
    backend.generate_key_pair(
        "test_k256", 
        AsymmetricAlgorithm::EcdsaK256, 
        None
    ).unwrap();
    
    // Sign with K256
    let data = b"test message";
    let operation = CryptoOperation::Sign {
        data: data.to_vec(),
        algorithm: SignatureAlgorithm::EcdsaK256,
    };
    
    let result = backend.perform_operation("test_k256", operation).unwrap();
    // Verify signature...
}
```

---

### Phase 4: Web3 Integration Examples

#### 4.1 Ethereum Signature Example

**File**: `crates/core/examples/ethereum_signing.rs` (NEW)

```rust
//! Example: Sign Ethereum transactions with K256
//!
//! Demonstrates secp256k1 signing compatible with Ethereum

use sealedge_core::backends::*;

fn main() -> anyhow::Result<()> {
    let backend = SoftwareHsmBackend::new()?;
    
    // Generate K256 key (compatible with Ethereum)
    backend.generate_key_pair(
        "ethereum_key",
        AsymmetricAlgorithm::EcdsaK256,
        None,
    )?;
    
    // Get public key
    let pubkey = backend.perform_operation(
        "ethereum_key",
        CryptoOperation::GetPublicKey,
    )?;
    
    // Derive Ethereum address (last 20 bytes of Keccak256(pubkey))
    let address = ethereum_address_from_pubkey(&pubkey);
    println!("Ethereum address: 0x{}", hex::encode(address));
    
    // Sign transaction hash
    let tx_hash = b"example transaction hash (32 bytes)";
    let signature = backend.perform_operation(
        "ethereum_key",
        CryptoOperation::Sign {
            data: tx_hash.to_vec(),
            algorithm: SignatureAlgorithm::EcdsaK256,
        },
    )?;
    
    println!("Transaction signature: {}", hex::encode(signature));
    
    Ok(())
}

fn ethereum_address_from_pubkey(pubkey: &[u8]) -> [u8; 20] {
    use sha3::{Digest, Keccak256};
    let hash = Keccak256::digest(&pubkey[1..]); // Skip 0x04 prefix
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    address
}
```

---

### Phase 5: Documentation

#### 5.1 Update Feature Flags Documentation

**File**: `FEATURES.md`

Add section on curve selection:

```markdown
### `k256` - secp256k1 (Bitcoin/Ethereum) Support

**Purpose**: Enables secp256k1 elliptic curve operations for Web3 compatibility.

**Dependencies Added**:
- `k256` (0.13) - secp256k1 cryptographic primitives

**What It Enables**:
- Bitcoin-compatible ECDSA signatures
- Ethereum transaction signing
- ECDH key exchange with K1 curve
- Interoperability with hardware wallets (Ledger, Trezor)

**Build Command**:
```bash
cargo build -p sealedge-core --features k256
```

**Note**: YubiKey hardware only supports P-256, not K1.
```

---

#### 5.2 Update Architecture Documentation

Add curve selection guidance to README:

```markdown
## Choosing Between P-256 and K1

| Curve | Use Case | Hardware Support |
|-------|----------|------------------|
| **P-256 (R1)** | Government systems, YubiKey, TPM | ✅ YubiKey, TPM 2.0 |
| **secp256k1 (K1)** | Bitcoin, Ethereum, Web3 apps | ✅ Ledger, Trezor |

**Default**: Use P-256 for maximum hardware compatibility
**Web3**: Use K1 for blockchain interoperability
```

---

## 🔒 Security Considerations

1. **Curve Validation**: Both curves are cryptographically secure (128-bit security)
2. **Implementation**: Use well-audited `k256` crate (same authors as `p256`)
3. **Side-Channel Resistance**: `k256` has constant-time implementations
4. **Hardware Support**: Document that YubiKey does NOT support K1

---

## 📦 Dependencies

```toml
k256 = { version = "0.13", features = ["ecdsa", "ecdh", "pem"] }
sha3 = "0.10"  # For Ethereum address derivation
```

---

## ✅ Testing Checklist

- [ ] Unit tests for K256 key generation
- [ ] Unit tests for K256 ECDSA sign/verify
- [ ] Unit tests for K256 ECDH key exchange
- [ ] Integration tests with Software HSM backend
- [ ] Example: Ethereum transaction signing
- [ ] Example: Bitcoin message signing
- [ ] Documentation updates
- [ ] CI tests for K256 feature flag
- [ ] Benchmark K256 vs P256 performance

---

## 🚀 Next Steps

1. **Review this RFC** - Get feedback on architecture
2. **Create feature branch**: `feat/k256-support`
3. **Implement Phase 1** - Core algorithm support
4. **Test Phase 1** - Unit tests passing
5. **Implement Phase 2** - Backend integration
6. **Add examples** - Ethereum/Bitcoin demos
7. **Update docs** - FEATURES.md, README.md
8. **Submit PR** - For review and merge

---

## 📚 References

- **k256 crate**: https://docs.rs/k256/
- **secp256k1 spec**: https://www.secg.org/sec2-v2.pdf
- **Ethereum Yellow Paper**: https://ethereum.github.io/yellowpaper/paper.pdf
- **Bitcoin secp256k1**: https://en.bitcoin.it/wiki/Secp256k1

---

For questions, contact the Sealedge team or open a GitHub issue.
