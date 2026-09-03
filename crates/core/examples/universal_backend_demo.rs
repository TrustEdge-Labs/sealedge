//
// Copyright (c) 2025 TRUSTEDGE LABS LLC
// This source code is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Project: sealedge — Privacy and trust at the edge.
//

//! Example demonstrating the Universal Backend system
//!
//! This example shows how to use the new capability-based backend architecture
//! to perform cryptographic operations across different backend types.

use anyhow::Result;
use sealedge_core::{
    BackendPreferences, CryptoOperation, CryptoResult, HashAlgorithm, KeyDerivationContext,
    UniversalBackendRegistry,
};

fn main() -> Result<()> {
    println!("● Sealedge Universal Backend System Demo");
    println!("==========================================\n");

    // Create a registry with default backends
    let registry = UniversalBackendRegistry::with_defaults()?;

    println!("● Available Backends:");
    for backend_name in registry.list_backend_names() {
        if let Some(backend) = registry.get_backend(backend_name) {
            let info = backend.backend_info();
            let caps = backend.get_capabilities();
            println!(
                "  • {}: {} (Hardware: {})",
                info.name, info.description, caps.hardware_backed
            );
        }
    }
    println!();

    // Example 1: Hash Operation
    println!("● Example 1: Hash Operation");
    println!("-----------------------------");

    let hash_op = CryptoOperation::Hash {
        data: b"Hello, Universal Backend!".to_vec(),
        algorithm: HashAlgorithm::Sha256,
    };

    match registry.perform_operation("demo_key", hash_op, None)? {
        CryptoResult::Hash(hash) => {
            println!("✔ SHA-256 Hash: {}", hex::encode(&hash[..8]));
            println!("   Full hash length: {} bytes", hash.len());
        }
        _ => println!("✖ Unexpected result type"),
    }
    println!();

    // Example 2: Key Derivation (will fail without keyring passphrase, but shows structure)
    println!("● Example 2: Key Derivation");
    println!("-----------------------------");

    let context = KeyDerivationContext::new(vec![1; 16])
        .with_additional_data(b"demo_context".to_vec())
        .with_iterations(600_000)
        .expect("600k is a valid iteration count");

    let derive_op = CryptoOperation::DeriveKey { context };

    match registry.perform_operation("demo_key", derive_op, None) {
        Ok(CryptoResult::DerivedKey(key)) => {
            println!("✔ Derived Key: {}...", hex::encode(&key[..8]));
            println!("   Full key length: {} bytes", key.len());
        }
        Err(e) => {
            println!("● Key derivation failed (expected without keyring passphrase):");
            println!("   Error: {}", e);
        }
        _ => println!("✖ Unexpected result type"),
    }
    println!();

    // Example 3: Backend Capability Discovery
    println!("● Example 3: Backend Capability Discovery");
    println!("-------------------------------------------");

    let test_operations = vec![
        (
            "Hash (SHA-256)",
            CryptoOperation::Hash {
                data: vec![1, 2, 3],
                algorithm: HashAlgorithm::Sha256,
            },
        ),
        (
            "Key Derivation",
            CryptoOperation::DeriveKey {
                context: KeyDerivationContext::new(vec![1; 16]),
            },
        ),
        (
            "Digital Signing",
            CryptoOperation::Sign {
                data: vec![1, 2, 3],
                algorithm: sealedge_core::SignatureAlgorithm::Ed25519,
            },
        ),
        (
            "Hardware Attestation",
            CryptoOperation::Attest {
                challenge: vec![1, 2, 3],
            },
        ),
    ];

    for (name, operation) in test_operations {
        let supported_backends = registry.find_all_backends_for_operation(&operation);
        if supported_backends.is_empty() {
            println!("  ✖ {}: No backends support this operation", name);
        } else {
            println!(
                "  ✔ {}: Supported by {}",
                name,
                supported_backends
                    .iter()
                    .map(|(name, _)| *name)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }
    println!();

    // Example 4: Backend Preferences
    println!("● Example 4: Backend Preferences");
    println!("----------------------------------");

    let hardware_prefs = BackendPreferences::hardware_preferred();
    let compat_prefs = BackendPreferences::maximum_compatibility();

    println!("  Hardware-preferred settings:");
    println!(
        "    • Prefer hardware-backed: {}",
        hardware_prefs.prefer_hardware_backed
    );
    println!(
        "    • Prefer attestation: {}",
        hardware_prefs.prefer_attestation
    );

    println!("  Maximum-compatibility settings:");
    println!(
        "    • Prefer hardware-backed: {}",
        compat_prefs.prefer_hardware_backed
    );
    println!(
        "    • Prefer attestation: {}",
        compat_prefs.prefer_attestation
    );
    println!();

    // Example 5: Future Extensibility
    println!("● Example 5: Future Extensibility");
    println!("-----------------------------------");
    println!("The Universal Backend system is designed for easy extension:");
    println!("  • New backends: YubiKeyBackend, TpmBackend, HsmBackend");
    println!("  • New operations: KeyExchange, Verify, GenerateKeyPair");
    println!("  • New algorithms: Post-quantum crypto, custom curves");
    println!("  • Runtime capability detection and selection");
    println!();

    println!("● Demo complete! The Universal Backend system provides:");
    println!("   ● Capability-based operation dispatch");
    println!("   ● Runtime backend discovery and selection");
    println!("   ● Easy extensibility for new crypto operations");
    println!("   ● Preference-driven security policy enforcement");

    Ok(())
}
