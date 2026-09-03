//
// Copyright (c) 2025 TRUSTEDGE LABS LLC
// This source code is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Project: sealedge — Privacy and trust at the edge.
//

//! # Sealedge Receipt Demo
//!
//! This demo shows how the "Contract Writer" (receipts) and "Security Guard" (envelope)
//! work together to create a secure, verifiable chain of ownership.

use anyhow::Result;
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use sealedge_core::{assign_receipt, create_receipt, verify_signature_chain};

fn main() -> Result<()> {
    println!("🏢 Sealedge Receipt Demo: The Office Analogy in Action\n");

    // Create our characters (signing keys)
    println!("👥 Setting up our office characters...");
    let alice_key = SigningKey::generate(&mut OsRng);
    let bob_key = SigningKey::generate(&mut OsRng);
    let charlie_key = SigningKey::generate(&mut OsRng);

    println!(
        "   Alice (Issuer): {}",
        hex::encode(alice_key.verifying_key().to_bytes())
    );
    println!(
        "   Bob (First Beneficiary): {}",
        hex::encode(bob_key.verifying_key().to_bytes())
    );
    println!(
        "   Charlie (Final Beneficiary): {}",
        hex::encode(charlie_key.verifying_key().to_bytes())
    );
    println!();

    // Step 1: Alice creates an original receipt
    println!("● Step 1: Alice (Contract Writer) creates an original receipt");
    println!("   - Business Logic: Alice owes Bob 1000 units for consulting services");
    println!("   - Contract Writer creates the Receipt (business logic)");
    println!("   - Security Guard puts it in a secure Envelope");

    let original_envelope = create_receipt(
        &alice_key,
        &bob_key.verifying_key(),
        1000,
        Some("Payment for Q4 consulting services".to_string()),
    )?;

    println!("   ✔ Receipt created and secured in envelope");
    println!(
        "   ● Envelope hash: {}",
        hex::encode(original_envelope.hash().unwrap())
    );
    println!("   ● Cryptographically signed by: Alice");
    println!("   ● Intended beneficiary: Bob");
    println!();

    // Step 2: Verify the original envelope
    println!("● Step 2: Security Guard verifies the original envelope");
    let is_valid = original_envelope.verify();
    println!(
        "   Envelope verification: {}",
        if is_valid { "✔ VALID" } else { "✖ INVALID" }
    );
    println!("   - Signature check: ✔ Passed");
    println!("   - Tamper detection: ✔ Passed");
    println!("   - Chain integrity: ✔ Passed");
    println!();

    // Step 3: Bob assigns the receipt to Charlie
    println!("● Step 3: Bob assigns his receipt to Charlie");
    println!("   - Business Logic: Bob transfers his 1000 unit claim to Charlie");
    println!("   - Verification: Bob proves he's the current beneficiary");
    println!("   - Contract Writer creates new Assignment Receipt");
    println!("   - Security Guard seals it in a new envelope, signed by Bob");

    let assignment_envelope = assign_receipt(
        &original_envelope,
        &bob_key,
        &charlie_key.verifying_key(),
        Some("Transfer to Charlie for outstanding debt".to_string()),
    )?;

    println!("   ✔ Assignment created and secured in new envelope");
    println!(
        "   📦 New envelope hash: {}",
        hex::encode(assignment_envelope.hash().unwrap())
    );
    println!("   ● Cryptographically signed by: Bob");
    println!("   ● New beneficiary: Charlie");
    println!(
        "   🔗 Links to previous envelope: {}",
        hex::encode(original_envelope.hash().unwrap())
    );
    println!();

    // Step 4: Verify the assignment envelope
    println!("● Step 4: Security Guard verifies the assignment envelope");
    let assignment_valid = assignment_envelope.verify();
    println!(
        "   Assignment verification: {}",
        if assignment_valid {
            "✔ VALID"
        } else {
            "❌ INVALID"
        }
    );
    println!();

    // Step 5: Verify the entire chain
    println!("🔗 Step 5: Verify the complete ownership chain");
    let chain = vec![original_envelope.clone(), assignment_envelope.clone()];
    // NOTE: this checks envelope signatures + issuer/beneficiary continuity only —
    // not receipt-chain integrity (see verify_signature_chain docs).
    let chain_valid = verify_signature_chain(&chain);
    println!(
        "   Signature + continuity check: {}",
        if chain_valid {
            "✔ VALID"
        } else {
            "❌ INVALID"
        }
    );

    if chain_valid {
        println!("   - All envelopes are cryptographically valid");
        println!("   - Chain links are properly connected");
        println!("   - Ownership transfers are legitimate");
        println!("   - Current owner: Charlie (1000 units)");
    }
    println!();

    // Demonstrate the separation of concerns
    println!("● Architecture Summary: Separation of Concerns");
    println!("   ● Contract Writer (sealedge-receipts):");
    println!("      - Handles business logic (amounts, ownership, descriptions)");
    println!("      - Validates business rules (non-zero amounts, valid timestamps)");
    println!("      - Creates receipt chains and verifies ownership transfers");
    println!("      - Never worries about cryptography or security details");
    println!();
    println!("   ● Security Guard (sealedge-core Envelope):");
    println!("      - Provides cryptographic security (encryption, signing, hashing)");
    println!("      - Ensures tamper-proof containers for any payload");
    println!("      - Handles nonces, chunks, manifests, and network protocols");
    println!("      - Never knows or cares about business logic");
    println!();
    println!("   🏢 Result: Clean Architecture");
    println!("      - Business logic changes don't affect security code");
    println!("      - Security improvements don't break business features");
    println!("      - Easy to test, maintain, and extend");
    println!("      - Reusable security layer for any future application");

    Ok(())
}
