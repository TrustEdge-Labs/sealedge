<!--
Copyright (c) 2025 TRUSTEDGE LABS LLC
MPL-2.0: https://mozilla.org/MPL/2.0/
Project: sealedge — Privacy and trust at the edge.
GitHub: https://github.com/TrustEdge-Labs/sealedge
-->


# Sealedge Security Policy

## Supported Versions

Sealedge is currently in active development. Security updates are provided for:

| Version | Status | Support Level |
| ------- | ------ | ------------- |
| v6.0.x | ✅ Current | Active security fixes |
| main branch | 🔄 Development | Active security fixes |
| v1.0–v5.x | ⏳ Legacy | Best effort |
| < v1.0 | ❌ Unsupported | No security support |

**Note**: As of v1.0, Sealedge follows semantic versioning. Security fixes will be backported to the latest release.

## Security Considerations

### Cryptographic Implementation

Sealedge implements privacy-preserving edge data encryption with the following security properties:

- **Encryption**: AES-256-GCM authenticated encryption (envelopes); XChaCha20-Poly1305 for `.seal` archive chunks
- **Key Derivation**: PBKDF2-HMAC-SHA256 (600k iterations + AES-256-GCM) for encrypted key files at rest (SEALEDGE-KEY-V2 format); HKDF-SHA256 for envelope key derivation (v1.8+)
- **Key Agreement**: X25519 ECDH for envelope key agreement; HPKE (RFC 9180 base mode; DHKEM(X25519,HKDF-SHA256)) wraps the per-archive content-encryption key to recipients
- **Digital Signatures**: Ed25519 for manifest integrity with domain separation
- **Hashing**: BLAKE3 for content verification
- **Nonce Management**: Deterministic 12-byte envelope nonces (8-byte HKDF-derived prefix + 3-byte big-endian chunk index + 1-byte last-chunk flag)
- **Asymmetric Encryption**: RSA OAEP-SHA256 in the optional hybrid encryption path only (v2.2+)

**Domain Separation**: Manifest signatures use cryptographic domain separation (`b"sealedge.manifest.v1"`) to prevent signature reuse across different contexts or protocols, ensuring signatures cannot be substituted from other systems.

### Known Limitations

1. **Side Channel Attacks**: No specific mitigations implemented
2. **Memory Safety**: Relies on Rust's memory safety guarantees
3. **External Audit**: No third-party security audit completed yet

### Current Security Status (v6.0)

**✅ Implemented Security Features:**
- AES-256-GCM authenticated encryption
- Ed25519 digital signatures for provenance with domain separation
- **X25519 ECDH Session Key Exchange**: Automated key derivation during auth handshake with BLAKE3 domain-separated KDF
- **Secret<T> Wrapper Type**: Zeroize-on-drop protection with redacted Debug for all sensitive fields (PINs, passphrases, JWT secrets, passwords)
- **Encrypted Key Files at Rest**: SEALEDGE-KEY-V2 format (Ed25519 signing key + independent X25519 key-agreement key) — PBKDF2-HMAC-SHA256 (600k iterations) + AES-256-GCM (v2.2+)
- **HKDF-SHA256 Envelope KDF**: Versioned envelope key derivation replacing legacy PBKDF2 usage (v1.8+)
- **X25519 ECDH + HPKE**: X25519 key agreement for envelopes; HPKE (RFC 9180) wraps the per-archive content-encryption key to recipients
- **RSA OAEP-SHA256**: Optional hybrid asymmetric encryption path replacing PKCS#1v1.5 padding (v2.2+)
- Connection timeouts and retry logic
- Graceful shutdown handling
- Domain separation prevents cross-context signature reuse
- **DoS Protection**: Resource bounds and limits enforcement
- **Bounds Checking**: Comprehensive validation of chunk sizes and stream limits
- **Length Integrity**: Cryptographic binding of chunk lengths via AAD
- **Mutual Authentication**: Ed25519-based client-server authentication with X25519 ECDH key exchange
- **CORS Hardening**: Restrictive CORS policies for verify-only and postgres platform builds
- **YubiKey Hardware Integration**: Hardware-backed signing and attestation via `yubikey` crate
- **Digital Receipt System**: Cryptographic ownership chains with attack resistance
- **Software Attestation**: Tamper-evident build provenance with Ed25519 signatures
- **45+ Dedicated Security Tests**: Covering timestamp validation, error handling, permissions, and cryptographic correctness (v2.3–v2.4)
- **Multi-Profile Archive Support**: cam.video, sensor, audio, and log archive profiles

**📋 Planned Security Features:**
- TPM and HSM key storage backends
- Key rotation and revocation mechanisms
- Enhanced rate limiting and monitoring
- Security audit logging
- Post-quantum cryptography readiness

### Security Assumptions

- Users manage encryption keys securely
- Network transport provides confidentiality (HTTPS/TLS) - being enhanced
- System entropy source is reliable for cryptographic operations
- Dependencies (aes-gcm, ed25519-dalek, etc.) are trustworthy

### DoS Protection & Resource Bounds

Sealedge implements comprehensive defense-in-depth against denial-of-service attacks:

**Stream-Level Limits:**
- Maximum chunk size: 128MB per chunk
- Maximum records per stream: 1,000,000 records
- Maximum total stream size: 10GB
- Early rejection of oversized requests

**Cryptographic Bounds:**
- Chunk length cryptographically bound via AAD
- Pre-decryption validation of expected sizes
- Post-decryption length verification
- Ciphertext size validation (≤ chunk_size + 16 bytes)

**Memory Protection:**
- Fixed-size buffers where possible
- Streaming processing without full data buffering
- Early termination on bounds violations
- Resource cleanup on validation failures

These protections prevent malicious actors from:
- Exhausting server memory with oversized chunks
- Creating arbitrarily large streams
- Manipulating chunk lengths to cause buffer overruns
- Bypassing validation through length field tampering

## Reporting a Vulnerability

We take security vulnerabilities seriously. Please follow responsible disclosure practices.

### 🔒 Private Security Issues

For **sensitive security vulnerabilities** that could be exploited:

1. **GitHub Security Advisories**: [Create Private Advisory](https://github.com/TrustEdge-Labs/sealedge/security/advisories/new)
2. **Direct Contact**: Email security concerns to security@[PLACEHOLDER] (planned)

**Do not** disclose sensitive vulnerabilities publicly until we've had time to address them.

### 📋 General Security Issues

For **general security improvements** or **questions about security practices**:

1. **Security Issue Template**: [Create Security Issue](./.github/ISSUE_TEMPLATE/security.yml)
2. **GitHub Issues**: Use for non-sensitive security discussions

### 🎯 What to Include

When reporting security issues, please include:

- **Description**: Clear description of the vulnerability
- **Impact**: Potential security impact and attack scenarios
- **Reproduction**: Steps to reproduce the issue
- **Environment**: Sealedge version, OS, Rust version
- **Mitigation**: Suggested fixes or workarounds (if any)

### ⏱️ Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 1 week
- **Progress Updates**: Weekly for active issues
- **Resolution**: Timeline depends on severity and complexity

### 🏆 Recognition

We appreciate security researchers who help improve Sealedge security:

- **Security Hall of Fame**: Recognition for responsible disclosure
- **Attribution**: Credit in release notes (with permission)
- **Coordination**: Work together on disclosure timeline

### Severity Classification

| Severity | Examples | Response Time |
| -------- | -------- | ------------- |
| **Critical** | Key recovery, authentication bypass | 24-48 hours |
| **High** | Encryption weakness, data corruption | 3-7 days |
| **Medium** | Information disclosure, DoS | 1-2 weeks |
| **Low** | Minor information leaks | 2-4 weeks |

## Security Best Practices

### For Users

1. **Key Management**:
   - Use strong, randomly generated keys
   - Rotate keys regularly
   - Store keys securely (hardware tokens recommended)
   - Never share keys over insecure channels

2. **Network Security**:
   - Always use TLS/HTTPS for network operations
   - Verify server certificates
   - Consider VPN or other transport security

3. **System Security**:
   - Keep Sealedge updated
   - Use on systems with full disk encryption
   - Monitor for unusual network activity
   - Regular security audits of infrastructure

### For Developers

1. **Code Review**: All security-related changes require review
2. **Testing**: Security features must have comprehensive tests
3. **Dependencies**: Regular updates and vulnerability scanning
4. **Documentation**: Security implications must be documented

## Security Audit Status

| Component | Last Audit | Status | Notes |
| --------- | ---------- | ------ | ----- |
| Cryptographic Implementation | March 2026 | ✅ Reviewed | v2.4 Security Review Remediation completed |
| Key Management | March 2026 | ✅ Reviewed | Encrypted key files, HKDF-SHA256 verified |
| Network Protocol | March 2026 | ✅ Reviewed | Transport timeout security documented |
| File Format | March 2026 | ✅ Reviewed | Base64, timestamp, permissions hardened |

**Previous Audit**: v2.4 Security Review Remediation completed March 2026 — full workspace test suite across 9 workspace crates, including 45+ dedicated security tests

## Compliance and Standards

Sealedge aims to align with:

- **NIST Cryptographic Standards**: AES, SHA-3 family (BLAKE3)
- **RFC Standards**: Ed25519 (RFC 8032), relevant IETF standards
- **Industry Best Practices**: OWASP guidelines, secure coding practices

## Contact Information

**Security Team**: TrustEdge Labs LLC Security Team
- **Lead**: TrustEdge Labs LLC (security@trustedgelabs.com)
- **GPG Key**: [To be provided] (for encrypted communications)
- **Security Advisory**: Subscribe to security notifications via GitHub Security Advisories

---

**Document Version**: 4.0
**Last Updated**: March 2026
**Next Review**: June 2026

---

*This document is part of the Sealedge project documentation.*

*Copyright (c) 2025 TRUSTEDGE LABS LLC. Licensed under the Mozilla Public License 2.0 (MPL-2.0).*
*See LICENSE file for full license terms.*

*For technical details, see [docs/technical/threat-model.md](docs/technical/threat-model.md), [docs/technical/protocol.md](docs/technical/protocol.md), and [docs/technical/format.md](docs/technical/format.md).*
*For contribution guidelines, see [README.md](README.md).*
