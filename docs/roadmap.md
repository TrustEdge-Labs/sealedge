<!--
Copyright (c) 2025 TRUSTEDGE LABS LLC
MPL-2.0: https://mozilla.org/MPL/2.0/
Project: sealedge — Privacy and trust at the edge.
GitHub: https://github.com/TrustEdge-Labs/sealedge
-->

# Sealedge Roadmap

> **Vision:** Trusted data from the edge. Capture, encrypt, and transfer data with cryptographic provenance and privacy-preserving architecture.

---

## Current Status (v2.6)

Sealedge v2.6 is a **security-hardened, production-ready platform** with:

- ✅ **Data-Agnostic Archives**: .seal format with generic, cam.video, sensor, audio, and log profiles
- ✅ **Full Data Lifecycle**: `seal keygen` → `seal wrap` → `seal verify` → `seal unwrap`
- ✅ **Strong Cryptography**: AES-256-GCM, Ed25519, ECDSA P-256, BLAKE3, HKDF-SHA256, RSA OAEP-SHA256
- ✅ **Encrypted Keys at Rest**: SEALEDGE-KEY-V2 format (Ed25519 signing + X25519 key-agreement; PBKDF2-SHA256 600k + AES-256-GCM), 0600 permissions, zeroize-on-drop
- ✅ **YubiKey Hardware Signing**: PIV ECDSA P-256 via `seal wrap --backend yubikey`
- ✅ **Platform Service**: Axum HTTP verification with PostgreSQL backend, 2 MB body limit, per-IP rate limiting, configurable CORS
- ✅ **Docker Deployment**: One-command `docker compose up` with auto-migration, optional TLS termination
- ✅ **SvelteKit Dashboard**: Verification status and receipt viewing (no client-side credentials)
- ✅ **Browser Verification**: WASM-based .seal archive verification with working decrypt
- ✅ **QUIC TLS Verified**: Real signature verification in HardwareBackedVerifier (MITM-proof)
- ✅ **Security Validated**: comprehensive test suite across 9 workspace crates, 16 milestones shipped (v1.0-v2.6)

---

## Future Directions

### Enhanced Hardware Support

**TPM 2.0 Integration**
- Hardware-backed key storage and attestation
- Platform integrity verification
- Enterprise security compliance

**HSM Support**
- PKCS#11 enterprise HSM integration
- Hardware security module backends
- High-availability key management

### Advanced Cryptography

**Post-Quantum Cryptography**
- Algorithm agility framework ready for PQC algorithms
- Hybrid classical/post-quantum signatures
- Future-proof cryptographic transitions

**Zero-Knowledge Proofs**
- Receipt verification without revealing amounts
- Privacy-preserving audit trails
- Selective disclosure mechanisms

### Ecosystem Integration

**IoT Device Support**
- Embedded device SDKs
- Lightweight protocol variants
- Edge device attestation

**Cloud Integration**
- AWS/Azure/GCP backend adapters
- Serverless function support
- Container orchestration

### Developer Experience

**Language Bindings**
- Python SDK with native performance
- JavaScript/TypeScript bindings
- Go and C++ interfaces

**Tooling & Monitoring**
- Visual receipt chain explorer
- Cryptographic audit tools
- Performance monitoring dashboards

---

## Contributing

Sealedge welcomes contributions in these areas:

- **Hardware Backend Development**: New crypto backend implementations
- **Protocol Extensions**: Enhanced network protocols and formats
- **Security Research**: Cryptographic analysis and testing
- **Documentation**: Guides, tutorials, and API documentation
- **Testing**: Security test scenarios and fuzzing

For contribution guidelines, see [CONTRIBUTING.md](../CONTRIBUTING.md).

---

## Community & Support

- **GitHub Issues**: Bug reports and feature requests
- **Discussions**: Architecture discussions and Q&A
- **Security**: Responsible disclosure via [SECURITY.md](../SECURITY.md)
- **Commercial**: Enterprise support at [enterprise@trustedgelabs.com](mailto:enterprise@trustedgelabs.com)

---

*This roadmap reflects current development priorities and may evolve based on community feedback and emerging requirements.*