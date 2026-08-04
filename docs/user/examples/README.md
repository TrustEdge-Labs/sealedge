<!--
Copyright (c) 2025 TRUSTEDGE LABS LLC
MPL-2.0: https://mozilla.org/MPL/2.0/
Project: sealedge — Privacy and trust at the edge.
GitHub: https://github.com/TrustEdge-Labs/sealedge
-->

# Sealedge Examples

Real-world examples and use cases for Sealedge privacy-preserving edge computing.

## 🚀 Getting Started

**New to Sealedge? Start here:**

| Guide | Description | Best For |
|-------|-------------|----------|
| **[Installation](installation.md)** | Complete setup with all features | First-time setup |
| **[Getting Started](getting-started.md)** | Basic encryption and key usage | Learning fundamentals |

## 📚 Core Features

### File & Data Processing
| Guide | Description | Use Cases |
|-------|-------------|-----------|
| **[.seal Archives](trst-archives.md)** | Secure archival with digital signatures | Evidence collection, security cameras |
| **[Audio Processing](audio.md)** | Live audio capture and processing | Voice notes, interviews, streaming |

### Network & Authentication
| Guide | Description | Use Cases |
|-------|-------------|-----------|
| **[Network Operations](network.md)** | Client-server communication | Secure file transfer, distributed systems |
| **[Software Attestation](attestation.md)** | Cryptographic software verification | Supply chain security, CI/CD |

### Advanced Integration
| Guide | Description | Use Cases |
|-------|-------------|-----------|
| **[Backend Systems](backends.md)** | Hardware and software backends | YubiKey, HSM, keyring integration |
| **[Real-World Integration](integration.md)** | Production deployment patterns | Docker, CI/CD, monitoring |
| **[Development Tools](development.md)** | Developer workflows and debugging | Testing, releases, performance |

## 🎯 Quick Examples by Use Case

### **Security & Compliance**
- [Security Camera Evidence Chain](trst-archives.md#security-camera-archive-workflow)
- [Legal Document Storage](integration.md#legal-evidence-chain)
- [Healthcare Data Protection](integration.md#healthcare-data-protection)

### **Development & CI/CD**
- [Automated Software Attestation](attestation.md#cicd-integration-example)
- [Container Integration](integration.md#docker-container-integration)
- [Release Management](development.md#release-management)

### **Audio & Media**
- [Professional Audio Recording](audio.md#high-quality-recording-session)
- [Voice Note Encryption](audio.md#voice-memo-recording)
- [Cross-Platform Audio Workflows](audio.md#cross-platform-audio-workflows)

### **Network & Distributed Systems**
- [Secure Client-Server Setup](network.md#network-mode-quick-start)
- [Mutual Authentication](network.md#mutual-authentication)
- [Connection Resilience](network.md#automatic-retry-with-backoff)

## 🛠️ By Technical Level

### **Beginner** (New Users)
1. [Installation Guide](installation.md) - Set up Sealedge
2. [Basic File Encryption](getting-started.md#simple-file-encryption) - First encryption
3. [Format-Aware Operations](getting-started.md#format-aware-operations) - Inspect data

### **Intermediate** (Regular Users)
1. [.seal Archive Creation](trst-archives.md#basic-archive-creation-and-verification) - Secure archival
2. [Network Client-Server](network.md#network-mode-quick-start) - Distributed encryption
3. [Audio Capture](audio.md#live-audio-capture) - Media processing

### **Advanced** (Developers & Admins)
1. [YubiKey Hardware Integration](backends.md#yubikey-examples-library-based) - Hardware security
2. [Software Attestation](attestation.md#basic-attestation-workflow) - Supply chain security
3. [CI/CD Integration](integration.md#cicd-pipeline-integration) - Production workflows

## 📋 Reference Information

### **Command Reference**
- **Core encryption**: `sealedge --help`
- **Network server**: `sealedge-server --help`
- **Network client**: `sealedge-client --help`
- **Archive tool**: `seal --help`

### **Related Documentation**
- **[CLI Reference](../cli.md)** - Complete command documentation
- **[Technical Specifications](../../technical/)** - Architecture and protocols
- **[Troubleshooting](../troubleshooting.md)** - Common issues and solutions

### **Quick Links**
- **Installation**: See [installation.md](installation.md) for all platforms
- **First Steps**: Start with [getting-started.md](getting-started.md)
- **Advanced Features**: Explore [backends.md](backends.md) and [integration.md](integration.md)

---

*For additional help, see the [main documentation index](../../README.md) or [CLI reference](../cli.md).*

---

**📖 Links:**
- **[Sealedge Home](https://github.com/TrustEdge-Labs/sealedge)** - Main repository
- **[Documentation](../../README.md)** - Complete docs index
- **[CLI Reference](../cli.md)** - Command reference

**⚖️ Legal:**
- **Copyright**: © 2025 Sealedge Labs LLC
- **License**: Mozilla Public License 2.0 ([MPL-2.0](https://mozilla.org/MPL/2.0/))
- **Commercial**: [Enterprise licensing available](mailto:enterprise@trustedgelabs.com)