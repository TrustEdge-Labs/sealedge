<!--
Copyright (c) 2025 TRUSTEDGE LABS LLC
MPL-2.0: https://mozilla.org/MPL/2.0/
Project: sealedge — Privacy and trust at the edge.
GitHub: https://github.com/TrustEdge-Labs/sealedge
-->

# Sealedge Core Authentication

> **For complete authentication documentation, see [docs/user/authentication.md](../../docs/user/authentication.md)**

This directory contains the core sealedge authentication implementation. For comprehensive setup guides, security considerations, and production deployment instructions, please refer to the user authentication guide.

## Quick Reference

- **Authentication Implementation**: [`src/auth.rs`](src/auth.rs) - Ed25519 mutual authentication system
- **Certificate Management**: Automatic Ed25519 certificate generation and validation
- **Session Management**: Cryptographically secure sessions with configurable timeouts

## Core Features

✔ **Mutual Authentication**: Ed25519-based client/server authentication  
✔ **Certificate Generation**: Automatic Ed25519 key pair and certificate creation  
✔ **Session Security**: Time-limited sessions with cryptographic session IDs  
✔ **Challenge-Response**: Replay protection with fresh random challenges  

## Documentation Structure

| Document | Purpose |
|----------|---------|
| **[docs/user/authentication.md](../../docs/user/authentication.md)** | **Complete authentication setup and usage guide** |
| **[../../SECURITY.md](../../SECURITY.md)** | Security policies and vulnerability reporting |

---

**For detailed authentication setup, troubleshooting, and production deployment, see [docs/user/authentication.md](../../docs/user/authentication.md).**
