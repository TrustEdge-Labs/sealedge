<!--
Copyright (c) 2025 TRUSTEDGE LABS LLC
MPL-2.0: https://mozilla.org/MPL/2.0/
Project: sealedge — Privacy and trust at the edge.
GitHub: https://github.com/TrustEdge-Labs/sealedge
-->

# Network Mode Examples

Secure client-server communication with mutual authentication and resilient connections.

## Network Mode Quick Start

**Authenticated server setup:**
```bash
# Start server with authentication required
./target/release/sealedge-server \
  --listen 127.0.0.1:8080 \
  --require-auth \
  --decrypt \
  --verbose
```

**Authenticated client connection:**
```bash
# Connect client with authentication
./target/release/sealedge-client \
  --server 127.0.0.1:8080 \
  --file file.txt \
  --enable-auth \
  --verbose
```

## Connection Resilience & Error Recovery

### Automatic Retry with Backoff

```bash
# Client with retry configuration (timeouts and delays are in SECONDS)
./target/release/sealedge-client \
  --server 192.168.1.100:8080 \
  --file large_file.bin \
  --retry-attempts 5 \
  --retry-delay 2 \
  --connect-timeout 30 \
  --verbose
```

### Connection Limits and Timeouts

```bash
# Server with per-connection limits and read timeout (SECONDS)
./target/release/sealedge-server \
  --listen 0.0.0.0:8080 \
  --connection-timeout 60 \
  --max-connection-bytes 1073741824 \
  --max-connection-chunks 10000 \
  --verbose \
  --decrypt
```

## Secure Authentication Examples

Sealedge network authentication is **Ed25519 mutual authentication** with an
**X25519 ECDH** handshake that derives the session encryption key. It is not
OpenSSL PEM mutual TLS — there are no `--cert`/`--key`/`--ca-cert` flags. Both
sides generate self-signed identity certificates automatically on first run.
See the [Authentication Guide](../authentication.md) for the full protocol.

### Mutual Authentication

```bash
# Server: require mutual authentication (generates ./sealedge-server.key/.cert)
./target/release/sealedge-server \
  --listen 0.0.0.0:8443 \
  --require-auth \
  --server-identity "Production Server" \
  --decrypt

# Client: enable authentication and pin the server's certificate
./target/release/sealedge-client \
  --server secure-server.example.com:8443 \
  --file sensitive_data.txt \
  --enable-auth \
  --client-identity "Mobile App v2.1" \
  --server-cert sealedge-server.cert
```

When authentication is enabled the session key is derived via ECDH, so no
`--key-hex` or shared secret is needed for the encrypted transfer.

## Legacy Network Examples (No Authentication)

### Basic Server-Client Communication

Without authentication there is no key exchange, so both sides must share the
same AES-256 key via `--key-hex`.

```bash
# Simple server (no authentication)
./target/release/sealedge-server \
  --listen 127.0.0.1:8080 \
  --decrypt \
  --key-hex "a1b2c3d4e5f6789a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4"

# Simple client (no authentication)
./target/release/sealedge-client \
  --server 127.0.0.1:8080 \
  --file document.txt \
  --key-hex "a1b2c3d4e5f6789a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4"
```

---


[← Back to Examples Index](README.md)

---

*This document is part of the Sealedge project documentation.*

**📖 Links:**
- **[Sealedge Home](https://github.com/TrustEdge-Labs/sealedge)** - Main repository
- **[Sealedge Labs](https://github.com/TrustEdge-Labs)** - Organization profile
- **[Documentation](https://github.com/TrustEdge-Labs/sealedge/tree/main/docs)** - Complete docs
- **[Issues](https://github.com/TrustEdge-Labs/sealedge/issues)** - Bug reports & features

**⚖️ Legal:**
- **Copyright**: © 2025 Sealedge Labs LLC
- **License**: Mozilla Public License 2.0 ([MPL-2.0](https://mozilla.org/MPL/2.0/))
- **Commercial**: [Enterprise licensing available](mailto:enterprise@trustedgelabs.com)
