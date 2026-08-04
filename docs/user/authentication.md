<!--
Copyright (c) 2025 TRUSTEDGE LABS LLC
MPL-2.0: https://mozilla.org/MPL/2.0/
Project: sealedge — Privacy and trust at the edge.
GitHub: https://github.com/TrustEdge-Labs/sealedge
-->

# Sealedge Authentication Guide

Complete guide to Sealedge's mutual authentication system for secure network operations.

## Table of Contents
- [Overview](#overview)
- [Quick Start](#quick-start)
- [Authentication Architecture](#authentication-architecture)
- [Certificate Management](#certificate-management)
- [Session Management](#session-management)
- [Configuration Reference](#configuration-reference)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)
- [Production Deployment](#production-deployment)

---

## Overview

Sealedge implements **mutual authentication** using Ed25519 digital signatures with **automated X25519 ECDH key exchange** to establish secure, encrypted sessions between clients and servers. This system ensures:

- **Server Authentication**: Clients verify they're connecting to legitimate Sealedge servers
- **Client Authorization**: Servers validate client identity and authorize access
- **Session Encryption**: X25519 ECDH derives a shared encryption key during the handshake — no out-of-band key sharing needed
- **Session Security**: Cryptographically secure session IDs prevent unauthorized access
- **Automatic Certificate Management**: Ed25519 key pairs and certificates generated automatically

### Security Benefits

✅ **Mutual Trust**: Both client and server authenticate each other
✅ **Automated Key Exchange**: X25519 ECDH derives session encryption keys from the auth handshake
✅ **Identity Verification**: Ed25519 certificates provide cryptographic proof of identity
✅ **Session Isolation**: Each connection gets unique, time-limited session with unique encryption key
✅ **Replay Protection**: Challenge-response protocol prevents replay attacks
✅ **Channel Binding**: Both public keys mixed into KDF prevent unknown-key-share attacks
✅ **Forward Security**: Sessions expire automatically after a fixed 30-minute timeout

[↑ Back to top](#table-of-contents)

---

## Quick Start

### Enable Authentication

**Server:**
```bash
./target/release/sealedge-server \
  --listen 127.0.0.1:8080 \
  --require-auth \
  --server-identity "My Secure Server" \
  --decrypt
```

**Client:**
```bash
./target/release/sealedge-client \
  --server 127.0.0.1:8080 \
  --file my_file.txt \
  --enable-auth \
  --client-identity "My Client App" \
  --server-cert sealedge-server.cert
```

> With authentication enabled the session key is derived via X25519 ECDH during
> the handshake, so no `--key-hex`, `--use-keyring`, or shared salt is needed for
> the encrypted transfer.

### First Run Experience

1. **Server startup**: Generates Ed25519 signing key (saved to disk)
2. **Server certificate**: Creates identity certificate with your specified identity
3. **Client connection**: Generates client identity certificate on first use
4. **Mutual handshake**: Challenge-response authentication between both parties
5. **Key exchange**: X25519 ECDH derives a shared session encryption key (both sides compute independently)
6. **Secure session**: Data transfer uses the ECDH-derived key — no `--key-hex` or `--use-keyring` needed

[↑ Back to top](#table-of-contents)

---

## Authentication Architecture

### How Sealedge Secure Session Works

The following diagram shows the complete security flow from initial connection through authenticated data transfer:

```mermaid
sequenceDiagram
    participant C as Client App
    participant CC as Client Certificate
    participant S as Server
    participant SC as Server Certificate
    participant SM as Session Manager
    
    Note over C,SM: Phase 1: Certificate Preparation
    
    C->>CC: Check for client certificate
    alt No client certificate exists
        C->>CC: Generate Ed25519 key pair
        C->>CC: Create self-signed certificate<br/>Identity: "Client App v1.0"
        CC-->>C: Client certificate ready
    end
    
    S->>SC: Check for server certificate
    alt No server certificate exists
        S->>SC: Generate Ed25519 key pair
        S->>SC: Create self-signed certificate<br/>Identity: "Production Server"
        SC-->>S: Server certificate ready
    end
    
    Note over C,SM: Phase 2: Connection & Authentication
    
    C->>S: TCP Connection Request
    S-->>C: Connection Established
    
    C->>S: Authentication Request<br/>{"type": "auth_request"}
    
    S->>S: Generate random challenge (32 bytes)
    S->>S: Sign challenge with server private key
    S->>C: Server Challenge + Server Certificate<br/>{"challenge": "...", "server_cert": {...}}
    
    C->>C: Verify server certificate signature
    C->>C: Extract server public key
    C->>C: Verify challenge signature
    
    alt Server authentication fails
        C->>C: Reject connection
        C-->>S: Authentication Failed
    else Server authentication succeeds
        C->>C: Sign server challenge with client key
        C->>C: Generate client challenge (32 bytes)
        C->>C: Sign client challenge with client key
        C->>S: Client Response + Client Certificate<br/>{"challenge_response": "...", "client_challenge": "...", "client_cert": {...}}
    end
    
    S->>S: Verify client certificate signature
    S->>S: Extract client public key
    S->>S: Verify challenge response signature
    
    alt Client authentication fails
        S->>S: Reject connection
        S-->>C: Authentication Failed
    else Client authentication succeeds
        S->>S: Sign client challenge with server key
        S->>SM: Create new session
        SM->>SM: Generate cryptographic session ID (64-bit)
        SM->>SM: Set session timeout (1800s)
        SM-->>S: Session created
        S->>C: Session Established<br/>{"session_id": "0x...", "challenge_response": "...", "timeout": 1800}
    end
    
    C->>C: Verify server's client challenge response
    C->>C: Store session ID
    
    Note over C,SM: Phase 3: Secure Data Transfer
    
    loop For each data chunk
        C->>C: Encrypt data with AES-256-GCM
        C->>C: Create signed manifest
        C->>S: Send encrypted chunk<br/>Session ID: 0x...
        S->>SM: Validate session ID
        
        alt Session invalid/expired
            SM-->>S: Session invalid
            S-->>C: Session Expired - Reconnect
        else Session valid
            SM-->>S: Session valid
            S->>S: Decrypt and process chunk
            S-->>C: Chunk received successfully
        end
    end
    
    Note over C,SM: Phase 4: Session Cleanup
    
    alt Normal completion
        C->>S: Transfer complete
        S->>SM: Mark session complete
    else Timeout or error
        SM->>SM: Session timeout (1800s)
        SM->>SM: Clean up expired session
    end
```

### Security Properties

This authentication flow provides:

1. **🔐 Mutual Authentication**: Both client and server prove their identities using Ed25519 signatures
2. **🔑 Automated Key Exchange**: X25519 ECDH derives a shared session encryption key from existing Ed25519 keys — no wire-format change needed
3. **🛡️ Identity Verification**: Certificates cryptographically bind identity strings to public keys
4. **🔄 Challenge-Response**: Prevents replay attacks with fresh random challenges mixed into the KDF
5. **⏱️ Session Security**: Time-limited sessions with cryptographically secure IDs
6. **🎯 Forward Security**: Each session uses unique identifiers and unique encryption keys, limiting exposure
7. **🔗 Channel Binding**: Both public keys (deterministically ordered) are mixed into the BLAKE3 KDF, preventing unknown-key-share attacks

### Implementation References

| Component | Source Code | Purpose |
|-----------|-------------|---------|
| **Authentication Flow** | [`src/auth.rs:server_authenticate()`](../../crates/core/src/auth.rs) | Server-side authentication implementation |
| **Challenge Generation** | [`src/auth.rs:client_authenticate()`](../../crates/core/src/auth.rs) | Client-side authentication, returns `ClientAuthResult` with session key |
| **ECDH Key Derivation** | [`src/auth.rs:derive_session_key()`](../../crates/core/src/auth.rs) | X25519 ECDH + BLAKE3 KDF for session encryption key |
| **Certificate Management** | [`src/auth.rs:ClientCertificate`](../../crates/core/src/auth.rs) | Certificate creation and validation |
| **Session Management** | [`src/auth.rs:SessionManager`](../../crates/core/src/auth.rs) | Session lifecycle and validation |
| **Integration Tests** | [`tests/auth_integration.rs`](../../crates/core/tests/auth_integration.rs) | Authentication + ECDH key agreement tests |

### How ECDH Session Key Derivation Works

When authentication is enabled, both sides independently derive the same session encryption key:

1. **Ed25519 to X25519 Conversion**: Each party converts their Ed25519 signing key to an X25519 key using `SigningKey::to_scalar_bytes()` and `VerifyingKey::to_montgomery()`
2. **Diffie-Hellman**: Standard X25519 DH produces a shared secret (DH commutativity: `client_secret * server_pub == server_secret * client_pub`)
3. **KDF**: BLAKE3 `derive_key` with domain `"SEALEDGE_SESSION_KEY_V1"` mixes the shared secret, challenge bytes, and both public keys (deterministically ordered)
4. **Result**: Both sides produce an identical 32-byte AES-256 session key without transmitting any key material

The client uses this key automatically for encryption; the server stores it in the `ProcessingSession` for decryption. No `--key-hex` flag is needed when auth is active.

### Certificate Format

Sealedge certificates contain:
- **Ed25519 Public Key**: For signature verification (32 bytes)
- **Identity String**: Human-readable client/server identity  
- **Timestamp**: Certificate creation time
- **Signature**: Self-signed with corresponding private key (64 bytes)

[↑ Back to top](#table-of-contents)

---

## Certificate Management

### Server Credential Storage

**Where Server Identity Lives:**

```bash
# Default server certificate location (current working directory)
./sealedge-server.key    # Ed25519 private key (32 bytes + metadata)
./sealedge-server.cert   # Self-signed certificate with identity

# Custom server certificate path
./target/release/sealedge-server \
  --require-auth \
  --server-key /opt/sealedge/server-production.key \
  --server-identity "Production Sealedge Server v1.0"

# Creates:
/opt/sealedge/server-production.key   # Private key file
/opt/sealedge/server-production.cert  # Certificate file
```

**Server Certificate Generation Process:**

1. **Check for Existing Certificate**: Server looks for `--server-key` path or `./sealedge-server.key`
2. **Generate Ed25519 Key Pair**: If missing, creates new 256-bit private key
3. **Create Self-Signed Certificate**: Binds server identity to public key
4. **Write to Filesystem**: Saves both private key and certificate files
5. **Set File Permissions**: Restricts private key access (recommended: `chmod 600`)

### Client Credential Storage

**Where Client Certificates Get Stored:**

```bash
# Default client certificate location (current working directory)
./sealedge-client.key    # Ed25519 private key (32 bytes + metadata)
./sealedge-client.cert   # Self-signed certificate with identity

# Custom client certificate path
./target/release/sealedge-client \
  --enable-auth \
  --client-cert ~/.config/sealedge/mobile-app.cert \
  --client-identity "Executive Mobile App v2.1"

# Creates (generated on first use if missing):
~/.config/sealedge/mobile-app.cert  # Certificate file (identity + public key)
```

**Client Certificate Generation Process:**

1. **Check for Existing Certificate**: Client looks for `--client-cert` path or `./sealedge-client.cert`
2. **Generate Ed25519 Key Pair**: If missing, creates new 256-bit private key
3. **Create Self-Signed Certificate**: Binds client identity to public key
4. **Write to Filesystem**: Saves both private key and certificate files
5. **Secure Storage**: Client apps should store keys in secure locations

### Certificate File Format

**Private Key File (`.key`):**
```
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIFOr7...Ed25519PrivateKeyData...
-----END PRIVATE KEY-----
```

**Certificate File (`.cert`):**
```json
{
  "identity": "Production Sealedge Server v1.0",
  "public_key": "AGd8f2V1...",
  "signature": "BDGd9f8A...",
  "created": "2025-08-30T10:15:30Z"
}
```

### Storage Security Best Practices

**File Permissions:**
```bash
# Secure server private key (root/service account only)
chmod 600 /opt/sealedge/server-production.key
chown sealedge-service:sealedge-service /opt/sealedge/server-production.key

# Secure client private key (user only)  
chmod 600 ~/.config/sealedge/mobile-app.key

# Certificate files can be world-readable (contain only public data)
chmod 644 /opt/sealedge/server-production.cert
chmod 644 ~/.config/sealedge/mobile-app.cert
```

**Directory Structure Examples:**

```
# Production Server Layout
/opt/sealedge/
├── server-production.key     # 600 sealedge-service:sealedge-service  
├── server-production.cert    # 644 sealedge-service:sealedge-service
├── logs/
└── config/

# Client Application Layout  
~/.config/sealedge/
├── mobile-app.key           # 600 user:user
├── mobile-app.cert          # 644 user:user
├── server-certificates/     # Trusted server cert store (optional)
└── config.json

# Development Environment
./sealedge-core/
├── sealedge-server.key     # 600 developer:developer
├── sealedge-server.cert    # 644 developer:developer  
├── sealedge-client.key     # 600 developer:developer
├── sealedge-client.cert    # 644 developer:developer
└── target/release/
```

### Manual Certificate Paths

```bash
# Specify custom certificate locations
./target/release/sealedge-server \
  --require-auth \
  --server-identity "Production Sealedge" \
  --server-key ./certificates/production_server.key

./target/release/sealedge-client \
  --enable-auth \
  --client-identity "Mobile App v2.1" \
  --client-cert ./certificates/mobile_client.cert
```

### Certificate Security

- **Ed25519 Keys**: 256-bit private keys with 32-byte public keys
- **Self-Signed**: Each certificate self-signed with corresponding private key
- **Identity Binding**: Human-readable identity cryptographically bound to key
- **File Protection**: Private keys should be protected with appropriate file permissions
- **No Certificate Authority**: Eliminates single point of failure and complex PKI infrastructure
- **Automatic Rotation**: Generate new certificates by deleting existing files and restarting

[↑ Back to top](#table-of-contents)

---

## Session Management

### Session Lifecycle

1. **Authentication**: Mutual challenge-response creates session
2. **Key Derivation**: X25519 ECDH derives a shared 256-bit session encryption key
3. **Session ID**: 128-bit cryptographically random session identifier
4. **Timeout**: Session timeout of 30 minutes (1800 seconds)
5. **Validation**: All requests validated against active session
6. **Cleanup**: Expired sessions automatically removed; key material zeroized

### Session Duration

The session timeout is a fixed 30 minutes (1800 seconds), defined by the
`SESSION_TIMEOUT` constant in `crates/core/src/auth.rs`. It is not configurable
via a CLI flag. When a session expires, the client simply re-authenticates and a
fresh ECDH session key is derived.

```bash
# Authenticated server (sessions expire after 1800s automatically)
./target/release/sealedge-server \
  --listen 127.0.0.1:8080 \
  --require-auth \
  --server-identity "Standard Server"
```

### Session Security

- **Cryptographic Randomness**: Session IDs generated with secure random number generator
- **Time-Limited**: All sessions expire automatically 
- **Single Use**: Each session tied to specific client connection
- **Memory Protection**: Session data cleared on expiration

[↑ Back to top](#table-of-contents)

---

## Configuration Reference

### Authentication CLI Options

#### Server Options
| Option | Required | Description | Example |
|--------|----------|-------------|---------|
| `--require-auth` | Yes | Enable mutual authentication | `--require-auth` |
| `--server-identity` | Recommended | Server identity for certificates | `--server-identity "Production Server"` |
| `--server-key` | Optional | Path to server signing key | `--server-key ./server.key` |

The session timeout is fixed at 1800 seconds and is not configurable via a flag.

#### Client Options  
| Option | Required | Description | Example |
|--------|----------|-------------|---------|
| `--enable-auth` | Yes | Enable authentication + server cert verification | `--enable-auth` |
| `--client-identity` | Recommended | Client identity for certificates | `--client-identity "Mobile App v1.0"` |
| `--client-cert` | Optional | Path to client certificate file | `--client-cert ./client.cert` |
| `--server-cert` | Optional | Path to trusted server certificate | `--server-cert ./server.cert` |

### Configuration Examples

#### High-Security Production
```bash
# Production server with tight security
./target/release/sealedge-server \
  --listen 0.0.0.0:8443 \
  --require-auth \
  --server-identity "Sealedge Production v2.1" \
  --server-key /etc/sealedge/server.key \
  --decrypt \
  --use-keyring \
  --output-dir /secure/uploads
```

#### Development Environment
```bash
# Development server
./target/release/sealedge-server \
  --listen 127.0.0.1:8080 \
  --require-auth \
  --server-identity "Development Server" \
  --decrypt
```

[↑ Back to top](#table-of-contents)

---

## Security Considerations

### Threat Model

**Protects Against:**
- ✅ Unauthorized server access (client authentication)
- ✅ Man-in-the-middle attacks (mutual authentication)
- ✅ Session hijacking (cryptographic session IDs)
- ✅ Replay attacks (challenge-response protocol)
- ✅ Identity spoofing (Ed25519 signatures)

**Does NOT Protect Against:**
- ❌ Compromised client/server private keys
- ❌ Network traffic analysis (ECDH-derived keys encrypt data but not metadata; use TLS/QUIC for transport encryption)
- ❌ Side-channel attacks on cryptographic operations
- ❌ Social engineering or credential theft

### Best Practices

#### Certificate Management
- **Rotate Keys Regularly**: Generate new Ed25519 keys periodically
- **Secure Storage**: Protect private keys with appropriate file permissions (`600` or `400`)
- **Backup Strategy**: Securely backup signing keys for disaster recovery
- **Access Control**: Limit access to certificate files and directories

#### Network Security
- **TLS Transport**: Use TLS/SSL for transport-layer encryption in addition to authentication
- **Network Isolation**: Deploy servers in isolated network segments when possible
- **Monitoring**: Log authentication events for security monitoring
- **Firewall Rules**: Restrict network access to authenticated endpoints

#### Session Management
- **Fixed Timeouts**: Sessions expire after a fixed 30-minute timeout; re-authenticate to continue
- **Session Monitoring**: Monitor active sessions and detect anomalies
- **Clean Shutdown**: Ensure proper session cleanup on server shutdown
- **Resource Limits**: Implement connection limits to prevent resource exhaustion

### Compliance Considerations

- **FIPS 140-2**: Ed25519 may not be FIPS-approved in all contexts
- **Industry Standards**: Verify authentication meets your industry requirements
- **Audit Trails**: Implement comprehensive logging for compliance auditing
- **Key Management**: Follow organizational key management policies

[↑ Back to top](#table-of-contents)

---

## Troubleshooting

### Common Authentication Errors

#### Client Cannot Connect

**Error:**
```
❌ Error: Server requires authentication but client not configured for auth
```

**Solution:**
Add authentication parameters to client:
```bash
./target/release/sealedge-client \
  --server 127.0.0.1:8080 \
  --file data.txt \
  --enable-auth \
  --client-identity "My Client"
```

#### Authentication Handshake Fails

**Error:**
```
❌ Error: Authentication failed - client certificate rejected by server
```

**Possible Causes:**
1. **Client certificate corrupted**: Delete client certificate and regenerate
2. **Clock skew**: Ensure client/server clocks are synchronized
3. **Network issues**: Check network connectivity and firewall rules

**Solution:**
```bash
# Delete corrupted certificates and regenerate
rm client_identity.cert server_identity.cert
# Restart with --verbose for detailed error information
```

#### Session Expired

**Error:**
```
❌ Error: Session expired - please reconnect
```

**Solution:**
- Sessions expire after a fixed 1800-second (30-minute) timeout
- Reconnect with fresh authentication; a new ECDH session key is derived
  automatically on the next handshake

### Debug Mode

Enable verbose logging for authentication debugging:

```bash
# Server debug
./target/release/sealedge-server \
  --require-auth \
  --verbose \
  --server-identity "Debug Server"

# Client debug  
./target/release/sealedge-client \
  --enable-auth \
  --verbose \
  --client-identity "Debug Client"
```

### Certificate Inspection

Examine certificate contents:
```bash
# Check if certificates exist
ls -la *_identity.cert *.key

# View certificate creation time
stat server_identity.cert client_identity.cert
```

[↑ Back to top](#table-of-contents)

---

## Production Deployment

### Pre-Deployment Checklist

#### Security Setup
- [ ] Generate production Ed25519 key pairs
- [ ] Set appropriate file permissions on private keys (`chmod 600`)
- [ ] Configure secure certificate storage location
- [ ] Understand the fixed 30-minute session timeout and client reconnect behavior
- [ ] Enable comprehensive logging

#### Network Configuration
- [ ] Configure TLS/SSL for transport encryption
- [ ] Set up firewall rules for authenticated endpoints
- [ ] Configure load balancers for authenticated traffic
- [ ] Test authentication under expected load

#### Operational Readiness
- [ ] Document certificate rotation procedures
- [ ] Set up monitoring for authentication failures
- [ ] Configure alerting for security events
- [ ] Train operations team on authentication troubleshooting

### Production Example

```bash
#!/bin/bash
# Production Sealedge server deployment script

# Security settings
SERVER_KEY="/etc/sealedge/production_server.key"
UPLOAD_DIR="/secure/sealedge/uploads"
LOG_FILE="/var/log/sealedge/auth.log"

# Ensure directories exist with correct permissions
mkdir -p "$(dirname $SERVER_KEY)" "$UPLOAD_DIR" "$(dirname $LOG_FILE)"
chmod 700 "$(dirname $SERVER_KEY)" "$UPLOAD_DIR"

# Start production server
./target/release/sealedge-server \
  --listen 0.0.0.0:8443 \
  --require-auth \
  --server-identity "Sealedge Production Server $(date +%Y)" \
  --server-key "$SERVER_KEY" \
  --decrypt \
  --use-keyring \
  --salt-hex "$PRODUCTION_SALT" \
  --output-dir "$UPLOAD_DIR" \
  --verbose 2>&1 | tee -a "$LOG_FILE"
```

### Container Deployment

#### Docker Deployment

```dockerfile
# Server container with authentication
FROM rust:latest as builder
COPY . /app
WORKDIR /app
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/sealedge-server /usr/local/bin/
EXPOSE 8080
CMD ["sealedge-server", "--require-auth", "--listen", "0.0.0.0:8080"]
```

#### Kubernetes Configuration

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: sealedge-certs
  namespace: sealedge
data:
  server.cert: |
    # Server certificate content will be generated automatically
    # or pre-populated from existing certificate files

---
apiVersion: v1
kind: Secret
metadata:
  name: sealedge-secrets
  namespace: sealedge
type: Opaque
data:
  # Base64 encoded production salt and other sensitive configuration
  production-salt: YWJjZGVmMTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4OTA=

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sealedge-server
  namespace: sealedge
spec:
  replicas: 3
  selector:
    matchLabels:
      app: sealedge-server
  template:
    metadata:
      labels:
        app: sealedge-server
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
      - name: sealedge-server
        image: sealedge:latest
        args: 
          - "--require-auth"
          - "--listen"
          - "0.0.0.0:8080"
          - "--server-identity"
          - "Sealedge-K8s-Production"
        ports:
        - containerPort: 8080
          name: sealedge
        env:
        - name: PRODUCTION_SALT
          valueFrom:
            secretKeyRef:
              name: sealedge-secrets
              key: production-salt
        volumeMounts:
        - name: certs
          mountPath: /certs
          readOnly: true
        - name: data
          mountPath: /data
        livenessProbe:
          tcpSocket:
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          tcpSocket:
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
        resources:
          requests:
            memory: "64Mi"
            cpu: "250m"
          limits:
            memory: "128Mi"
            cpu: "500m"
      volumes:
      - name: certs
        configMap:
          name: sealedge-certs
          defaultMode: 0600
      - name: data
        persistentVolumeClaim:
          claimName: sealedge-data

---
apiVersion: v1
kind: Service
metadata:
  name: sealedge-service
  namespace: sealedge
spec:
  selector:
    app: sealedge-server
  ports:
  - port: 8080
    targetPort: 8080
    name: sealedge
  type: ClusterIP

---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: sealedge-data
  namespace: sealedge
spec:
  accessModes:
  - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
```

### Monitoring and Alerting

Monitor these authentication metrics:
- Authentication success/failure rates
- Session creation and expiration events
- Certificate generation and rotation events
- Connection attempt frequency and sources
- Session timeout and cleanup operations

### Backup and Recovery

Critical authentication components to backup:
- Server and client Ed25519 private keys
- Certificate files and metadata
- Authentication configuration parameters
- Session management configuration

[↑ Back to top](#table-of-contents)

---

## Advanced Topics

### Custom Identity Schemes

Use structured identity strings for complex deployments:
```bash
# Hierarchical identity naming
--server-identity "Sealedge-Production-East-Server01"
--client-identity "MobileApp-v2.1.3-iOS-Device12345"

# Environment-specific identities
--server-identity "Sealedge-${ENVIRONMENT}-${REGION}-${INSTANCE}"
--client-identity "Client-${APP_VERSION}-${DEVICE_TYPE}-${USER_ID}"
```

### Certificate Rotation

Implement certificate rotation for long-running deployments:
```bash
# Generate new server key
mv server_signing.key server_signing.key.backup
./target/release/sealedge-server --require-auth --server-identity "Rotated Server"
# Server generates new key automatically
```

### Integration with PKI

For enterprise deployments, consider integrating with existing PKI:
- Use Sealedge authentication for application-layer security
- Combine with TLS client certificates for transport-layer security
- Implement certificate validation against enterprise CA

---

[↑ Back to top](#table-of-contents)

---

This completes the Sealedge Authentication Guide. For additional technical implementation details, refer to the source code in [`crates/core/src/`](crates/core/src/) and the integration tests in [`crates/core/tests/auth_integration.rs`](crates/core/tests/auth_integration.rs).

---

**📖 Links:**
- **[Sealedge Home](https://github.com/TrustEdge-Labs/sealedge)** - Main repository
- **[Documentation](../README.md)** - Complete docs index
- **[CLI Reference](cli.md)** - Command reference

**⚖️ Legal:**
- **Copyright**: © 2025 Sealedge Labs LLC
- **License**: Mozilla Public License 2.0 ([MPL-2.0](https://mozilla.org/MPL/2.0/))
- **Commercial**: [Enterprise licensing available](mailto:enterprise@trustedgelabs.com)
