<!--
Copyright (c) 2025 TRUSTEDGE LABS LLC
MPL-2.0: https://mozilla.org/MPL/2.0/
Project: sealedge — Privacy and trust at the edge.
GitHub: https://github.com/TrustEdge-Labs/sealedge
-->

# Sealedge Troubleshooting Guide

Comprehensive error handling, common issues, and diagnostic procedures for Sealedge.

## Table of Contents
- [Common Error Messages](#common-error-messages)
- [Configuration Issues](#configuration-issues)
- [Backend Issues](#backend-issues)
- [Network Problems](#network-problems)
- [Authentication Issues](#authentication-issues)
- [Audio System Issues](#audio-system-issues)
- [Cryptographic Errors](#cryptographic-errors)
- [File and Format Issues](#file-and-format-issues)
- [Debug and Diagnostic Commands](#debug-and-diagnostic-commands)

---

## Common Error Messages

### File System Errors

#### `No such file or directory (os error 2)`
**Error Example:**
```
Error: open envelope. Caused by: No such file or directory (os error 2)
```

**Cause:** Input file doesn't exist or path is incorrect.

**Solution:**
```bash
# Check file exists
ls -la your_file.seal

# Use absolute path if needed
./target/release/sealedge-client --file /full/path/to/file.seal
```

[↑ Back to top](#table-of-contents)

---

## Configuration Issues

### Backend Configuration

#### `Operation not supported by available backends`
**Error Example:**
```
Error: Operation not supported by available backends
```

**Solution:**
```bash
# List available key-management backends
sealedge --list-backends

# Select a specific backend (keyring, tpm, hsm, matter)
sealedge --input file.txt --out /dev/null --envelope file.seal --backend hsm --key-out key.hex

# Pass backend-specific settings (repeatable key=value)
sealedge --input file.txt --out /dev/null --envelope file.seal --backend tpm --backend-config "device=/dev/tpm0"
```

### Salt Format Issues

#### `Odd number of digits`
**Error Example:**
```
Error: salt_hex decode. Caused by: Odd number of digits
```

**Cause:** Salt hex string has odd number of characters (must be even).

**Solution:**
```bash
# Wrong: 15 characters
--salt-hex "abcdef1234567890abc"

# Correct: 32 characters (16 bytes)
--salt-hex "abcdef1234567890abcdef1234567890"

# Generate valid salt
openssl rand -hex 16
```

[↑ Back to top](#table-of-contents)

---

## Backend Issues

The `sealedge` envelope CLI selects a key-management backend with `--backend`
(valid values: `keyring` (default), `tpm`, `hsm`, `matter`). There is no backend
"registry" CLI — the surface is `--list-backends`, `--backend`, and
`--backend-config key=value`.

#### `Operation not supported by available backends`

**Cause:** The requested backend is not available in this build, or the chosen
backend cannot perform the operation.

**Solution:**
```bash
# See which backends this build supports
sealedge --list-backends

# Encrypt with a generated key (works in any build)
sealedge --input file.txt --out /dev/null --envelope file.seal --key-out file.key
```

The `keyring` backend (and `--use-keyring` / `--set-passphrase`) requires a build
with the `keyring` feature: `cargo build -p sealedge-cli --features keyring`.
Without it these commands fail with a clear "requires the 'keyring' feature" error.

#### Passing backend configuration

Some backends accept extra settings via one or more `--backend-config key=value`
flags:

```bash
sealedge \
  --input file.txt \
  --out /dev/null \
  --envelope file.seal \
  --backend tpm \
  --backend-config "device=/dev/tpm0"
```

#### YubiKey hardware

The `sealedge` envelope CLI does not sign with a YubiKey. Hardware signing is
provided by the `seal` archive tool (`seal wrap --backend yubikey --sign-only`,
built with `--features yubikey`). See
[Backend Examples](examples/backends.md#yubikey-hardware-signing-seal-archives).


---

## Network Problems

### Connection Issues

#### `Connection refused`
**Symptoms:**
```
Connection attempt 1 failed: connection refused
```

**Diagnosis:**
1. Check if server is running:
   ```bash
   netstat -tlnp | grep :8080
   ```

2. Verify server address and port:
   ```bash
   # Test connectivity
   telnet 127.0.0.1 8080
   ```

**Solutions:**
```bash
# Start server on correct port
./target/release/sealedge-server --listen 127.0.0.1:8080

# Check firewall rules
sudo ufw status
```

#### `Connection timeout`
**Symptoms:**
```
Connection attempt 2 failed: timeout after 15s
```

**Solutions:**
```bash
# Increase timeout for slow networks
./target/release/sealedge-client \
  --server remote.example.com:8080 \
  --connect-timeout 30 \
  --retry-attempts 3

# Use retry logic for unstable networks
./target/release/sealedge-client \
  --retry-attempts 5 \
  --retry-delay 3
```

### Server Issues

#### Server Startup Problems
**Check server logs with verbose mode:**
```bash
./target/release/sealedge-server \
  --listen 0.0.0.0:8080 \
  --verbose \
  --decrypt
```

**Common server issues:**
- Port already in use: `Address already in use (os error 98)`
- Permission denied: `Permission denied (os error 13)` - try different port > 1024
- Interface binding issues: Use `127.0.0.1` instead of `0.0.0.0`

---

## Authentication Issues

### Authentication Configuration

#### `Server requires authentication but client not configured for auth`
**Error Example:**
```
❌ Error: Server requires authentication but client not configured for auth
```

**Solution:**
```bash
# Add authentication to client
./target/release/sealedge-client \
  --server 127.0.0.1:8080 \
  --file data.wav \
  --enable-auth \
  --client-identity "My Client App"
```

#### `Authentication failed - client certificate rejected by server`
**Possible Causes:**
1. **Corrupted certificates**: Delete and regenerate
2. **Clock skew**: Sync system clocks
3. **Wrong identity**: Check client/server identity strings

**Solutions:**
```bash
# Delete corrupted certificates
rm *_identity.cert *.key

# Regenerate with verbose logging
./target/release/sealedge-server \
  --require-auth \
  --verbose \
  --server-identity "Debug Server"

./target/release/sealedge-client \
  --enable-auth \
  --verbose \
  --client-identity "Debug Client"
```

#### `Session expired - please reconnect`
**Cause:** The authenticated session is time-limited and has expired.

**Solutions:**
```bash
# Reconnect with fresh authentication (a new ECDH session key is derived)
./target/release/sealedge-client \
  --server 127.0.0.1:8080 \
  --file data.txt \
  --enable-auth \
  --client-identity "Client"
```

[↑ Back to top](#table-of-contents)

---

## Audio System Issues

### Audio Device Problems

#### `No audio input devices found`
**Cause:** System audio drivers not available or Sealedge built without audio features.

**Solutions:**
```bash
# Verify audio features are enabled
./target/release/sealedge --help | grep -i audio

# If missing, rebuild with audio features
cargo build --release --features audio

# Check system audio devices
arecord --list-devices  # Linux
system_profiler SPAudioDataType  # macOS
```

#### `Failed to open audio device: Permission denied`
**Cause:** Insufficient permissions to access audio hardware.

**Solutions:**
```bash
# Linux: Add user to audio group
sudo usermod -a -G audio $USER
# Logout and login required

# Check current groups
groups $USER

# Test with PulseAudio (encrypt mode needs --out and a key; --out captures raw PCM)
./target/release/sealedge \
  --live-capture \
  --audio-device "pulse" \
  --max-duration 5 \
  --out capture.raw \
  --key-out capture.key
```

#### `Audio device "device_name" not found`
**Cause:** Incorrect device name or device no longer available.

**Solutions:**
```bash
# Always check available devices first
./target/release/sealedge --list-audio-devices

# Copy device name exactly from the list
./target/release/sealedge \
  --live-capture \
  --audio-device "hw:CARD=USB_AUDIO,DEV=0" \
  --max-duration 5 \
  --out capture.raw \
  --key-out capture.key

# Use system default as fallback
./target/release/sealedge \
  --live-capture \
  --max-duration 5 \
  --out capture.raw \
  --key-out capture.key
```

#### Silent Audio Capture
**Cause:** Microphone muted, wrong input levels, or incorrect device.

**Solutions:**
```bash
# Check microphone levels (Linux)
alsamixer  # Adjust capture levels

# Test with system tools first
arecord -d 3 test_system.wav  # Linux
sox -d test_system.wav trim 0 3  # macOS/Linux

# Use verbose output for debugging
./target/release/sealedge \
  --live-capture \
  --max-duration 5 \
  --out capture.raw \
  --key-out capture.key \
  --verbose

# Try different sample rates
./target/release/sealedge \
  --live-capture \
  --sample-rate 44100 \
  --max-duration 5 \
  --out capture.raw \
  --key-out capture.key
```

#### Decrypted Audio Not Playable
**Cause:** Live audio captures output raw PCM data, not playable audio files.

**Important:** Sealedge decryption behavior varies by input type:
- **File inputs** (MP3, WAV, etc.): Original format preserved
- **Live audio captures** (`--live-capture`): Outputs **raw PCM data** (32-bit float, little-endian)

**Solutions:**
```bash
# For live audio captures: Always use .raw extension for clarity
./target/release/sealedge \
  --decrypt \
  --input live_audio.seal \
  --out audio.raw \
  --key-hex $KEY \
  --verbose

# For live audio captures: Extract audio parameters from verbose output
# Look for: "Sample Rate: 44100Hz, Channels: 2, Format: f32"

# For live audio captures: Convert raw PCM to playable WAV
ffmpeg -f f32le -ar 44100 -ac 2 -i audio.raw audio.wav

# For file inputs: Use original extension
./target/release/sealedge \
  --decrypt \
  --input music_file.seal \
  --out music_file.mp3 \
  --key-hex $KEY
# Output will be playable MP3 file (original format preserved)
```

**📋 For comprehensive audio testing and system configuration, see [TESTING.md](TESTING.md#audio-system-testing).**

[↑ Back to top](#table-of-contents)

---

## Cryptographic Errors

### Decryption Failures

#### `AES-GCM decrypt/verify failed`
**Common Causes:**
1. **Wrong key**: Key doesn't match encryption key
2. **Wrong passphrase/salt**: PBKDF2 derivation mismatch  
3. **File corruption**: Encrypted data has been modified
4. **Format mismatch**: File isn't a valid .seal file

**Diagnostic Steps:**
```bash
# 1. Verify file is valid .seal format
file encrypted.seal
hexdump -C encrypted.seal | head -1
# Should start with magic bytes

# 2. Test with known good key
./target/release/sealedge \
  --decrypt \
  --input encrypted.seal \
  --out test.txt \
  --key-hex "known_good_key_64_hex_chars"

# 3. Test passphrase/salt combination
./target/release/sealedge \
  --decrypt \
  --input encrypted.seal \
  --out test.txt \
  --use-keyring \
  --salt-hex "original_salt_used_for_encryption"
```

#### `bad magic`
**Cause:** File is not a valid Sealedge envelope format.

**Solutions:**
```bash
# Check file format
file suspicious_file.seal

# Verify file wasn't corrupted
./target/release/sealedge \
  --input original_file.txt \
  --out /dev/null \
  --envelope new_envelope.seal \
  --key-hex $(openssl rand -hex 32)
```

[↑ Back to top](#table-of-contents)

---

## File and Format Issues

### Format-Aware Decryption Issues

#### Unknown File Type Detection
**Symptoms:** File shows as `application/octet-stream` instead of expected type

**Diagnosis:**
```bash
# Inspect file format detection
./target/release/sealedge --input file.seal --inspect --verbose

# Check original file extension and content
file original_file.pdf  # Should show PDF document
hexdump -C original_file.pdf | head -2  # Check file headers
```

**Solutions:**
```bash
# For unknown extensions, the file will still decrypt correctly
# but will show as binary data. This is expected behavior.

# To verify correct handling:
./target/release/sealedge --decrypt --input file.seal --out restored_file.pdf --key-hex $KEY
file restored_file.pdf  # Should match original type
diff original_file.pdf restored_file.pdf  # Should be identical
```

#### MIME Type Mismatch
**Symptoms:** Expected MIME type doesn't match detected type

**Common Causes:**
- File extension doesn't match content (e.g., `.txt` file containing JSON)
- Corrupted file headers
- Custom file formats not in MIME database

**Verification:**
```bash
# Check what MIME type was detected
./target/release/sealedge --input file.seal --inspect

# Expected output:
# MIME Type: application/pdf  (for PDF files)
# MIME Type: application/json (for JSON files)
# MIME Type: text/plain      (for text files)
# MIME Type: application/octet-stream (for unknown types)
```

#### Format Inspection Without Decryption
**Use Case:** Verify file type before decryption

```bash
# Inspect encrypted archive
./target/release/sealedge --input suspicious_file.seal --inspect --verbose

# Example output:
# Sealedge Archive Information:
#   File: suspicious_file.seal
#   Format Version: 1
#   Algorithm: AES-256-GCM
#   Data Type: File
#   MIME Type: application/pdf
#   Output Behavior: Original file format preserved

# This tells you it's a PDF file without decrypting it
```

### Format Validation

#### Header Corruption
**Test for header corruption:**
```bash
# Verify file magic bytes
hexdump -C file.seal | head -1
# Should show expected magic bytes

# Test with known good file
cp known_good.seal test_copy.seal
./target/release/sealedge --input test_copy.seal --inspect
```

#### Record Tampering Detection
**Symptoms:** Decryption fails partway through file

**Validation Test:**
```bash
# Create test file
echo "test data" > test.txt

# Encrypt (save the key so the decrypt step below can reuse it)
./target/release/sealedge \
  --input test.txt \
  --out /dev/null \
  --envelope test.seal \
  --key-out last_key.hex

# Verify encryption worked
./target/release/sealedge \
  --decrypt \
  --input test.seal \
  --out recovered.txt \
  --key-hex $(cat last_key.hex)

# Compare files
diff test.txt recovered.txt
```

### Format-Aware Output Verification

#### Audio vs File Confusion
**Symptoms:** Expected audio file but got different output

**Diagnosis:**
```bash
# Check what type of data was originally encrypted
./target/release/sealedge --input file.seal --inspect

# For file inputs (MP3, WAV, etc.):
# Data Type: File
# MIME Type: audio/mpeg (or audio/wav)
# Output Behavior: Original file format preserved

# For live audio capture:
# Data Type: Audio
# Sample Rate: 44100 Hz
# Channels: 1 (mono)
# Output Behavior: Raw PCM data (requires conversion)
```

**Solution:**
```bash
# File inputs preserve format automatically
./target/release/sealedge --decrypt --input music.seal --out music.mp3 --key-hex $KEY
# Output: Playable MP3 file

# Live audio requires conversion
./target/release/sealedge --decrypt --input live_capture.seal --out audio.raw --key-hex $KEY
ffmpeg -f f32le -ar 44100 -ac 1 -i audio.raw audio.wav
```

#### Header Corruption
**Test for header corruption:**
```bash
# Verify file magic bytes
hexdump -C file.seal | head -1
# Should show expected magic bytes

# Test with known good file
cp known_good.seal test_copy.seal
./target/release/sealedge --input test_copy.seal --inspect
```

#### Record Tampering Detection
**Symptoms:** Decryption fails partway through file

**Validation Test:**
```bash
# Create test file
echo "test data" > test.txt

# Encrypt (save the key so the decrypt step below can reuse it)
./target/release/sealedge \
  --input test.txt \
  --out /dev/null \
  --envelope test.seal \
  --key-out last_key.hex

# Verify encryption worked
./target/release/sealedge \
  --decrypt \
  --input test.seal \
  --out recovered.txt \
  --key-hex $(cat last_key.hex)

# Compare files
diff test.txt recovered.txt
```

[↑ Back to top](#table-of-contents)

---

## Debug and Diagnostic Commands

### Verbose Logging

Enable verbose output for detailed troubleshooting:

```bash
# Server with debug output
./target/release/sealedge-server \
  --listen 127.0.0.1:8080 \
  --verbose \
  --decrypt

# Client with debug output  
./target/release/sealedge-client \
  --server 127.0.0.1:8080 \
  --file file.txt \
  --verbose

# File encryption/decryption with format details
./target/release/sealedge \
  --decrypt \
  --input file.seal \
  --out restored.txt \
  --key-hex $KEY \
  --verbose

# Example verbose output:
# ● Input Type: File
#   MIME Type: application/json
# ✔ Output: Original file format preserved
# ✔ Decrypt complete. Wrote 1337 bytes.
# ● Output file preserves original format and should be directly usable.
```

### Format Inspection Commands

```bash
# Quick format check (no decryption)
./target/release/sealedge --input file.seal --inspect

# Detailed format inspection
./target/release/sealedge --input file.seal --inspect --verbose

# Compare multiple files
for file in *.seal; do
  echo "=== $file ==="
  ./target/release/sealedge --input "$file" --inspect
  echo
done
```

# Authentication debug
./target/release/sealedge-server \
  --require-auth \
  --verbose \
  --server-identity "Debug Server"
```

### System Information

Gather system information for bug reports:

```bash
# Sealedge version
./target/release/sealedge --version

# System information
uname -a
rustc --version

# Network connectivity
netstat -tlnp | grep sealedge
ss -tlnp | grep :8080

# Certificate files
ls -la *_identity.cert *.key

# File permissions
ls -la input_file.txt output_dir/
```

### Test Environment Setup

Create clean test environment:

```bash
# Clean slate for testing
rm -f *.seal *.hex *_identity.cert *.key

# Generate test data
echo "Hello Sealedge Testing" > test_input.txt

# Test basic encryption/decryption
./target/release/sealedge \
  --input test_input.txt \
  --out /dev/null \
  --envelope test.seal \
  --key-out test.key

./target/release/sealedge \
  --decrypt \
  --input test.seal \
  --out test_output.txt \
  --key-hex $(cat test.key)

# Verify round-trip
diff test_input.txt test_output.txt
```

### Network Testing

Test network components in isolation:

```bash
# Test server startup
./target/release/sealedge-server \
  --listen 127.0.0.1:8080 \
  --verbose &
SERVER_PID=$!

# Wait for startup
sleep 2

# Test connection
echo "test" | nc 127.0.0.1 8080

# Clean shutdown
kill $SERVER_PID
```

[↑ Back to top](#table-of-contents)

---

## Getting Help

If issues persist after following this guide:

1. **Check logs**: Always run with `--verbose` for detailed output
2. **Test minimal case**: Use simplest possible command that reproduces issue
3. **Environment**: Note OS, Rust version, and Sealedge version
4. **Create issue**: Use [GitHub issue templates](https://github.com/TrustEdge-Labs/sealedge/issues/new/choose)

### Issue Report Template

```markdown
**System Information:**
- OS: [e.g., Ubuntu 22.04]
- Rust version: [e.g., 1.75.0]
- Sealedge version: [output of --version]

**Command that failed:**
```bash
./target/release/sealedge-client --server 127.0.0.1:8080 --file file.txt
```

**Error output:**
```
[paste complete error message with --verbose]
```

**Expected behavior:**
[what should have happened]

**Additional context:**
[any other relevant information]
```

---

[↑ Back to top](#table-of-contents)

---

This troubleshooting guide covers the most common Sealedge issues. For authentication-specific problems, also see [AUTHENTICATION_GUIDE.md](authentication.md#troubleshooting).

---

**📖 Links:**
- **[Sealedge Home](https://github.com/TrustEdge-Labs/sealedge)** - Main repository
- **[Documentation](../README.md)** - Complete docs index
- **[CLI Reference](cli.md)** - Command reference

**⚖️ Legal:**
- **Copyright**: © 2025 Sealedge Labs LLC
- **License**: Mozilla Public License 2.0 ([MPL-2.0](https://mozilla.org/MPL/2.0/))
- **Commercial**: [Enterprise licensing available](mailto:enterprise@trustedgelabs.com)
