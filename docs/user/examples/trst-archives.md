<!--
Copyright (c) 2025 TRUSTEDGE LABS LLC
MPL-2.0: https://mozilla.org/MPL/2.0/
Project: sealedge — Privacy and trust at the edge.
GitHub: https://github.com/TrustEdge-Labs/sealedge
-->

# .seal Archive System Examples

The Sealedge .seal archive system provides secure archival with Ed25519 digital
signatures and cryptographic chunk verification, ideal for evidence collection,
security camera footage, and tamper-evident data storage.

Archives are **encrypted by default**: content is sealed under a per-archive
random content-encryption key (XChaCha20-Poly1305), which is HPKE-wrapped to the
device's X25519 key-agreement key (recipient #0). On disk each chunk is
`[nonce:24][ciphertext]`. Use `--sign-only` for signed-but-plaintext chunks.

If you omit `--device-key`, `wrap` auto-generates a `device.key` +
`device.pub` bundle. The device `id` is **derived from the signing key** —
there is no `--device-id` flag, and `model`/`firmware`/`resolution`/`codec`
(cam.video) are fixed defaults in the manifest.

## Basic Archive Creation and Verification

**Create a basic .seal archive:**
```bash
# Create sample data
echo "This is sensitive evidence data" > evidence.txt

# Create a .seal archive (auto-generates device.key + device.pub, encrypts by default)
./target/release/seal wrap --in evidence.txt --out evidence.seal --unencrypted

# The archive directory structure:
ls -R evidence.seal/
# evidence.seal/manifest.json          # Signed 0.2.0 manifest (incl. encryption block)
# evidence.seal/signatures/manifest.sig
# evidence.seal/chunks/00000.bin       # [nonce:24][ciphertext]

# Verify the archive integrity using the generated public key
# (a V2 .pub has two lines; pass the ed25519 line)
./target/release/seal verify evidence.seal --device-pub "$(grep '^ed25519:' device.pub)"
```

**Expected verification output:**
```
Signature: PASS
Continuity: PASS
Segments: 1  Duration(s): 0.0  Chunk(s): 1.0
```

## Security Camera Archive Workflow

**High-quality video evidence archival:**
```bash
# Generate a reusable device key bundle first (prompts for a passphrase)
./target/release/seal keygen --out-key cam.key --out-pub cam.pub

# Create a cam.video archive. device.id is derived from the key; fps and
# chunk duration are configurable, resolution/codec are fixed defaults.
./target/release/seal wrap \
  --in security_footage.bin \
  --out court_evidence.seal \
  --profile cam.video \
  --fps 60 \
  --chunk-seconds 2.0 \
  --device-key cam.key

# Verify with the stored device certificate
./target/release/seal verify court_evidence.seal --device-pub "$(grep '^ed25519:' cam.pub)"

# Example successful verification:
# Signature: PASS
# Continuity: PASS
# Segments: 16  Duration(s): 32.0  Chunk(s): 2.0
```

## Sharing an Archive with an Auditor

An archive can be made readable by additional recipients at wrap time via
repeatable `--recipient` flags (each an X25519 public key). Any recipient later
decrypts with its own key bundle.

```bash
# Auditor generates and shares only their public key
./target/release/seal keygen --out-key auditor.key --out-pub auditor.pub

# Wrap for the device AND the auditor (pass the auditor's x25519 line)
./target/release/seal wrap \
  --in evidence.txt \
  --out shared.seal \
  --device-key cam.key \
  --recipient "$(grep '^x25519:' auditor.pub)"

# The auditor decrypts with their OWN key bundle
./target/release/seal unwrap shared.seal --device-key auditor.key --out recovered.txt
```

## Large File Chunked Archival

**Efficient handling of large files with custom chunk sizes:**
```bash
# Archive a large file with 4MB chunks
./target/release/seal wrap \
  --in large_dataset.bin \
  --out dataset.seal \
  --chunk-size 4194304 \
  --device-key cam.key

# Archive audio with the audio profile (codec/sample-rate live here, not cam.video)
./target/release/seal wrap \
  --in audio_stream.bin \
  --out audio.seal \
  --profile audio \
  --sample-rate 48000 \
  --bit-depth 16 \
  --channels 2 \
  --codec pcm \
  --device-key cam.key

# Verify a large archive
./target/release/seal verify dataset.seal --device-pub "$(grep '^ed25519:' cam.pub)"
```

## Recovering Data from an Archive

Encrypted archives are recovered with `seal unwrap` using a recipient's key
bundle; the signature is verified against the manifest's embedded signing key.

```bash
# Recover the original bytes (any recipient uses its own key bundle)
./target/release/seal unwrap court_evidence.seal --device-key cam.key --out recovered.bin

# Optionally pin the expected signer
./target/release/seal unwrap court_evidence.seal \
  --device-key cam.key \
  --device-pub "$(grep '^ed25519:' cam.pub)" \
  --out recovered.bin
```

## Archive Metadata Inspection

**Examine archive contents without verification:**
```bash
# Inspect the manifest (the signer's key is nested under device.public_key)
cat evidence.seal/manifest.json | jq '.device.public_key'
cat evidence.seal/manifest.json | jq .

# Check archive structure
find evidence.seal -type f -exec ls -lh {} \;

# The manifest's blake3_hash for each segment is computed over the STORED chunk
# bytes ([nonce:24][ciphertext] when encrypted), so this matches for each chunk:
cd evidence.seal/chunks
for chunk in *.bin; do
  echo -n "$chunk: "
  blake3sum "$chunk" | cut -d' ' -f1
done
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
