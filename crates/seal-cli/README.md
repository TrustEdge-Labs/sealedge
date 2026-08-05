<!--
Copyright (c) 2025 TRUSTEDGE LABS LLC
MPL-2.0: https://mozilla.org/MPL/2.0/
Project: sealedge — Privacy and trust at the edge.
GitHub: https://github.com/TrustEdge-Labs/sealedge
-->

# sealedge-seal-cli

> **STABLE** -- This crate is Tier 1 (Stable). Production-committed, tested in CI, and actively maintained.

CLI tool for `.seal` archive and point-attestation operations. Binary name: `seal`.

`seal` wraps input data into signed (and optionally encrypted) `.seal` archives,
verifies them with public keys only, and recovers plaintext for authorized
recipients. It also produces and verifies point attestations that bind two
artifacts (for example an SBOM to a binary).

---

## Key model (`SEALEDGE-KEY-V2`)

A device keypair is a `SEALEDGE-KEY-V2` bundle containing two independent keys:

- an **Ed25519 signing key** (used only to sign manifests), and
- an **X25519 key-agreement key** (used for content confidentiality).

Bundles are encrypted at rest by default with PBKDF2-HMAC-SHA256 (600,000
iterations) + AES-256-GCM; the passphrase is prompted interactively. For CI and
automation, `--unencrypted` generates/reads a plaintext bundle instead.

The `.pub` file carries **two lines**, one key per line:

```
ed25519:<base64>
x25519:<base64>
```

Because the public-key file has two lines, always select the signing line when a
command wants an `ed25519:` verifier, e.g. `--device-pub "$(grep '^ed25519:' device.pub)"`.

Legacy single-key `SEALEDGE-KEY-V1` files are rejected — re-run `seal keygen`.

## Archive format (`trst_version` 0.2.0, C4)

```
<name>.seal/
├── manifest.json          # Canonical manifest (0.2.0); includes device.key_agreement_public
│                          #   and an `encryption` block when the archive is encrypted
├── signatures/
│   └── manifest.sig       # Detached Ed25519 signature over the canonical manifest
└── chunks/
    ├── 00000.bin          # [nonce:24][ciphertext] when encrypted; plaintext under --sign-only
    └── ...
```

Content is encrypted under a **per-archive random content-encryption key (CEK)**
with XChaCha20-Poly1305 — the CEK is never derived from the signing key. The CEK
is HPKE-wrapped (RFC 9180 base mode; DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 /
ChaCha20-Poly1305) to one or more recipients: recipient #0 is always the device,
and each `--recipient x25519:<b64>` adds another. An archive created with
`--sign-only` has no `encryption` block and stores plaintext chunks.

Verifiers only need public keys and reject any archive whose `trst_version` is not
`0.2.0`. See `docs/designs/c4-content-encryption-redesign.md`.

---

## Commands

| Command | Purpose |
|---------|---------|
| `keygen` | Generate a `SEALEDGE-KEY-V2` bundle and its `.pub` file |
| `wrap` | Create a signed (and by default encrypted) `.seal` archive |
| `verify` | Verify an archive using public keys only |
| `verify-chronicle` | Verify a device's cross-archive chronicle (linkage, rotations + optional witness) |
| `rekey` | Rotate a chronicle to a new signing key (emits a dual-signed rotation entry) |
| `witness` | Submit the chronicle tip for a signed, timestamped platform witness receipt |
| `unwrap` | Decrypt and recover the original data (recipient uses its own bundle) |
| `emit-request` | Build a verification request JSON (optionally POST it to a platform) |
| `attest-sbom` | Bind an SBOM to a binary as a signed point attestation |
| `verify-attestation` | Verify a point attestation, optionally against file hashes |

Key flags (see `seal <command> --help` for the full list):

- `keygen --out-key <p> --out-pub <p> [--unencrypted]`
- `wrap --in <f> --out <dir.seal> [--device-key <k>] [--profile generic|cam.video|sensor|audio|log] [--recipient x25519:<b64>]... [--sign-only] [--unencrypted] [--backend software|yubikey] [--chunk-size N] [--seed N] [--chronicle <state>] [--prev-archive <p> | --prev-hash <b3:> --prev-seq <n>]` (plus profile-specific flags). Encrypted to the device key by default; if `--device-key` is omitted a `device.key`/`device.pub` pair is auto-generated. `--backend yubikey` requires `--sign-only`.
- `verify <archive> --device-pub <ed25519:...> [--json] [--emit-receipt <path>]`
- `verify-chronicle <paths...> --device-pub <ed25519:...> [--witness <receipt>] [--witness-jwks <url|file>] [--json]` — `--device-pub` pins the **genesis** identity; the walk follows rotation entries and reports the current identity/epoch.
- `rekey --chronicle <state> --old-key <old bundle> --new-key <new bundle> --out <dir.seal> [--unencrypted]` — the new key must be a pre-generated `seal keygen` bundle.
- `witness --chronicle <state> --device-key <k> [--rotation <dir>] [--post <url>] [--out <f>] [--unencrypted]` — pass `--rotation` when the tip is a rotation entry so the platform records device lineage.
- `unwrap <archive> --device-key <recipient bundle> --out <path> [--device-pub <signer pin>] [--unencrypted]`
- `emit-request --archive <dir> --device-pub <.pub> --out <json> [--post <url>]`
- `attest-sbom --binary <f> --sbom <f> --device-key <k> --device-pub <k> [--out <f>] [--unencrypted]`
- `verify-attestation <file> --device-pub <ed25519:...|.pub> [--binary <f>] [--sbom <f>]`

### Exit codes

`seal verify` returns a distinct exit code per failure class, so scripts can branch on
the result (also documented in [docs/user/cli.md](../../docs/user/cli.md)):

| Code | Meaning |
|------|---------|
| `0`  | Success — signature and continuity both pass |
| `10` | Signature verification failed |
| `11` | Continuity / integrity chain verification failed |
| `12` | Archive read, schema, or IO error (bad archive, missing chunk, unsupported `trst_version`) |
| `13` | Chronicle linkage / contiguity failure (`verify-chronicle`) |
| `14` | Internal canonicalization error |
| `1`  | Other error |

`verify-attestation` uses `0` (verified), `10` (signature or file-hash mismatch), and
`1` (other errors).

---

## Examples

**Keygen → wrap → verify → unwrap** (unencrypted keys for a quick, non-interactive run):

```bash
# 1. Generate a device keypair (plaintext bundle for CI; drop --unencrypted for a prompt)
cargo run -p sealedge-seal-cli -- keygen --out-key device.key --out-pub device.pub --unencrypted

# 2. Wrap input into an encrypted archive (encrypted to the device by default)
cargo run -p sealedge-seal-cli -- wrap --in sample.bin --out archive.seal --device-key device.key --unencrypted

# 3. Verify with the signing (ed25519) public key only
cargo run -p sealedge-seal-cli -- verify archive.seal --device-pub "$(grep '^ed25519:' device.pub)"

# 4. Recover the original bytes
cargo run -p sealedge-seal-cli -- unwrap archive.seal --device-key device.key --out recovered.bin --unencrypted
```

**Add an auditor as an extra recipient** (repeat `--recipient` for more):

```bash
cargo run -p sealedge-seal-cli -- wrap --in sample.bin --out archive.seal \
  --device-key device.key --unencrypted \
  --recipient "x25519:<auditor-x25519-pub>"
```

**Signed-but-unencrypted archive** (plaintext chunks, no CEK):

```bash
cargo run -p sealedge-seal-cli -- wrap --sign-only --in sample.bin --out archive.seal \
  --device-key device.key --unencrypted
```

**SBOM point attestation:**

```bash
cargo run -p sealedge-seal-cli -- attest-sbom \
  --binary target/release/seal --sbom bom.cdx.json \
  --device-key device.key --device-pub device.pub \
  --out attestation.se-attestation.json --unencrypted

cargo run -p sealedge-seal-cli -- verify-attestation attestation.se-attestation.json \
  --device-pub "$(grep '^ed25519:' device.pub)" \
  --binary target/release/seal --sbom bom.cdx.json
```

Production devices should use encrypted key files (omit `--unencrypted`); the flag
is an explicit escape hatch for CI where interactive prompts are not possible.

---

## License

Licensed under the Mozilla Public License 2.0 (MPL-2.0).
