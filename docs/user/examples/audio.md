<!--
Copyright (c) 2025 TRUSTEDGE LABS LLC
MPL-2.0: https://mozilla.org/MPL/2.0/
Project: sealedge — Privacy and trust at the edge.
GitHub: https://github.com/TrustEdge-Labs/sealedge
-->

# Audio Examples

Live audio capture, processing, and streaming examples for Sealedge.

## Live Audio Capture

> These examples require a build with the `audio` feature
> (`cargo build -p sealedge-cli --features audio`). Encrypt mode always needs
> `--out` (a round-trip copy of the captured PCM); send it to `/dev/null` when
> you only want the encrypted envelope.

**Basic audio capture:**
```bash
# List available audio devices
./target/release/sealedge --list-audio-devices

# Capture 10 seconds of audio
./target/release/sealedge \
  --live-capture \
  --out /dev/null \
  --envelope voice_note.seal \
  --key-out voice_key.hex \
  --max-duration 10
```

## Advanced Live Audio Capture

### Voice Memo Recording

> The keyring flags (`--use-keyring`, `--backend keyring`) require a build with
> the `keyring` feature in addition to `audio`.

```bash
# Quick voice note with system keyring
./target/release/sealedge \
  --live-capture \
  --out /dev/null \
  --max-duration 30 \
  --envelope voice_note_$(date +%Y%m%d_%H%M%S).seal \
  --backend keyring \
  --salt-hex "voice_notes_salt_1234567890abcdef" \
  --use-keyring
```

### High-Quality Recording Session

```bash
# Professional audio recording with device selection
./target/release/sealedge --list-audio-devices

# Record from professional interface (copy the device name from the list above)
./target/release/sealedge \
  --live-capture \
  --out /dev/null \
  --audio-device "USB Audio Device" \
  --max-duration 1800 \
  --sample-rate 48000 \
  --channels 2 \
  --envelope studio_session.seal \
  --key-out session_key.hex \
  --verbose
```

## Audio Pipeline Examples

### Audio Device Discovery and Setup

#### Discovering Available Audio Devices
```bash
# List all available audio input devices
./target/release/sealedge --list-audio-devices --verbose

# Cross-platform device discovery
./target/release/sealedge \
  --live-capture \
  --out /dev/null \
  --audio-device "Microphone (Realtek Audio)" \
  --sample-rate 44100 \
  --channels 1 \
  --envelope test_audio.seal \
  --key-out test.key
```

### Real-time Audio Chunking

### Audio Streaming Simulation

### Audio Troubleshooting Examples

#### Testing Audio Device Access
```bash
# Test minimal audio capture
./target/release/sealedge \
  --live-capture \
  --out /dev/null \
  --max-duration 1 \
  --envelope audio_test.seal \
  --key-out test.key \
  --verbose
```

### Audio Post-Processing and Format Conversion

**Converting Raw PCM to Standard Formats (Live Audio Only):**
```bash
# Convert raw PCM to WAV
ffmpeg -f f32le -ar 44100 -ac 1 -i recovered_audio.raw recovered_audio.wav

# Convert to MP3
ffmpeg -f f32le -ar 44100 -ac 1 -i recovered_audio.raw -b:a 128k recovered_audio.mp3
```

### Cross-Platform Audio Workflows

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
