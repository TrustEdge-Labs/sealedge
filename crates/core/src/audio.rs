//
// Copyright (c) 2025 TRUSTEDGE LABS LLC
// This source code is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Project: sealedge — Privacy and trust at the edge.
// GitHub: https://github.com/TrustEdge-Labs/sealedge
//

//! Live audio capture module
//!
//! This module provides real-time audio capture from microphones using the cpal library.
//! It supports cross-platform audio input with configurable sample rates, chunk sizes,
//! and device selection.
//!
//! Note: This module requires the "audio" feature to be enabled.

use anyhow::{anyhow, Result};
use std::time::Instant;

#[cfg(feature = "audio")]
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
#[cfg(feature = "audio")]
use cpal::{Device, Host, SampleFormat, Stream, StreamConfig};
#[cfg(feature = "audio")]
use num_traits::ToPrimitive;
#[cfg(feature = "audio")]
use std::sync::mpsc::{self, Receiver, Sender};
#[cfg(feature = "audio")]
use std::sync::{Arc, Mutex};

/// Audio capture configuration
#[derive(Debug, Clone)]
pub struct AudioConfig {
    /// Device name (None for default device)
    pub device_name: Option<String>,
    /// Sample rate in Hz
    pub sample_rate: u32,
    /// Number of channels (1 for mono, 2 for stereo)
    pub channels: u16,
    /// Chunk duration in milliseconds
    pub chunk_duration_ms: u64,
    /// Buffer size for audio chunks
    pub buffer_size: usize,
}

impl Default for AudioConfig {
    fn default() -> Self {
        Self {
            device_name: None,
            sample_rate: 44100,
            channels: 1,             // Mono by default
            chunk_duration_ms: 1000, // 1 second chunks
            buffer_size: 8192,
        }
    }
}

/// Audio chunk with metadata
#[derive(Debug, Clone)]
pub struct AudioChunk {
    /// Raw audio data (f32 samples)
    pub data: Vec<f32>,
    /// Timestamp when chunk was captured
    pub timestamp: Instant,
    /// Sample rate used
    pub sample_rate: u32,
    /// Number of channels
    pub channels: u16,
    /// Chunk sequence number
    pub sequence: u64,
}

impl AudioChunk {
    /// Convert to bytes for encryption
    pub fn to_bytes(&self) -> Vec<u8> {
        // Simple conversion: convert f32 samples to bytes
        // In production, you might want to use a proper audio format
        let mut bytes = Vec::with_capacity(self.data.len() * 4);
        for sample in &self.data {
            bytes.extend_from_slice(&sample.to_le_bytes());
        }
        bytes
    }

    /// Convert from bytes (for decryption)
    pub fn from_bytes(
        bytes: &[u8],
        sample_rate: u32,
        channels: u16,
        sequence: u64,
    ) -> Result<Self> {
        if !bytes.len().is_multiple_of(4) {
            return Err(anyhow!("Invalid byte length for f32 samples"));
        }

        let mut data = Vec::with_capacity(bytes.len() / 4);
        // len is a multiple of 4 (checked above), so as_chunks leaves no remainder.
        for chunk in bytes.as_chunks::<4>().0 {
            let sample = f32::from_le_bytes(*chunk);
            data.push(sample);
        }

        Ok(Self {
            data,
            timestamp: Instant::now(),
            sample_rate,
            channels,
            sequence,
        })
    }

    /// Duration of this chunk in milliseconds
    pub fn duration_ms(&self) -> u64 {
        (self.data.len() as u64 * 1000) / (self.sample_rate as u64 * self.channels as u64)
    }
}

#[cfg(feature = "audio")]
#[cfg_attr(docsrs, doc(cfg(feature = "audio")))]
/// Audio capture manager (only available with "audio" feature)
pub struct AudioCapture {
    config: AudioConfig,
    host: Host,
    device: Option<Device>,
    stream: Option<Stream>,
    chunk_sender: Option<Sender<AudioChunk>>,
    chunk_receiver: Option<Receiver<AudioChunk>>,
    sequence_counter: Arc<Mutex<u64>>,
}

#[cfg(feature = "audio")]
#[cfg_attr(docsrs, doc(cfg(feature = "audio")))]
impl AudioCapture {
    /// Create a new audio capture instance
    pub fn new(config: AudioConfig) -> Result<Self> {
        let host = cpal::default_host();

        Ok(Self {
            config,
            host,
            device: None,
            stream: None,
            chunk_sender: None,
            chunk_receiver: None,
            sequence_counter: Arc::new(Mutex::new(0)),
        })
    }

    /// List available audio input devices
    pub fn list_devices(&self) -> Result<Vec<String>> {
        let mut devices = Vec::new();

        for device in self.host.input_devices()? {
            if let Ok(name) = device.name() {
                devices.push(name);
            }
        }

        Ok(devices)
    }

    /// Initialize the audio device and stream
    pub fn initialize(&mut self) -> Result<()> {
        // Get the audio device
        let device = if let Some(ref device_name) = self.config.device_name {
            self.host
                .input_devices()?
                .find(|d| d.name().map(|n| n == *device_name).unwrap_or(false))
                .ok_or_else(|| anyhow!("Device '{}' not found", device_name))?
        } else {
            self.host
                .default_input_device()
                .ok_or_else(|| anyhow!("No default input device available"))?
        };

        println!("♪ Using audio device: {}", device.name()?);

        // Get supported configuration
        let supported_config = device
            .supported_input_configs()?
            .find(|config| {
                config.channels() == self.config.channels
                    && config.min_sample_rate().0 <= self.config.sample_rate
                    && config.max_sample_rate().0 >= self.config.sample_rate
            })
            .ok_or_else(|| anyhow!("No supported configuration found"))?;

        let stream_config = StreamConfig {
            channels: self.config.channels,
            sample_rate: cpal::SampleRate(self.config.sample_rate),
            buffer_size: cpal::BufferSize::Default,
        };

        println!(
            "● Audio config: {} Hz, {} channels",
            stream_config.sample_rate.0, stream_config.channels
        );

        // Create channel for audio chunks
        let (sender, receiver) = mpsc::channel();
        self.chunk_sender = Some(sender.clone());
        self.chunk_receiver = Some(receiver);

        // Create the audio stream
        let chunk_duration_samples =
            (self.config.sample_rate as u64 * self.config.chunk_duration_ms) / 1000;
        let buffer = Arc::new(Mutex::new(Vec::<f32>::new()));
        let sequence_counter = Arc::clone(&self.sequence_counter);

        let stream = match supported_config.sample_format() {
            SampleFormat::I8 => self.create_stream::<i8>(
                &device,
                &stream_config,
                sender,
                buffer,
                sequence_counter,
                chunk_duration_samples,
            )?,
            SampleFormat::I16 => self.create_stream::<i16>(
                &device,
                &stream_config,
                sender,
                buffer,
                sequence_counter,
                chunk_duration_samples,
            )?,
            SampleFormat::U8 => self.create_stream::<u8>(
                &device,
                &stream_config,
                sender,
                buffer,
                sequence_counter,
                chunk_duration_samples,
            )?,
            SampleFormat::U16 => self.create_stream::<u16>(
                &device,
                &stream_config,
                sender,
                buffer,
                sequence_counter,
                chunk_duration_samples,
            )?,
            SampleFormat::F32 => self.create_stream::<f32>(
                &device,
                &stream_config,
                sender,
                buffer,
                sequence_counter,
                chunk_duration_samples,
            )?,
            _ => {
                return Err(anyhow!(
                    "Unsupported sample format: {:?}",
                    supported_config.sample_format()
                ));
            }
        };

        self.device = Some(device);
        self.stream = Some(stream);

        Ok(())
    }

    /// Create audio stream for a specific sample type
    fn create_stream<T>(
        &self,
        device: &Device,
        config: &StreamConfig,
        sender: Sender<AudioChunk>,
        buffer: Arc<Mutex<Vec<f32>>>,
        sequence_counter: Arc<Mutex<u64>>,
        chunk_duration_samples: u64,
    ) -> Result<Stream>
    where
        T: cpal::Sample + cpal::SizedSample + ToPrimitive,
    {
        let config_clone = self.config.clone();

        let stream = device.build_input_stream(
            config,
            move |data: &[T], _: &cpal::InputCallbackInfo| {
                // Convert samples to f32 using ToPrimitive trait
                let samples: Vec<f32> = data.iter().filter_map(|&s| s.to_f32()).collect();

                // Add to buffer
                {
                    let mut buffer = buffer.lock().unwrap();
                    buffer.extend_from_slice(&samples);

                    // Check if we have enough samples for a chunk
                    if buffer.len() >= chunk_duration_samples as usize {
                        let chunk_data = buffer.drain(..chunk_duration_samples as usize).collect();

                        // Get next sequence number
                        let sequence = {
                            let mut counter = sequence_counter.lock().unwrap();
                            *counter += 1;
                            *counter
                        };

                        let chunk = AudioChunk {
                            data: chunk_data,
                            timestamp: Instant::now(),
                            sample_rate: config_clone.sample_rate,
                            channels: config_clone.channels,
                            sequence,
                        };

                        // Send chunk (ignore errors if receiver is dropped)
                        let _ = sender.send(chunk);
                    }
                }
            },
            |err| eprintln!("🚨 Audio stream error: {}", err),
            None,
        )?;

        Ok(stream)
    }

    /// Start audio capture
    pub fn start(&mut self) -> Result<()> {
        if self.stream.is_none() {
            return Err(anyhow!("Audio capture not initialized"));
        }

        self.stream.as_ref().unwrap().play()?;
        println!("♪ Audio capture started");
        Ok(())
    }

    /// Stop audio capture
    pub fn stop(&mut self) -> Result<()> {
        if let Some(stream) = &self.stream {
            stream.pause()?;
            println!("■ Audio capture stopped");
        }
        Ok(())
    }

    /// Get the next audio chunk (blocking)
    pub fn next_chunk(&self) -> Result<AudioChunk> {
        self.chunk_receiver
            .as_ref()
            .ok_or_else(|| anyhow!("Audio capture not initialized"))?
            .recv()
            .map_err(|e| anyhow!("Failed to receive audio chunk: {}", e))
    }

    /// Try to get the next audio chunk (non-blocking)
    pub fn try_next_chunk(&self) -> Result<Option<AudioChunk>> {
        match self
            .chunk_receiver
            .as_ref()
            .ok_or_else(|| anyhow!("Audio capture not initialized"))?
            .try_recv()
        {
            Ok(chunk) => Ok(Some(chunk)),
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(mpsc::TryRecvError::Disconnected) => {
                Err(anyhow!("Audio capture channel disconnected"))
            }
        }
    }

    /// Get audio configuration
    pub fn config(&self) -> &AudioConfig {
        &self.config
    }
}

#[cfg(feature = "audio")]
#[cfg_attr(docsrs, doc(cfg(feature = "audio")))]
impl Drop for AudioCapture {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

// Feature-disabled implementation: returns errors when audio feature is not compiled
#[cfg(not(feature = "audio"))]
/// Audio capture (feature-disabled: returns errors when audio feature is not compiled)
pub struct AudioCapture {
    _config: AudioConfig,
}

#[cfg(not(feature = "audio"))]
impl AudioCapture {
    /// Create a new audio capture instance (feature-disabled)
    pub fn new(_config: AudioConfig) -> Result<Self> {
        Err(anyhow!(
            "Audio capture not available - this binary was compiled without audio support.\n\
            To enable audio capture:\n\
            1. Install audio libraries: sudo apt install libasound2-dev pkg-config\n\
            2. Rebuild with audio feature: cargo build --features audio\n\
            3. Or use default build (audio enabled by default): cargo build"
        ))
    }

    /// List available audio input devices (feature-disabled)
    pub fn list_devices(&self) -> Result<Vec<String>> {
        Err(anyhow!(
            "Audio capture not available - audio feature not enabled"
        ))
    }

    /// Initialize the audio device and stream (feature-disabled)
    pub fn initialize(&mut self) -> Result<()> {
        Err(anyhow!(
            "Audio capture not available - audio feature not enabled"
        ))
    }

    /// Start audio capture (feature-disabled)
    pub fn start(&mut self) -> Result<()> {
        Err(anyhow!(
            "Audio capture not available - audio feature not enabled"
        ))
    }

    /// Stop audio capture (feature-disabled)
    pub fn stop(&mut self) -> Result<()> {
        Ok(()) // No-op for feature-disabled
    }

    /// Get the next audio chunk (feature-disabled)
    pub fn next_chunk(&self) -> Result<AudioChunk> {
        Err(anyhow!(
            "Audio capture not available - audio feature not enabled"
        ))
    }

    /// Try to get the next audio chunk (feature-disabled)
    pub fn try_next_chunk(&self) -> Result<Option<AudioChunk>> {
        Err(anyhow!(
            "Audio capture not available - audio feature not enabled"
        ))
    }

    /// Get audio configuration (feature-disabled)
    pub fn config(&self) -> &AudioConfig {
        &self._config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audio_config_default() {
        let config = AudioConfig::default();
        assert_eq!(config.sample_rate, 44100);
        assert_eq!(config.channels, 1);
        assert_eq!(config.chunk_duration_ms, 1000);
    }

    #[test]
    fn test_audio_chunk_to_from_bytes() {
        let chunk = AudioChunk {
            data: vec![0.1, -0.5, 0.8, -0.2],
            timestamp: Instant::now(),
            sample_rate: 44100,
            channels: 1,
            sequence: 1,
        };

        let bytes = chunk.to_bytes();
        let restored = AudioChunk::from_bytes(&bytes, 44100, 1, 1).unwrap();

        assert_eq!(chunk.data.len(), restored.data.len());
        for (original, restored) in chunk.data.iter().zip(restored.data.iter()) {
            assert!((original - restored).abs() < f32::EPSILON);
        }
    }

    #[test]
    #[cfg(feature = "audio")]
    fn test_list_devices() {
        let config = AudioConfig::default();
        let capture = AudioCapture::new(config).unwrap();

        // This might fail in CI environments without audio devices
        match capture.list_devices() {
            Ok(devices) => {
                println!("Available audio devices: {:?}", devices);
            }
            Err(e) => {
                println!("No audio devices available (expected in CI): {}", e);
            }
        }
    }

    #[test]
    #[cfg(not(feature = "audio"))]
    fn test_audio_feature_disabled() {
        let config = AudioConfig::default();
        match AudioCapture::new(config) {
            Err(e) => {
                assert!(e.to_string().contains("Audio capture not available"));
            }
            Ok(_) => panic!("Expected error when audio feature disabled"),
        }
    }
}
