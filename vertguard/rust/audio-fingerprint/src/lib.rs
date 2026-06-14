//! VertGuard audio fingerprinting — MFCC + spectral analysis.
//!
//! STATUS: Phase 4.2 scaffold. Computes a deterministic fingerprint
//! from raw PCM samples using a simplified MFCC pipeline and spectral
//! statistics. The `StreamProcessor` accumulates chunks and emits
//! fingerprints in real time.
//!
//! See `docs/module-1-media-authenticity.md`.

pub mod error;
pub mod mfcc;
pub mod spectral;
pub mod stream;

pub use error::Error;
pub use stream::StreamProcessor;

use serde::{Deserialize, Serialize};

const MIN_SAMPLES: usize = 1024;
const N_MFCC:      usize = 13;

/// Compact audio fingerprint.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AudioFingerprint {
    pub mfcc_hash:    String,
    pub spectral_hash: String,
    pub duration_ms:  u64,
}

/// Compute an `AudioFingerprint` from raw PCM `samples` at `sample_rate` Hz.
pub fn fingerprint(samples: &[f32], sample_rate: u32) -> Result<AudioFingerprint, Error> {
    if sample_rate == 0 {
        return Err(Error::InvalidInput("sample_rate must be > 0".into()));
    }
    if samples.len() < MIN_SAMPLES {
        return Err(Error::InsufficientData(MIN_SAMPLES));
    }

    let mfcc_frames = mfcc::extract_mfcc(samples, sample_rate, N_MFCC);
    if mfcc_frames.is_empty() {
        return Err(Error::ProcessingFailure("MFCC produced no frames".into()));
    }
    let mfcc_hash = mfcc_hash(&mfcc_frames);

    let centroid  = spectral::spectral_centroid(samples, sample_rate);
    let flux      = spectral::spectral_flux(&mfcc_frames);
    let spec_hash = spectral::spectral_hash(centroid, &flux);

    let duration_ms = (samples.len() as u64 * 1000) / sample_rate as u64;

    Ok(AudioFingerprint {
        mfcc_hash:    mfcc_hash,
        spectral_hash: spec_hash,
        duration_ms,
    })
}

/// Encodes mean MFCC vector as a hex string.
fn mfcc_hash(frames: &[Vec<f32>]) -> String {
    let n_coeffs = frames[0].len();
    let mut means = vec![0.0_f32; n_coeffs];
    for f in frames {
        for (i, &v) in f.iter().enumerate() {
            means[i] += v;
        }
    }
    let count = frames.len() as f32;
    let mut bytes = Vec::with_capacity(n_coeffs * 4);
    for m in &mut means {
        *m /= count;
        bytes.extend_from_slice(&m.to_le_bytes());
    }
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sine(freq: f32, sr: u32, n: usize) -> Vec<f32> {
        (0..n)
            .map(|i| (2.0 * std::f32::consts::PI * freq * i as f32 / sr as f32).sin())
            .collect()
    }

    #[test]
    fn fingerprint_returns_ok_for_sufficient_data() {
        let samples = sine(440.0, 16000, 16000);
        let fp = fingerprint(&samples, 16000).expect("fingerprint failed");
        assert!(!fp.mfcc_hash.is_empty());
        assert!(!fp.spectral_hash.is_empty());
        assert_eq!(fp.duration_ms, 1000);
    }

    #[test]
    fn fingerprint_rejects_insufficient_data() {
        let samples = vec![0.0f32; 16];
        assert!(fingerprint(&samples, 16000).is_err());
    }

    #[test]
    fn fingerprint_rejects_zero_sample_rate() {
        let samples = vec![0.0f32; 16000];
        assert!(fingerprint(&samples, 0).is_err());
    }

    #[test]
    fn stream_processor_emits_after_three_seconds() {
        let sr = 16000_u32;
        let mut proc = StreamProcessor::new(sr, 1024);
        let chunk = sine(440.0, sr, 1024);
        let mut emitted = None;
        for _ in 0..50 {
            emitted = proc.process_chunk(&chunk);
            if emitted.is_some() {
                break;
            }
        }
        assert!(emitted.is_some(), "expected fingerprint after 3 s of audio");
    }
}
