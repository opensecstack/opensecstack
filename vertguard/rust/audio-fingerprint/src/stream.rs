use crate::{fingerprint, AudioFingerprint, Error};

/// Minimum samples needed before emitting a fingerprint (3 seconds).
const MIN_SECONDS: u64 = 3;

/// Accumulates audio chunks and emits a fingerprint once enough data
/// is collected.
pub struct StreamProcessor {
    sample_rate: u32,
    chunk_size:  usize,
    buffer:      Vec<f32>,
    min_samples: usize,
}

impl StreamProcessor {
    pub fn new(sample_rate: u32, chunk_size: usize) -> Self {
        let min_samples = sample_rate as usize * MIN_SECONDS as usize;
        Self {
            sample_rate,
            chunk_size,
            buffer: Vec::with_capacity(min_samples * 2),
            min_samples,
        }
    }

    /// Feed a chunk of samples. Returns a fingerprint once `MIN_SECONDS`
    /// of audio has accumulated; the internal buffer is then drained.
    pub fn process_chunk(&mut self, samples: &[f32]) -> Option<AudioFingerprint> {
        self.buffer.extend_from_slice(samples);

        if self.buffer.len() < self.min_samples {
            return None;
        }

        let window: Vec<f32> = self.buffer.drain(..self.min_samples).collect();
        fingerprint(&window, self.sample_rate).ok()
    }

    pub fn sample_rate(&self) -> u32   { self.sample_rate }
    pub fn chunk_size(&self)  -> usize { self.chunk_size  }
    pub fn buffered(&self)    -> usize { self.buffer.len() }
}
