const PRE_EMPHASIS: f32 = 0.97;
const N_MELS:       usize = 26;

/// Extract MFCC features from raw PCM samples.
///
/// Pipeline: pre-emphasis → frame → Hamming window → FFT magnitude
///           → mel filterbank → log → DCT.
pub fn extract_mfcc(samples: &[f32], sample_rate: u32, n_mfcc: usize) -> Vec<Vec<f32>> {
    let frame_len  = (sample_rate as usize * 25) / 1000; // 25 ms
    let frame_step = (sample_rate as usize * 10) / 1000; // 10 ms shift

    let emphasized = pre_emphasis(samples);
    let frames     = frame(&emphasized, frame_len, frame_step);
    let windowed   = hamming_window(&frames);
    let magnitudes = fft_magnitude(&windowed);
    let mel        = mel_filterbank(&magnitudes, sample_rate, N_MELS);
    let log_mel    = log_compress(&mel);
    dct(&log_mel, n_mfcc)
}

fn pre_emphasis(samples: &[f32]) -> Vec<f32> {
    if samples.is_empty() {
        return vec![];
    }
    let mut out = Vec::with_capacity(samples.len());
    out.push(samples[0]);
    for i in 1..samples.len() {
        out.push(samples[i] - PRE_EMPHASIS * samples[i - 1]);
    }
    out
}

fn frame(samples: &[f32], frame_len: usize, frame_step: usize) -> Vec<Vec<f32>> {
    if samples.len() < frame_len {
        return vec![];
    }
    let n_frames = 1 + (samples.len() - frame_len) / frame_step;
    (0..n_frames)
        .map(|i| samples[i * frame_step..i * frame_step + frame_len].to_vec())
        .collect()
}

fn hamming_window(frames: &[Vec<f32>]) -> Vec<Vec<f32>> {
    frames
        .iter()
        .map(|f| {
            let n = f.len();
            f.iter()
                .enumerate()
                .map(|(i, &s)| {
                    let w = 0.54 - 0.46 * (2.0 * std::f32::consts::PI * i as f32 / (n - 1) as f32).cos();
                    s * w
                })
                .collect()
        })
        .collect()
}

/// Computes approximate DFT magnitude via a naive O(N²) approach.
/// Acceptable for fingerprinting stubs; replace with a real FFT for production.
fn fft_magnitude(frames: &[Vec<f32>]) -> Vec<Vec<f32>> {
    frames
        .iter()
        .map(|f| {
            let n = f.len();
            let half = n / 2 + 1;
            (0..half)
                .map(|k| {
                    let (mut re, mut im) = (0.0_f32, 0.0_f32);
                    for (j, &x) in f.iter().enumerate() {
                        let angle = -2.0 * std::f32::consts::PI * k as f32 * j as f32 / n as f32;
                        re += x * angle.cos();
                        im += x * angle.sin();
                    }
                    (re * re + im * im).sqrt()
                })
                .collect()
        })
        .collect()
}

fn hz_to_mel(hz: f32) -> f32 {
    2595.0 * (1.0 + hz / 700.0).log10()
}

fn mel_to_hz(mel: f32) -> f32 {
    700.0 * (10.0_f32.powf(mel / 2595.0) - 1.0)
}

fn mel_filterbank(magnitudes: &[Vec<f32>], sample_rate: u32, n_mels: usize) -> Vec<Vec<f32>> {
    if magnitudes.is_empty() {
        return vec![];
    }
    let n_fft   = magnitudes[0].len();
    let mel_min = hz_to_mel(0.0);
    let mel_max = hz_to_mel(sample_rate as f32 / 2.0);
    let mel_pts: Vec<f32> = (0..=n_mels + 1)
        .map(|i| mel_to_hz(mel_min + (mel_max - mel_min) * i as f32 / (n_mels + 1) as f32))
        .collect();

    let bin: Vec<usize> = mel_pts
        .iter()
        .map(|&hz| {
            let b = ((n_fft as f32 * 2.0 - 2.0) * hz / sample_rate as f32).round() as usize;
            b.min(n_fft - 1)
        })
        .collect();

    let filters: Vec<Vec<f32>> = (0..n_mels)
        .map(|m| {
            (0..n_fft)
                .map(|k| {
                    if k < bin[m] || k > bin[m + 2] {
                        0.0
                    } else if k <= bin[m + 1] {
                        (k - bin[m]) as f32 / (bin[m + 1] - bin[m] + 1) as f32
                    } else {
                        (bin[m + 2] - k) as f32 / (bin[m + 2] - bin[m + 1] + 1) as f32
                    }
                })
                .collect()
        })
        .collect();

    magnitudes
        .iter()
        .map(|mag| {
            filters
                .iter()
                .map(|filt| filt.iter().zip(mag.iter()).map(|(f, m)| f * m).sum())
                .collect()
        })
        .collect()
}

fn log_compress(frames: &[Vec<f32>]) -> Vec<Vec<f32>> {
    frames
        .iter()
        .map(|f| f.iter().map(|&v| (v + 1e-10).ln()).collect())
        .collect()
}

/// Type-II DCT, returns the first `n_mfcc` coefficients per frame.
fn dct(frames: &[Vec<f32>], n_mfcc: usize) -> Vec<Vec<f32>> {
    frames
        .iter()
        .map(|f| {
            let n = f.len();
            (0..n_mfcc.min(n))
                .map(|k| {
                    let scale = if k == 0 { 1.0 / (n as f32).sqrt() } else { (2.0 / n as f32).sqrt() };
                    scale * f.iter().enumerate().map(|(j, &x)| {
                        x * (std::f32::consts::PI * k as f32 * (2 * j + 1) as f32 / (2 * n) as f32).cos()
                    }).sum::<f32>()
                })
                .collect()
        })
        .collect()
}
