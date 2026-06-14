/// Spectral centroid — frequency-weighted mean of the magnitude spectrum.
pub fn spectral_centroid(samples: &[f32], sample_rate: u32) -> f32 {
    if samples.is_empty() {
        return 0.0;
    }
    let n         = samples.len();
    let half      = n / 2 + 1;
    let bin_hz    = sample_rate as f32 / n as f32;

    let (mut weighted, mut total) = (0.0_f32, 0.0_f32);
    for k in 0..half {
        let (mut re, mut im) = (0.0_f32, 0.0_f32);
        for (j, &x) in samples.iter().enumerate() {
            let angle = -2.0 * std::f32::consts::PI * k as f32 * j as f32 / n as f32;
            re += x * angle.cos();
            im += x * angle.sin();
        }
        let mag = (re * re + im * im).sqrt();
        weighted += k as f32 * bin_hz * mag;
        total    += mag;
    }
    if total < 1e-10 { 0.0 } else { weighted / total }
}

/// Spectral flux — L1 distance between consecutive magnitude frames.
pub fn spectral_flux(frames: &[Vec<f32>]) -> Vec<f32> {
    if frames.len() < 2 {
        return vec![0.0; frames.len()];
    }
    let mut flux = vec![0.0_f32];
    for w in frames.windows(2) {
        let diff: f32 = w[0]
            .iter()
            .zip(w[1].iter())
            .map(|(a, b)| (b - a).abs())
            .sum();
        flux.push(diff);
    }
    flux
}

/// Encodes centroid + flux statistics as a short hex string.
pub fn spectral_hash(centroid: f32, flux: &[f32]) -> String {
    let flux_mean = if flux.is_empty() {
        0.0_f32
    } else {
        flux.iter().sum::<f32>() / flux.len() as f32
    };
    let flux_max = flux.iter().cloned().fold(0.0_f32, f32::max);

    // Pack four f32 fields into bytes then hex-encode — cheap, deterministic.
    let mut bytes = [0u8; 16];
    bytes[0..4].copy_from_slice(&centroid.to_le_bytes());
    bytes[4..8].copy_from_slice(&flux_mean.to_le_bytes());
    bytes[8..12].copy_from_slice(&flux_max.to_le_bytes());
    bytes[12..16].copy_from_slice(&(flux.len() as u32).to_le_bytes());

    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
