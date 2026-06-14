//! VertGuard triple-hash — SHA-256 + SHA-512 + BLAKE3 in one pass.
//!
//! STATUS: Phase 4.2 scaffold. All three digests are computed over a
//! single linear scan of `data` using an update-based API so large
//! buffers are not copied.
//!
//! See `docs/vantage-hash-bridge.md`.

use blake3::Hasher as Blake3Hasher;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};

/// Three digests computed from the same input.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct TripleHash {
    pub sha256: String,
    pub sha512: String,
    pub blake3: String,
}

/// Compute all three hashes in a single pass; returns raw byte strings
/// encoded as lowercase hex.
pub fn hash(data: &[u8]) -> TripleHash {
    hash_hex(data)
}

/// Compute all three hashes; returns hex-encoded digest strings.
pub fn hash_hex(data: &[u8]) -> TripleHash {
    let mut sha256  = Sha256::new();
    let mut sha512  = Sha512::new();
    let mut b3      = Blake3Hasher::new();

    // Single pass — feed all three hashers from the same slice.
    sha256.update(data);
    sha512.update(data);
    b3.update(data);

    TripleHash {
        sha256: hex::encode(sha256.finalize()),
        sha512: hex::encode(sha512.finalize()),
        blake3: b3.finalize().to_hex().to_string(),
    }
}

/// Verify that `data` reproduces every digest in `expected`.
pub fn verify(data: &[u8], expected: &TripleHash) -> bool {
    let got = hash_hex(data);
    got == *expected
}

impl TripleHash {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HELLO: &[u8] = b"hello world";

    #[test]
    fn hash_produces_non_empty_digests() {
        let th = hash(HELLO);
        assert_eq!(th.sha256.len(), 64);
        assert_eq!(th.sha512.len(), 128);
        assert_eq!(th.blake3.len(), 64);
    }

    #[test]
    fn hash_is_deterministic() {
        assert_eq!(hash(HELLO), hash(HELLO));
    }

    #[test]
    fn verify_passes_for_correct_data() {
        let th = hash(HELLO);
        assert!(verify(HELLO, &th));
    }

    #[test]
    fn verify_fails_for_wrong_data() {
        let th = hash(HELLO);
        assert!(!verify(b"goodbye world", &th));
    }

    #[test]
    fn to_json_round_trips() {
        let th   = hash(HELLO);
        let json = th.to_json();
        let got: TripleHash = serde_json::from_str(&json).expect("deserialize failed");
        assert_eq!(th, got);
    }

    #[test]
    fn empty_input_is_handled() {
        let th = hash(b"");
        assert!(!th.sha256.is_empty());
    }
}
