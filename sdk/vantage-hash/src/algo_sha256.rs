use sha2::{Digest, Sha256};

/// Compute a SHA-256 digest (32 bytes) of `content`.
///
/// SHA-256 is the NIST-standardised algorithm and maps to the TDS
/// **minute-hand** tier. It is the primary WORM chain hash algorithm.
///
/// The byte output is identical to a standalone `sha256(content)` computation
/// and can be extracted from a `TripleHash` for regulatory / interoperability use.
pub(crate) fn compute(content: &[u8]) -> [u8; 32] {
    Sha256::digest(content).into()
}
