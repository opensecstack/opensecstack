use sha2::{Digest, Sha512};

/// Compute a SHA-512 digest (64 bytes) of `content`.
///
/// SHA-512 provides the largest digest and strongest collision resistance,
/// mapping to the TDS **hour-hand** tier — used for long-term archival and
/// Ed25519 anchor signing.
pub(crate) fn compute(content: &[u8]) -> [u8; 64] {
    Sha512::digest(content).into()
}
