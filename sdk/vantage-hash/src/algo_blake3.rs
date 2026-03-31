/// Compute a BLAKE3 digest (32 bytes) of `content`.
///
/// BLAKE3 is the fastest of the three TripleHash algorithms and maps to the
/// TDS **second-hand** tier — suitable for per-request, real-time integrity checks.
pub(crate) fn compute(content: &[u8]) -> [u8; 32] {
    *blake3::hash(content).as_bytes()
}
