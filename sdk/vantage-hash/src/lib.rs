//! `vantage-hash` — CITADEL's TripleHash composite digest.
//!
//! ```text
//! TripleHash(content) = BLAKE3(content)  ||  SHA-256(content)  ||  SHA-512(content)
//!                       [32 bytes]            [32 bytes]             [64 bytes]
//!                       ═══════════════════════════════════════════════════════════
//!                       128 bytes total  (256 hex chars on the wire)
//! ```
//!
//! ## TDS alignment
//!
//! | Algorithm | Digest  | TDS tier    | Use case                          |
//! |-----------|---------|-------------|-----------------------------------|
//! | BLAKE3    | 32 B    | Second hand | Per-request / real-time integrity  |
//! | SHA-256   | 32 B    | Minute hand | WORM chain hashing (primary)       |
//! | SHA-512   | 64 B    | Hour hand   | Anchor signing / archival          |
//!
//! ## Quick start
//!
//! ```rust
//! use vantage_hash::TripleHash;
//!
//! let content = b"Kerkese payload";
//! let hash = TripleHash::compute(content);
//!
//! println!("BLAKE3:  {}", hash.blake3_hex());
//! println!("SHA-256: {}", hash.sha256_hex());
//! println!("SHA-512: {}", hash.sha512_hex());
//! println!("Full:    {}", hash.hex());          // 256 hex chars
//!
//! assert!(TripleHash::verify(content, &hash));
//! ```

mod algo_blake3;
mod algo_sha256;
mod algo_sha512;

pub mod tds;

use serde::{Deserialize, Serialize};

// ── Error ─────────────────────────────────────────────────────────────────────

/// Errors from [`TripleHash`] decoding operations.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// The full-hex string was not exactly 256 characters.
    InvalidLength { got: usize },

    /// One JSON component field decoded to the wrong number of bytes.
    InvalidComponentLength {
        component: &'static str,
        expected: usize,
        got: usize,
    },

    /// Hex decoding of a component failed (message is the hex error description).
    HexDecode {
        component: &'static str,
        message: String,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidLength { got } => {
                write!(f, "invalid length: expected 256 hex chars, got {got}")
            }
            Error::InvalidComponentLength {
                component,
                expected,
                got,
            } => {
                write!(
                    f,
                    "invalid {component} length: expected {expected} bytes, got {got}"
                )
            }
            Error::HexDecode { component, message } => {
                write!(f, "hex decode error in {component}: {message}")
            }
        }
    }
}

impl std::error::Error for Error {}

// ── TripleHash ─────────────────────────────────────────────────────────────────

/// A 128-byte composite digest produced by three independent hash algorithms.
///
/// Layout (fixed):
/// ```text
/// bytes   0 ..  32  →  BLAKE3(content)   (32 bytes)
/// bytes  32 ..  64  →  SHA-256(content)  (32 bytes)
/// bytes  64 .. 128  →  SHA-512(content)  (64 bytes)
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct TripleHash {
    inner: [u8; 128],
}

impl TripleHash {
    // ── Construction ──────────────────────────────────────────────────────────

    /// Compute a `TripleHash` from arbitrary `content`.
    ///
    /// All three algorithms run independently; any failure in one does not
    /// affect the others.
    pub fn compute(content: &[u8]) -> Self {
        let b3 = algo_blake3::compute(content);
        let s2 = algo_sha256::compute(content);
        let s5 = algo_sha512::compute(content);

        let mut inner = [0u8; 128];
        inner[0..32].copy_from_slice(&b3);
        inner[32..64].copy_from_slice(&s2);
        inner[64..128].copy_from_slice(&s5);

        TripleHash { inner }
    }

    /// Verify that `content` produces this `TripleHash`.
    ///
    /// All 128 bytes are compared. Returns `false` if any single component
    /// does not match. The comparison is performed in constant time to avoid
    /// timing side-channels.
    pub fn verify(content: &[u8], expected: &TripleHash) -> bool {
        let actual = Self::compute(content);
        // Constant-time comparison: XOR each byte and accumulate differences.
        // A short-circuit `==` would leak how many bytes match.
        let mut diff = 0u8;
        for (a, b) in actual.inner.iter().zip(expected.inner.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }

    /// Decode a `TripleHash` from a 256-character hexadecimal string
    /// (the full 128-byte wire format produced by [`Self::hex`]).
    pub fn from_hex(s: &str) -> Result<Self, Error> {
        if s.len() != 256 {
            return Err(Error::InvalidLength { got: s.len() });
        }
        let bytes = hex::decode(s).map_err(|e| Error::HexDecode {
            component: "full",
            message: e.to_string(),
        })?;
        let mut inner = [0u8; 128];
        inner.copy_from_slice(&bytes);
        Ok(TripleHash { inner })
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    /// The raw 128-byte digest.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; 128] {
        &self.inner
    }

    /// Full 256-character hex encoding of all 128 bytes.
    ///
    /// Layout: `blake3_hex (64) | sha256_hex (64) | sha512_hex (128)`
    pub fn hex(&self) -> String {
        hex::encode(&self.inner)
    }

    /// BLAKE3 component — 64 hex characters (32 bytes).
    pub fn blake3_hex(&self) -> String {
        hex::encode(&self.inner[0..32])
    }

    /// SHA-256 component — 64 hex characters (32 bytes).
    ///
    /// This is identical to a standalone `sha256(content)` digest and can be
    /// extracted by regulators / auditors who require standard SHA-256 output.
    pub fn sha256_hex(&self) -> String {
        hex::encode(&self.inner[32..64])
    }

    /// SHA-512 component — 128 hex characters (64 bytes).
    pub fn sha512_hex(&self) -> String {
        hex::encode(&self.inner[64..128])
    }

    /// BLAKE3 raw bytes (32 bytes).
    pub fn blake3_bytes(&self) -> &[u8; 32] {
        self.inner[0..32]
            .try_into()
            .expect("slice is exactly 32 bytes")
    }

    /// SHA-256 raw bytes (32 bytes).
    pub fn sha256_bytes(&self) -> &[u8; 32] {
        self.inner[32..64]
            .try_into()
            .expect("slice is exactly 32 bytes")
    }

    /// SHA-512 raw bytes (64 bytes).
    pub fn sha512_bytes(&self) -> &[u8; 64] {
        self.inner[64..128]
            .try_into()
            .expect("slice is exactly 64 bytes")
    }
}

// ── Formatting ────────────────────────────────────────────────────────────────

impl std::fmt::Debug for TripleHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TripleHash")
            .field("blake3", &self.blake3_hex())
            .field("sha256", &self.sha256_hex())
            .field("sha512", &self.sha512_hex())
            .finish()
    }
}

impl std::fmt::Display for TripleHash {
    /// Short fingerprint: first 16 hex chars of the BLAKE3 component followed by "…".
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}…", &self.blake3_hex()[..16])
    }
}

// ── Serde ─────────────────────────────────────────────────────────────────────
//
// Wire format:
//   { "blake3": "<64 hex>", "sha256": "<64 hex>", "sha512": "<128 hex>" }

impl Serialize for TripleHash {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = s.serialize_struct("TripleHash", 3)?;
        st.serialize_field("blake3", &self.blake3_hex())?;
        st.serialize_field("sha256", &self.sha256_hex())?;
        st.serialize_field("sha512", &self.sha512_hex())?;
        st.end()
    }
}

impl<'de> Deserialize<'de> for TripleHash {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Repr {
            blake3: String,
            sha256: String,
            sha512: String,
        }
        let r = Repr::deserialize(d)?;

        let b3 = hex::decode(&r.blake3)
            .map_err(|e| serde::de::Error::custom(format!("blake3 hex: {e}")))?;
        let s2 = hex::decode(&r.sha256)
            .map_err(|e| serde::de::Error::custom(format!("sha256 hex: {e}")))?;
        let s5 = hex::decode(&r.sha512)
            .map_err(|e| serde::de::Error::custom(format!("sha512 hex: {e}")))?;

        if b3.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "blake3 must be 32 bytes, got {}",
                b3.len()
            )));
        }
        if s2.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "sha256 must be 32 bytes, got {}",
                s2.len()
            )));
        }
        if s5.len() != 64 {
            return Err(serde::de::Error::custom(format!(
                "sha512 must be 64 bytes, got {}",
                s5.len()
            )));
        }

        let mut inner = [0u8; 128];
        inner[0..32].copy_from_slice(&b3);
        inner[32..64].copy_from_slice(&s2);
        inner[64..128].copy_from_slice(&s5);

        Ok(TripleHash { inner })
    }
}
