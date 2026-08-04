//! Time Dimension Segmentation (TDS) tier routing.
//!
//! TDS maps an operation's duration to the appropriate hash algorithm tier.
//! Each tier corresponds to one component of [`crate::TripleHash`]:
//!
//! | Tier        | Duration         | Algorithm | TripleHash component |
//! |-------------|------------------|-----------|----------------------|
//! | SecondHand  | < 300 ms         | BLAKE3    | bytes 0..32          |
//! | MinuteHand  | 300 ms – 30 s    | SHA-256   | bytes 32..64         |
//! | HourHand    | > 30 s           | SHA-512   | bytes 64..128        |

use std::time::Duration;

/// A TDS tier, selecting which hash algorithm to use for a given time window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tier {
    /// **Second hand** — operations completing in under 300 ms.
    ///
    /// Uses **BLAKE3**: fastest algorithm, SIMD-optimised, suitable for
    /// per-request real-time integrity verification.
    SecondHand,

    /// **Minute hand** — operations taking 300 ms to 30 s.
    ///
    /// Uses **SHA-256**: NIST-standardised, widest regulatory acceptance.
    /// This is the primary WORM chain hash algorithm.
    MinuteHand,

    /// **Hour hand** — operations taking longer than 30 s.
    ///
    /// Uses **SHA-512**: largest digest (64 bytes), highest collision
    /// resistance. Used for archival storage and Ed25519 anchor signing.
    HourHand,
}

impl Tier {
    /// Select the TDS tier for a given operation duration.
    ///
    /// ```rust
    /// use vantage_hash::tds::Tier;
    /// use std::time::Duration;
    ///
    /// assert_eq!(Tier::for_duration(Duration::from_millis(100)), Tier::SecondHand);
    /// assert_eq!(Tier::for_duration(Duration::from_secs(5)),     Tier::MinuteHand);
    /// assert_eq!(Tier::for_duration(Duration::from_secs(60)),    Tier::HourHand);
    /// ```
    pub fn for_duration(d: Duration) -> Self {
        if d < Duration::from_millis(300) {
            Tier::SecondHand
        } else if d <= Duration::from_secs(30) {
            Tier::MinuteHand
        } else {
            Tier::HourHand
        }
    }

    /// The canonical algorithm name for this tier (used in logs and reports).
    pub fn algorithm_name(self) -> &'static str {
        match self {
            Tier::SecondHand => "BLAKE3",
            Tier::MinuteHand => "SHA-256",
            Tier::HourHand => "SHA-512",
        }
    }

    /// The byte offset range within a [`crate::TripleHash`] for this tier's component.
    ///
    /// Returns `(start, end)` where `hash.as_bytes()[start..end]` is the component.
    pub fn byte_range(self) -> (usize, usize) {
        match self {
            Tier::SecondHand => (0, 32),
            Tier::MinuteHand => (32, 64),
            Tier::HourHand => (64, 128),
        }
    }

    /// The number of bytes in this tier's hash component.
    pub fn digest_len(self) -> usize {
        let (s, e) = self.byte_range();
        e - s
    }
}

impl std::fmt::Display for Tier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.algorithm_name())
    }
}
