//! Minimal UUID type matching Go's `github.com/google/uuid.UUID` on the
//! wire: a 16-byte value, JSON-encoded as (and parsed from) the canonical
//! lowercase, hyphenated `8-4-4-4-12` string form. `internal/marshal/types.go`
//! uses `uuid.UUID` for `Kerkese.ExecutionID` and `Decision.ExecutionID`/
//! `WORMEntryID` — this type exists only to round-trip that JSON shape
//! without pulling in the full `uuid` crate (which assumes an OS RNG by
//! default and is not obviously no_std-friendly across all its features).
//!
//! This crate does not generate random UUIDs itself — a no_std freestanding
//! kernel has no portable source of randomness this crate can assume. Build
//! one from caller-supplied bytes (e.g. from a hardware RNG, or minted
//! host-side) via [`Uuid::from_bytes`].

use alloc::string::String;
use core::fmt;
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};

/// A 16-byte UUID, wire-compatible with Go's `uuid.UUID`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct Uuid(pub [u8; 16]);

/// A Kerkese/Decision field with a zero `uuid.UUID` (Go's `uuid.UUID{}`)
/// means "server should mint one" / "not applicable" — see
/// `handlers/marshal.go`'s `if k.ExecutionID == (uuid.UUID{})` check.
pub const NIL: Uuid = Uuid([0u8; 16]);

/// Error returned when parsing a UUID string fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UuidParseError;

impl fmt::Display for UuidParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid UUID string")
    }
}

impl Uuid {
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Uuid(bytes)
    }

    pub const fn is_nil(&self) -> bool {
        let b = self.0;
        let mut i = 0;
        while i < 16 {
            if b[i] != 0 {
                return false;
            }
            i += 1;
        }
        true
    }

    /// Parses the canonical `8-4-4-4-12` hyphenated hex string Go's
    /// `uuid.Parse`/`uuid.MustParse` produce and accept.
    ///
    /// Lenient, not a full validator: this only counts hex digits and
    /// discards every `-` unconditionally, so it doesn't check hyphen
    /// *position* the way Go's stricter canonical-form parser does —
    /// `"00000000-0000000000000000000001"` (32 hex digits, hyphen in the
    /// wrong place) parses successfully here. Harmless today since both
    /// sides of this wire format only ever emit canonically-formatted
    /// UUIDs, but this function should not be trusted as a validator if a
    /// caller ever feeds it untrusted/attacker-controlled input.
    pub fn parse(s: &str) -> Result<Self, UuidParseError> {
        let mut out = [0u8; 16];
        let mut byte_idx = 0;
        let mut nibble: Option<u8> = None;

        for c in s.chars() {
            if c == '-' {
                continue;
            }
            let v = c.to_digit(16).ok_or(UuidParseError)? as u8;
            match nibble.take() {
                None => nibble = Some(v),
                Some(hi) => {
                    if byte_idx >= 16 {
                        return Err(UuidParseError);
                    }
                    out[byte_idx] = (hi << 4) | v;
                    byte_idx += 1;
                }
            }
        }

        if byte_idx != 16 || nibble.is_some() {
            return Err(UuidParseError);
        }
        Ok(Uuid(out))
    }
}

impl fmt::Display for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.0;
        write!(
            f,
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
        )
    }
}

impl Serialize for Uuid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Uuid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Uuid::parse(&s).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn round_trips_canonical_string() {
        let s = "7e9a9a7e-2a1f-4c13-9f60-5a1f2e0d1a98";
        let u = Uuid::parse(s).expect("valid uuid");
        assert_eq!(u.to_string(), s);
    }

    #[test]
    fn matches_go_fixture_uuid() {
        // From citadel/internal/marshal/sig_test.go's fixture.
        let s = "00000000-0000-0000-0000-000000000001";
        let u = Uuid::parse(s).expect("valid uuid");
        assert_eq!(u.0, {
            let mut b = [0u8; 16];
            b[15] = 1;
            b
        });
        assert_eq!(u.to_string(), s);
    }

    #[test]
    fn rejects_malformed_input() {
        assert!(Uuid::parse("not-a-uuid").is_err());
        assert!(Uuid::parse("00000000-0000-0000-0000-00000000000").is_err()); // too short
        assert!(Uuid::parse("00000000-0000-0000-0000-0000000000012").is_err()); // too long
    }
}
