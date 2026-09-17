use alloc::string::String;
use core::fmt;

use crate::transport::TransportError;

/// Top-level error for [`crate::submit_kerkese`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KerkeseError {
    /// Failed to JSON-encode the outgoing [`crate::Kerkese`].
    Encode(String),
    /// The transport failed to deliver the request or get a usable response.
    Transport(TransportError),
    /// The transport returned bytes, but they didn't decode as a MARSHAL
    /// [`crate::Decision`].
    Decode(String),
}

impl fmt::Display for KerkeseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KerkeseError::Encode(e) => write!(f, "encoding kerkese: {e}"),
            KerkeseError::Transport(e) => write!(f, "submitting kerkese: {e}"),
            KerkeseError::Decode(e) => write!(f, "decoding decision: {e}"),
        }
    }
}
