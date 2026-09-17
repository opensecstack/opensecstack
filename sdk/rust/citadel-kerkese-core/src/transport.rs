//! The transport boundary: this crate builds and signs Kerkese envelopes
//! and parses Decisions, but performs **no I/O** itself — no HTTP, no TLS,
//! no sockets. Callers supply the real transport by implementing
//! [`KerkeseTransport`], the same "runtime interface" split
//! `sp-runtime-interface`/`sp-io` uses in Substrate: the no_std/deterministic
//! core declares the *shape* of the host call it needs, and whatever
//! std/async environment hosts it (a Tokio-backed HTTP client, a
//! kernel-mode network stack, a mock in a unit test) supplies the
//! implementation.

use alloc::string::String;
use alloc::vec::Vec;

/// Transport-level failure submitting an envelope to MARSHAL. Deliberately
/// coarse — this crate doesn't know or care whether the underlying
/// transport is HTTP, a Unix socket, or a kernel IPC channel, so it can't
/// usefully distinguish e.g. "DNS failure" from "connection refused". The
/// caller's `KerkeseTransport` impl is free to log/expose richer detail on
/// its own side; only a coarse category crosses back into this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// The transport could not deliver the request at all (connection
    /// refused, no route, link down, etc).
    Unreachable(String),
    /// The transport delivered the request but did not get a usable
    /// response back in time.
    Timeout,
    /// The transport delivered the request and got a response, but the
    /// response was not a well-formed MARSHAL Decision (e.g. non-2xx HTTP
    /// status, or a body this crate's caller couldn't otherwise interpret).
    BadResponse(String),
    /// Anything else, with a caller-supplied description.
    Other(String),
}

impl core::fmt::Display for TransportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TransportError::Unreachable(msg) => write!(f, "transport unreachable: {msg}"),
            TransportError::Timeout => f.write_str("transport timed out"),
            TransportError::BadResponse(msg) => write!(f, "bad response from transport: {msg}"),
            TransportError::Other(msg) => write!(f, "transport error: {msg}"),
        }
    }
}

/// A caller-supplied transport for submitting a serialized Kerkese envelope
/// and getting a serialized Decision back, synchronously.
///
/// Implementations own all actual I/O (HTTP, TLS, retries, timeouts) — this
/// trait's contract is just "hand these bytes to MARSHAL, hand me back
/// whatever bytes it returned for a successful exchange, or tell me why you
/// couldn't". `submit` takes `&self` and returns synchronously (no `async
/// fn`) specifically so this crate has no executor/reactor dependency; a
/// caller in an async host environment is expected to block internally
/// (e.g. `Handle::block_on`) inside its own `submit` implementation.
pub trait KerkeseTransport {
    /// Submits `envelope_bytes` (a JSON-encoded [`crate::Kerkese`]) to
    /// MARSHAL and returns the raw response body bytes (expected to decode
    /// as a JSON [`crate::Decision`]) on success.
    fn submit(&self, envelope_bytes: &[u8]) -> Result<Vec<u8>, TransportError>;
}
