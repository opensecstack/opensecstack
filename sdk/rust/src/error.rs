use thiserror::Error;

/// All errors returned by the OpenSecStack SDK.
#[derive(Debug, Error)]
pub enum Error {
    /// The server returned a non-2xx response with a structured error body.
    #[error("API error HTTP {status}: [{code}] {message}")]
    Api {
        status: u16,
        code: String,
        message: String,
    },

    /// Authentication failed (bad credentials or token exchange error).
    #[error("authentication failed: {0}")]
    Auth(String),

    /// The server returned HTTP 429. `retry_after` is parsed from the
    /// `Retry-After` response header (seconds), or 60 if absent.
    #[error("rate limited, retry after {retry_after}s")]
    RateLimit { retry_after: u64 },

    /// The requested resource was not found (HTTP 404).
    #[error("not found: {0}")]
    NotFound(String),

    /// All retry attempts were exhausted without a successful response.
    #[error("request failed after {attempts} attempts: {last_error}")]
    MaxRetriesExceeded {
        attempts: u32,
        last_error: String,
    },

    /// An underlying `reqwest` transport error.
    #[error("HTTP transport error: {0}")]
    Transport(#[from] reqwest::Error),

    /// JSON serialisation / deserialisation error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// I/O error (e.g. reading file for spec upload, writing report stream).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The server returned an unexpected response format.
    #[error("unexpected response: {0}")]
    UnexpectedResponse(String),
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, Error>;
