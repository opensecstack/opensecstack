use thiserror::Error;

/// Typed errors returned by the parser. The parser never panics on malformed input.
#[derive(Debug, Error)]
pub enum ParseError {
    #[error("invalid format: {message}")]
    InvalidFormat {
        line: Option<usize>,
        message: String,
    },

    #[error("unsupported version `{version}` (supported: {supported:?})")]
    UnsupportedVersion {
        version: String,
        supported: Vec<String>,
    },

    #[error("circular $ref reference: {path:?}")]
    CircularReference { path: Vec<String> },

    #[error("schema size {size_bytes} bytes exceeds maximum {max_bytes} bytes")]
    SizeExceeded { size_bytes: usize, max_bytes: usize },

    #[error("invalid schema: {errors:?}")]
    InvalidSchema { errors: Vec<String> },

    #[error("fetch error for `{url}`: {message}")]
    FetchError { url: String, message: String },
}
