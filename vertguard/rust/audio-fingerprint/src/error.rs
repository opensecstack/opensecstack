use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("insufficient data: need at least {0} samples")]
    InsufficientData(usize),

    #[error("processing failure: {0}")]
    ProcessingFailure(String),
}
