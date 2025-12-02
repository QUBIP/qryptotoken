use thiserror::Error;

#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("Invalid key length (expected: {expected}, got: {actual})")]
    InvalidKeyLen { expected: usize, actual: usize },

    #[error("Invalid signature length (expected: {expected}, got: {actual})")]
    InvalidSignatureLen { expected: usize, actual: usize },

    #[error("Invalid signature: {0})")]
    InvalidSignature(String),

    #[error("Invalid public key: {0})")]
    InvalidPublicKey(String),

    #[error("Invalid private key: {0})")]
    InvalidPrivateKey(String),

    #[error("Context length exceeds {max} bytes (got: {actual})")]
    ContextTooLong { max: usize, actual: usize },

    #[error("Randomness generation failed: {0}")]
    RandomnessError(#[from] rand_core::OsError),

    #[error("{0}")]
    SigningError(String),

    #[error("{0}")]
    VerificationError(String),

    #[error("Internal error: {0}")]
    InternalError(String),
}

pub type AResult<T> = std::result::Result<T, AdapterError>;

impl From<AdapterError> for signature::Error {
    fn from(err: AdapterError) -> Self {
        signature::Error::from_source(err)
    }
}

impl From<std::array::TryFromSliceError> for AdapterError {
    fn from(e: std::array::TryFromSliceError) -> Self {
        AdapterError::InternalError(format!("Array conversion failed: {e}"))
    }
}
