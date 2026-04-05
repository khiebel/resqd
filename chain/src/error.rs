use thiserror::Error;

pub type Result<T> = std::result::Result<T, ChainError>;

#[derive(Debug, Error)]
pub enum ChainError {
    #[error("missing environment variable: {0}")]
    MissingEnv(&'static str),

    #[error("invalid chain config: {0}")]
    InvalidConfig(String),

    #[error("contract call failed: {0}")]
    ContractCall(String),

    #[error("asset id hash must be 32 bytes, got {0}")]
    InvalidAssetIdHash(usize),
}
