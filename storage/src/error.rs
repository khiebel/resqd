use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("S3 error: {0}")]
    S3(String),

    #[error("GCS error: {0}")]
    Gcs(String),

    #[error("object not found: {0}")]
    NotFound(String),

    #[error("erasure coding error: {0}")]
    Erasure(String),

    #[error("insufficient backends: need {needed}, have {have}")]
    InsufficientBackends { needed: usize, have: usize },

    #[error("insufficient shards to reconstruct: need {needed}, have {have}")]
    InsufficientShards { needed: usize, have: usize },

    #[error("config error: {0}")]
    Config(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type StorageResult<T> = Result<T, StorageError>;

impl From<resqd_core::error::ResqdError> for StorageError {
    fn from(e: resqd_core::error::ResqdError) -> Self {
        StorageError::Erasure(e.to_string())
    }
}
