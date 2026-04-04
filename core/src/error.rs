use thiserror::Error;

#[derive(Error, Debug)]
pub enum ResqdError {
    #[error("encryption failed: {0}")]
    Encryption(String),

    #[error("decryption failed: {0}")]
    Decryption(String),

    #[error("key encapsulation failed: {0}")]
    KeyEncapsulation(String),

    #[error("key derivation failed: {0}")]
    KeyDerivation(String),

    #[error("canary verification failed: expected {expected} accesses, found {found}")]
    CanaryMismatch { expected: u64, found: u64 },

    #[error("canary chain broken at index {index}")]
    CanaryChainBroken { index: u64 },

    #[error("erasure coding failed: {0}")]
    ErasureCoding(String),

    #[error("shard reconstruction failed: need {needed} shards, have {have}")]
    InsufficientShards { needed: usize, have: usize },

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),
}

pub type Result<T> = std::result::Result<T, ResqdError>;
