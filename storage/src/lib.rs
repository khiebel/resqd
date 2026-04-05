//! RESQD multi-cloud storage layer.
//!
//! Provides an async `ObjectStore` trait with S3 and GCS implementations,
//! and a `MultiCloudVault` that splits each object into Reed-Solomon 4+2
//! shards distributed across backends. Any 4 of 6 shards can reconstruct.

pub mod error;
pub mod object_store;
pub mod prefixed;
pub mod s3;
pub mod gcs;
pub mod vault;

pub use error::{StorageError, StorageResult};
pub use object_store::ObjectStore;
pub use prefixed::PrefixedStore;
pub use s3::S3Store;
pub use gcs::GcsStore;
pub use vault::MultiCloudVault;
