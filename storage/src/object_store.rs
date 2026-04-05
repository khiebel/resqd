use async_trait::async_trait;
use bytes::Bytes;

use crate::error::StorageResult;

/// Minimal async object store abstraction.
///
/// Keys are opaque slash-separated paths. Values are arbitrary bytes.
/// Implementations should treat the same key deterministically across
/// backends so the vault can fan a single logical key out to shards.
#[async_trait]
pub trait ObjectStore: Send + Sync {
    /// Human-readable backend name (e.g. "s3:resqd-vault-...").
    fn name(&self) -> &str;

    async fn put(&self, key: &str, data: Bytes) -> StorageResult<()>;

    async fn get(&self, key: &str) -> StorageResult<Bytes>;

    async fn delete(&self, key: &str) -> StorageResult<()>;

    async fn exists(&self, key: &str) -> StorageResult<bool>;
}
