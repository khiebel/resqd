//! `PrefixedStore` — wraps an `ObjectStore` and prepends a prefix to every key.
//!
//! Used to fan out shards across multiple logical "backends" that share the
//! same underlying bucket (e.g. until we add a third cloud, we simulate 6
//! distinct shard destinations via 3 prefixes on S3 + 3 prefixes on GCS).

use async_trait::async_trait;
use bytes::Bytes;
use std::sync::Arc;

use crate::error::StorageResult;
use crate::object_store::ObjectStore;

pub struct PrefixedStore {
    inner: Arc<dyn ObjectStore>,
    prefix: String,
    name: String,
}

impl PrefixedStore {
    pub fn new(inner: Arc<dyn ObjectStore>, prefix: impl Into<String>) -> Self {
        let prefix = prefix.into();
        let name = format!("{}/{}", inner.name(), prefix);
        Self { inner, prefix, name }
    }

    fn k(&self, key: &str) -> String {
        format!("{}/{}", self.prefix, key)
    }
}

#[async_trait]
impl ObjectStore for PrefixedStore {
    fn name(&self) -> &str {
        &self.name
    }

    async fn put(&self, key: &str, data: Bytes) -> StorageResult<()> {
        self.inner.put(&self.k(key), data).await
    }

    async fn get(&self, key: &str) -> StorageResult<Bytes> {
        self.inner.get(&self.k(key)).await
    }

    async fn delete(&self, key: &str) -> StorageResult<()> {
        self.inner.delete(&self.k(key)).await
    }

    async fn exists(&self, key: &str) -> StorageResult<bool> {
        self.inner.exists(&self.k(key)).await
    }
}
