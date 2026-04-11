//! In-memory `ObjectStore` implementation for hermetic tests.
//!
//! Backs a `BTreeMap<String, Bytes>` with an `Arc<Mutex<>>` for
//! interior mutability across `&self` trait methods. Not intended for
//! production — no durability, no concurrency-aware conflict handling,
//! no size limits, no eviction. The point is to let the api + stream
//! tests exercise paths like the Chunk 2.x absorption checks without
//! needing a live S3 bucket or LocalStack.
//!
//! Verimus-inspired addition (2026-04-11). Eric's project runs 100%
//! of its tests against `MongoMemoryServer` + an in-memory blob store;
//! RESQD's test suite currently hits real DynamoDB + S3 which makes
//! iteration slow and flakey. This is the first rung of swapping that
//! out.

use async_trait::async_trait;
use bytes::Bytes;
use std::collections::BTreeMap;
use std::sync::Mutex;

use crate::error::{StorageError, StorageResult};
use crate::object_store::ObjectStore;

#[derive(Debug)]
pub struct MemStore {
    name: String,
    inner: Mutex<BTreeMap<String, Bytes>>,
}

impl MemStore {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            inner: Mutex::new(BTreeMap::new()),
        }
    }

    /// Number of keys currently stored. Handy for tests that want to
    /// assert no leaks after a cleanup path.
    pub fn len(&self) -> usize {
        self.inner.lock().expect("mem store poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterate over every (key, bytes_len) pair. Useful for tests that
    /// want to walk prefixes the way `S3Store::list_prefix` would.
    pub fn keys(&self) -> Vec<(String, usize)> {
        self.inner
            .lock()
            .expect("mem store poisoned")
            .iter()
            .map(|(k, v)| (k.clone(), v.len()))
            .collect()
    }

    /// Delete every key that starts with `prefix`. Returns the number
    /// of keys removed.
    pub fn purge_prefix(&self, prefix: &str) -> usize {
        let mut guard = self.inner.lock().expect("mem store poisoned");
        let to_remove: Vec<String> = guard
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect();
        for k in &to_remove {
            guard.remove(k);
        }
        to_remove.len()
    }
}

impl Default for MemStore {
    fn default() -> Self {
        Self::new("mem:test")
    }
}

#[async_trait]
impl ObjectStore for MemStore {
    fn name(&self) -> &str {
        &self.name
    }

    async fn put(&self, key: &str, data: Bytes) -> StorageResult<()> {
        let mut guard = self.inner.lock().expect("mem store poisoned");
        guard.insert(key.to_string(), data);
        Ok(())
    }

    async fn get(&self, key: &str) -> StorageResult<Bytes> {
        let guard = self.inner.lock().expect("mem store poisoned");
        guard
            .get(key)
            .cloned()
            .ok_or_else(|| StorageError::NotFound(key.to_string()))
    }

    async fn delete(&self, key: &str) -> StorageResult<()> {
        let mut guard = self.inner.lock().expect("mem store poisoned");
        guard.remove(key);
        Ok(())
    }

    async fn exists(&self, key: &str) -> StorageResult<bool> {
        let guard = self.inner.lock().expect("mem store poisoned");
        Ok(guard.contains_key(key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trip() {
        let store = MemStore::new("mem:unit");
        assert!(store.is_empty());
        store.put("a/b", Bytes::from_static(b"hello")).await.unwrap();
        store.put("a/c", Bytes::from_static(b"world")).await.unwrap();
        assert_eq!(store.len(), 2);
        assert!(store.exists("a/b").await.unwrap());
        assert_eq!(&store.get("a/b").await.unwrap()[..], b"hello");

        store.delete("a/b").await.unwrap();
        assert!(!store.exists("a/b").await.unwrap());
        assert!(matches!(
            store.get("a/b").await,
            Err(StorageError::NotFound(_))
        ));
        assert_eq!(store.len(), 1);
    }

    #[tokio::test]
    async fn purge_prefix_only_matches_prefix() {
        let store = MemStore::default();
        store.put("keep/x", Bytes::from_static(b"1")).await.unwrap();
        store.put("drop/a", Bytes::from_static(b"2")).await.unwrap();
        store.put("drop/b", Bytes::from_static(b"3")).await.unwrap();
        let removed = store.purge_prefix("drop/");
        assert_eq!(removed, 2);
        assert_eq!(store.len(), 1);
        assert!(store.exists("keep/x").await.unwrap());
    }
}
