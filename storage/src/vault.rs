//! `MultiCloudVault` — erasure-coded object store spanning multiple backends.
//!
//! Takes a logical object, splits it via Reed-Solomon 4+2 (from `resqd-core`),
//! writes one shard per backend. Any 4 of 6 backends can reconstruct the
//! original. A 64-byte sidecar (`<key>.meta`) stores the original length,
//! co-located with shard 0 (same key space per backend). Simple, explicit.

use bytes::Bytes;
use futures::future::join_all;
use resqd_core::erasure::{DATA_SHARDS, TOTAL_SHARDS, encode, reconstruct};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::error::{StorageError, StorageResult};
use crate::object_store::ObjectStore;

#[derive(Debug, Serialize, Deserialize)]
struct ShardMeta {
    original_len: usize,
    total_shards: usize,
    data_shards: usize,
}

pub struct MultiCloudVault {
    backends: Vec<Arc<dyn ObjectStore>>,
}

impl MultiCloudVault {
    /// Create a vault across `backends`. Must provide at least `TOTAL_SHARDS`
    /// (6) backends. Only the first `TOTAL_SHARDS` are used; extras are ignored.
    pub fn new(backends: Vec<Arc<dyn ObjectStore>>) -> StorageResult<Self> {
        if backends.len() < TOTAL_SHARDS {
            return Err(StorageError::InsufficientBackends {
                needed: TOTAL_SHARDS,
                have: backends.len(),
            });
        }
        Ok(Self {
            backends: backends.into_iter().take(TOTAL_SHARDS).collect(),
        })
    }

    /// Write an object. Encodes into 6 shards and writes shard_i to backend_i.
    /// Also writes a sidecar meta object to backend 0.
    pub async fn put(&self, key: &str, data: Bytes) -> StorageResult<()> {
        let original_len = data.len();
        let shards = encode(&data)?;

        let meta = ShardMeta {
            original_len,
            total_shards: TOTAL_SHARDS,
            data_shards: DATA_SHARDS,
        };
        let meta_bytes = serde_json::to_vec(&meta)
            .map_err(|e| StorageError::Config(format!("meta serialize: {e}")))?;

        let shard_key = |i: usize| format!("{key}.shard{i}");

        let mut futs = Vec::with_capacity(TOTAL_SHARDS + 1);
        for (i, shard) in shards.into_iter().enumerate() {
            let backend = self.backends[i].clone();
            let k = shard_key(i);
            futs.push(tokio::spawn(async move {
                backend.put(&k, Bytes::from(shard)).await
            }));
        }
        // meta sidecar → backend 0
        let meta_backend = self.backends[0].clone();
        let meta_key = format!("{key}.meta");
        futs.push(tokio::spawn(async move {
            meta_backend.put(&meta_key, Bytes::from(meta_bytes)).await
        }));

        for r in join_all(futs).await {
            r.map_err(|e| StorageError::Config(format!("join: {e}")))??;
        }
        Ok(())
    }

    /// Read an object. Fetches all shards in parallel; tolerates up to
    /// `TOTAL_SHARDS - DATA_SHARDS` (2) missing. Reconstructs and returns
    /// the original bytes.
    pub async fn get(&self, key: &str) -> StorageResult<Bytes> {
        // Fetch meta from backend 0.
        let meta_bytes = self.backends[0].get(&format!("{key}.meta")).await?;
        let meta: ShardMeta = serde_json::from_slice(&meta_bytes)
            .map_err(|e| StorageError::Config(format!("meta parse: {e}")))?;

        let shard_key = |i: usize| format!("{key}.shard{i}");

        let mut futs = Vec::with_capacity(TOTAL_SHARDS);
        for i in 0..TOTAL_SHARDS {
            let backend = self.backends[i].clone();
            let k = shard_key(i);
            futs.push(tokio::spawn(async move { backend.get(&k).await }));
        }

        let mut shards: Vec<Option<Vec<u8>>> = Vec::with_capacity(TOTAL_SHARDS);
        let mut present = 0usize;
        for r in join_all(futs).await {
            match r {
                Ok(Ok(b)) => {
                    shards.push(Some(b.to_vec()));
                    present += 1;
                }
                _ => shards.push(None),
            }
        }
        if present < DATA_SHARDS {
            return Err(StorageError::InsufficientShards {
                needed: DATA_SHARDS,
                have: present,
            });
        }

        let data = reconstruct(&mut shards, meta.original_len)?;
        Ok(Bytes::from(data))
    }

    /// Delete all shards + meta for an object. Best-effort: returns the first
    /// error but attempts all deletions.
    pub async fn delete(&self, key: &str) -> StorageResult<()> {
        let shard_key = |i: usize| format!("{key}.shard{i}");

        let mut futs = Vec::with_capacity(TOTAL_SHARDS + 1);
        for i in 0..TOTAL_SHARDS {
            let backend = self.backends[i].clone();
            let k = shard_key(i);
            futs.push(tokio::spawn(async move { backend.delete(&k).await }));
        }
        let meta_backend = self.backends[0].clone();
        let meta_key = format!("{key}.meta");
        futs.push(tokio::spawn(async move {
            meta_backend.delete(&meta_key).await
        }));

        let mut first_err: Option<StorageError> = None;
        for r in join_all(futs).await {
            match r {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
                Err(e) => {
                    if first_err.is_none() {
                        first_err = Some(StorageError::Config(format!("join: {e}")));
                    }
                }
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}
