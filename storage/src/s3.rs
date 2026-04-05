use async_trait::async_trait;
use aws_sdk_s3::Client;
use aws_sdk_s3::presigning::PresigningConfig;
use aws_sdk_s3::primitives::ByteStream;
use bytes::Bytes;
use std::time::Duration;

use crate::error::{StorageError, StorageResult};
use crate::object_store::ObjectStore;

pub struct S3Store {
    client: Client,
    bucket: String,
    name: String,
}

impl S3Store {
    /// Build an `S3Store` using the default AWS credential chain
    /// (env vars, ~/.aws/credentials, IMDS, etc.).
    pub async fn new(bucket: impl Into<String>) -> StorageResult<Self> {
        let bucket = bucket.into();
        let cfg = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let client = Client::new(&cfg);
        let name = format!("s3:{bucket}");
        Ok(Self { client, bucket, name })
    }

    /// Presign a PUT URL so a client can upload an object directly to S3
    /// without passing through Lambda (sidesteps the 6 MB sync payload cap).
    pub async fn presign_put(
        &self,
        key: &str,
        content_type: &str,
        ttl: Duration,
    ) -> StorageResult<String> {
        let presigned = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .content_type(content_type)
            .presigned(
                PresigningConfig::expires_in(ttl)
                    .map_err(|e| StorageError::S3(format!("presign config: {e}")))?,
            )
            .await
            .map_err(|e| StorageError::S3(format!("presign put {key}: {e}")))?;
        Ok(presigned.uri().to_string())
    }

    /// Presign a GET URL for download. Lets the browser stream large blobs
    /// straight from S3 instead of proxying them through Lambda.
    pub async fn presign_get(&self, key: &str, ttl: Duration) -> StorageResult<String> {
        let presigned = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .presigned(
                PresigningConfig::expires_in(ttl)
                    .map_err(|e| StorageError::S3(format!("presign config: {e}")))?,
            )
            .await
            .map_err(|e| StorageError::S3(format!("presign get {key}: {e}")))?;
        Ok(presigned.uri().to_string())
    }

    /// Fast existence check. Same as `exists()` but exposes the method
    /// on the concrete type so the API crate can use it without going
    /// through the `ObjectStore` trait.
    pub async fn head(&self, key: &str) -> StorageResult<bool> {
        <Self as ObjectStore>::exists(self, key).await
    }

    /// List keys beneath `prefix` along with their `LastModified` times.
    /// Used by the vault listing endpoint to enumerate a user's assets.
    /// Returns at most 1000 entries (S3 default page size) — fine for MVP;
    /// pagination is a future extension.
    pub async fn list_prefix(
        &self,
        prefix: &str,
    ) -> StorageResult<Vec<(String, Option<i64>)>> {
        let resp = self
            .client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(prefix)
            .send()
            .await
            .map_err(|e| StorageError::S3(format!("list {prefix}: {e}")))?;

        Ok(resp
            .contents()
            .iter()
            .filter_map(|o| {
                let key = o.key()?.to_string();
                let modified = o.last_modified().map(|t| t.secs());
                Some((key, modified))
            })
            .collect())
    }
}

#[async_trait]
impl ObjectStore for S3Store {
    fn name(&self) -> &str {
        &self.name
    }

    async fn put(&self, key: &str, data: Bytes) -> StorageResult<()> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(ByteStream::from(data))
            .send()
            .await
            .map_err(|e| StorageError::S3(format!("put {key}: {e}")))?;
        Ok(())
    }

    async fn get(&self, key: &str) -> StorageResult<Bytes> {
        let resp = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| {
                let s = format!("{e}");
                if s.contains("NoSuchKey") || s.contains("NotFound") {
                    StorageError::NotFound(key.to_string())
                } else {
                    StorageError::S3(format!("get {key}: {e}"))
                }
            })?;

        let bytes = resp
            .body
            .collect()
            .await
            .map_err(|e| StorageError::S3(format!("read {key}: {e}")))?
            .into_bytes();
        Ok(bytes)
    }

    async fn delete(&self, key: &str) -> StorageResult<()> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| StorageError::S3(format!("delete {key}: {e}")))?;
        Ok(())
    }

    async fn exists(&self, key: &str) -> StorageResult<bool> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(e) => {
                let s = format!("{e}");
                if s.contains("NotFound") || s.contains("NoSuchKey") || s.contains("404") {
                    Ok(false)
                } else {
                    Err(StorageError::S3(format!("head {key}: {e}")))
                }
            }
        }
    }
}
