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

    // ── S3 multipart upload support ──────────────────────────────────
    //
    // Added 2026-04-11 for Verimus streaming integration Chunk 1.4. Used
    // by the sharded-stream vault path where each shard accumulates its
    // erasure-coded bytes across many chunk groups before finalizing as
    // a single S3 object. S3's multipart upload lets the client push a
    // file much larger than Lambda's payload cap, and each part is
    // uploaded directly from the browser via a presigned URL so bytes
    // never flow through Lambda at all.
    //
    // S3 requires that every part except the final one be at least 5 MB.
    // This layer is agnostic to that — the client's streaming buffer is
    // responsible for batching smaller chunk-group pieces into ≥5 MB
    // parts before requesting a presigned UploadPart URL.

    /// Start a multipart upload. Returns the S3-assigned `upload_id`
    /// that subsequent `UploadPart`, `CompleteMultipartUpload`, and
    /// `AbortMultipartUpload` calls must reference.
    pub async fn create_multipart_upload(
        &self,
        key: &str,
        content_type: &str,
    ) -> StorageResult<String> {
        let resp = self
            .client
            .create_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .content_type(content_type)
            .send()
            .await
            .map_err(|e| StorageError::S3(format!("create_multipart {key}: {e}")))?;

        resp.upload_id()
            .map(|s| s.to_string())
            .ok_or_else(|| StorageError::S3("create_multipart: no upload_id in response".into()))
    }

    /// Presign an `UploadPart` URL so the browser can PUT one part
    /// directly to S3, bypassing Lambda. The client must PUT at least
    /// 5 MB per part (except the final one) or S3 will reject the
    /// eventual `CompleteMultipartUpload`.
    ///
    /// Part numbers are 1-indexed per the S3 spec (part 0 is illegal).
    pub async fn presign_upload_part(
        &self,
        key: &str,
        upload_id: &str,
        part_number: i32,
        ttl: Duration,
    ) -> StorageResult<String> {
        let presigned = self
            .client
            .upload_part()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(upload_id)
            .part_number(part_number)
            .presigned(
                PresigningConfig::expires_in(ttl)
                    .map_err(|e| StorageError::S3(format!("presign config: {e}")))?,
            )
            .await
            .map_err(|e| {
                StorageError::S3(format!(
                    "presign upload_part {key} part {part_number}: {e}"
                ))
            })?;
        Ok(presigned.uri().to_string())
    }

    /// Finalize a multipart upload. `parts` is a list of
    /// `(part_number, etag)` pairs in the order they were uploaded.
    /// Part numbers must be unique and strictly increasing per the S3
    /// spec. Each ETag must exactly match the value S3 returned in the
    /// UploadPart response (with quoting stripped — this helper adds
    /// them back in).
    pub async fn complete_multipart_upload(
        &self,
        key: &str,
        upload_id: &str,
        parts: Vec<(i32, String)>,
    ) -> StorageResult<()> {
        use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};

        let completed_parts: Vec<CompletedPart> = parts
            .into_iter()
            .map(|(part_number, etag)| {
                // S3 stores ETags with embedded quotes; the client may or
                // may not strip them. Normalize by re-quoting if needed.
                let etag_quoted = if etag.starts_with('"') && etag.ends_with('"') {
                    etag
                } else {
                    format!("\"{etag}\"")
                };
                CompletedPart::builder()
                    .part_number(part_number)
                    .e_tag(etag_quoted)
                    .build()
            })
            .collect();

        let multipart_upload = CompletedMultipartUpload::builder()
            .set_parts(Some(completed_parts))
            .build();

        self.client
            .complete_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(upload_id)
            .multipart_upload(multipart_upload)
            .send()
            .await
            .map_err(|e| StorageError::S3(format!("complete_multipart {key}: {e}")))?;
        Ok(())
    }

    /// Stream the object's body through BLAKE3 and return the hex
    /// digest. The body bytes are consumed in chunks so Lambda memory
    /// stays bounded by the largest single SDK buffer, not the total
    /// shard size. This is Track 2 Chunk 2.3 — the server-side
    /// absorption check, stricter than "random range" because it
    /// verifies every byte of the shard.
    pub async fn blake3_hex(&self, key: &str) -> StorageResult<Option<String>> {
        use tokio::io::AsyncReadExt;
        let resp = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await;
        let resp = match resp {
            Ok(r) => r,
            Err(e) => {
                let s = format!("{e}");
                if s.contains("NoSuchKey") || s.contains("NotFound") || s.contains("404") {
                    return Ok(None);
                }
                return Err(StorageError::S3(format!("get {key}: {e}")));
            }
        };
        let mut reader = resp.body.into_async_read();
        let mut hasher = blake3::Hasher::new();
        let mut buf = vec![0u8; 256 * 1024];
        loop {
            let n = reader
                .read(&mut buf)
                .await
                .map_err(|e| StorageError::S3(format!("read {key}: {e}")))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(Some(hasher.finalize().to_hex().to_string()))
    }

    /// Fetch the content length of an object without downloading the
    /// body. Used by the Track 2 proof-of-absorption path to verify
    /// that a completed multipart upload assembled to the byte count
    /// the client claimed it would. Returns `None` if the object
    /// doesn't exist (treated by callers as a verification failure,
    /// not a 500).
    pub async fn head_content_length(&self, key: &str) -> StorageResult<Option<u64>> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(resp) => Ok(resp.content_length().map(|n| n.max(0) as u64)),
            Err(e) => {
                let s = format!("{e}");
                if s.contains("NotFound") || s.contains("NoSuchKey") || s.contains("404") {
                    Ok(None)
                } else {
                    Err(StorageError::S3(format!("head {key}: {e}")))
                }
            }
        }
    }

    /// Abort an in-flight multipart upload. Safe to call on an upload
    /// that's already been aborted or completed — S3 returns 404 in
    /// those cases, which this method treats as a no-op.
    pub async fn abort_multipart_upload(
        &self,
        key: &str,
        upload_id: &str,
    ) -> StorageResult<()> {
        match self
            .client
            .abort_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(upload_id)
            .send()
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => {
                // 404 on abort is fine — the upload is already gone.
                let s = format!("{e}");
                if s.contains("NoSuchUpload") || s.contains("NotFound") {
                    Ok(())
                } else {
                    Err(StorageError::S3(format!(
                        "abort_multipart {key}: {e}"
                    )))
                }
            }
        }
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
                if e.as_service_error()
                    .map_or(false, |se| se.is_no_such_key())
                {
                    StorageError::NotFound(key.to_string())
                } else {
                    let s = format!("{e}");
                    if s.contains("NoSuchKey") || s.contains("NotFound") {
                        StorageError::NotFound(key.to_string())
                    } else {
                        StorageError::S3(format!("get {key}: {e}"))
                    }
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
