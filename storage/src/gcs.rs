//! GCS object store via the JSON API.
//!
//! Auth: we shell out to `gcloud auth print-access-token` to get a bearer
//! token. gcloud natively supports external_account (WIF/AWS) credentials,
//! while the Rust auth crates in the yoshidan/google-cloud-* stack as of
//! 2026-04 do NOT. This sidesteps that gap entirely.
//!
//! Set `RESQD_GCLOUD_CONFIG` to the gcloud configuration name that has the
//! WIF cred file activated (default: `resqd-wif`). That configuration must
//! already have run `gcloud auth login --cred-file=...`.

use async_trait::async_trait;
use bytes::Bytes;
use reqwest::Client;
use std::process::Command;

use crate::error::{StorageError, StorageResult};
use crate::object_store::ObjectStore;

const GCS_BASE: &str = "https://storage.googleapis.com/storage/v1";
const GCS_UPLOAD: &str = "https://storage.googleapis.com/upload/storage/v1";

pub struct GcsStore {
    http: Client,
    bucket: String,
    name: String,
    gcloud_config: String,
}

impl GcsStore {
    pub async fn new(bucket: impl Into<String>) -> StorageResult<Self> {
        let bucket = bucket.into();
        let gcloud_config = std::env::var("RESQD_GCLOUD_CONFIG")
            .unwrap_or_else(|_| "resqd-wif".to_string());
        let http = Client::builder()
            .build()
            .map_err(|e| StorageError::Config(format!("reqwest init: {e}")))?;
        let name = format!("gcs:{bucket}");
        let store = Self {
            http,
            bucket,
            name,
            gcloud_config,
        };
        // Fail fast if we can't mint a token.
        store.access_token().await?;
        Ok(store)
    }

    async fn access_token(&self) -> StorageResult<String> {
        let cfg = self.gcloud_config.clone();
        let out = tokio::task::spawn_blocking(move || {
            Command::new("gcloud")
                .env("CLOUDSDK_ACTIVE_CONFIG_NAME", &cfg)
                .args(["auth", "print-access-token"])
                .output()
        })
        .await
        .map_err(|e| StorageError::Config(format!("gcloud join: {e}")))?
        .map_err(|e| StorageError::Config(format!("gcloud spawn: {e}")))?;

        if !out.status.success() {
            return Err(StorageError::Config(format!(
                "gcloud auth print-access-token failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }
}

#[async_trait]
impl ObjectStore for GcsStore {
    fn name(&self) -> &str {
        &self.name
    }

    async fn put(&self, key: &str, data: Bytes) -> StorageResult<()> {
        let token = self.access_token().await?;
        let url = format!(
            "{GCS_UPLOAD}/b/{}/o?uploadType=media&name={}",
            self.bucket,
            urlencoding::encode(key)
        );
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&token)
            .header("Content-Type", "application/octet-stream")
            .body(data)
            .send()
            .await
            .map_err(|e| StorageError::Gcs(format!("put {key}: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(StorageError::Gcs(format!(
                "put {key} status {status}: {body}"
            )));
        }
        Ok(())
    }

    async fn get(&self, key: &str) -> StorageResult<Bytes> {
        let token = self.access_token().await?;
        let url = format!(
            "{GCS_BASE}/b/{}/o/{}?alt=media",
            self.bucket,
            urlencoding::encode(key)
        );
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| StorageError::Gcs(format!("get {key}: {e}")))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(StorageError::NotFound(key.to_string()));
        }
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(StorageError::Gcs(format!(
                "get {key} status {status}: {body}"
            )));
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| StorageError::Gcs(format!("read {key}: {e}")))?;
        Ok(bytes)
    }

    async fn delete(&self, key: &str) -> StorageResult<()> {
        let token = self.access_token().await?;
        let url = format!(
            "{GCS_BASE}/b/{}/o/{}",
            self.bucket,
            urlencoding::encode(key)
        );
        let resp = self
            .http
            .delete(&url)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| StorageError::Gcs(format!("delete {key}: {e}")))?;
        // 204 No Content on success, 404 on missing.
        let status = resp.status();
        if status.is_success() || status == reqwest::StatusCode::NOT_FOUND {
            return Ok(());
        }
        let body = resp.text().await.unwrap_or_default();
        Err(StorageError::Gcs(format!(
            "delete {key} status {status}: {body}"
        )))
    }

    async fn exists(&self, key: &str) -> StorageResult<bool> {
        let token = self.access_token().await?;
        let url = format!(
            "{GCS_BASE}/b/{}/o/{}",
            self.bucket,
            urlencoding::encode(key)
        );
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| StorageError::Gcs(format!("head {key}: {e}")))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(false);
        }
        if resp.status().is_success() {
            return Ok(true);
        }
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        Err(StorageError::Gcs(format!(
            "head {key} status {status}: {body}"
        )))
    }
}
