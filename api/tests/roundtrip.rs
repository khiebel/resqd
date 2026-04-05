//! Smoke test for the full upload → fetch → verify flow using an
//! in-memory object store. No S3, no GCS, no chain — just the crate's
//! logic and the canary chain. Proves the handler wiring is correct.

use async_trait::async_trait;
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use bytes::Bytes;
use resqd_api::{AppConfig, AppState, router};
use resqd_storage::{MultiCloudVault, ObjectStore, PrefixedStore, StorageError, StorageResult};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tower::ServiceExt;

/// Minimal in-memory ObjectStore for tests.
struct MemStore {
    name: String,
    inner: Mutex<HashMap<String, Bytes>>,
}

impl MemStore {
    fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            inner: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl ObjectStore for MemStore {
    fn name(&self) -> &str {
        &self.name
    }

    async fn put(&self, key: &str, data: Bytes) -> StorageResult<()> {
        self.inner.lock().unwrap().insert(key.to_string(), data);
        Ok(())
    }

    async fn get(&self, key: &str) -> StorageResult<Bytes> {
        self.inner
            .lock()
            .unwrap()
            .get(key)
            .cloned()
            .ok_or_else(|| StorageError::NotFound(key.to_string()))
    }

    async fn delete(&self, key: &str) -> StorageResult<()> {
        self.inner.lock().unwrap().remove(key);
        Ok(())
    }

    async fn exists(&self, key: &str) -> StorageResult<bool> {
        Ok(self.inner.lock().unwrap().contains_key(key))
    }
}

/// Build AppState with 6 in-memory backends and the chain disabled.
async fn test_state() -> Arc<AppState> {
    let mem: Arc<dyn ObjectStore> = Arc::new(MemStore::new("mem:test"));
    let backends: Vec<Arc<dyn ObjectStore>> = (0..6)
        .map(|i| {
            Arc::new(PrefixedStore::new(mem.clone(), format!("shard-{i}"))) as Arc<dyn ObjectStore>
        })
        .collect();
    let vault = MultiCloudVault::new(backends).expect("vault");

    Arc::new(AppState {
        config: AppConfig {
            s3_bucket: "test".into(),
            gcs_bucket: None,
            chain_enabled: false,
            chain: None,
        },
        vault,
        chain: None,
    })
}

#[tokio::test]
async fn health_returns_ok() {
    let app = router(test_state().await);
    let res = app
        .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn upload_fetch_verify_roundtrip() {
    let app = router(test_state().await);

    // ---------- UPLOAD ----------
    let payload = Bytes::from_static(b"the quick brown canary jumps over the vault gate");
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/vault")
                .header("content-type", "application/octet-stream")
                .body(Body::from(payload.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let upload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let asset_id = upload["asset_id"].as_str().unwrap().to_string();
    assert_eq!(upload["canary_sequence"].as_u64(), Some(0));
    assert_eq!(upload["size_bytes"].as_u64(), Some(payload.len() as u64));
    assert_eq!(upload["anchored_on_chain"].as_bool(), Some(false));
    println!("uploaded asset_id={asset_id}");

    // ---------- FETCH (access 1 — rotates to sequence 1) ----------
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/vault/{asset_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let seq = res
        .headers()
        .get("x-resqd-canary-sequence")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(seq, "1");
    let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    assert_eq!(&body[..], &payload[..], "bytes round-tripped");

    // ---------- FETCH (access 2 — rotates to sequence 2) ----------
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/vault/{asset_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers().get("x-resqd-canary-sequence").unwrap(),
        "2"
    );

    // ---------- VERIFY (expected count 3: 1 initial + 2 fetches) ----------
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/vault/{asset_id}/verify?count=3"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let verify: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(verify["on_chain_access_count"].as_u64(), Some(3));
    assert_eq!(verify["matches"].as_bool(), Some(true));

    // ---------- VERIFY wrong count ----------
    let res = app
        .oneshot(
            Request::builder()
                .uri(format!("/vault/{asset_id}/verify?count=99"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let verify: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(verify["matches"].as_bool(), Some(false));
}

#[tokio::test]
async fn fetch_nonexistent_returns_404() {
    let app = router(test_state().await);
    let res = app
        .oneshot(
            Request::builder()
                .uri("/vault/bogus-id-does-not-exist")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn upload_empty_body_returns_400() {
    let app = router(test_state().await);
    let res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/vault")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}
