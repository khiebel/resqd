//! Integration test: real S3 + GCS round-trip through MultiCloudVault.
//!
//! Requires live credentials:
//!   - AWS: ~/.aws/credentials or env (AWS_ACCESS_KEY_ID/SECRET)
//!   - GCP: GOOGLE_APPLICATION_CREDENTIALS pointing at a WIF cred file
//!           (with AWS env vars also set so the Google auth lib can STS-exchange)
//!
//! Uses prefixed stores to simulate 6 backends across 2 real buckets:
//!   s3/a, s3/b, s3/c, gcs/a, gcs/b, gcs/c
//!
//! Writes 1 MiB of random data, reads it back, verifies, deletes, ignored by
//! default to keep `cargo test` hermetic. Run with:
//!   cargo test --test multicloud_roundtrip -- --ignored --nocapture

use bytes::Bytes;
use rand::RngCore;
use std::sync::Arc;

use resqd_storage::{GcsStore, MultiCloudVault, ObjectStore, PrefixedStore, S3Store};

const S3_BUCKET: &str = "resqd-vault-64553a1a";
const GCS_BUCKET: &str = "resqd-vault-64553a1a";

#[tokio::test]
#[ignore]
async fn multicloud_roundtrip_1mib() {
    let s3: Arc<dyn ObjectStore> = Arc::new(
        S3Store::new(S3_BUCKET).await.expect("s3 init"),
    );
    let gcs: Arc<dyn ObjectStore> = Arc::new(
        GcsStore::new(GCS_BUCKET).await.expect("gcs init"),
    );

    let backends: Vec<Arc<dyn ObjectStore>> = vec![
        Arc::new(PrefixedStore::new(s3.clone(), "shard-a")),
        Arc::new(PrefixedStore::new(s3.clone(), "shard-b")),
        Arc::new(PrefixedStore::new(s3.clone(), "shard-c")),
        Arc::new(PrefixedStore::new(gcs.clone(), "shard-a")),
        Arc::new(PrefixedStore::new(gcs.clone(), "shard-b")),
        Arc::new(PrefixedStore::new(gcs.clone(), "shard-c")),
    ];

    for b in &backends {
        println!("backend: {}", b.name());
    }

    let vault = MultiCloudVault::new(backends).expect("vault init");

    // 1 MiB random payload
    let mut data = vec![0u8; 1024 * 1024];
    rand::rng().fill_bytes(&mut data);
    let data = Bytes::from(data);
    let key = format!("integration-test/roundtrip-{}", chrono::Utc::now().timestamp());

    println!("put {} ({} bytes)", key, data.len());
    vault.put(&key, data.clone()).await.expect("vault put");

    println!("get {}", key);
    let got = vault.get(&key).await.expect("vault get");

    assert_eq!(got.len(), data.len(), "length mismatch");
    assert_eq!(got, data, "bytes mismatch");
    println!("round-trip verified: {} bytes match", got.len());

    println!("delete {}", key);
    vault.delete(&key).await.expect("vault delete");
    println!("cleanup ok");
}
