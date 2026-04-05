//! Shared application state and config.

use anyhow::Context;
use resqd_chain::{CanaryAnchorClient, ChainConfig};
use resqd_storage::{MultiCloudVault, ObjectStore, PrefixedStore, S3Store};
use std::sync::Arc;

/// Prefix inside the vault bucket where large single-blob uploads land.
/// These are NOT erasure-coded — the client PUTs the encrypted blob
/// directly via a presigned URL and the server only records the metadata
/// and anchors the canary on-chain.
pub const LARGE_BLOB_PREFIX: &str = "large/";

/// Configuration loaded at startup. Most values come from environment
/// variables so the same binary runs in Lambda, Fargate, or locally.
#[derive(Clone, Debug)]
pub struct AppConfig {
    /// S3 bucket used for the first 3 erasure shards.
    pub s3_bucket: String,
    /// (Optional) GCS bucket used for the last 3 erasure shards. If absent,
    /// the vault runs in S3-only mode (6 shards all on S3 across prefixes).
    pub gcs_bucket: Option<String>,
    /// Whether on-chain anchoring is enabled. Disabled in unit tests or
    /// when running against a signer-less environment.
    pub chain_enabled: bool,
    /// Chain config (only required when `chain_enabled`).
    pub chain: Option<ChainConfig>,
}

impl AppConfig {
    /// Build from environment variables.
    ///
    /// - `RESQD_S3_BUCKET` (required)
    /// - `RESQD_GCS_BUCKET` (optional)
    /// - `RESQD_CHAIN_ENABLED` (optional, default false)
    /// - `RESQD_CHAIN_RPC_URL` / `RESQD_CHAIN_CONTRACT` / `RESQD_CHAIN_SIGNER_KEY`
    ///   (required if chain enabled)
    pub fn from_env() -> anyhow::Result<Self> {
        let s3_bucket = std::env::var("RESQD_S3_BUCKET")
            .context("RESQD_S3_BUCKET is required")?;
        let gcs_bucket = std::env::var("RESQD_GCS_BUCKET").ok();

        let chain_enabled = std::env::var("RESQD_CHAIN_ENABLED")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let chain = if chain_enabled {
            Some(ChainConfig::from_env().context("chain config")?)
        } else {
            None
        };

        Ok(Self {
            s3_bucket,
            gcs_bucket,
            chain_enabled,
            chain,
        })
    }
}

/// Runtime state shared across all request handlers. Cheap to clone (`Arc`
/// internals). Built once at process startup.
pub struct AppState {
    pub config: AppConfig,
    pub vault: MultiCloudVault,
    /// Unwrapped S3Store for the same bucket. Used by the large-file
    /// path to generate presigned URLs directly — the erasure-coded
    /// `vault` can't do that since it fans each object out to 6 shards.
    pub s3: Arc<S3Store>,
    pub chain: Option<CanaryAnchorClient>,
}

impl AppState {
    /// Build the live state from a config.
    ///
    /// Sets up:
    /// - S3 client (AWS default credential chain)
    /// - (optional) GCS client (gcloud WIF path — requires AWS creds in env)
    /// - (optional) chain client
    /// - A MultiCloudVault with 6 prefixed shards
    pub async fn from_config(config: AppConfig) -> anyhow::Result<Self> {
        let s3_concrete = Arc::new(
            S3Store::new(&config.s3_bucket)
                .await
                .context("init S3Store")?,
        );
        let s3: Arc<dyn ObjectStore> = s3_concrete.clone();

        // 6 shards: if GCS is configured, 3+3 split; otherwise 6 S3 prefixes.
        let backends: Vec<Arc<dyn ObjectStore>> = if let Some(gcs_bucket) = &config.gcs_bucket {
            let gcs = Arc::new(
                resqd_storage::GcsStore::new(gcs_bucket)
                    .await
                    .context("init GcsStore")?,
            ) as Arc<dyn ObjectStore>;
            vec![
                Arc::new(PrefixedStore::new(s3.clone(), "shard-a")),
                Arc::new(PrefixedStore::new(s3.clone(), "shard-b")),
                Arc::new(PrefixedStore::new(s3.clone(), "shard-c")),
                Arc::new(PrefixedStore::new(gcs.clone(), "shard-a")),
                Arc::new(PrefixedStore::new(gcs.clone(), "shard-b")),
                Arc::new(PrefixedStore::new(gcs, "shard-c")),
            ]
        } else {
            vec![
                Arc::new(PrefixedStore::new(s3.clone(), "shard-a")),
                Arc::new(PrefixedStore::new(s3.clone(), "shard-b")),
                Arc::new(PrefixedStore::new(s3.clone(), "shard-c")),
                Arc::new(PrefixedStore::new(s3.clone(), "shard-d")),
                Arc::new(PrefixedStore::new(s3.clone(), "shard-e")),
                Arc::new(PrefixedStore::new(s3, "shard-f")),
            ]
        };

        let vault = MultiCloudVault::new(backends).context("init MultiCloudVault")?;

        let chain = if let Some(chain_config) = config.chain.clone() {
            Some(CanaryAnchorClient::new(chain_config).context("init chain client")?)
        } else {
            None
        };

        Ok(Self {
            config,
            vault,
            s3: s3_concrete,
            chain,
        })
    }
}
