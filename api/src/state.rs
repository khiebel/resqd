//! Shared application state and config.

use crate::auth::{AuthConfig, AuthState};
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
    /// Whether passkey authentication is enabled. When false, the auth
    /// routes return 400 and vault endpoints remain public (legacy alpha
    /// mode — used for tests and for the smoke-test deploy path).
    pub auth_enabled: bool,
    /// Auth config (only required when `auth_enabled`).
    pub auth: Option<AuthConfig>,
    /// Uppercase ISO-3166-1 alpha-2 country codes we refuse to serve.
    /// Set via `RESQD_BLOCKED_COUNTRIES` (comma-separated). Empty list
    /// = no blocking. Enforcement is middleware-level based on the
    /// `cf-ipcountry` header Cloudflare injects — best-effort only,
    /// documented in `docs/JURISDICTION.md`. A real CF dashboard rule
    /// should sit in front of this for defence-in-depth.
    pub blocked_countries: Vec<String>,
    /// Shared secret the Cloudflare Worker injects as `x-origin-secret`.
    /// If set, requests without a matching header are rejected with 403.
    /// This prevents direct-to-API-Gateway access that bypasses CF Access.
    pub origin_secret: Option<String>,
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

        let auth_enabled = std::env::var("RESQD_AUTH_ENABLED")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let auth = if auth_enabled {
            Some(AuthConfig::from_env().context("auth config")?)
        } else {
            None
        };

        let blocked_countries = std::env::var("RESQD_BLOCKED_COUNTRIES")
            .ok()
            .map(|s| {
                s.split(',')
                    .map(|v| v.trim().to_ascii_uppercase())
                    .filter(|v| v.len() == 2)
                    .collect()
            })
            .unwrap_or_default();

        let origin_secret = std::env::var("RESQD_ORIGIN_SECRET").ok().filter(|s| !s.is_empty());

        Ok(Self {
            s3_bucket,
            gcs_bucket,
            chain_enabled,
            chain,
            auth_enabled,
            auth,
            blocked_countries,
            origin_secret,
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
    /// Passkey auth state (webauthn builder + DynamoDB client). `None`
    /// when `auth_enabled = false`. Handlers that need auth must check
    /// this and return 400/401.
    pub auth: Option<AuthState>,
    /// CloudWatch client for metrics endpoint.
    pub cloudwatch: aws_sdk_cloudwatch::Client,
    /// S3 client for admin metrics (vault object stats).
    pub s3_admin: aws_sdk_s3::Client,
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

        let auth = if let Some(auth_config) = config.auth.clone() {
            Some(
                AuthState::from_config(auth_config)
                    .await
                    .context("init auth state")?,
            )
        } else {
            None
        };

        // Admin-only AWS clients — reuse the default credential chain.
        let aws_conf = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let cloudwatch = aws_sdk_cloudwatch::Client::new(&aws_conf);
        let s3_admin = aws_sdk_s3::Client::new(&aws_conf);

        Ok(Self {
            config,
            vault,
            s3: s3_concrete,
            chain,
            auth,
            cloudwatch,
            s3_admin,
        })
    }
}
