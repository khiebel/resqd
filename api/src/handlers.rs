//! HTTP route handlers.

use crate::state::{AppState, LARGE_BLOB_PREFIX};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use resqd_core::canary::CanaryChain;
use resqd_core::crypto::hash::AssetHash;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};
use uuid::Uuid;

/// Number of shards the client erasure-codes into. Mirrors
/// `resqd_core::erasure::TOTAL_SHARDS` but declared here so the handler
/// doesn't need to pull the erasure module in.
const TOTAL_SHARDS: usize = 6;

/// Presigned URL TTL. The client needs to finish uploading all 6 shards
/// within this window; if it doesn't, init has to be called again.
const PRESIGN_TTL: Duration = Duration::from_secs(900); // 15 min

// -------------------------------------------------------------------
//                          Response types
// -------------------------------------------------------------------

#[derive(Serialize)]
pub struct UploadResponse {
    pub asset_id: String,
    pub size_bytes: u64,
    pub canary_sequence: u64,
    pub canary_hash_hex: String,
    pub anchored_on_chain: bool,
}

#[derive(Serialize)]
pub struct VerifyResponse {
    pub asset_id: String,
    pub expected_count: u64,
    pub on_chain_access_count: u64,
    pub matches: bool,
}

#[derive(Deserialize)]
pub struct VerifyQuery {
    pub count: u64,
}

// ── Large-file path types ────────────────────────────────────────────

/// Response from `POST /vault/init` — a fresh asset id plus 6 presigned
/// PUT URLs, one per shard. The client is expected to erasure-code its
/// encrypted blob into TOTAL_SHARDS pieces in WASM and PUT each one to
/// the corresponding `upload_url` in parallel, then call
/// `POST /vault/{asset_id}/commit` with the shard sizes to finalize.
#[derive(Serialize)]
pub struct InitResponse {
    pub asset_id: String,
    pub data_shards: u8,
    pub parity_shards: u8,
    pub shards: Vec<ShardUploadSlot>,
    /// How long the presigned URLs are valid, in seconds.
    pub ttl_seconds: u64,
}

#[derive(Serialize)]
pub struct ShardUploadSlot {
    pub index: u8,
    pub upload_url: String,
}

/// Client-supplied commit payload. `original_len` is the byte length of
/// the encrypted blob before erasure coding (the value `erasure_encode`
/// returned in WASM); required to strip padding on read. The client
/// already knows this locally so we take it as input rather than trying
/// to re-derive it from shard sizes.
#[derive(Deserialize)]
pub struct CommitRequest {
    pub original_len: u64,
}

/// Response from `POST /vault/{id}/commit` — same shape as the legacy
/// upload response so the frontend can treat them uniformly.
#[derive(Serialize)]
pub struct CommitResponse {
    pub asset_id: String,
    pub original_len: u64,
    pub canary_sequence: u64,
    pub canary_hash_hex: String,
    pub anchored_on_chain: bool,
    pub data_shards: u8,
    pub parity_shards: u8,
}

/// Response body for `GET /vault/{id}` when the asset lives in the
/// sharded/large mode. The client fetches each shard URL in parallel
/// and reconstructs the blob via `erasure_reconstruct` in WASM. Missing
/// shards come back as `download_url: null` (any 4 of 6 suffice).
#[derive(Serialize)]
pub struct ShardedFetchResponse {
    pub mode: &'static str, // always "sharded"
    pub asset_id: String,
    pub original_len: u64,
    pub data_shards: u8,
    pub parity_shards: u8,
    pub shards: Vec<ShardDownloadSlot>,
    pub canary_sequence: u64,
    pub canary_hash_hex: String,
    pub ttl_seconds: u64,
}

#[derive(Serialize)]
pub struct ShardDownloadSlot {
    pub index: u8,
    pub download_url: Option<String>,
}

/// Per-asset manifest we persist alongside the canary chain sidecar. Tells
/// the fetch handler whether an asset is stored as sharded big-blob shards
/// or as inline bytes in the erasure-coded vault.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct AssetManifest {
    mode: String, // "sharded"
    original_len: u64,
    data_shards: u8,
    parity_shards: u8,
}

// -------------------------------------------------------------------
//                          Error handling
// -------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("storage error: {0}")]
    Storage(#[from] resqd_storage::StorageError),
    #[error("chain error: {0}")]
    Chain(#[from] resqd_chain::ChainError),
    #[error("not found")]
    NotFound,
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, msg) = match &self {
            ApiError::NotFound => (StatusCode::NOT_FOUND, self.to_string()),
            ApiError::BadRequest(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            _ => {
                error!(error = %self, "handler error");
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string())
            }
        };
        (status, Json(serde_json::json!({ "error": msg }))).into_response()
    }
}

type ApiResult<T> = Result<T, ApiError>;

// -------------------------------------------------------------------
//                          Handlers
// -------------------------------------------------------------------

/// Liveness probe.
pub async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "service": "resqd-api",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

/// `POST /vault` — upload raw bytes. Returns a fresh asset_id and the
/// initial canary commitment (anchored on-chain if the chain is enabled).
///
/// NOTE: This is an MVP shape. In the real product the client encrypts
/// with WASM before upload; the server never sees plaintext. For now we
/// store whatever the client sends so we can wire the full round-trip.
pub async fn upload(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> ApiResult<Json<UploadResponse>> {
    if body.is_empty() {
        return Err(ApiError::BadRequest("empty body".into()));
    }

    // Fresh opaque asset_id (uuid v4). The canary chain uses the string
    // form; the on-chain anchor uses BLAKE3(asset_id) as its bytes32 key
    // so we never leak the raw id on-chain.
    let asset_id = Uuid::new_v4().to_string();
    let asset_id_hash: [u8; 32] = AssetHash::from_bytes(asset_id.as_bytes()).0;

    info!(asset_id = %asset_id, size = body.len(), "upload");

    // Persist the bytes through the erasure-coded multi-cloud vault.
    state.vault.put(&asset_id, body.clone()).await?;

    // Initialize the canary chain.
    let chain = CanaryChain::new(&asset_id);
    let initial = chain.commitments[0].clone();

    // Persist the canary chain JSON alongside the asset (separate key).
    // This is the simplest durable store; later we may push it into the
    // vault's meta sidecar or a dedicated manifest.
    let chain_json = serde_json::to_vec(&chain)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!(e)))?;
    state
        .vault
        .put(&chain_key(&asset_id), Bytes::from(chain_json))
        .await?;

    // Anchor the initial commitment on-chain if the chain is enabled.
    let anchored = if let Some(client) = &state.chain {
        match client.anchor_commitment(asset_id_hash, &initial).await {
            Ok(receipt) => {
                info!(
                    asset_id = %asset_id,
                    block = ?receipt.block_number,
                    "anchored initial commitment"
                );
                true
            }
            Err(e) => {
                error!(error = %e, asset_id = %asset_id, "anchor failed");
                // Don't fail the upload — log and continue. The chain
                // state can be reconciled later. This is an explicit
                // design tradeoff: prefer availability over consistency
                // for the MVP. Revisit when we add an anchor retry queue.
                false
            }
        }
    } else {
        false
    };

    Ok(Json(UploadResponse {
        asset_id,
        size_bytes: body.len() as u64,
        canary_sequence: initial.sequence,
        canary_hash_hex: initial.hash.to_hex(),
        anchored_on_chain: anchored,
    }))
}

/// `POST /vault/init` — start a sharded large-file upload. Returns an
/// asset_id and 6 presigned S3 PUT URLs (one per Reed-Solomon shard).
/// The client erasure-codes its encrypted blob client-side via WASM,
/// PUTs each shard to its slot, then calls `/vault/{id}/commit` with
/// the original byte length to finalize.
pub async fn init(State(state): State<Arc<AppState>>) -> ApiResult<Json<InitResponse>> {
    let asset_id = Uuid::new_v4().to_string();
    info!(asset_id = %asset_id, "init sharded upload");

    let mut shards = Vec::with_capacity(TOTAL_SHARDS);
    for i in 0..TOTAL_SHARDS {
        let key = shard_key(&asset_id, i);
        let url = state
            .s3
            .presign_put(&key, "application/octet-stream", PRESIGN_TTL)
            .await?;
        shards.push(ShardUploadSlot {
            index: i as u8,
            upload_url: url,
        });
    }

    Ok(Json(InitResponse {
        asset_id,
        data_shards: 4,
        parity_shards: 2,
        shards,
        ttl_seconds: PRESIGN_TTL.as_secs(),
    }))
}

/// `POST /vault/{id}/commit` — finalize a sharded upload. Verifies all 6
/// shards exist in S3, persists the manifest + initial canary chain, and
/// anchors the first commitment on-chain. Idempotent: if the manifest
/// already exists for this asset_id, returns the existing state.
pub async fn commit(
    State(state): State<Arc<AppState>>,
    Path(asset_id): Path<String>,
    Json(req): Json<CommitRequest>,
) -> ApiResult<Json<CommitResponse>> {
    info!(asset_id = %asset_id, original_len = req.original_len, "commit sharded upload");

    // Idempotency: if the manifest already exists, return the existing state
    // rather than re-creating the chain. Prevents double-anchoring on retries.
    if let Ok(existing) = state.vault.get(&manifest_key(&asset_id)).await {
        let manifest: AssetManifest = serde_json::from_slice(&existing)
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("decode manifest: {e}")))?;
        let chain_bytes = state.vault.get(&chain_key(&asset_id)).await?;
        let chain: CanaryChain = serde_json::from_slice(&chain_bytes)
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("decode chain: {e}")))?;
        let initial = &chain.commitments[0];
        return Ok(Json(CommitResponse {
            asset_id: asset_id.clone(),
            original_len: manifest.original_len,
            canary_sequence: initial.sequence,
            canary_hash_hex: initial.hash.to_hex(),
            anchored_on_chain: state.chain.is_some(),
            data_shards: manifest.data_shards,
            parity_shards: manifest.parity_shards,
        }));
    }

    // Verify all 6 shards exist in S3. Can't short-circuit at 4/6 because
    // for the sharded mode we require the client to upload all shards
    // — otherwise the stored resilience doesn't match the promise.
    for i in 0..TOTAL_SHARDS {
        let key = shard_key(&asset_id, i);
        let exists = state.s3.head(&key).await?;
        if !exists {
            return Err(ApiError::BadRequest(format!(
                "shard {i} not found at {key} — upload all 6 before commit"
            )));
        }
    }

    // Build the manifest + canary chain sidecar.
    let manifest = AssetManifest {
        mode: "sharded".into(),
        original_len: req.original_len,
        data_shards: 4,
        parity_shards: 2,
    };
    let manifest_json = serde_json::to_vec(&manifest)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!(e)))?;
    state
        .vault
        .put(&manifest_key(&asset_id), Bytes::from(manifest_json))
        .await?;

    let chain = CanaryChain::new(&asset_id);
    let initial = chain.commitments[0].clone();
    let chain_json = serde_json::to_vec(&chain)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!(e)))?;
    state
        .vault
        .put(&chain_key(&asset_id), Bytes::from(chain_json))
        .await?;

    let asset_id_hash: [u8; 32] = AssetHash::from_bytes(asset_id.as_bytes()).0;
    let anchored = if let Some(client) = &state.chain {
        match client.anchor_commitment(asset_id_hash, &initial).await {
            Ok(receipt) => {
                info!(
                    asset_id = %asset_id,
                    block = ?receipt.block_number,
                    "anchored sharded upload"
                );
                true
            }
            Err(e) => {
                error!(error = %e, asset_id = %asset_id, "anchor failed");
                false
            }
        }
    } else {
        false
    };

    Ok(Json(CommitResponse {
        asset_id,
        original_len: req.original_len,
        canary_sequence: initial.sequence,
        canary_hash_hex: initial.hash.to_hex(),
        anchored_on_chain: anchored,
        data_shards: 4,
        parity_shards: 2,
    }))
}

/// `GET /vault/{id}` — fetch an asset. Rotates the canary chain and
/// anchors the new commitment before returning anything. This is the
/// single most important invariant: **no read without a rotation**.
///
/// Handles both storage modes:
/// - Sharded (large files): returns JSON with 6 presigned download URLs
///   that the client reassembles in WASM. Manifest presence signals this.
/// - Inline (small files, legacy): returns raw bytes from the
///   erasure-coded vault. Fallback when no manifest exists.
pub async fn fetch(
    State(state): State<Arc<AppState>>,
    Path(asset_id): Path<String>,
) -> ApiResult<Response> {
    info!(asset_id = %asset_id, "fetch");

    // Load the current canary chain.
    let chain_bytes = match state.vault.get(&chain_key(&asset_id)).await {
        Ok(b) => b,
        Err(resqd_storage::StorageError::NotFound(_)) => return Err(ApiError::NotFound),
        Err(e) => return Err(ApiError::Storage(e)),
    };
    let mut chain: CanaryChain = serde_json::from_slice(&chain_bytes)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("decode chain: {e}")))?;

    // Rotate BEFORE serving anything. Non-negotiable.
    let new_commitment = chain.rotate();

    // Persist the updated chain.
    let chain_json = serde_json::to_vec(&chain)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!(e)))?;
    state
        .vault
        .put(&chain_key(&asset_id), Bytes::from(chain_json))
        .await?;

    // Anchor on-chain if enabled. Log-and-continue on failure.
    if let Some(client) = &state.chain {
        let asset_id_hash: [u8; 32] = AssetHash::from_bytes(asset_id.as_bytes()).0;
        if let Err(e) = client.anchor_commitment(asset_id_hash, &new_commitment).await {
            error!(error = %e, asset_id = %asset_id, "rotation anchor failed");
        }
    }

    // Decide which storage mode to serve from.
    match state.vault.get(&manifest_key(&asset_id)).await {
        // Sharded / large mode
        Ok(m) => {
            let manifest: AssetManifest = serde_json::from_slice(&m)
                .map_err(|e| ApiError::Internal(anyhow::anyhow!("decode manifest: {e}")))?;

            let mut slots = Vec::with_capacity(TOTAL_SHARDS);
            for i in 0..TOTAL_SHARDS {
                let key = shard_key(&asset_id, i);
                let url = match state.s3.presign_get(&key, PRESIGN_TTL).await {
                    Ok(u) => Some(u),
                    Err(e) => {
                        warn!(error = %e, shard = i, "presign get failed");
                        None
                    }
                };
                slots.push(ShardDownloadSlot {
                    index: i as u8,
                    download_url: url,
                });
            }

            let resp = ShardedFetchResponse {
                mode: "sharded",
                asset_id: asset_id.clone(),
                original_len: manifest.original_len,
                data_shards: manifest.data_shards,
                parity_shards: manifest.parity_shards,
                shards: slots,
                canary_sequence: new_commitment.sequence,
                canary_hash_hex: new_commitment.hash.to_hex(),
                ttl_seconds: PRESIGN_TTL.as_secs(),
            };
            Ok((
                [
                    (
                        "x-resqd-canary-sequence",
                        new_commitment.sequence.to_string(),
                    ),
                    ("x-resqd-canary-hash", new_commitment.hash.to_hex()),
                ],
                Json(resp),
            )
                .into_response())
        }

        // No manifest → legacy inline mode. Fall through to the
        // erasure-coded vault for the bytes.
        Err(resqd_storage::StorageError::NotFound(_)) => {
            let bytes = state.vault.get(&asset_id).await.map_err(|e| match e {
                resqd_storage::StorageError::NotFound(_) => ApiError::NotFound,
                other => ApiError::Storage(other),
            })?;
            Ok((
                [
                    ("content-type", "application/octet-stream".to_string()),
                    (
                        "x-resqd-canary-sequence",
                        new_commitment.sequence.to_string(),
                    ),
                    ("x-resqd-canary-hash", new_commitment.hash.to_hex()),
                ],
                bytes,
            )
                .into_response())
        }

        Err(e) => Err(ApiError::Storage(e)),
    }
}

/// `GET /vault/{id}/verify?count=N` — check that the on-chain anchor state
/// matches the owner's expected access count. If the chain is disabled,
/// falls back to checking the off-chain canary chain only.
pub async fn verify(
    State(state): State<Arc<AppState>>,
    Path(asset_id): Path<String>,
    Query(q): Query<VerifyQuery>,
) -> ApiResult<Json<VerifyResponse>> {
    let chain_bytes = match state.vault.get(&chain_key(&asset_id)).await {
        Ok(b) => b,
        Err(resqd_storage::StorageError::NotFound(_)) => return Err(ApiError::NotFound),
        Err(e) => return Err(ApiError::Storage(e)),
    };
    let chain: CanaryChain = serde_json::from_slice(&chain_bytes)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("decode chain: {e}")))?;
    let offchain_count = chain.access_count();

    let onchain_count = if let Some(client) = &state.chain {
        let asset_id_hash: [u8; 32] = AssetHash::from_bytes(asset_id.as_bytes()).0;
        let anchor = client.get_anchor(asset_id_hash).await?;
        if anchor.exists {
            anchor.sequence + 1
        } else {
            0
        }
    } else {
        offchain_count
    };

    Ok(Json(VerifyResponse {
        asset_id,
        expected_count: q.count,
        on_chain_access_count: onchain_count,
        matches: onchain_count == q.count,
    }))
}

/// The sidecar key where each asset's canary chain JSON lives in the vault.
fn chain_key(asset_id: &str) -> String {
    format!("_chain/{asset_id}.json")
}

/// Sidecar key for the asset manifest (large/sharded mode only).
fn manifest_key(asset_id: &str) -> String {
    format!("_manifest/{asset_id}.json")
}

/// Raw-S3 key where a sharded-mode shard lives.
fn shard_key(asset_id: &str, index: usize) -> String {
    format!("{LARGE_BLOB_PREFIX}{asset_id}/shard-{index}")
}
