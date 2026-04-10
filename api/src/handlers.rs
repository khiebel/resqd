//! HTTP route handlers.

use crate::auth::{AuthUser, ConsumeStorageResult};
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
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{error, info, warn};
use uuid::Uuid;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Queue a failed anchor for later retry. Best-effort — never fails the
/// main request. Writes to the `resqd-anchor-retries` DynamoDB table so
/// an admin can sweep and re-anchor later via `POST /admin/retry-anchors`.
async fn queue_anchor_retry(
    state: &AppState,
    asset_id: &str,
    sequence: u64,
    hash_hex: &str,
    prev_hash_hex: Option<&str>,
) {
    let Some(auth) = &state.auth else { return };
    let table = &auth.config.anchor_retry_table;
    let now = now_secs();
    let expires_at = now + 7 * 24 * 3600; // 7-day TTL

    let mut builder = auth
        .dynamo
        .put_item()
        .table_name(table)
        .item("pk", aws_sdk_dynamodb::types::AttributeValue::S(asset_id.to_string()))
        .item("sk", aws_sdk_dynamodb::types::AttributeValue::S(sequence.to_string()))
        .item("hash_hex", aws_sdk_dynamodb::types::AttributeValue::S(hash_hex.to_string()))
        .item("created_at", aws_sdk_dynamodb::types::AttributeValue::N(now.to_string()))
        .item("status", aws_sdk_dynamodb::types::AttributeValue::S("pending".to_string()))
        .item("attempts", aws_sdk_dynamodb::types::AttributeValue::N("0".to_string()))
        .item("expires_at", aws_sdk_dynamodb::types::AttributeValue::N(expires_at.to_string()));

    if let Some(ph) = prev_hash_hex {
        builder = builder.item("prev_hash_hex", aws_sdk_dynamodb::types::AttributeValue::S(ph.to_string()));
    }

    if let Err(e) = builder.send().await {
        error!(error = %e, asset_id = %asset_id, sequence = %sequence, "failed to queue anchor retry");
    } else {
        info!(asset_id = %asset_id, sequence = %sequence, "queued anchor retry");
    }
}

/// Owner sidecar key. Written on commit so the listing endpoint can
/// enumerate a user's assets via `ListObjectsV2` with this prefix.
fn owner_sidecar_key(user_id: &str, asset_id: &str) -> String {
    format!("_owner/{user_id}/{asset_id}.json")
}

/// Parse an asset_id out of an owner sidecar key like `_owner/{uid}/{id}.json`.
fn asset_id_from_sidecar_key(key: &str) -> Option<&str> {
    let name = key.rsplit('/').next()?;
    name.strip_suffix(".json")
}

// ── Share sidecars ───────────────────────────────────────────────────
//
// Shares are implemented entirely in raw-S3 sidecars — no new DynamoDB
// table. A share has two sidecar faces:
//
// 1. `_shares/{asset_id}/{recipient_user_id}.json` — scoped to the
//    asset. Lets the owner list "who is this shared with" with one
//    `list_prefix` call, and drives the DELETE path (unshare) when the
//    owner only knows the recipient email/user_id, not the share
//    contents.
//
// 2. `_shared_with/{recipient_user_id}/{asset_id}.json` — scoped to
//    the recipient. Drives the recipient's "Shared with me" vault
//    listing with one `list_prefix` call, mirroring the existing
//    `_owner/{user_id}/...` pattern. Contains the recipient-specific
//    wrapped per-asset key and the sender's pubkey so the client can
//    ECDH-derive and unwrap without a second round trip.
//
// Both sidecars carry the same opaque encrypted-meta blob (sealed
// under the *sender's* master key, re-encrypted under the ECDH wrap
// key so the recipient can actually decrypt it) so the recipient's
// list view can show a real filename without fetching the asset
// manifest. The share flow is read-only: the sender encrypts content
// once for the recipient, the server stores that ciphertext, the
// recipient decrypts. Nothing about the sidecar lets a recipient
// modify, delete, or re-share the underlying asset — those paths
// check `asset.owner_id == caller.user_id` and reject sharees.

/// Sidecar key for ring-owned assets. Mirrors the _owner/{uid}/...
/// pattern but scoped to a ring_id so list_vault can enumerate all
/// assets belonging to a ring with one `list_prefix` call.
fn ring_asset_sidecar_key(ring_id: &str, asset_id: &str) -> String {
    format!("_ring_assets/{ring_id}/{asset_id}.json")
}

fn share_sidecar_owner_key(asset_id: &str, recipient_user_id: &str) -> String {
    format!("_shares/{asset_id}/{recipient_user_id}.json")
}

fn share_sidecar_recipient_key(recipient_user_id: &str, asset_id: &str) -> String {
    format!("_shared_with/{recipient_user_id}/{asset_id}.json")
}

/// Parse an asset_id out of a `_shared_with/{uid}/{id}.json` sidecar key.
fn asset_id_from_shared_with_key(key: &str) -> Option<&str> {
    let name = key.rsplit('/').next()?;
    name.strip_suffix(".json")
}

/// Persisted shape of an owner-side share sidecar at
/// `_shares/{asset_id}/{recipient_user_id}.json`. Minimal — it's just
/// the index entry the owner needs to enumerate / revoke shares.
/// Everything the recipient needs to actually read the asset lives in
/// the recipient-side sidecar.
#[derive(Serialize, Deserialize, Clone, Debug)]
struct OwnerShareRecord {
    asset_id: String,
    recipient_user_id: String,
    recipient_email: String,
    /// Unix seconds the share was created. Used for UI sort order.
    created_at: u64,
}

/// Persisted shape of the recipient-side sidecar at
/// `_shared_with/{recipient_user_id}/{asset_id}.json`. Self-contained:
/// everything the recipient needs to decrypt and read the asset lives
/// here, because the recipient is never allowed to read the owner's
/// original asset manifest (which carries the owner's wrapped key).
#[derive(Serialize, Deserialize, Clone, Debug)]
struct RecipientShareRecord {
    asset_id: String,
    /// user_id and email of the sharing user. Display-name is surfaced
    /// in the recipient's UI ("shared by <owner>") and the user_id is
    /// used by the fetch path to look up the sender's pubkey on the
    /// read side.
    sender_user_id: String,
    sender_email: String,
    /// Sender's long-term X25519 public identity, base64. Copied here
    /// so the recipient can ECDH-derive the wrap key without calling
    /// `/users/lookup` every read.
    sender_pubkey_x25519_b64: String,
    /// The per-asset XChaCha20 key, wrapped under the ECDH-derived
    /// share wrap key (HKDF(`ECDH(a_priv, b_pub)`, info=`resqd-share-v1
    /// || 0x00 || asset_id`)). The recipient recomputes the same wrap
    /// key from their own privkey + the sender's pubkey and unwraps.
    wrapped_key_for_recipient_b64: String,
    /// `{name, mime}` JSON sealed under the SAME ECDH-derived wrap key
    /// as the per-asset key, so the recipient can surface the real
    /// filename in their "Shared with me" listing without decrypting
    /// the whole asset. Optional — sender may choose to omit.
    #[serde(default)]
    encrypted_meta_for_recipient_b64: Option<String>,
    created_at: u64,
}

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
///
/// `wrapped_key_b64` is the per-asset encryption key sealed under the
/// user's PRF-derived master key, base64-encoded. Optional so that the
/// legacy unauthenticated flow still works. When present, it's round-
/// tripped verbatim via the asset manifest and returned on fetch; the
/// server never unwraps it.
///
/// `encrypted_meta_b64` is a client-encrypted `{name, mime}` JSON blob
/// sealed under the user's master key. Returned on both fetch and the
/// `/vault` listing so the client can display a real filename in the
/// list view without downloading + decrypting the whole asset. Server
/// is zero-knowledge of the contents — it's just an opaque base64 string.
#[derive(Deserialize)]
pub struct CommitRequest {
    pub original_len: u64,
    #[serde(default)]
    pub wrapped_key_b64: Option<String>,
    #[serde(default)]
    pub encrypted_meta_b64: Option<String>,
    /// When present, the asset is owned by a family ring instead of
    /// an individual user. The per-asset key in `wrapped_key_b64` is
    /// wrapped to the ring's X25519 pubkey via `sender_wrap_key(
    /// uploader_priv, ring_pub, asset_id)`. Any ring member who holds
    /// the ring privkey can read. Quota is charged to the uploader.
    #[serde(default)]
    pub ring_id: Option<String>,
    /// Uploader's X25519 pubkey, required when `ring_id` is present.
    /// Stored in the manifest so ring members can ECDH-derive the
    /// wrap key on the read side: `recipient_wrap_key(ring_priv,
    /// uploader_pub, asset_id)`.
    #[serde(default)]
    pub uploader_pubkey_x25519_b64: Option<String>,
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
    /// How the caller came to see this asset: `"owner"` when the
    /// caller is the registered owner (the wrapped_key is sealed
    /// under their own master key) or `"sharee"` when the caller is
    /// a recipient of a share (the wrapped_key is the
    /// ECDH-wrap-key-sealed copy from the share sidecar and
    /// `sender_pubkey_x25519_b64` must be present).
    pub role: &'static str,
    /// Base64-encoded per-asset key. For `role == "owner"` this is
    /// wrapped under the caller's master key. For `role == "sharee"`
    /// this is wrapped under the ECDH-derived share wrap key — the
    /// caller must recompute that wrap key via
    /// `HKDF(ECDH(their_privkey, sender_pubkey), "resqd-share-v1 ||
    /// 0x00 || asset_id")` before unwrapping.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wrapped_key_b64: Option<String>,
    /// Client-encrypted `{name, mime}` JSON. Same wrapping rules as
    /// `wrapped_key_b64` — sealed under the master key when the
    /// caller is the owner, sealed under the share wrap key when the
    /// caller is a sharee.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_meta_b64: Option<String>,
    /// Sender's long-term X25519 public identity, base64. Only
    /// present on sharee fetches — owners don't need it since they
    /// unwrap under their own master key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_pubkey_x25519_b64: Option<String>,
    /// Ring id, when the asset belongs to a family ring.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ring_id: Option<String>,
    /// Uploader's X25519 pubkey — present on ring assets so the
    /// reader can `recipient_wrap_key(ring_priv, uploader_pub,
    /// asset_id)` to unwrap the per-asset key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uploader_pubkey_x25519_b64: Option<String>,
}

/// Entry in the `GET /vault` listing response. `encrypted_meta_b64`
/// is the same opaque blob the client sent at commit time — the server
/// just passes it back so the browser can decrypt the filename locally.
///
/// When `role == "sharee"` the item was surfaced via the
/// `_shared_with/{caller_user_id}/...` sidecar, and the caller cannot
/// perform any mutating action on it — the vault UI hides Delete and
/// Share controls for shared items, and the API rejects those calls
/// at the handler level regardless.
#[derive(Serialize)]
pub struct VaultListItem {
    pub asset_id: String,
    pub created_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_meta_b64: Option<String>,
    /// `"owner"` or `"sharee"`. Default on existing rows (which predate
    /// sharing) is `"owner"`.
    pub role: &'static str,
    /// For sharees only: the email of the sender. Lets the UI say
    /// "shared by <sender>" without another round trip.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shared_by_email: Option<String>,
    /// For sharees only: sender's X25519 pubkey, copied straight out
    /// of the share sidecar. Lets the Recovery Kit export assemble a
    /// sharee-decryptable record for this asset without a second round
    /// trip to `/users/lookup`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_pubkey_x25519_b64: Option<String>,
    /// Ring id when role == "ring_member".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ring_id: Option<String>,
    /// Uploader pubkey for ring assets.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uploader_pubkey_x25519_b64: Option<String>,
}

#[derive(Serialize)]
pub struct VaultListResponse {
    pub user_id: String,
    pub count: usize,
    pub assets: Vec<VaultListItem>,
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
    /// Owner of this asset (JWT `sub` of the user who committed it).
    /// `None` means the asset was uploaded in legacy anonymous mode,
    /// pre-auth. Those assets stay accessible to anyone with the id
    /// (matching v0 behavior) so we don't retroactively lock people
    /// out of their test data.
    #[serde(default)]
    owner_id: Option<String>,
    /// Per-asset key wrapped under the owner's master key, base64.
    #[serde(default)]
    wrapped_key_b64: Option<String>,
    /// Client-encrypted `{name, mime}` JSON sealed under the master key.
    #[serde(default)]
    encrypted_meta_b64: Option<String>,
    /// Unix seconds at commit time. Used by the listing endpoint for
    /// "recently added" sorting.
    #[serde(default)]
    created_at: Option<u64>,
    /// When present, this asset belongs to a family ring (Phase 3).
    /// The `wrapped_key_b64` is wrapped to the ring's X25519 pubkey,
    /// not the individual user's master key.
    #[serde(default)]
    ring_id: Option<String>,
    /// X25519 pubkey of the user who uploaded this ring asset. Required
    /// when `ring_id` is present — ring members need it for the read-
    /// side ECDH: `recipient_wrap_key(ring_priv, uploader_pub, asset_id)`.
    #[serde(default)]
    uploader_pubkey_x25519_b64: Option<String>,
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
    #[error("quota exceeded: used {used} of {cap} bytes, cannot add {requested} more")]
    QuotaExceeded {
        used: u64,
        cap: u64,
        requested: u64,
    },
    #[error("auth: {0}")]
    Auth(#[from] crate::auth::AuthError),
    #[error("internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match &self {
            ApiError::NotFound => {
                (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": self.to_string() }))).into_response()
            }
            ApiError::BadRequest(_) => {
                (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": self.to_string() }))).into_response()
            }
            ApiError::QuotaExceeded { used, cap, requested } => {
                // 413 Payload Too Large — the client SHOULD NOT retry
                // and should show a "you're out of space" message with
                // the exact numbers so the user can decide what to delete.
                (
                    StatusCode::PAYLOAD_TOO_LARGE,
                    Json(serde_json::json!({
                        "error": self.to_string(),
                        "code": "quota_exceeded",
                        "storage_used_bytes": used,
                        "storage_quota_bytes": cap,
                        "requested_bytes": requested,
                    })),
                )
                    .into_response()
            }
            ApiError::Auth(crate::auth::AuthError::Unauthorized) => {
                (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": "unauthorized" }))).into_response()
            }
            _ => {
                error!(error = %self, "handler error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": self.to_string() })),
                )
                    .into_response()
            }
        }
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
                // Don't fail the upload — log and continue. Queue for
                // later retry via POST /admin/retry-anchors.
                queue_anchor_retry(
                    &state, &asset_id, initial.sequence,
                    &initial.hash.to_hex(), None,
                ).await;
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
pub async fn init(State(state): State<Arc<AppState>>, user: AuthUser) -> ApiResult<Json<InitResponse>> {
    let asset_id = Uuid::new_v4().to_string();
    info!(asset_id = %asset_id, user_id = %user.user_id, "init sharded upload");

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
///
/// When auth is enabled and the caller is authenticated, the user id is
/// recorded as the asset owner and a sidecar is written so the listing
/// endpoint can enumerate the user's assets. Anonymous commits remain
/// allowed for legacy/test flows.
pub async fn commit(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(asset_id): Path<String>,
    Json(req): Json<CommitRequest>,
) -> ApiResult<Json<CommitResponse>> {
    info!(asset_id = %asset_id, original_len = req.original_len, owner = %user.user_id, "commit sharded upload");

    // Idempotency: if the manifest already exists, return the existing state
    // rather than re-creating the chain. Prevents double-anchoring on retries.
    if let Ok(existing) = state.vault.get(&manifest_key(&asset_id)).await {
        let manifest: AssetManifest = serde_json::from_slice(&existing)
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("decode manifest: {e}")))?;
        // If the existing manifest has an owner, only the owner can re-commit.
        if let Some(existing_owner) = &manifest.owner_id {
            if existing_owner != &user.user_id {
                return Err(ApiError::NotFound);
            }
        }
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

    // Quota check — reject if the upload would exceed the user's storage cap.
    // Done AFTER shard existence so a client can't burn someone else's
    // upload slot by rejecting early.
    if let Some(auth_state) = state.auth.as_ref() {
        match crate::auth::try_consume_storage(auth_state, &user.email, req.original_len).await? {
            ConsumeStorageResult::Ok => {}
            ConsumeStorageResult::Exceeded { used, cap, requested } => {
                return Err(ApiError::QuotaExceeded { used, cap, requested });
            }
        }
    }

    // ── Ring-owned asset validation ──
    //
    // If the caller specified a ring_id, verify membership + write role.
    // Ring assets need an uploader pubkey for the read-side ECDH so the
    // client must supply it, and it must match their stored identity.
    if let Some(ring_id) = &req.ring_id {
        let auth_state = state.auth.as_ref().ok_or(ApiError::Auth(
            crate::auth::AuthError::Unauthorized,
        ))?;
        let membership = crate::rings::get_caller_membership_pub(
            auth_state, ring_id, &user.user_id,
        )
        .await
        .map_err(|_| ApiError::NotFound)?
        .ok_or(ApiError::NotFound)?;
        if !membership.0.can_write() {
            return Err(ApiError::BadRequest(format!(
                "your ring role '{}' cannot upload — Owner or Adult required",
                membership.0.as_str()
            )));
        }
        // Uploader pubkey is required and must match.
        let up_pub = req.uploader_pubkey_x25519_b64.as_deref().ok_or(
            ApiError::BadRequest(
                "uploader_pubkey_x25519_b64 required when ring_id is present".into(),
            ),
        )?;
        let caller_row = crate::auth::get_user_by_email(auth_state, &user.email)
            .await
            .map_err(ApiError::from)?
            .ok_or(ApiError::Internal(anyhow::anyhow!("caller missing")))?;
        let stored_pk = caller_row.pubkey_x25519_b64.as_deref().unwrap_or("");
        if stored_pk != up_pub {
            return Err(ApiError::BadRequest(
                "uploader_pubkey does not match your stored identity".into(),
            ));
        }
    }

    // Build the manifest + canary chain sidecar.
    let owner_id = Some(user.user_id.clone());
    let created_at = now_secs();
    let manifest = AssetManifest {
        mode: "sharded".into(),
        original_len: req.original_len,
        data_shards: 4,
        parity_shards: 2,
        owner_id: owner_id.clone(),
        wrapped_key_b64: req.wrapped_key_b64.clone(),
        encrypted_meta_b64: req.encrypted_meta_b64.clone(),
        created_at: Some(created_at),
        ring_id: req.ring_id.clone(),
        uploader_pubkey_x25519_b64: req.uploader_pubkey_x25519_b64.clone(),
    };
    let manifest_json = serde_json::to_vec(&manifest)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!(e)))?;
    state
        .vault
        .put(&manifest_key(&asset_id), Bytes::from(manifest_json))
        .await?;

    // Sidecar: ring-owned assets go to `_ring_assets/{ring_id}/...`;
    // individually owned assets go to `_owner/{uid}/...`. Both carry
    // the same encrypted_meta_b64 blob for the listing endpoint.
    use resqd_storage::ObjectStore;
    if let Some(ring_id) = &req.ring_id {
        let sidecar = serde_json::json!({
            "asset_id": asset_id,
            "created_at": created_at,
            "encrypted_meta_b64": req.encrypted_meta_b64,
            "uploader_pubkey_x25519_b64": req.uploader_pubkey_x25519_b64,
        });
        let bytes = serde_json::to_vec(&sidecar)
            .map_err(|e| ApiError::Internal(anyhow::anyhow!(e)))?;
        state
            .s3
            .put(
                &ring_asset_sidecar_key(ring_id, &asset_id),
                Bytes::from(bytes),
            )
            .await?;
    } else if let Some(uid) = &owner_id {
        let sidecar = serde_json::json!({
            "asset_id": asset_id,
            "created_at": created_at,
            "encrypted_meta_b64": req.encrypted_meta_b64,
        });
        let bytes = serde_json::to_vec(&sidecar)
            .map_err(|e| ApiError::Internal(anyhow::anyhow!(e)))?;
        state
            .s3
            .put(&owner_sidecar_key(uid, &asset_id), Bytes::from(bytes))
            .await?;
    }

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
                error!(error = %e, asset_id = %asset_id, "anchor failed (commit)");
                queue_anchor_retry(
                    &state, &asset_id, initial.sequence,
                    &initial.hash.to_hex(), None,
                ).await;
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
    user: Option<AuthUser>,
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
            let prev = new_commitment.prev_hash.as_ref().map(|h| h.to_hex());
            queue_anchor_retry(
                &state, &asset_id, new_commitment.sequence,
                &new_commitment.hash.to_hex(), prev.as_deref(),
            ).await;
        }
    }

    // Decide which storage mode to serve from.
    match state.vault.get(&manifest_key(&asset_id)).await {
        // Sharded / large mode
        Ok(m) => {
            let manifest: AssetManifest = serde_json::from_slice(&m)
                .map_err(|e| ApiError::Internal(anyhow::anyhow!("decode manifest: {e}")))?;

            // Access check — four cases:
            //
            // 1. Ring-owned asset (manifest.ring_id present): caller
            //    must be a member of the ring. Returns wrapped_key
            //    and uploader_pubkey so the client can ECDH with the
            //    ring privkey. `role = "ring_member"`.
            //
            // 2. Individual owner: `role = "owner"`, wrapped_key
            //    sealed under the caller's master key.
            //
            // 3. Sharee: `_shared_with/{user_id}/{asset_id}` sidecar
            //    → `role = "sharee"`, wrapped_key sealed under the
            //    ECDH-derived share wrap key.
            //
            // 4. Pre-auth / legacy: `owner_id = None` → public by id.
            use resqd_storage::ObjectStore;

            // Ring asset — check ring membership.
            let ring_access: Option<(
                &'static str,
                Option<String>,
                Option<String>,
                Option<String>,
                Option<String>,
                Option<String>,
            )> = if let Some(ring_id) = &manifest.ring_id {
                let u = user.as_ref().ok_or(ApiError::NotFound)?;
                let auth_state = state.auth.as_ref().ok_or(ApiError::Auth(
                    crate::auth::AuthError::Unauthorized,
                ))?;
                let _membership = crate::rings::get_caller_membership_pub(
                    auth_state, ring_id, &u.user_id,
                )
                .await
                .map_err(|_| ApiError::NotFound)?
                .ok_or(ApiError::NotFound)?;
                Some((
                    "ring_member",
                    manifest.wrapped_key_b64.clone(),
                    manifest.encrypted_meta_b64.clone(),
                    None, // no sender_pubkey for rings
                    Some(ring_id.clone()),
                    manifest.uploader_pubkey_x25519_b64.clone(),
                ))
            } else {
                None
            };

            let (role, wrapped_key_b64, encrypted_meta_b64, sender_pubkey, resp_ring_id, resp_uploader_pub) =
                if let Some(ra) = ring_access {
                    ra
                } else {
                    match (&manifest.owner_id, &user) {
                        (Some(owner), Some(u)) if u.user_id == *owner => (
                            "owner",
                            manifest.wrapped_key_b64.clone(),
                            manifest.encrypted_meta_b64.clone(),
                            None,
                            None,
                            None,
                        ),
                        (Some(_), Some(u)) => {
                            let key = share_sidecar_recipient_key(&u.user_id, &asset_id);
                            match state.s3.get(&key).await {
                                Ok(bytes) => {
                                    let rec: RecipientShareRecord =
                                        serde_json::from_slice(&bytes).map_err(|e| {
                                            ApiError::Internal(anyhow::anyhow!(
                                                "decode share sidecar: {e}"
                                            ))
                                        })?;
                                    (
                                        "sharee",
                                        Some(rec.wrapped_key_for_recipient_b64),
                                        rec.encrypted_meta_for_recipient_b64,
                                        Some(rec.sender_pubkey_x25519_b64),
                                        None,
                                        None,
                                    )
                                }
                                Err(resqd_storage::StorageError::NotFound(_)) => {
                                    return Err(ApiError::NotFound);
                                }
                                Err(e) => return Err(ApiError::Storage(e)),
                            }
                        }
                        (Some(_), None) => return Err(ApiError::NotFound),
                        (None, _) => (
                            "owner",
                            manifest.wrapped_key_b64.clone(),
                            manifest.encrypted_meta_b64.clone(),
                            None,
                            None,
                            None,
                        ),
                    }
                };

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
                role,
                wrapped_key_b64,
                encrypted_meta_b64,
                sender_pubkey_x25519_b64: sender_pubkey,
                ring_id: resp_ring_id,
                uploader_pubkey_x25519_b64: resp_uploader_pub,
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

/// `DELETE /vault/{id}` — permanently remove an asset from the vault.
///
/// Requires auth and an exact owner match — users can only delete their
/// own assets. Legacy anonymous assets (owner_id = None) are rejected
/// with 404 to keep them immutable; they were created before the auth
/// system existed and there's no way to prove who owned them.
///
/// Deletes: 6 sharded blobs, asset manifest, canary chain sidecar, and
/// the owner sidecar. Best-effort: we proceed through every step and
/// only return an error if the *first* call fails (the bit that would
/// leave the asset still listable). A stray shard is harmless debris;
/// a stranded owner sidecar would keep the asset showing up in /vault.
///
/// The on-chain canary anchor is intentionally NOT deleted — the base
/// chain is append-only by design, and leaving the historical record
/// is part of the tamper-evidence story. If you delete an asset and
/// later try to prove "I never had it", the on-chain anchor is still
/// there showing otherwise. That's the feature.
pub async fn delete_asset(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(asset_id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    info!(asset_id = %asset_id, user_id = %user.user_id, "delete");

    // Load manifest and verify owner.
    let manifest_bytes = match state.vault.get(&manifest_key(&asset_id)).await {
        Ok(b) => b,
        Err(resqd_storage::StorageError::NotFound(_)) => return Err(ApiError::NotFound),
        Err(e) => return Err(ApiError::Storage(e)),
    };
    let manifest: AssetManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("decode manifest: {e}")))?;

    match manifest.owner_id.as_deref() {
        Some(owner) if owner == user.user_id => {}
        _ => return Err(ApiError::NotFound),
    }

    // Remove the owner sidecar first — this is what /vault listing reads,
    // so killing it first makes the asset disappear from the user's view
    // immediately even if a later step fails.
    use resqd_storage::ObjectStore;
    let sidecar_key = owner_sidecar_key(&user.user_id, &asset_id);
    state.s3.delete(&sidecar_key).await?;

    // Release the quota held by this asset. Best-effort — if it fails
    // the user's counter drifts high by this asset's bytes, but we
    // don't want delete to fail over accounting noise. A periodic
    // reconciliation job can fix drift later.
    if let Some(auth_state) = state.auth.as_ref() {
        let _ = crate::auth::release_storage(auth_state, &user.email, manifest.original_len).await;
    }

    // Delete the 6 shards. Parallelize via join_all — each delete is an
    // independent S3 DeleteObject.
    use futures::future::join_all;
    let shard_futs = (0..TOTAL_SHARDS).map(|i| {
        let s3 = state.s3.clone();
        let key = shard_key(&asset_id, i);
        async move {
            let _ = s3.delete(&key).await;
        }
    });
    join_all(shard_futs).await;

    // Manifest + chain sidecars live in the erasure-coded vault.
    let _ = state.vault.delete(&manifest_key(&asset_id)).await;
    let _ = state.vault.delete(&chain_key(&asset_id)).await;

    Ok(Json(serde_json::json!({
        "asset_id": asset_id,
        "deleted": true,
    })))
}

/// `GET /vault` — list assets owned by the authenticated user.
///
/// Driven by the `_owner/{user_id}/...` sidecars written at commit time.
/// Each sidecar is a tiny JSON doc containing `created_at` and the
/// opaque `encrypted_meta_b64` blob (filename + MIME, sealed under the
/// user's master key). We fan out the GetObject calls in parallel so
/// that rendering a 100-asset vault is one S3 LIST + one parallel
/// batch of GETs, not N serial round trips. Returns up to 1000 entries
/// (ListObjectsV2 default page); pagination is a future extension.
pub async fn list_vault(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> ApiResult<Json<VaultListResponse>> {
    #[derive(Deserialize)]
    struct OwnerSidecar {
        #[serde(default)]
        created_at: u64,
        #[serde(default)]
        encrypted_meta_b64: Option<String>,
    }

    // Fan out both prefix listings in parallel — they're independent
    // S3 ListObjectsV2 calls.
    let owner_prefix = format!("_owner/{}/", user.user_id);
    let shared_prefix = format!("_shared_with/{}/", user.user_id);
    let (owned_keys_res, shared_keys_res) = tokio::join!(
        state.s3.list_prefix(&owner_prefix),
        state.s3.list_prefix(&shared_prefix),
    );
    let owned_keys = owned_keys_res?;
    let shared_keys = shared_keys_res?;

    use futures::future::join_all;
    use resqd_storage::ObjectStore;

    // Owner items.
    let owned_fetches = owned_keys.into_iter().map(|(key, modified)| {
        let s3 = state.s3.clone();
        async move {
            let asset_id = asset_id_from_sidecar_key(&key)?.to_string();
            let body = s3.get(&key).await.ok();
            let sidecar = body
                .as_ref()
                .and_then(|b| serde_json::from_slice::<OwnerSidecar>(b).ok());
            let created_at = sidecar
                .as_ref()
                .map(|s| s.created_at)
                .filter(|n| *n > 0)
                .unwrap_or_else(|| modified.map(|s| s as u64).unwrap_or(0));
            Some(VaultListItem {
                asset_id,
                created_at,
                encrypted_meta_b64: sidecar.and_then(|s| s.encrypted_meta_b64),
                role: "owner",
                shared_by_email: None,
                sender_pubkey_x25519_b64: None,
                ring_id: None,
                uploader_pubkey_x25519_b64: None,
            })
        }
    });

    // Sharee items — read the full RecipientShareRecord so we can
    // surface the sender's email + pubkey in the listing (drives the
    // "shared by" UI and the Recovery Kit export path).
    let shared_fetches = shared_keys.into_iter().map(|(key, modified)| {
        let s3 = state.s3.clone();
        async move {
            let asset_id = asset_id_from_shared_with_key(&key)?.to_string();
            let body = s3.get(&key).await.ok()?;
            let rec: RecipientShareRecord = serde_json::from_slice(&body).ok()?;
            let created_at = if rec.created_at > 0 {
                rec.created_at
            } else {
                modified.map(|s| s as u64).unwrap_or(0)
            };
            Some(VaultListItem {
                asset_id,
                created_at,
                encrypted_meta_b64: rec.encrypted_meta_for_recipient_b64,
                role: "sharee",
                shared_by_email: Some(rec.sender_email),
                sender_pubkey_x25519_b64: Some(rec.sender_pubkey_x25519_b64),
                ring_id: None,
                uploader_pubkey_x25519_b64: None,
            })
        }
    });

    // Ring assets — enumerate every ring the caller belongs to, then
    // fan out list_prefix for each ring's _ring_assets/ prefix. For
    // the alpha population (1-3 rings per user, 0-10 assets per ring)
    // this is a handful of S3 calls in parallel.
    let ring_keys_fut = async {
        let auth = match state.auth.as_ref() {
            Some(a) => a,
            None => return vec![],
        };
        let ring_out = auth
            .dynamo
            .query()
            .table_name(&auth.config.rings_table)
            .index_name("user_id-index")
            .key_condition_expression("user_id = :uid")
            .expression_attribute_values(
                ":uid",
                aws_sdk_dynamodb::types::AttributeValue::S(user.user_id.clone()),
            )
            .send()
            .await;
        let ring_out = match ring_out {
            Ok(o) => o,
            Err(_) => return vec![],
        };
        let ring_ids: Vec<String> = ring_out
            .items()
            .iter()
            .filter_map(|i| i.get("ring_id").and_then(|v| v.as_s().ok().cloned()))
            .collect();
        let futs = ring_ids.into_iter().map(|rid| {
            let s3 = state.s3.clone();
            async move {
                let prefix = format!("_ring_assets/{rid}/");
                let keys = s3.list_prefix(&prefix).await.unwrap_or_default();
                keys.into_iter()
                    .filter_map(|(key, modified)| {
                        let asset_id = asset_id_from_sidecar_key(&key)?.to_string();
                        Some((rid.clone(), asset_id, modified))
                    })
                    .collect::<Vec<_>>()
            }
        });
        join_all(futs).await.into_iter().flatten().collect::<Vec<_>>()
    };

    let (owned_items, shared_items, ring_asset_keys) = tokio::join!(
        join_all(owned_fetches),
        join_all(shared_fetches),
        ring_keys_fut
    );

    // Fetch ring asset sidecars in parallel.
    let ring_fetches = ring_asset_keys.into_iter().map(|(ring_id, asset_id, modified)| {
        let s3 = state.s3.clone();
        async move {
            let key = ring_asset_sidecar_key(&ring_id, &asset_id);
            let body = s3.get(&key).await.ok()?;
            #[derive(Deserialize)]
            struct RingAssetSidecar {
                #[serde(default)]
                created_at: u64,
                #[serde(default)]
                encrypted_meta_b64: Option<String>,
                #[serde(default)]
                uploader_pubkey_x25519_b64: Option<String>,
            }
            let sc: RingAssetSidecar = serde_json::from_slice(&body).ok()?;
            let created_at = if sc.created_at > 0 {
                sc.created_at
            } else {
                modified.map(|s| s as u64).unwrap_or(0)
            };
            Some(VaultListItem {
                asset_id,
                created_at,
                encrypted_meta_b64: sc.encrypted_meta_b64,
                role: "ring_member",
                shared_by_email: None,
                sender_pubkey_x25519_b64: None,
                ring_id: Some(ring_id),
                uploader_pubkey_x25519_b64: sc.uploader_pubkey_x25519_b64,
            })
        }
    });
    let ring_items = join_all(ring_fetches).await;

    let mut assets: Vec<VaultListItem> = owned_items
        .into_iter()
        .flatten()
        .chain(shared_items.into_iter().flatten())
        .chain(ring_items.into_iter().flatten())
        .collect();
    // Newest first, independent of role.
    assets.sort_by(|a, b| b.created_at.cmp(&a.created_at));

    Ok(Json(VaultListResponse {
        user_id: user.user_id,
        count: assets.len(),
        assets,
    }))
}

// ────────────────────────────────────────────────────────────────────
//                          Share handlers
// ────────────────────────────────────────────────────────────────────

/// Request body for `POST /vault/{id}/shares`. All fields are produced
/// client-side — the server is zero-knowledge of both the per-asset key
/// and the wrap key. `sender_pubkey_x25519_b64` is copied from the
/// caller's own session (browser state) rather than looked up on the
/// server so the pinned value is exactly what the client is using; the
/// server still validates that it matches the caller's stored pubkey so
/// sharees can't be tricked into ECDH-ing against an attacker-chosen
/// pubkey.
#[derive(Deserialize)]
pub struct CreateShareRequest {
    pub recipient_email: String,
    /// Sender's own X25519 pubkey, base64. MUST match the value the
    /// server has on file for the caller — we reject otherwise.
    pub sender_pubkey_x25519_b64: String,
    /// Per-asset key sealed under the ECDH-derived share wrap key.
    pub wrapped_key_for_recipient_b64: String,
    /// `{name, mime}` sealed under the same wrap key. Optional — the
    /// sender can choose to withhold the filename hint, in which case
    /// the sharee's list view just shows `asset_id`.
    #[serde(default)]
    pub encrypted_meta_for_recipient_b64: Option<String>,
}

#[derive(Serialize)]
pub struct CreateShareResponse {
    pub asset_id: String,
    pub recipient_user_id: String,
    pub recipient_email: String,
    pub created_at: u64,
}

#[derive(Serialize)]
pub struct ShareSummary {
    pub recipient_user_id: String,
    pub recipient_email: String,
    pub created_at: u64,
}

#[derive(Serialize)]
pub struct ListSharesResponse {
    pub asset_id: String,
    pub count: usize,
    pub shares: Vec<ShareSummary>,
}

/// `POST /vault/{id}/shares` — grant read-only access to another user.
///
/// **Owner-only.** The caller MUST be the registered owner of the asset;
/// sharees cannot re-share.
///
/// Writes two sidecars:
/// - `_shares/{asset_id}/{recipient_user_id}.json` (owner-facing index)
/// - `_shared_with/{recipient_user_id}/{asset_id}.json` (recipient's
///   self-contained read record)
///
/// Read-only by construction: the recipient's sidecar contains the
/// *wrapped per-asset key* but not any credential that would let them
/// write to S3. Presigned upload URLs are minted only for the owner in
/// `/vault/init`, and `POST /vault/{id}/commit`, `DELETE /vault/{id}`
/// both gate on `asset.owner_id == caller.user_id`. A recipient trying
/// to mutate the asset will see 404, matching the semantics of an
/// asset they don't own.
pub async fn create_share(
    State(state): State<Arc<AppState>>,
    user: crate::auth::AuthUser,
    Path(asset_id): Path<String>,
    Json(req): Json<CreateShareRequest>,
) -> ApiResult<Json<CreateShareResponse>> {
    let auth = state
        .auth
        .as_ref()
        .ok_or(ApiError::Auth(crate::auth::AuthError::Unauthorized))?;

    // Load the asset manifest to verify the caller is the owner. The
    // ownership check happens BEFORE the recipient lookup so we don't
    // even leak "this asset exists" to non-owners via a slow-path
    // email-probe.
    let manifest_bytes = match state.vault.get(&manifest_key(&asset_id)).await {
        Ok(b) => b,
        Err(resqd_storage::StorageError::NotFound(_)) => return Err(ApiError::NotFound),
        Err(e) => return Err(ApiError::Storage(e)),
    };
    let manifest: AssetManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("decode manifest: {e}")))?;
    match manifest.owner_id.as_deref() {
        Some(owner) if owner == user.user_id => {}
        // Collapsed 404 even for "you're not the owner" so the endpoint
        // doesn't leak asset existence to non-owners.
        _ => return Err(ApiError::NotFound),
    }

    // Verify the pubkey the caller pinned into this share request
    // actually matches their stored identity. This closes a foot-gun
    // where a compromised client would otherwise be able to sneak an
    // attacker-controlled pubkey into every share record, giving the
    // attacker the wrap key on the recipient's read path.
    let caller_row = crate::auth::get_user_by_email(auth, &user.email)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("caller row missing")))?;
    let stored_pk = caller_row
        .pubkey_x25519_b64
        .as_deref()
        .ok_or(ApiError::BadRequest(
            "mint an X25519 identity via /auth/me/identity before sharing".into(),
        ))?;
    if stored_pk != req.sender_pubkey_x25519_b64 {
        return Err(ApiError::BadRequest(
            "sender_pubkey_x25519_b64 does not match the caller's stored identity".into(),
        ));
    }

    // Resolve recipient by email. Recipient must have minted an
    // identity themselves — otherwise we have no pubkey to wrap
    // against, and presumably the client already did this lookup via
    // /users/lookup before calling us, so a missing recipient here is
    // a race (deleted account) and treated as 404.
    let recipient_email = req.recipient_email.trim().to_ascii_lowercase();
    if recipient_email.is_empty() || !recipient_email.contains('@') {
        return Err(ApiError::BadRequest("recipient_email required".into()));
    }
    if recipient_email == user.email {
        return Err(ApiError::BadRequest(
            "cannot share an asset with yourself".into(),
        ));
    }
    let recipient = crate::auth::get_user_by_email(auth, &recipient_email)
        .await
        .map_err(ApiError::from)?
        .ok_or(ApiError::NotFound)?;
    let _recipient_pk = recipient
        .pubkey_x25519_b64
        .as_deref()
        .ok_or(ApiError::BadRequest(
            "recipient has not yet minted an X25519 identity — they must log in once to establish one".into(),
        ))?;

    let created_at = now_secs();

    let recipient_record = RecipientShareRecord {
        asset_id: asset_id.clone(),
        sender_user_id: user.user_id.clone(),
        sender_email: user.email.clone(),
        sender_pubkey_x25519_b64: req.sender_pubkey_x25519_b64.clone(),
        wrapped_key_for_recipient_b64: req.wrapped_key_for_recipient_b64.clone(),
        encrypted_meta_for_recipient_b64: req.encrypted_meta_for_recipient_b64.clone(),
        created_at,
    };
    let owner_record = OwnerShareRecord {
        asset_id: asset_id.clone(),
        recipient_user_id: recipient.user_id.clone(),
        recipient_email: recipient.email.clone(),
        created_at,
    };

    use resqd_storage::ObjectStore;
    let recipient_bytes = serde_json::to_vec(&recipient_record)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!(e)))?;
    let owner_bytes = serde_json::to_vec(&owner_record)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!(e)))?;

    // Write the recipient-facing sidecar FIRST so a partial failure
    // leaves the recipient able to read the asset even if the owner's
    // listing side is incomplete — erring toward availability over
    // a clean index. A reconciliation job can rebuild `_shares/` from
    // `_shared_with/` later if they diverge.
    state
        .s3
        .put(
            &share_sidecar_recipient_key(&recipient.user_id, &asset_id),
            Bytes::from(recipient_bytes),
        )
        .await?;
    state
        .s3
        .put(
            &share_sidecar_owner_key(&asset_id, &recipient.user_id),
            Bytes::from(owner_bytes),
        )
        .await?;

    info!(
        asset_id = %asset_id,
        owner = %user.user_id,
        recipient = %recipient.user_id,
        "share created"
    );

    Ok(Json(CreateShareResponse {
        asset_id,
        recipient_user_id: recipient.user_id,
        recipient_email: recipient.email,
        created_at,
    }))
}

/// `GET /vault/{id}/shares` — list current recipients of an asset.
/// Owner-only. Collapses to 404 for non-owners so we don't leak asset
/// existence.
pub async fn list_shares(
    State(state): State<Arc<AppState>>,
    user: crate::auth::AuthUser,
    Path(asset_id): Path<String>,
) -> ApiResult<Json<ListSharesResponse>> {
    let _auth = state
        .auth
        .as_ref()
        .ok_or(ApiError::Auth(crate::auth::AuthError::Unauthorized))?;

    let manifest_bytes = match state.vault.get(&manifest_key(&asset_id)).await {
        Ok(b) => b,
        Err(resqd_storage::StorageError::NotFound(_)) => return Err(ApiError::NotFound),
        Err(e) => return Err(ApiError::Storage(e)),
    };
    let manifest: AssetManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("decode manifest: {e}")))?;
    match manifest.owner_id.as_deref() {
        Some(owner) if owner == user.user_id => {}
        _ => return Err(ApiError::NotFound),
    }

    let prefix = format!("_shares/{asset_id}/");
    let keys = state.s3.list_prefix(&prefix).await?;

    use futures::future::join_all;
    use resqd_storage::ObjectStore;
    let fetches = keys.into_iter().map(|(key, _modified)| {
        let s3 = state.s3.clone();
        async move {
            let body = s3.get(&key).await.ok()?;
            let rec: OwnerShareRecord = serde_json::from_slice(&body).ok()?;
            Some(ShareSummary {
                recipient_user_id: rec.recipient_user_id,
                recipient_email: rec.recipient_email,
                created_at: rec.created_at,
            })
        }
    });
    let mut shares: Vec<ShareSummary> =
        join_all(fetches).await.into_iter().flatten().collect();
    shares.sort_by(|a, b| b.created_at.cmp(&a.created_at));

    Ok(Json(ListSharesResponse {
        asset_id,
        count: shares.len(),
        shares,
    }))
}

/// `DELETE /vault/{id}/shares/{recipient_email}` — revoke a share.
/// Owner-only.
///
/// Deletes both sidecars. Note the well-known limitation: a recipient
/// who has already fetched and cached the asset's per-asset key
/// (either in session or via a Recovery Kit export) still retains the
/// ability to read the data they already have — this is inherent to
/// symmetric-key encryption. Forward secrecy would require rotating
/// the per-asset key and re-wrapping for every remaining sharee, which
/// is a deliberate non-goal for the alpha and called out explicitly in
/// the security model copy.
pub async fn delete_share(
    State(state): State<Arc<AppState>>,
    user: crate::auth::AuthUser,
    Path((asset_id, recipient_email)): Path<(String, String)>,
) -> ApiResult<Json<serde_json::Value>> {
    let auth = state
        .auth
        .as_ref()
        .ok_or(ApiError::Auth(crate::auth::AuthError::Unauthorized))?;

    // Ownership check.
    let manifest_bytes = match state.vault.get(&manifest_key(&asset_id)).await {
        Ok(b) => b,
        Err(resqd_storage::StorageError::NotFound(_)) => return Err(ApiError::NotFound),
        Err(e) => return Err(ApiError::Storage(e)),
    };
    let manifest: AssetManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("decode manifest: {e}")))?;
    match manifest.owner_id.as_deref() {
        Some(owner) if owner == user.user_id => {}
        _ => return Err(ApiError::NotFound),
    }

    let recipient_email = recipient_email.trim().to_ascii_lowercase();
    let recipient = crate::auth::get_user_by_email(auth, &recipient_email)
        .await
        .map_err(ApiError::from)?
        .ok_or(ApiError::NotFound)?;

    use resqd_storage::ObjectStore;
    let _ = state
        .s3
        .delete(&share_sidecar_recipient_key(&recipient.user_id, &asset_id))
        .await;
    let _ = state
        .s3
        .delete(&share_sidecar_owner_key(&asset_id, &recipient.user_id))
        .await;

    info!(
        asset_id = %asset_id,
        owner = %user.user_id,
        recipient = %recipient.user_id,
        "share revoked"
    );

    Ok(Json(serde_json::json!({
        "asset_id": asset_id,
        "recipient_email": recipient_email,
        "revoked": true,
    })))
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
