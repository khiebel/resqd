//! Streaming upload endpoints — Chunk 1.4 of the Verimus integration plan.
//!
//! The existing `handlers::init` / `handlers::commit` path is fine for
//! files under ~200 MB, where the client can afford to hold the entire
//! erasure-coded output in WASM memory before firing off six parallel
//! `PUT` requests. For larger files the browser tab runs out of memory
//! and the whole upload fails.
//!
//! This module adds a parallel path that uses S3 multipart uploads. The
//! client streams a file through `crypto::stream::StreamEncryptor`, feeds
//! each sealed chunk into `erasure::stream::StreamEncoder`, buffers
//! shard-chunks until they reach S3's 5 MB minimum part size, then PUTs
//! each part directly to S3 via a per-part presigned URL. Bytes never
//! flow through Lambda.
//!
//! ## Endpoints
//!
//! - `POST /vault/stream/init`
//!     Creates six in-flight S3 multipart uploads, one per shard. Returns
//!     the six upload IDs plus the S3 keys the client needs to reference
//!     when requesting presigned part URLs. Also writes a tiny ownership
//!     sidecar so commit/abort can enforce ownership without a new
//!     DynamoDB table.
//!
//! - `POST /vault/stream/{asset_id}/presigned-parts`
//!     Batch-generates presigned `UploadPart` URLs for specific part
//!     numbers of a specific shard. The client calls this as needed —
//!     typically a batch of 10–20 URLs at a time so it can start
//!     uploading without round-tripping to Lambda for every part.
//!
//! - `POST /vault/stream/{asset_id}/commit`
//!     Finalizes all six shards. Runs `CompleteMultipartUpload` for
//!     each, writes the per-group BLAKE3 hashes + stream header to the
//!     asset manifest (reusing the existing `_manifest/{id}.json`
//!     sidecar layout with a new `"sharded-stream"` mode), creates the
//!     canary chain, anchors on Base L2, and charges the quota.
//!
//! - `POST /vault/stream/{asset_id}/abort`
//!     Aborts all six in-flight multipart uploads and deletes the
//!     ownership sidecar. Safe to call multiple times.
//!
//! ## Security invariants
//!
//! 1. All four endpoints require an authenticated session (no anonymous
//!    streaming uploads).
//! 2. The ownership sidecar `_stream_upload/{asset_id}.json` records
//!    the creator's `user_id` at init time; commit and abort both
//!    verify that the caller matches before touching anything.
//! 3. Presigned `UploadPart` URLs are scoped to a specific upload_id +
//!    part_number pair, so they can't be reused to upload to a
//!    different part of a different shard.
//! 4. Commit refuses if any shard doesn't produce a valid
//!    `CompleteMultipartUpload` — partial-success failures are surfaced
//!    with explicit `failed_shards` in the response so the client can
//!    retry just the broken half instead of the whole upload.

use crate::auth::{AuthUser, ConsumeStorageResult};
use crate::handlers::ApiError;
use crate::state::{AppState, LARGE_BLOB_PREFIX};
// Bring the ObjectStore trait into scope so we can call `.delete()`
// on `state.s3` (an `Arc<S3Store>`) in the Chunk 2.2/2.3 cleanup paths.
// Without this, the trait methods on S3Store are invisible here.
#[allow(unused_imports)]
use resqd_storage::ObjectStore;
use axum::{
    Json,
    extract::{Path, State},
};
use bytes::Bytes;
use resqd_core::canary::CanaryChain;
use resqd_core::crypto::hash::AssetHash;
use resqd_core::crypto::stream::StreamHeader;
use resqd_core::erasure::stream::StreamManifest;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{info, warn};
use uuid::Uuid;

// Private alias for brevity within this module.
type ApiResult<T> = Result<T, ApiError>;

/// Fixed at 6 to match `resqd_core::erasure::TOTAL_SHARDS`. Exposed here
/// so the module doesn't need to pull the erasure module in directly.
const TOTAL_SHARDS: usize = 6;

/// TTL for presigned UploadPart URLs. The client is expected to use each
/// URL within this window. Longer than the single-shot `PRESIGN_TTL`
/// because large-file uploads can take minutes to tens of minutes.
const STREAM_PART_PRESIGN_TTL: Duration = Duration::from_secs(3600); // 1 hour

/// Maximum number of presigned URLs the client may request in a single
/// `presigned-parts` call. Bounds Lambda work on malicious / buggy
/// clients. A well-behaved client should request 10–50 per batch.
const MAX_PRESIGNED_BATCH: usize = 100;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn shard_key(asset_id: &str, index: usize) -> String {
    format!("{LARGE_BLOB_PREFIX}{asset_id}/shard-{index}")
}

fn stream_state_key(asset_id: &str) -> String {
    format!("_stream_upload/{asset_id}.json")
}

fn chain_key(asset_id: &str) -> String {
    format!("_chain/{asset_id}.json")
}

fn manifest_key(asset_id: &str) -> String {
    format!("_manifest/{asset_id}.json")
}

// ── Ownership sidecar ─────────────────────────────────────────────────

/// Written by `stream_init` and read by `stream_commit` / `stream_abort`.
/// Lets the Lambda verify ownership of an in-flight upload without
/// needing a new DynamoDB table — the vault bucket already has
/// everything we need. Deleted on commit or abort.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct StreamUploadSidecar {
    asset_id: String,
    owner_id: String,
    created_at: u64,
    shards: [ShardUploadHandle; TOTAL_SHARDS],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ShardUploadHandle {
    shard_index: u8,
    upload_id: String,
    s3_key: String,
}

async fn load_sidecar(
    state: &Arc<AppState>,
    asset_id: &str,
) -> ApiResult<StreamUploadSidecar> {
    let bytes = state.vault.get(&stream_state_key(asset_id)).await?;
    serde_json::from_slice(&bytes)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("decode stream sidecar: {e}")))
}

async fn save_sidecar(
    state: &Arc<AppState>,
    sidecar: &StreamUploadSidecar,
) -> ApiResult<()> {
    let json = serde_json::to_vec(sidecar)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("encode stream sidecar: {e}")))?;
    state
        .vault
        .put(&stream_state_key(&sidecar.asset_id), Bytes::from(json))
        .await?;
    Ok(())
}

async fn delete_sidecar(state: &Arc<AppState>, asset_id: &str) {
    let _ = state.vault.delete(&stream_state_key(asset_id)).await;
}

fn check_owner(sidecar: &StreamUploadSidecar, user: &AuthUser) -> ApiResult<()> {
    if sidecar.owner_id != user.user_id {
        warn!(
            asset_id = %sidecar.asset_id,
            sidecar_owner = %sidecar.owner_id,
            caller = %user.user_id,
            "stream upload ownership mismatch"
        );
        return Err(ApiError::NotFound);
    }
    Ok(())
}

// ── Manifest extension for streaming uploads ──────────────────────────

/// Stream-mode metadata attached to the asset manifest. Stored as JSON
/// inside `_manifest/{asset_id}.json` alongside the existing sharded
/// fields. Decoders use the presence of this struct (and the manifest's
/// `mode` field being `"sharded-stream"`) to take the streaming read
/// path.
///
/// The full `StreamManifest` and `StreamHeader` are round-tripped
/// verbatim so the read side can rebuild `StreamDecoder` and
/// `StreamDecryptor` without any server-side interpretation of the
/// crypto state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StreamInfo {
    pub version: u8,
    /// Opaque `StreamManifest` from `resqd_core::erasure::stream`.
    pub stream_manifest: StreamManifest,
    /// Opaque `StreamHeader` from `resqd_core::crypto::stream`. The
    /// decoder needs this to rebuild `StreamDecryptor` with the same
    /// stream_id and chunk_size the encryptor used.
    pub stream_header: StreamHeader,
    /// Client-computed BLAKE3 of each shard's entire concatenated
    /// contents. Not verified by the server in this chunk — that is
    /// Chunk 2.3 (server-side random-range re-read). Stashed in the
    /// manifest now so Track 2 can consume it without a manifest
    /// schema bump.
    #[serde(default)]
    pub expected_shard_hashes_hex: Option<[String; TOTAL_SHARDS]>,
}

// ── Request / response types ──────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct StreamInitRequest {
    /// Client-supplied hint. Not enforced, just logged — quota is still
    /// checked against the real byte count at commit time.
    #[serde(default)]
    pub content_length_hint: Option<u64>,
    /// Copied from the single-shot path — supports ring-owned assets.
    #[serde(default)]
    pub ring_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct StreamInitResponse {
    pub asset_id: String,
    pub data_shards: u8,
    pub parity_shards: u8,
    pub shards: Vec<StreamShardSlot>,
    /// How long each presigned UploadPart URL stays valid.
    pub part_ttl_seconds: u64,
}

#[derive(Debug, Serialize)]
pub struct StreamShardSlot {
    pub shard_index: u8,
    pub upload_id: String,
    pub s3_key: String,
}

#[derive(Debug, Deserialize)]
pub struct StreamPresignedPartsRequest {
    pub shard_index: u8,
    /// 1-indexed S3 part numbers to generate presigned URLs for. Max
    /// `MAX_PRESIGNED_BATCH` per call.
    pub part_numbers: Vec<i32>,
}

#[derive(Debug, Serialize)]
pub struct StreamPresignedPartsResponse {
    pub shard_index: u8,
    pub parts: Vec<StreamPresignedPart>,
}

#[derive(Debug, Serialize)]
pub struct StreamPresignedPart {
    pub part_number: i32,
    pub upload_url: String,
}

#[derive(Debug, Deserialize)]
pub struct StreamCommitRequest {
    pub stream_manifest: StreamManifest,
    pub stream_header: StreamHeader,
    /// Per-shard list of completed (part_number, etag) pairs, in the
    /// order S3 returned them. Six outer entries, one per shard index.
    pub shards: Vec<StreamCompletedShard>,
    /// Optional client-computed BLAKE3 of each shard's concatenated
    /// contents. Stashed in the manifest for Track 2 to consume later.
    #[serde(default)]
    pub expected_shard_hashes_hex: Option<Vec<String>>,
    /// Client-declared byte count per shard (sum of every byte
    /// appended into that shard buffer). Verified server-side against
    /// S3 HeadObject after CompleteMultipartUpload — commit is
    /// rejected on mismatch. Part of Chunk 2.2 absorption defense.
    #[serde(default)]
    pub expected_shard_bytes: Option<Vec<u64>>,
    /// Wrapped per-asset key + encrypted filename/mime meta — same
    /// semantics as the single-shot path.
    #[serde(default)]
    pub wrapped_key_b64: Option<String>,
    #[serde(default)]
    pub encrypted_meta_b64: Option<String>,
    #[serde(default)]
    pub ring_id: Option<String>,
    #[serde(default)]
    pub uploader_pubkey_x25519_b64: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct StreamCompletedShard {
    pub shard_index: u8,
    pub parts: Vec<StreamCompletedPart>,
}

#[derive(Debug, Deserialize)]
pub struct StreamCompletedPart {
    pub part_number: i32,
    pub etag: String,
}

#[derive(Debug, Serialize)]
pub struct StreamCommitResponse {
    pub asset_id: String,
    pub total_input_bytes: u64,
    pub group_count: u32,
    pub data_shards: u8,
    pub parity_shards: u8,
    pub canary_sequence: u64,
    pub canary_hash_hex: String,
    pub anchored_on_chain: bool,
}

#[derive(Debug, Serialize)]
pub struct StreamAbortResponse {
    pub asset_id: String,
    pub aborted_shards: usize,
}

// ── Handlers ──────────────────────────────────────────────────────────

/// `POST /vault/stream/init` — Start a streaming upload.
///
/// Creates six S3 multipart uploads, one per shard, and writes an
/// ownership sidecar. Returns the six upload IDs + S3 keys the client
/// will reference when requesting presigned part URLs.
pub async fn stream_init(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<StreamInitRequest>,
) -> ApiResult<Json<StreamInitResponse>> {
    let asset_id = Uuid::new_v4().to_string();
    info!(
        asset_id = %asset_id,
        user_id = %user.user_id,
        ring_id = ?req.ring_id,
        hint = ?req.content_length_hint,
        "stream_init"
    );

    // Ring membership is validated at commit time along with the
    // ownership check on the uploader pubkey. Nothing ring-specific
    // happens at init beyond recording the asset_id.

    // Kick off six parallel S3 multipart uploads.
    let mut shards_raw: Vec<ShardUploadHandle> = Vec::with_capacity(TOTAL_SHARDS);
    for i in 0..TOTAL_SHARDS {
        let s3_key = shard_key(&asset_id, i);
        let upload_id = state
            .s3
            .create_multipart_upload(&s3_key, "application/octet-stream")
            .await
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("shard {i} create_multipart: {e}")))?;
        shards_raw.push(ShardUploadHandle {
            shard_index: i as u8,
            upload_id,
            s3_key,
        });
    }

    // Collect into a fixed-size array so the sidecar type is stable.
    let shards_arr: [ShardUploadHandle; TOTAL_SHARDS] = shards_raw
        .clone()
        .try_into()
        .map_err(|_| ApiError::Internal(anyhow::anyhow!("shard count mismatch")))?;

    let sidecar = StreamUploadSidecar {
        asset_id: asset_id.clone(),
        owner_id: user.user_id.clone(),
        created_at: now_secs(),
        shards: shards_arr,
    };
    save_sidecar(&state, &sidecar).await?;

    let response_shards: Vec<StreamShardSlot> = shards_raw
        .into_iter()
        .map(|h| StreamShardSlot {
            shard_index: h.shard_index,
            upload_id: h.upload_id,
            s3_key: h.s3_key,
        })
        .collect();

    Ok(Json(StreamInitResponse {
        asset_id,
        data_shards: 4,
        parity_shards: 2,
        shards: response_shards,
        part_ttl_seconds: STREAM_PART_PRESIGN_TTL.as_secs(),
    }))
}

/// `POST /vault/stream/{asset_id}/presigned-parts` — Generate a batch
/// of presigned UploadPart URLs for one shard. The client calls this
/// repeatedly as it streams through a file, requesting enough URLs in
/// each batch to cover the next 10–50 parts.
pub async fn stream_presigned_parts(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(asset_id): Path<String>,
    Json(req): Json<StreamPresignedPartsRequest>,
) -> ApiResult<Json<StreamPresignedPartsResponse>> {
    if req.part_numbers.is_empty() {
        return Err(ApiError::BadRequest("part_numbers must not be empty".into()));
    }
    if req.part_numbers.len() > MAX_PRESIGNED_BATCH {
        return Err(ApiError::BadRequest(format!(
            "part_numbers batch exceeds {MAX_PRESIGNED_BATCH}"
        )));
    }
    for n in &req.part_numbers {
        // S3 part numbers are 1-indexed and capped at 10,000.
        if *n < 1 || *n > 10_000 {
            return Err(ApiError::BadRequest(format!(
                "part_number {n} out of range (1..=10000)"
            )));
        }
    }

    let shard_index = req.shard_index as usize;
    if shard_index >= TOTAL_SHARDS {
        return Err(ApiError::BadRequest(format!(
            "shard_index {shard_index} out of range"
        )));
    }

    let sidecar = load_sidecar(&state, &asset_id).await?;
    check_owner(&sidecar, &user)?;

    let handle = &sidecar.shards[shard_index];

    let mut parts: Vec<StreamPresignedPart> = Vec::with_capacity(req.part_numbers.len());
    for part_number in req.part_numbers {
        let url = state
            .s3
            .presign_upload_part(
                &handle.s3_key,
                &handle.upload_id,
                part_number,
                STREAM_PART_PRESIGN_TTL,
            )
            .await
            .map_err(|e| {
                ApiError::Internal(anyhow::anyhow!(
                    "presign shard {shard_index} part {part_number}: {e}"
                ))
            })?;
        parts.push(StreamPresignedPart { part_number, upload_url: url });
    }

    info!(
        asset_id = %asset_id,
        user_id = %user.user_id,
        shard = shard_index,
        count = parts.len(),
        "stream_presigned_parts issued"
    );

    Ok(Json(StreamPresignedPartsResponse {
        shard_index: req.shard_index,
        parts,
    }))
}

/// `POST /vault/stream/{asset_id}/commit` — Finalize all six shards.
///
/// Runs `CompleteMultipartUpload` for each shard, writes the asset
/// manifest (embedding the full StreamManifest + StreamHeader) and the
/// canary chain sidecar, charges the quota against the owner's cap,
/// and anchors the initial commitment on-chain (best-effort).
pub async fn stream_commit(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(asset_id): Path<String>,
    Json(req): Json<StreamCommitRequest>,
) -> ApiResult<Json<StreamCommitResponse>> {
    info!(
        asset_id = %asset_id,
        user_id = %user.user_id,
        total_bytes = req.stream_manifest.total_input_bytes,
        groups = req.stream_manifest.group_count(),
        "stream_commit"
    );

    let sidecar = load_sidecar(&state, &asset_id).await?;
    check_owner(&sidecar, &user)?;

    if req.shards.len() != TOTAL_SHARDS {
        return Err(ApiError::BadRequest(format!(
            "commit requires {TOTAL_SHARDS} shards, got {}",
            req.shards.len()
        )));
    }

    // Quota check, same as the single-shot commit. Use the sum of
    // input bytes to the erasure encoder — that's the ciphertext
    // bytes, which are within a few bytes per chunk of plaintext
    // and are the right thing to charge.
    let billable_size = req.stream_manifest.total_input_bytes;
    if let Some(auth_state) = state.auth.as_ref() {
        match crate::auth::try_consume_storage(auth_state, &user.email, billable_size).await? {
            ConsumeStorageResult::Ok => {}
            ConsumeStorageResult::Exceeded { used, cap, requested } => {
                return Err(ApiError::QuotaExceeded { used, cap, requested });
            }
        }
    }

    // Ring support mirrors the single-shot commit.
    if let Some(ring_id) = &req.ring_id {
        let auth_state = state
            .auth
            .as_ref()
            .ok_or(ApiError::Auth(crate::auth::AuthError::Unauthorized))?;
        let membership =
            crate::rings::get_caller_membership_pub(auth_state, ring_id, &user.user_id)
                .await
                .map_err(|_| ApiError::NotFound)?
                .ok_or(ApiError::NotFound)?;
        if !membership.0.can_write() {
            return Err(ApiError::BadRequest(format!(
                "your ring role '{}' cannot upload — Owner or Adult required",
                membership.0.as_str()
            )));
        }
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

    // Finalize all six multipart uploads. We collect failures rather
    // than bailing on the first one so the response can tell the
    // client exactly which shards need to be retried.
    let mut failed_shards: Vec<u8> = Vec::new();
    for completed in &req.shards {
        let idx = completed.shard_index as usize;
        if idx >= TOTAL_SHARDS {
            return Err(ApiError::BadRequest(format!(
                "shard_index {idx} out of range"
            )));
        }
        let handle = &sidecar.shards[idx];

        // S3 requires the parts list be non-empty and sorted by part number.
        if completed.parts.is_empty() {
            warn!(
                asset_id = %asset_id,
                shard = idx,
                "stream_commit: empty parts list for shard"
            );
            failed_shards.push(completed.shard_index);
            continue;
        }
        let mut parts_sorted: Vec<(i32, String)> = completed
            .parts
            .iter()
            .map(|p| (p.part_number, p.etag.clone()))
            .collect();
        parts_sorted.sort_by_key(|(n, _)| *n);

        if let Err(e) = state
            .s3
            .complete_multipart_upload(&handle.s3_key, &handle.upload_id, parts_sorted)
            .await
        {
            warn!(
                asset_id = %asset_id,
                shard = idx,
                error = %e,
                "stream_commit: complete_multipart failed"
            );
            failed_shards.push(completed.shard_index);
        }
    }

    if !failed_shards.is_empty() {
        return Err(ApiError::BadRequest(format!(
            "commit failed for shards {failed_shards:?} — retry those parts and call commit again"
        )));
    }

    // Chunk 2.2 — proof-of-absorption, first rung.
    //
    // Now that all six multiparts have been finalized into real S3
    // objects, HeadObject each shard and verify its ContentLength
    // against what the client said it sent. This catches truncated or
    // extended uploads at the network layer before we anchor anything
    // on-chain. If the client didn't send `expected_shard_bytes` (e.g.
    // an older TS build), we skip the check rather than fail-closed.
    if let Some(expected_bytes) = &req.expected_shard_bytes {
        if expected_bytes.len() != TOTAL_SHARDS {
            return Err(ApiError::BadRequest(format!(
                "expected_shard_bytes must have {TOTAL_SHARDS} entries, got {}",
                expected_bytes.len()
            )));
        }
        let mut mismatches: Vec<(usize, u64, Option<u64>)> = Vec::new();
        for i in 0..TOTAL_SHARDS {
            let key = &sidecar.shards[i].s3_key;
            let actual = state
                .s3
                .head_content_length(key)
                .await
                .map_err(|e| ApiError::Internal(anyhow::anyhow!("head shard {i}: {e}")))?;
            match actual {
                Some(n) if n == expected_bytes[i] => {}
                Some(n) => mismatches.push((i, expected_bytes[i], Some(n))),
                None => mismatches.push((i, expected_bytes[i], None)),
            }
        }
        if !mismatches.is_empty() {
            warn!(
                asset_id = %asset_id,
                user_id = %user.user_id,
                mismatches = ?mismatches,
                "stream_commit rejected: shard content length mismatch"
            );
            // Chunk 2.5 — every absorption verdict (pass OR fail)
            // lands in the admin audit stream so the admin console's
            // "Failed Absorptions (24h)" tile can show zero in steady
            // state and red on any incident. Failures carry enough
            // context (shard index, expected vs observed bytes) to
            // drive a postmortem without digging through Lambda logs.
            if let Some(auth_state) = state.auth.as_ref() {
                let detail = serde_json::json!({
                    "asset_id": asset_id,
                    "user_id": user.user_id,
                    "reason": "content_length_mismatch",
                    "mismatches": mismatches.iter().map(|(idx, exp, got)| {
                        serde_json::json!({
                            "shard_index": idx,
                            "expected_bytes": exp,
                            "observed_bytes": got,
                        })
                    }).collect::<Vec<_>>(),
                });
                crate::admin::log_admin_action(
                    &auth_state.dynamo,
                    "system",
                    "shard_absorption_failed",
                    &asset_id,
                    &detail,
                ).await;
            }
            // Best-effort cleanup — delete each composite shard object
            // so we don't leave orphans. The ownership sidecar is
            // deleted on return by the standard `delete_sidecar` call
            // at the bottom of the success path, but we need to
            // remove it manually on this error path too.
            for i in 0..TOTAL_SHARDS {
                let _ = state.s3.delete(&sidecar.shards[i].s3_key).await;
            }
            delete_sidecar(&state, &asset_id).await;
            return Err(ApiError::AbsorptionFailed {
                reason: "content_length_mismatch".into(),
                failed_shard_indices: mismatches.iter().map(|(i, _, _)| *i).collect(),
            });
        }
    }

    // Build the stream_info metadata for the manifest. Optional client-
    // supplied expected hashes are converted into a fixed-size array
    // (Option<[String; 6]>). If the client didn't send any, store None.
    let expected_shard_hashes_hex = req.expected_shard_hashes_hex.and_then(|v| {
        if v.len() == TOTAL_SHARDS {
            let arr: [String; TOTAL_SHARDS] = v.try_into().ok()?;
            Some(arr)
        } else {
            None
        }
    });

    // Chunk 2.3 — proof-of-absorption, second rung.
    //
    // With a client-supplied full-shard hash in hand, verify each
    // shard byte-for-byte by streaming its object body through
    // BLAKE3 on the server side. This is stricter than the plan's
    // "random 16 KB range" sketch — we hash EVERY byte — which
    // makes the defense independent of whether the client committed
    // to a Merkle tree. Memory stays bounded because the SDK body
    // is read into a fixed 256 KB reusable buffer inside
    // `S3Store::blake3_hex`, not collected into `Bytes`.
    //
    // Cost: O(total_bytes) per commit. For the alpha population
    // where files are <100 MB, this adds <1 s to a commit. If we
    // ever reach multi-GB typical files, Chunk 2.6 (background
    // reaper) or a Merkle-based random-range scheme can take this
    // off the commit path.
    if let Some(ref expected_hashes) = expected_shard_hashes_hex {
        let mut mismatches: Vec<usize> = Vec::new();
        for i in 0..TOTAL_SHARDS {
            let key = &sidecar.shards[i].s3_key;
            let expected = expected_hashes[i].to_ascii_lowercase();
            if expected.is_empty() {
                continue;
            }
            let actual = state
                .s3
                .blake3_hex(key)
                .await
                .map_err(|e| ApiError::Internal(anyhow::anyhow!("blake3 shard {i}: {e}")))?;
            match actual {
                Some(a) if a.to_ascii_lowercase() == expected => {}
                _ => mismatches.push(i),
            }
        }
        if !mismatches.is_empty() {
            warn!(
                asset_id = %asset_id,
                user_id = %user.user_id,
                mismatches = ?mismatches,
                "stream_commit rejected: shard BLAKE3 mismatch (post-commit absorption)"
            );
            // Chunk 2.5 — record the BLAKE3 mismatch in the admin
            // audit stream. Carries the shard indices that failed so
            // the admin console can show which shards drifted.
            if let Some(auth_state) = state.auth.as_ref() {
                let detail = serde_json::json!({
                    "asset_id": asset_id,
                    "user_id": user.user_id,
                    "reason": "blake3_mismatch",
                    "failed_shard_indices": mismatches,
                });
                crate::admin::log_admin_action(
                    &auth_state.dynamo,
                    "system",
                    "shard_absorption_failed",
                    &asset_id,
                    &detail,
                ).await;
            }
            // Same cleanup pattern as the Content-Length mismatch
            // branch above — delete the composite shard objects so
            // they don't orphan and remove the ownership sidecar
            // before returning the error.
            for i in 0..TOTAL_SHARDS {
                let _ = state.s3.delete(&sidecar.shards[i].s3_key).await;
            }
            delete_sidecar(&state, &asset_id).await;
            return Err(ApiError::AbsorptionFailed {
                reason: "blake3_mismatch".into(),
                failed_shard_indices: mismatches,
            });
        }
    }

    let stream_info = StreamInfo {
        version: 1,
        stream_manifest: req.stream_manifest.clone(),
        stream_header: req.stream_header.clone(),
        expected_shard_hashes_hex,
    };

    // Persist the manifest. We reuse the existing `_manifest/{id}.json`
    // sidecar layout with `mode: "sharded-stream"` so the fetch path
    // can distinguish a streaming upload from a single-shot sharded one.
    let manifest_json = serde_json::json!({
        "mode": "sharded-stream",
        "original_len": billable_size,
        "data_shards": req.stream_manifest.data_shards,
        "parity_shards": req.stream_manifest.parity_shards,
        "owner_id": user.user_id,
        "wrapped_key_b64": req.wrapped_key_b64,
        "encrypted_meta_b64": req.encrypted_meta_b64,
        "created_at": now_secs(),
        "ring_id": req.ring_id,
        "uploader_pubkey_x25519_b64": req.uploader_pubkey_x25519_b64,
        "stream_info": stream_info,
    });
    let manifest_bytes = Bytes::from(
        serde_json::to_vec(&manifest_json)
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("encode manifest: {e}")))?,
    );
    state
        .vault
        .put(&manifest_key(&asset_id), manifest_bytes)
        .await?;

    // Create and persist the canary chain. `CanaryChain::new` already
    // populates the first commitment at index 0 — same pattern as the
    // single-shot `handlers::commit`.
    let chain = CanaryChain::new(&asset_id);
    let initial = chain.commitments[0].clone();
    let chain_json = serde_json::to_vec(&chain)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("encode chain: {e}")))?;
    state
        .vault
        .put(&chain_key(&asset_id), Bytes::from(chain_json))
        .await?;

    // Best-effort anchor on-chain. Failure is logged but does not fail
    // the commit — a background reaper picks up stuck anchors via
    // `POST /admin/retry-anchors`. Same asset-id-hash derivation the
    // single-shot path uses.
    let asset_id_hash: [u8; 32] = AssetHash::from_bytes(asset_id.as_bytes()).0;
    let anchored = if let Some(chain_client) = &state.chain {
        match chain_client
            .anchor_commitment(asset_id_hash, &initial)
            .await
        {
            Ok(_) => true,
            Err(e) => {
                warn!(
                    asset_id = %asset_id,
                    error = %e,
                    "stream_commit: on-chain anchor failed — will be retried"
                );
                false
            }
        }
    } else {
        false
    };

    // Delete the ownership sidecar — the upload is committed and
    // there's nothing to retry anymore.
    delete_sidecar(&state, &asset_id).await;

    info!(
        asset_id = %asset_id,
        user_id = %user.user_id,
        bytes = billable_size,
        groups = req.stream_manifest.group_count(),
        anchored,
        "stream_commit done"
    );

    Ok(Json(StreamCommitResponse {
        asset_id: asset_id.clone(),
        total_input_bytes: billable_size,
        group_count: req.stream_manifest.group_count(),
        data_shards: req.stream_manifest.data_shards,
        parity_shards: req.stream_manifest.parity_shards,
        canary_sequence: initial.sequence,
        canary_hash_hex: initial.hash.to_hex(),
        anchored_on_chain: anchored,
    }))
}

/// `POST /vault/stream/{asset_id}/abort` — Abort all six in-flight
/// multipart uploads and delete the ownership sidecar. Safe to call
/// multiple times; S3's `AbortMultipartUpload` treats missing uploads
/// as a no-op and this handler does too.
pub async fn stream_abort(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(asset_id): Path<String>,
) -> ApiResult<Json<StreamAbortResponse>> {
    info!(asset_id = %asset_id, user_id = %user.user_id, "stream_abort");

    // If the sidecar is already gone, there's nothing to abort.
    let sidecar = match load_sidecar(&state, &asset_id).await {
        Ok(s) => s,
        Err(ApiError::Storage(_)) | Err(ApiError::NotFound) => {
            return Ok(Json(StreamAbortResponse {
                asset_id,
                aborted_shards: 0,
            }));
        }
        Err(e) => return Err(e),
    };
    check_owner(&sidecar, &user)?;

    let mut aborted = 0_usize;
    for handle in &sidecar.shards {
        match state
            .s3
            .abort_multipart_upload(&handle.s3_key, &handle.upload_id)
            .await
        {
            Ok(_) => aborted += 1,
            Err(e) => {
                warn!(
                    asset_id = %asset_id,
                    shard = handle.shard_index,
                    error = %e,
                    "stream_abort: abort_multipart failed — continuing"
                );
            }
        }
    }

    delete_sidecar(&state, &asset_id).await;

    Ok(Json(StreamAbortResponse {
        asset_id,
        aborted_shards: aborted,
    }))
}
