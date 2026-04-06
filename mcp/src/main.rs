//! RESQD MCP server.
//!
//! A [Model Context Protocol](https://modelcontextprotocol.io) server that
//! exposes the RESQD vault to Claude (or any MCP client) as a set of
//! tools. The server runs locally alongside the client, speaks
//! JSON-RPC 2.0 over stdio, and authenticates to the RESQD API with
//! a user-generated API token.
//!
//! # Zero-knowledge and agents
//!
//! RESQD is a zero-knowledge vault — the server never sees plaintext or
//! any key material. For an agent to upload or read a vault, the agent
//! therefore needs a copy of the user's master key. This server reads
//! that key from `RESQD_MASTER_KEY_B64` at startup (base64url of the 32
//! bytes derived in-browser from the user's passkey via the WebAuthn
//! PRF extension). It's imperfect — we've moved the key off the user's
//! device — but it's the pragmatic shape of "let Claude put a file in
//! my vault" today. A future version may use proxy re-encryption so
//! each agent holds only a delegated key scoped to specific assets.
//!
//! # Tools exposed
//!
//! - `upload_file { path, name? }` — encrypt a local file and store it
//! - `list_vault {}` — list the user's assets with decrypted filenames
//! - `fetch_file { asset_id, save_to }` — download + decrypt to disk
//! - `delete_file { asset_id }` — permanent removal
//!
//! # Transport
//!
//! MCP uses newline-delimited JSON-RPC 2.0 over stdio. We hand-roll the
//! subset we need (initialize, tools/list, tools/call) — pulling in a
//! full SDK would be overkill for four tools. `stderr` is safe for
//! logging; `stdout` is reserved for protocol messages.

use anyhow::{Context, Result, anyhow};
use base64::prelude::*;
use rand::RngCore;
use resqd_core::{crypto::{encrypt, share}, erasure};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::Write as _;
use std::sync::Mutex;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

const PROTOCOL_VERSION: &str = "2024-11-05";
const SERVER_NAME: &str = "resqd-mcp";
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

// ────────────────────────────────────────────────────────────────────
//                              Config
// ────────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct Config {
    api_url: String,
    api_token: String,
    master_key: [u8; 32],
    /// Optional X25519 private identity, needed for reading shared and
    /// ring-owned assets. Without this the MCP server can still upload,
    /// list, and fetch personal assets, but shared/ring reads will fail
    /// with a clear error telling the user which env var to set.
    x25519_privkey: Option<[u8; 32]>,
}

impl Config {
    fn from_env() -> Result<Self> {
        let api_url = std::env::var("RESQD_API_URL")
            .context("RESQD_API_URL is required (e.g. https://api.resqd.ai)")?;
        let api_token = std::env::var("RESQD_API_TOKEN").context(
            "RESQD_API_TOKEN is required — mint one at https://resqd-app.pages.dev/settings/",
        )?;
        let key_b64 = std::env::var("RESQD_MASTER_KEY_B64").context(
            "RESQD_MASTER_KEY_B64 is required — copy it from https://resqd-app.pages.dev/settings/",
        )?;
        // Try every common base64 variant — the browser exports
        // base64url-no-pad via `bytesToB64u`, but users may paste
        // padded standard base64 from other tools.
        let trimmed = key_b64.trim();
        let key_bytes = BASE64_URL_SAFE_NO_PAD
            .decode(trimmed)
            .or_else(|_| BASE64_URL_SAFE.decode(trimmed))
            .or_else(|_| BASE64_STANDARD_NO_PAD.decode(trimmed))
            .or_else(|_| BASE64_STANDARD.decode(trimmed))
            .context("RESQD_MASTER_KEY_B64 must be base64 (standard or url-safe, with or without padding)")?;
        if key_bytes.len() != 32 {
            return Err(anyhow!(
                "RESQD_MASTER_KEY_B64 decoded to {} bytes, expected 32",
                key_bytes.len()
            ));
        }
        let mut master_key = [0u8; 32];
        master_key.copy_from_slice(&key_bytes);

        // X25519 identity — optional. Needed for shared/ring reads.
        let x25519_privkey = std::env::var("RESQD_X25519_PRIVKEY_B64")
            .ok()
            .and_then(|b64| {
                let trimmed = b64.trim();
                let bytes = BASE64_URL_SAFE_NO_PAD
                    .decode(trimmed)
                    .or_else(|_| BASE64_URL_SAFE.decode(trimmed))
                    .or_else(|_| BASE64_STANDARD_NO_PAD.decode(trimmed))
                    .or_else(|_| BASE64_STANDARD.decode(trimmed))
                    .ok()?;
                if bytes.len() != 32 { return None; }
                let mut k = [0u8; 32];
                k.copy_from_slice(&bytes);
                Some(k)
            });

        Ok(Self {
            api_url: api_url.trim_end_matches('/').to_string(),
            api_token,
            master_key,
            x25519_privkey,
        })
    }
}

// ────────────────────────────────────────────────────────────────────
//                     Wire-format helpers (match web client)
// ────────────────────────────────────────────────────────────────────

/// Encrypt `plaintext` under `key` and return the JSON string that the
/// rest of the system round-trips. The format is
/// `{"nonce":"<b64>","ciphertext":"<b64>"}` — identical to what the WASM
/// `encrypt_data` in `core/src/wasm.rs` emits, byte for byte. This is
/// what the upload page stores as `wrapped_key_b64` (outer base64 of
/// this JSON) and `encrypted_meta_b64`.
fn encrypt_blob_json(key: &[u8; 32], plaintext: &[u8]) -> Result<String> {
    let blob = encrypt::encrypt(key, plaintext).map_err(|e| anyhow!("encrypt: {e}"))?;
    Ok(
        json!({
            "nonce": BASE64_STANDARD.encode(&blob.nonce),
            "ciphertext": BASE64_STANDARD.encode(&blob.ciphertext),
        })
        .to_string(),
    )
}

fn decrypt_blob_json(key: &[u8; 32], blob_json: &str) -> Result<Vec<u8>> {
    #[derive(Deserialize)]
    struct Blob {
        nonce: String,
        ciphertext: String,
    }
    let parsed: Blob = serde_json::from_str(blob_json).context("parse encrypted blob json")?;
    let blob = encrypt::EncryptedBlob {
        nonce: BASE64_STANDARD.decode(&parsed.nonce).context("nonce b64")?,
        ciphertext: BASE64_STANDARD
            .decode(&parsed.ciphertext)
            .context("ciphertext b64")?,
    };
    encrypt::decrypt(key, &blob).map_err(|e| anyhow!("decrypt: {e}"))
}

/// Wrap plaintext in the `[header_len u32 LE | header JSON | body]`
/// frame used by the web client so fetch can recover the filename.
fn frame_plaintext(name: &str, mime: &str, body: &[u8]) -> Vec<u8> {
    let header = json!({ "v": 1, "name": name, "mime": mime }).to_string();
    let header_bytes = header.as_bytes();
    let mut out = Vec::with_capacity(4 + header_bytes.len() + body.len());
    out.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(header_bytes);
    out.extend_from_slice(body);
    out
}

/// Inverse of `frame_plaintext` — recovers `(name, mime, body)`. Legacy
/// blobs with no frame fall through to `(None, None, full bytes)`.
fn unframe_plaintext(bytes: &[u8]) -> (Option<String>, Option<String>, Vec<u8>) {
    let legacy = (None, None, bytes.to_vec());
    if bytes.len() < 4 {
        return legacy;
    }
    let header_len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    if header_len == 0 || header_len > 1024 || 4 + header_len > bytes.len() {
        return legacy;
    }
    let header_slice = &bytes[4..4 + header_len];
    #[derive(Deserialize)]
    struct Header {
        v: u32,
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        mime: Option<String>,
    }
    match serde_json::from_slice::<Header>(header_slice) {
        Ok(h) if h.v == 1 => (h.name, h.mime, bytes[4 + header_len..].to_vec()),
        _ => legacy,
    }
}

fn fresh_per_asset_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut k);
    k
}

// ────────────────────────────────────────────────────────────────────
//                        HTTP client
// ────────────────────────────────────────────────────────────────────

struct ApiClient {
    http: reqwest::Client,
    cfg: Config,
    /// In-memory cache of unwrapped ring privkeys. Lazily populated on
    /// first access to a ring-owned asset.
    ring_privkeys: Mutex<HashMap<String, [u8; 32]>>,
}

impl ApiClient {
    fn new(cfg: Config) -> Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent(format!("resqd-mcp/{SERVER_VERSION}"))
            .build()?;
        Ok(Self {
            http,
            cfg,
            ring_privkeys: Mutex::new(HashMap::new()),
        })
    }

    /// Get (or lazily fetch + unwrap) the ring privkey for a ring.
    async fn get_ring_privkey(&self, ring_id: &str) -> Result<[u8; 32]> {
        // Check cache first.
        if let Some(k) = self.ring_privkeys.lock().unwrap().get(ring_id) {
            return Ok(*k);
        }
        let x_priv = self.cfg.x25519_privkey.ok_or_else(|| {
            anyhow!("RESQD_X25519_PRIVKEY_B64 required to read ring-owned assets")
        })?;
        // Fetch membership.
        let resp = self.http
            .get(self.url(&format!("/rings/{ring_id}/me")))
            .bearer_auth(&self.cfg.api_token)
            .send()
            .await
            .context("GET /rings/{id}/me")?;
        if !resp.status().is_success() {
            return Err(anyhow!("ring membership fetch failed: {}", resp.status()));
        }
        let data: Value = resp.json().await?;
        let wrapped_b64 = data.get("wrapped_ring_privkey_b64")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("ring privkey not available (estate locked?)"))?;
        let inviter_pub_b64 = data.get("inviter_pubkey_x25519_b64")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("inviter pubkey missing from membership"))?;
        let inviter_pub = BASE64_STANDARD.decode(inviter_pub_b64).context("inviter pub b64")?;
        if inviter_pub.len() != 32 {
            return Err(anyhow!("inviter pub is {} bytes", inviter_pub.len()));
        }
        let mut inv_pub = [0u8; 32];
        inv_pub.copy_from_slice(&inviter_pub);
        // Derive the wrap key the inviter used: recipient_wrap_key(my_priv, inviter_pub, ring_id).
        let wrap_key = share::recipient_wrap_key(&x_priv, &inv_pub, ring_id);
        // Unwrap the ring privkey.
        let outer = BASE64_STANDARD.decode(wrapped_b64).context("wrapped ring priv b64")?;
        let s = std::str::from_utf8(&outer).context("wrapped ring priv utf8")?;
        let ring_priv_bytes = decrypt_blob_json(&wrap_key, s)?;
        if ring_priv_bytes.len() != 32 {
            return Err(anyhow!("ring privkey is {} bytes", ring_priv_bytes.len()));
        }
        let mut ring_priv = [0u8; 32];
        ring_priv.copy_from_slice(&ring_priv_bytes);
        self.ring_privkeys.lock().unwrap().insert(ring_id.to_string(), ring_priv);
        Ok(ring_priv)
    }

    /// Derive the per-asset unwrap key for any role.
    async fn derive_asset_key(
        &self,
        manifest: &FetchResponse,
        asset_id: &str,
    ) -> Result<[u8; 32]> {
        let wrapped_b64 = manifest.wrapped_key_b64.as_deref()
            .ok_or_else(|| anyhow!("no wrapped key — legacy unkeyed asset"))?;
        let role = manifest.role.as_deref().unwrap_or("owner");

        let unwrap_key: [u8; 32] = match role {
            "ring_member" => {
                let ring_id = manifest.ring_id.as_deref()
                    .ok_or_else(|| anyhow!("ring_member but no ring_id"))?;
                let up_pub_b64 = manifest.uploader_pubkey_x25519_b64.as_deref()
                    .ok_or_else(|| anyhow!("ring_member but no uploader_pubkey"))?;
                let up_pub_bytes = BASE64_STANDARD.decode(up_pub_b64)?;
                if up_pub_bytes.len() != 32 {
                    return Err(anyhow!("uploader pub {} bytes", up_pub_bytes.len()));
                }
                let mut up_pub = [0u8; 32];
                up_pub.copy_from_slice(&up_pub_bytes);
                let ring_priv = self.get_ring_privkey(ring_id).await?;
                share::recipient_wrap_key(&ring_priv, &up_pub, asset_id)
            }
            "sharee" => {
                let x_priv = self.cfg.x25519_privkey.ok_or_else(|| {
                    anyhow!("RESQD_X25519_PRIVKEY_B64 required to read shared assets")
                })?;
                let sender_pub_b64 = manifest.sender_pubkey_x25519_b64.as_deref()
                    .ok_or_else(|| anyhow!("sharee but no sender_pubkey"))?;
                let sender_pub_bytes = BASE64_STANDARD.decode(sender_pub_b64)?;
                if sender_pub_bytes.len() != 32 {
                    return Err(anyhow!("sender pub {} bytes", sender_pub_bytes.len()));
                }
                let mut sp = [0u8; 32];
                sp.copy_from_slice(&sender_pub_bytes);
                share::recipient_wrap_key(&x_priv, &sp, asset_id)
            }
            _ => {
                // Owner — unwrap under master key.
                return Ok(self.cfg.master_key);
            }
        };

        // Unwrap the per-asset key under the derived wrap key.
        let outer = BASE64_STANDARD.decode(wrapped_b64).context("wrapped key b64")?;
        let s = std::str::from_utf8(&outer).context("wrapped key utf8")?;
        let key_bytes = decrypt_blob_json(&unwrap_key, s)?;
        if key_bytes.len() != 32 {
            return Err(anyhow!("per-asset key {} bytes", key_bytes.len()));
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(&key_bytes);
        Ok(k)
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.cfg.api_url, path)
    }

    async fn init_upload(&self) -> Result<InitResponse> {
        let resp = self
            .http
            .post(self.url("/vault/init"))
            .bearer_auth(&self.cfg.api_token)
            .json(&json!({}))
            .send()
            .await
            .context("POST /vault/init")?;
        if !resp.status().is_success() {
            return Err(anyhow!("init failed: {} {}", resp.status(), resp.text().await.unwrap_or_default()));
        }
        resp.json().await.context("decode init response")
    }

    async fn commit_upload(
        &self,
        asset_id: &str,
        original_len: u64,
        wrapped_key_b64: String,
        encrypted_meta_b64: String,
    ) -> Result<CommitResponse> {
        let body = json!({
            "original_len": original_len,
            "wrapped_key_b64": wrapped_key_b64,
            "encrypted_meta_b64": encrypted_meta_b64,
        });
        let resp = self
            .http
            .post(self.url(&format!("/vault/{asset_id}/commit")))
            .bearer_auth(&self.cfg.api_token)
            .json(&body)
            .send()
            .await
            .context("POST /vault/{id}/commit")?;
        if !resp.status().is_success() {
            return Err(anyhow!("commit failed: {} {}", resp.status(), resp.text().await.unwrap_or_default()));
        }
        resp.json().await.context("decode commit response")
    }

    async fn put_shard(&self, url: &str, bytes: Vec<u8>) -> Result<()> {
        let resp = self
            .http
            .put(url)
            .header("content-type", "application/octet-stream")
            .body(bytes)
            .send()
            .await
            .context("PUT shard")?;
        if !resp.status().is_success() {
            return Err(anyhow!(
                "shard PUT failed: {} {}",
                resp.status(),
                resp.text().await.unwrap_or_default()
            ));
        }
        Ok(())
    }

    async fn list_vault(&self) -> Result<VaultListResponse> {
        let resp = self
            .http
            .get(self.url("/vault"))
            .bearer_auth(&self.cfg.api_token)
            .send()
            .await
            .context("GET /vault")?;
        if !resp.status().is_success() {
            return Err(anyhow!("list failed: {} {}", resp.status(), resp.text().await.unwrap_or_default()));
        }
        resp.json().await.context("decode list response")
    }

    async fn fetch_manifest(&self, asset_id: &str) -> Result<FetchResponse> {
        let resp = self
            .http
            .get(self.url(&format!("/vault/{asset_id}")))
            .bearer_auth(&self.cfg.api_token)
            .send()
            .await
            .context("GET /vault/{id}")?;
        if !resp.status().is_success() {
            return Err(anyhow!("fetch failed: {} {}", resp.status(), resp.text().await.unwrap_or_default()));
        }
        resp.json().await.context("decode fetch response")
    }

    async fn download_shard(&self, url: &str) -> Result<Vec<u8>> {
        let resp = self.http.get(url).send().await.context("GET shard")?;
        if !resp.status().is_success() {
            return Err(anyhow!("shard GET failed: {}", resp.status()));
        }
        Ok(resp.bytes().await?.to_vec())
    }

    async fn delete_asset(&self, asset_id: &str) -> Result<()> {
        let resp = self
            .http
            .delete(self.url(&format!("/vault/{asset_id}")))
            .bearer_auth(&self.cfg.api_token)
            .send()
            .await
            .context("DELETE /vault/{id}")?;
        if !resp.status().is_success() {
            return Err(anyhow!("delete failed: {} {}", resp.status(), resp.text().await.unwrap_or_default()));
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct InitResponse {
    asset_id: String,
    shards: Vec<ShardSlot>,
}

#[derive(Deserialize)]
struct ShardSlot {
    index: u8,
    upload_url: String,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct CommitResponse {
    asset_id: String,
    original_len: u64,
    canary_sequence: u64,
    canary_hash_hex: String,
    anchored_on_chain: bool,
}

#[derive(Deserialize)]
struct VaultListResponse {
    count: usize,
    assets: Vec<VaultListItem>,
}

#[derive(Deserialize)]
struct VaultListItem {
    asset_id: String,
    created_at: u64,
    #[serde(default)]
    encrypted_meta_b64: Option<String>,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    shared_by_email: Option<String>,
    #[serde(default)]
    sender_pubkey_x25519_b64: Option<String>,
    #[serde(default)]
    ring_id: Option<String>,
    #[serde(default)]
    uploader_pubkey_x25519_b64: Option<String>,
}

#[derive(Deserialize)]
struct FetchResponse {
    #[allow(dead_code)]
    asset_id: String,
    original_len: u64,
    #[serde(default)]
    data_shards: u8,
    shards: Vec<FetchShardSlot>,
    #[serde(default)]
    wrapped_key_b64: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    encrypted_meta_b64: Option<String>,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    sender_pubkey_x25519_b64: Option<String>,
    #[serde(default)]
    ring_id: Option<String>,
    #[serde(default)]
    uploader_pubkey_x25519_b64: Option<String>,
}

#[derive(Deserialize)]
struct FetchShardSlot {
    index: u8,
    download_url: Option<String>,
}

// ────────────────────────────────────────────────────────────────────
//                          Tool implementations
// ────────────────────────────────────────────────────────────────────

async fn tool_upload_file(api: &ApiClient, args: &Value) -> Result<Value> {
    let path = args
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("missing required arg: path"))?;
    let expanded = shellexpand_home(path);
    let body = tokio::fs::read(&expanded)
        .await
        .with_context(|| format!("read file {expanded}"))?;
    let name = args
        .get("name")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| {
            std::path::Path::new(&expanded)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("upload.bin")
                .to_string()
        });
    let mime = guess_mime(&name);

    // Frame plaintext, encrypt with fresh per-asset key.
    let per_asset_key = fresh_per_asset_key();
    let plaintext = frame_plaintext(&name, &mime, &body);
    let encrypted_blob = encrypt_blob_json(&per_asset_key, &plaintext)?;
    let encrypted_bytes = encrypted_blob.as_bytes().to_vec();
    let original_len = encrypted_bytes.len() as u64;

    // Wrap per-asset key under master + encrypt meta under master, each
    // in the same `btoa(JSON)` outer wrapper the web client uses.
    let wrapped_blob = encrypt_blob_json(&api.cfg.master_key, &per_asset_key)?;
    let wrapped_key_b64 = BASE64_STANDARD.encode(wrapped_blob.as_bytes());

    let meta_json = json!({ "name": name, "mime": mime }).to_string();
    let meta_blob = encrypt_blob_json(&api.cfg.master_key, meta_json.as_bytes())?;
    let encrypted_meta_b64 = BASE64_STANDARD.encode(meta_blob.as_bytes());

    // Erasure-code into 6 shards.
    let shards = erasure::encode(&encrypted_bytes).map_err(|e| anyhow!("erasure encode: {e}"))?;

    // Init upload, get presigned URLs.
    let init = api.init_upload().await?;
    if init.shards.len() != shards.len() {
        return Err(anyhow!(
            "server expects {} shards, WASM produced {}",
            init.shards.len(),
            shards.len()
        ));
    }

    // Fan out shard PUTs in parallel.
    let mut futs = Vec::new();
    for slot in &init.shards {
        let shard_bytes = shards[slot.index as usize].clone();
        futs.push(api.put_shard(&slot.upload_url, shard_bytes));
    }
    for f in futures_join_all(futs).await {
        f?;
    }

    // Commit.
    let commit = api
        .commit_upload(&init.asset_id, original_len, wrapped_key_b64, encrypted_meta_b64)
        .await?;

    Ok(json!({
        "asset_id": commit.asset_id,
        "name": name,
        "mime": mime,
        "size": body.len(),
        "canary_sequence": commit.canary_sequence,
        "anchored_on_chain": commit.anchored_on_chain,
    }))
}

async fn tool_list_vault(api: &ApiClient) -> Result<Value> {
    let resp = api.list_vault().await?;
    let mut items: Vec<Value> = Vec::with_capacity(resp.assets.len());
    for a in &resp.assets {
        let role = a.role.as_deref().unwrap_or("owner");
        // Derive the right key for meta decryption based on role.
        let (name, mime) = if let Some(b64) = &a.encrypted_meta_b64 {
            let meta_key: Option<[u8; 32]> = match role {
                "ring_member" => {
                    // Ring meta is sealed under the same ECDH wrap key
                    // as the per-asset key. But we don't have an asset_id
                    // for the HKDF info... we do have it: a.asset_id.
                    // Need ring privkey + uploader pubkey.
                    if let (Some(ring_id), Some(up_pub_b64)) =
                        (&a.ring_id, &a.uploader_pubkey_x25519_b64)
                    {
                        if let Ok(ring_priv) = api.get_ring_privkey(ring_id).await {
                            if let Ok(up_bytes) = BASE64_STANDARD.decode(up_pub_b64) {
                                if up_bytes.len() == 32 {
                                    let mut up = [0u8; 32];
                                    up.copy_from_slice(&up_bytes);
                                    Some(share::recipient_wrap_key(&ring_priv, &up, &a.asset_id))
                                } else { None }
                            } else { None }
                        } else { None }
                    } else { None }
                }
                "sharee" => {
                    if let (Some(x_priv), Some(sp_b64)) =
                        (api.cfg.x25519_privkey, &a.sender_pubkey_x25519_b64)
                    {
                        if let Ok(sp_bytes) = BASE64_STANDARD.decode(sp_b64) {
                            if sp_bytes.len() == 32 {
                                let mut sp = [0u8; 32];
                                sp.copy_from_slice(&sp_bytes);
                                Some(share::recipient_wrap_key(&x_priv, &sp, &a.asset_id))
                            } else { None }
                        } else { None }
                    } else { None }
                }
                _ => Some(api.cfg.master_key),
            };
            if let Some(key) = meta_key {
                let outer = BASE64_STANDARD.decode(b64.as_bytes()).ok();
                let decrypted = outer
                    .and_then(|o| std::str::from_utf8(&o).ok().map(|s| s.to_string()))
                    .and_then(|s| decrypt_blob_json(&key, &s).ok());
                if let Some(plain) = decrypted {
                    let parsed: Value = serde_json::from_slice(&plain).unwrap_or_default();
                    (
                        parsed.get("name").and_then(|v| v.as_str()).map(String::from),
                        parsed.get("mime").and_then(|v| v.as_str()).map(String::from),
                    )
                } else { (None, None) }
            } else { (None, None) }
        } else { (None, None) };

        let mut item = json!({
            "asset_id": a.asset_id,
            "created_at": a.created_at,
            "name": name,
            "mime": mime,
            "role": role,
        });
        if let Some(email) = &a.shared_by_email {
            item["shared_by"] = json!(email);
        }
        if let Some(rid) = &a.ring_id {
            item["ring_id"] = json!(rid);
        }
        items.push(item);
    }
    Ok(json!({ "count": resp.count, "assets": items }))
}

async fn tool_fetch_file(api: &ApiClient, args: &Value) -> Result<Value> {
    let asset_id = args
        .get("asset_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("missing required arg: asset_id"))?;
    let save_to = args
        .get("save_to")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("missing required arg: save_to"))?;
    let save_to = shellexpand_home(save_to);

    let manifest = api.fetch_manifest(asset_id).await?;

    // Unwrap the per-asset key. Role-aware: owner uses master key,
    // sharee uses ECDH wrap key, ring_member uses ring privkey ECDH.
    let asset_key: [u8; 32] = if manifest.wrapped_key_b64.is_some() {
        api.derive_asset_key(&manifest, asset_id).await?
    } else {
        api.cfg.master_key
    };

    // Download all available shards in parallel.
    let mut futs = Vec::new();
    for slot in &manifest.shards {
        let idx = slot.index;
        let url_opt = slot.download_url.clone();
        let http = api.http.clone();
        futs.push(async move {
            let Some(url) = url_opt else { return (idx, None) };
            match http.get(&url).send().await {
                Ok(r) if r.status().is_success() => match r.bytes().await {
                    Ok(b) => (idx, Some(b.to_vec())),
                    Err(_) => (idx, None),
                },
                _ => (idx, None),
            }
        });
    }
    let results = futures_join_all(futs).await;

    let mut shard_slots: Vec<Option<Vec<u8>>> = vec![None; manifest.shards.len()];
    for (idx, data) in results {
        shard_slots[idx as usize] = data;
    }
    let present = shard_slots.iter().filter(|o| o.is_some()).count();
    let needed = if manifest.data_shards == 0 {
        4
    } else {
        manifest.data_shards as usize
    };
    if present < needed {
        return Err(anyhow!(
            "only {}/{} required shards available — vault is degraded",
            present,
            needed
        ));
    }

    let encrypted_bytes =
        erasure::reconstruct(&mut shard_slots, manifest.original_len as usize)
            .map_err(|e| anyhow!("erasure reconstruct: {e}"))?;
    let blob_json = std::str::from_utf8(&encrypted_bytes).context("encrypted blob utf8")?;
    let plaintext = decrypt_blob_json(&asset_key, blob_json)?;
    let (name, mime, body) = unframe_plaintext(&plaintext);

    tokio::fs::write(&save_to, &body)
        .await
        .with_context(|| format!("write {save_to}"))?;

    Ok(json!({
        "path": save_to,
        "name": name,
        "mime": mime,
        "size": body.len(),
    }))
}

async fn tool_delete_file(api: &ApiClient, args: &Value) -> Result<Value> {
    let asset_id = args
        .get("asset_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("missing required arg: asset_id"))?;
    api.delete_asset(asset_id).await?;
    Ok(json!({ "asset_id": asset_id, "deleted": true }))
}

// Minimal join_all shim — 6 shards, serial awaits are fine.
// We avoid a full `futures` dep for a single combinator.
async fn futures_join_all<F, T>(futs: Vec<F>) -> Vec<T>
where
    F: std::future::Future<Output = T>,
{
    let mut out = Vec::with_capacity(futs.len());
    for f in futs {
        out.push(f.await);
    }
    out
}

fn shellexpand_home(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{home}/{rest}");
        }
    }
    path.to_string()
}

fn guess_mime(name: &str) -> String {
    let ext = std::path::Path::new(name)
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| s.to_ascii_lowercase());
    match ext.as_deref() {
        Some("txt") | Some("md") => "text/plain",
        Some("json") => "application/json",
        Some("pdf") => "application/pdf",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("png") => "image/png",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("mp4") => "video/mp4",
        Some("mov") => "video/quicktime",
        Some("mp3") => "audio/mpeg",
        Some("zip") => "application/zip",
        _ => "application/octet-stream",
    }
    .to_string()
}

// ────────────────────────────────────────────────────────────────────
//                        JSON-RPC / MCP framing
// ────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct RpcRequest {
    jsonrpc: String,
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

fn success(id: Option<Value>, result: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result,
    })
}

fn error(id: Option<Value>, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message },
    })
}

fn tools_catalog() -> Value {
    json!({
        "tools": [
            {
                "name": "upload_file",
                "description": "Encrypt a file on disk and store it in the user's RESQD vault. The file is encrypted client-side with a fresh per-asset key before it ever leaves this machine; the vault never sees plaintext. Returns the new asset_id.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "Absolute or home-relative path to the file to upload (e.g. ~/Documents/tax_return_2026.pdf)." },
                        "name": { "type": "string", "description": "Optional display name. Defaults to the file's basename." }
                    },
                    "required": ["path"]
                }
            },
            {
                "name": "list_vault",
                "description": "List assets in the user's RESQD vault. Returns each asset's id, decrypted filename and MIME type, and creation time. Filenames are decrypted locally — the server only sees ciphertext.",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "fetch_file",
                "description": "Download an asset from the user's RESQD vault and decrypt it to a local path. Triggers a canary rotation and on-chain anchor as a side effect (this is the core tamper-evidence guarantee — every read is logged on Base L2).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "asset_id": { "type": "string" },
                        "save_to": { "type": "string", "description": "Filesystem path to write the decrypted file to." }
                    },
                    "required": ["asset_id", "save_to"]
                }
            },
            {
                "name": "delete_file",
                "description": "Permanently remove an asset from the user's RESQD vault. The on-chain canary history for the asset is preserved (Base L2 is append-only by design).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "asset_id": { "type": "string" }
                    },
                    "required": ["asset_id"]
                }
            }
        ]
    })
}

fn tool_content(value: Value) -> Value {
    json!({
        "content": [
            { "type": "text", "text": serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string()) }
        ]
    })
}

async fn handle_request(req: RpcRequest, api: &ApiClient) -> Value {
    if req.jsonrpc != "2.0" {
        return error(req.id, -32600, "invalid JSON-RPC version");
    }
    match req.method.as_str() {
        "initialize" => success(
            req.id,
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "serverInfo": { "name": SERVER_NAME, "version": SERVER_VERSION },
                "capabilities": { "tools": {} }
            }),
        ),
        "notifications/initialized" => Value::Null, // notification — no response
        "tools/list" => success(req.id, tools_catalog()),
        "tools/call" => {
            let name = req.params.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let args = req.params.get("arguments").cloned().unwrap_or(json!({}));
            let result = match name {
                "upload_file" => tool_upload_file(api, &args).await,
                "list_vault" => tool_list_vault(api).await,
                "fetch_file" => tool_fetch_file(api, &args).await,
                "delete_file" => tool_delete_file(api, &args).await,
                _ => Err(anyhow!("unknown tool: {name}")),
            };
            match result {
                Ok(v) => success(req.id, tool_content(v)),
                Err(e) => success(
                    req.id,
                    json!({
                        "content": [{ "type": "text", "text": format!("error: {e:#}") }],
                        "isError": true
                    }),
                ),
            }
        }
        _ => error(req.id, -32601, &format!("method not found: {}", req.method)),
    }
}

// ────────────────────────────────────────────────────────────────────
//                                main
// ────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    // All logging goes to stderr — stdout is reserved for MCP protocol.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cfg = Config::from_env()?;
    tracing::info!(api_url = %cfg.api_url, "resqd-mcp starting");
    let api = ApiClient::new(cfg)?;

    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin).lines();
    let mut stdout = tokio::io::stdout();

    while let Some(line) = reader.next_line().await? {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let req: RpcRequest = match serde_json::from_str(trimmed) {
            Ok(r) => r,
            Err(e) => {
                let err = error(None, -32700, &format!("parse error: {e}"));
                write_message(&mut stdout, &err).await?;
                continue;
            }
        };

        let is_notification = req.id.is_none();
        let resp = handle_request(req, &api).await;
        // Notifications MUST NOT get a response.
        if !is_notification && !resp.is_null() {
            write_message(&mut stdout, &resp).await?;
        }
    }

    Ok(())
}

async fn write_message(stdout: &mut tokio::io::Stdout, value: &Value) -> Result<()> {
    let mut buf = serde_json::to_vec(value)?;
    buf.push(b'\n');
    stdout.write_all(&buf).await?;
    stdout.flush().await?;
    Ok(())
}

// Silence unused-import warning from the `Write` trait we imported
// for documentation parity with earlier drafts. The actual writes go
// through tokio's AsyncWriteExt.
#[allow(dead_code)]
fn _silence_write() {
    let _ = std::io::stdout().flush();
}
