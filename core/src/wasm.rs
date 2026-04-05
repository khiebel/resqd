//! WASM bindings for browser-side cryptography.
//!
//! All encryption/decryption happens in the browser via this WASM module.
//! The server NEVER sees plaintext data or keys.
//!
//! Build: wasm-pack build --target web --features wasm

#![cfg(feature = "wasm")]

use wasm_bindgen::prelude::*;

use crate::crypto::{hash, encrypt, kem, keys};
use crate::erasure;
use crate::canary::CanaryChain;

// ── Hashing ──────────────────────────────────────────────────────────

/// Hash bytes using BLAKE3. Returns hex string.
#[wasm_bindgen]
pub fn hash_bytes(data: &[u8]) -> String {
    hash::AssetHash::from_bytes(data).to_hex()
}

/// Create a commitment hash: BLAKE3(data || context). Returns hex string.
#[wasm_bindgen]
pub fn hash_commit(data: &[u8], context: &[u8]) -> String {
    hash::AssetHash::commit(data, context).to_hex()
}

// ── Encryption ───────────────────────────────────────────────────────

/// Encrypt plaintext with a 32-byte key. Returns JSON {nonce, ciphertext} (base64).
#[wasm_bindgen]
pub fn encrypt_data(key: &[u8], plaintext: &[u8]) -> Result<String, JsError> {
    if key.len() != 32 {
        return Err(JsError::new("key must be 32 bytes"));
    }
    let key_arr: [u8; 32] = key.try_into().unwrap();
    let blob = encrypt::encrypt(&key_arr, plaintext)
        .map_err(|e| JsError::new(&e.to_string()))?;

    // Return as JSON with base64-encoded fields
    use serde::Serialize;
    #[derive(Serialize)]
    struct WasmBlob {
        nonce: String,
        ciphertext: String,
    }
    let result = WasmBlob {
        nonce: base64_encode(&blob.nonce),
        ciphertext: base64_encode(&blob.ciphertext),
    };
    serde_json::to_string(&result)
        .map_err(|e| JsError::new(&e.to_string()))
}

/// Decrypt ciphertext. Takes JSON blob from encrypt_data + 32-byte key.
#[wasm_bindgen]
pub fn decrypt_data(key: &[u8], blob_json: &str) -> Result<Vec<u8>, JsError> {
    if key.len() != 32 {
        return Err(JsError::new("key must be 32 bytes"));
    }
    let key_arr: [u8; 32] = key.try_into().unwrap();

    #[derive(serde::Deserialize)]
    struct WasmBlob {
        nonce: String,
        ciphertext: String,
    }
    let parsed: WasmBlob = serde_json::from_str(blob_json)
        .map_err(|e| JsError::new(&e.to_string()))?;

    let blob = encrypt::EncryptedBlob {
        nonce: base64_decode(&parsed.nonce)?,
        ciphertext: base64_decode(&parsed.ciphertext)?,
    };

    encrypt::decrypt(&key_arr, &blob)
        .map_err(|e| JsError::new(&e.to_string()))
}

// ── Key Derivation ───────────────────────────────────────────────────

/// Derive a 32-byte key from passphrase + 16-byte salt using Argon2id.
#[wasm_bindgen]
pub fn derive_key(passphrase: &str, salt: &[u8]) -> Result<Vec<u8>, JsError> {
    if salt.len() != 16 {
        return Err(JsError::new("salt must be 16 bytes"));
    }
    let salt_arr: [u8; 16] = salt.try_into().unwrap();
    let key = keys::derive_key(passphrase, &salt_arr)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(key.to_vec())
}

/// Generate a random 16-byte salt.
#[wasm_bindgen]
pub fn generate_salt() -> Vec<u8> {
    keys::generate_salt().to_vec()
}

/// Generate a random 32-byte symmetric key.
#[wasm_bindgen]
pub fn generate_random_key() -> Vec<u8> {
    keys::generate_random_key().to_vec()
}

// ── Post-Quantum KEM ─────────────────────────────────────────────────

/// Generate ML-KEM-768 keypair. Returns JSON {public_key, secret_key} (base64).
#[wasm_bindgen]
pub fn kem_generate() -> Result<String, JsError> {
    let kp = kem::generate_keypair()
        .map_err(|e| JsError::new(&e.to_string()))?;

    #[derive(serde::Serialize)]
    struct KemKeys {
        public_key: String,
        secret_key: String,
    }
    let result = KemKeys {
        public_key: base64_encode(&kp.public_key.0),
        secret_key: base64_encode(&kp.secret_key),
    };
    serde_json::to_string(&result)
        .map_err(|e| JsError::new(&e.to_string()))
}

/// Encapsulate shared secret with public key. Returns JSON {ciphertext, shared_secret}.
#[wasm_bindgen]
pub fn kem_encapsulate(public_key_b64: &str) -> Result<String, JsError> {
    let pk_bytes = base64_decode(public_key_b64)?;
    let pk = kem::KemPublicKey(pk_bytes);
    let enc = kem::encapsulate(&pk)
        .map_err(|e| JsError::new(&e.to_string()))?;

    #[derive(serde::Serialize)]
    struct KemResult {
        ciphertext: String,
        shared_secret: String,
    }
    let result = KemResult {
        ciphertext: base64_encode(&enc.ciphertext),
        shared_secret: base64_encode(&enc.shared_secret),
    };
    serde_json::to_string(&result)
        .map_err(|e| JsError::new(&e.to_string()))
}

/// Decapsulate shared secret. Returns 32-byte shared secret (base64).
#[wasm_bindgen]
pub fn kem_decapsulate(secret_key_b64: &str, ciphertext_b64: &str) -> Result<String, JsError> {
    let sk = base64_decode(secret_key_b64)?;
    let ct = base64_decode(ciphertext_b64)?;
    let ss = kem::decapsulate(&sk, &ct)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(base64_encode(&ss))
}

// ── Erasure Coding ───────────────────────────────────────────────────

/// Erasure-code data into 4+2 Reed-Solomon shards. Any 4 of 6 shards
/// reconstruct the original.
///
/// Returns JSON `{shards: [base64, base64, ...], original_len: u32}`.
/// The caller uploads each shard to a separate storage backend and saves
/// `original_len` so decode knows how many bytes of padding to strip.
#[wasm_bindgen]
pub fn erasure_encode(data: &[u8]) -> Result<String, JsError> {
    let shards = erasure::encode(data)
        .map_err(|e| JsError::new(&e.to_string()))?;

    #[derive(serde::Serialize)]
    struct EncodedShards {
        shards: Vec<String>,
        original_len: u32,
        data_shards: u8,
        parity_shards: u8,
    }
    let result = EncodedShards {
        shards: shards.iter().map(|s| base64_encode(s)).collect(),
        original_len: data.len() as u32,
        data_shards: erasure::DATA_SHARDS as u8,
        parity_shards: erasure::PARITY_SHARDS as u8,
    };
    serde_json::to_string(&result)
        .map_err(|e| JsError::new(&e.to_string()))
}

/// Reconstruct original bytes from a (possibly incomplete) set of shards.
///
/// `shards_json` must be a JSON array of length TOTAL_SHARDS (6) where each
/// slot is either a base64-encoded shard or `null`. At least DATA_SHARDS (4)
/// slots must be non-null.
///
/// `original_len` must be the value returned by `erasure_encode` (tells the
/// decoder how many trailing pad bytes to strip).
#[wasm_bindgen]
pub fn erasure_reconstruct(shards_json: &str, original_len: u32) -> Result<Vec<u8>, JsError> {
    let raw: Vec<Option<String>> = serde_json::from_str(shards_json)
        .map_err(|e| JsError::new(&format!("parse shards: {e}")))?;

    if raw.len() != erasure::TOTAL_SHARDS {
        return Err(JsError::new(&format!(
            "expected {} shards, got {}",
            erasure::TOTAL_SHARDS,
            raw.len()
        )));
    }

    let mut shards: Vec<Option<Vec<u8>>> = raw
        .into_iter()
        .map(|opt| match opt {
            Some(b64) => base64_decode(&b64).map(Some),
            None => Ok(None),
        })
        .collect::<Result<_, _>>()?;

    erasure::reconstruct(&mut shards, original_len as usize)
        .map_err(|e| JsError::new(&e.to_string()))
}

// ── Canary System ────────────────────────────────────────────────────

/// Create a new canary chain for an asset. Returns JSON.
#[wasm_bindgen]
pub fn canary_create(asset_id: &str) -> Result<String, JsError> {
    let chain = CanaryChain::new(asset_id);
    serde_json::to_string(&chain)
        .map_err(|e| JsError::new(&e.to_string()))
}

/// Rotate canary (call on every access). Takes chain JSON, returns updated JSON.
#[wasm_bindgen]
pub fn canary_rotate(chain_json: &str) -> Result<String, JsError> {
    let mut chain: CanaryChain = serde_json::from_str(chain_json)
        .map_err(|e| JsError::new(&e.to_string()))?;
    chain.rotate();
    serde_json::to_string(&chain)
        .map_err(|e| JsError::new(&e.to_string()))
}

/// Verify canary chain integrity. Returns access count or error.
#[wasm_bindgen]
pub fn canary_verify(chain_json: &str) -> Result<u64, JsError> {
    let chain: CanaryChain = serde_json::from_str(chain_json)
        .map_err(|e| JsError::new(&e.to_string()))?;
    chain.verify_chain()
        .map_err(|e| JsError::new(&e.to_string()))
}

// ── Helpers ──────────────────────────────────────────────────────────

fn base64_encode(data: &[u8]) -> String {
    use base64ct::{Base64, Encoding};
    Base64::encode_string(data)
}

fn base64_decode(s: &str) -> Result<Vec<u8>, JsError> {
    use base64ct::{Base64, Encoding};
    Base64::decode_vec(s)
        .map_err(|e| JsError::new(&format!("base64 decode error: {e}")))
}
