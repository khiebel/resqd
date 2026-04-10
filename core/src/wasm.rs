//! WASM bindings for browser-side cryptography.
//!
//! All encryption/decryption happens in the browser via this WASM module.
//! The server NEVER sees plaintext data or keys.
//!
//! Build: wasm-pack build --target web --features wasm

#![cfg(feature = "wasm")]

use wasm_bindgen::prelude::*;

use crate::crypto::{hash, encrypt, kem, keys, share, stream};
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

// ── Streaming encryption (Track 1, Chunk 1.2) ────────────────────────
//
// Stateful wrappers around crypto::stream::{StreamEncryptor, StreamDecryptor}
// so the browser can feed a File.stream() through WASM 1 MB at a time
// without ever holding the whole payload in memory.
//
// Wire format across the FFI boundary:
//   header:  {"stream_id_b64":"...","chunk_size":N}
//   chunk:   {"counter":N,"is_last":bool,"ciphertext_b64":"..."}
//
// Callers MUST mark the final chunk with is_last=true — the decryptor
// treats a missing is_last marker as a truncation attack.

/// Stateful streaming encryptor. Create one per file, call `sealChunk`
/// for each slice of plaintext, set `is_last=true` on the final slice.
#[wasm_bindgen]
pub struct WasmStreamEncryptor {
    inner: stream::StreamEncryptor,
}

#[wasm_bindgen]
impl WasmStreamEncryptor {
    #[wasm_bindgen(constructor)]
    pub fn new(key: &[u8], chunk_size: u32) -> Result<WasmStreamEncryptor, JsError> {
        if key.len() != 32 {
            return Err(JsError::new("key must be 32 bytes"));
        }
        let key_arr: [u8; 32] = key.try_into().unwrap();
        Ok(Self {
            inner: stream::StreamEncryptor::new(&key_arr, chunk_size),
        })
    }

    /// Get the stream header as JSON. Persist this alongside the sealed
    /// chunks and hand it to `WasmStreamDecryptor` on the read side.
    #[wasm_bindgen(js_name = headerJson)]
    pub fn header_json(&self) -> Result<String, JsError> {
        let h = self.inner.header();
        #[derive(serde::Serialize)]
        struct WasmHeader {
            stream_id_b64: String,
            chunk_size: u32,
        }
        let out = WasmHeader {
            stream_id_b64: base64_encode(&h.stream_id),
            chunk_size: h.chunk_size,
        };
        serde_json::to_string(&out).map_err(|e| JsError::new(&e.to_string()))
    }

    /// Seal the next chunk. `is_last` MUST be true on the final chunk or
    /// the decryptor will report a truncation error at `finish()`.
    /// Returns JSON: `{"counter":N,"is_last":bool,"ciphertext_b64":"..."}`.
    #[wasm_bindgen(js_name = sealChunk)]
    pub fn seal_chunk(&mut self, plaintext: &[u8], is_last: bool) -> Result<String, JsError> {
        let sealed = self
            .inner
            .seal_chunk(plaintext, is_last)
            .map_err(|e| JsError::new(&e.to_string()))?;

        #[derive(serde::Serialize)]
        struct WasmChunk {
            counter: u32,
            is_last: bool,
            ciphertext_b64: String,
        }
        let out = WasmChunk {
            counter: sealed.counter,
            is_last: sealed.is_last,
            ciphertext_b64: base64_encode(&sealed.ciphertext),
        };
        serde_json::to_string(&out).map_err(|e| JsError::new(&e.to_string()))
    }

    #[wasm_bindgen(js_name = chunksSealed)]
    pub fn chunks_sealed(&self) -> u32 {
        self.inner.chunks_sealed()
    }

    #[wasm_bindgen(js_name = isFinished)]
    pub fn is_finished(&self) -> bool {
        self.inner.is_finished()
    }
}

/// Stateful streaming decryptor. Create one per file, feed the same chunk
/// JSONs back in the order they were sealed, call `finish()` to assert
/// the stream was not truncated.
#[wasm_bindgen]
pub struct WasmStreamDecryptor {
    inner: stream::StreamDecryptor,
}

#[wasm_bindgen]
impl WasmStreamDecryptor {
    /// Create a decryptor from a 32-byte key and the header JSON returned
    /// by `WasmStreamEncryptor.headerJson()`.
    #[wasm_bindgen(constructor)]
    pub fn new(key: &[u8], header_json: &str) -> Result<WasmStreamDecryptor, JsError> {
        if key.len() != 32 {
            return Err(JsError::new("key must be 32 bytes"));
        }
        let key_arr: [u8; 32] = key.try_into().unwrap();

        #[derive(serde::Deserialize)]
        struct WasmHeader {
            stream_id_b64: String,
            chunk_size: u32,
        }
        let parsed: WasmHeader = serde_json::from_str(header_json)
            .map_err(|e| JsError::new(&format!("parse header: {e}")))?;

        let stream_id_bytes = base64_decode(&parsed.stream_id_b64)?;
        if stream_id_bytes.len() != 20 {
            return Err(JsError::new(&format!(
                "stream_id must decode to 20 bytes, got {}",
                stream_id_bytes.len()
            )));
        }
        let mut stream_id = [0u8; 20];
        stream_id.copy_from_slice(&stream_id_bytes);

        let header = stream::StreamHeader {
            stream_id,
            chunk_size: parsed.chunk_size,
        };
        Ok(Self {
            inner: stream::StreamDecryptor::new(&key_arr, header),
        })
    }

    /// Open a sealed chunk (exactly the JSON returned by `sealChunk`).
    /// Returns the plaintext bytes.
    #[wasm_bindgen(js_name = openChunk)]
    pub fn open_chunk(&mut self, chunk_json: &str) -> Result<Vec<u8>, JsError> {
        #[derive(serde::Deserialize)]
        struct WasmChunk {
            counter: u32,
            is_last: bool,
            ciphertext_b64: String,
        }
        let parsed: WasmChunk = serde_json::from_str(chunk_json)
            .map_err(|e| JsError::new(&format!("parse chunk: {e}")))?;

        let sealed = stream::SealedChunk {
            counter: parsed.counter,
            is_last: parsed.is_last,
            ciphertext: base64_decode(&parsed.ciphertext_b64)?,
        };

        self.inner
            .open_chunk(&sealed)
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// Call once all chunks have been opened. Returns an error if no
    /// chunk was ever marked `is_last` (truncation attack).
    pub fn finish(&self) -> Result<(), JsError> {
        self.inner
            .finish()
            .map_err(|e| JsError::new(&e.to_string()))
    }

    #[wasm_bindgen(js_name = chunksOpened)]
    pub fn chunks_opened(&self) -> u32 {
        self.inner.chunks_opened()
    }
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

// ── X25519 identity + ECDH share wrap keys ───────────────────────────
//
// Every user has a long-term X25519 identity used for read-only asset
// sharing. These helpers let the browser:
//
// 1. Mint a fresh identity at first login post-migration.
// 2. Derive a wrap key for a specific recipient+asset on the send side.
// 3. Derive the matching wrap key on the receive side.
//
// The wrap key is always 32 bytes and is fed to `encrypt_data` /
// `decrypt_data` exactly like any other symmetric key.

/// Generate a fresh X25519 identity keypair. Returns
/// `{"public_b64": "...", "private_b64": "..."}`. The caller is
/// responsible for sealing the private half under the master key before
/// persisting anywhere.
#[wasm_bindgen]
pub fn x25519_generate_identity() -> Result<String, JsError> {
    let kp = share::IdentityKeypair::generate();
    #[derive(serde::Serialize)]
    struct Out {
        public_b64: String,
        private_b64: String,
    }
    let out = Out {
        public_b64: base64_encode(&kp.public),
        private_b64: base64_encode(&kp.private),
    };
    serde_json::to_string(&out).map_err(|e| JsError::new(&e.to_string()))
}

/// Derive the public half from a private X25519 scalar. Used by
/// `resqd-recover` to verify a recovery kit's public key matches the
/// sealed private key.
#[wasm_bindgen]
pub fn x25519_public_from_private(private_b64: &str) -> Result<String, JsError> {
    let priv_bytes = base64_decode(private_b64)?;
    let priv32 = share::parse_key32(&priv_bytes, "x25519 private")
        .map_err(|e| JsError::new(&e.to_string()))?;
    let kp = share::IdentityKeypair::from_private(priv32);
    Ok(base64_encode(&kp.public))
}

/// Sender-side: derive the wrap key used to encrypt a per-asset key for
/// a specific recipient and asset. Asset id is mixed in as HKDF `info`
/// so each (sender, recipient, asset) triple gets a domain-separated
/// wrap key.
#[wasm_bindgen]
pub fn x25519_sender_wrap_key(
    sender_private_b64: &str,
    recipient_public_b64: &str,
    asset_id: &str,
) -> Result<String, JsError> {
    let sp = base64_decode(sender_private_b64)?;
    let rp = base64_decode(recipient_public_b64)?;
    let sp32 = share::parse_key32(&sp, "sender private")
        .map_err(|e| JsError::new(&e.to_string()))?;
    let rp32 = share::parse_key32(&rp, "recipient public")
        .map_err(|e| JsError::new(&e.to_string()))?;
    let k = share::sender_wrap_key(&sp32, &rp32, asset_id);
    Ok(base64_encode(&k))
}

/// Recipient-side mirror of [`x25519_sender_wrap_key`]. Returns the same
/// 32-byte value that the sender computed (ECDH is symmetric).
#[wasm_bindgen]
pub fn x25519_recipient_wrap_key(
    recipient_private_b64: &str,
    sender_public_b64: &str,
    asset_id: &str,
) -> Result<String, JsError> {
    let rp = base64_decode(recipient_private_b64)?;
    let sp = base64_decode(sender_public_b64)?;
    let rp32 = share::parse_key32(&rp, "recipient private")
        .map_err(|e| JsError::new(&e.to_string()))?;
    let sp32 = share::parse_key32(&sp, "sender public")
        .map_err(|e| JsError::new(&e.to_string()))?;
    let k = share::recipient_wrap_key(&rp32, &sp32, asset_id);
    Ok(base64_encode(&k))
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
