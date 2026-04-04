//! BLAKE3 hashing — patent-distinct from SHA-256.
//!
//! BLAKE3 is a Merkle tree hash that runs at 8+ GB/s on modern hardware.
//! We use it for: asset integrity hashes, canary commitments, key derivation mixing.

use crate::error::Result;
use serde::{Deserialize, Serialize};

/// A BLAKE3 hash digest (32 bytes).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetHash(pub [u8; 32]);

impl AssetHash {
    /// Hash raw bytes.
    pub fn from_bytes(data: &[u8]) -> Self {
        Self(*blake3::hash(data).as_bytes())
    }

    /// Hash a file by streaming chunks (constant memory).
    pub fn from_reader<R: std::io::Read>(mut reader: R) -> Result<Self> {
        let mut hasher = blake3::Hasher::new();
        let mut buf = [0u8; 65536]; // 64KB chunks
        loop {
            let n = reader
                .read(&mut buf)
                .map_err(|e| crate::error::ResqdError::InvalidInput(e.to_string()))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(Self(*hasher.finalize().as_bytes()))
    }

    /// Hex-encoded hash string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from hex string.
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s)
            .map_err(|e| crate::error::ResqdError::InvalidInput(e.to_string()))?;
        if bytes.len() != 32 {
            return Err(crate::error::ResqdError::InvalidInput(
                "hash must be 32 bytes".into(),
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Create a commitment hash: BLAKE3(data || context).
    /// Used for canary commitments and on-chain anchors.
    pub fn commit(data: &[u8], context: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(data);
        hasher.update(context);
        Self(*hasher.finalize().as_bytes())
    }

    /// Derive a keyed hash (BLAKE3 keyed mode, 256-bit key).
    /// Used for canary token generation.
    pub fn keyed(key: &[u8; 32], data: &[u8]) -> Self {
        Self(*blake3::keyed_hash(key, data).as_bytes())
    }
}

impl std::fmt::Display for AssetHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_deterministic() {
        let h1 = AssetHash::from_bytes(b"hello resqd");
        let h2 = AssetHash::from_bytes(b"hello resqd");
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_different_inputs() {
        let h1 = AssetHash::from_bytes(b"file A");
        let h2 = AssetHash::from_bytes(b"file B");
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_hex_roundtrip() {
        let h = AssetHash::from_bytes(b"test data");
        let hex_str = h.to_hex();
        let h2 = AssetHash::from_hex(&hex_str).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn hash_commit_includes_context() {
        let c1 = AssetHash::commit(b"secret", b"context-A");
        let c2 = AssetHash::commit(b"secret", b"context-B");
        assert_ne!(c1, c2);
    }

    #[test]
    fn hash_keyed_requires_correct_key() {
        let key_a = [1u8; 32];
        let key_b = [2u8; 32];
        let h1 = AssetHash::keyed(&key_a, b"data");
        let h2 = AssetHash::keyed(&key_b, b"data");
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_streaming() {
        let data = b"hello resqd";
        let h1 = AssetHash::from_bytes(data);
        let h2 = AssetHash::from_reader(&data[..]).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_known_vector() {
        // BLAKE3 official test vector: empty input
        let h = AssetHash::from_bytes(b"");
        assert_eq!(
            h.to_hex(),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }
}
