//! XChaCha20-Poly1305 AEAD encryption — patent-distinct from AES-256-CBC.
//!
//! XChaCha20-Poly1305 is a stream cipher with 192-bit nonces (safe for random
//! nonce generation) and built-in authentication (AEAD). AES-CBC has neither.
//!
//! All encryption happens client-side. The server never sees plaintext.

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use serde::{Deserialize, Serialize};

use crate::error::{ResqdError, Result};

/// An encrypted payload with its nonce.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedBlob {
    /// 24-byte XChaCha20 nonce (safe to store alongside ciphertext).
    pub nonce: Vec<u8>,
    /// Ciphertext with Poly1305 authentication tag appended.
    pub ciphertext: Vec<u8>,
}

/// Encrypt plaintext with a 256-bit key.
///
/// Generates a random 192-bit nonce (XChaCha20's extended nonce makes
/// random nonce collisions astronomically unlikely).
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<EncryptedBlob> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| ResqdError::Encryption(e.to_string()))?;

    Ok(EncryptedBlob {
        nonce: nonce.to_vec(),
        ciphertext,
    })
}

/// Decrypt an encrypted blob with a 256-bit key.
pub fn decrypt(key: &[u8; 32], blob: &EncryptedBlob) -> Result<Vec<u8>> {
    if blob.nonce.len() != 24 {
        return Err(ResqdError::Decryption(format!(
            "invalid nonce length: {} (expected 24)",
            blob.nonce.len()
        )));
    }

    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XNonce::from_slice(&blob.nonce);

    cipher
        .decrypt(nonce, blob.ciphertext.as_ref())
        .map_err(|e| ResqdError::Decryption(e.to_string()))
}

/// Encrypt with Additional Authenticated Data (AAD).
///
/// The AAD is authenticated but not encrypted — useful for binding
/// ciphertext to metadata (asset ID, timestamp) without encrypting it.
pub fn encrypt_with_aad(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<EncryptedBlob> {
    use chacha20poly1305::aead::Payload;

    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

    let payload = Payload {
        msg: plaintext,
        aad,
    };

    let ciphertext = cipher
        .encrypt(&nonce, payload)
        .map_err(|e| ResqdError::Encryption(e.to_string()))?;

    Ok(EncryptedBlob {
        nonce: nonce.to_vec(),
        ciphertext,
    })
}

/// Decrypt with AAD verification.
pub fn decrypt_with_aad(key: &[u8; 32], blob: &EncryptedBlob, aad: &[u8]) -> Result<Vec<u8>> {
    use chacha20poly1305::aead::Payload;

    if blob.nonce.len() != 24 {
        return Err(ResqdError::Decryption("invalid nonce length".into()));
    }

    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XNonce::from_slice(&blob.nonce);

    let payload = Payload {
        msg: blob.ciphertext.as_ref(),
        aad,
    };

    cipher
        .decrypt(nonce, payload)
        .map_err(|e| ResqdError::Decryption(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        key[0] = 0x42;
        key[31] = 0xFF;
        key
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = test_key();
        let plaintext = b"treasured family photo metadata";

        let blob = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &blob).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn ciphertext_differs_from_plaintext() {
        let key = test_key();
        let plaintext = b"secret document";

        let blob = encrypt(&key, plaintext).unwrap();
        assert_ne!(blob.ciphertext, plaintext);
    }

    #[test]
    fn different_nonces_each_time() {
        let key = test_key();
        let plaintext = b"same input";

        let blob1 = encrypt(&key, plaintext).unwrap();
        let blob2 = encrypt(&key, plaintext).unwrap();

        // Same plaintext, different nonces → different ciphertext
        assert_ne!(blob1.nonce, blob2.nonce);
        assert_ne!(blob1.ciphertext, blob2.ciphertext);
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = test_key();
        let mut key2 = test_key();
        key2[0] = 0x99;

        let blob = encrypt(&key1, b"secret").unwrap();
        let result = decrypt(&key2, &blob);

        assert!(result.is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = test_key();
        let mut blob = encrypt(&key, b"integrity check").unwrap();

        // Flip a bit in the ciphertext
        if let Some(byte) = blob.ciphertext.first_mut() {
            *byte ^= 0x01;
        }

        let result = decrypt(&key, &blob);
        assert!(result.is_err());
    }

    #[test]
    fn aad_roundtrip() {
        let key = test_key();
        let plaintext = b"encrypted content";
        let aad = b"asset_id:12345|timestamp:2026-04-03";

        let blob = encrypt_with_aad(&key, plaintext, aad).unwrap();
        let decrypted = decrypt_with_aad(&key, &blob, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_aad_fails() {
        let key = test_key();
        let plaintext = b"encrypted content";
        let aad = b"asset_id:12345";

        let blob = encrypt_with_aad(&key, plaintext, aad).unwrap();
        let result = decrypt_with_aad(&key, &blob, b"asset_id:99999");

        assert!(result.is_err());
    }

    #[test]
    fn large_payload() {
        let key = test_key();
        let plaintext = vec![0xAB_u8; 10 * 1024 * 1024]; // 10 MB

        let blob = encrypt(&key, &plaintext).unwrap();
        let decrypted = decrypt(&key, &blob).unwrap();

        assert_eq!(decrypted, plaintext);
    }
}
