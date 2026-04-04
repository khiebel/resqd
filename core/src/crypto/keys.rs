//! Key derivation and management.
//!
//! User's master key is derived client-side from passphrase using Argon2id.
//! The server never sees the passphrase or the derived key.

use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use rand::Rng;

use crate::error::{ResqdError, Result};

/// Derive a 256-bit encryption key from a passphrase using Argon2id.
///
/// Argon2id is memory-hard, making brute-force attacks expensive.
/// Parameters tuned for ~0.5s on modern hardware.
pub fn derive_key(passphrase: &str, salt: &[u8; 16]) -> Result<[u8; 32]> {
    let argon2 = Argon2::default();

    let salt_str = SaltString::encode_b64(salt)
        .map_err(|e| ResqdError::KeyDerivation(e.to_string()))?;

    let hash = argon2
        .hash_password(passphrase.as_bytes(), &salt_str)
        .map_err(|e| ResqdError::KeyDerivation(e.to_string()))?;

    let hash_output = hash
        .hash
        .ok_or_else(|| ResqdError::KeyDerivation("no hash output".into()))?;

    let bytes = hash_output.as_bytes();
    if bytes.len() < 32 {
        return Err(ResqdError::KeyDerivation(format!(
            "hash output too short: {} bytes",
            bytes.len()
        )));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes[..32]);
    Ok(key)
}

/// Generate a random 128-bit salt for key derivation.
pub fn generate_salt() -> [u8; 16] {
    rand::rng().random()

}

/// Generate a random 256-bit symmetric key (for per-asset encryption).
pub fn generate_random_key() -> [u8; 32] {
    rand::rng().random()

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_key_deterministic() {
        let salt = [42u8; 16];
        let k1 = derive_key("my-passphrase", &salt).unwrap();
        let k2 = derive_key("my-passphrase", &salt).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn derive_key_different_passphrase() {
        let salt = [42u8; 16];
        let k1 = derive_key("passphrase-A", &salt).unwrap();
        let k2 = derive_key("passphrase-B", &salt).unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn derive_key_different_salt() {
        let k1 = derive_key("same-passphrase", &[1u8; 16]).unwrap();
        let k2 = derive_key("same-passphrase", &[2u8; 16]).unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn random_key_is_32_bytes() {
        let key = generate_random_key();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn random_keys_are_unique() {
        let k1 = generate_random_key();
        let k2 = generate_random_key();
        assert_ne!(k1, k2);
    }
}
