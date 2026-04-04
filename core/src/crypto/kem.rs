//! ML-KEM-768 Post-Quantum Key Encapsulation — patent-distinct from RSA.
//!
//! ML-KEM (FIPS 203) is lattice-based, resistant to quantum computers.
//! Uses the ml-kem crate's high-level API for key generation,
//! encapsulation, and decapsulation.

use ml_kem::{MlKem768, KemCore, EncodedSizeUser};
use ml_kem::kem::{Decapsulate, Encapsulate};
use chacha20poly1305::aead::OsRng;
use serde::{Deserialize, Serialize};

use crate::error::{ResqdError, Result};

type EK768 = <MlKem768 as KemCore>::EncapsulationKey;
type DK768 = <MlKem768 as KemCore>::DecapsulationKey;

/// A ML-KEM-768 keypair for post-quantum key exchange.
pub struct KemKeypair {
    pub public_key: KemPublicKey,
    pub secret_key: Vec<u8>,
}

/// Public key bytes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KemPublicKey(pub Vec<u8>);

/// Encapsulation result.
pub struct KemEncapsulated {
    pub ciphertext: Vec<u8>,
    pub shared_secret: [u8; 32],
}

/// Generate a new ML-KEM-768 keypair.
pub fn generate_keypair() -> Result<KemKeypair> {
    let (dk, ek) = MlKem768::generate(&mut OsRng);

    // Serialize using EncodedSizeUser trait
    let ek_bytes = ek.as_bytes().to_vec();
    let dk_bytes = dk.as_bytes().to_vec();

    Ok(KemKeypair {
        public_key: KemPublicKey(ek_bytes),
        secret_key: dk_bytes,
    })
}

/// Encapsulate a shared secret using the recipient's public key.
pub fn encapsulate(public_key: &KemPublicKey) -> Result<KemEncapsulated> {
    let ek = EK768::from_bytes(
        &hybrid_array::Array::try_from(public_key.0.as_slice())
            .map_err(|_| ResqdError::KeyEncapsulation("invalid public key length".into()))?
    );

    let (ct, ss) = ek.encapsulate(&mut OsRng).map_err(|e| {
        ResqdError::KeyEncapsulation(format!("encapsulation failed: {:?}", e))
    })?;

    let mut shared_secret = [0u8; 32];
    shared_secret.copy_from_slice(ss.as_ref());

    let ct_bytes = ct.as_slice().to_vec();

    Ok(KemEncapsulated {
        ciphertext: ct_bytes,
        shared_secret,
    })
}

/// Decapsulate a shared secret using the recipient's secret key.
pub fn decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> Result<[u8; 32]> {
    let dk = DK768::from_bytes(
        &hybrid_array::Array::try_from(secret_key)
            .map_err(|_| ResqdError::KeyEncapsulation("invalid secret key length".into()))?
    );

    let ct = hybrid_array::Array::try_from(ciphertext)
        .map_err(|_| ResqdError::KeyEncapsulation("invalid ciphertext length".into()))?;

    let ss = dk.decapsulate(&ct).map_err(|e| {
        ResqdError::KeyEncapsulation(format!("decapsulation failed: {:?}", e))
    })?;

    let mut shared_secret = [0u8; 32];
    shared_secret.copy_from_slice(ss.as_ref());
    Ok(shared_secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kem_roundtrip() {
        let keypair = generate_keypair().unwrap();
        let encapsulated = encapsulate(&keypair.public_key).unwrap();
        let shared_secret = decapsulate(&keypair.secret_key, &encapsulated.ciphertext).unwrap();
        assert_eq!(shared_secret, encapsulated.shared_secret);
    }

    #[test]
    fn different_keypairs_different_secrets() {
        let kp1 = generate_keypair().unwrap();
        let kp2 = generate_keypair().unwrap();
        let enc1 = encapsulate(&kp1.public_key).unwrap();
        let enc2 = encapsulate(&kp2.public_key).unwrap();
        assert_ne!(enc1.shared_secret, enc2.shared_secret);
    }

    #[test]
    fn wrong_secret_key_produces_different_secret() {
        let kp1 = generate_keypair().unwrap();
        let kp2 = generate_keypair().unwrap();
        let encapsulated = encapsulate(&kp1.public_key).unwrap();
        let wrong_secret = decapsulate(&kp2.secret_key, &encapsulated.ciphertext).unwrap();
        assert_ne!(wrong_secret, encapsulated.shared_secret);
    }

    #[test]
    fn kem_full_encryption_flow() {
        let keypair = generate_keypair().unwrap();
        let encapsulated = encapsulate(&keypair.public_key).unwrap();
        let plaintext = b"quantum-safe family photo";
        let encrypted = crate::crypto::encrypt::encrypt(
            &encapsulated.shared_secret, plaintext
        ).unwrap();
        let shared_secret = decapsulate(
            &keypair.secret_key, &encapsulated.ciphertext
        ).unwrap();
        let decrypted = crate::crypto::encrypt::decrypt(&shared_secret, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
