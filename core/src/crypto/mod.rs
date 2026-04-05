//! Cryptographic primitives for RESQD.
//!
//! All algorithms are intentionally distinct from patent US11431691B2:
//! - BLAKE3 (not SHA-256) for hashing
//! - XChaCha20-Poly1305 (not AES-256-CBC) for encryption
//! - ML-KEM-768 (not RSA) for key encapsulation
//! - ML-DSA-65 for digital signatures

pub mod hash;
pub mod encrypt;
pub mod kem;
pub mod keys;
pub mod share;

pub use hash::*;
pub use encrypt::*;
pub use kem::*;
pub use keys::*;
pub use share::*;
