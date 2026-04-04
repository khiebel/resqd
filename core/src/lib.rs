//! RESQD Core — Quantum-hardened cryptographic engine
//!
//! Provides: BLAKE3 hashing, XChaCha20-Poly1305 encryption,
//! ML-KEM-768 post-quantum key encapsulation, canary-based
//! tamper detection, and Reed-Solomon erasure coding.

pub mod crypto;
pub mod erasure;
pub mod canary;
pub mod error;

#[cfg(feature = "wasm")]
pub mod wasm;
