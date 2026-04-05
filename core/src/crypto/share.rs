//! Long-term X25519 identity + ECDH-derived share wrap keys.
//!
//! # Role in the RESQD crypto stack
//!
//! Every user has a stable X25519 keypair ("identity key") in addition
//! to the PRF-derived symmetric master key. The public half is stored
//! server-side in plaintext (like a PGP public key); the private half is
//! sealed under the user's master key with XChaCha20-Poly1305 via the
//! existing [`encrypt`](super::encrypt) module and also stored server-side
//! as an opaque blob.
//!
//! The server therefore never learns anyone's private key. Both halves
//! can be re-derived from the user's passkey alone (PRF -> master key ->
//! unwrap privkey). This is what lets the sharing flow be zero-knowledge:
//! the server routes ciphertext between users without ever holding a
//! decryption key.
//!
//! # Share wrap derivation
//!
//! When user A wants to share asset X with user B (read-only), A's client:
//!
//! 1. Fetches B's public X25519 key from the server.
//! 2. Computes `shared = X25519(a_priv, b_pub)`.
//! 3. Derives a 32-byte wrap key via `HKDF-SHA256(shared, info =
//!    "resqd-share-v1|<asset_id>")`. Binding the `info` field to the
//!    asset id makes wrap keys domain-separated per asset even if two
//!    users share many assets between each other.
//! 4. Encrypts the asset's per-asset key under that wrap key using the
//!    standard [`encrypt::encrypt`](super::encrypt::encrypt) routine.
//! 5. POSTs `{recipient_email, sender_pubkey_b64, wrapped_key}` to the
//!    share endpoint. The server stores that blob in a sidecar.
//!
//! On the read side, user B fetches the same sidecar, recomputes the
//! same shared secret (ECDH is symmetric), re-derives the wrap key, and
//! decrypts the per-asset key. No server involvement.
//!
//! # Read-only enforcement
//!
//! The share format intentionally has no notion of a "write share". Any
//! recipient can read, nobody can write — the server enforces that every
//! mutating endpoint checks caller identity against the asset's owner
//! record. See `api/src/handlers.rs`.

use hkdf::Hkdf;
use rand::Rng;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::{ResqdError, Result};

/// Info string used as the HKDF domain separator for share wrap keys.
/// Hard-wired so every implementation (browser, Lambda, CLI, recover
/// tool, third-party) derives the same key. If this ever needs to
/// change, bump to `resqd-share-v2` and carry a version tag inside
/// each share record.
pub const SHARE_HKDF_INFO_V1: &[u8] = b"resqd-share-v1";

/// An X25519 long-term identity keypair.
///
/// The private half is a `StaticSecret` — `x25519-dalek` deliberately
/// splits ephemeral vs. static use. Identities are static, and their
/// raw bytes must be persistable across sessions, which `StaticSecret`
/// supports (and `EphemeralSecret` does not).
pub struct IdentityKeypair {
    pub public: [u8; 32],
    pub private: [u8; 32],
}

impl IdentityKeypair {
    /// Generate a fresh random identity.
    pub fn generate() -> Self {
        // `rand::rng()` is a `ThreadRng` which implements `CryptoRng` —
        // suitable for generating long-term private keys. We go through
        // `random::<[u8; 32]>()` rather than the `rand_core` `OsRng`
        // path because `rand 0.9` restructured the `RngCore` trait and
        // `OsRng::fill_bytes` is no longer available from the top-level
        // `rand` re-exports.
        let priv_bytes: [u8; 32] = rand::rng().random();
        let secret = StaticSecret::from(priv_bytes);
        let public = PublicKey::from(&secret).to_bytes();
        Self {
            public,
            private: priv_bytes,
        }
    }

    /// Re-hydrate an identity from its raw 32 private bytes. The public
    /// half is derived.
    pub fn from_private(private: [u8; 32]) -> Self {
        let secret = StaticSecret::from(private);
        let public = PublicKey::from(&secret).to_bytes();
        Self { public, private }
    }
}

/// Compute the 32-byte X25519 shared secret between `self_private` and
/// `other_public`. This is raw ECDH — callers should always feed the
/// result through [`derive_share_wrap_key`] before using it for
/// encryption, never directly as an AEAD key.
pub fn x25519_shared_secret(self_private: &[u8; 32], other_public: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*self_private);
    let other = PublicKey::from(*other_public);
    secret.diffie_hellman(&other).to_bytes()
}

/// Derive a 32-byte share wrap key from a raw X25519 shared secret and a
/// per-asset context string.
///
/// Uses HKDF-SHA256 with:
/// - no salt (the shared secret is already uniformly random)
/// - `info = SHARE_HKDF_INFO_V1 || 0x00 || asset_id`
///
/// Binding the asset id into `info` means that even if user A shares
/// twenty assets with user B, each wrap key is independent — a
/// compromise of any one wrap key (which would require an already
/// catastrophic failure) doesn't spread to the others.
pub fn derive_share_wrap_key(shared_secret: &[u8; 32], asset_id: &str) -> [u8; 32] {
    let mut info = Vec::with_capacity(SHARE_HKDF_INFO_V1.len() + 1 + asset_id.len());
    info.extend_from_slice(SHARE_HKDF_INFO_V1);
    info.push(0x00);
    info.extend_from_slice(asset_id.as_bytes());

    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut out = [0u8; 32];
    hk.expand(&info, &mut out)
        .expect("HKDF-SHA256 expand for 32 bytes is infallible");
    out
}

/// One-shot: derive the share wrap key the sender uses to re-wrap a
/// per-asset key for a specific recipient.
pub fn sender_wrap_key(
    sender_private: &[u8; 32],
    recipient_public: &[u8; 32],
    asset_id: &str,
) -> [u8; 32] {
    let shared = x25519_shared_secret(sender_private, recipient_public);
    derive_share_wrap_key(&shared, asset_id)
}

/// One-shot: derive the same share wrap key on the recipient side. ECDH
/// is symmetric, so `sender_wrap_key(a_priv, b_pub) ==
/// recipient_wrap_key(b_priv, a_pub)`.
pub fn recipient_wrap_key(
    recipient_private: &[u8; 32],
    sender_public: &[u8; 32],
    asset_id: &str,
) -> [u8; 32] {
    let shared = x25519_shared_secret(recipient_private, sender_public);
    derive_share_wrap_key(&shared, asset_id)
}

/// Parse a raw 32-byte key from a slice, returning a clear error if the
/// length is wrong. Used by WASM bindings and the recover CLI where the
/// input comes from base64 decode.
pub fn parse_key32(bytes: &[u8], label: &'static str) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map(|arr: &[u8; 32]| *arr)
        .map_err(|_| {
            ResqdError::KeyDerivation(format!(
                "{label}: expected 32 bytes, got {}",
                bytes.len()
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecdh_is_symmetric() {
        let a = IdentityKeypair::generate();
        let b = IdentityKeypair::generate();
        let ab = x25519_shared_secret(&a.private, &b.public);
        let ba = x25519_shared_secret(&b.private, &a.public);
        assert_eq!(ab, ba);
    }

    #[test]
    fn wrap_keys_match_across_parties() {
        let alice = IdentityKeypair::generate();
        let bob = IdentityKeypair::generate();
        let ka = sender_wrap_key(&alice.private, &bob.public, "asset-123");
        let kb = recipient_wrap_key(&bob.private, &alice.public, "asset-123");
        assert_eq!(ka, kb);
    }

    #[test]
    fn wrap_keys_are_per_asset() {
        let alice = IdentityKeypair::generate();
        let bob = IdentityKeypair::generate();
        let k1 = sender_wrap_key(&alice.private, &bob.public, "asset-1");
        let k2 = sender_wrap_key(&alice.private, &bob.public, "asset-2");
        assert_ne!(k1, k2, "different assets must yield different wrap keys");
    }

    #[test]
    fn wrap_keys_differ_per_recipient_pair() {
        let alice = IdentityKeypair::generate();
        let bob = IdentityKeypair::generate();
        let carol = IdentityKeypair::generate();
        let ab = sender_wrap_key(&alice.private, &bob.public, "x");
        let ac = sender_wrap_key(&alice.private, &carol.public, "x");
        assert_ne!(ab, ac, "different recipients must yield different wrap keys");
    }

    #[test]
    fn keypair_from_private_round_trips() {
        let orig = IdentityKeypair::generate();
        let restored = IdentityKeypair::from_private(orig.private);
        assert_eq!(orig.public, restored.public);
        assert_eq!(orig.private, restored.private);
    }

    #[test]
    fn round_trip_wrap_unwrap_per_asset_key() {
        // Verify the whole envelope: sender re-wraps a per-asset key for
        // the recipient, recipient unwraps and gets the same bytes.
        use crate::crypto::encrypt::{decrypt, encrypt};

        let alice = IdentityKeypair::generate();
        let bob = IdentityKeypair::generate();
        let asset_id = "asset-test";
        let per_asset_key = [0x42u8; 32];

        let wrap_key_alice = sender_wrap_key(&alice.private, &bob.public, asset_id);
        let envelope = encrypt(&wrap_key_alice, &per_asset_key).unwrap();

        let wrap_key_bob = recipient_wrap_key(&bob.private, &alice.public, asset_id);
        let recovered = decrypt(&wrap_key_bob, &envelope).unwrap();
        assert_eq!(recovered, per_asset_key);
    }
}
