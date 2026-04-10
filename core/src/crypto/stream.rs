//! Streaming XChaCha20-Poly1305 — encrypt/decrypt large payloads chunk by
//! chunk without ever holding the whole file in memory.
//!
//! This is Track 1, Chunk 1.1 of the Verimus integration plan
//! (`~/.claude/plans/verimus-streaming-integration.md`). Inspired by Eric's
//! Verimus stream-based encryption pipeline — the feature that lets RESQD
//! finally handle multi-gigabyte files without the browser tab dying.
//!
//! ## Design
//!
//! - Each stream is initialized with a fresh random 20-byte `stream_id`.
//! - Each chunk gets a unique 24-byte nonce computed deterministically from
//!   `stream_id || counter_be32`. XChaCha20's 192-bit nonce is more than big
//!   enough; the first 20 bytes are random per-stream and the last 4 are a
//!   monotonic counter, so nonces never collide across chunks or streams.
//! - Each chunk is AEAD-sealed with Additional Authenticated Data (AAD)
//!   equal to `stream_id || counter_be32 || is_last_byte`. Binding the AAD
//!   to the counter and the `is_last` flag prevents three specific attacks:
//!     1. **Reordering** — swapping chunk N and chunk M fails because each
//!        chunk's AAD carries its own counter.
//!     2. **Truncation** — dropping the final chunk fails because the
//!        decryptor's `finish()` method requires that at least one chunk
//!        was marked `is_last = true`.
//!     3. **Cross-stream splice** — mixing a chunk from stream A into the
//!        decryption of stream B fails because the stream_ids differ in
//!        both nonce and AAD.
//! - Chunks can be verified and decrypted independently and in parallel as
//!   long as the caller later asserts they arrived in order.
//!
//! ## Boundaries this module does NOT address
//!
//! - Storage layout of sealed chunks (that's the streaming Reed-Solomon
//!   splitter in Chunk 1.3 and the S3 multipart plumbing in Chunk 1.4).
//! - WASM bindings (Chunk 1.2).
//! - Progress/cancel (Chunk 1.5).

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    XChaCha20Poly1305, XNonce,
};
use serde::{Deserialize, Serialize};

use crate::error::{ResqdError, Result};

/// The header shared across all chunks of a stream. Emit this once per
/// stream — both sender and receiver need the same `stream_id` and
/// `chunk_size` to decrypt.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StreamHeader {
    /// 20 random bytes uniquely identifying this stream. Prevents cross-
    /// stream splicing and gives each chunk a unique nonce prefix.
    pub stream_id: [u8; 20],
    /// Target plaintext bytes per non-final chunk. Final chunk may be
    /// smaller. Used for sanity checks and memory budgeting.
    pub chunk_size: u32,
}

/// One encrypted chunk of a stream. Self-describing enough that a verifier
/// can authenticate it without seeing its neighbors, but ordering must be
/// enforced by the decryptor (see `StreamDecryptor::open_chunk`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SealedChunk {
    /// Zero-based position of this chunk within its stream.
    pub counter: u32,
    /// True for the final chunk of the stream. The decryptor uses this to
    /// detect truncation.
    pub is_last: bool,
    /// Ciphertext with Poly1305 tag appended.
    pub ciphertext: Vec<u8>,
}

/// Hard ceiling on chunks per stream. 2^32 - 1 chunks × 1 MB per chunk is
/// roughly 4 petabytes, so this is effectively unreachable in practice.
pub const MAX_STREAM_CHUNKS: u32 = u32::MAX - 1;

/// Encryptor for a single stream. Not reusable — create a new one per file.
pub struct StreamEncryptor {
    cipher: XChaCha20Poly1305,
    header: StreamHeader,
    next_counter: u32,
    sealed: bool,
}

impl StreamEncryptor {
    /// Create a new stream encryptor with a fresh random `stream_id`.
    pub fn new(key: &[u8; 32], chunk_size: u32) -> Self {
        // Reuse the existing AeadCore::generate_nonce path (same RNG the rest
        // of the crate uses) to get 24 random bytes, then keep the first 20
        // as the stream_id. This avoids pulling `rand_core::RngCore` directly
        // into scope and matches the style of `encrypt.rs`.
        let random = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let mut stream_id = [0u8; 20];
        stream_id.copy_from_slice(&random[..20]);

        Self::with_stream_id(key, chunk_size, stream_id)
    }

    /// Deterministic constructor for tests and protocol fixtures. Callers
    /// must guarantee `stream_id` uniqueness themselves — never reuse one
    /// across two streams under the same key.
    pub fn with_stream_id(key: &[u8; 32], chunk_size: u32, stream_id: [u8; 20]) -> Self {
        Self {
            cipher: XChaCha20Poly1305::new(key.into()),
            header: StreamHeader {
                stream_id,
                chunk_size,
            },
            next_counter: 0,
            sealed: false,
        }
    }

    /// Header to send alongside the sealed chunks. Cheap — clones 24 bytes.
    pub fn header(&self) -> StreamHeader {
        self.header.clone()
    }

    /// Number of chunks sealed so far.
    pub fn chunks_sealed(&self) -> u32 {
        self.next_counter
    }

    /// True once a chunk with `is_last = true` has been sealed.
    pub fn is_finished(&self) -> bool {
        self.sealed
    }

    /// Seal the next chunk. Set `is_last = true` on the final chunk of the
    /// stream — this is how the decryptor detects truncation. After a final
    /// chunk is sealed, further calls return an error.
    pub fn seal_chunk(&mut self, plaintext: &[u8], is_last: bool) -> Result<SealedChunk> {
        if self.sealed {
            return Err(ResqdError::Encryption(
                "stream already sealed — cannot append more chunks".into(),
            ));
        }
        if self.next_counter >= MAX_STREAM_CHUNKS {
            return Err(ResqdError::Encryption(
                "stream exceeded MAX_STREAM_CHUNKS".into(),
            ));
        }

        let counter = self.next_counter;
        let nonce_bytes = chunk_nonce(&self.header.stream_id, counter);
        let aad_bytes = chunk_aad(&self.header.stream_id, counter, is_last);
        let nonce = XNonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad_bytes,
                },
            )
            .map_err(|e| ResqdError::Encryption(e.to_string()))?;

        self.next_counter += 1;
        if is_last {
            self.sealed = true;
        }

        Ok(SealedChunk {
            counter,
            is_last,
            ciphertext,
        })
    }
}

/// Decryptor for a single stream. Enforces in-order consumption and
/// truncation detection. Not reusable — create a new one per file.
pub struct StreamDecryptor {
    cipher: XChaCha20Poly1305,
    header: StreamHeader,
    next_counter: u32,
    finished: bool,
}

impl StreamDecryptor {
    /// Create a new decryptor. Both `key` and `header` must match what the
    /// encryptor used.
    pub fn new(key: &[u8; 32], header: StreamHeader) -> Self {
        Self {
            cipher: XChaCha20Poly1305::new(key.into()),
            header,
            next_counter: 0,
            finished: false,
        }
    }

    /// Open the next chunk. Enforces that `chunk.counter` matches the
    /// expected next counter (no reordering, no skipping) and that no
    /// chunks arrive after one marked `is_last`.
    pub fn open_chunk(&mut self, chunk: &SealedChunk) -> Result<Vec<u8>> {
        if self.finished {
            return Err(ResqdError::Decryption(
                "stream already finished — extra chunk received after final marker".into(),
            ));
        }
        if chunk.counter != self.next_counter {
            return Err(ResqdError::Decryption(format!(
                "chunk counter out of order: expected {}, got {}",
                self.next_counter, chunk.counter
            )));
        }

        let nonce_bytes = chunk_nonce(&self.header.stream_id, chunk.counter);
        let aad_bytes = chunk_aad(&self.header.stream_id, chunk.counter, chunk.is_last);
        let nonce = XNonce::from_slice(&nonce_bytes);

        let plaintext = self
            .cipher
            .decrypt(
                nonce,
                Payload {
                    msg: chunk.ciphertext.as_ref(),
                    aad: &aad_bytes,
                },
            )
            .map_err(|e| ResqdError::Decryption(e.to_string()))?;

        self.next_counter += 1;
        if chunk.is_last {
            self.finished = true;
        }

        Ok(plaintext)
    }

    /// Call once all chunks have been consumed. Returns an error if no
    /// chunk was ever marked `is_last` (i.e. the stream was truncated).
    pub fn finish(&self) -> Result<()> {
        if !self.finished {
            return Err(ResqdError::Decryption(
                "stream truncated — never received a final chunk".into(),
            ));
        }
        Ok(())
    }

    /// Number of chunks successfully opened so far.
    pub fn chunks_opened(&self) -> u32 {
        self.next_counter
    }
}

// ── internal helpers ────────────────────────────────────────────────────

/// nonce = stream_id (20 B) || counter big-endian (4 B). 24 B total = XChaCha20 nonce width.
fn chunk_nonce(stream_id: &[u8; 20], counter: u32) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    nonce[..20].copy_from_slice(stream_id);
    nonce[20..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

/// aad = stream_id || counter_be || is_last_byte. Included in every chunk's
/// authentication so tampering with any of them invalidates the Poly1305 tag.
fn chunk_aad(stream_id: &[u8; 20], counter: u32, is_last: bool) -> [u8; 25] {
    let mut aad = [0u8; 25];
    aad[..20].copy_from_slice(stream_id);
    aad[20..24].copy_from_slice(&counter.to_be_bytes());
    aad[24] = u8::from(is_last);
    aad
}

// ── tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(17) ^ 0xA5;
        }
        key
    }

    fn chunk_up(plaintext: &[u8], chunk_size: usize) -> Vec<&[u8]> {
        plaintext.chunks(chunk_size).collect()
    }

    fn seal_whole_stream(
        key: &[u8; 32],
        chunk_size: u32,
        plaintext: &[u8],
    ) -> (StreamHeader, Vec<SealedChunk>) {
        let mut enc = StreamEncryptor::new(key, chunk_size);
        let slices = chunk_up(plaintext, chunk_size as usize);
        let mut sealed = Vec::with_capacity(slices.len());
        for (i, slice) in slices.iter().enumerate() {
            let is_last = i == slices.len() - 1;
            sealed.push(enc.seal_chunk(slice, is_last).unwrap());
        }
        assert!(enc.is_finished(), "encryptor should be finished after last chunk");
        (enc.header(), sealed)
    }

    #[test]
    fn streaming_roundtrip_many_chunks() {
        // 2.5 MB plaintext, 256 KB chunks → 10 chunks (9 full + 1 partial)
        let key = test_key();
        let plaintext: Vec<u8> = (0..2_500_000_u32).map(|i| (i & 0xFF) as u8).collect();
        let (header, sealed) = seal_whole_stream(&key, 256 * 1024, &plaintext);

        assert_eq!(sealed.len(), 10, "expected 10 chunks for 2.5 MB / 256 KB");
        assert!(sealed.last().unwrap().is_last);
        assert!(!sealed[0].is_last);

        let mut dec = StreamDecryptor::new(&key, header);
        let mut reconstructed = Vec::with_capacity(plaintext.len());
        for chunk in &sealed {
            reconstructed.extend_from_slice(&dec.open_chunk(chunk).unwrap());
        }
        dec.finish().unwrap();

        assert_eq!(reconstructed, plaintext);
        assert_eq!(dec.chunks_opened(), sealed.len() as u32);
    }

    #[test]
    fn truncation_is_detected_even_when_every_chunk_decrypts() {
        // An attacker drops the final chunk. Every remaining chunk still
        // decrypts cleanly — but finish() must fail because we never saw an
        // is_last marker.
        let key = test_key();
        let plaintext = vec![0xCA_u8; 900_000]; // 9 chunks of 100 KB
        let (header, mut sealed) = seal_whole_stream(&key, 100_000, &plaintext);

        assert!(sealed.pop().unwrap().is_last, "popped chunk should be the final one");

        let mut dec = StreamDecryptor::new(&key, header);
        for chunk in &sealed {
            // Each remaining chunk should still open cleanly…
            dec.open_chunk(chunk).unwrap();
        }
        // …but the stream as a whole was truncated.
        let result = dec.finish();
        assert!(result.is_err());
        assert!(
            format!("{}", result.unwrap_err()).contains("truncated"),
            "error should mention truncation"
        );
    }

    #[test]
    fn reordering_chunks_is_rejected() {
        let key = test_key();
        let plaintext: Vec<u8> = (0..400_000_u32).map(|i| (i >> 3) as u8).collect();
        let (header, mut sealed) = seal_whole_stream(&key, 50_000, &plaintext);

        // Swap chunk 1 and chunk 2. Both decrypt in isolation against their
        // own nonces/AAD, but the decryptor enforces in-order counters.
        sealed.swap(1, 2);

        let mut dec = StreamDecryptor::new(&key, header);
        dec.open_chunk(&sealed[0]).unwrap(); // chunk 0, fine
        let result = dec.open_chunk(&sealed[1]); // claims counter=2 when we expect counter=1
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("out of order"));
    }

    #[test]
    fn tampered_ciphertext_fails_that_chunk() {
        let key = test_key();
        let (header, mut sealed) = seal_whole_stream(&key, 1024, &vec![0x42_u8; 4096]);
        // Flip a bit in chunk 2's ciphertext.
        sealed[2].ciphertext[0] ^= 0x01;

        let mut dec = StreamDecryptor::new(&key, header);
        dec.open_chunk(&sealed[0]).unwrap();
        dec.open_chunk(&sealed[1]).unwrap();
        assert!(dec.open_chunk(&sealed[2]).is_err());
    }

    #[test]
    fn cross_stream_splicing_fails() {
        // Take chunk 0 from stream A and try to replay it as chunk 0 of
        // stream B under the same key. AAD differs because stream_id
        // differs → decryption fails.
        let key = test_key();
        let (_hdr_a, sealed_a) = seal_whole_stream(&key, 1024, b"alpha");
        let (hdr_b, _sealed_b) = seal_whole_stream(&key, 1024, b"beta");

        let mut dec = StreamDecryptor::new(&key, hdr_b);
        assert!(dec.open_chunk(&sealed_a[0]).is_err());
    }

    #[test]
    fn cannot_seal_after_final_chunk() {
        let key = test_key();
        let mut enc = StreamEncryptor::new(&key, 1024);
        enc.seal_chunk(b"first", false).unwrap();
        enc.seal_chunk(b"last", true).unwrap();
        assert!(enc.seal_chunk(b"after", false).is_err());
    }

    #[test]
    fn deterministic_stream_id_gives_identical_headers() {
        let key = test_key();
        let stream_id = [0x7F_u8; 20];
        let enc_a = StreamEncryptor::with_stream_id(&key, 1024, stream_id);
        let enc_b = StreamEncryptor::with_stream_id(&key, 1024, stream_id);
        assert_eq!(enc_a.header(), enc_b.header());
    }

    #[test]
    fn random_stream_ids_differ_across_instances() {
        let key = test_key();
        let enc_a = StreamEncryptor::new(&key, 1024);
        let enc_b = StreamEncryptor::new(&key, 1024);
        assert_ne!(
            enc_a.header().stream_id,
            enc_b.header().stream_id,
            "two fresh encryptors must have different random stream_ids"
        );
    }
}
