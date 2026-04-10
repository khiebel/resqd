//! Streaming Reed-Solomon encoder/decoder.
//!
//! This is Track 1, Chunk 1.3 of the Verimus integration plan
//! (`~/.claude/plans/verimus-streaming-integration.md`). Paired with
//! `crypto::stream`, it lets RESQD erasure-code multi-gigabyte files
//! without ever holding the whole payload in memory: the caller feeds
//! one sealed ciphertext chunk at a time, gets back six shard-chunks,
//! and pushes each one to its destination S3 multipart upload (Chunk
//! 1.4).
//!
//! ## Shape
//!
//! - Input: a sequence of plaintext chunks (typically sealed ciphertext
//!   from `crypto::stream::StreamEncryptor`), variable size.
//! - Output: per input chunk, a [`ShardGroup`] carrying all 6 shard-
//!   chunks. Each shard-chunk is the same size within a group, but
//!   groups can differ in size (the final group is usually smaller).
//! - Sidecar: a [`StreamManifest`] produced on `finish()` that records
//!   per-group metadata. This is what the read side needs to know how
//!   big each group is and which BLAKE3 hash to expect after decoding
//!   it (the hash is what powers Track 2's proof-of-absorption — the
//!   manifest itself is the source of truth for "the bytes we expected").
//!
//! ## Why the manifest carries a per-group hash
//!
//! Reed-Solomon with `reconstruct()` will happily produce a valid-looking
//! answer if you feed it four corrupt shards that happen to satisfy the
//! linear system. In practice that requires the corruption to be on
//! specific shards, and the BLAKE3 check below is cheap enough to run
//! unconditionally. It's a belt to go with the Poly1305 suspenders in
//! the sealed-chunk layer above.
//!
//! ## Boundaries this module does NOT address
//!
//! - Where the shard-chunks go (that's the S3 multipart plumbing in 1.4).
//! - Per-group ordering across shards (the caller must write group N to
//!   all 6 shards before moving to group N+1, or record offsets).
//! - The server-side random-range re-read of shards (that's Track 2
//!   Chunk 2.3).

use reed_solomon_erasure::galois_8::ReedSolomon;
use serde::{Deserialize, Serialize};

use crate::error::{ResqdError, Result};

use super::{DATA_SHARDS, PARITY_SHARDS, TOTAL_SHARDS};

/// Per-group metadata recorded in the manifest. One entry per encoded
/// input chunk.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupMeta {
    /// Bytes of *input* for this group (pre-padding). On decode we use
    /// this to trim the reconstructed output down to the actual payload.
    pub data_len: u32,
    /// Size of each of the 6 shard-chunks for this group (post-padding,
    /// divided by `DATA_SHARDS`). All 6 shards of a given group are the
    /// same size; different groups may have different sizes.
    pub shard_size: u32,
    /// BLAKE3 of the original input bytes for this group. Verified after
    /// decoding to catch post-reconstruction corruption.
    pub input_hash: [u8; 32],
}

/// Sidecar that the read side needs to make sense of the 6 shard streams.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamManifest {
    /// Manifest schema version. Bump when the on-disk shape changes.
    pub version: u8,
    pub data_shards: u8,
    pub parity_shards: u8,
    /// Total bytes of input across all groups. Sanity check + UI.
    pub total_input_bytes: u64,
    /// One entry per group. `groups.len()` == number of encoded chunks.
    pub groups: Vec<GroupMeta>,
}

impl StreamManifest {
    pub fn total_shards(&self) -> usize {
        self.data_shards as usize + self.parity_shards as usize
    }

    pub fn group_count(&self) -> u32 {
        self.groups.len() as u32
    }
}

/// The 6 shard-chunks produced from a single input group. The caller
/// typically appends `shards[i]` to shard `i`'s S3 multipart upload.
#[derive(Clone, Debug)]
pub struct ShardGroup {
    pub group_index: u32,
    pub shards: [Vec<u8>; TOTAL_SHARDS],
}

// ── encoder ─────────────────────────────────────────────────────────────

pub struct StreamEncoder {
    rs: ReedSolomon,
    total_input_bytes: u64,
    groups: Vec<GroupMeta>,
}

impl StreamEncoder {
    pub fn new() -> Result<Self> {
        let rs = ReedSolomon::new(DATA_SHARDS, PARITY_SHARDS)
            .map_err(|e| ResqdError::ErasureCoding(format!("init failed: {e}")))?;
        Ok(Self {
            rs,
            total_input_bytes: 0,
            groups: Vec::new(),
        })
    }

    pub fn groups_encoded(&self) -> u32 {
        self.groups.len() as u32
    }

    pub fn total_input_bytes(&self) -> u64 {
        self.total_input_bytes
    }

    /// Encode one group of input bytes into 6 shard-chunks.
    ///
    /// Any non-empty `input` slice is legal. The input is padded up to a
    /// multiple of `DATA_SHARDS`, split across 4 data shards, and 2 parity
    /// shards are computed from them.
    pub fn encode_group(&mut self, input: &[u8]) -> Result<ShardGroup> {
        if input.is_empty() {
            return Err(ResqdError::ErasureCoding(
                "cannot encode an empty group".into(),
            ));
        }

        // Pad input to a multiple of DATA_SHARDS so it splits cleanly.
        let shard_size = input.len().div_ceil(DATA_SHARDS);
        let padded_len = shard_size * DATA_SHARDS;

        // Allocate six shard buffers of the same length.
        let mut shards: Vec<Vec<u8>> = (0..TOTAL_SHARDS)
            .map(|_| vec![0u8; shard_size])
            .collect();

        // Copy input into the 4 data shards. The trailing bytes of the
        // last data shard stay zero (padding), which is fine because we
        // remember the original `data_len` in the manifest and trim on
        // the decode side.
        for (i, chunk) in input.chunks(shard_size).enumerate() {
            shards[i][..chunk.len()].copy_from_slice(chunk);
        }

        // Compute parity in-place on the pre-sized shard buffers.
        self.rs
            .encode(&mut shards)
            .map_err(|e| ResqdError::ErasureCoding(format!("encode failed: {e}")))?;

        debug_assert_eq!(shards.len(), TOTAL_SHARDS);
        debug_assert_eq!(padded_len, shard_size * DATA_SHARDS);

        // Record the manifest entry.
        let input_hash: [u8; 32] = *blake3::hash(input).as_bytes();
        let group_index = self.groups.len() as u32;
        self.groups.push(GroupMeta {
            data_len: input.len() as u32,
            shard_size: shard_size as u32,
            input_hash,
        });
        self.total_input_bytes += input.len() as u64;

        // Collect the shards into the fixed-size array the public API
        // promises. `drain().collect()` + `try_into()` is the idiomatic
        // Vec → [T; N] dance.
        let shards_arr: [Vec<u8>; TOTAL_SHARDS] = shards
            .into_iter()
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| ResqdError::ErasureCoding("shard count mismatch".into()))?;

        Ok(ShardGroup {
            group_index,
            shards: shards_arr,
        })
    }

    /// Finalize the stream and return the manifest. The encoder is
    /// consumed — it cannot be used after this.
    pub fn finish(self) -> StreamManifest {
        StreamManifest {
            version: 1,
            data_shards: DATA_SHARDS as u8,
            parity_shards: PARITY_SHARDS as u8,
            total_input_bytes: self.total_input_bytes,
            groups: self.groups,
        }
    }
}

// ── decoder ─────────────────────────────────────────────────────────────

pub struct StreamDecoder {
    rs: ReedSolomon,
    manifest: StreamManifest,
    next_group_index: u32,
}

impl StreamDecoder {
    pub fn new(manifest: StreamManifest) -> Result<Self> {
        if manifest.version != 1 {
            return Err(ResqdError::ErasureCoding(format!(
                "unsupported stream manifest version {}",
                manifest.version
            )));
        }
        if manifest.data_shards as usize != DATA_SHARDS
            || manifest.parity_shards as usize != PARITY_SHARDS
        {
            return Err(ResqdError::ErasureCoding(format!(
                "manifest shard config ({}+{}) does not match compiled defaults ({}+{})",
                manifest.data_shards, manifest.parity_shards, DATA_SHARDS, PARITY_SHARDS
            )));
        }
        let rs = ReedSolomon::new(DATA_SHARDS, PARITY_SHARDS)
            .map_err(|e| ResqdError::ErasureCoding(format!("init failed: {e}")))?;
        Ok(Self {
            rs,
            manifest,
            next_group_index: 0,
        })
    }

    pub fn manifest(&self) -> &StreamManifest {
        &self.manifest
    }

    pub fn groups_decoded(&self) -> u32 {
        self.next_group_index
    }

    /// Decode the next group. `shards` must have exactly `TOTAL_SHARDS`
    /// entries (6), each `Some(bytes)` or `None` for a missing shard.
    /// At least `DATA_SHARDS` entries must be `Some`. Must be called in
    /// group-index order.
    pub fn decode_group(&mut self, mut shards: Vec<Option<Vec<u8>>>) -> Result<Vec<u8>> {
        if self.next_group_index >= self.manifest.group_count() {
            return Err(ResqdError::ErasureCoding(format!(
                "decoded all {} groups, no more to open",
                self.manifest.group_count()
            )));
        }
        if shards.len() != TOTAL_SHARDS {
            return Err(ResqdError::ErasureCoding(format!(
                "expected {} shards, got {}",
                TOTAL_SHARDS,
                shards.len()
            )));
        }
        let present = shards.iter().filter(|s| s.is_some()).count();
        if present < DATA_SHARDS {
            return Err(ResqdError::InsufficientShards {
                needed: DATA_SHARDS,
                have: present,
            });
        }

        // Look up this group's metadata (data_len, expected hash, shard_size)
        // from the manifest. This is the authoritative source.
        let meta = &self.manifest.groups[self.next_group_index as usize];

        // Every present shard for this group must be exactly `shard_size`
        // bytes. Catch mis-sized uploads early.
        for (i, shard) in shards.iter().enumerate() {
            if let Some(bytes) = shard
                && bytes.len() != meta.shard_size as usize
            {
                return Err(ResqdError::ErasureCoding(format!(
                    "group {} shard {}: expected {} bytes, got {}",
                    self.next_group_index,
                    i,
                    meta.shard_size,
                    bytes.len()
                )));
            }
        }

        // Reconstruct missing shards if any are None.
        self.rs
            .reconstruct(&mut shards)
            .map_err(|e| ResqdError::ErasureCoding(format!("reconstruct failed: {e}")))?;

        // Reassemble the original input by concatenating the 4 data
        // shards and trimming back to `data_len`.
        let mut output = Vec::with_capacity(meta.shard_size as usize * DATA_SHARDS);
        for shard in shards.iter().take(DATA_SHARDS) {
            let bytes = shard.as_ref().ok_or_else(|| {
                ResqdError::ErasureCoding("data shard missing after reconstruct".into())
            })?;
            output.extend_from_slice(bytes);
        }
        output.truncate(meta.data_len as usize);

        // Verify the hash matches what the manifest recorded. This is the
        // post-reconstruction integrity check — belt to Poly1305's
        // suspenders above.
        let actual: [u8; 32] = *blake3::hash(&output).as_bytes();
        if actual != meta.input_hash {
            return Err(ResqdError::ErasureCoding(format!(
                "group {} hash mismatch after reconstruction",
                self.next_group_index
            )));
        }

        self.next_group_index += 1;
        Ok(output)
    }

    /// Call once all groups have been decoded. Asserts that every group
    /// in the manifest was consumed; the caller should not see this fail
    /// if they iterated `manifest.group_count()` times.
    pub fn finish(&self) -> Result<()> {
        if self.next_group_index != self.manifest.group_count() {
            return Err(ResqdError::ErasureCoding(format!(
                "incomplete stream: decoded {} of {} groups",
                self.next_group_index,
                self.manifest.group_count()
            )));
        }
        Ok(())
    }
}

// ── tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Pseudo-random but deterministic bytes for reproducible tests.
    fn det_bytes(seed: u8, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| ((i as u16).wrapping_mul(31) ^ (seed as u16).wrapping_mul(977)) as u8)
            .collect()
    }

    fn encode_whole_stream(input_groups: &[Vec<u8>]) -> (Vec<ShardGroup>, StreamManifest) {
        let mut enc = StreamEncoder::new().unwrap();
        let mut groups = Vec::with_capacity(input_groups.len());
        for g in input_groups {
            groups.push(enc.encode_group(g).unwrap());
        }
        (groups, enc.finish())
    }

    #[test]
    fn stream_roundtrip_many_groups() {
        // 10 groups of varying sizes from ~1 KB up to ~120 KB.
        let inputs: Vec<Vec<u8>> = (0..10_u8)
            .map(|i| det_bytes(i, 1024 + (i as usize) * 12_345))
            .collect();
        let (encoded, manifest) = encode_whole_stream(&inputs);

        assert_eq!(manifest.group_count(), inputs.len() as u32);
        assert_eq!(
            manifest.total_input_bytes,
            inputs.iter().map(|v| v.len() as u64).sum::<u64>()
        );

        let mut dec = StreamDecoder::new(manifest).unwrap();
        for (i, group) in encoded.iter().enumerate() {
            let as_options: Vec<Option<Vec<u8>>> =
                group.shards.iter().cloned().map(Some).collect();
            let out = dec.decode_group(as_options).unwrap();
            assert_eq!(out, inputs[i]);
        }
        dec.finish().unwrap();
    }

    #[test]
    fn stream_roundtrip_survives_two_missing_shards_per_group() {
        let inputs: Vec<Vec<u8>> = (0..5_u8)
            .map(|i| det_bytes(i, 50_000 + (i as usize) * 1_000))
            .collect();
        let (encoded, manifest) = encode_whole_stream(&inputs);

        let mut dec = StreamDecoder::new(manifest).unwrap();
        for (i, group) in encoded.iter().enumerate() {
            let mut as_options: Vec<Option<Vec<u8>>> =
                group.shards.iter().cloned().map(Some).collect();
            // Drop two shards — one data (index 1) and one parity (index 5).
            // 4+2 Reed-Solomon can recover from any 2 missing.
            as_options[1] = None;
            as_options[5] = None;
            let out = dec.decode_group(as_options).unwrap();
            assert_eq!(out, inputs[i], "mismatch on group {i}");
        }
        dec.finish().unwrap();
    }

    #[test]
    fn stream_rejects_three_missing_shards() {
        let inputs = vec![det_bytes(42, 10_000)];
        let (encoded, manifest) = encode_whole_stream(&inputs);

        let mut dec = StreamDecoder::new(manifest).unwrap();
        let mut as_options: Vec<Option<Vec<u8>>> =
            encoded[0].shards.iter().cloned().map(Some).collect();
        as_options[0] = None;
        as_options[1] = None;
        as_options[2] = None; // only 3 left, need 4

        let err = dec.decode_group(as_options).unwrap_err();
        assert!(matches!(err, ResqdError::InsufficientShards { .. }));
    }

    #[test]
    fn stream_hash_catches_post_reconstruction_corruption() {
        // Feed the decoder all 6 shards, but flip one bit in a DATA shard.
        // Reed-Solomon `reconstruct()` only fixes missing shards, not
        // corrupted ones, so the corruption survives and the hash check
        // at the end of `decode_group` should catch it.
        let inputs = vec![det_bytes(7, 8_000)];
        let (mut encoded, manifest) = encode_whole_stream(&inputs);
        encoded[0].shards[0][0] ^= 0xFF;

        let mut dec = StreamDecoder::new(manifest).unwrap();
        let as_options: Vec<Option<Vec<u8>>> =
            encoded[0].shards.iter().cloned().map(Some).collect();
        let err = dec.decode_group(as_options).unwrap_err();
        assert!(format!("{err}").contains("hash mismatch"));
    }

    #[test]
    fn stream_rejects_wrong_shard_size() {
        let inputs = vec![det_bytes(1, 5_000)];
        let (mut encoded, manifest) = encode_whole_stream(&inputs);
        // Truncate one shard to an incorrect size.
        encoded[0].shards[3].truncate(10);

        let mut dec = StreamDecoder::new(manifest).unwrap();
        let as_options: Vec<Option<Vec<u8>>> =
            encoded[0].shards.iter().cloned().map(Some).collect();
        let err = dec.decode_group(as_options).unwrap_err();
        assert!(format!("{err}").contains("expected"));
    }

    #[test]
    fn stream_finish_requires_all_groups() {
        let inputs: Vec<Vec<u8>> = (0..3_u8).map(|i| det_bytes(i, 2_048)).collect();
        let (encoded, manifest) = encode_whole_stream(&inputs);

        let mut dec = StreamDecoder::new(manifest).unwrap();
        // Only decode the first two groups
        for group in encoded.iter().take(2) {
            let as_options: Vec<Option<Vec<u8>>> =
                group.shards.iter().cloned().map(Some).collect();
            dec.decode_group(as_options).unwrap();
        }
        assert!(dec.finish().is_err());
    }

    #[test]
    fn stream_manifest_roundtrips_through_json() {
        let inputs = vec![det_bytes(9, 3_000), det_bytes(10, 7_777)];
        let (_, manifest) = encode_whole_stream(&inputs);
        let json = serde_json::to_string(&manifest).unwrap();
        let parsed: StreamManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(manifest, parsed);
    }

    #[test]
    fn integration_crypto_stream_feeds_erasure_stream() {
        // End-to-end: encrypt with crypto::stream, erasure-encode each
        // sealed chunk, then reverse the pipeline. This is the payload
        // path Chunk 1.4 will wire to S3 multipart uploads.
        use crate::crypto::stream::{StreamDecryptor, StreamEncryptor};

        let key = {
            let mut k = [0u8; 32];
            for (i, b) in k.iter_mut().enumerate() {
                *b = (i as u8) ^ 0xA5;
            }
            k
        };
        let original: Vec<u8> = det_bytes(33, 500_000); // 500 KB
        let chunk_size = 64 * 1024; // 64 KB

        // ── seal ──
        let mut enc = StreamEncryptor::new(&key, chunk_size as u32);
        let mut sealed = Vec::new();
        let slices: Vec<&[u8]> = original.chunks(chunk_size).collect();
        for (i, slice) in slices.iter().enumerate() {
            let is_last = i == slices.len() - 1;
            sealed.push(enc.seal_chunk(slice, is_last).unwrap());
        }
        let header = enc.header();

        // ── erasure encode each sealed chunk's ciphertext ──
        let mut erasure_enc = StreamEncoder::new().unwrap();
        let mut shard_groups = Vec::new();
        for chunk in &sealed {
            shard_groups.push(erasure_enc.encode_group(&chunk.ciphertext).unwrap());
        }
        let manifest = erasure_enc.finish();

        assert_eq!(manifest.group_count(), sealed.len() as u32);

        // ── decode: erasure first, then crypto::stream decrypt ──
        let mut erasure_dec = StreamDecoder::new(manifest).unwrap();
        let mut stream_dec = StreamDecryptor::new(&key, header);
        let mut reassembled = Vec::with_capacity(original.len());

        for (sealed_meta, group) in sealed.iter().zip(shard_groups.iter()) {
            // Simulate losing one shard to prove the erasure layer works.
            let mut as_options: Vec<Option<Vec<u8>>> =
                group.shards.iter().cloned().map(Some).collect();
            as_options[2] = None;

            let recovered_ciphertext = erasure_dec.decode_group(as_options).unwrap();
            assert_eq!(recovered_ciphertext, sealed_meta.ciphertext);

            // Rebuild the sealed chunk from the reconstructed ciphertext,
            // plus the original counter/is_last (which in production will
            // come from the chunk-group metadata in the manifest).
            let rebuilt = crate::crypto::stream::SealedChunk {
                counter: sealed_meta.counter,
                is_last: sealed_meta.is_last,
                ciphertext: recovered_ciphertext,
            };
            let plaintext_chunk = stream_dec.open_chunk(&rebuilt).unwrap();
            reassembled.extend_from_slice(&plaintext_chunk);
        }
        erasure_dec.finish().unwrap();
        stream_dec.finish().unwrap();

        assert_eq!(reassembled, original);
    }
}
