//! Reed-Solomon erasure coding for multi-cloud shard distribution.
//!
//! Default config: 4 data shards + 2 parity shards = 6 total.
//! Any 4 of 6 can reconstruct the asset. Storage overhead: 1.5x.
//!
//! Each shard goes to a different cloud (AWS S3, GCP GCS, Azure Blob).
//! No single cloud has the complete asset.

use reed_solomon_erasure::galois_8::ReedSolomon;

use crate::error::{ResqdError, Result};

/// Default erasure coding parameters.
pub const DATA_SHARDS: usize = 4;
pub const PARITY_SHARDS: usize = 2;
pub const TOTAL_SHARDS: usize = DATA_SHARDS + PARITY_SHARDS;

/// Encode data into erasure-coded shards.
///
/// Returns TOTAL_SHARDS shards, each of equal size.
/// Any DATA_SHARDS of them can reconstruct the original.
pub fn encode(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let rs = ReedSolomon::new(DATA_SHARDS, PARITY_SHARDS)
        .map_err(|e| ResqdError::ErasureCoding(format!("init failed: {e}")))?;

    // Pad data to be evenly divisible by DATA_SHARDS
    let shard_size = (data.len() + DATA_SHARDS - 1) / DATA_SHARDS;
    let padded_len = shard_size * DATA_SHARDS;

    let mut padded = data.to_vec();
    padded.resize(padded_len, 0);

    // Split into data shards
    let mut shards: Vec<Vec<u8>> = padded.chunks(shard_size).map(|c| c.to_vec()).collect();

    // Add empty parity shards
    for _ in 0..PARITY_SHARDS {
        shards.push(vec![0u8; shard_size]);
    }

    // Compute parity
    rs.encode(&mut shards)
        .map_err(|e| ResqdError::ErasureCoding(format!("encode failed: {e}")))?;

    Ok(shards)
}

/// Reconstruct data from available shards.
///
/// Pass None for missing shards. Needs at least DATA_SHARDS present.
pub fn reconstruct(shards: &mut Vec<Option<Vec<u8>>>, original_len: usize) -> Result<Vec<u8>> {
    let present = shards.iter().filter(|s| s.is_some()).count();
    if present < DATA_SHARDS {
        return Err(ResqdError::InsufficientShards {
            needed: DATA_SHARDS,
            have: present,
        });
    }

    let rs = ReedSolomon::new(DATA_SHARDS, PARITY_SHARDS)
        .map_err(|e| ResqdError::ErasureCoding(format!("init failed: {e}")))?;

    rs.reconstruct(shards)
        .map_err(|e| ResqdError::ErasureCoding(format!("reconstruct failed: {e}")))?;

    // Reassemble data shards
    let mut data = Vec::with_capacity(original_len);
    for shard in shards.iter().take(DATA_SHARDS) {
        if let Some(s) = shard {
            data.extend_from_slice(s);
        }
    }

    // Trim padding
    data.truncate(original_len);
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_produces_correct_shard_count() {
        let data = b"hello resqd erasure coding test";
        let shards = encode(data).unwrap();
        assert_eq!(shards.len(), TOTAL_SHARDS);
    }

    #[test]
    fn full_shards_reconstruct() {
        let data = b"family photo bytes here";
        let shards = encode(data).unwrap();
        let mut optional: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        let recovered = reconstruct(&mut optional, data.len()).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn survives_losing_parity_shards() {
        let data = b"important document content";
        let shards = encode(data).unwrap();
        let mut optional: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();

        // Lose both parity shards (indices 4 and 5)
        optional[4] = None;
        optional[5] = None;

        let recovered = reconstruct(&mut optional, data.len()).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn survives_losing_data_shards() {
        let data = b"critical crypto seed phrase backup";
        let shards = encode(data).unwrap();
        let mut optional: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();

        // Lose 2 data shards (worst case for 4,2 config)
        optional[0] = None;
        optional[2] = None;

        let recovered = reconstruct(&mut optional, data.len()).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn fails_with_too_many_missing() {
        let data = b"test data";
        let shards = encode(data).unwrap();
        let mut optional: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();

        // Lose 3 shards (only 3 remain, need 4)
        optional[0] = None;
        optional[1] = None;
        optional[2] = None;

        let result = reconstruct(&mut optional, data.len());
        assert!(result.is_err());
    }

    #[test]
    fn large_data_roundtrip() {
        let data = vec![0xAB_u8; 1024 * 1024]; // 1 MB
        let shards = encode(&data).unwrap();
        let mut optional: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();

        // Lose one shard
        optional[3] = None;

        let recovered = reconstruct(&mut optional, data.len()).unwrap();
        assert_eq!(recovered, data);
    }
}
