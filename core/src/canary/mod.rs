//! Canary-based tamper detection system.
//!
//! Every asset has a chain of canary tokens. Each access rotates the canary
//! and produces a new BLAKE3 commitment. The commitment chain is anchored
//! on-chain (Base L2). The owner can verify: "my canary chain has exactly K
//! entries, meaning the asset was accessed exactly K times."
//!
//! No party — including the service operator — can access an asset without
//! producing a new canary commitment. Silent observation is impossible.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use rand::Rng;

use crate::crypto::hash::AssetHash;
use crate::error::{ResqdError, Result};

/// A single canary token (256-bit random secret).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CanaryToken(pub [u8; 32]);

/// A canary commitment (BLAKE3 hash of canary + asset_id + sequence).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanaryCommitment {
    pub hash: AssetHash,
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
    /// Hash of the previous commitment (chain integrity).
    pub prev_hash: Option<AssetHash>,
}

/// The full canary chain for an asset.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CanaryChain {
    pub asset_id: String,
    pub commitments: Vec<CanaryCommitment>,
    /// Current canary token (encrypted, only owner can read).
    pub current_token: CanaryToken,
}

impl CanaryToken {
    /// Generate a new random canary token.
    pub fn generate() -> Self {
        Self(rand::rng().random())
    }

    /// Compute the commitment for this canary.
    ///
    /// commitment = BLAKE3(token || asset_id || sequence_bytes)
    pub fn commit(&self, asset_id: &str, sequence: u64) -> AssetHash {
        let mut data = Vec::with_capacity(32 + asset_id.len() + 8);
        data.extend_from_slice(&self.0);
        data.extend_from_slice(asset_id.as_bytes());
        data.extend_from_slice(&sequence.to_le_bytes());
        AssetHash::from_bytes(&data)
    }
}

impl CanaryChain {
    /// Create a new canary chain for an asset (called on first upload).
    pub fn new(asset_id: &str) -> Self {
        let token = CanaryToken::generate();
        let commitment = CanaryCommitment {
            hash: token.commit(asset_id, 0),
            sequence: 0,
            timestamp: Utc::now(),
            prev_hash: None,
        };

        Self {
            asset_id: asset_id.to_string(),
            commitments: vec![commitment],
            current_token: token,
        }
    }

    /// Rotate the canary (called on every access).
    ///
    /// Generates a new canary token, computes commitment, chains to previous.
    /// Returns the new commitment (to be anchored on-chain).
    pub fn rotate(&mut self) -> CanaryCommitment {
        let new_token = CanaryToken::generate();
        let sequence = self.commitments.len() as u64;
        let prev_hash = self.commitments.last().map(|c| c.hash.clone());

        let commitment = CanaryCommitment {
            hash: new_token.commit(&self.asset_id, sequence),
            sequence,
            timestamp: Utc::now(),
            prev_hash,
        };

        self.commitments.push(commitment.clone());
        self.current_token = new_token;
        commitment
    }

    /// Verify the entire canary chain integrity.
    ///
    /// Checks: sequential ordering, prev_hash linkage, no gaps.
    /// Does NOT verify individual canary tokens (those are secret).
    pub fn verify_chain(&self) -> Result<u64> {
        if self.commitments.is_empty() {
            return Err(ResqdError::CanaryChainBroken { index: 0 });
        }

        // First commitment should have no prev_hash
        if self.commitments[0].prev_hash.is_some() {
            return Err(ResqdError::CanaryChainBroken { index: 0 });
        }

        for i in 1..self.commitments.len() {
            let current = &self.commitments[i];
            let previous = &self.commitments[i - 1];

            // Sequence must be contiguous
            if current.sequence != previous.sequence + 1 {
                return Err(ResqdError::CanaryChainBroken {
                    index: current.sequence,
                });
            }

            // prev_hash must match the previous commitment's hash
            match &current.prev_hash {
                Some(prev) if prev == &previous.hash => {}
                _ => {
                    return Err(ResqdError::CanaryChainBroken {
                        index: current.sequence,
                    });
                }
            }

            // Timestamps must be non-decreasing
            if current.timestamp < previous.timestamp {
                return Err(ResqdError::CanaryChainBroken {
                    index: current.sequence,
                });
            }
        }

        Ok(self.commitments.len() as u64)
    }

    /// Get the total number of accesses (including initial creation).
    pub fn access_count(&self) -> u64 {
        self.commitments.len() as u64
    }

    /// Get the latest commitment (for on-chain anchoring).
    pub fn latest_commitment(&self) -> Option<&CanaryCommitment> {
        self.commitments.last()
    }

    /// Verify that the reported access count matches the chain.
    pub fn verify_access_count(&self, expected: u64) -> Result<()> {
        let actual = self.access_count();
        if actual != expected {
            return Err(ResqdError::CanaryMismatch {
                expected,
                found: actual,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_chain_has_one_commitment() {
        let chain = CanaryChain::new("asset-001");
        assert_eq!(chain.access_count(), 1);
        assert_eq!(chain.commitments[0].sequence, 0);
        assert!(chain.commitments[0].prev_hash.is_none());
    }

    #[test]
    fn rotate_increments_access_count() {
        let mut chain = CanaryChain::new("asset-001");
        chain.rotate();
        chain.rotate();
        chain.rotate();
        assert_eq!(chain.access_count(), 4); // 1 initial + 3 rotations
    }

    #[test]
    fn rotate_chains_prev_hash() {
        let mut chain = CanaryChain::new("asset-001");
        let first_hash = chain.commitments[0].hash.clone();
        let commitment = chain.rotate();
        assert_eq!(commitment.prev_hash.unwrap(), first_hash);
    }

    #[test]
    fn verify_chain_valid() {
        let mut chain = CanaryChain::new("asset-001");
        chain.rotate();
        chain.rotate();
        let count = chain.verify_chain().unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn verify_chain_detects_gap() {
        let mut chain = CanaryChain::new("asset-001");
        chain.rotate();

        // Tamper: skip a sequence number
        chain.commitments[1].sequence = 5;

        assert!(chain.verify_chain().is_err());
    }

    #[test]
    fn verify_chain_detects_broken_link() {
        let mut chain = CanaryChain::new("asset-001");
        chain.rotate();
        chain.rotate();

        // Tamper: change the prev_hash
        chain.commitments[2].prev_hash = Some(AssetHash::from_bytes(b"fake"));

        assert!(chain.verify_chain().is_err());
    }

    #[test]
    fn verify_access_count_matches() {
        let mut chain = CanaryChain::new("asset-001");
        chain.rotate();
        chain.rotate();
        assert!(chain.verify_access_count(3).is_ok());
        assert!(chain.verify_access_count(2).is_err());
    }

    #[test]
    fn each_rotation_produces_unique_commitment() {
        let mut chain = CanaryChain::new("asset-001");
        let c1 = chain.rotate();
        let c2 = chain.rotate();
        let c3 = chain.rotate();
        assert_ne!(c1.hash, c2.hash);
        assert_ne!(c2.hash, c3.hash);
    }

    #[test]
    fn commitment_is_deterministic_for_same_token() {
        let token = CanaryToken([42u8; 32]);
        let h1 = token.commit("asset-001", 5);
        let h2 = token.commit("asset-001", 5);
        assert_eq!(h1, h2);
    }

    #[test]
    fn commitment_differs_for_different_sequence() {
        let token = CanaryToken([42u8; 32]);
        let h1 = token.commit("asset-001", 0);
        let h2 = token.commit("asset-001", 1);
        assert_ne!(h1, h2);
    }

    #[test]
    fn serialization_roundtrip() {
        let mut chain = CanaryChain::new("asset-001");
        chain.rotate();
        chain.rotate();

        let json = serde_json::to_string(&chain).unwrap();
        let deserialized: CanaryChain = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.access_count(), 3);
        assert!(deserialized.verify_chain().is_ok());
    }
}
