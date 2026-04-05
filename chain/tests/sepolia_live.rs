//! Live Base Sepolia integration test. Runs against the deployed contract
//! and a funded dev wallet. Marked `#[ignore]` so it doesn't run by default.
//!
//! Run with:
//! ```
//! export RESQD_CHAIN_RPC_URL=https://sepolia.base.org
//! export RESQD_CHAIN_CONTRACT=0xd45453477aa729C157E4840e81F81D4437Ec99f3
//! export RESQD_CHAIN_SIGNER_KEY=0x...
//! cargo test --test sepolia_live -- --ignored --nocapture
//! ```

use resqd_chain::{CanaryAnchorClient, ChainConfig, asset_hash_to_bytes32};
use resqd_core::canary::CanaryChain;
use resqd_core::crypto::hash::AssetHash;

#[tokio::test]
#[ignore]
async fn rotate_and_anchor_on_sepolia() {
    let config = ChainConfig::from_env().expect("env vars not set");
    let client = CanaryAnchorClient::new(config).expect("client");

    // Use a unique asset id per run so we don't collide with previous runs.
    let asset_id = format!(
        "sepolia-live-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    );
    println!("asset_id: {asset_id}");
    let asset_id_hash: [u8; 32] = AssetHash::from_bytes(asset_id.as_bytes()).0;

    // Create chain and anchor initial commitment
    let mut chain = CanaryChain::new(&asset_id);
    let c0 = chain.commitments[0].clone();
    println!("submitting initial anchor (sequence 0)...");
    let r0 = client
        .anchor_commitment(asset_id_hash, &c0)
        .await
        .expect("anchor 0");
    println!(
        "✓ anchor 0 mined in block {:?}, tx {:?}, gas {}",
        r0.block_number, r0.transaction_hash, r0.gas_used
    );

    // Rotate and anchor twice more
    for _ in 0..2 {
        let commit = chain.rotate();
        println!("submitting rotation anchor (sequence {})...", commit.sequence);
        let receipt = client
            .anchor_commitment(asset_id_hash, &commit)
            .await
            .unwrap_or_else(|e| panic!("anchor {}: {e}", commit.sequence));
        println!(
            "✓ anchor {} mined in block {:?}, tx {:?}, gas {}",
            commit.sequence, receipt.block_number, receipt.transaction_hash, receipt.gas_used
        );
    }

    // Verify on-chain state
    let onchain = client.get_anchor(asset_id_hash).await.expect("getAnchor");
    let offchain = chain.latest_commitment().unwrap();
    println!("onchain state: {:#?}", onchain);
    println!("offchain hash: {}", offchain.hash.to_hex());
    println!("offchain seq : {}", offchain.sequence);
    assert!(onchain.exists);
    assert_eq!(onchain.sequence, offchain.sequence);
    assert_eq!(
        onchain.commitment_hash,
        asset_hash_to_bytes32(&offchain.hash)
    );
    assert!(
        client
            .verify_access_count(asset_id_hash, 3)
            .await
            .expect("verify"),
    );

    println!("✓ full rotate-and-anchor round-trip verified on Base Sepolia");
    println!(
        "contract: https://sepolia.basescan.org/address/{:?}",
        client.contract_address()
    );
}
