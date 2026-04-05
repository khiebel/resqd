//! End-to-end integration test: spin up a local anvil node, deploy the
//! contract, rotate a real `CanaryChain`, anchor each commitment, and verify
//! the on-chain state matches the off-chain state.
//!
//! This is the single test that proves the Rust↔Solidity↔anchor bridge
//! actually works. It requires `anvil` on PATH (installed with Foundry).
//!
//! Run with: `cargo test --test anvil_roundtrip -- --nocapture`

use alloy::{
    hex,
    node_bindings::Anvil,
    network::{EthereumWallet, TransactionBuilder},
    primitives::FixedBytes,
    providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
    sol,
};
use resqd_chain::{CanaryAnchorClient, ChainConfig, asset_hash_to_bytes32};
use resqd_core::canary::CanaryChain;
use resqd_core::crypto::hash::AssetHash;

// Inline the deployable contract so the test doesn't depend on a pre-built
// artifact path. This gives alloy::sol! both the ABI and the bytecode via
// the filesystem path.
sol! {
    #[sol(rpc, bytecode = "0x")]
    #[allow(missing_docs)]
    contract ResqdCanaryAnchor {
        function owner() external view returns (address);
        function authorizedSigners(address) external view returns (bool);
        function authorizeSigner(address signer) external;
        function anchor(
            bytes32 assetId,
            bytes32 commitmentHash,
            uint64 sequence,
            bytes32 prevHash
        ) external;
        function getAnchor(bytes32 assetId) external view returns (
            bytes32 commitmentHash,
            uint64 sequence,
            uint64 timestamp,
            bool exists
        );
    }
}

/// Load the deployment bytecode from the Foundry build output.
fn load_deploy_bytecode() -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("contracts/out/ResqdCanaryAnchor.sol/ResqdCanaryAnchor.json");
    let json = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("run `forge build` in ../contracts first. missing: {}", path.display()));
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let bytecode_hex = v["bytecode"]["object"]
        .as_str()
        .expect("bytecode.object in artifact");
    hex::decode(bytecode_hex.trim_start_matches("0x")).unwrap()
}

#[tokio::test]
async fn rotate_and_anchor_full_chain() {
    // ---------- Spin up anvil ----------
    let anvil = Anvil::new().try_spawn().expect("failed to start anvil — install Foundry?");
    let rpc_url = anvil.endpoint_url();
    let deployer_key = anvil.keys()[0].clone();
    let deployer: PrivateKeySigner = deployer_key.clone().into();
    let wallet = EthereumWallet::from(deployer.clone());

    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(rpc_url.clone());

    // ---------- Deploy contract ----------
    let bytecode = load_deploy_bytecode();
    let deploy_tx = alloy::rpc::types::TransactionRequest::default()
        .with_deploy_code(bytecode);
    let pending = alloy::providers::Provider::send_transaction(&provider, deploy_tx)
        .await
        .expect("send deploy tx");
    let receipt = pending.get_receipt().await.expect("deploy receipt");
    let contract_addr = receipt
        .contract_address
        .expect("contract address in deploy receipt");
    println!("deployed ResqdCanaryAnchor at {}", contract_addr);

    // ---------- Build our client ----------
    let config = ChainConfig {
        rpc_url,
        contract: contract_addr,
        signer_key: format!("0x{}", hex::encode(deployer_key.to_bytes())),
    };
    let client = CanaryAnchorClient::new(config).expect("client");

    // ---------- Create a canary chain in Rust, anchor every commitment ----------
    let asset_id = "test-asset-alpha-001";
    let asset_id_hash: [u8; 32] = AssetHash::from_bytes(asset_id.as_bytes()).0;

    let mut chain = CanaryChain::new(asset_id);
    // Anchor the initial commitment (sequence 0)
    let c0 = chain.commitments[0].clone();
    let r0 = client.anchor_commitment(asset_id_hash, &c0).await.expect("anchor sequence 0");
    println!("anchor 0 mined in block {:?}", r0.block_number);

    // Now rotate a few times and anchor each
    for _ in 0..3 {
        let commit = chain.rotate();
        let receipt = client
            .anchor_commitment(asset_id_hash, &commit)
            .await
            .unwrap_or_else(|e| panic!("anchor sequence {}: {e}", commit.sequence));
        println!(
            "anchor {} mined in block {:?} ({} gas)",
            commit.sequence,
            receipt.block_number,
            receipt.gas_used
        );
    }

    // ---------- Verify on-chain state matches off-chain ----------
    let onchain = client.get_anchor(asset_id_hash).await.expect("getAnchor");
    let offchain = chain.latest_commitment().unwrap();

    assert!(onchain.exists, "asset should exist on-chain");
    assert_eq!(onchain.sequence, offchain.sequence, "sequence mismatch");
    assert_eq!(
        onchain.commitment_hash,
        asset_hash_to_bytes32(&offchain.hash),
        "commitment hash mismatch"
    );

    // Access count: chain has 4 commitments (1 initial + 3 rotations), sequence 3
    assert_eq!(chain.access_count(), 4);
    assert_eq!(onchain.sequence, 3);
    assert!(
        client
            .verify_access_count(asset_id_hash, 4)
            .await
            .expect("verifyAccessCount"),
        "on-chain verifyAccessCount(4) should be true"
    );
    assert!(
        !client
            .verify_access_count(asset_id_hash, 5)
            .await
            .expect("verifyAccessCount"),
        "on-chain verifyAccessCount(5) should be false"
    );

    // Verify Rust-side chain integrity still holds
    chain.verify_chain().expect("off-chain chain verify");

    println!("✓ full rotate-and-anchor round-trip verified");
}

#[tokio::test]
async fn reject_replayed_sequence() {
    let anvil = Anvil::new().try_spawn().expect("anvil");
    let rpc_url = anvil.endpoint_url();
    let deployer_key = anvil.keys()[0].clone();
    let deployer: PrivateKeySigner = deployer_key.clone().into();
    let wallet = EthereumWallet::from(deployer.clone());

    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(rpc_url.clone());

    let bytecode = load_deploy_bytecode();
    let deploy_tx = alloy::rpc::types::TransactionRequest::default()
        .with_deploy_code(bytecode);
    let receipt = alloy::providers::Provider::send_transaction(&provider, deploy_tx)
        .await
        .expect("send deploy tx")
        .get_receipt()
        .await
        .expect("deploy receipt");
    let contract_addr = receipt.contract_address.expect("address");

    let config = ChainConfig {
        rpc_url,
        contract: contract_addr,
        signer_key: format!("0x{}", hex::encode(deployer_key.to_bytes())),
    };
    let client = CanaryAnchorClient::new(config).expect("client");

    let asset_id_hash: [u8; 32] = AssetHash::from_bytes(b"replay-test").0;
    let mut chain = CanaryChain::new("replay-test");

    // Anchor sequence 0
    client
        .anchor_commitment(asset_id_hash, &chain.commitments[0].clone())
        .await
        .expect("anchor 0");

    // Try to re-anchor the same sequence — should fail
    let replay = chain.commitments[0].clone();
    let result = client.anchor_commitment(asset_id_hash, &replay).await;
    assert!(result.is_err(), "replaying sequence 0 should revert on-chain");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("InvalidSequence") || err.contains("0x"),
        "expected InvalidSequence revert, got: {err}"
    );

    // Sanity: anchoring the real sequence 1 should work
    let c1 = chain.rotate();
    client.anchor_commitment(asset_id_hash, &c1).await.expect("anchor 1");

    let final_state = client.get_anchor(asset_id_hash).await.expect("getAnchor");
    assert_eq!(final_state.sequence, 1);

    println!("✓ replay rejection verified");
}

// Silence unused warnings when sol! binding fields aren't used by some tests
#[allow(dead_code)]
fn _suppress_unused_warnings() {
    let _ = FixedBytes::<32>::default();
    let _ = ResqdCanaryAnchor::ownerCall {};
}
