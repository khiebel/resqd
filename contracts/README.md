# RESQD Contracts

Solidity contracts for on-chain canary commitment anchoring.

## Contracts

### `ResqdCanaryAnchor.sol`

Tamper-evident canary anchor. Every asset access in the RESQD vault must
rotate the canary and write a new commitment on-chain. The contract enforces
strict chain integrity (monotonic sequence + prevHash linkage), so no party
— including the RESQD service operator — can access an asset without
producing a verifiable on-chain trail.

- No global pause. No upgrade path. By design.
- Authorized signer model: owner authorizes signer addresses (e.g. the AWS
  KMS-backed signer used by the service).
- Gas: ~30-50k per anchor on Base (~$0.002/anchor at typical gas).

## Quickstart

```bash
# Install Foundry (one-time)
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Install forge-std
forge install foundry-rs/forge-std --no-commit

# Build + test
forge build
forge test -vv

# Fuzz test with more runs
forge test --fuzz-runs 10000
```

## Deploy to Base Sepolia (testnet)

```bash
export PRIVATE_KEY=0x...          # deployer key
export BASESCAN_API_KEY=...       # for verification (optional)

forge script script/Deploy.s.sol:DeployScript \
  --rpc-url base_sepolia \
  --broadcast \
  --verify
```

## Deploy to Base mainnet

```bash
forge script script/Deploy.s.sol:DeployScript \
  --rpc-url base \
  --broadcast \
  --verify
```

## Integration

The Rust service calls `anchor(assetId, commitmentHash, sequence, prevHash)`
after every canary rotation in `resqd-core`. The `assetId` is a BLAKE3 hash
of the client-side asset identifier (opaque, non-correlatable). The
`commitmentHash` is produced by `CanaryChain::rotate()` in the Rust core.

See `../core/src/canary/mod.rs` for the Rust-side chain logic that mirrors
the on-chain invariants.
