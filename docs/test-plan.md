# RESQD Comprehensive Test Plan

**Version:** 1.0
**Date:** 2026-04-02
**Crate:** `resqd-core` at `/Users/khiebel/CodeBucket/resqd/core/`

---

## Test File Structure

```
core/
  src/
    crypto/
      hash.rs              # inline unit tests (BLAKE3)
      encrypt.rs           # inline unit tests (XChaCha20-Poly1305)
      kem.rs               # inline unit tests (ML-KEM-768)
      keys.rs              # inline unit tests (Argon2id)
    canary/
      mod.rs               # inline unit tests (canary chain)
    erasure/
      mod.rs               # inline unit tests (Reed-Solomon)
  tests/                           # integration tests (Rust)
    integration_upload.rs          # full upload flow: hash -> encrypt -> erasure -> store
    integration_download.rs        # full download flow: fetch shards -> reconstruct -> decrypt -> verify
    integration_canary.rs          # canary lifecycle across operations
    integration_multicloud.rs      # multi-cloud shard distribution + failover
    integration_keyring.rs         # key ring creation, sharing, revocation
    security_plaintext.rs          # no plaintext leakage verification
    security_tamper.rs             # tamper detection across all layers
    security_sidechannel.rs        # timing and side-channel resistance
    performance_crypto.rs          # encryption/hashing throughput benchmarks
    performance_erasure.rs         # erasure coding throughput benchmarks
    chaos_cloud_failure.rs         # simulated cloud provider outages
    chaos_shard_corruption.rs      # corrupted/missing shard recovery
web/
  __tests__/                       # TypeScript/Jest tests
    wasm-bridge.test.ts            # WASM <-> JS boundary
    crypto-wasm.test.ts            # WASM crypto operations in browser context
  e2e/                             # Playwright E2E tests
    signup-vault.spec.ts           # signup -> upload -> download flow
    share-family.spec.ts           # family sharing flow
    dead-man-switch.spec.ts        # dead man's switch escalation
    recovery.spec.ts               # account/key recovery flow
    performance.spec.ts            # browser performance metrics
```

---

## 1. Unit Tests (Rust)

All unit tests live inline in source files under `core/src/`. Run with `cargo test`.

### 1.1 BLAKE3 Hashing -- `core/src/crypto/hash.rs`

**Existing coverage:** Determinism, uniqueness, hex roundtrip, commit context, keyed hashing, streaming, empty-input known vector.

| Test ID | Description | Expected Result | Status |
|---------|-------------|-----------------|--------|
| TC-UNIT-001 | BLAKE3 known vector: 1-byte input `0x00` | Matches official BLAKE3 test vector | New |
| TC-UNIT-002 | BLAKE3 known vector: 1024-byte incrementing pattern | Matches official BLAKE3 test vector | New |
| TC-UNIT-003 | Streaming hash of 100MB matches single-shot | Hashes are identical | New |
| TC-UNIT-004 | `from_hex` rejects odd-length strings | Returns `InvalidInput` error | New |
| TC-UNIT-005 | `from_hex` rejects non-hex characters | Returns `InvalidInput` error | New |
| TC-UNIT-006 | `from_hex` rejects wrong-length (31 or 33 bytes) | Returns `InvalidInput` error | New |
| TC-UNIT-007 | `commit()` is not commutative: `commit(a,b) != commit(b,a)` | Hashes differ | New |
| TC-UNIT-008 | Empty data + empty context produces valid hash | Non-zero 32-byte hash | New |
| TC-UNIT-009 | `from_bytes` on empty input matches known BLAKE3 vector `af1349b9...` | Hex matches | Exists |
| TC-UNIT-010 | `keyed()` with different keys produces different hashes | Hashes differ | Exists |

```rust
// Additions for core/src/crypto/hash.rs #[cfg(test)] mod tests

#[test]
fn hash_known_vector_single_byte() {
    let h = AssetHash::from_bytes(&[0x00]);
    let expected = blake3::hash(&[0x00]);
    assert_eq!(h.0, *expected.as_bytes());
}

#[test]
fn hash_known_vector_incrementing_1024() {
    let input: Vec<u8> = (0u8..=255).cycle().take(1024).collect();
    let h = AssetHash::from_bytes(&input);
    let expected = blake3::hash(&input);
    assert_eq!(h.0, *expected.as_bytes());
}

#[test]
fn hash_streaming_large() {
    let data = vec![0xABu8; 100 * 1024 * 1024];
    let h1 = AssetHash::from_bytes(&data);
    let h2 = AssetHash::from_reader(&data[..]).unwrap();
    assert_eq!(h1, h2);
}

#[test]
fn hash_from_hex_rejects_odd_length() {
    assert!(AssetHash::from_hex("abc").is_err());
}

#[test]
fn hash_from_hex_rejects_non_hex() {
    let bad = "zz".repeat(32);
    assert!(AssetHash::from_hex(&bad).is_err());
}

#[test]
fn hash_from_hex_rejects_wrong_length() {
    let short = "ab".repeat(31);
    let long = "ab".repeat(33);
    assert!(AssetHash::from_hex(&short).is_err());
    assert!(AssetHash::from_hex(&long).is_err());
}

#[test]
fn hash_commit_not_commutative() {
    let c1 = AssetHash::commit(b"alpha", b"beta");
    let c2 = AssetHash::commit(b"beta", b"alpha");
    assert_ne!(c1, c2);
}

#[test]
fn hash_empty_data_empty_context() {
    let h = AssetHash::commit(b"", b"");
    assert_ne!(h.0, [0u8; 32]);
}
```

### 1.2 XChaCha20-Poly1305 Encryption -- `core/src/crypto/encrypt.rs`

**Existing coverage:** Roundtrip, ciphertext differs from plaintext, unique nonces, wrong key, tampered ciphertext, AAD roundtrip, wrong AAD, 10MB payload.

| Test ID | Description | Expected Result | Status |
|---------|-------------|-----------------|--------|
| TC-UNIT-011 | Encrypt empty plaintext | Roundtrips; ciphertext is 16 bytes (Poly1305 tag only) | New |
| TC-UNIT-012 | Nonce is exactly 24 bytes | `blob.nonce.len() == 24` | New |
| TC-UNIT-013 | Ciphertext length = plaintext length + 16 | Exact length match | New |
| TC-UNIT-014 | Decrypt with truncated ciphertext | Returns `Decryption` error | New |
| TC-UNIT-015 | Decrypt with truncated nonce (12 bytes) | Returns `Decryption` error | New |
| TC-UNIT-016 | Encrypt 100MB payload roundtrips | Content matches after decrypt | New |
| TC-UNIT-017 | AAD with empty plaintext | Roundtrips; wrong AAD still fails | New |
| TC-UNIT-018 | IND-CPA: same plaintext+key produces different ciphertexts | Ciphertexts differ | New |
| TC-UNIT-019 | Single bit flip in ciphertext detected | Returns `Decryption` error | Exists |
| TC-UNIT-020 | Encrypt with all-zero key succeeds | Roundtrips correctly | New |

```rust
// Additions for core/src/crypto/encrypt.rs #[cfg(test)] mod tests

#[test]
fn encrypt_empty_plaintext() {
    let key = test_key();
    let blob = encrypt(&key, b"").unwrap();
    let decrypted = decrypt(&key, &blob).unwrap();
    assert_eq!(decrypted, b"");
    assert_eq!(blob.ciphertext.len(), 16); // Poly1305 tag only
}

#[test]
fn nonce_is_24_bytes() {
    let key = test_key();
    let blob = encrypt(&key, b"test").unwrap();
    assert_eq!(blob.nonce.len(), 24);
}

#[test]
fn ciphertext_length_correct() {
    let key = test_key();
    let plaintext = b"exactly this length";
    let blob = encrypt(&key, plaintext).unwrap();
    assert_eq!(blob.ciphertext.len(), plaintext.len() + 16);
}

#[test]
fn truncated_ciphertext_fails() {
    let key = test_key();
    let mut blob = encrypt(&key, b"data").unwrap();
    blob.ciphertext.truncate(blob.ciphertext.len() / 2);
    assert!(decrypt(&key, &blob).is_err());
}

#[test]
fn truncated_nonce_fails() {
    let key = test_key();
    let mut blob = encrypt(&key, b"data").unwrap();
    blob.nonce.truncate(12);
    assert!(decrypt(&key, &blob).is_err());
}

#[test]
fn encrypt_100mb() {
    let key = test_key();
    let plaintext = vec![0xCDu8; 100 * 1024 * 1024];
    let blob = encrypt(&key, &plaintext).unwrap();
    let decrypted = decrypt(&key, &blob).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn aad_with_empty_plaintext() {
    let key = test_key();
    let aad = b"metadata";
    let blob = encrypt_with_aad(&key, b"", aad).unwrap();
    let decrypted = decrypt_with_aad(&key, &blob, aad).unwrap();
    assert_eq!(decrypted, b"");
    assert!(decrypt_with_aad(&key, &blob, b"wrong").is_err());
}

#[test]
fn ind_cpa_security() {
    let key = test_key();
    let pt = b"identical";
    let c1 = encrypt(&key, pt).unwrap();
    let c2 = encrypt(&key, pt).unwrap();
    assert_ne!(c1.ciphertext, c2.ciphertext);
}

#[test]
fn all_zero_key_works() {
    let key = [0u8; 32];
    let plaintext = b"test with zero key";
    let blob = encrypt(&key, plaintext).unwrap();
    let decrypted = decrypt(&key, &blob).unwrap();
    assert_eq!(decrypted, plaintext);
}
```

### 1.3 ML-KEM-768 Key Encapsulation -- `core/src/crypto/kem.rs`

**Existing coverage:** Roundtrip, different keypairs, wrong secret key, full encryption flow (KEM + XChaCha20).

| Test ID | Description | Expected Result | Status |
|---------|-------------|-----------------|--------|
| TC-UNIT-021 | Public key is 1184 bytes (ML-KEM-768 spec) | `kp.public_key.0.len() == 1184` | New |
| TC-UNIT-022 | Secret key is 2400 bytes | `kp.secret_key.len() == 2400` | New |
| TC-UNIT-023 | Ciphertext is 1088 bytes | `enc.ciphertext.len() == 1088` | New |
| TC-UNIT-024 | Shared secret is exactly 32 bytes | Length matches | New |
| TC-UNIT-025 | Encapsulate with invalid public key (wrong length) | Returns `KeyEncapsulation` error | New |
| TC-UNIT-026 | Decapsulate with invalid secret key (wrong length) | Returns `KeyEncapsulation` error | New |
| TC-UNIT-027 | Decapsulate with invalid ciphertext (wrong length) | Returns `KeyEncapsulation` error | New |
| TC-UNIT-028 | 100 roundtrips all produce unique shared secrets | All 100 secrets are distinct | New |
| TC-UNIT-029 | Serialized public key roundtrips through base64 | Encapsulation still works | New |

```rust
// Additions for core/src/crypto/kem.rs #[cfg(test)] mod tests

#[test]
fn kem_public_key_size() {
    let kp = generate_keypair().unwrap();
    assert_eq!(kp.public_key.0.len(), 1184);
}

#[test]
fn kem_secret_key_size() {
    let kp = generate_keypair().unwrap();
    assert_eq!(kp.secret_key.len(), 2400);
}

#[test]
fn kem_ciphertext_size() {
    let kp = generate_keypair().unwrap();
    let enc = encapsulate(&kp.public_key).unwrap();
    assert_eq!(enc.ciphertext.len(), 1088);
}

#[test]
fn kem_shared_secret_size() {
    let kp = generate_keypair().unwrap();
    let enc = encapsulate(&kp.public_key).unwrap();
    assert_eq!(enc.shared_secret.len(), 32);
}

#[test]
fn kem_invalid_public_key_rejected() {
    let bad_pk = KemPublicKey(vec![0u8; 100]);
    assert!(encapsulate(&bad_pk).is_err());
}

#[test]
fn kem_invalid_secret_key_rejected() {
    let kp = generate_keypair().unwrap();
    let enc = encapsulate(&kp.public_key).unwrap();
    assert!(decapsulate(&[0u8; 100], &enc.ciphertext).is_err());
}

#[test]
fn kem_invalid_ciphertext_rejected() {
    let kp = generate_keypair().unwrap();
    assert!(decapsulate(&kp.secret_key, &[0u8; 100]).is_err());
}

#[test]
fn kem_100_roundtrips_unique() {
    let mut secrets = std::collections::HashSet::new();
    for _ in 0..100 {
        let kp = generate_keypair().unwrap();
        let enc = encapsulate(&kp.public_key).unwrap();
        let ss = decapsulate(&kp.secret_key, &enc.ciphertext).unwrap();
        assert_eq!(ss, enc.shared_secret);
        secrets.insert(ss);
    }
    assert_eq!(secrets.len(), 100);
}
```

### 1.4 Key Derivation (Argon2id) -- `core/src/crypto/keys.rs`

**Existing coverage:** Determinism, different passphrase, different salt, random key size, random key uniqueness.

| Test ID | Description | Expected Result | Status |
|---------|-------------|-----------------|--------|
| TC-UNIT-030 | Derived key is exactly 32 bytes | `key.len() == 32` | New |
| TC-UNIT-031 | Empty passphrase produces valid key | 32-byte non-zero key | New |
| TC-UNIT-032 | Unicode passphrase works | Roundtrips deterministically | New |
| TC-UNIT-033 | Very long passphrase (10KB) works | 32-byte key produced | New |
| TC-UNIT-034 | Generated salt is exactly 16 bytes | `salt.len() == 16` | New |
| TC-UNIT-035 | Two generated salts are unique | Salts differ | New |
| TC-UNIT-036 | Key derivation is slow enough (>100ms) | Wall clock > 100ms | New |
| TC-UNIT-037 | Same passphrase + different salt = different key | Keys differ | Exists |

```rust
// Additions for core/src/crypto/keys.rs #[cfg(test)] mod tests

#[test]
fn derived_key_is_32_bytes() {
    let key = derive_key("test", &[0u8; 16]).unwrap();
    assert_eq!(key.len(), 32);
}

#[test]
fn empty_passphrase_produces_key() {
    let key = derive_key("", &[42u8; 16]).unwrap();
    assert_ne!(key, [0u8; 32]);
}

#[test]
fn unicode_passphrase() {
    let salt = [99u8; 16];
    let k1 = derive_key("\u{1F512}\u{1F30D}", &salt).unwrap();
    let k2 = derive_key("\u{1F512}\u{1F30D}", &salt).unwrap();
    assert_eq!(k1, k2);
}

#[test]
fn long_passphrase() {
    let long = "a".repeat(10240);
    let key = derive_key(&long, &[1u8; 16]).unwrap();
    assert_eq!(key.len(), 32);
}

#[test]
fn salt_is_16_bytes() {
    let salt = generate_salt();
    assert_eq!(salt.len(), 16);
}

#[test]
fn salts_are_unique() {
    let s1 = generate_salt();
    let s2 = generate_salt();
    assert_ne!(s1, s2);
}

#[test]
fn key_derivation_is_slow_enough() {
    let start = std::time::Instant::now();
    derive_key("benchmark-passphrase", &[0u8; 16]).unwrap();
    let elapsed = start.elapsed();
    assert!(elapsed.as_millis() >= 100, "Argon2id too fast: {}ms", elapsed.as_millis());
}
```

### 1.5 Canary Chain -- `core/src/canary/mod.rs`

**Existing coverage:** New chain, rotate increments, prev_hash chaining, verify valid, detect gap, detect broken link, access count, unique commitments, deterministic commit, different sequence, serialization roundtrip.

| Test ID | Description | Expected Result | Status |
|---------|-------------|-----------------|--------|
| TC-UNIT-038 | First commitment has `prev_hash: None` | `commitments[0].prev_hash.is_none()` | Exists |
| TC-UNIT-039 | 1000 rotations maintains valid chain | `verify_chain()` returns `Ok(1001)` | New |
| TC-UNIT-040 | Verify detects timestamp going backwards | Returns `CanaryChainBroken` | New |
| TC-UNIT-041 | Different asset IDs produce different commitments | Hashes differ | New |
| TC-UNIT-042 | Empty chain (manually cleared) fails verification | Returns `CanaryChainBroken` | New |
| TC-UNIT-043 | Token is 32 bytes of randomness | `token.0.len() == 32` | New |
| TC-UNIT-044 | `latest_commitment()` returns last after rotations | Sequence matches | New |
| TC-UNIT-045 | Inserted duplicate commitment detected | Chain verification fails | New |

```rust
// Additions for core/src/canary/mod.rs #[cfg(test)] mod tests

#[test]
fn chain_1000_rotations_valid() {
    let mut chain = CanaryChain::new("stress-test");
    for _ in 0..1000 {
        chain.rotate();
    }
    let count = chain.verify_chain().unwrap();
    assert_eq!(count, 1001);
}

#[test]
fn verify_detects_timestamp_regression() {
    let mut chain = CanaryChain::new("time-test");
    chain.rotate();
    // Tamper: set second commitment's timestamp before first
    chain.commitments[1].timestamp = chain.commitments[0].timestamp
        - chrono::Duration::seconds(1);
    assert!(chain.verify_chain().is_err());
}

#[test]
fn different_asset_ids_different_commitments() {
    let token = CanaryToken([42u8; 32]);
    let h1 = token.commit("asset-A", 0);
    let h2 = token.commit("asset-B", 0);
    assert_ne!(h1, h2);
}

#[test]
fn empty_chain_fails_verification() {
    let mut chain = CanaryChain::new("empty-test");
    chain.commitments.clear();
    assert!(chain.verify_chain().is_err());
}

#[test]
fn token_is_32_bytes() {
    let token = CanaryToken::generate();
    assert_eq!(token.0.len(), 32);
}

#[test]
fn latest_commitment_after_rotations() {
    let mut chain = CanaryChain::new("latest-test");
    chain.rotate();
    chain.rotate();
    chain.rotate();
    let latest = chain.latest_commitment().unwrap();
    assert_eq!(latest.sequence, 3);
}

#[test]
fn duplicate_commitment_detected() {
    let mut chain = CanaryChain::new("dup-test");
    chain.rotate();
    chain.rotate();
    // Tamper: duplicate second commitment as third
    let dup = chain.commitments[1].clone();
    chain.commitments.push(dup);
    assert!(chain.verify_chain().is_err());
}
```

### 1.6 Reed-Solomon Erasure Coding -- `core/src/erasure/mod.rs`

**Existing coverage:** Correct shard count, full reconstruct, survive losing parity shards, survive losing data shards, too many missing, 1MB roundtrip.

| Test ID | Description | Expected Result | Status |
|---------|-------------|-----------------|--------|
| TC-UNIT-046 | All shards are equal size | All `shard.len()` identical | New |
| TC-UNIT-047 | Shard size = ceil(data.len / DATA_SHARDS) | Exact calculation | New |
| TC-UNIT-048 | Empty data encodes and reconstructs | Recovered == empty | New |
| TC-UNIT-049 | 1-byte data encodes to 6 shards | All shards present, recoverable | New |
| TC-UNIT-050 | Lose any 2 of 6 shards and recover (all 15 combinations) | All combinations succeed | New |
| TC-UNIT-051 | 10MB data roundtrip with 2 shards missing | Content matches | New |
| TC-UNIT-052 | Exactly DATA_SHARDS present suffices | Reconstruction succeeds | New |
| TC-UNIT-053 | DATA_SHARDS-1 present fails | Returns `InsufficientShards` | New |

```rust
// Additions for core/src/erasure/mod.rs #[cfg(test)] mod tests

#[test]
fn all_shards_equal_size() {
    let data = b"variable length test data here!";
    let shards = encode(data).unwrap();
    let size = shards[0].len();
    for shard in &shards {
        assert_eq!(shard.len(), size);
    }
}

#[test]
fn shard_size_calculation() {
    let data = vec![0u8; 100];
    let shards = encode(&data).unwrap();
    let expected_shard_size = (100 + DATA_SHARDS - 1) / DATA_SHARDS; // ceil(100/4) = 25
    assert_eq!(shards[0].len(), expected_shard_size);
}

#[test]
fn empty_data_roundtrip() {
    let data = b"";
    let shards = encode(data).unwrap();
    let mut optional: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
    let recovered = reconstruct(&mut optional, 0).unwrap();
    assert_eq!(recovered, data);
}

#[test]
fn single_byte_data() {
    let data = &[0xFFu8];
    let shards = encode(data).unwrap();
    assert_eq!(shards.len(), TOTAL_SHARDS);
    let mut optional: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
    let recovered = reconstruct(&mut optional, 1).unwrap();
    assert_eq!(recovered, data);
}

#[test]
fn all_two_shard_loss_combinations() {
    let data = b"test all 15 combinations of losing 2 of 6";
    let shards = encode(data).unwrap();

    for i in 0..TOTAL_SHARDS {
        for j in (i + 1)..TOTAL_SHARDS {
            let mut optional: Vec<Option<Vec<u8>>> = shards.iter().cloned().map(Some).collect();
            optional[i] = None;
            optional[j] = None;
            let recovered = reconstruct(&mut optional, data.len()).unwrap();
            assert_eq!(recovered, data, "Failed losing shards {} and {}", i, j);
        }
    }
}

#[test]
fn ten_mb_with_missing_shards() {
    let data = vec![0xABu8; 10 * 1024 * 1024];
    let shards = encode(&data).unwrap();
    let mut optional: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
    optional[1] = None;
    optional[4] = None;
    let recovered = reconstruct(&mut optional, data.len()).unwrap();
    assert_eq!(recovered, data);
}

#[test]
fn exactly_data_shards_present() {
    let data = b"minimal recovery test";
    let shards = encode(data).unwrap();
    let mut optional: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
    optional[4] = None; // lose both parity
    optional[5] = None;
    let recovered = reconstruct(&mut optional, data.len()).unwrap();
    assert_eq!(recovered, data);
}

#[test]
fn data_shards_minus_one_fails() {
    let data = b"should fail";
    let shards = encode(data).unwrap();
    let mut optional: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
    optional[0] = None;
    optional[1] = None;
    optional[2] = None;
    assert!(reconstruct(&mut optional, data.len()).is_err());
}
```

---

## 2. Integration Tests -- `core/tests/`

These test cross-module flows. Each file is a separate integration test binary.

### 2.1 Upload Flow -- `core/tests/integration_upload.rs`

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| TC-INT-001 | Full upload pipeline: hash -> derive key -> encrypt -> erasure encode -> canary create | All steps succeed; 6 shards produced; canary chain has 1 commitment |
| TC-INT-002 | Upload with AAD binding (asset_id in AAD) | Decrypt with correct AAD works; wrong AAD fails |
| TC-INT-003 | Upload with KEM: generate keypair, encapsulate, encrypt with shared secret | Recipient can decapsulate and decrypt |
| TC-INT-004 | Upload preserves original file hash | Hash of decrypted content matches hash of original |
| TC-INT-005 | Upload of 0-byte file completes without error | All pipeline steps succeed |
| TC-INT-006 | Upload of 500MB file completes | Pipeline completes, shards are correct size |

### 2.2 Download Flow -- `core/tests/integration_download.rs`

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| TC-INT-007 | Full download pipeline: collect shards -> reconstruct -> decrypt -> verify hash | Plaintext matches original |
| TC-INT-008 | Download with 2 missing shards | Reconstruction succeeds; hash matches |
| TC-INT-009 | Download with wrong key fails cleanly | Returns `Decryption` error, no partial plaintext |
| TC-INT-010 | Download verifies canary chain before returning data | Chain verification runs; access count incremented |
| TC-INT-011 | Download of file encrypted with KEM shared secret | Full KEM decapsulate -> decrypt flow works |

### 2.3 Canary Lifecycle -- `core/tests/integration_canary.rs`

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| TC-INT-012 | Create chain -> upload -> 5 downloads -> verify count = 6 | `verify_access_count(6)` succeeds |
| TC-INT-013 | Serialize canary chain to JSON, deserialize, continue rotating | Chain remains valid after round-trip |
| TC-INT-014 | Two assets have independent canary chains | Rotating one does not affect the other |
| TC-INT-015 | Canary chain survives concurrent rotations (race simulation) | Chain remains valid or returns error (no corruption) |

### 2.4 Multi-Cloud Simulation -- `core/tests/integration_multicloud.rs`

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| TC-INT-016 | Distribute 6 shards to 3 simulated providers (2 each) | Reconstruction works from any 4 |
| TC-INT-017 | One provider goes down (loses 2 shards) | Remaining 4 shards reconstruct |
| TC-INT-018 | Shard routing metadata tracks which shard is where | Metadata accurately reflects shard locations |
| TC-INT-019 | Re-upload after provider failure redistributes shards | New shard distribution covers at least 2 providers |

### 2.5 Key Ring Sharing -- `core/tests/integration_keyring.rs`

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| TC-INT-020 | Owner creates key ring, adds family member via KEM | Family member can decrypt shared assets |
| TC-INT-021 | Owner revokes family member access | Family member's decapsulated key no longer works for new assets |
| TC-INT-022 | Key ring contains per-asset keys wrapped with member's KEM public key | Each member gets independently wrapped keys |
| TC-INT-023 | Adding a member does not require re-encrypting existing assets | Existing shards unchanged; only key wrapping added |

---

## 3. Security Tests -- `core/tests/`

### 3.1 No Plaintext Leakage -- `core/tests/security_plaintext.rs`

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| TC-SEC-001 | Encrypted blob does not contain plaintext substring (>8 bytes) | No plaintext fragments in ciphertext |
| TC-SEC-002 | No shard contains recognizable plaintext | grep-style scan of all 6 shards finds nothing |
| TC-SEC-003 | Canary chain JSON does not contain plaintext | Serialized chain has no file content |
| TC-SEC-004 | Error messages do not leak key material | All error strings checked for key/plaintext bytes |
| TC-SEC-005 | WASM memory does not retain plaintext after decrypt (zeroize check) | Post-decrypt memory scan finds no plaintext (requires zeroize on drop) |
| TC-SEC-006 | Key material is zeroized after use | `Drop` on key structs zeros memory |

### 3.2 Tamper Detection -- `core/tests/security_tamper.rs`

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| TC-SEC-007 | Flip every bit position in ciphertext, each detected | All 8*len bit flips caught by Poly1305 |
| TC-SEC-008 | Replace one shard with random data, reconstruction detects | Either reconstruction fails or hash mismatch |
| TC-SEC-009 | Swap two shards' positions | Reconstruction produces wrong data, hash mismatch catches it |
| TC-SEC-010 | Modify canary chain (insert extra commitment) | `verify_chain()` detects tampering |
| TC-SEC-011 | Modify canary chain (remove middle commitment) | `verify_chain()` detects gap |
| TC-SEC-012 | Replay old canary token | Commitment with wrong sequence number detected |
| TC-SEC-013 | Modify AAD after encryption | `decrypt_with_aad` fails |
| TC-SEC-014 | Truncate encrypted blob by 1 byte | Decryption fails |

### 3.3 Side-Channel Resistance -- `core/tests/security_sidechannel.rs`

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| TC-SEC-015 | Decryption time is constant regardless of which byte is wrong | Timing variance < 5% across 1000 trials |
| TC-SEC-016 | KEM decapsulation time constant for valid vs invalid ciphertext | Timing variance < 5% |
| TC-SEC-017 | Key derivation time independent of passphrase content | Timing variance < 10% for equal-length passphrases |
| TC-SEC-018 | Hash comparison is constant-time | Timing of `==` on AssetHash does not vary with match position |
| TC-SEC-019 | No early-exit on partial nonce match | Rejection timing uniform |

---

## 4. Performance Tests -- `core/tests/`

Use `#[bench]` (nightly) or `criterion` crate for benchmarks.

### 4.1 Crypto Throughput -- `core/tests/performance_crypto.rs`

| Test ID | Description | Target | File |
|---------|-------------|--------|------|
| TC-PERF-001 | BLAKE3 hash throughput (1GB data) | > 5 GB/s (native), > 500 MB/s (WASM) | `performance_crypto.rs` |
| TC-PERF-002 | XChaCha20-Poly1305 encrypt throughput (1GB) | > 1 GB/s (native), > 100 MB/s (WASM) | `performance_crypto.rs` |
| TC-PERF-003 | XChaCha20-Poly1305 decrypt throughput (1GB) | > 1 GB/s (native), > 100 MB/s (WASM) | `performance_crypto.rs` |
| TC-PERF-004 | ML-KEM-768 keygen latency | < 1ms (native), < 10ms (WASM) | `performance_crypto.rs` |
| TC-PERF-005 | ML-KEM-768 encapsulate latency | < 1ms (native), < 10ms (WASM) | `performance_crypto.rs` |
| TC-PERF-006 | ML-KEM-768 decapsulate latency | < 1ms (native), < 10ms (WASM) | `performance_crypto.rs` |
| TC-PERF-007 | Argon2id key derivation latency | 300-800ms (tuned for security) | `performance_crypto.rs` |
| TC-PERF-008 | Full upload pipeline latency (10MB file) | < 2s (native), < 10s (WASM) | `performance_crypto.rs` |

### 4.2 Erasure Coding Throughput -- `core/tests/performance_erasure.rs`

| Test ID | Description | Target |
|---------|-------------|--------|
| TC-PERF-009 | Reed-Solomon encode throughput (100MB) | > 500 MB/s |
| TC-PERF-010 | Reed-Solomon reconstruct throughput (100MB, 2 missing) | > 300 MB/s |
| TC-PERF-011 | Shard size overhead ratio | Exactly 1.5x for 4+2 config |

### 4.3 WASM vs Native Comparison

| Test ID | Description | Target |
|---------|-------------|--------|
| TC-PERF-012 | WASM hash throughput as % of native | > 30% of native speed |
| TC-PERF-013 | WASM encrypt throughput as % of native | > 15% of native speed |
| TC-PERF-014 | WASM module load time in browser | < 500ms on 4G connection |
| TC-PERF-015 | WASM memory usage for 50MB file encrypt | < 200MB peak |

---

## 5. End-to-End Tests (Playwright) -- `web/e2e/`

Requires the web app running locally (`next dev`) with WASM loaded.

### 5.1 Signup and Vault -- `web/e2e/signup-vault.spec.ts`

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| TC-E2E-001 | New user signup with passphrase | Account created, key derived, vault empty |
| TC-E2E-002 | Upload a PDF file | File appears in vault list with correct name and hash |
| TC-E2E-003 | Download the uploaded file | Browser receives identical file (byte comparison) |
| TC-E2E-004 | Delete a file | File removed from vault, shards deleted from all providers |
| TC-E2E-005 | Upload 10 files sequentially | All appear in vault, all downloadable |
| TC-E2E-006 | Upload a 100MB file (large file path) | Progress indicator shown, upload completes |
| TC-E2E-007 | Login with wrong passphrase | Error shown, vault not accessible |
| TC-E2E-008 | Login with correct passphrase | Vault loads, files visible |

### 5.2 Family Sharing -- `web/e2e/share-family.spec.ts`

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| TC-E2E-009 | Owner shares a file with family member | Family member sees file in their vault |
| TC-E2E-010 | Family member downloads shared file | Content matches original |
| TC-E2E-011 | Owner revokes family member access | Family member can no longer see/download file |
| TC-E2E-012 | Family member cannot re-share (no forward sharing) | Share button not available to non-owners |

### 5.3 Dead Man's Switch -- `web/e2e/dead-man-switch.spec.ts`

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| TC-E2E-013 | Configure dead man's switch with 30-day check-in | Settings saved, countdown shown |
| TC-E2E-014 | Check-in resets the timer | Timer resets to 30 days |
| TC-E2E-015 | Simulate missed check-in (time manipulation) | Escalation notifications sent to designated contacts |
| TC-E2E-016 | Designated contact can access vault after escalation | Contact sees shared assets with decryption key |

### 5.4 Recovery Flow -- `web/e2e/recovery.spec.ts`

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| TC-E2E-017 | Generate recovery kit (PDF with QR codes) | PDF downloads with Shamir shares |
| TC-E2E-018 | Recover account using recovery kit | Vault restored with all files intact |
| TC-E2E-019 | Partial recovery kit (not enough shares) fails | Error: insufficient shares |

### 5.5 Browser Performance -- `web/e2e/performance.spec.ts`

| Test ID | Description | Target |
|---------|-------------|--------|
| TC-E2E-020 | Time to Interactive after login | < 3s on 4G throttle |
| TC-E2E-021 | WASM module load time | < 2s on broadband |
| TC-E2E-022 | 5MB file encrypt + upload wall clock | < 10s |
| TC-E2E-023 | 5MB file download + decrypt wall clock | < 10s |
| TC-E2E-024 | Memory usage stays below threshold during 50MB upload | < 300MB browser heap |

---

## 6. Chaos Tests -- `core/tests/`

### 6.1 Cloud Provider Failures -- `core/tests/chaos_cloud_failure.rs`

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| TC-CHAOS-001 | AWS S3 returns 503 during shard upload | Retry with backoff, eventually succeeds or falls back to alternate provider |
| TC-CHAOS-002 | GCS returns timeout during shard download | Other shards fetched; reconstruction from 4 of 6 |
| TC-CHAOS-003 | Azure Blob returns 403 (permission revoked) | Error surfaced to user with actionable message |
| TC-CHAOS-004 | All providers for one shard fail simultaneously | Degraded mode: reconstruction from remaining 5 shards (only 1 lost = OK) |
| TC-CHAOS-005 | Network partition during upload (3 of 6 shards uploaded) | Upload can be resumed; partial shards cleaned up or completed |
| TC-CHAOS-006 | DNS resolution failure for one provider | Falls back to IP or alternate endpoint |
| TC-CHAOS-007 | Slow provider (10s latency per shard) | Timeout triggers, parallel uploads to other providers fill gap |

### 6.2 Shard Corruption -- `core/tests/chaos_shard_corruption.rs`

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| TC-CHAOS-008 | One shard truncated to half size | Reconstruction detects bad shard, treats as missing, reconstructs from 5 |
| TC-CHAOS-009 | One shard has random bytes | Hash mismatch detected, shard excluded, reconstruct from 5 |
| TC-CHAOS-010 | Two shards corrupted | Still reconstructable from remaining 4 valid shards |
| TC-CHAOS-011 | Three shards corrupted | Fails with `InsufficientShards` error |
| TC-CHAOS-012 | Shard bit-rot: single bit flip in one shard | Hash check detects, shard excluded, reconstruct from 5 |
| TC-CHAOS-013 | Shard replaced with all zeros | Hash mismatch, excluded, reconstruct from 5 |
| TC-CHAOS-014 | Provider returns shard from wrong asset | Asset-ID-bound hash check rejects, reconstruct from 5 |

---

## 7. WASM Bridge Tests -- `web/__tests__/`

### 7.1 WASM-JS Boundary -- `web/__tests__/wasm-bridge.test.ts`

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| TC-WASM-001 | `hash_bytes` returns 64-char hex string | Length 64, all hex chars |
| TC-WASM-002 | `encrypt_data` returns valid JSON with nonce + ciphertext (base64) | JSON parses, both fields base64 |
| TC-WASM-003 | `decrypt_data` roundtrips with `encrypt_data` | Plaintext matches |
| TC-WASM-004 | `derive_key` produces 32-byte Uint8Array | Length 32 |
| TC-WASM-005 | `kem_generate` returns JSON with public_key + secret_key | Both fields present, base64 |
| TC-WASM-006 | `kem_encapsulate` + `kem_decapsulate` roundtrip | Shared secrets match |
| TC-WASM-007 | `canary_create` returns valid JSON chain | Parseable, has asset_id and commitments |
| TC-WASM-008 | `canary_rotate` increments access count | Count increases by 1 |
| TC-WASM-009 | `canary_verify` returns access count for valid chain | Returns number |
| TC-WASM-010 | Wrong key length (31 bytes) to `encrypt_data` | Throws JsError with "key must be 32 bytes" |
| TC-WASM-011 | Wrong salt length to `derive_key` | Throws JsError with "salt must be 16 bytes" |
| TC-WASM-012 | Invalid base64 to `kem_encapsulate` | Throws JsError |

---

## CI/CD Integration

### Test Tiers

| Tier | Tests | Runs On | Timeout |
|------|-------|---------|---------|
| **Tier 1: Fast** | All unit tests (`cargo test`) | Every push | 5 min |
| **Tier 2: Integration** | Integration + security tests (`cargo test --test 'integration_*' --test 'security_*'`) | Every PR | 15 min |
| **Tier 3: Performance** | Performance benchmarks (`cargo bench`) | Nightly / release | 30 min |
| **Tier 4: E2E** | Playwright tests (`npx playwright test`) | Every PR to main | 20 min |
| **Tier 5: Chaos** | Chaos tests (require mock cloud infra) | Weekly / pre-release | 30 min |

### GitHub Actions Workflow

```yaml
# .github/workflows/test.yml
name: RESQD Test Suite
on: [push, pull_request]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo test --workspace

  wasm-build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          targets: wasm32-unknown-unknown
      - run: cargo install wasm-pack
      - run: cd core && wasm-pack build --target web --features wasm

  integration-tests:
    runs-on: ubuntu-latest
    if: github.event_name == 'pull_request'
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo test --test 'integration_*' --test 'security_*'

  e2e-tests:
    runs-on: ubuntu-latest
    if: github.base_ref == 'main'
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
      - run: cd web && npm ci && npx playwright install
      - run: cd web && npm run dev &
      - run: cd web && npx playwright test
```

---

## Test Data Sets

| Data Set | Size | Purpose | Location |
|----------|------|---------|----------|
| `tiny.txt` | 0 bytes | Empty file edge case | `core/tests/fixtures/` |
| `small.txt` | 13 bytes ("Hello, RESQD!") | Minimal content | `core/tests/fixtures/` |
| `medium.pdf` | 5 MB | Typical document | `core/tests/fixtures/` (generated) |
| `large.bin` | 100 MB | Stress test | Generated at test time |
| `huge.bin` | 500 MB | Max file size test | Generated at test time |
| `unicode.txt` | 1 KB | Multi-script text | `core/tests/fixtures/` |
| `binary.dat` | 1 MB | Random bytes | Generated at test time |

---

## Test ID Summary

| Range | Category | Count |
|-------|----------|-------|
| TC-UNIT-001 to TC-UNIT-053 | Unit tests (Rust) | 53 |
| TC-INT-001 to TC-INT-023 | Integration tests | 23 |
| TC-SEC-001 to TC-SEC-019 | Security tests | 19 |
| TC-PERF-001 to TC-PERF-015 | Performance tests | 15 |
| TC-E2E-001 to TC-E2E-024 | E2E browser tests | 24 |
| TC-CHAOS-001 to TC-CHAOS-014 | Chaos tests | 14 |
| TC-WASM-001 to TC-WASM-012 | WASM bridge tests | 12 |
| **Total** | | **160** |
