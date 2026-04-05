//! Build a tiny synthetic Recovery Kit end-to-end using the same
//! crypto stack the web upload path uses, then verify resqd-recover
//! can decrypt it. Run as:
//!
//!   cargo run --example build_smoke_kit -- /tmp/kit.json
//!   target/debug/resqd-recover decrypt -k /tmp/kit.json -o /tmp/out
//!
//! This is an integration test, not a unit test — it lives in
//! examples/ so it doesn't run in `cargo test` but is trivially
//! scriptable when we want to smoke the whole pipeline.

use base64::{Engine as _, prelude::BASE64_STANDARD};
use resqd_core::crypto::encrypt::{EncryptedBlob, encrypt};
use resqd_core::erasure;
use std::io::Write;

fn main() {
    let out_path = std::env::args()
        .nth(1)
        .expect("usage: build_smoke_kit <out_path>");

    // The asset we're "uploading": a small text file.
    let key = [7u8; 32];
    let name = "hello.txt";
    let body = b"hello recover\n";

    // Wrap in the v1 frame: u32 LE header_len | header JSON | body.
    let header = format!(r#"{{"v":1,"name":"{name}","mime":"text/plain"}}"#);
    let header_bytes = header.as_bytes();
    let mut frame = Vec::new();
    frame.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
    frame.extend_from_slice(header_bytes);
    frame.extend_from_slice(body);

    // AEAD encrypt, emit the same envelope shape encrypt_data does.
    let EncryptedBlob { nonce, ciphertext } = encrypt(&key, &frame).unwrap();
    let envelope_json = format!(
        r#"{{"nonce":"{}","ciphertext":"{}"}}"#,
        BASE64_STANDARD.encode(&nonce),
        BASE64_STANDARD.encode(&ciphertext),
    );
    let envelope_bytes = envelope_json.as_bytes();
    let original_len = envelope_bytes.len();

    // Reed-Solomon 4+2 on the envelope bytes, same as the upload flow.
    let shards = erasure::encode(envelope_bytes).unwrap();
    let shards_b64: Vec<String> = shards.iter().map(|s| BASE64_STANDARD.encode(s)).collect();

    let kit = serde_json::json!({
        "version": 1,
        "spec_url": "local-smoke",
        "generated_at": 0,
        "recovery_tool": {"cli_name": "resqd-recover", "install_hint": "", "source_url": ""},
        "recovery_service": {"diy_url": "", "concierge_url": "", "heir_claim_url": ""},
        "user": {
            "user_id": "uid",
            "email": "k@example.com",
            "master_key_b64": BASE64_STANDARD.encode([0u8;32]),
            "x25519_pubkey_b64": BASE64_STANDARD.encode([0u8;32]),
            "x25519_privkey_b64": BASE64_STANDARD.encode([0u8;32]),
        },
        "assets": [{
            "asset_id": "smoke-1",
            "role": "owner",
            "filename": "hello.txt",
            "mime": "text/plain",
            "created_at": 0,
            "crypto": {
                "aead": "xchacha20-poly1305",
                "per_asset_key_b64": BASE64_STANDARD.encode(&key),
                "frame_format": "resqd-frame-v1",
            },
            "erasure": {
                "k": erasure::DATA_SHARDS,
                "n": erasure::TOTAL_SHARDS,
                "original_len": original_len,
            },
            "shards": (0..erasure::TOTAL_SHARDS).map(|i| serde_json::json!({
                "index": i,
                "ciphertext_b64": shards_b64[i],
            })).collect::<Vec<_>>(),
        }]
    });

    std::fs::File::create(&out_path)
        .unwrap()
        .write_all(serde_json::to_string_pretty(&kit).unwrap().as_bytes())
        .unwrap();
    eprintln!("wrote smoke kit to {out_path}");
}
