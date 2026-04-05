//! `resqd-recover` — offline reconstruction tool for RESQD Recovery Kits.
//!
//! This is the "data of last resort" reader. Given a Recovery Kit JSON
//! file (produced by the `Download Recovery Kit` button in the web
//! Settings page) it walks every asset, reconstructs the original
//! plaintext via Reed-Solomon decode + XChaCha20-Poly1305 decrypt, and
//! writes the recovered files to an output directory.
//!
//! Key design property: **zero network access, zero server**. Once you
//! have a kit on disk and this binary, you can recover your data even
//! if resqd.ai has vanished from the internet entirely. No S3, no API,
//! no DNS. That guarantee is the whole point of the tool.
//!
//! The implementation is deliberately small — it depends only on
//! `resqd-core` (for the shared erasure and AEAD code paths) plus
//! standard Rust crypto crates. The full read path is well under 500
//! lines and can be audited in one sitting.

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, prelude::BASE64_STANDARD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use clap::{Parser, Subcommand};
use resqd_core::erasure;
use serde::Deserialize;
use std::{fs, io::Write, path::PathBuf};

// ────────────────────────────────────────────────────────────────────
//                          CLI surface
// ────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "resqd-recover",
    version,
    about = "Reconstruct a RESQD vault from a Recovery Kit with zero server dependency"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Walk a Recovery Kit and write every decrypted file into an output
    /// directory. Uses no network. Default behaviour.
    Decrypt {
        /// Path to the `resqd-recovery-kit-*.json` file.
        #[arg(long, short = 'k')]
        kit: PathBuf,
        /// Where to write recovered files. Created if missing.
        #[arg(long, short = 'o', default_value = "./recovered")]
        out_dir: PathBuf,
        /// Parse and print the kit summary without writing any files.
        /// Useful for previewing what a kit contains before running a
        /// full recovery.
        #[arg(long)]
        dry_run: bool,
    },
    /// Print a one-screen summary of a kit: version, owner email,
    /// asset count, per-asset filename and size. Does no decryption.
    Inspect {
        #[arg(long, short = 'k')]
        kit: PathBuf,
    },
}

// ────────────────────────────────────────────────────────────────────
//                          Kit schema
// ────────────────────────────────────────────────────────────────────
//
// These structs mirror `RECOVERY_KIT_SPEC.md` v1 exactly. Unknown
// fields are ignored (serde default) so additive additions in future
// minor kit updates within v1 remain compatible.

#[derive(Debug, Deserialize)]
struct Kit {
    version: u32,
    #[serde(default)]
    spec_url: String,
    #[serde(default)]
    generated_at: u64,
    user: KitUser,
    assets: Vec<KitAsset>,
}

#[derive(Debug, Deserialize)]
struct KitUser {
    #[serde(default)]
    user_id: String,
    #[serde(default)]
    email: String,
    // master_key_b64 / x25519_* are accepted but not needed for
    // decryption — each asset already carries its unwrapped
    // per_asset_key_b64. We pull them through for display and for the
    // optional consistency check.
    #[serde(default)]
    x25519_pubkey_b64: Option<String>,
    #[serde(default)]
    x25519_privkey_b64: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Display-only fields (`role`, `mime`, `shared_by_email`,
                    // `created_at`) are parsed for future-facing summary
                    // commands; keeping them in the struct ties the
                    // reader to the spec even when the tool doesn't
                    // currently print them.
struct KitAsset {
    asset_id: String,
    #[serde(default)]
    role: String,
    #[serde(default)]
    filename: Option<String>,
    #[serde(default)]
    mime: Option<String>,
    #[serde(default)]
    shared_by_email: Option<String>,
    #[serde(default)]
    created_at: u64,
    crypto: KitCrypto,
    erasure: KitErasure,
    shards: Vec<KitShard>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // `frame_format` is a spec-version tag we check
                    // implicitly via the `FrameHeader::v` field — kept
                    // in the struct so readers can pattern-match on it
                    // in future versions.
struct KitCrypto {
    aead: String,
    per_asset_key_b64: String,
    #[serde(default)]
    frame_format: String,
}

#[derive(Debug, Deserialize)]
struct KitErasure {
    k: usize,
    n: usize,
    original_len: usize,
}

#[derive(Debug, Deserialize)]
struct KitShard {
    index: usize,
    #[serde(default)]
    ciphertext_b64: Option<String>,
}

// Envelope produced by `resqd-core`'s `encrypt_data` WASM function —
// the erasure-reconstructed bytes decode to this JSON, and then the
// nonce + ciphertext feed the XChaCha20-Poly1305 decrypt step.
#[derive(Debug, Deserialize)]
struct Envelope {
    nonce: String,
    ciphertext: String,
}

// Frame header written by the web upload page. The plaintext is
// `[u32 LE header_len | header JSON | body]` so the decrypted file
// can carry its original filename + mime out-of-band of any
// filesystem metadata.
#[derive(Debug, Deserialize)]
struct FrameHeader {
    v: u32,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    mime: Option<String>,
}

// ────────────────────────────────────────────────────────────────────
//                          Entry point
// ────────────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Decrypt { kit, out_dir, dry_run } => cmd_decrypt(&kit, &out_dir, dry_run),
        Cmd::Inspect { kit } => cmd_inspect(&kit),
    }
}

fn cmd_inspect(path: &PathBuf) -> Result<()> {
    let kit = load_kit(path)?;
    print_summary(&kit);
    Ok(())
}

fn cmd_decrypt(path: &PathBuf, out_dir: &PathBuf, dry_run: bool) -> Result<()> {
    let kit = load_kit(path)?;
    print_summary(&kit);

    if !dry_run {
        fs::create_dir_all(out_dir)
            .with_context(|| format!("create output dir {}", out_dir.display()))?;
    }

    let mut ok = 0usize;
    let mut fail = 0usize;

    for (i, asset) in kit.assets.iter().enumerate() {
        print!("[{}/{}] {} ", i + 1, kit.assets.len(), &asset.asset_id);
        std::io::stdout().flush().ok();

        match recover_asset(asset) {
            Ok((name, body)) => {
                if dry_run {
                    println!(
                        "✓ {} bytes ({})",
                        body.len(),
                        name.as_deref().unwrap_or("no-name")
                    );
                    ok += 1;
                    continue;
                }
                let out_name = sanitize_filename(name.as_deref(), &asset.asset_id);
                let out_path = out_dir.join(&out_name);
                match fs::write(&out_path, &body) {
                    Ok(_) => {
                        println!("✓ {} -> {}", body.len(), out_path.display());
                        ok += 1;
                    }
                    Err(e) => {
                        println!("✗ write failed: {e}");
                        fail += 1;
                    }
                }
            }
            Err(e) => {
                println!("✗ {e}");
                fail += 1;
            }
        }
    }

    println!();
    println!("{} recovered, {} failed", ok, fail);
    if fail > 0 {
        std::process::exit(2);
    }
    Ok(())
}

// ────────────────────────────────────────────────────────────────────
//                          Core pipeline
// ────────────────────────────────────────────────────────────────────

fn load_kit(path: &PathBuf) -> Result<Kit> {
    let bytes = fs::read(path)
        .with_context(|| format!("read kit {}", path.display()))?;
    let kit: Kit = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse kit {}", path.display()))?;
    if kit.version != 1 {
        bail!(
            "unsupported Recovery Kit version {} — this tool only understands v1",
            kit.version
        );
    }
    Ok(kit)
}

fn print_summary(kit: &Kit) {
    println!("RESQD Recovery Kit");
    println!("  version       : {}", kit.version);
    println!("  generated at  : {} (unix)", kit.generated_at);
    println!("  user_id       : {}", kit.user.user_id);
    println!("  email         : {}", kit.user.email);
    println!("  assets        : {}", kit.assets.len());
    println!("  spec          : {}", kit.spec_url);

    // Optional consistency check: pubkey must match privkey.
    if let (Some(pub_b64), Some(priv_b64)) = (
        kit.user.x25519_pubkey_b64.as_deref(),
        kit.user.x25519_privkey_b64.as_deref(),
    ) {
        match verify_identity_consistency(pub_b64, priv_b64) {
            Ok(true) => println!("  identity      : ✓ consistent"),
            Ok(false) => {
                println!("  identity      : ✗ WARNING pubkey does not match privkey");
            }
            Err(e) => {
                println!("  identity      : ? skipped ({e})");
            }
        }
    }
    println!();
}

fn verify_identity_consistency(pub_b64: &str, priv_b64: &str) -> Result<bool> {
    let priv_bytes = BASE64_STANDARD.decode(priv_b64)?;
    let pub_bytes = BASE64_STANDARD.decode(pub_b64)?;
    if priv_bytes.len() != 32 || pub_bytes.len() != 32 {
        bail!("identity halves are not 32 bytes");
    }
    let priv32: [u8; 32] = priv_bytes.try_into().unwrap();
    let derived = resqd_core::crypto::share::IdentityKeypair::from_private(priv32);
    Ok(derived.public.as_slice() == pub_bytes.as_slice())
}

/// The full decryption pipeline for a single asset:
///
/// 1. Decode the per-asset key from base64 (32 bytes).
/// 2. Decode each present shard from base64 into raw bytes, leaving
///    missing shards as `None`.
/// 3. Run `resqd_core::erasure::reconstruct` — matches the same (k=4,
///    n=6, galois_8) params the writer uses.
/// 4. The reconstructed bytes are the UTF-8 JSON envelope
///    `{nonce, ciphertext}` produced by `encrypt_data`. Parse it.
/// 5. XChaCha20-Poly1305 decrypt with the per-asset key + the
///    envelope's 24-byte nonce.
/// 6. Strip the frame header (u32 LE header_len || header JSON ||
///    body) to recover the original file bytes and filename.
fn recover_asset(asset: &KitAsset) -> Result<(Option<String>, Vec<u8>)> {
    if asset.crypto.aead != "xchacha20-poly1305" {
        bail!("unsupported AEAD {}", asset.crypto.aead);
    }
    let key_bytes = BASE64_STANDARD
        .decode(&asset.crypto.per_asset_key_b64)
        .context("decode per_asset_key_b64")?;
    if key_bytes.len() != 32 {
        bail!("per-asset key is {} bytes, expected 32", key_bytes.len());
    }
    let key: [u8; 32] = key_bytes.try_into().unwrap();

    // Step 1+2: decode shards.
    if asset.erasure.n != erasure::TOTAL_SHARDS || asset.erasure.k != erasure::DATA_SHARDS {
        bail!(
            "unsupported erasure params k={} n={} (this tool only supports k={} n={})",
            asset.erasure.k,
            asset.erasure.n,
            erasure::DATA_SHARDS,
            erasure::TOTAL_SHARDS
        );
    }
    let mut shards: Vec<Option<Vec<u8>>> = vec![None; erasure::TOTAL_SHARDS];
    for s in &asset.shards {
        if s.index >= erasure::TOTAL_SHARDS {
            bail!("shard index {} out of range", s.index);
        }
        if let Some(b64) = &s.ciphertext_b64 {
            let bytes = BASE64_STANDARD
                .decode(b64)
                .with_context(|| format!("decode shard {}", s.index))?;
            shards[s.index] = Some(bytes);
        }
    }
    let present = shards.iter().filter(|s| s.is_some()).count();
    if present < erasure::DATA_SHARDS {
        bail!(
            "only {} of {} required shards present — cannot reconstruct",
            present,
            erasure::DATA_SHARDS
        );
    }

    // Step 3: Reed-Solomon reconstruct.
    let ct_json_bytes = erasure::reconstruct(&mut shards, asset.erasure.original_len)
        .map_err(|e| anyhow!("erasure reconstruct: {e}"))?;

    // Step 4: parse envelope.
    let envelope: Envelope =
        serde_json::from_slice(&ct_json_bytes).context("parse encrypted envelope")?;
    let nonce = BASE64_STANDARD
        .decode(&envelope.nonce)
        .context("decode nonce")?;
    let ciphertext = BASE64_STANDARD
        .decode(&envelope.ciphertext)
        .context("decode ciphertext")?;
    if nonce.len() != 24 {
        bail!("XChaCha20 nonce must be 24 bytes, got {}", nonce.len());
    }

    // Step 5: AEAD decrypt.
    let cipher = XChaCha20Poly1305::new((&key).into());
    let nonce = XNonce::from_slice(&nonce);
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_slice())
        .map_err(|e| anyhow!("XChaCha20-Poly1305 decrypt failed: {e}"))?;

    // Step 6: unwrap the frame header.
    let (name, body) = unwrap_frame(&plaintext, asset);
    Ok((name, body))
}

/// Strip the `[u32 LE header_len | header JSON | body]` frame. Falls
/// back to returning the entire plaintext as the body if the header
/// is absent, oversized, or unparseable — matches the same graceful
/// fallback the web `/fetch` page uses so legacy assets uploaded
/// before the frame format existed still recover.
fn unwrap_frame(plaintext: &[u8], asset: &KitAsset) -> (Option<String>, Vec<u8>) {
    if plaintext.len() < 4 {
        return (asset.filename.clone(), plaintext.to_vec());
    }
    let header_len = u32::from_le_bytes([plaintext[0], plaintext[1], plaintext[2], plaintext[3]]);
    if header_len == 0 || header_len > 1024 || 4 + header_len as usize > plaintext.len() {
        return (asset.filename.clone(), plaintext.to_vec());
    }
    let header_bytes = &plaintext[4..4 + header_len as usize];
    let parsed: Result<FrameHeader, _> = serde_json::from_slice(header_bytes);
    match parsed {
        Ok(header) if header.v == 1 => {
            let body = plaintext[4 + header_len as usize..].to_vec();
            // Prefer the frame's name over the kit's metadata filename —
            // the frame is authoritative (it's inside the encrypted
            // plaintext), the kit metadata is display-only.
            let name = header.name.or_else(|| asset.filename.clone());
            let _ = header.mime; // not used for filename choice
            (name, body)
        }
        _ => (asset.filename.clone(), plaintext.to_vec()),
    }
}

/// Produce a safe output filename:
/// - Replace path separators with underscores (defence against
///   traversal — `..`, absolute paths, `x/y/z.png` all collapse to
///   `x_y_z.png`)
/// - Strip control characters
/// - Fall back to `{asset_id}.bin` if the result is empty
///
/// The recover tool never writes outside its output directory.
fn sanitize_filename(name: Option<&str>, asset_id: &str) -> String {
    let raw = name.unwrap_or("").trim();
    if raw.is_empty() {
        return format!("{asset_id}.bin");
    }
    let cleaned: String = raw
        .chars()
        .map(|c| {
            if c == '/' || c == '\\' || c.is_control() {
                '_'
            } else {
                c
            }
        })
        .collect();
    // Strip leading dots to avoid hidden-file surprises + traversal
    // via `..filename`.
    let cleaned = cleaned.trim_start_matches('.').to_string();
    if cleaned.is_empty() {
        format!("{asset_id}.bin")
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_path_separators() {
        // `..` becomes `.._` once slashes are replaced, then leading
        // dots are stripped — so `../etc/passwd` collapses to
        // `_etc_passwd`. Strictly safer than the naive `__etc_passwd`
        // because the parent-dir component disappears entirely.
        assert_eq!(sanitize_filename(Some("../etc/passwd"), "x"), "_etc_passwd");
        assert_eq!(sanitize_filename(Some("/abs/path"), "x"), "_abs_path");
        assert_eq!(sanitize_filename(Some("a\\b\\c"), "x"), "a_b_c");
        // Both Unix and Windows path separators collapse. Interior
        // `..` is preserved as literal characters in the basename —
        // that's safe because all path separators were already
        // replaced, so the result is a single flat filename.
        assert_eq!(sanitize_filename(Some("..\\..\\secret"), "x"), "_.._secret");
    }

    #[test]
    fn sanitize_handles_empty_and_hidden() {
        assert_eq!(sanitize_filename(Some(""), "asset-1"), "asset-1.bin");
        assert_eq!(sanitize_filename(None, "asset-1"), "asset-1.bin");
        assert_eq!(sanitize_filename(Some("....."), "asset-1"), "asset-1.bin");
    }

    #[test]
    fn unwrap_frame_strips_v1_header() {
        let header = br#"{"v":1,"name":"hello.txt","mime":"text/plain"}"#;
        let mut frame = Vec::new();
        frame.extend_from_slice(&(header.len() as u32).to_le_bytes());
        frame.extend_from_slice(header);
        frame.extend_from_slice(b"body bytes");
        let asset = fake_asset();
        let (name, body) = unwrap_frame(&frame, &asset);
        assert_eq!(name.as_deref(), Some("hello.txt"));
        assert_eq!(body, b"body bytes");
    }

    #[test]
    fn unwrap_frame_legacy_fallback() {
        // No frame header — the whole plaintext is the body.
        let plaintext = b"legacy-no-frame";
        let asset = fake_asset();
        let (name, body) = unwrap_frame(plaintext, &asset);
        assert_eq!(name, asset.filename);
        assert_eq!(body, plaintext);
    }

    fn fake_asset() -> KitAsset {
        KitAsset {
            asset_id: "x".into(),
            role: "owner".into(),
            filename: Some("fallback.bin".into()),
            mime: None,
            shared_by_email: None,
            created_at: 0,
            crypto: KitCrypto {
                aead: "xchacha20-poly1305".into(),
                per_asset_key_b64: "".into(),
                frame_format: "resqd-frame-v1".into(),
            },
            erasure: KitErasure {
                k: 4,
                n: 6,
                original_len: 0,
            },
            shards: vec![],
        }
    }
}
