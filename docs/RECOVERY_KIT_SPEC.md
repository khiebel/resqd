# RESQD Recovery Kit — Format Specification

**Version:** 1
**Status:** Stable (breaking changes require version bump)
**Reference implementation writer:** `web/app/lib/recoveryKit.ts`
**Reference implementation reader:** `recover/src/main.rs` (crate `resqd-recover`)

## Purpose

A Recovery Kit is the canonical "data of last resort" artifact that a RESQD
user downloads to guarantee they can reconstruct their vault with **zero
dependency on resqd.ai being alive**. If the servers disappear, the domain
lapses, the S3 bucket is reclaimed, and the business goes under, the user's
kit on disk plus an open-source tool are enough to get every file back.

The kit is also the hand-off point for paid recovery services: it carries
URLs for a free DIY path (the reference reader), a concierge path for users
who don't want to run a CLI, and an heir-claim path for posthumous recovery.
When resqd is alive those URLs are live; when it isn't, the DIY path still
works.

## File shape

The kit is a **single JSON file** with embedded base64 ciphertext shards. It
is intentionally not a ZIP — the goal is that any language with a
JSON parser and a cryptography library can walk and verify it without pulling
in an archive dependency.

```
resqd-recovery-kit-{email_slug}-{YYYY-MM-DD}.json
```

## Top-level schema

```jsonc
{
  "version": 1,
  "spec_url": "https://github.com/khiebel/resqd/blob/main/docs/RECOVERY_KIT_SPEC.md",
  "generated_at": 1775419721,          // unix seconds
  "recovery_tool": {
    "cli_name": "resqd-recover",
    "install_hint": "cargo install --git https://github.com/khiebel/resqd resqd-recover",
    "source_url": "https://github.com/khiebel/resqd"
  },
  "recovery_service": {
    "diy_url":        "https://github.com/khiebel/resqd#recovery",
    "concierge_url":  "https://resqd.ai/recover",
    "heir_claim_url": "https://resqd.ai/heir"
  },
  "user": {
    "user_id": "…",
    "email":   "…",
    "master_key_b64":     "…",         // 32 bytes, STANDARD base64
    "x25519_pubkey_b64":  "…",         // 32 bytes, STANDARD base64
    "x25519_privkey_b64": "…"          // 32 bytes, STANDARD base64
  },
  "assets": [ /* RecoveryKitAsset, see below */ ]
}
```

### Base64 variant

All base64 fields in the kit use the **standard** alphabet
(RFC 4648 §4) with padding. No URL-safe variants. No URL-safe without
padding. The reference reader verifies this.

### Master key and identity

The kit carries the user's PRF-derived vault master key **in plaintext**.
This is deliberate: the kit itself IS the last-resort artifact, so
demanding a second factor to unlock it would defeat its purpose. The
user is responsible for storing the kit like a printed passphrase — on an
encrypted drive, in a safe, wrapped in an external passphrase they
remember, etc.

The X25519 identity keypair is also carried in plaintext for the same
reason. It is only used by the recover tool for one thing: verifying
the kit's internal consistency (the `x25519_pubkey_b64` must
recompute from `x25519_privkey_b64`). The per-asset keys in the kit
are **pre-unwrapped**, so the reader never has to do any X25519 or
ECDH work — it just XChaCha20-decrypts each asset with its own key.

## `RecoveryKitAsset`

```jsonc
{
  "asset_id": "…",
  "role": "owner" | "sharee",
  "filename": "photo.jpg",             // may be null for legacy/no-name
  "mime":     "image/jpeg",            // may be null
  "shared_by_email": "alice@…",        // sharee only, optional
  "created_at": 1775000000,

  "crypto": {
    "aead": "xchacha20-poly1305",      // only valid value in v1
    "per_asset_key_b64": "…",          // 32 bytes, STANDARD base64
    "frame_format": "resqd-frame-v1"   // see "Frame format" below
  },

  "erasure": {
    "k": 4,                            // data shards
    "n": 6,                            // total shards
    "original_len": 123456             // bytes of ciphertext pre-erasure
  },

  "shards": [
    { "index": 0, "ciphertext_b64": "…" },   // base64 of raw shard bytes
    { "index": 1, "ciphertext_b64": "…" },
    { "index": 2, "ciphertext_b64": "…" },
    { "index": 3, "ciphertext_b64": "…" },
    { "index": 4, "ciphertext_b64": "…" },
    { "index": 5, "ciphertext_b64": "…" }
  ]
}
```

### Key properties

- **Every `per_asset_key_b64` is already unwrapped.** The reader never
  looks at master keys, X25519 keys, or ECDH. It just loads the 32
  bytes and passes them to XChaCha20. Owner and sharee assets are
  indistinguishable at decrypt time — all the key-management
  complexity was done in the browser at export time.
- **Shards are indexed 0..n-1.** The reader MUST reconstruct with the
  same (k, n) parameters and the same shard index mapping as the
  writer.
- **Missing shards** are allowed: any entry may have
  `"ciphertext_b64": null`. Reed-Solomon 4+2 tolerates up to `n-k = 2`
  missing shards per asset. A reader encountering more than `n-k`
  nulls for a single asset MUST fail that asset and continue with the
  rest of the kit.

## Decryption pipeline

For each asset in order:

1. **Collect shards.** Build a length-`n` array where index `i` holds
   the raw bytes of shard index `i` (or `None` if null). Verify at
   least `k` entries are non-null; error out otherwise.

2. **Reed-Solomon reconstruct.** Use the same RS(k, n) GF(256) code
   resqd-core uses (`reed-solomon-erasure` crate, `ReedSolomon<Field8>`
   default). Reconstruct the data shards and truncate to
   `erasure.original_len` bytes. Output: the XChaCha20 envelope as
   JSON text.

3. **Parse the envelope.** `{"nonce": "<base64>", "ciphertext": "<base64>"}`.
   Standard base64 in both fields.

4. **XChaCha20-Poly1305 decrypt.** 24-byte nonce, 32-byte key (from
   `per_asset_key_b64`), standard xchacha20poly1305 crate with
   no associated data. Output: the **plaintext frame**.

5. **Unwrap the frame.** See below.

6. **Write to disk.** Filename is the frame header's `name` field if
   present, else the `filename` metadata from the kit, else
   `{asset_id}.bin`. MIME type is advisory only and not preserved in
   most filesystems.

### Frame format (`resqd-frame-v1`)

Every uploaded asset is wrapped in a small header before encryption so
the decrypted plaintext is self-describing:

```
┌─────────────────┬─────────────────────────────┬────────────────────┐
│  header_len     │         header JSON         │       body         │
│  (u32 LE, 4 B)  │   {"v":1,"name":…,"mime":…} │  (original bytes)  │
└─────────────────┴─────────────────────────────┴────────────────────┘
```

- `header_len` is little-endian unsigned 32-bit, `0 < header_len ≤ 1024`.
- Header is UTF-8 JSON with at least `{"v": 1}`. Additional fields:
  `name: string`, `mime: string`.
- If `header_len == 0` OR the header does not parse OR `v != 1`, the
  reader treats the entire plaintext as the body (legacy pre-frame
  uploads). This is the same fallback the web `/fetch` page uses.

### Reader guarantees

A v1-compliant reader MUST:

- Verify `version == 1` and fail fast otherwise
- Treat missing or malformed top-level fields as a fatal kit error
- Process assets independently — an error on one asset MUST NOT
  abort the whole recovery
- Write output files into a caller-specified output directory with
  their original filenames (or `{asset_id}.bin` fallbacks), creating
  subdirectories as needed if filenames contain path separators
  (reader MUST sanitize against path traversal — `..` segments,
  absolute paths, etc. — before writing)
- Not require any network access

A v1-compliant reader SHOULD:

- Verify `x25519_pubkey_b64 == x25519_public_from_private(x25519_privkey_b64)`
  as an internal-consistency check before starting any decryption
- Emit a summary line per asset (success / skip + reason)
- Exit non-zero if any asset failed

## Version policy

- Format version is a monotonically increasing integer at
  `kit.version`.
- Any breaking change — new required field, new required crypto
  primitive, changed base64 variant, changed frame format, changed
  erasure parameters — requires a new top-level version and a new
  spec document. Readers MUST reject kits whose version they don't
  understand.
- Additive optional fields within a version (new assets roles, new
  metadata fields) are not a breaking change. Readers MUST ignore
  unknown optional fields.

## What's NOT in the kit

The kit is a snapshot. It does **not** contain:

- Canary chain history (that's on-chain already, append-only, and
  recoverable via the Base Sepolia contract if anyone wants to
  verify access history independently)
- API tokens (mint fresh ones against a live API if you need them)
- Future shares you receive after the export (download a fresh kit)
- Marketing/account metadata beyond user_id + email

## Three recovery paths

Every kit carries all three URLs. The DIY path is always free and always
works — it's just running the open-source reference reader against the
kit. The concierge and heir-claim paths are planned paid products that
will live at resqd.ai; until they exist, they 404, and users fall back
to DIY. This is deliberate: the business model sits **on top of** the
cryptographic guarantee, not in front of it.

| Path       | Price | Availability                           | Reader         |
|------------|-------|-----------------------------------------|----------------|
| DIY        | Free  | Always, from any kit, forever           | `resqd-recover`|
| Concierge  | Paid  | When resqd.ai is up                     | resqd staff    |
| Heir claim | Paid  | When resqd.ai is up, with identity docs | resqd staff    |

## Reference reader

`resqd-recover` is a standalone Rust binary. It depends on `resqd-core`
only for the XChaCha20-Poly1305 AEAD path and nothing else — it's
fewer than 500 lines and can be audited in one sitting. Source:
`recover/src/main.rs` in the resqd monorepo.

```
cargo install --git https://github.com/khiebel/resqd resqd-recover

resqd-recover decrypt \
    --kit path/to/resqd-recovery-kit-*.json \
    --out-dir ./recovered
```

The tool prints a per-asset summary and exits 0 iff every asset
succeeded. It never touches the network.
